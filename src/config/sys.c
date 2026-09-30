/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "config/sys.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/log.h"
#include "core/uuid.h"
#include "crypto/madmin.h"
#include "kms/cfgcrypt.h"
#include "object/sysconfig.h"

#define CONFIG_FILE "config/config.json"
#define HISTORY_PREFIX "config/history/"

struct buckets_config_sys {
  buckets_objlayer *layer;
  buckets_kms *kms; /* seals the configuration when set (config.EncryptBytes) */
  char *password; /* "ak:sk": the key of legacy encrypted config files */
  pthread_rwlock_t lock;
  buckets_config *cfg;
  buckets_config_changed_fn hook;
  void *hook_ud;
};

buckets_config_sys *buckets_config_sys_new(const char *root_access_key, const char *root_secret_key) {
  buckets_config_sys *s = buckets_xcalloc(1, sizeof(*s));
  size_t n = strlen(root_access_key) + strlen(root_secret_key) + 2;
  s->password = buckets_xmalloc(n);
  snprintf(s->password, n, "%s:%s", root_access_key, root_secret_key);
  pthread_rwlock_init(&s->lock, NULL);
  s->cfg = buckets_config_new();
  return s;
}

void buckets_config_sys_free(buckets_config_sys *s) {
  if (!s) return;
  buckets_config_free(s->cfg);
  pthread_rwlock_destroy(&s->lock);
  free(s->password);
  free(s);
}

void buckets_config_sys_set_hook(buckets_config_sys *s, buckets_config_changed_fn fn, void *ud) {
  s->hook = fn;
  s->hook_ud = ud;
}

static bool utf8_valid(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n;) {
    uint8_t c = p[i];
    size_t k = c < 0x80 ? 1 : (c >> 5) == 6 ? 2 : (c >> 4) == 14 ? 3 : (c >> 3) == 30 ? 4 : 0;
    if (!k || i + k > n) return false;
    for (size_t j = 1; j < k; j++) {
      if ((p[i + j] & 0xC0) != 0x80) return false;
    }
    i += k;
  }
  return true;
}

/* readConfig + decryptData. */
void buckets_config_sys_set_kms(buckets_config_sys *s, buckets_kms *k) { s->kms = k; }

/* saveConfig with the KMS's seal when there is one */
static buckets_obj_err write_sealed(buckets_config_sys *s, const char *path, const char *data, size_t n) {
  if (!s->kms) return buckets_sysconfig_write(s->layer, path, data, n);
  buckets_buf sealed = BUCKETS_BUF_INIT;
  buckets_obj_err e = buckets_cfgcrypt_seal(s->kms, path, data, n, &sealed)
                          ? buckets_sysconfig_write(s->layer, path, sealed.data, sealed.len)
                          : BUCKETS_OBJ_ERR_IO;
  buckets_buf_free(&sealed);
  return e;
}

static buckets_obj_err read_decrypted(buckets_config_sys *s, const char *path, buckets_buf *out, int64_t *mtime) {
  buckets_obj_err e = buckets_sysconfig_read(s->layer, path, out, mtime);
  if (e || utf8_valid((const uint8_t *)out->data, out->len)) return e;
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (!buckets_madmin_decrypt(s->password, out->data, out->len, &plain) &&
      !(s->kms && (buckets_buf_reset(&plain), buckets_cfgcrypt_open(s->kms, path, out->data, out->len, &plain)))) {
    buckets_buf_free(&plain);
    return BUCKETS_OBJ_ERR_CORRUPT;
  }
  buckets_buf_free(out);
  *out = plain;
  return BUCKETS_OBJ_OK;
}

static buckets_config *read_config(buckets_config_sys *s, char *err, size_t errlen, bool *io_error) {
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_obj_err e = read_decrypted(s, CONFIG_FILE, &data, NULL);
  buckets_config *c = NULL;
  *io_error = false;
  if (e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) {
    c = buckets_config_new();
  } else if (e) {
    snprintf(err, errlen, "reading %s: %s", CONFIG_FILE, buckets_obj_strerror(e));
    *io_error = true;
  } else {
    c = buckets_config_from_json(data.data, data.len, err, errlen);
  }
  buckets_buf_free(&data);
  return c;
}

bool buckets_config_sys_load(buckets_config_sys *s, buckets_objlayer *layer, char *err, size_t errlen) {
  s->layer = layer;
  bool io;
  buckets_config *c = read_config(s, err, errlen, &io);
  if (!c) return false;
  pthread_rwlock_wrlock(&s->lock);
  buckets_config_free(s->cfg);
  s->cfg = c;
  pthread_rwlock_unlock(&s->lock);
  return true;
}

bool buckets_config_sys_reload(buckets_config_sys *s) {
  char err[256];
  if (!s->layer || !buckets_config_sys_load(s, s->layer, err, sizeof(err))) return false;
  if (s->hook) s->hook(s->hook_ud, "", false);
  return true;
}

buckets_config *buckets_config_sys_snapshot(buckets_config_sys *s) {
  pthread_rwlock_rdlock(&s->lock);
  buckets_config *c = buckets_config_clone(s->cfg);
  pthread_rwlock_unlock(&s->lock);
  return c;
}

char *buckets_config_sys_value(buckets_config_sys *s, const char *subsys, const char *target, const char *key) {
  pthread_rwlock_rdlock(&s->lock);
  char *v = buckets_config_get(s->cfg, subsys, target, key);
  pthread_rwlock_unlock(&s->lock);
  return v;
}

bool buckets_config_sys_update(buckets_config_sys *s, buckets_config *cfg, const char *history_kv, const char *subsys,
                               char *err, size_t errlen) {
  if (!s->layer) {
    snprintf(err, errlen, "server not initialized");
    buckets_config_free(cfg);
    return false;
  }
  char *json = buckets_config_to_json(cfg);
  buckets_obj_err e = write_sealed(s, CONFIG_FILE, json, strlen(json));
  free(json);
  if (!e && history_kv) {
    char id[BUCKETS_UUID_STR_LEN + 1], path[128];
    buckets_uuid_v4(id);
    snprintf(path, sizeof(path), HISTORY_PREFIX "%s.kv", id);
    e = write_sealed(s, path, history_kv, strlen(history_kv));
  }
  if (e) {
    snprintf(err, errlen, "saving the configuration: %s", buckets_obj_strerror(e));
    buckets_config_free(cfg);
    return false;
  }
  pthread_rwlock_wrlock(&s->lock);
  buckets_config_free(s->cfg);
  s->cfg = cfg;
  pthread_rwlock_unlock(&s->lock);
  if (s->hook) s->hook(s->hook_ud, subsys ? subsys : "", true);
  return true;
}

void buckets_config_history_free(buckets_config_history *h, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(h[i].restore_id);
    free(h[i].data);
  }
  free(h);
}

static int cmp_hist(const void *a, const void *b) {
  const buckets_config_history *x = a, *y = b;
  return x->create_ns < y->create_ns ? -1 : x->create_ns > y->create_ns;
}

size_t buckets_config_sys_history(buckets_config_sys *s, int count, bool with_data, buckets_config_history **out) {
  *out = NULL;
  if (!s->layer) return 0;
  char **names;
  size_t n;
  if (buckets_sysconfig_list(s->layer, HISTORY_PREFIX, false, &names, &n)) return 0;
  buckets_config_history *h = buckets_xcalloc(n ? n : 1, sizeof(*h));
  size_t k = 0;
  for (size_t i = 0; i < n && (count < 0 || (int)k < count); i++) {
    size_t len = strlen(names[i]);
    if (len <= 3 || strcmp(names[i] + len - 3, ".kv") != 0) continue;
    char path[256];
    snprintf(path, sizeof(path), HISTORY_PREFIX "%s", names[i]);
    buckets_buf data = BUCKETS_BUF_INIT;
    int64_t mtime = 0;
    if (read_decrypted(s, path, &data, &mtime)) {
      buckets_buf_free(&data);
      continue;
    }
    h[k].restore_id = buckets_xstrndup(names[i], len - 3);
    h[k].create_ns = mtime;
    h[k].data = with_data ? buckets_buf_detach(&data) : NULL;
    buckets_buf_free(&data);
    k++;
  }
  buckets_sysconfig_names_free(names, n);
  qsort(h, k, sizeof(*h), cmp_hist);
  *out = h;
  return k;
}

bool buckets_config_sys_history_read(buckets_config_sys *s, const char *restore_id, buckets_buf *out) {
  if (!s->layer || strchr(restore_id, '/')) return false;
  char path[256];
  snprintf(path, sizeof(path), HISTORY_PREFIX "%s.kv", restore_id);
  return read_decrypted(s, path, out, NULL) == BUCKETS_OBJ_OK;
}

bool buckets_config_sys_history_delete(buckets_config_sys *s, const char *restore_id) {
  if (!s->layer || strchr(restore_id, '/')) return false;
  char path[256];
  snprintf(path, sizeof(path), HISTORY_PREFIX "%s.kv", restore_id);
  buckets_obj_err e = buckets_sysconfig_delete(s->layer, path);
  return e == BUCKETS_OBJ_OK || e == BUCKETS_OBJ_ERR_NO_SUCH_KEY;
}
