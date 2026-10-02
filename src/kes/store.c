/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "kes/store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "core/common.h"

/* ---- helpers --------------------------------------------------------------------- */

const char *buckets_kes_conf_str(yyjson_val *o, const char *path) {
  char key[64];
  while (o && *path) {
    const char *dot = strchr(path, '.');
    size_t n = dot ? (size_t)(dot - path) : strlen(path);
    snprintf(key, sizeof(key), "%.*s", (int)n, path);
    o = yyjson_obj_get(o, key);
    path = dot ? dot + 1 : path + n;
  }
  return yyjson_get_str(o);
}

bool buckets_kes_valid_name(const char *s) {
  size_t n = strlen(s);
  if (!n || n > 80 || strcmp(s, "_") == 0) return false;
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
              (c == '-' && i > 0 && i < n - 1);
    if (!ok) return false;
  }
  return true;
}

void buckets_kes_error_text(const char *body, size_t n, char *out, size_t cap) {
  *out = '\0';
  yyjson_doc *d = n ? yyjson_read(body, n, 0) : NULL;
  yyjson_val *r = yyjson_doc_get_root(d);
  yyjson_val *errs = yyjson_obj_get(r, "errors"); /* Vault */
  yyjson_val *e = yyjson_obj_get(r, "error");     /* Azure {"error": {"code", "message"}}, GCP likewise */
  const char *m = NULL;
  if (yyjson_is_arr(errs)) m = yyjson_get_str(yyjson_arr_get_first(errs));
  else if (yyjson_is_obj(e)) m = yyjson_get_str(yyjson_obj_get(e, "message"));
  else if (yyjson_is_str(e)) m = yyjson_get_str(e);
  if (!m) m = yyjson_get_str(yyjson_obj_get(r, "message"));
  if (!m) m = yyjson_get_str(yyjson_obj_get(r, "Message")); /* AWS */
  if (m) snprintf(out, cap, "%s", m);
  else if (n) snprintf(out, cap, "%.*s", (int)(n > 300 ? 300 : n), body);
  yyjson_doc_free(d);
}

buckets_kes_store *buckets_kes_store_open(yyjson_val *ks, char *err, size_t errlen) {
  if (!yyjson_is_obj(ks) || yyjson_obj_size(ks) != 1) {
    snprintf(err, errlen, "kesconf: invalid keystore config: specify exactly one key store");
    return NULL;
  }
  yyjson_val *conf;
  if ((conf = yyjson_obj_get(ks, "fs"))) return buckets_kes_fs_open(conf, err, errlen);
  if ((conf = yyjson_obj_get(ks, "vault"))) return buckets_kes_vault_open(conf, err, errlen);
  if ((conf = yyjson_obj_get(yyjson_obj_get(ks, "aws"), "secretsmanager"))) return buckets_kes_aws_open(conf, err, errlen);
  if ((conf = yyjson_obj_get(yyjson_obj_get(ks, "azure"), "keyvault"))) return buckets_kes_azure_open(conf, err, errlen);
  if ((conf = yyjson_obj_get(yyjson_obj_get(ks, "gcp"), "secretmanager"))) return buckets_kes_gcp_open(conf, err, errlen);
  snprintf(err, errlen, "kesconf: unsupported key store: buckets-kes keeps keys in fs, vault, aws, azure or gcp");
  return NULL;
}

void buckets_kes_store_close(buckets_kes_store *s) {
  if (s) s->ops->close(s);
}

/* ---- fs: one file per key, named after it (MinIO KES's FS key store) --------------------- */

typedef struct {
  buckets_kes_store base;
  char *dir;
} fs_store;

static char *fs_path(fs_store *f, const char *name) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", f->dir, name);
  return p.data;
}

static buckets_kes_status fs_status(buckets_kes_store *s, int64_t *lat, char *err, size_t errlen) {
  fs_store *f = (fs_store *)s;
  struct stat st;
  *lat = 1;
  if (stat(f->dir, &st) != 0) return snprintf(err, errlen, "fs: %s: %s", f->dir, strerror(errno)), BUCKETS_KES_UNREACHABLE;
  return BUCKETS_KES_OK;
}

static buckets_kes_status fs_create(buckets_kes_store *s, const char *name, const char *v, size_t n, char *err,
                                    size_t errlen) {
  char *p = fs_path((fs_store *)s, name);
  int fd = open(p, O_CREAT | O_EXCL | O_WRONLY, 0600);
  buckets_kes_status st = BUCKETS_KES_OK;
  if (fd < 0) {
    st = errno == EEXIST ? BUCKETS_KES_EXISTS : BUCKETS_KES_FAILED;
    if (st == BUCKETS_KES_FAILED) snprintf(err, errlen, "fs: failed to create '%s': %s", p, strerror(errno));
  } else {
    bool ok = write(fd, v, n) == (ssize_t)n && fsync(fd) == 0;
    close(fd);
    if (!ok) {
      unlink(p);
      snprintf(err, errlen, "fs: failed to write '%s'", p);
      st = BUCKETS_KES_FAILED;
    }
  }
  free(p);
  return st;
}

static buckets_kes_status fs_get(buckets_kes_store *s, const char *name, buckets_buf *out, char *err, size_t errlen) {
  char *p = fs_path((fs_store *)s, name);
  FILE *f = fopen(p, "r");
  buckets_kes_status st = BUCKETS_KES_OK;
  if (!f) {
    st = errno == ENOENT ? BUCKETS_KES_NOT_FOUND : BUCKETS_KES_FAILED;
    if (st == BUCKETS_KES_FAILED) snprintf(err, errlen, "fs: failed to read '%s': %s", p, strerror(errno));
  } else {
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(out, tmp, n);
    fclose(f);
  }
  free(p);
  return st;
}

static buckets_kes_status fs_del(buckets_kes_store *s, const char *name, char *err, size_t errlen) {
  char *p = fs_path((fs_store *)s, name);
  buckets_kes_status st = BUCKETS_KES_OK;
  if (unlink(p) != 0) {
    st = errno == ENOENT ? BUCKETS_KES_NOT_FOUND : BUCKETS_KES_FAILED;
    if (st == BUCKETS_KES_FAILED) snprintf(err, errlen, "fs: failed to delete '%s': %s", p, strerror(errno));
  }
  free(p);
  return st;
}

static buckets_kes_status fs_list(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen) {
  fs_store *f = (fs_store *)s;
  *names = NULL, *n = 0;
  DIR *d = opendir(f->dir);
  if (!d) return snprintf(err, errlen, "fs: failed to list '%s': %s", f->dir, strerror(errno)), BUCKETS_KES_FAILED;
  size_t cap = 0;
  for (struct dirent *e; (e = readdir(d)) != NULL;) {
    if (e->d_name[0] == '.' || !buckets_kes_valid_name(e->d_name)) continue;
    if (*n == cap) *names = buckets_xrealloc(*names, (cap = cap ? 2 * cap : 16) * sizeof(char *));
    (*names)[(*n)++] = buckets_xstrdup(e->d_name);
  }
  closedir(d);
  return BUCKETS_KES_OK;
}

static void fs_close(buckets_kes_store *s) {
  fs_store *f = (fs_store *)s;
  free(f->dir);
  free(f);
}

static const buckets_kes_store_ops fs_ops = {fs_status, fs_create, fs_get, fs_del, fs_list, fs_close};

buckets_kes_store *buckets_kes_fs_open(yyjson_val *conf, char *err, size_t errlen) {
  const char *dir = buckets_kes_conf_str(conf, "path");
  if (!dir || !*dir) return snprintf(err, errlen, "kesconf: invalid fs keystore: no path specified"), NULL;
  if (mkdir(dir, 0755) != 0 && errno != EEXIST)
    return snprintf(err, errlen, "fs: failed to create '%s': %s", dir, strerror(errno)), NULL;
  fs_store *f = buckets_xcalloc(1, sizeof(*f));
  f->base.ops = &fs_ops;
  snprintf(f->base.desc, sizeof(f->base.desc), "Filesystem: %s", dir);
  f->dir = buckets_xstrdup(dir);
  return &f->base;
}
