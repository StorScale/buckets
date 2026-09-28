/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/metadata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/msgpack.h"
#include "object/object.h"

#define FORMAT 1
#define VERSION 1

/* tinylib/msgp field order of BucketMetadata. */
static const char *const k_config_fields[BUCKETS_BCFG__COUNT] = {
    "PolicyConfigJSON",   "NotificationConfigXML", "LifecycleConfigXML",   "ObjectLockConfigXML",
    "VersioningConfigXML", "EncryptionConfigXML",  "TaggingConfigXML",     "QuotaConfigJSON",
    "ReplicationConfigXML", "BucketTargetsConfigJSON", "BucketTargetsConfigMetaJSON",
};
/* The *UpdatedAt fields come in a different order than the configs. */
static const struct {
  const char *field;
  buckets_bucket_cfg cfg;
} k_updated_fields[BUCKETS_BCFG__COUNT] = {
    {"PolicyConfigUpdatedAt", BUCKETS_BCFG_POLICY},
    {"ObjectLockConfigUpdatedAt", BUCKETS_BCFG_OBJECT_LOCK},
    {"EncryptionConfigUpdatedAt", BUCKETS_BCFG_ENCRYPTION},
    {"TaggingConfigUpdatedAt", BUCKETS_BCFG_TAGGING},
    {"QuotaConfigUpdatedAt", BUCKETS_BCFG_QUOTA},
    {"ReplicationConfigUpdatedAt", BUCKETS_BCFG_REPLICATION},
    {"VersioningConfigUpdatedAt", BUCKETS_BCFG_VERSIONING},
    {"LifecycleConfigUpdatedAt", BUCKETS_BCFG_LIFECYCLE},
    {"NotificationConfigUpdatedAt", BUCKETS_BCFG_NOTIFICATION},
    {"BucketTargetsConfigUpdatedAt", BUCKETS_BCFG_TARGETS},
    {"BucketTargetsConfigMetaUpdatedAt", BUCKETS_BCFG_TARGETS_META},
};

static const buckets_gotime k_zero = {BUCKETS_GO_ZERO_TIME_SEC, 0};

void buckets_bucket_meta_init(buckets_bucket_meta *m, const char *name, int64_t created_ns) {
  memset(m, 0, sizeof(*m));
  m->name = buckets_xstrdup(name);
  m->created = created_ns ? (buckets_gotime){created_ns / 1000000000LL, (int32_t)(created_ns % 1000000000LL)} : k_zero;
  for (int i = 0; i < BUCKETS_BCFG__COUNT; i++) m->updated[i] = k_zero;
}

void buckets_bucket_meta_free(buckets_bucket_meta *m) {
  free(m->name);
  for (int i = 0; i < BUCKETS_BCFG__COUNT; i++) buckets_buf_free(&m->config[i]);
  memset(m, 0, sizeof(*m));
}

int64_t buckets_bucket_meta_created_ns(const buckets_bucket_meta *m) {
  if (m->created.sec == BUCKETS_GO_ZERO_TIME_SEC) return 0;
  return m->created.sec * 1000000000LL + m->created.nsec;
}

void buckets_bucket_meta_encode(const buckets_bucket_meta *m, buckets_buf *out) {
  uint8_t hdr[4] = {FORMAT, 0, VERSION, 0};
  buckets_buf_append(out, hdr, 4);
  buckets_mp_map(out, 3 + 2 * BUCKETS_BCFG__COUNT); /* 25 fields, always map16 like msgp */
  buckets_mp_cstr(out, "Name");
  buckets_mp_cstr(out, m->name ? m->name : "");
  buckets_mp_cstr(out, "Created");
  buckets_mp_time_sec(out, m->created.sec, m->created.nsec);
  buckets_mp_cstr(out, "LockEnabled");
  buckets_mp_bool(out, m->lock_enabled);
  for (int i = 0; i < BUCKETS_BCFG__COUNT; i++) {
    buckets_mp_cstr(out, k_config_fields[i]);
    buckets_mp_bin(out, m->config[i].data ? m->config[i].data : "", m->config[i].len);
  }
  for (int i = 0; i < BUCKETS_BCFG__COUNT; i++) {
    const buckets_gotime *t = &m->updated[k_updated_fields[i].cfg];
    buckets_mp_cstr(out, k_updated_fields[i].field);
    buckets_mp_time_sec(out, t->sec, t->nsec);
  }
}

bool buckets_bucket_meta_decode(const void *data, size_t n, buckets_bucket_meta *m) {
  const uint8_t *p = data;
  memset(m, 0, sizeof(*m));
  m->created = k_zero;
  for (int i = 0; i < BUCKETS_BCFG__COUNT; i++) m->updated[i] = k_zero;
  if (n <= 4 || (p[0] | p[1] << 8) != FORMAT || (p[2] | p[3] << 8) != VERSION) return false;
  buckets_mp_reader r = buckets_mp_reader_init(p + 4, n - 4);
  uint32_t fields;
  if (!buckets_mp_read_map(&r, &fields)) return false;
  for (uint32_t f = 0; f < fields; f++) {
    buckets_str key, v;
    if (!buckets_mp_read_str(&r, &key)) goto fail;
    bool handled = false;
    if (buckets_str_eq_c(key, "Name")) {
      if (!buckets_mp_read_str(&r, &v)) goto fail;
      free(m->name);
      m->name = buckets_str_dup(v);
      handled = true;
    } else if (buckets_str_eq_c(key, "Created")) {
      if (!buckets_mp_read_time_sec(&r, &m->created.sec, &m->created.nsec)) goto fail;
      handled = true;
    } else if (buckets_str_eq_c(key, "LockEnabled")) {
      if (!buckets_mp_read_bool(&r, &m->lock_enabled)) goto fail;
      handled = true;
    }
    for (int i = 0; !handled && i < BUCKETS_BCFG__COUNT; i++) {
      if (buckets_str_eq_c(key, k_config_fields[i])) {
        if (!buckets_mp_read_nil(&r)) {
          if (!buckets_mp_read_bin(&r, &v)) goto fail;
          buckets_buf_reset(&m->config[i]);
          buckets_buf_append(&m->config[i], v.p, v.n);
        }
        handled = true;
      }
    }
    for (int i = 0; !handled && i < BUCKETS_BCFG__COUNT; i++) {
      if (buckets_str_eq_c(key, k_updated_fields[i].field)) {
        buckets_gotime *t = &m->updated[k_updated_fields[i].cfg];
        if (!buckets_mp_read_time_sec(&r, &t->sec, &t->nsec)) goto fail;
        handled = true;
      }
    }
    if (!handled && !buckets_mp_skip(&r)) goto fail;
  }
  if (!r.err) return true;
fail:
  buckets_bucket_meta_free(m);
  return false;
}

/* ---- persistence ------------------------------------------------------------ */

static char *meta_object(const char *bucket) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "buckets/%s/.metadata.bin", bucket);
  return p.data;
}

static long mem_read(void *ud, void *buf, size_t n) {
  buckets_str *s = ud;
  size_t take = BUCKETS_MIN(n, s->n);
  memcpy(buf, s->p, take);
  s->p += take;
  s->n -= take;
  return (long)take;
}

bool buckets_bucket_meta_load(buckets_drive *d, const char *bucket, buckets_bucket_meta *m) {
  char *obj = meta_object(bucket);
  buckets_obj_reader *r;
  buckets_object_info oi;
  bool ok = false;
  if (buckets_obj_open(d, BUCKETS_META_BUCKET, obj, NULL, 0, INT64_MAX, &r, &oi) == BUCKETS_OBJ_OK) {
    buckets_buf data = BUCKETS_BUF_INIT;
    buckets_buf_reserve(&data, (size_t)oi.size);
    char tmp[16384];
    long n;
    while ((n = buckets_obj_read(r, tmp, sizeof(tmp))) > 0) buckets_buf_append(&data, tmp, (size_t)n);
    ok = n == 0 && buckets_bucket_meta_decode(data.data, data.len, m);
    buckets_buf_free(&data);
    buckets_obj_reader_free(r);
    buckets_object_info_free(&oi);
  }
  free(obj);
  return ok;
}

bool buckets_bucket_meta_save(buckets_drive *d, const buckets_bucket_meta *m) {
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_bucket_meta_encode(m, &data);
  char *obj = meta_object(m->name);
  buckets_str src = buckets_buf_str(&data);
  /* MinIO's saveConfig stores it like any object: content-type from the .bin extension. */
  buckets_xl_kv ct = {"content-type", (uint8_t *)"application/octet-stream", 24};
  buckets_put_opts opts = {.meta = &ct, .nmeta = 1};
  bool ok = buckets_obj_put(d, BUCKETS_META_BUCKET, obj, mem_read, &src, (int64_t)data.len, &opts, NULL) ==
            BUCKETS_OBJ_OK;
  free(obj);
  buckets_buf_free(&data);
  return ok;
}

void buckets_bucket_meta_delete(buckets_drive *d, const char *bucket) {
  char *obj = meta_object(bucket);
  buckets_obj_delete(d, BUCKETS_META_BUCKET, obj, NULL);
  free(obj);
}
