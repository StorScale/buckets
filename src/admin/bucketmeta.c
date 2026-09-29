/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin cluster bucket export|import: every bucket's configurations in a
 * zip (<bucket>/<config file>), each written as MinIO marshals the parsed
 * configuration, and read back with MinIO's order and rules (object lock
 * first, then versioning, then the rest; replication and remote targets are
 * exported but not imported). Replaces MinIO's ExportBucketMetadataHandler
 * and ImportBucketMetadataHandler (cmd/admin-bucket-handlers.go). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "admin/admin.h"
#include "bucket/lifecycle.h"
#include "bucket/metadata.h"
#include "bucket/metasys.h"
#include "bucket/notification.h"
#include "bucket/objectlock.h"
#include "bucket/quota.h"
#include "bucket/replication.h"
#include "bucket/sseconfig.h"
#include "bucket/tags.h"
#include "bucket/targets.h"
#include "bucket/versioning.h"
#include "core/zipwrite.h"
#include "iam/policy.h"
#include "notify/event.h"
#include "notify/notifier.h"
#include "s3/zipindex.h"
#include "siterepl/siterepl.h"
#include "tier/tier.h"

#define F_POLICY "policy.json"
#define F_NOTIFICATION "notification.xml"
#define F_LIFECYCLE "lifecycle.xml"
#define F_SSE "bucket-encryption.xml"
#define F_TAGGING "tagging.xml"
#define F_QUOTA "quota.json"
#define F_OBJECT_LOCK "object-lock.xml"
#define F_VERSIONING "versioning.xml"
#define F_REPLICATION "replication.xml"
#define F_TARGETS "bucket-targets.json"

#define NOTIFY_EMPTY "<NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></NotificationConfiguration>"

/* ---- export ------------------------------------------------------------------------------------- */

static void add(buckets_zipw *z, const char *bucket, const char *file, const buckets_buf *data, time_t now) {
  char name[1100];
  snprintf(name, sizeof(name), "%s/%s", bucket, file);
  buckets_zipw_add(z, name, data->data ? data->data : "", data->len, now);
}

static void export_bucket(buckets_s3_server *s, buckets_zipw *z, const char *bucket, time_t now) {
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  buckets_buf b = BUCKETS_BUF_INIT;
  const buckets_buf *cfg = st->meta.config;
  /* policy */
  if (cfg[BUCKETS_BCFG_POLICY].len) {
    buckets_policy *p;
    char err[256];
    if (buckets_bucket_policy_parse(cfg[BUCKETS_BCFG_POLICY].data, cfg[BUCKETS_BCFG_POLICY].len, bucket, &p, err,
                                    sizeof(err))) {
      buckets_bucket_policy_json(p, &b);
      buckets_policy_free(p);
      add(z, bucket, F_POLICY, &b, now);
    }
  }
  /* notification: always (an empty configuration when none) */
  buckets_buf_reset(&b);
  if (st->has_notify) buckets_notify_config_xml(&st->notify, s->region, &b);
  else buckets_buf_append_c(&b, NOTIFY_EMPTY);
  add(z, bucket, F_NOTIFICATION, &b, now);
  if (st->has_lifecycle) {
    buckets_buf_reset(&b);
    buckets_lifecycle_xml(&st->lifecycle, true, &b);
    add(z, bucket, F_LIFECYCLE, &b, now);
  }
  if (st->has_sse) {
    buckets_buf_reset(&b);
    buckets_sse_config_xml(&st->sse, &b);
    add(z, bucket, F_SSE, &b, now);
  }
  if (cfg[BUCKETS_BCFG_TAGGING].len) {
    buckets_tags t;
    buckets_tags_error te;
    if (buckets_tags_parse_xml(cfg[BUCKETS_BCFG_TAGGING].data, cfg[BUCKETS_BCFG_TAGGING].len, false, &t, &te)) {
      buckets_buf_reset(&b);
      buckets_tags_xml(&t, &b);
      buckets_tags_free(&t);
      add(z, bucket, F_TAGGING, &b, now);
    }
  }
  /* quota: always (the zero quota when none) */
  buckets_buf_reset(&b);
  buckets_quota q;
  memset(&q, 0, sizeof(q));
  if (st->has_quota) q = st->quota;
  buckets_quota_json(&q, &b);
  add(z, bucket, F_QUOTA, &b, now);
  if (cfg[BUCKETS_BCFG_OBJECT_LOCK].len) {
    buckets_lock_config lc;
    char err[256];
    if (buckets_lock_config_parse(cfg[BUCKETS_BCFG_OBJECT_LOCK].data, cfg[BUCKETS_BCFG_OBJECT_LOCK].len, &lc, err,
                                  sizeof(err))) {
      buckets_buf_reset(&b);
      buckets_lock_config_xml(&lc, &b);
      add(z, bucket, F_OBJECT_LOCK, &b, now);
    }
  }
  /* versioning: only Enabled or Suspended */
  if (st->versioning.status == BUCKETS_VERSIONING_ENABLED || st->versioning.status == BUCKETS_VERSIONING_SUSPENDED) {
    buckets_buf_reset(&b);
    buckets_versioning_xml(&st->versioning, &b);
    add(z, bucket, F_VERSIONING, &b, now);
  }
  if (st->has_replication) {
    buckets_buf_reset(&b);
    buckets_replication_xml(&st->replication, &b);
    add(z, bucket, F_REPLICATION, &b, now);
  }
  /* remote targets: always, credentials and all */
  buckets_buf_reset(&b);
  buckets_bucket_targets_xml(&st->targets, &b);
  add(z, bucket, F_TARGETS, &b, now);
  buckets_buf_free(&b);
  buckets_bucket_state_release(st);
}

static int by_name(const void *a, const void *b) {
  return strcmp(((const buckets_bucket_info *)a)->name, ((const buckets_bucket_info *)b)->name);
}

/* path.Clean, "." being nothing (pathClean) */
static char *path_clean(const char *p) {
  size_t n = strlen(p);
  buckets_buf b = BUCKETS_BUF_INIT;
  const char *s = p;
  bool rooted = *s == '/';
  char **parts = NULL;
  size_t np = 0;
  while (*s) {
    while (*s == '/') s++;
    const char *e = s;
    while (*e && *e != '/') e++;
    size_t l = (size_t)(e - s);
    if (l == 1 && s[0] == '.') {
    } else if (l == 2 && s[0] == '.' && s[1] == '.') {
      if (np && strcmp(parts[np - 1], "..") != 0) free(parts[--np]);
      else if (!rooted) {
        parts = buckets_xrealloc(parts, (np + 1) * sizeof(char *));
        parts[np++] = buckets_xstrdup("..");
      }
    } else if (l) {
      parts = buckets_xrealloc(parts, (np + 1) * sizeof(char *));
      parts[np++] = buckets_xstrndup(s, l);
    }
    s = e;
  }
  if (rooted) buckets_buf_append_char(&b, '/');
  for (size_t i = 0; i < np; i++) {
    if (i) buckets_buf_append_char(&b, '/');
    buckets_buf_append_c(&b, parts[i]);
    free(parts[i]);
  }
  free(parts);
  buckets_buf_append_char(&b, '\0');
  (void)n;
  if (strcmp(b.data, ".") == 0 || !*b.data) b.data[0] = '\0';
  return b.data;
}

void buckets_admin_export_bucket_metadata(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ExportBucketMetadata")) return;
  buckets_s3_server *s = c->s;
  const char *qb = buckets_query_get(&c->q, "bucket");
  char *bucket = path_clean(qb ? qb : "");
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (*bucket) {
    buckets_obj_err e = buckets_obj_stat_bucket(s->layer, bucket);
    if (e) {
      const buckets_s3_error_info *ei = buckets_s3_error_get(buckets_s3_obj_error(e));
      buckets_admin_json_error(c, ei->status, ei->code, ei->message, NULL, NULL);
      free(bucket);
      return;
    }
    bk = buckets_xcalloc(1, sizeof(*bk));
    bk->name = buckets_xstrdup(bucket);
    nb = 1;
  } else if (buckets_obj_list_buckets(s->layer, &bk, &nb) != BUCKETS_OBJ_OK) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    free(bucket);
    return;
  } else {
    size_t k = 0;
    for (size_t i = 0; i < nb; i++) {
      if (*bk[i].name == '.') {
        free(bk[i].name);
        continue;
      }
      bk[k++] = bk[i];
    }
    nb = k;
    qsort(bk, nb, sizeof(*bk), by_name);
  }
  buckets_buf_reset(&c->resp->body);
  buckets_zipw *z = buckets_zipw_new(&c->resp->body);
  time_t now = time(NULL);
  for (size_t i = 0; i < nb; i++) export_bucket(s, z, bk[i].name, now);
  buckets_zipw_finish(z);
  buckets_bucket_info_free(bk, nb);
  free(bucket);
  c->resp->status = 200;
}

/* ---- import ------------------------------------------------------------------------------------- */

enum { S_OLOCK, S_VERSIONING, S_POLICY, S_TAGGING, S_SSE, S_LIFECYCLE, S_NOTIFICATION, S_QUOTA, S_CORS, S__N };
static const char *const k_status_keys[S__N] = {"olock",     "versioning",   "policy", "tagging", "sse",
                                                "lifecycle", "notification", "quota",  "cors"};

typedef struct {
  char *bucket;
  bool set[S__N];
  char *err[S__N];
  char *bucket_err;
} bucket_status;

typedef struct {
  bucket_status *v;
  size_t n;
} report;

typedef struct {
  char *bucket;
  buckets_bucket_meta meta;
  bool created; /* by this import */
} imported;

typedef struct {
  imported *v;
  size_t n;
} bucket_map;

static bucket_status *status_of(report *r, const char *bucket) {
  for (size_t i = 0; i < r->n; i++)
    if (strcmp(r->v[i].bucket, bucket) == 0) return &r->v[i];
  r->v = buckets_xrealloc(r->v, (r->n + 1) * sizeof(*r->v));
  bucket_status *st = &r->v[r->n++];
  memset(st, 0, sizeof(*st));
  st->bucket = buckets_xstrdup(bucket);
  return st;
}

/* importMetaReport.SetStatus */
static void set_status(report *r, const char *bucket, const char *file, const char *err) {
  bucket_status *st = status_of(r, bucket);
  int k = -1;
  if (strcmp(file, F_POLICY) == 0) k = S_POLICY;
  else if (strcmp(file, F_NOTIFICATION) == 0) k = S_NOTIFICATION;
  else if (strcmp(file, F_LIFECYCLE) == 0) k = S_LIFECYCLE;
  else if (strcmp(file, F_SSE) == 0) k = S_SSE;
  else if (strcmp(file, F_TAGGING) == 0) k = S_TAGGING;
  else if (strcmp(file, F_QUOTA) == 0) k = S_QUOTA;
  else if (strcmp(file, F_OBJECT_LOCK) == 0) k = S_OLOCK;
  else if (strcmp(file, F_VERSIONING) == 0) k = S_VERSIONING;
  if (k < 0) {
    free(st->bucket_err);
    st->bucket_err = buckets_xstrdup(err ? err : "");
    return;
  }
  st->set[k] = true;
  free(st->err[k]);
  st->err[k] = err && *err ? buckets_xstrdup(err) : NULL;
}

static imported *map_get(bucket_map *m, const char *bucket) {
  for (size_t i = 0; i < m->n; i++)
    if (strcmp(m->v[i].bucket, bucket) == 0) return &m->v[i];
  return NULL;
}

static imported *map_add(bucket_map *m, const char *bucket) {
  m->v = buckets_xrealloc(m->v, (m->n + 1) * sizeof(*m->v));
  imported *im = &m->v[m->n++];
  memset(im, 0, sizeof(*im));
  im->bucket = buckets_xstrdup(bucket);
  return im;
}

/* MakeBucket with ForceCreate (fine if it exists), then the bucket's
 * metadata as the metadata system has it. NULL on failure (err set). */
static imported *ensure_bucket(buckets_s3_server *s, bucket_map *m, const char *bucket, bool lock, char *err,
                               size_t errlen) {
  imported *im = map_get(m, bucket);
  if (im) return im;
  buckets_obj_err e = buckets_obj_make_bucket(s->layer, bucket);
  if (e && e != BUCKETS_OBJ_ERR_BUCKET_EXISTS) {
    snprintf(err, errlen, "%s", buckets_obj_strerror(e));
    return NULL;
  }
  im = map_add(m, bucket);
  if (!buckets_bucket_meta_load(s->layer, bucket, &im->meta)) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    buckets_bucket_meta_init(&im->meta, bucket, (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    if (lock) { /* MakeBucket with LockEnabled: versioning on, locking on */
      buckets_buf_append_c(&im->meta.config[BUCKETS_BCFG_VERSIONING],
                           "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>");
      buckets_buf_append_c(&im->meta.config[BUCKETS_BCFG_OBJECT_LOCK],
                           "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>");
    }
  }
  im->created = true;
  return im;
}

typedef struct {
  const uint8_t *data;
  size_t len;
  int64_t off;
} mem_src;

static long mem_read(void *ud, void *buf, size_t n) {
  mem_src *m = ud;
  if (m->off >= (int64_t)m->len) return 0;
  size_t left = m->len - (size_t)m->off;
  if (n > left) n = left;
  memcpy(buf, m->data + m->off, n);
  m->off += (int64_t)n;
  return (long)n;
}

/* A file's contents; false when it cannot be read. */
static bool zip_file(const uint8_t *zip, size_t zlen, const buckets_zipfile *f, buckets_buf *out) {
  mem_src src = {zip, zlen, f->offset};
  buckets_zip_reader *r = buckets_zip_reader_new(f, mem_read, &src);
  if (!r) return false;
  char buf[16384];
  long n;
  while ((n = buckets_zip_reader_read(r, buf, sizeof(buf))) > 0) buckets_buf_append(out, buf, (size_t)n);
  buckets_zip_reader_free(r);
  return n == 0;
}

static void set_cfg(imported *im, buckets_bucket_cfg k, const buckets_buf *data, buckets_gotime now) {
  buckets_buf_reset(&im->meta.config[k]);
  buckets_buf_append(&im->meta.config[k], data->data ? data->data : "", data->len);
  im->meta.updated[k] = now;
}

static bool tier_valid(void *ud, const char *tier) { return buckets_tiers_valid(((buckets_s3_server *)ud)->tiers, tier); }

static const char *malformed(char *out, size_t cap, const char *err) {
  snprintf(out, cap, "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_MALFORMED_XML)->message, err);
  return out;
}

void buckets_admin_import_bucket_metadata(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:ImportBucketMetadata")) return;
  buckets_s3_server *s = c->s;
  buckets_s3_error de = buckets_s3_read_doc(c);
  if (de) {
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  const uint8_t *zip = (const uint8_t *)(c->doc.data ? c->doc.data : "");
  size_t zlen = c->doc.len;
  buckets_zipfiles files = {0};
  int64_t need = 0;
  char zerr[256];
  if (buckets_zipindex_read_dir(zip, zlen, (int64_t)zlen, &files, &need, zerr, sizeof(zerr)) != BUCKETS_ZIP_DIR_OK) {
    buckets_zipfiles_free(&files);
    buckets_admin_error(c, BUCKETS_ERR_INVALID_REQUEST);
    return;
  }
  report rpt = {0};
  bucket_map m = {0};
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  buckets_gotime now = {ts.tv_sec, (int32_t)ts.tv_nsec};
  char err[1024];
  static const char *const k_malformed_zip = "malformed zip - expecting format bucket/<config.json>";

  /* the buckets that exist, with their metadata */
  for (size_t i = 0; i < files.n; i++) {
    const char *name = files.f[i].name;
    const char *slash = strchr(name, '/');
    if (!slash || strchr(slash + 1, '/')) {
      set_status(&rpt, name, "", k_malformed_zip);
      continue;
    }
    char *bucket = buckets_xstrndup(name, (size_t)(slash - name));
    if (!map_get(&m, bucket)) {
      buckets_bucket_meta bm;
      if (buckets_obj_stat_bucket(s->layer, bucket) == BUCKETS_OBJ_OK && buckets_bucket_meta_load(s->layer, bucket, &bm)) {
        imported *im = map_add(&m, bucket);
        im->meta = bm;
      }
    }
    free(bucket);
  }

  /* three passes: object lock, versioning, then everything else */
  for (int pass = 0; pass < 3; pass++) {
    for (size_t i = 0; i < files.n; i++) {
      const char *name = files.f[i].name;
      const char *slash = strchr(name, '/');
      if (!slash || strchr(slash + 1, '/')) {
        if (pass < 2) set_status(&rpt, name, "", k_malformed_zip);
        continue;
      }
      char *bucket = buckets_xstrndup(name, (size_t)(slash - name));
      const char *file = slash + 1;
      buckets_buf data = BUCKETS_BUF_INIT;
      bool readable = zip_file(zip, zlen, &files.f[i], &data);
      if (pass == 0 && strcmp(file, F_OBJECT_LOCK) == 0) {
        buckets_lock_config lc;
        char perr[256];
        if (!readable) set_status(&rpt, bucket, file, "zip: not a valid zip file");
        else if (!buckets_lock_config_parse(data.data ? data.data : "", data.len, &lc, perr, sizeof(perr)))
          set_status(&rpt, bucket, file, malformed(err, sizeof(err), perr));
        else {
          imported *im = ensure_bucket(s, &m, bucket, lc.enabled, err, sizeof(err));
          if (!im) set_status(&rpt, bucket, file, err);
          else {
            buckets_buf x = BUCKETS_BUF_INIT;
            buckets_lock_config_xml(&lc, &x);
            set_cfg(im, BUCKETS_BCFG_OBJECT_LOCK, &x, now);
            buckets_buf_free(&x);
            set_status(&rpt, bucket, file, NULL);
          }
        }
      } else if (pass == 1 && strcmp(file, F_VERSIONING) == 0) {
        buckets_versioning v;
        char perr[256];
        if (!readable) set_status(&rpt, bucket, file, "zip: not a valid zip file");
        else if (!buckets_versioning_parse(data.data ? data.data : "", data.len, &v, perr, sizeof(perr)))
          set_status(&rpt, bucket, file, perr);
        else {
          imported *im = ensure_bucket(s, &m, bucket, false, err, sizeof(err));
          bool suspended = v.status == BUCKETS_VERSIONING_SUSPENDED;
          if (!im) set_status(&rpt, bucket, file, err);
          else if (suspended && buckets_sr_enabled(s->sr))
            set_status(&rpt, bucket, file,
                       "Cluster replication is enabled for this site, so the versioning state cannot be suspended.");
          else if (suspended && (im->meta.lock_enabled || im->meta.config[BUCKETS_BCFG_OBJECT_LOCK].len))
            set_status(&rpt, bucket, file,
                       "An Object Lock configuration is present on this bucket, so the versioning state cannot be "
                       "suspended.");
          else if (suspended && im->meta.config[BUCKETS_BCFG_REPLICATION].len)
            set_status(&rpt, bucket, file,
                       "A replication configuration is present on this bucket, so the versioning state cannot be "
                       "suspended.");
          else {
            buckets_buf x = BUCKETS_BUF_INIT;
            buckets_versioning_xml(&v, &x);
            set_cfg(im, BUCKETS_BCFG_VERSIONING, &x, now);
            buckets_buf_free(&x);
            set_status(&rpt, bucket, file, NULL);
          }
          buckets_versioning_free(&v);
        }
      } else if (pass == 2) {
        imported *im = ensure_bucket(s, &m, bucket, false, err, sizeof(err));
        if (!im) {
          set_status(&rpt, bucket, "", err);
        } else if (strcmp(file, F_NOTIFICATION) == 0) {
          buckets_notify_config nc;
          buckets_s3_error ne;
          char msg[512];
          if (!buckets_notify_config_parse(data.data ? data.data : "", data.len, s->region, buckets_notifier_exists,
                                           s->notifier, &nc, &ne, msg, sizeof(msg)))
            set_status(&rpt, bucket, file, malformed(err, sizeof(err), *msg ? msg : buckets_s3_error_get(ne)->message));
          else {
            buckets_buf x = BUCKETS_BUF_INIT;
            buckets_notify_config_xml(&nc, s->region, &x);
            buckets_notify_config_free(&nc);
            set_cfg(im, BUCKETS_BCFG_NOTIFICATION, &x, now);
            buckets_buf_free(&x);
            set_status(&rpt, bucket, file, NULL);
          }
        } else if (strcmp(file, F_POLICY) == 0) {
          buckets_policy *p;
          char perr[512];
          if (data.len > 20 * 1024) set_status(&rpt, bucket, file, "PolicyTooLarge");
          else if (!buckets_bucket_policy_parse(data.data ? data.data : "", data.len, bucket, &p, perr, sizeof(perr)))
            set_status(&rpt, bucket, file, perr);
          else {
            if (!*buckets_policy_version(p)) set_status(&rpt, bucket, file, "PolicyInvalidVersion");
            else {
              buckets_buf x = BUCKETS_BUF_INIT;
              buckets_bucket_policy_json(p, &x);
              set_cfg(im, BUCKETS_BCFG_POLICY, &x, now);
              buckets_buf_free(&x);
              set_status(&rpt, bucket, file, NULL);
            }
            buckets_policy_free(p);
          }
        } else if (strcmp(file, F_LIFECYCLE) == 0) {
          buckets_lifecycle lc;
          buckets_lc_error le;
          bool lock = im->meta.lock_enabled || im->meta.config[BUCKETS_BCFG_OBJECT_LOCK].len;
          if (!buckets_lifecycle_parse(data.data ? data.data : "", data.len, false, &lc, &le)) {
            set_status(&rpt, bucket, file, le.msg);
          } else {
            if (!buckets_lifecycle_validate(&lc, lock, tier_valid, s, &le)) set_status(&rpt, bucket, file, le.msg);
            else {
              buckets_buf x = BUCKETS_BUF_INIT;
              buckets_lifecycle_xml(&lc, true, &x);
              set_cfg(im, BUCKETS_BCFG_LIFECYCLE, &x, now);
              buckets_buf_free(&x);
              set_status(&rpt, bucket, file, NULL);
            }
            buckets_lifecycle_free(&lc);
          }
        } else if (strcmp(file, F_SSE) == 0) {
          buckets_sse_config sc;
          char perr[256];
          if (!buckets_sse_config_parse(data.data ? data.data : "", data.len, &sc, perr, sizeof(perr)))
            set_status(&rpt, bucket, file, malformed(err, sizeof(err), perr));
          else if (!s->kms)
            set_status(&rpt, bucket, file, buckets_s3_error_get(BUCKETS_ERR_KMS_NOT_CONFIGURED)->message);
          else {
            buckets_buf x = BUCKETS_BUF_INIT;
            buckets_sse_config_xml(&sc, &x);
            set_cfg(im, BUCKETS_BCFG_ENCRYPTION, &x, now);
            buckets_buf_free(&x);
            set_status(&rpt, bucket, file, NULL);
          }
        } else if (strcmp(file, F_TAGGING) == 0) {
          buckets_tags t;
          buckets_tags_error te;
          if (!buckets_tags_parse_xml(data.data ? data.data : "", data.len, false, &t, &te)) {
            char msg[256];
            buckets_tags_err_message(&te, msg, sizeof(msg));
            set_status(&rpt, bucket, file, malformed(err, sizeof(err), msg));
          } else {
            buckets_buf x = BUCKETS_BUF_INIT;
            buckets_tags_xml(&t, &x);
            buckets_tags_free(&t);
            set_cfg(im, BUCKETS_BCFG_TAGGING, &x, now);
            buckets_buf_free(&x);
            set_status(&rpt, bucket, file, NULL);
          }
        } else if (strcmp(file, F_QUOTA) == 0) {
          buckets_quota q;
          char perr[256];
          if (!buckets_quota_parse(data.data ? data.data : "", data.len, &q, perr, sizeof(perr)))
            set_status(&rpt, bucket, file, perr);
          else {
            set_cfg(im, BUCKETS_BCFG_QUOTA, &data, now); /* stored as given */
            set_status(&rpt, bucket, file, NULL);
          }
        }
      }
      buckets_buf_free(&data);
      free(bucket);
    }
  }

  for (size_t i = 0; i < m.n; i++) {
    imported *im = &m.v[i];
    if (!buckets_bucket_meta_save(s->layer, &im->meta)) {
      set_status(&rpt, im->bucket, "", "unable to save the bucket metadata");
      continue;
    }
    buckets_metasys_changed(s->meta, im->bucket);
    /* BucketMetaHook with every replicated configuration */
    static const char *const k_sr_types[] = {"policy", "tags", "version-config", "object-lock-config", "sse-config",
                                             "quota-config"};
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(k_sr_types); k++) buckets_sr_bucket_meta_hook(s->sr, im->bucket, k_sr_types[k]);
  }

  /* madmin.BucketMetaImportErrs */
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_buf_append_char(&out, '{');
  if (rpt.n) {
    /* map keys in order */
    for (size_t i = 1; i < rpt.n; i++)
      for (size_t j = i; j > 0 && strcmp(rpt.v[j - 1].bucket, rpt.v[j].bucket) > 0; j--) {
        bucket_status t = rpt.v[j];
        rpt.v[j] = rpt.v[j - 1];
        rpt.v[j - 1] = t;
      }
    buckets_buf_append_c(&out, "\"buckets\":{");
    for (size_t i = 0; i < rpt.n; i++) {
      bucket_status *st = &rpt.v[i];
      if (i) buckets_buf_append_char(&out, ',');
      buckets_json_go_string(&out, st->bucket, strlen(st->bucket));
      buckets_buf_append_c(&out, ":{");
      for (int k = 0; k < S__N; k++) {
        buckets_buf_appendf(&out, "%s\"%s\":{\"isSet\":%s", k ? "," : "", k_status_keys[k], st->set[k] ? "true" : "false");
        if (st->err[k]) {
          buckets_buf_append_c(&out, ",\"error\":");
          buckets_json_go_string(&out, st->err[k], strlen(st->err[k]));
        }
        buckets_buf_append_char(&out, '}');
        free(st->err[k]);
      }
      if (st->bucket_err && *st->bucket_err) {
        buckets_buf_append_c(&out, ",\"error\":");
        buckets_json_go_string(&out, st->bucket_err, strlen(st->bucket_err));
      }
      buckets_buf_append_char(&out, '}');
      free(st->bucket_err);
      free(st->bucket);
    }
    buckets_buf_append_char(&out, '}');
  }
  buckets_buf_append_char(&out, '}');
  free(rpt.v);
  for (size_t i = 0; i < m.n; i++) {
    buckets_bucket_meta_free(&m.v[i].meta);
    free(m.v[i].bucket);
  }
  free(m.v);
  buckets_zipfiles_free(&files);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, out.data, out.len);
  buckets_buf_free(&out);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}
