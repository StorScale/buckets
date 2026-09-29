/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Warm backends (MinIO's cmd/warm-backend*.go): the remote tiers that
 * transitioned object data is written to. S3 and MinIO tiers go through the
 * S3 client; Azure and GCS have their own (azure.c, gcs.c). */
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "net/s3client.h"
#include "tier/internal.h"

/* ---- dispatch ---------------------------------------------------------------------------- */

buckets_warm *buckets_warm_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen) {
  buckets_warm *w = NULL;
  switch (t->type) {
    case BUCKETS_TIER_S3:
    case BUCKETS_TIER_MINIO: w = buckets_warm_s3_new(t, tls, err, errlen); break;
    case BUCKETS_TIER_AZURE: w = buckets_warm_azure_new(t, tls, err, errlen); break;
    case BUCKETS_TIER_GCS: w = buckets_warm_gcs_new(t, tls, err, errlen); break;
    default: snprintf(err, errlen, "unsupported tier type"); return NULL;
  }
  if (w) {
    atomic_store(&w->refs, 1);
    w->tier = buckets_xstrdup(t->name);
  }
  return w;
}

buckets_warm *buckets_warm_ref(buckets_warm *w) {
  if (w) atomic_fetch_add(&w->refs, 1);
  return w;
}

void buckets_warm_release(buckets_warm *w) {
  if (!w || atomic_fetch_sub(&w->refs, 1) != 1) return;
  free(w->tier);
  w->ops->destroy(w);
}

const char *buckets_warm_tier(const buckets_warm *w) { return w->tier; }

buckets_warm_err buckets_warm_put(buckets_warm *w, const char *object, buckets_http_read_fn rd, void *rd_ud,
                                  int64_t length, const char *orig_name, char *rv, size_t rvcap, char *err,
                                  size_t errlen) {
  *rv = '\0';
  *err = '\0';
  return w->ops->put(w, object, rd, rd_ud, length, orig_name, rv, rvcap, err, errlen);
}

buckets_warm_err buckets_warm_get(buckets_warm *w, const char *object, const char *rv, int64_t off, int64_t len,
                                  buckets_warm_stream **out, char *err, size_t errlen) {
  *out = NULL;
  *err = '\0';
  return w->ops->get(w, object, rv ? rv : "", off, len, out, err, errlen);
}

long buckets_warm_stream_read(buckets_warm_stream *s, void *buf, size_t n) {
  if (s->remaining == 0) return 0;
  if (s->remaining > 0 && (int64_t)n > s->remaining) n = (size_t)s->remaining;
  long k = buckets_http_stream_read(s->body, buf, n);
  if (k > 0 && s->remaining > 0) s->remaining -= k;
  if (k == 0 && s->remaining > 0) return -1; /* short body */
  return k;
}

void buckets_warm_stream_free(buckets_warm_stream *s) {
  if (!s) return;
  if (s->body) buckets_http_stream_free(s->body);
  if (s->free_ud) s->free_ud(s->ud);
  free(s);
}

buckets_warm_err buckets_warm_remove(buckets_warm *w, const char *object, const char *rv, char *err, size_t errlen) {
  *err = '\0';
  return w->ops->remove(w, object, rv ? rv : "", err, errlen);
}

buckets_warm_err buckets_warm_in_use(buckets_warm *w, bool *in_use, char *err, size_t errlen) {
  *in_use = false;
  *err = '\0';
  return w->ops->in_use(w, in_use, err, errlen);
}

void buckets_warm_dest(const char *prefix, const char *object, buckets_buf *out) {
  if (prefix && *prefix) {
    buckets_buf_append_c(out, prefix);
    buckets_buf_append_c(out, "/");
  }
  buckets_buf_append_c(out, object);
}

/* "http(s)://host[:port][/...]" -> host[:port], secure */
bool buckets_warm_endpoint(const char *url, char *host, size_t cap, bool *secure) {
  const char *p = url;
  *secure = false;
  if (strncmp(p, "https://", 8) == 0) {
    *secure = true;
    p += 8;
  } else if (strncmp(p, "http://", 7) == 0) {
    p += 7;
  } else {
    return false;
  }
  size_t n = strcspn(p, "/");
  if (!n || n >= cap) return false;
  memcpy(host, p, n);
  host[n] = '\0';
  return true;
}

/* ---- S3 and MinIO tiers ------------------------------------------------------------------ */

typedef struct {
  buckets_warm base;
  buckets_s3c *c;
  char *bucket, *prefix, *storage_class;
  bool minio;
} warm_s3;

static buckets_warm_err s3_error(const buckets_s3c_result *r, char *err, size_t errlen) {
  snprintf(err, errlen, "%s", buckets_s3c_error(r));
  if (r->network || r->status == 0) return BUCKETS_WARM_ERR_DOWN;
  if (strcmp(r->code, "NoSuchBucket") == 0) return BUCKETS_WARM_ERR_BUCKET;
  if (strcmp(r->code, "NoSuchKey") == 0 || strcmp(r->code, "NoSuchVersion") == 0 || r->status == 404)
    return BUCKETS_WARM_ERR_NOT_FOUND;
  if (strcmp(r->code, "SignatureDoesNotMatch") == 0 || strcmp(r->code, "InvalidAccessKeyId") == 0)
    return BUCKETS_WARM_ERR_CREDENTIALS;
  return BUCKETS_WARM_ERR_OTHER;
}

static buckets_warm_err s3_put(buckets_warm *bw, const char *object, buckets_http_read_fn rd, void *rd_ud, int64_t length,
                               const char *orig_name, char *rv, size_t rvcap, char *err, size_t errlen) {
  warm_s3 *w = (warm_s3 *)bw;
  buckets_buf key = BUCKETS_BUF_INIT;
  buckets_warm_dest(w->prefix, object, &key);
  buckets_http_kv h[3];
  size_t nh = 0;
  if (orig_name) h[nh++] = (buckets_http_kv){"X-Amz-Meta-Name", orig_name};
  if (*w->storage_class) h[nh++] = (buckets_http_kv){"X-Amz-Storage-Class", w->storage_class};
  buckets_s3c_result r;
  bool ok = buckets_s3c_do_stream(w->c, "PUT", w->bucket, key.data, NULL, h, nh, rd, rd_ud, length, &r);
  buckets_warm_err e = BUCKETS_WARM_OK;
  if (ok) buckets_s3c_header_copy(&r, "X-Amz-Version-Id", rv, rvcap);
  else e = s3_error(&r, err, errlen);
  buckets_s3c_result_free(&r);
  buckets_buf_free(&key);
  return e;
}

static buckets_warm_err s3_get(buckets_warm *bw, const char *object, const char *rv, int64_t off, int64_t len,
                               buckets_warm_stream **out, char *err, size_t errlen) {
  warm_s3 *w = (warm_s3 *)bw;
  buckets_buf key = BUCKETS_BUF_INIT, q = BUCKETS_BUF_INIT;
  buckets_warm_dest(w->prefix, object, &key);
  if (*rv) {
    buckets_buf_append_c(&q, "versionId=");
    buckets_url_encode(&q, rv, false);
  }
  char range[80];
  buckets_http_kv h[1];
  size_t nh = 0;
  if (off > 0 || len >= 0) {
    if (len >= 0) snprintf(range, sizeof(range), "bytes=%lld-%lld", (long long)off, (long long)(off + len - 1));
    else snprintf(range, sizeof(range), "bytes=%lld-", (long long)off);
    h[nh++] = (buckets_http_kv){"Range", range};
  }
  buckets_s3c_result r;
  buckets_http_stream *st = buckets_s3c_open(w->c, "GET", w->bucket, key.data, q.len ? q.data : NULL, h, nh, &r);
  buckets_warm_err e = BUCKETS_WARM_OK;
  if (!st) {
    e = s3_error(&r, err, errlen);
  } else {
    buckets_warm_stream *s = buckets_xcalloc(1, sizeof(*s));
    s->body = st;
    s->remaining = len >= 0 ? len : -1;
    *out = s;
  }
  buckets_s3c_result_free(&r);
  buckets_buf_free(&key);
  buckets_buf_free(&q);
  return e;
}

static buckets_warm_err s3_remove(buckets_warm *bw, const char *object, const char *rv, char *err, size_t errlen) {
  warm_s3 *w = (warm_s3 *)bw;
  buckets_buf key = BUCKETS_BUF_INIT, q = BUCKETS_BUF_INIT;
  buckets_warm_dest(w->prefix, object, &key);
  if (*rv) {
    buckets_buf_append_c(&q, "versionId=");
    buckets_url_encode(&q, rv, false);
  }
  buckets_s3c_result r;
  bool ok = buckets_s3c_do(w->c, "DELETE", w->bucket, key.data, q.len ? q.data : NULL, NULL, 0, NULL, 0, &r);
  buckets_warm_err e = ok ? BUCKETS_WARM_OK : s3_error(&r, err, errlen);
  buckets_s3c_result_free(&r);
  buckets_buf_free(&key);
  buckets_buf_free(&q);
  return e;
}

static buckets_warm_err s3_in_use(buckets_warm *bw, bool *in_use, char *err, size_t errlen) {
  warm_s3 *w = (warm_s3 *)bw;
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&q, "delimiter=%2F&list-type=2&max-keys=1&prefix=");
  buckets_url_encode(&q, w->prefix, false);
  buckets_s3c_result r;
  bool ok = buckets_s3c_do(w->c, "GET", w->bucket, NULL, q.data, NULL, 0, NULL, 0, &r);
  buckets_warm_err e = BUCKETS_WARM_OK;
  if (!ok) e = s3_error(&r, err, errlen);
  else *in_use = r.body.data && (strstr(r.body.data, "<Contents>") || strstr(r.body.data, "<CommonPrefixes>"));
  buckets_s3c_result_free(&r);
  buckets_buf_free(&q);
  return e;
}

static void s3_destroy(buckets_warm *bw) {
  warm_s3 *w = (warm_s3 *)bw;
  buckets_s3c_free(w->c);
  free(w->bucket);
  free(w->prefix);
  free(w->storage_class);
  free(w);
}

static const buckets_warm_ops k_s3_ops = {s3_put, s3_get, s3_remove, s3_in_use, s3_destroy};

static char *trim_slash(const char *p) {
  size_t n = strlen(p);
  if (n && p[n - 1] == '/') n--;
  return buckets_xstrndup(p, n);
}

buckets_warm *buckets_warm_s3_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen) {
  bool minio = t->type == BUCKETS_TIER_MINIO;
  const char *endpoint = minio ? t->minio.endpoint : t->s3.endpoint;
  const char *ak = minio ? t->minio.access_key : t->s3.access_key;
  const char *sk = minio ? t->minio.secret_key : t->s3.secret_key;
  const char *bucket = minio ? t->minio.bucket : t->s3.bucket;
  if (minio) {
    if (!*ak || !*sk) {
      snprintf(err, errlen, "both access and secret keys are required");
      return NULL;
    }
    if (!*bucket) {
      snprintf(err, errlen, "no bucket name was provided");
      return NULL;
    }
  } else {
    bool wf = *t->s3.aws_role_web_identity_token_file, arn = *t->s3.aws_role_arn;
    if (wf != arn) {
      snprintf(err, errlen, "both the token file and the role ARN are required");
      return NULL;
    }
    if ((!*ak) != (!*sk)) {
      snprintf(err, errlen, "both the access and secret keys are required");
      return NULL;
    }
    if (t->s3.aws_role && (wf || arn || *ak || *sk)) {
      snprintf(err, errlen, "AWS Role cannot be activated with static credentials or the web identity token file");
      return NULL;
    }
    if (!*bucket) {
      snprintf(err, errlen, "no bucket name was provided");
      return NULL;
    }
    if (!*ak) { /* IAM role credentials (EC2/EKS) are not supported here */
      snprintf(err, errlen, "insufficient parameters for S3 backend authentication");
      return NULL;
    }
  }
  char host[512];
  bool secure;
  if (!buckets_warm_endpoint(endpoint, host, sizeof(host), &secure)) {
    snprintf(err, errlen, "parse \"%s\": invalid URI for request", endpoint);
    return NULL;
  }
  warm_s3 *w = buckets_xcalloc(1, sizeof(*w));
  w->base.ops = &k_s3_ops;
  w->minio = minio;
  char app[300];
  snprintf(app, sizeof(app), "%s-tier-%s", minio ? "minio" : "s3", t->name);
  buckets_s3c_config cfg = {.endpoint = host,
                            .secure = secure,
                            .access_key = ak,
                            .secret_key = sk,
                            .region = minio ? t->minio.region : t->s3.region,
                            .tls = secure ? tls : NULL,
                            .timeout_ms = 15 * 60 * 1000,
                            .app_info = app};
  w->c = buckets_s3c_new(&cfg);
  w->bucket = buckets_xstrdup(bucket);
  w->prefix = trim_slash(minio ? t->minio.prefix : t->s3.prefix);
  w->storage_class = buckets_xstrdup(minio ? "" : t->s3.storage_class);
  return &w->base;
}
