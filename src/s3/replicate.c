/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket replication: remote targets and their health (MinIO's
 * cmd/bucket-targets.go), replication decisions, and the worker pool that
 * replicates object versions and deletes (cmd/bucket-replication.go). What
 * goes over the wire is what MinIO's minio-go client sends, so either
 * server can replicate to the other. */
#include "s3/replicate.h"

#include <ctype.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bucket/metasys.h"
#include "bucket/objectlock.h"
#include "bucket/tags.h"
#include "core/auditctx.h"
#include "core/log.h"
#include "core/msgpack.h"
#include "notify/event.h"
#include "object/sysconfig.h"
#include "core/strmap.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/xxhash.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "s3/checksum.h"
#include "s3/compress.h"
#include "s3/internal.h"
#include "s3/sse.h"
#include "s3/sign.h"
#include "s3/xml.h"

#define REPL_WORKERS 16
#define REPL_MRF_WORKERS 4
#define REPL_QUEUE_MAX 100000
#define MRF_RETRY_LIMIT 3
#define HEALTH_INTERVAL_MS 5000

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void rfc3339nano(int64_t ns, char out[BUCKETS_TIME_RFC3339_NANO_LEN + 1]) {
  buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), out);
}

/* ---- decisions ---------------------------------------------------------------------- */

void buckets_repl_dsc_free(buckets_repl_dsc *d) {
  for (size_t i = 0; i < d->n; i++) free(d->t[i].arn);
  free(d->t);
  d->t = NULL;
  d->n = 0;
}

static void dsc_set(buckets_repl_dsc *d, const char *arn, bool replicate, bool sync) {
  for (size_t i = 0; i < d->n; i++) {
    if (strcmp(d->t[i].arn, arn) == 0) {
      d->t[i].replicate = replicate;
      d->t[i].sync = sync;
      return;
    }
  }
  d->t = buckets_xrealloc(d->t, (d->n + 1) * sizeof(*d->t));
  d->t[d->n++] = (buckets_repl_tdec){buckets_xstrdup(arn), replicate, sync};
}

bool buckets_repl_dsc_any(const buckets_repl_dsc *d) {
  for (size_t i = 0; i < d->n; i++)
    if (d->t[i].replicate) return true;
  return false;
}

bool buckets_repl_dsc_sync(const buckets_repl_dsc *d) {
  for (size_t i = 0; i < d->n; i++)
    if (d->t[i].sync) return true;
  return false;
}

void buckets_repl_dsc_pending(const buckets_repl_dsc *d, buckets_buf *out) {
  for (size_t i = 0; i < d->n; i++)
    if (d->t[i].replicate) buckets_buf_appendf(out, "%s=%s;", d->t[i].arn, BUCKETS_RS_PENDING);
}

static const char *kv_get_fold(const buckets_xl_kv *kv, size_t n, const char *key) {
  for (size_t i = 0; i < n; i++)
    if (strcasecmp(kv[i].key, key) == 0) return (const char *)kv[i].value;
  return NULL;
}

static bool sys_ssec(const buckets_xl_kv *sys, size_t nsys) {
  return kv_get_fold(sys, nsys, BUCKETS_SSE_META_SEALED_SSEC) != NULL;
}

/* The target's sync flag (tgt.replicateSync), false when unknown. */
static bool target_sync(buckets_bucket_state *st, const char *arn) {
  for (size_t i = 0; i < st->targets.n; i++)
    if (strcmp(st->targets.t[i].arn, arn) == 0) return st->targets.t[i].replication_sync;
  return false;
}

static bool target_known(buckets_bucket_state *st, const char *arn) {
  for (size_t i = 0; i < st->targets.n; i++)
    if (strcmp(st->targets.t[i].arn, arn) == 0) return true;
  return false;
}

void buckets_repl_must(buckets_s3_server *s, const char *bucket, const char *object, const buckets_xl_kv *meta,
                       size_t nmeta, const buckets_xl_kv *sys, size_t nsys, const char *user_tags, buckets_repl_type op,
                       bool replication_request, buckets_repl_dsc *out) {
  memset(out, 0, sizeof(*out));
  if (!s->meta || !s->layer) return;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  if (!st->has_replication || !buckets_versioning_enabled_for(&st->versioning, object)) goto done;
  const char *status = kv_get_fold(meta, nmeta, BUCKETS_H_REPL_STATUS);
  bool replica = status && strcmp(status, BUCKETS_RS_REPLICA) == 0;
  if (replica && op != BUCKETS_REPL_METADATA) goto done;
  if (replication_request) goto done;
  const char *tags = user_tags ? user_tags : kv_get_fold(meta, nmeta, "X-Amz-Tagging");
  buckets_repl_obj o = {.name = object, .user_tags = tags, .ssec = sys_ssec(sys, nsys), .replica = replica,
                        .existing = op == BUCKETS_REPL_EXISTING};
  char **arns = NULL;
  size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
  for (size_t i = 0; i < na; i++) {
    o.target_arn = arns[i];
    bool rep = buckets_replication_replicate(&st->replication, &o);
    dsc_set(out, arns[i], rep, target_sync(st, arns[i]));
  }
  buckets_replication_arns_free(arns, na);
done:
  buckets_bucket_state_release(st);
}

static const char *sys_str(const buckets_object_info *oi, const char *key) {
  const buckets_xl_kv *kv = buckets_object_sys(oi, key);
  return kv ? (const char *)kv->value : NULL;
}

void buckets_repl_check_delete(buckets_s3_server *s, const char *bucket, const char *object, const char *version_id,
                               const buckets_object_info *goi, bool versioned, bool replication_request,
                               buckets_repl_dsc *out) {
  memset(out, 0, sizeof(*out));
  if (!s->meta || replication_request || !versioned) return;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  if (!st->has_replication) goto done;
  const char *tags = goi ? buckets_object_meta(goi, "X-Amz-Tagging") : NULL;
  bool dm = goi && goi->delete_marker && !(sys_str(goi, BUCKETS_META_PURGE_STATUS) && *sys_str(goi, BUCKETS_META_PURGE_STATUS));
  buckets_repl_obj o = {.name = object,
                        .ssec = goi && sys_ssec(goi->meta_sys, goi->nmeta_sys),
                        .user_tags = tags,
                        .delete_marker = goi && goi->delete_marker,
                        .version_id = version_id,
                        .op = BUCKETS_REPL_DELETE};
  (void)dm;
  char **arns = NULL;
  size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
  for (size_t i = 0; i < na; i++) {
    o.target_arn = arns[i];
    bool rep = buckets_replication_replicate(&st->replication, &o);
    /* the target could be down: its status does not matter here */
    dsc_set(out, arns[i], target_known(st, arns[i]) ? rep : false, false);
  }
  buckets_replication_arns_free(arns, na);
done:
  buckets_bucket_state_release(st);
}

const char *buckets_repl_version_status(const buckets_object_info *oi, char *buf, size_t cap) {
  const char *internal = sys_str(oi, BUCKETS_META_REPL_STATUS);
  const char *replica = sys_str(oi, BUCKETS_META_REPLICA_STATUS);
  const char *st = "";
  if (internal && *internal) {
    st = buckets_repl_composite_status(internal);
    /* a replica updated after the last replication reports as REPLICA */
    const char *rts = sys_str(oi, BUCKETS_META_REPLICA_TS), *lts = sys_str(oi, BUCKETS_META_REPL_TS);
    long long rs = 0, ls = 0;
    long rn = 0, ln = 0;
    if (strcmp(st, BUCKETS_RS_COMPLETED) == 0 && replica && *replica && rts &&
        buckets_time_parse_rfc3339(rts, &rs, &rn) && rs > BUCKETS_GO_ZERO_SEC) {
      if (!lts || !buckets_time_parse_rfc3339(lts, &ls, &ln) || rs > ls || (rs == ls && rn > ln)) st = replica;
    }
  } else if (replica && *replica) {
    st = replica;
  }
  if (!*st) return NULL;
  snprintf(buf, cap, "%s", st);
  return buf;
}

/* ---- targets and their health ------------------------------------------------------- */

struct buckets_repl_target {
  _Atomic int refs;
  char *bucket;
  char *fp; /* what the client was built from */
  buckets_bucket_target t;
  buckets_s3c *c;
};

typedef struct {
  char key[300]; /* scheme://host:port */
  char endpoint[256];
  bool secure;
  bool online;
  int64_t last_online_sec;
  int64_t offline_since_ns; /* mono, 0 when online */
  int64_t offline_total_ns;
  int64_t offline_count;
  int64_t lat_curr, lat_avg, lat_max;
  int64_t nlat;
} ep_health;

typedef enum { JOB_OBJECT, JOB_DELETE } job_kind;

typedef struct job {
  struct job *next;
  job_kind kind;
  char *bucket, *object;
  char version_id[37];
  buckets_repl_type op;
  char *event;
  int retry;
  /* deletes */
  bool dm;                 /* a delete marker (DeleteMarkerVersionID) */
  int64_t dm_mtime;
  char *repl_status, *purge_status; /* the state recorded at delete time */
  char *target_arn;        /* resync: this target only */
  char *reset_id;
  int64_t qsize;           /* the version's size, for the queue statistics */
  int64_t due_ns;          /* MRF retries: not before (monotonic) */
} job;

typedef struct {
  pthread_mutex_t mu;
  pthread_cond_t cv;
  job *head, *tail;
  size_t n;
  pthread_t th;
  bool started;
  struct buckets_repl *r;
  bool mrf;
} worker;

struct buckets_repl {
  buckets_s3_server *s;
  pthread_mutex_t mu; /* targets and health */
  buckets_strmap targets; /* arn -> buckets_repl_target* */
  ep_health *hc;
  size_t nhc;
  buckets_tls_client *tls;
  worker w[REPL_WORKERS];
  worker mrf;
  pthread_t hc_thread;
  bool hc_started;
  _Atomic bool stop;
  pthread_mutex_t stop_mu;
  pthread_cond_t stop_cv;
  _Atomic int active;
};

static char *target_fp(const buckets_bucket_target *t) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%s|%d|%s|%s|%s|%s|%s|%s|%d|%lld", t->endpoint, t->secure, t->access_key, t->secret_key,
                      t->session_token, t->region, t->target_bucket, t->storage_class, t->replication_sync,
                      (long long)t->health_check_ns);
  buckets_buf_append_c(&b, t->disable_proxy ? "|p" : "|");
  buckets_buf_append_c(&b, t->reset_id);
  buckets_buf_append_char(&b, '\0');
  return b.data;
}

/* The TLS client for targets: system roots plus certs/CAs, made on first
 * use (bootstrap can run before the certificates directory is known). */
static buckets_tls_client *repl_tls(buckets_repl *r) {
  if (!r) return NULL;
  pthread_mutex_lock(&r->mu);
  if (!r->tls) {
    char err[256];
    r->tls = buckets_tls_client_new(r->s->ca_path, err, sizeof(err));
  }
  buckets_tls_client *t = r->tls;
  pthread_mutex_unlock(&r->mu);
  return t;
}

buckets_tls_client *buckets_repl_tls(buckets_repl *r) { return repl_tls(r); }

buckets_s3c *buckets_repl_client_for(buckets_repl *r, const buckets_bucket_target *t) {
  char app[512];
  snprintf(app, sizeof(app), "minio-replication-target/DEVELOPMENT.GOGET %s", t->arn);
  buckets_s3c_config cfg = {.endpoint = t->endpoint,
                            .secure = t->secure,
                            .access_key = t->access_key,
                            .secret_key = t->secret_key,
                            .session_token = t->session_token,
                            .region = t->region,
                            .tls = t->secure ? repl_tls(r) : NULL,
                            .timeout_ms = 60000,
                            .app_info = app};
  return buckets_s3c_new(&cfg);
}

static void target_unref(buckets_repl_target *t) {
  if (!t || atomic_fetch_sub(&t->refs, 1) != 1) return;
  buckets_s3c_free(t->c);
  buckets_bucket_target_free(&t->t);
  free(t->bucket);
  free(t->fp);
  free(t);
}

void buckets_repl_target_put(buckets_repl_target *t) { target_unref(t); }
buckets_s3c *buckets_repl_target_client(buckets_repl_target *t) { return t->c; }
const buckets_bucket_target *buckets_repl_target_info(buckets_repl_target *t) { return &t->t; }

static void hc_key(const char *endpoint, bool secure, char *out, size_t cap) {
  snprintf(out, cap, "%s://%s", secure ? "https" : "http", endpoint);
}

/* The endpoint's health entry, made (online until the heartbeat says otherwise) when there is none; r->mu held. */
static ep_health *hc_ensure(buckets_repl *r, const char *key, const char *endpoint, bool secure) {
  for (size_t i = 0; i < r->nhc; i++)
    if (strcmp(r->hc[i].key, key) == 0) return &r->hc[i];
  r->hc = buckets_xrealloc(r->hc, (r->nhc + 1) * sizeof(*r->hc));
  ep_health *h = &r->hc[r->nhc++];
  memset(h, 0, sizeof(*h));
  snprintf(h->key, sizeof(h->key), "%s", key);
  snprintf(h->endpoint, sizeof(h->endpoint), "%s", endpoint);
  h->secure = secure;
  h->online = true;
  return h;
}

/* isOffline: an endpoint not yet checked counts as online (and gets checked). */
bool buckets_repl_offline(buckets_repl *r, const char *endpoint, bool secure) {
  if (!r) return false;
  char key[300];
  hc_key(endpoint, secure, key, sizeof(key));
  pthread_mutex_lock(&r->mu);
  bool offline = !hc_ensure(r, key, endpoint, secure)->online;
  pthread_mutex_unlock(&r->mu);
  return offline;
}

static void mark_offline(buckets_repl *r, const char *endpoint, bool secure) {
  char key[300];
  hc_key(endpoint, secure, key, sizeof(key));
  pthread_mutex_lock(&r->mu);
  for (size_t i = 0; i < r->nhc; i++) {
    if (strcmp(r->hc[i].key, key) == 0 && r->hc[i].online) {
      r->hc[i].online = false;
      r->hc[i].offline_since_ns = mono_ns();
      r->hc[i].offline_count++;
    }
  }
  pthread_mutex_unlock(&r->mu);
}

void buckets_repl_health_fill(buckets_repl *r, buckets_bucket_target *t) {
  if (!r) return;
  char key[300];
  hc_key(t->endpoint, t->secure, key, sizeof(key));
  pthread_mutex_lock(&r->mu);
  hc_ensure(r, key, t->endpoint, t->secure); /* a target asked about is watched from now on (initHC) */
  for (size_t i = 0; i < r->nhc; i++) {
    ep_health *h = &r->hc[i];
    if (strcmp(h->key, key) != 0) continue;
    t->online = h->online;
    t->last_online_sec = h->last_online_sec ? h->last_online_sec : BUCKETS_GO_ZERO_SEC;
    t->last_online_nsec = 0;
    t->total_downtime_ns = h->offline_total_ns + (h->offline_since_ns ? mono_ns() - h->offline_since_ns : 0);
    t->lat_curr = h->lat_curr;
    t->lat_avg = h->lat_avg;
    t->lat_max = h->lat_max;
    t->offline_count = h->offline_count;
  }
  pthread_mutex_unlock(&r->mu);
}

size_t buckets_repl_health_list(buckets_repl *r, buckets_repl_ep_health **out) {
  *out = NULL;
  if (!r) return 0;
  pthread_mutex_lock(&r->mu);
  size_t n = r->nhc;
  buckets_repl_ep_health *o = buckets_xcalloc(n + 1, sizeof(*o));
  for (size_t i = 0; i < n; i++) {
    ep_health *h = &r->hc[i];
    snprintf(o[i].endpoint, sizeof(o[i].endpoint), "%s", h->endpoint);
    o[i].online = h->online;
    o[i].offline_ns = h->offline_total_ns + (h->offline_since_ns ? mono_ns() - h->offline_since_ns : 0);
    o[i].last_online_sec = h->last_online_sec;
    o[i].lat_curr = h->lat_curr, o[i].lat_avg = h->lat_avg, o[i].lat_max = h->lat_max;
    o[i].offline_count = h->offline_count;
  }
  pthread_mutex_unlock(&r->mu);
  *out = o;
  return n;
}

/* heartBeat: every endpoint in use, GET /minio/health/live. */
static void mrf_load(buckets_repl *r);

static void *hc_main(void *arg) {
  buckets_repl *r = arg;
  bool mrf_loaded = false;
  while (!atomic_load(&r->stop)) {
    /* the MRF saved at the last shutdown, once the node knows its name */
    if (!mrf_loaded && r->s->layer && r->s->meta && r->s->endpoint[0]) {
      mrf_load(r);
      mrf_loaded = true;
    }
    pthread_mutex_lock(&r->mu);
    size_t n = r->nhc;
    ep_health *snap = buckets_xcalloc(n + 1, sizeof(*snap));
    if (n) memcpy(snap, r->hc, n * sizeof(*snap));
    pthread_mutex_unlock(&r->mu);
    for (size_t i = 0; i < n && !atomic_load(&r->stop); i++) {
      buckets_s3c_config cfg = {.endpoint = snap[i].endpoint, .secure = snap[i].secure,
                                .tls = snap[i].secure ? repl_tls(r) : NULL, .timeout_ms = 3000};
      buckets_s3c *c = buckets_s3c_new(&cfg);
      buckets_s3c_result res;
      int64_t t0 = mono_ns();
      bool ok = buckets_s3c_health(c, "live", 3000, &res);
      int64_t lat = mono_ns() - t0;
      buckets_s3c_result_free(&res);
      buckets_s3c_free(c);
      pthread_mutex_lock(&r->mu);
      for (size_t k = 0; k < r->nhc; k++) {
        ep_health *h = &r->hc[k];
        if (strcmp(h->key, snap[i].key) != 0) continue;
        if (ok) {
          if (h->offline_since_ns) {
            h->offline_total_ns += mono_ns() - h->offline_since_ns;
            h->offline_since_ns = 0;
          }
          h->online = true;
          h->last_online_sec = now_ns() / 1000000000LL;
          h->nlat++;
          h->lat_curr = lat;
          if (lat > h->lat_max) h->lat_max = lat;
          h->lat_avg = (h->lat_avg * (h->nlat - 1) + lat) / h->nlat;
        } else if (h->online) {
          h->online = false;
          h->offline_since_ns = mono_ns();
          h->offline_count++;
        }
      }
      pthread_mutex_unlock(&r->mu);
    }
    free(snap);
    pthread_mutex_lock(&r->stop_mu);
    if (!atomic_load(&r->stop)) {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      if (mrf_loaded) ts.tv_sec += HEALTH_INTERVAL_MS / 1000;
      else ts.tv_sec += 1; /* soon after startup: the saved MRF */
      pthread_cond_timedwait(&r->stop_cv, &r->stop_mu, &ts);
    }
    pthread_mutex_unlock(&r->stop_mu);
  }
  return NULL;
}

buckets_repl_target *buckets_repl_target_get(buckets_repl *r, const char *bucket, const char *arn) {
  if (!r || !r->s->meta || !arn || !*arn) return NULL;
  buckets_bucket_state *st = buckets_metasys_get(r->s->meta, bucket);
  const buckets_bucket_target *want = NULL;
  for (size_t i = 0; i < st->targets.n; i++)
    if (strcmp(st->targets.t[i].arn, arn) == 0) want = &st->targets.t[i];
  if (!want) {
    buckets_bucket_state_release(st);
    return NULL;
  }
  char *fp = target_fp(want);
  char key[1024];
  snprintf(key, sizeof(key), "%s\n%s", bucket, arn);
  pthread_mutex_lock(&r->mu);
  buckets_repl_target *t = buckets_strmap_get(&r->targets, key);
  if (t && strcmp(t->fp, fp) == 0) {
    atomic_fetch_add(&t->refs, 1);
    pthread_mutex_unlock(&r->mu);
    free(fp);
    buckets_bucket_state_release(st);
    return t;
  }
  pthread_mutex_unlock(&r->mu);
  buckets_repl_target *nt = buckets_xcalloc(1, sizeof(*nt));
  atomic_init(&nt->refs, 2); /* the map's and the caller's */
  nt->bucket = buckets_xstrdup(bucket);
  nt->fp = fp;
  buckets_bucket_target_copy(&nt->t, want);
  buckets_bucket_state_release(st);
  nt->c = buckets_repl_client_for(r, &nt->t);
  pthread_mutex_lock(&r->mu);
  target_unref(buckets_strmap_put(&r->targets, key, nt));
  pthread_mutex_unlock(&r->mu);
  return nt;
}

/* ---- the source version ------------------------------------------------------------- */

static const buckets_http_request k_noreq;

/* A server-side context for the S3 helpers (no request headers). */
static void fake_ctx(buckets_s3_server *s, s3_ctx *c, const char *bucket) {
  memset(c, 0, sizeof(*c));
  c->s = s;
  c->req = &k_noreq;
  c->bucket = (char *)bucket;
}

typedef struct {
  buckets_obj_reader *r;
  buckets_sse_reader *sr;
  buckets_comp_reader *cr;
} src_rd;

static long src_read(void *ud, void *buf, size_t n) {
  src_rd *s = ud;
  if (s->cr) return buckets_comp_reader_read(s->cr, buf, n);
  if (s->sr) return buckets_sse_reader_read(s->sr, buf, n);
  return buckets_obj_read(s->r, buf, n);
}

static void src_close(src_rd *s) {
  if (s->cr) buckets_comp_reader_free(s->cr);
  else if (s->sr) buckets_sse_reader_free(s->sr);
  else if (s->r) buckets_obj_reader_free(s->r);
  memset(s, 0, sizeof(*s));
}

static long obj_source(void *ud, void *buf, size_t n) { return buckets_obj_read(ud, buf, n); }
static void obj_source_free(void *ud) { buckets_obj_reader_free(ud); }

/* What replication reads of a version (GetObjectNInfo with
 * ReplicationRequest): SSE-C objects as stored, others as plaintext. */
typedef struct {
  buckets_object_info oi; /* etag: the ETag clients see; size: what is sent */
  int64_t stored_size;
  bool ssec, encrypted, compressed;
  uint8_t key[32];
  bool have_key;
} src_info;

static void src_info_free(src_info *si) {
  buckets_object_info_free(&si->oi);
  OPENSSL_cleanse(si->key, sizeof(si->key));
}

static bool src_stat(buckets_s3_server *s, const char *bucket, const char *object, const char *vid, src_info *si,
                     buckets_obj_err *err) {
  memset(si, 0, sizeof(*si));
  *err = buckets_obj_stat(s->layer, bucket, object, vid, &si->oi);
  if (*err) return false;
  si->stored_size = si->oi.size;
  si->encrypted = buckets_s3_sse_encrypted(&si->oi);
  si->ssec = si->encrypted && buckets_s3_sse_kind_of(&si->oi) == BUCKETS_SSE_C;
  si->compressed = buckets_s3_is_compressed(&si->oi);
  if (si->oi.delete_marker) return true;
  s3_ctx c;
  fake_ctx(s, &c, bucket);
  if (si->encrypted && !si->ssec) {
    if (buckets_s3_sse_object_key(&c, &si->oi, bucket, object, false, si->key) != BUCKETS_ERR_NONE) {
      *err = BUCKETS_OBJ_ERR_IO;
      buckets_object_info_free(&si->oi);
      return false;
    }
    si->have_key = true;
    char etag[80];
    buckets_s3_sse_client_etag(&c, &si->oi, si->key, etag);
    snprintf(si->oi.etag, sizeof(si->oi.etag), "%s", etag);
  }
  if (!si->ssec && (si->encrypted || si->compressed)) si->oi.size = buckets_s3_actual_size(&si->oi);
  return true;
}

/* Opens [off, off+len) of what is sent. */
static bool src_open(buckets_s3_server *s, const char *bucket, const char *object, src_info *si, int64_t off,
                     int64_t len, src_rd *out) {
  memset(out, 0, sizeof(*out));
  const char *vid = si->oi.version_id;
  if (si->ssec || (!si->encrypted && !si->compressed)) {
    buckets_object_info tmp;
    if (buckets_obj_open(s->layer, bucket, object, vid, off, len, &out->r, &tmp)) return false;
    buckets_object_info_free(&tmp);
    return true;
  }
  int64_t roff = off, rlen = len, plain = si->oi.size;
  buckets_sse_range rg;
  buckets_comp_range crg;
  bool comp = si->compressed && len > 0;
  if (comp) {
    buckets_s3_compressed_range(&si->oi, si->have_key ? si->key : NULL, off, &crg);
    roff = crg.stored_off, rlen = si->stored_size - crg.stored_off;
  } else {
    si->oi.size = si->stored_size;
    buckets_s3_sse_range(&si->oi, off, len, &rg);
    si->oi.size = plain;
    roff = rg.enc_off, rlen = rg.enc_len;
  }
  buckets_obj_reader *r;
  buckets_object_info tmp;
  if (buckets_obj_open(s->layer, bucket, object, vid, roff, rlen, &r, &tmp)) return false;
  buckets_object_info_free(&tmp);
  if (comp) {
    out->cr = buckets_comp_reader_new(&si->oi, si->stored_size, si->have_key ? si->key : NULL, &crg, len, obj_source, r,
                                      obj_source_free);
  } else {
    si->oi.size = si->stored_size;
    out->sr = buckets_sse_reader_new(&si->oi, si->key, &rg, len, obj_source, r, obj_source_free);
    si->oi.size = plain;
  }
  return true;
}

/* objInfo.isMultipart() */
static bool src_multipart(const src_info *si) {
  if (si->encrypted) {
    if (!sys_str(&si->oi, BUCKETS_SSE_META_MULTIPART)) return false;
  }
  return strlen(si->oi.etag) != 32;
}

/* ---- request headers (putReplicationOpts, minio-go PutObjectOptions.Header) ---- */

typedef struct {
  buckets_http_kv kv[BUCKETS_SIGN_MAX_HEADERS - 8];
  char *own[BUCKETS_SIGN_MAX_HEADERS - 8];
  size_t n;
} hdrs;

static void hset(hdrs *h, const char *name, const char *value) {
  for (size_t i = 0; i < h->n; i++) {
    if (strcasecmp(h->kv[i].name, name) == 0) {
      free(h->own[i]);
      h->own[i] = buckets_xstrdup(value);
      h->kv[i].value = h->own[i];
      return;
    }
  }
  if (h->n >= BUCKETS_ARRAY_LEN(h->kv)) return;
  h->own[h->n] = buckets_xstrdup(value);
  h->kv[h->n] = (buckets_http_kv){NULL, h->own[h->n]};
  /* names are static or kept in the value buffer's sibling */
  h->kv[h->n].name = buckets_xstrdup(name);
  h->n++;
}

static void hfree(hdrs *h) {
  for (size_t i = 0; i < h->n; i++) {
    free(h->own[i]);
    free((char *)h->kv[i].name);
  }
  h->n = 0;
}

static void hdel(hdrs *h, const char *name) {
  for (size_t i = 0; i < h->n; i++) {
    if (strcasecmp(h->kv[i].name, name) != 0) continue;
    free(h->own[i]);
    free((char *)h->kv[i].name);
    memmove(&h->kv[i], &h->kv[i + 1], (h->n - i - 1) * sizeof(h->kv[0]));
    memmove(&h->own[i], &h->own[i + 1], (h->n - i - 1) * sizeof(h->own[0]));
    h->n--;
    return;
  }
}

/* Go's http.CanonicalHeaderKey */
static void canon(const char *in, char *out, size_t cap) {
  bool up = true;
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++) {
    out[i] = up ? (char)toupper((unsigned char)in[i]) : (char)tolower((unsigned char)in[i]);
    up = in[i] == '-';
  }
  out[i] = '\0';
}

static bool fold_eq(const char *a, const char *b) { return strcasecmp(a, b) == 0; }
static bool fold_prefix(const char *s, const char *p) { return strncasecmp(s, p, strlen(p)) == 0; }

/* MinIO's standardHeaders (dropped from UserMetadata). */
static bool standard_header(const char *k) {
  static const char *const std[] = {"content-type", "cache-control", "content-encoding", "content-language",
                                    "content-disposition", "x-amz-storage-class", "x-amz-tagging",
                                    "x-amz-replication-status", "x-amz-object-lock-mode",
                                    "x-amz-object-lock-retain-until-date", "x-amz-object-lock-legal-hold",
                                    "x-amz-tagging-count", "x-amz-server-side-encryption"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(std); i++)
    if (fold_eq(k, std[i])) return true;
  return false;
}

/* minio-go: amz, standard, storage-class and minio headers go as they are,
 * anything else as x-amz-meta-<key>. */
static void set_user_meta(hdrs *h, const char *k, const char *v) {
  static const char *const gostd[] = {"content-type", "cache-control", "content-encoding", "content-disposition",
                                      "content-language", "x-amz-website-redirect-location", "x-amz-object-lock-mode",
                                      "x-amz-metadata-directive", "x-amz-object-lock-retain-until-date", "expires",
                                      "x-amz-replication-status"};
  bool asis = fold_prefix(k, "x-amz-") || fold_prefix(k, "x-minio-") || fold_eq(k, "x-amz-storage-class");
  for (size_t i = 0; !asis && i < BUCKETS_ARRAY_LEN(gostd); i++) asis = fold_eq(k, gostd[i]);
  char name[512];
  if (asis) canon(k, name, sizeof(name));
  else {
    char tmp[500];
    snprintf(tmp, sizeof(tmp), "x-amz-meta-%s", k);
    canon(tmp, name, sizeof(name));
  }
  hset(h, name, v);
}

/* validSSEReplicationHeaders */
static const char *sse_repl_header(const char *k) {
  static const struct {
    const char *internal, *repl;
  } m[] = {{"X-Minio-Internal-Server-Side-Encryption-Sealed-Key", "X-Minio-Replication-Server-Side-Encryption-Sealed-Key"},
           {"X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm", "X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm"},
           {"X-Minio-Internal-Server-Side-Encryption-Iv", "X-Minio-Replication-Server-Side-Encryption-Iv"},
           {"X-Minio-Internal-Encrypted-Multipart", "X-Minio-Replication-Encrypted-Multipart"},
           {"X-Minio-Internal-Actual-Object-Size", "X-Minio-Replication-Actual-Object-Size"}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(m); i++)
    if (strcmp(k, m[i].internal) == 0) return m[i].repl;
  return NULL;
}

/* The version's checksum headers for part (0: the object): x-amz-checksum-<alg>
 * values and X-Amz-Checksum-Algorithm; multipart set when composite. */
static void crc_headers(const buckets_object_info *oi, int part, hdrs *h, bool *multipart, bool *full_object) {
  if (multipart) *multipart = false;
  if (full_object) *full_object = false;
  if (!oi->checksum) return;
  buckets_http_response tmp = {.content_length = -1};
  buckets_checksum_write_headers(oi->checksum, oi->checksum_len, part, &tmp);
  buckets_str rest = buckets_buf_str(&tmp.headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str name, value;
    if (!buckets_str_cut(buckets_str_trim(line), ':', &name, &value)) continue;
    value = buckets_str_trim(value);
    if (value.n && value.p[value.n - 1] == '\r') value.n--;
    char *n = buckets_str_dup(name), *v = buckets_str_dup(value);
    if (fold_eq(n, "X-Amz-Checksum-Type")) {
      if (full_object && strcmp(v, "FULL_OBJECT") == 0) *full_object = true;
    } else {
      static const struct {
        const char *h, *alg;
      } a[] = {{"x-amz-checksum-crc32", "CRC32"}, {"x-amz-checksum-crc32c", "CRC32C"}, {"x-amz-checksum-sha1", "SHA1"},
               {"x-amz-checksum-sha256", "SHA256"}, {"x-amz-checksum-crc64nvme", "CRC64NVME"}};
      for (size_t i = 0; i < BUCKETS_ARRAY_LEN(a); i++) {
        if (!fold_eq(n, a[i].h)) continue;
        char cn[64];
        canon(a[i].h, cn, sizeof(cn));
        if (part == 0 && multipart && strchr(v, '-')) *multipart = true;
        hset(h, cn, v);
        hset(h, "X-Amz-Checksum-Algorithm", a[i].alg);
      }
    }
    free(n);
    free(v);
  }
  buckets_buf_free(&tmp.headers);
}

static const char *meta_fold(const buckets_object_info *oi, const char *k) { return kv_get_fold(oi->meta, oi->nmeta, k); }

/* A stored RFC3339 timestamp (x-minio-internal-...-timestamp), else mod time. */
static int64_t meta_ts(const buckets_object_info *oi, const char *key) {
  const char *v = sys_str(oi, key);
  long long s;
  long n;
  if (v && buckets_time_parse_rfc3339(v, &s, &n)) return (int64_t)s * 1000000000LL + n;
  return oi->mod_time_ns;
}

/* putReplicationOpts + PutObjectOptions.Header */
static void put_headers(const src_info *si, const char *tgt_sc, hdrs *h, bool *is_mp) {
  const buckets_object_info *oi = &si->oi;
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  const char *ct = meta_fold(oi, "content-type");
  hset(h, "Content-Type", ct && *ct ? ct : "application/octet-stream");
  const char *ce = meta_fold(oi, "content-encoding");
  if (ce && *ce) hset(h, "Content-Encoding", ce);
  const char *cd = meta_fold(oi, "content-disposition");
  if (cd && *cd) hset(h, "Content-Disposition", cd);
  const char *cl = meta_fold(oi, "content-language");
  if (cl && *cl) hset(h, "Content-Language", cl);
  const char *cc = meta_fold(oi, "cache-control");
  if (cc && *cc) hset(h, "Cache-Control", cc);
  const char *exp = meta_fold(oi, "expires");
  time_t et;
  if (exp && buckets_time_parse_http(buckets_str_c(exp), &et)) {
    char hb[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http(et, hb);
    hset(h, "Expires", hb);
  }
  const char *mode = meta_fold(oi, BUCKETS_LOCK_MODE_META);
  if (mode && *mode) hset(h, "X-Amz-Object-Lock-Mode", mode);
  const char *until = meta_fold(oi, BUCKETS_LOCK_UNTIL_META);
  if (until && *until) {
    long long s;
    long n;
    if (buckets_time_parse_rfc3339(until, &s, &n)) {
      char rd[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
      buckets_time_rfc3339_nano(s, 0, rd); /* RFC3339: no fraction */
      hset(h, "X-Amz-Object-Lock-Retain-Until-Date", rd);
      rfc3339nano(meta_ts(oi, BUCKETS_META_RETENTION_TS), ts);
      hset(h, BUCKETS_H_SRC_RET_TS, ts);
    }
  }
  const char *hold = meta_fold(oi, BUCKETS_LOCK_HOLD_META);
  if (hold && *hold) {
    hset(h, "X-Amz-Object-Lock-Legal-Hold", hold);
    rfc3339nano(meta_ts(oi, BUCKETS_META_LEGALHOLD_TS), ts);
    hset(h, BUCKETS_H_SRC_LH_TS, ts);
  }
  if (si->encrypted && !si->ssec) {
    if (buckets_s3_sse_kind_of(oi) == BUCKETS_SSE_KMS) {
      hset(h, "X-Amz-Server-Side-Encryption", "aws:kms");
      const char *kid = sys_str(oi, BUCKETS_SSE_META_KEY_ID);
      if (kid && *kid) {
        char arn[400];
        snprintf(arn, sizeof(arn), "%s", kid);
        hset(h, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", arn);
      }
    } else {
      hset(h, "X-Amz-Server-Side-Encryption", "AES256");
    }
  }
  const char *sc = tgt_sc && *tgt_sc ? tgt_sc : NULL;
  const char *osc = meta_fold(oi, "x-amz-storage-class");
  if (!sc && osc && (strcmp(osc, "STANDARD") == 0 || strcmp(osc, "REDUCED_REDUNDANCY") == 0)) sc = osc;
  if (sc) hset(h, "X-Amz-Storage-Class", sc);
  hset(h, BUCKETS_H_REPL_STATUS, BUCKETS_RS_REPLICA);
  rfc3339nano(oi->mod_time_ns, ts);
  hset(h, BUCKETS_H_SRC_MTIME, ts);
  if (si->oi.etag[0]) hset(h, BUCKETS_H_SRC_ETAG, si->oi.etag);
  hset(h, BUCKETS_H_SRC_REPL_REQUEST, "true");
  const char *tags = meta_fold(oi, "X-Amz-Tagging");
  if (tags && *tags) {
    buckets_tags t = {0};
    buckets_tags_error te;
    if (buckets_tags_parse_query(tags, true, &t, &te) && t.n) {
      buckets_buf b = BUCKETS_BUF_INIT;
      buckets_tags_string(&t, &b);
      buckets_buf_append_char(&b, '\0');
      hset(h, "X-Amz-Tagging", b.data);
      buckets_buf_free(&b);
      rfc3339nano(meta_ts(oi, BUCKETS_META_TAGGING_TS), ts);
      hset(h, BUCKETS_H_SRC_TAG_TS, ts);
    }
    buckets_tags_free(&t);
  }
  /* UserMetadata: what is left of the user's metadata; SSE-C objects
   * carry their sealed key along */
  for (size_t i = 0; i < oi->nmeta; i++) {
    const char *k = oi->meta[i].key;
    if (fold_prefix(k, BUCKETS_XL_RESERVED_PREFIX) || standard_header(k) || fold_eq(k, "etag")) continue;
    if (fold_eq(k, "expires")) continue; /* sent above */
    set_user_meta(h, k, (const char *)oi->meta[i].value);
  }
  if (si->ssec) {
    for (size_t i = 0; i < oi->nmeta_sys; i++) {
      const char *rh = sse_repl_header(oi->meta_sys[i].key);
      if (rh) hset(h, rh, (const char *)oi->meta_sys[i].value);
    }
  }
  *is_mp = src_multipart(si);
  if (oi->checksum && oi->checksum_len) {
    if (si->ssec) {
      char b64[512];
      if (oi->checksum_len * 4 / 3 + 8 < sizeof(b64)) {
        buckets_base64_encode(oi->checksum, oi->checksum_len, b64);
        hset(h, BUCKETS_H_REPL_SSEC_CRC, b64);
      }
    } else {
      bool mp = false, full = false;
      crc_headers(oi, 0, h, &mp, &full);
      *is_mp = mp;
      if (!src_multipart(si) && full) *is_mp = false;
    }
  }
}

/* ---- replicating one version to one target ---------------------------------------- */

typedef enum { ACT_NONE, ACT_METADATA, ACT_ALL } repl_action;

typedef struct {
  char arn[256];
  const char *prev;       /* previous status for this target */
  char status[16];        /* COMPLETED / FAILED / PENDING */
  char purge[16];         /* deletes: the version purge status */
  repl_action action;
  int64_t size;
  bool resynced;
  char resync_ts[128];
  char err[512];
  char code[64]; /* the remote's error code */
} tinfo;

static void query_vid(char *out, size_t cap, const char *vid) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "versionId=");
  buckets_url_encode(&b, vid, false);
  snprintf(out, cap, "%.*s", (int)b.len, b.data);
  buckets_buf_free(&b);
}

/* ---- bandwidth limits (MinIO's bucket bandwidth monitor): a token bucket
 * per target, shared by every transfer to it ---- */

typedef struct {
  char key[600];
  int64_t limit;  /* bytes per second */
  double tokens;
  int64_t last_ns;
} throttle;

static pthread_mutex_t g_thr_mu = PTHREAD_MUTEX_INITIALIZER;
static throttle *g_thr;
static size_t g_nthr;

static void throttle_take(const char *bucket, const char *arn, int64_t limit, size_t n) {
  if (limit <= 0) return;
  char key[600];
  snprintf(key, sizeof(key), "%s\n%s", bucket, arn);
  for (;;) {
    pthread_mutex_lock(&g_thr_mu);
    throttle *t = NULL;
    for (size_t i = 0; i < g_nthr; i++)
      if (strcmp(g_thr[i].key, key) == 0) t = &g_thr[i];
    if (!t) {
      g_thr = buckets_xrealloc(g_thr, (g_nthr + 1) * sizeof(*g_thr));
      t = &g_thr[g_nthr++];
      memset(t, 0, sizeof(*t));
      snprintf(t->key, sizeof(t->key), "%s", key);
      t->tokens = (double)limit;
      t->last_ns = mono_ns();
    }
    t->limit = limit;
    int64_t now = mono_ns();
    t->tokens += (double)(now - t->last_ns) / 1e9 * (double)limit;
    if (t->tokens > (double)limit) t->tokens = (double)limit; /* one second of burst */
    t->last_ns = now;
    double need = (double)n;
    if (t->tokens >= need || t->tokens >= (double)limit) {
      t->tokens -= need;
      pthread_mutex_unlock(&g_thr_mu);
      return;
    }
    double missing = need - t->tokens;
    pthread_mutex_unlock(&g_thr_mu);
    int64_t wait_ns = (int64_t)(missing / (double)limit * 1e9);
    if (wait_ns > 100000000) wait_ns = 100000000;
    struct timespec ts = {wait_ns / 1000000000LL, wait_ns % 1000000000LL};
    nanosleep(&ts, NULL);
  }
}

typedef struct {
  src_rd *rd;
  const char *bucket, *arn;
  int64_t limit;
} throttled;

static long throttled_read(void *ud, void *buf, size_t n) {
  throttled *t = ud;
  if (t->limit > 0 && n > 65536) n = 65536;
  long k = src_read(t->rd, buf, n);
  if (k > 0) throttle_take(t->bucket, t->arn, t->limit, (size_t)k);
  return k;
}

/* Where a version goes: a replication target, or a batch job's remote. */
typedef struct {
  buckets_s3c *c;
  const char *bucket, *object; /* the target's */
  const char *arn;             /* bandwidth limit key */
  int64_t limit;
  const char *endpoint; /* replication targets: marked offline on network errors */
  bool secure;
  bool plain;           /* no version ID (S3 targets of batch jobs) */
} dest;

static dest dest_of(buckets_repl_target *t, const char *object) {
  return (dest){t->c, t->t.target_bucket, object, t->t.arn, t->t.bandwidth_limit, t->t.endpoint, t->t.secure, false};
}

static void dest_offline(buckets_s3_server *s, const dest *d) {
  if (d->endpoint) mark_offline(s->repl, d->endpoint, d->secure);
}

static bool single_put(buckets_s3_server *s, const dest *d, const char *bucket, const char *object, src_info *si,
                       hdrs *h, tinfo *ti) {
  src_rd rd;
  if (!src_open(s, bucket, object, si, 0, si->oi.size, &rd)) {
    snprintf(ti->err, sizeof(ti->err), "unable to read source object");
    return false;
  }
  char q[128] = "";
  if (!d->plain) query_vid(q, sizeof(q), si->oi.version_id);
  buckets_s3c_result res;
  throttled th = {&rd, bucket, d->arn, d->limit};
  bool ok = buckets_s3c_do_stream(d->c, "PUT", d->bucket, d->object, q[0] ? q : NULL, h->kv, h->n, throttled_read, &th,
                                  si->oi.size, &res);
  src_close(&rd);
  if (!ok) {
    snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
    snprintf(ti->code, sizeof(ti->code), "%s", res.code);
    if (strcmp(res.code, "PreconditionFailed") == 0) ok = true;
    if (res.network) dest_offline(s, d);
  }
  buckets_s3c_result_free(&res);
  return ok;
}

static char *xml_text(const buckets_buf *body, const char *elem) {
  buckets_xml_doc d = {0};
  char *out = NULL;
  if (body->len && buckets_xml_parse((buckets_str){body->data, body->len}, &d) && d.count) {
    size_t n = buckets_xml_child(&d, 0, elem);
    if (n) {
      buckets_buf t = BUCKETS_BUF_INIT;
      buckets_xml_unescape(d.nodes[n].text, &t);
      out = buckets_xstrndup(t.data ? t.data : "", t.len);
      buckets_buf_free(&t);
    }
  }
  buckets_xml_doc_free(&d);
  return out;
}

/* replicateObjectWithMultipart */
static bool multipart_put(buckets_s3_server *s, const dest *d, const char *bucket, const char *object,
                          src_info *si, hdrs *h, tinfo *ti) {
  const char *vid = d->plain ? "null" : si->oi.version_id;
  char q[256];
  buckets_buf qb = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&qb, "uploads=");
  if (strcmp(vid, "null") != 0) {
    buckets_buf_append_c(&qb, "&versionId=");
    buckets_url_encode(&qb, vid, false);
  }
  snprintf(q, sizeof(q), "%.*s", (int)qb.len, qb.data);
  buckets_buf_free(&qb);
  /* a new upload must not carry the mtime */
  hdrs nh = {0};
  for (size_t i = 0; i < h->n; i++)
    if (!fold_eq(h->kv[i].name, BUCKETS_H_SRC_MTIME)) hset(&nh, h->kv[i].name, h->kv[i].value);
  char *upload_id = NULL;
  buckets_s3c_result res;
  for (int attempt = 0; attempt < 3 && !upload_id; attempt++) {
    bool ok = buckets_s3c_do(d->c, "POST", d->bucket, d->object, q, nh.kv, nh.n, NULL, 0, &res);
    if (ok) upload_id = xml_text(&res.body, "UploadId");
    else if (strcmp(res.code, "PreconditionFailed") == 0) {
      buckets_s3c_result_free(&res);
      hfree(&nh);
      return true;
    } else {
      snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
      if (res.network) dest_offline(s, d);
    }
    buckets_s3c_result_free(&res);
  }
  hfree(&nh);
  if (!upload_id) return false;
  buckets_buf complete = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&complete, "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
  bool ok = true;
  int64_t off = 0;
  buckets_buf uq = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < si->oi.nparts && ok; i++) {
    const buckets_xl_part *p = &si->oi.parts[i];
    int64_t size = si->ssec ? p->size : p->actual_size;
    hdrs ph = {0};
    if (!d->plain) hset(&ph, BUCKETS_H_SRC_REPL_REQUEST, "true");
    if (!si->ssec) crc_headers(&si->oi, p->number, &ph, NULL, NULL);
    /* PutObjectPart sends no checksum algorithm header */
    for (size_t k = 0; k < ph.n; k++) {
      if (fold_eq(ph.kv[k].name, "X-Amz-Checksum-Algorithm")) {
        free(ph.own[k]);
        free((char *)ph.kv[k].name);
        memmove(&ph.kv[k], &ph.kv[k + 1], (ph.n - k - 1) * sizeof(ph.kv[0]));
        memmove(&ph.own[k], &ph.own[k + 1], (ph.n - k - 1) * sizeof(ph.own[0]));
        ph.n--;
        k--;
      }
    }
    buckets_buf_reset(&uq);
    buckets_buf_appendf(&uq, "partNumber=%d&uploadId=", p->number);
    buckets_url_encode(&uq, upload_id, false);
    buckets_buf_append_char(&uq, '\0');
    src_rd rd;
    if (!src_open(s, bucket, object, si, off, size, &rd)) {
      snprintf(ti->err, sizeof(ti->err), "unable to read source object");
      hfree(&ph);
      ok = false;
      break;
    }
    throttled th = {&rd, bucket, d->arn, d->limit};
    ok = buckets_s3c_do_stream(d->c, "PUT", d->bucket, d->object, uq.data, ph.kv, ph.n, throttled_read, &th, size,
                               &res);
    src_close(&rd);
    hfree(&ph);
    if (!ok) {
      snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
      if (res.network) dest_offline(s, d);
      buckets_s3c_result_free(&res);
      break;
    }
    char etag[256];
    buckets_s3c_header_copy(&res, "ETag", etag, sizeof(etag));
    buckets_buf_appendf(&complete, "<Part><PartNumber>%d</PartNumber><ETag>", p->number);
    buckets_xml_text(&complete, etag, strlen(etag));
    buckets_buf_append_c(&complete, "</ETag>");
    static const struct {
      const char *h, *x;
    } ck[] = {{"x-amz-checksum-crc32", "ChecksumCRC32"}, {"x-amz-checksum-crc32c", "ChecksumCRC32C"},
              {"x-amz-checksum-sha1", "ChecksumSHA1"}, {"x-amz-checksum-sha256", "ChecksumSHA256"},
              {"x-amz-checksum-crc64nvme", "ChecksumCRC64NVME"}};
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(ck); k++) {
      char v[128];
      buckets_s3c_header_copy(&res, ck[k].h, v, sizeof(v));
      if (v[0]) buckets_buf_appendf(&complete, "<%s>%s</%s>", ck[k].x, v, ck[k].x);
    }
    buckets_buf_append_c(&complete, "</Part>");
    buckets_s3c_result_free(&res);
    off += size;
  }
  buckets_buf_append_c(&complete, "</CompleteMultipartUpload>");
  buckets_buf_reset(&uq);
  buckets_buf_append_c(&uq, "uploadId=");
  buckets_url_encode(&uq, upload_id, false);
  buckets_buf_append_char(&uq, '\0');
  if (ok) {
    hdrs ch = {0};
    hset(&ch, "Content-Type", "application/octet-stream");
    const char *as = sys_str(&si->oi, BUCKETS_ACTUAL_SIZE_META);
    hset(&ch, BUCKETS_H_REPL_ACTUAL_SIZE, as ? as : "");
    if (si->ssec) {
      const char *crc = meta_fold(&si->oi, BUCKETS_H_REPL_SSEC_CRC);
      if (crc && *crc) hset(&ch, BUCKETS_H_REPL_SSEC_CRC, crc);
    } else if (si->oi.checksum) {
      hdrs tmp = {0};
      crc_headers(&si->oi, 0, &tmp, NULL, NULL);
      for (size_t k = 0; k < tmp.n; k++) {
        char *v = buckets_xstrdup(tmp.kv[k].value), *dash = strchr(v, '-');
        if (dash) *dash = '\0';
        hset(&ch, tmp.kv[k].name, v);
        free(v);
      }
      hfree(&tmp);
    }
    char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    rfc3339nano(si->oi.mod_time_ns, ts);
    if (!d->plain) {
      hset(&ch, BUCKETS_H_SRC_MTIME, ts);
      if (si->oi.etag[0]) hset(&ch, BUCKETS_H_SRC_ETAG, si->oi.etag);
      hset(&ch, BUCKETS_H_SRC_REPL_REQUEST, "true");
    }
    ok = buckets_s3c_do(d->c, "POST", d->bucket, d->object, uq.data, ch.kv, ch.n, complete.data, complete.len, &res);
    if (ok && res.body.len && strstr(res.body.data, "<Error>")) {
      char *code = xml_text(&res.body, "Code");
      snprintf(ti->err, sizeof(ti->err), "%s", code ? code : "InternalError");
      free(code);
      ok = false;
    } else if (!ok) {
      snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
    }
    buckets_s3c_result_free(&res);
    hfree(&ch);
  }
  if (!ok) { /* abort the remote upload */
    for (int attempt = 0; attempt < 3; attempt++) {
      bool aok = buckets_s3c_do(d->c, "DELETE", d->bucket, d->object, uq.data, NULL, 0, NULL, 0, &res);
      buckets_s3c_result_free(&res);
      if (aok) break;
    }
  }
  buckets_buf_free(&uq);
  buckets_buf_free(&complete);
  free(upload_id);
  return ok;
}

/* The target's view of the version (StatObject with ACCESS tagging directive). */
typedef struct {
  bool ok;
  buckets_s3c_result res;
} remote_stat;

static bool header_eq(const buckets_s3c_result *r, const char *name, const char *want) {
  char v[1024];
  buckets_s3c_header_copy(r, name, v, sizeof(v));
  return strcmp(v, want ? want : "") == 0;
}

/* getReplicationAction */
static repl_action replication_action(const src_info *si, const buckets_s3c_result *r, buckets_repl_type op) {
  const buckets_object_info *oi = &si->oi;
  char etag[256], vid[64], lm[64], cl[32], dm[16];
  buckets_s3c_header_copy(r, "ETag", etag, sizeof(etag));
  char *e = etag;
  while (*e == '"') e++;
  size_t el = strlen(e);
  while (el && e[el - 1] == '"') e[--el] = '\0';
  buckets_s3c_header_copy(r, "X-Amz-Version-Id", vid, sizeof(vid));
  buckets_s3c_header_copy(r, "Last-Modified", lm, sizeof(lm));
  buckets_s3c_header_copy(r, "Content-Length", cl, sizeof(cl));
  buckets_s3c_header_copy(r, "X-Amz-Delete-Marker", dm, sizeof(dm));
  time_t lmt = 0;
  buckets_time_parse_http(buckets_str_c(lm), &lmt);
  int64_t src_s = oi->mod_time_ns / 1000000000LL;
  if (op == BUCKETS_REPL_EXISTING && src_s > (int64_t)lmt && strcmp(oi->version_id, "null") == 0) return ACT_NONE;
  const char *rvid = vid[0] ? vid : "null";
  int64_t sz = si->ssec ? buckets_s3_sse_actual_size(oi) : oi->size;
  if (strcmp(oi->etag, e) != 0 || strcmp(oi->version_id, rvid) != 0 || sz != strtoll(cl, NULL, 10) ||
      oi->delete_marker != (strcmp(dm, "true") == 0) || src_s != (int64_t)lmt)
    return ACT_ALL;
  const char *ct = meta_fold(oi, "content-type");
  if (!header_eq(r, "Content-Type", ct ? ct : "")) return ACT_METADATA;
  const char *ce = meta_fold(oi, "content-encoding");
  if (ce && *ce && !header_eq(r, "Content-Encoding", ce)) return ACT_METADATA;
  /* tags */
  const char *tags = meta_fold(oi, "X-Amz-Tagging");
  char rtags[4096], rcount[16];
  buckets_s3c_header_copy(r, "X-Amz-Tagging", rtags, sizeof(rtags));
  buckets_s3c_header_copy(r, "X-Amz-Tagging-Count", rcount, sizeof(rcount));
  buckets_tags a = {0}, b = {0};
  buckets_tags_error te;
  buckets_tags_parse_query(tags ? tags : "", true, &a, &te);
  buckets_tags_parse_query(rtags, true, &b, &te);
  long rc = strtol(rcount, NULL, 10);
  bool tags_differ = (size_t)rc != a.n;
  if (!tags_differ && rc > 0) {
    if (a.n != b.n) tags_differ = true;
    for (size_t i = 0; i < a.n && !tags_differ; i++) {
      const char *v = buckets_tags_get(&b, a.keys[i]);
      tags_differ = !v || strcmp(v, a.values[i]) != 0;
    }
  }
  buckets_tags_free(&a);
  buckets_tags_free(&b);
  if (tags_differ) return ACT_METADATA;
  /* the compared metadata: user-defined on one side, response headers on the other */
  static const char *const keys[] = {"Expires", "Cache-Control", "Content-Language", "Content-Disposition",
                                     "X-Amz-Object-Lock-Mode", "X-Amz-Object-Lock-Retain-Until-Date",
                                     "X-Amz-Object-Lock-Legal-Hold", "X-Amz-Website-Redirect-Location", "X-Amz-Meta-"};
  size_t n1 = 0, n2 = 0;
  for (size_t i = 0; i < oi->nmeta; i++) {
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(keys); k++) {
      if (!fold_prefix(oi->meta[i].key, keys[k])) continue;
      n1++;
      char v[1024];
      buckets_s3c_header_copy(r, oi->meta[i].key, v, sizeof(v));
      if (strcmp(v, (const char *)oi->meta[i].value) != 0 &&
          !(fold_eq(oi->meta[i].key, "expires") && buckets_s3c_header(r, "Expires", NULL)))
        return ACT_METADATA;
      break;
    }
  }
  buckets_str rest = buckets_buf_str(&r->headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str name, value;
    if (!buckets_str_cut(line, ':', &name, &value)) continue;
    char *nm = buckets_str_dup(buckets_str_trim(name));
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(keys); k++) {
      if (fold_prefix(nm, keys[k])) {
        n2++;
        break;
      }
    }
    free(nm);
  }
  if (n1 != n2) return ACT_METADATA;
  return ACT_NONE;
}

/* getCopyObjMetadata + Core.CopyObject: a metadata-only update of the
 * target's copy of the version. */
static bool copy_metadata(buckets_s3_server *s, buckets_repl_target *t, const char *object, const src_info *si,
                          tinfo *ti) {
  const buckets_object_info *oi = &si->oi;
  hdrs h = {0};
  for (size_t i = 0; i < oi->nmeta; i++) {
    const char *k = oi->meta[i].key;
    if (fold_prefix(k, BUCKETS_XL_RESERVED_PREFIX) || fold_eq(k, BUCKETS_H_REPL_STATUS) || fold_eq(k, "etag") ||
        fold_eq(k, "X-Amz-Meta-X-Amz-Unencrypted-Content-Length") || fold_eq(k, "X-Amz-Meta-X-Amz-Unencrypted-Content-Md5"))
      continue;
    char name[512];
    canon(k, name, sizeof(name));
    hset(&h, name, (const char *)oi->meta[i].value);
  }
  const char *ce = meta_fold(oi, "content-encoding");
  if (ce && *ce) hset(&h, "Content-Encoding", ce);
  const char *ct = meta_fold(oi, "content-type");
  if (ct && *ct) hset(&h, "Content-Type", ct);
  const char *tags = meta_fold(oi, "X-Amz-Tagging");
  hset(&h, "X-Amz-Tagging", tags ? tags : "");
  hset(&h, "X-Amz-Tagging-Directive", "REPLACE");
  const char *sc = t->t.storage_class && *t->t.storage_class ? t->t.storage_class : meta_fold(oi, "x-amz-storage-class");
  if (sc && (strcmp(sc, "STANDARD") == 0 || strcmp(sc, "REDUCED_REDUNDANCY") == 0)) hset(&h, "X-Amz-Storage-Class", sc);
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  hset(&h, BUCKETS_H_SRC_ETAG, oi->etag);
  rfc3339nano(oi->mod_time_ns, ts);
  hset(&h, BUCKETS_H_SRC_MTIME, ts);
  hset(&h, BUCKETS_H_REPL_STATUS, BUCKETS_RS_REPLICA);
  hset(&h, BUCKETS_H_SRC_REPL_REQUEST, "true");
  /* timestamps default to the modification time unless stored */
  if (meta_fold(oi, BUCKETS_LOCK_HOLD_META)) {
    rfc3339nano(meta_ts(oi, BUCKETS_META_LEGALHOLD_TS), ts);
    hset(&h, BUCKETS_H_SRC_LH_TS, ts);
  }
  if (meta_fold(oi, BUCKETS_LOCK_UNTIL_META)) {
    rfc3339nano(meta_ts(oi, BUCKETS_META_RETENTION_TS), ts);
    hset(&h, BUCKETS_H_SRC_RET_TS, ts);
  }
  if ((tags && *tags) || sys_str(oi, BUCKETS_META_TAGGING_TS)) {
    rfc3339nano(meta_ts(oi, BUCKETS_META_TAGGING_TS), ts);
    hset(&h, BUCKETS_H_SRC_TAG_TS, ts);
  }
  buckets_buf src = BUCKETS_BUF_INIT;
  buckets_url_encode(&src, t->t.target_bucket, true);
  buckets_buf_append_char(&src, '/');
  buckets_url_encode(&src, object, true);
  if (strcmp(oi->version_id, "null") != 0) buckets_buf_appendf(&src, "?versionId=%s", oi->version_id);
  buckets_buf_append_char(&src, '\0');
  hset(&h, "X-Amz-Copy-Source", src.data);
  buckets_buf_free(&src);
  char q[128];
  query_vid(q, sizeof(q), oi->version_id);
  buckets_s3c_result res;
  bool ok = buckets_s3c_do(t->c, "PUT", t->t.target_bucket, object, q, h.kv, h.n, NULL, 0, &res);
  if (!ok) {
    snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
    if (res.network) mark_offline(s->repl, t->t.endpoint, t->t.secure);
  }
  buckets_s3c_result_free(&res);
  hfree(&h);
  return ok;
}

/* replicateObject (all: replicateAll, which first asks the target what it has). */
static void replicate_to(buckets_s3_server *s, const job *j, buckets_repl_target *t, const char *prev_internal,
                         tinfo *ti) {
  snprintf(ti->arn, sizeof(ti->arn), "%s", t->t.arn);
  char prev[32];
  buckets_repl_target_status(prev_internal, t->t.arn, prev, sizeof(prev));
  snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_FAILED);
  bool all = j->op != BUCKETS_REPL_OBJECT;
  ti->action = all ? ACT_METADATA : ACT_ALL;
  if (buckets_repl_offline(s->repl, t->t.endpoint, t->t.secure)) {
    snprintf(ti->err, sizeof(ti->err), "remote target is offline for bucket:%s arn:%s", j->bucket, t->t.arn);
    return;
  }
  src_info si;
  buckets_obj_err gerr;
  if (!src_stat(s, j->bucket, j->object, j->version_id, &si, &gerr)) {
    snprintf(ti->err, sizeof(ti->err), "unable to read source object: %s", buckets_obj_strerror(gerr));
    snprintf(ti->status, sizeof(ti->status), "%s", prev[0] ? prev : BUCKETS_RS_FAILED);
    return;
  }
  if (!*t->t.target_bucket) {
    src_info_free(&si);
    return;
  }
  ti->size = si.ssec ? si.stored_size : si.oi.size;
  repl_action act = ACT_ALL;
  if (all) {
    hdrs sh = {0};
    hset(&sh, BUCKETS_H_SRC_PROXY, "false");
    hset(&sh, "X-Amz-Tagging-Directive", "ACCESS");
    char q[128];
    query_vid(q, sizeof(q), si.oi.version_id);
    buckets_s3c_result res;
    bool ok = buckets_s3c_do(t->c, "HEAD", t->t.target_bucket, j->object, strcmp(si.oi.version_id, "null") ? q : NULL,
                             sh.kv, sh.n, NULL, 0, &res);
    hfree(&sh);
    if (ok) {
      act = replication_action(&si, &res, j->op);
      if (act == ACT_NONE) {
        snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_COMPLETED);
        ti->action = ACT_NONE;
        buckets_s3c_result_free(&res);
        src_info_free(&si);
        return;
      }
    } else if (si.ssec && strcmp(res.code, "InvalidRequest") == 0) {
      /* SSE-C objects refuse HEAD without their key: the version exists */
      snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_COMPLETED);
      ti->action = ACT_NONE;
      buckets_s3c_result_free(&res);
      src_info_free(&si);
      return;
    } else if (res.status == 404 || res.status == 405 || res.status == 503 ||
               strcmp(res.code, "NoSuchKey") == 0 || strcmp(res.code, "NoSuchVersion") == 0 ||
               strcmp(res.code, "MethodNotAllowed") == 0) {
      act = ACT_ALL;
    } else {
      if (res.network) mark_offline(s->repl, t->t.endpoint, t->t.secure);
      snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
      buckets_s3c_result_free(&res);
      src_info_free(&si);
      return;
    }
    buckets_s3c_result_free(&res);
  }
  ti->action = act;
  bool ok;
  if (act == ACT_METADATA) {
    ok = copy_metadata(s, t, j->object, &si, ti);
  } else {
    hdrs h = {0};
    bool mp = false;
    put_headers(&si, t->t.storage_class, &h, &mp);
    dest d = dest_of(t, j->object);
    ok = mp ? multipart_put(s, &d, j->bucket, j->object, &si, &h, ti) : single_put(s, &d, j->bucket, j->object, &si, &h, ti);
    hfree(&h);
  }
  snprintf(ti->status, sizeof(ti->status), "%s", ok ? BUCKETS_RS_COMPLETED : BUCKETS_RS_FAILED);
  if (ok && j->op == BUCKETS_REPL_EXISTING && t->t.reset_id && *t->t.reset_id) {
    char hb[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http(time(NULL), hb);
    snprintf(ti->resync_ts, sizeof(ti->resync_ts), "%s;%s", hb, t->t.reset_id);
    ti->resynced = true;
  }
  src_info_free(&si);
}

/* ---- recording the outcome --------------------------------------------------------- */

typedef struct {
  const char *internal; /* new ReplicationStatusInternal */
  const char *composite;
  const tinfo *ti;
  size_t n;
  const char *tags;
} status_edit;

static buckets_obj_err edit_status(void *ud, const buckets_object_info *cur, buckets_xl_kv **user, size_t *nuser,
                                   buckets_xl_kv **sys, size_t *nsys) {
  (void)cur;
  status_edit *e = ud;
  buckets_xl_kv_set(sys, nsys, BUCKETS_META_REPL_STATUS, e->internal, strlen(e->internal));
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  rfc3339nano(now_ns(), ts);
  buckets_xl_kv_set(sys, nsys, BUCKETS_META_REPL_TS, ts, strlen(ts));
  buckets_xl_kv_set(user, nuser, BUCKETS_H_REPL_STATUS, e->composite, strlen(e->composite));
  for (size_t i = 0; i < e->n; i++) {
    if (!e->ti[i].resync_ts[0]) continue;
    char key[400];
    snprintf(key, sizeof(key), "%s-%s", BUCKETS_META_REPL_RESET, e->ti[i].arn);
    buckets_xl_kv_set(sys, nsys, key, e->ti[i].resync_ts, strlen(e->ti[i].resync_ts));
  }
  return BUCKETS_OBJ_OK;
}

static const char *overall(const tinfo *ti, size_t n) {
  if (!n) return "";
  size_t done = 0;
  for (size_t i = 0; i < n; i++) {
    if (strcmp(ti[i].status, BUCKETS_RS_FAILED) == 0) return BUCKETS_RS_FAILED;
    if (strcmp(ti[i].status, BUCKETS_RS_COMPLETED) == 0) done++;
  }
  return done == n ? BUCKETS_RS_COMPLETED : BUCKETS_RS_PENDING;
}

static void job_free(job *j) {
  if (!j) return;
  free(j->bucket);
  free(j->object);
  free(j->event);
  free(j->repl_status);
  free(j->purge_status);
  free(j->target_arn);
  free(j->reset_id);
  free(j);
}

static void enqueue(buckets_repl *r, job *j, bool mrf);
static void mrf_save(buckets_repl *r);
static void mrf_load(buckets_repl *r);

static void audit_repl(const char *event, const char *api, const char *bucket, const char *object, const char *vid,
                       const char *status) {
  const char *k[] = {"replicationStatus"};
  const char *v[] = {status};
  (void)k, (void)v;
  buckets_audit_internal(event ? event : "", api, bucket, object, vid, NULL, NULL, NULL, 0);
}

/* replicateObject: every target the rules pick, then the version's status. */
static void replicate_object(buckets_repl *r, job *j) {
  buckets_s3_server *s = r->s;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, j->bucket);
  if (!st->has_replication) {
    buckets_bucket_state_release(st);
    buckets_s3_send_internal_event(s, BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED, j->bucket, j->object, NULL,
                                   j->version_id, "Internal: [Replication]");
    return;
  }
  buckets_object_info cur;
  if (buckets_obj_stat(s->layer, j->bucket, j->object, j->version_id, &cur)) {
    buckets_bucket_state_release(st);
    return;
  }
  const char *tags = buckets_object_meta(&cur, "X-Amz-Tagging");
  buckets_repl_obj o = {.name = j->object, .ssec = sys_ssec(cur.meta_sys, cur.nmeta_sys), .user_tags = tags};
  char **arns = NULL;
  size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
  buckets_bucket_state_release(st);
  const char *prev_c = sys_str(&cur, BUCKETS_META_REPL_STATUS);
  char *prev = buckets_xstrdup(prev_c ? prev_c : "");
  tinfo *ti = buckets_xcalloc(na + 1, sizeof(*ti));
  size_t nti = 0;
  for (size_t i = 0; i < na; i++) {
    if (j->target_arn && strcmp(j->target_arn, arns[i]) != 0) {
      /* resync of another target: keep this one's status */
      snprintf(ti[nti].arn, sizeof(ti[nti].arn), "%s", arns[i]);
      buckets_repl_target_status(prev, arns[i], ti[nti].status, sizeof(ti[nti].status));
      if (!ti[nti].status[0]) continue;
      nti++;
      continue;
    }
    buckets_repl_target *t = buckets_repl_target_get(r, j->bucket, arns[i]);
    if (!t) {
      buckets_s3_send_internal_event(s, BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED, j->bucket, j->object, &cur,
                                     j->version_id, "Internal: [Replication]");
      continue;
    }
    int64_t t0 = mono_ns();
    replicate_to(s, j, t, prev, &ti[nti]);
    int64_t dur = mono_ns() - t0;
    {
      /* ReplicationStats.Update: data replications whose status changed */
      char was[32];
      buckets_repl_target_status(prev, arns[i], was, sizeof(was));
      bool data = j->op != BUCKETS_REPL_METADATA && ti[nti].action == ACT_ALL;
      bool done = strcmp(ti[nti].status, BUCKETS_RS_COMPLETED) == 0 && strcmp(was, BUCKETS_RS_COMPLETED) != 0;
      bool fail = strcmp(ti[nti].status, BUCKETS_RS_FAILED) == 0 && strcmp(was, BUCKETS_RS_PENDING) == 0;
      if (data && (done || fail)) buckets_repl_stats_update(j->bucket, arns[i], done, fail, ti[nti].size, dur);
    }
    if (ti[nti].err[0]) buckets_log_warn("replication: %s/%s(%s) to %s: %s", j->bucket, j->object, j->version_id,
                                         t->t.endpoint, ti[nti].err);
    buckets_repl_target_put(t);
    nti++;
  }
  buckets_replication_arns_free(arns, na);
  buckets_buf internal = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < nti; i++) buckets_buf_appendf(&internal, "%s=%s;", ti[i].arn, ti[i].status);
  buckets_buf_append_char(&internal, '\0');
  internal.len--;
  const char *ov = overall(ti, nti);
  bool resynced = false;
  for (size_t i = 0; i < nti; i++) resynced |= ti[i].resynced;
  buckets_object_info upd;
  memset(&upd, 0, sizeof(upd));
  bool have_upd = false;
  if (nti && (strcmp(prev, internal.data ? internal.data : "") != 0 || resynced)) {
    status_edit e = {internal.data ? internal.data : "", ov, ti, nti, tags};
    have_upd = buckets_obj_update_meta(s->layer, j->bucket, j->object, j->version_id, edit_status, &e, &upd) == BUCKETS_OBJ_OK;
  }
  int ev = strcmp(ov, BUCKETS_RS_FAILED) == 0 ? BUCKETS_EV_OBJECT_REPLICATION_FAILED : BUCKETS_EV_OBJECT_REPLICATION_COMPLETE;
  if (nti) buckets_s3_send_internal_event(s, ev, j->bucket, j->object, have_upd ? &upd : &cur, j->version_id,
                                          "Internal: [Replication]");
  audit_repl(j->event, "ReplicateObject", j->bucket, j->object, j->version_id, *ov ? ov : "");
  if (have_upd) buckets_object_info_free(&upd);
  buckets_object_info_free(&cur);
  /* failures go to the MRF queue, a few times; then the scanner takes over */
  if (nti && strcmp(ov, BUCKETS_RS_COMPLETED) != 0 && j->retry < MRF_RETRY_LIMIT) {
    job *m = buckets_xcalloc(1, sizeof(*m));
    m->kind = JOB_OBJECT;
    m->bucket = buckets_xstrdup(j->bucket);
    m->object = buckets_xstrdup(j->object);
    snprintf(m->version_id, sizeof(m->version_id), "%s", j->version_id);
    m->op = BUCKETS_REPL_HEAL;
    m->event = buckets_xstrdup("replicate:mrf");
    m->retry = j->retry + 1;
    m->qsize = j->qsize;
    enqueue(r, m, true);
  }
  buckets_buf_free(&internal);
  free(prev);
  free(ti);
}

/* replicateDeleteToTarget */
static void delete_to(buckets_s3_server *s, const job *j, buckets_repl_target *t, tinfo *ti) {
  snprintf(ti->arn, sizeof(ti->arn), "%s", t->t.arn);
  char prev[32] = "", prev_purge[32] = "";
  buckets_repl_target_status(j->repl_status, t->t.arn, prev, sizeof(prev));
  buckets_repl_target_status(j->purge_status, t->t.arn, prev_purge, sizeof(prev_purge));
  bool versioned_delete = !j->dm; /* VersionID set: a version removed for good */
  snprintf(ti->status, sizeof(ti->status), "%s", prev);
  snprintf(ti->purge, sizeof(ti->purge), "%s", prev_purge);
  if (!versioned_delete && strcmp(prev, BUCKETS_RS_COMPLETED) == 0 && j->op != BUCKETS_REPL_EXISTING) return;
  if (versioned_delete && strcmp(prev_purge, BUCKETS_VPS_COMPLETE) == 0) return;
  if (buckets_repl_offline(s->repl, t->t.endpoint, t->t.secure)) {
    if (versioned_delete) snprintf(ti->purge, sizeof(ti->purge), BUCKETS_VPS_FAILED);
    else snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_FAILED);
    snprintf(ti->err, sizeof(ti->err), "remote target is offline");
    return;
  }
  char q[128];
  query_vid(q, sizeof(q), j->version_id);
  buckets_s3c_result res;
  if (j->dm) { /* already replicated? (existing objects, healing) */
    hdrs sh = {0};
    hset(&sh, BUCKETS_H_SRC_PROXY, "false");
    hset(&sh, BUCKETS_H_CHECK_REPL_READY, "true");
    bool ok = buckets_s3c_do(t->c, "HEAD", t->t.target_bucket, j->object, q, sh.kv, sh.n, NULL, 0, &res);
    hfree(&sh);
    char ready[16];
    buckets_s3c_header_copy(&res, BUCKETS_H_REPL_READY, ready, sizeof(ready));
    if (!ok && res.status == 405) { /* the marker is there */
      snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_COMPLETED);
      buckets_s3c_result_free(&res);
      return;
    }
    bool nf = res.status == 404;
    if (!ok && !nf && res.status != 503) {
      if (res.network) mark_offline(s->repl, t->t.endpoint, t->t.secure);
      if (strcmp(ready, "true") != 0) {
        snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_FAILED);
        snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
        buckets_s3c_result_free(&res);
        return;
      }
    }
    buckets_s3c_result_free(&res);
  }
  hdrs h = {0};
  if (j->dm) hset(&h, "X-Minio-Source-Deletemarker", "true");
  if (j->dm_mtime) {
    char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    rfc3339nano(j->dm_mtime, ts);
    hset(&h, BUCKETS_H_SRC_MTIME, ts);
  }
  hset(&h, BUCKETS_H_REPL_STATUS, BUCKETS_RS_REPLICA);
  hset(&h, BUCKETS_H_SRC_REPL_REQUEST, "true");
  bool ok = buckets_s3c_do(t->c, "DELETE", t->t.target_bucket, j->object, q, h.kv, h.n, NULL, 0, &res) && res.status == 204;
  hfree(&h);
  if (!ok) {
    snprintf(ti->err, sizeof(ti->err), "%s", buckets_s3c_error(&res));
    if (versioned_delete) snprintf(ti->purge, sizeof(ti->purge), BUCKETS_VPS_FAILED);
    else snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_FAILED);
    if (res.network) mark_offline(s->repl, t->t.endpoint, t->t.secure);
  } else if (versioned_delete) {
    snprintf(ti->purge, sizeof(ti->purge), BUCKETS_VPS_COMPLETE);
  } else {
    snprintf(ti->status, sizeof(ti->status), BUCKETS_RS_COMPLETED);
  }
  buckets_s3c_result_free(&res);
  if (ok && j->op == BUCKETS_REPL_EXISTING && t->t.reset_id && *t->t.reset_id) {
    char hb[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http(time(NULL), hb);
    snprintf(ti->resync_ts, sizeof(ti->resync_ts), "%s;%s", hb, t->t.reset_id);
  }
}

/* replicateDelete */
static void replicate_delete(buckets_repl *r, job *j) {
  buckets_s3_server *s = r->s;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, j->bucket);
  bool has = st->has_replication;
  bool versioned = buckets_versioning_enabled_for(&st->versioning, j->object);
  bool suspended = st->versioning.status == BUCKETS_VERSIONING_SUSPENDED;
  buckets_bucket_state_release(st);
  if (!has) {
    buckets_s3_send_internal_event(s, BUCKETS_EV_OBJECT_REPLICATION_NOT_TRACKED, j->bucket, j->object, NULL,
                                   j->version_id, "Internal: [Replication]");
    return;
  }
  /* the targets the delete was queued for */
  const char *src = j->dm ? j->repl_status : j->purge_status;
  tinfo *ti = NULL;
  size_t nti = 0;
  {
    /* the targets in "arn=STATUS;", or just the one being resynced */
    const char *p = j->target_arn ? "" : (src ? src : "");
    bool one = j->target_arn != NULL;
    while (*p || one) {
      char arn[256];
      if (one) {
        snprintf(arn, sizeof(arn), "%s", j->target_arn);
        one = false;
      } else {
        const char *eq = strchr(p, '='), *semi = eq ? strchr(eq, ';') : NULL;
        if (!eq || !semi) break;
        snprintf(arn, sizeof(arn), "%.*s", (int)(eq - p), p);
        p = semi + 1;
      }
      buckets_repl_target *t = buckets_repl_target_get(r, j->bucket, arn);
      if (!t) continue;
      ti = buckets_xrealloc(ti, (nti + 1) * sizeof(*ti));
      memset(&ti[nti], 0, sizeof(ti[0]));
      delete_to(s, j, t, &ti[nti]);
      if (ti[nti].err[0]) buckets_log_warn("replication: delete %s/%s(%s) to %s: %s", j->bucket, j->object,
                                           j->version_id, t->t.endpoint, ti[nti].err);
      buckets_repl_target_put(t);
      nti++;
    }
  }
  buckets_buf rs = BUCKETS_BUF_INIT, ps = BUCKETS_BUF_INIT;
  size_t failed = 0, done = 0;
  for (size_t i = 0; i < nti; i++) {
    if (j->dm) {
      buckets_buf_appendf(&rs, "%s=%s;", ti[i].arn, ti[i].status);
      failed += strcmp(ti[i].status, BUCKETS_RS_FAILED) == 0;
      done += strcmp(ti[i].status, BUCKETS_RS_COMPLETED) == 0;
    } else {
      if (ti[i].purge[0]) buckets_buf_appendf(&ps, "%s=%s;", ti[i].arn, ti[i].purge);
      failed += strcmp(ti[i].purge, BUCKETS_VPS_FAILED) == 0;
      done += strcmp(ti[i].purge, BUCKETS_VPS_COMPLETE) == 0;
    }
  }
  buckets_buf_append_char(&rs, '\0');
  rs.len--;
  buckets_buf_append_char(&ps, '\0');
  ps.len--;
  bool all_done = nti && done == nti;
  const char *status = !nti ? "" : failed ? BUCKETS_RS_FAILED : all_done ? BUCKETS_RS_COMPLETED : BUCKETS_RS_PENDING;
  /* record the outcome on the source (DeleteObject with the new state) */
  const char *prev = j->dm ? j->repl_status : j->purge_status;
  const char *now = j->dm ? rs.data : ps.data;
  if (nti) {
    buckets_delete_opts o = {.version_id = j->version_id, .versioned = versioned, .suspended = suspended,
                             .mod_time_ns = j->dm_mtime};
    const char *rk[64], *rv[64];
    char keys[64][300];
    size_t nr = 0;
    for (size_t i = 0; i < nti && nr < 64; i++) {
      if (!ti[i].resync_ts[0]) continue;
      snprintf(keys[nr], sizeof(keys[nr]), "%s-%s", BUCKETS_META_REPL_RESET, ti[i].arn);
      rk[nr] = keys[nr];
      rv[nr] = ti[i].resync_ts;
      nr++;
    }
    o.reset_keys = rk, o.reset_values = rv, o.nreset = nr;
    if (j->dm) {
      o.repl_status = rs.data;
      if (strcmp(prev ? prev : "", now ? now : "") != 0) o.repl_ts_ns = now_ns();
    } else {
      o.purge_status = ps.data;
    }
    buckets_delete_result res;
    buckets_obj_err err = buckets_obj_delete_ex(s->layer, j->bucket, j->object, &o, &res);
    (void)err;
  }
  int ev = failed ? BUCKETS_EV_OBJECT_REPLICATION_FAILED : BUCKETS_EV_OBJECT_REPLICATION_COMPLETE;
  if (nti) buckets_s3_send_internal_event(s, ev, j->bucket, j->object, NULL, j->version_id, "Internal: [Replication]");
  audit_repl(j->event, "ReplicateDelete", j->bucket, j->object, j->version_id, status);
  if (failed && j->retry < MRF_RETRY_LIMIT) {
    job *m = buckets_xcalloc(1, sizeof(*m));
    *m = *j;
    m->next = NULL;
    m->bucket = buckets_xstrdup(j->bucket);
    m->object = buckets_xstrdup(j->object);
    m->event = buckets_xstrdup("replicate:mrf");
    m->repl_status = buckets_xstrdup(j->dm ? rs.data : (j->repl_status ? j->repl_status : ""));
    m->purge_status = buckets_xstrdup(j->dm ? (j->purge_status ? j->purge_status : "") : ps.data);
    m->target_arn = j->target_arn ? buckets_xstrdup(j->target_arn) : NULL;
    m->reset_id = j->reset_id ? buckets_xstrdup(j->reset_id) : NULL;
    m->retry = j->retry + 1;
    enqueue(r, m, true);
  }
  buckets_buf_free(&rs);
  buckets_buf_free(&ps);
  free(ti);
}

/* ---- workers -------------------------------------------------------------------------- */

static int mrf_delay_ms(void) {
  const char *e = getenv("BUCKETS_REPLICATION_MRF_DELAY_MS");
  int v = e ? atoi(e) : 0;
  return v > 0 ? v : 60000;
}

static void *worker_main(void *arg) {
  worker *w = arg;
  buckets_repl *r = w->r;
  for (;;) {
    pthread_mutex_lock(&w->mu);
    for (;;) {
      while (!w->head && !atomic_load(&r->stop)) pthread_cond_wait(&w->cv, &w->mu);
      if (atomic_load(&r->stop) || !w->mrf) break;
      /* retries wait for their time, staying queued (and saved at shutdown) */
      int64_t wait = w->head->due_ns - mono_ns();
      if (wait <= 0) break;
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      int64_t ns = ts.tv_nsec + (wait < 1000000000LL ? wait : 1000000000LL);
      ts.tv_sec += ns / 1000000000LL;
      ts.tv_nsec = ns % 1000000000LL;
      pthread_cond_timedwait(&w->cv, &w->mu, &ts);
    }
    if (atomic_load(&r->stop)) {
      pthread_mutex_unlock(&w->mu);
      break;
    }
    job *j = w->head;
    w->head = j->next;
    if (!w->head) w->tail = NULL;
    w->n--;
    pthread_mutex_unlock(&w->mu);
    atomic_fetch_add(&r->active, 1);
    buckets_repl_stats_workers(1);
    buckets_repl_stats_queue(j->bucket, j->qsize, -1);
    if (r->s->layer && r->s->meta) {
      if (j->kind == JOB_OBJECT) replicate_object(r, j);
      else replicate_delete(r, j);
    }
    atomic_fetch_sub(&r->active, 1);
    buckets_repl_stats_workers(-1);
    job_free(j);
  }
  return NULL;
}

static void enqueue(buckets_repl *r, job *j, bool mrf) {
  if (!r || atomic_load(&r->stop)) {
    job_free(j);
    return;
  }
  worker *w;
  if (mrf) {
    w = &r->mrf;
  } else {
    char key[2048];
    snprintf(key, sizeof(key), "%s%s", j->bucket, j->object);
    w = &r->w[buckets_xxh64(key, strlen(key)) % REPL_WORKERS];
  }
  pthread_mutex_lock(&w->mu);
  if (w->n >= REPL_QUEUE_MAX) {
    pthread_mutex_unlock(&w->mu);
    buckets_log_warn("replication: unable to keep up with incoming traffic");
    if (mrf) buckets_repl_stats_mrf_dropped(j->qsize);
    job_free(j);
    return;
  }
  buckets_repl_stats_queue(j->bucket, j->qsize, 1);
  if (mrf) j->due_ns = mono_ns() + (int64_t)mrf_delay_ms() * 1000000LL;
  if (w->tail) w->tail->next = j;
  else w->head = j;
  w->tail = j;
  w->n++;
  pthread_cond_signal(&w->cv);
  pthread_mutex_unlock(&w->mu);
}

static void worker_start(buckets_repl *r, worker *w, bool mrf) {
  pthread_mutex_init(&w->mu, NULL);
  pthread_cond_init(&w->cv, NULL);
  w->r = r;
  w->mrf = mrf;
  w->started = pthread_create(&w->th, NULL, worker_main, w) == 0;
}

buckets_repl *buckets_repl_new(buckets_s3_server *s) {
  buckets_repl *r = buckets_xcalloc(1, sizeof(*r));
  r->s = s;
  pthread_mutex_init(&r->mu, NULL);
  pthread_mutex_init(&r->stop_mu, NULL);
  pthread_cond_init(&r->stop_cv, NULL);
  for (size_t i = 0; i < REPL_WORKERS; i++) worker_start(r, &r->w[i], false);
  worker_start(r, &r->mrf, true);
  r->hc_started = pthread_create(&r->hc_thread, NULL, hc_main, r) == 0;
  buckets_repl_stats_init();
  return r;
}

void buckets_repl_stop(buckets_repl *r) {
  if (!r || atomic_exchange(&r->stop, true)) return;
  pthread_mutex_lock(&r->stop_mu);
  pthread_cond_broadcast(&r->stop_cv);
  pthread_mutex_unlock(&r->stop_mu);
  worker *all[REPL_WORKERS + 1];
  for (size_t i = 0; i < REPL_WORKERS; i++) all[i] = &r->w[i];
  all[REPL_WORKERS] = &r->mrf;
  for (size_t i = 0; i <= REPL_WORKERS; i++) {
    pthread_mutex_lock(&all[i]->mu);
    pthread_cond_broadcast(&all[i]->cv);
    pthread_mutex_unlock(&all[i]->mu);
  }
  for (size_t i = 0; i <= REPL_WORKERS; i++)
    if (all[i]->started) pthread_join(all[i]->th, NULL);
  if (r->hc_started) pthread_join(r->hc_thread, NULL);
  if (r->s->layer) mrf_save(r); /* the retries still waiting */
}

void buckets_repl_free(buckets_repl *r) {
  if (!r) return;
  buckets_repl_stop(r);
  worker *all[REPL_WORKERS + 1];
  for (size_t i = 0; i < REPL_WORKERS; i++) all[i] = &r->w[i];
  all[REPL_WORKERS] = &r->mrf;
  for (size_t i = 0; i <= REPL_WORKERS; i++) {
    for (job *j = all[i]->head, *nx; j; j = nx) {
      nx = j->next;
      job_free(j);
    }
  }
  size_t it = 0;
  void *v;
  while (buckets_strmap_next(&r->targets, &it, NULL, &v)) target_unref(v);
  buckets_strmap_free(&r->targets);
  free(r->hc);
  if (r->tls) buckets_tls_client_free(r->tls);
  free(r);
}

/* ---- scheduling ------------------------------------------------------------------------ */

void buckets_repl_schedule(buckets_s3_server *s, const char *bucket, const buckets_object_info *oi,
                           const buckets_repl_dsc *d, buckets_repl_type op, const char *event) {
  if (!s->repl || !buckets_repl_dsc_any(d)) return;
  job *j = buckets_xcalloc(1, sizeof(*j));
  j->kind = JOB_OBJECT;
  j->bucket = buckets_xstrdup(bucket);
  j->object = buckets_xstrdup(oi->name);
  snprintf(j->version_id, sizeof(j->version_id), "%s", oi->version_id);
  j->op = op;
  j->qsize = oi->size;
  j->event = buckets_xstrdup(event ? event : "replicate:incoming");
  if (buckets_repl_dsc_sync(d)) {
    replicate_object(s->repl, j);
    job_free(j);
    return;
  }
  enqueue(s->repl, j, false);
}

void buckets_repl_schedule_delete(buckets_s3_server *s, const char *bucket, const char *object,
                                  const buckets_delete_result *res, const char *event) {
  if (!s->repl) return;
  const char *st = res->delete_marker ? buckets_repl_composite_status(res->repl_status)
                                      : buckets_repl_composite_purge(res->purge_status);
  if (strcmp(st, BUCKETS_RS_PENDING) != 0) return;
  job *j = buckets_xcalloc(1, sizeof(*j));
  j->kind = JOB_DELETE;
  j->bucket = buckets_xstrdup(bucket);
  j->object = buckets_xstrdup(object);
  snprintf(j->version_id, sizeof(j->version_id), "%s", res->version_id);
  j->dm = res->delete_marker;
  j->dm_mtime = res->mod_time_ns;
  j->repl_status = buckets_xstrdup(res->repl_status);
  j->purge_status = buckets_xstrdup(res->purge_status);
  j->op = BUCKETS_REPL_DELETE;
  j->event = buckets_xstrdup(event ? event : "replicate:incoming:delete");
  enqueue(s->repl, j, false);
}

/* ---- proxying (active-active) ---------------------------------------------------------- */

bool buckets_repl_proxy_open(buckets_repl *r, const char *bucket, const char *object, const char *version_id,
                             const char *range, bool head, buckets_repl_proxy *out) {
  memset(out, 0, sizeof(*out));
  if (!r || !r->s->meta) return false;
  buckets_bucket_state *st = buckets_metasys_get(r->s->meta, bucket);
  if (!st->has_replication || st->versioning.status == BUCKETS_VERSIONING_SUSPENDED) {
    buckets_bucket_state_release(st);
    return false;
  }
  buckets_repl_obj o = {.name = object};
  char **arns = NULL;
  size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
  buckets_bucket_state_release(st);
  bool found = false;
  for (size_t i = 0; i < na && !found; i++) {
    buckets_repl_target *t = buckets_repl_target_get(r, bucket, arns[i]);
    if (!t) continue;
    if (t->t.disable_proxy || buckets_repl_offline(r, t->t.endpoint, t->t.secure)) {
      buckets_repl_target_put(t);
      continue;
    }
    hdrs h = {0};
    hset(&h, BUCKETS_H_SRC_PROXY, "true");
    if (range && *range) hset(&h, "Range", range);
    char q[128] = "";
    if (version_id && *version_id) query_vid(q, sizeof(q), version_id);
    if (head) {
      found = buckets_s3c_do(t->c, "HEAD", t->t.target_bucket, object, q[0] ? q : NULL, h.kv, h.n, NULL, 0, &out->res);
    } else {
      out->body = buckets_s3c_open(t->c, "GET", t->t.target_bucket, object, q[0] ? q : NULL, h.kv, h.n, &out->res);
      found = out->body != NULL;
    }
    hfree(&h);
    buckets_repl_stats_proxy(bucket, head ? BUCKETS_REPL_PROXY_HEAD : BUCKETS_REPL_PROXY_GET, !found);
    if (found) {
      out->t = t;
    } else {
      if (out->res.network) mark_offline(r, t->t.endpoint, t->t.secure);
      buckets_s3c_result_free(&out->res);
      buckets_repl_target_put(t);
    }
  }
  buckets_replication_arns_free(arns, na);
  return found;
}

void buckets_repl_proxy_close(buckets_repl_proxy *p) {
  if (p->body) buckets_http_stream_free(p->body);
  buckets_s3c_result_free(&p->res);
  if (p->t) buckets_repl_target_put(p->t);
  memset(p, 0, sizeof(*p));
}

/* ---- existing objects: heal decisions and resync ---------------------------------------
 * getHealReplicateObjectInfo, replicationConfig.Resync / resyncTarget and the
 * replicationResyncer (resyncBucket, its status in
 * .minio.sys/buckets/<bucket>/.replication/resync.bin). */

/* resyncTarget: whether a version must go (again) to arn for its reset. */
static bool resync_target(const buckets_object_info *oi, const buckets_bucket_target *t, const char *tgt_status) {
  char key[400];
  snprintf(key, sizeof(key), "%s-%s", BUCKETS_META_REPL_RESET, t->arn);
  const char *rs = sys_str(oi, key);
  if (!rs) rs = meta_fold(oi, "X-Minio-Replication-Reset-Status"); /* older releases */
  bool has_before = t->reset_before_sec != BUCKETS_GO_ZERO_SEC;
  int64_t before = has_before ? t->reset_before_sec * 1000000000LL + t->reset_before_nsec : 0;
  if (!rs) {
    if (*t->reset_id && has_before && oi->mod_time_ns < before) return true;
    return !tgt_status || !*tgt_status;
  }
  if (!*t->reset_id || (t->reset_before_sec == 0 && t->reset_before_nsec == 0)) return false;
  const char *semi = strchr(rs, ';');
  if (!semi) return false;
  bool new_reset = strcmp(semi + 1, t->reset_id) != 0;
  if (!new_reset && tgt_status && strcmp(tgt_status, BUCKETS_RS_COMPLETED) == 0) return false;
  return new_reset && has_before && oi->mod_time_ns < before;
}

/* For one version and one target: does the target's existing-object resync
 * want it (rcfg.Resync), and is it replicated there at all (dsc)? */
static bool version_needs_resync(buckets_s3_server *s, const char *bucket, const buckets_object_info *oi,
                                 const buckets_bucket_target *t) {
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  bool want = false;
  const char *ps = sys_str(oi, BUCKETS_META_PURGE_STATUS);
  bool purge = ps && *ps;
  if (st->has_replication) {
    buckets_repl_obj o = {.name = oi->name, .target_arn = t->arn};
    if (oi->delete_marker && !purge) {
      o.delete_marker = true;
      o.version_id = oi->version_id;
      o.op = BUCKETS_REPL_DELETE;
      o.existing = true;
    } else {
      o.user_tags = buckets_object_meta(oi, "X-Amz-Tagging");
      o.ssec = sys_ssec(oi->meta_sys, oi->nmeta_sys);
      o.existing = true;
    }
    char **arns = NULL;
    size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
    for (size_t i = 0; i < na && !want; i++)
      if (strcmp(arns[i], t->arn) == 0) want = buckets_replication_replicate(&st->replication, &o);
    buckets_replication_arns_free(arns, na);
  }
  buckets_bucket_state_release(st);
  if (!want) return false;
  char tst[32];
  buckets_repl_target_status(sys_str(oi, BUCKETS_META_REPL_STATUS), t->arn, tst, sizeof(tst));
  return resync_target(oi, t, tst);
}

/* The resync status of a bucket's targets (BucketReplicationResyncStatus). */
typedef enum { RS_NONE = 0, RS_PENDING, RS_CANCELED, RS_STARTED, RS_COMPLETED, RS_FAILED } rs_state;

static const char *rs_state_name(int st) {
  switch (st) {
  case RS_STARTED: return "Ongoing";
  case RS_COMPLETED: return "Completed";
  case RS_FAILED: return "Failed";
  case RS_PENDING: return "Pending";
  case RS_CANCELED: return "Canceled";
  }
  return "";
}

typedef struct {
  char *arn;
  int64_t start_sec, lu_sec, before_sec;
  int32_t start_nsec, lu_nsec, before_nsec;
  char *id;
  int64_t status;
  int64_t failed_size, failed_count, repl_size, repl_count;
  char *bucket, *object;
} rs_tgt;

typedef struct {
  int64_t version, id;
  int64_t lu_sec;
  int32_t lu_nsec;
  rs_tgt *t;
  size_t n;
} rs_bucket;

static void rs_bucket_free(rs_bucket *b) {
  for (size_t i = 0; i < b->n; i++) {
    free(b->t[i].arn);
    free(b->t[i].id);
    free(b->t[i].bucket);
    free(b->t[i].object);
  }
  free(b->t);
  memset(b, 0, sizeof(*b));
}

static void rs_now(int64_t *sec, int32_t *nsec) {
  int64_t ns = now_ns();
  *sec = ns / 1000000000LL;
  *nsec = (int32_t)(ns % 1000000000LL);
}

static rs_tgt *rs_find(rs_bucket *b, const char *arn, bool add) {
  for (size_t i = 0; i < b->n; i++)
    if (strcmp(b->t[i].arn, arn) == 0) return &b->t[i];
  if (!add) return NULL;
  b->t = buckets_xrealloc(b->t, (b->n + 1) * sizeof(*b->t));
  rs_tgt *t = &b->t[b->n++];
  memset(t, 0, sizeof(*t));
  t->arn = buckets_xstrdup(arn);
  t->id = buckets_xstrdup("");
  t->bucket = buckets_xstrdup("");
  t->object = buckets_xstrdup("");
  t->start_sec = t->lu_sec = t->before_sec = BUCKETS_GO_ZERO_SEC;
  return t;
}

static void rs_encode(const rs_bucket *b, buckets_buf *out) {
  uint8_t hdr[4] = {1, 0, 1, 0}; /* resyncMetaFormat, resyncMetaVersion (LE) */
  buckets_buf_append(out, hdr, 4);
  buckets_mp_map(out, 4);
  buckets_mp_cstr(out, "v");
  buckets_mp_int(out, b->version ? b->version : 1);
  buckets_mp_cstr(out, "brs");
  buckets_mp_map(out, (uint32_t)b->n);
  for (size_t i = 0; i < b->n; i++) {
    const rs_tgt *t = &b->t[i];
    buckets_mp_cstr(out, t->arn);
    buckets_mp_map(out, 11);
    buckets_mp_cstr(out, "st");
    buckets_mp_time_sec(out, t->start_sec, t->start_nsec);
    buckets_mp_cstr(out, "lst");
    buckets_mp_time_sec(out, t->lu_sec, t->lu_nsec);
    buckets_mp_cstr(out, "id");
    buckets_mp_cstr(out, t->id);
    buckets_mp_cstr(out, "rdt");
    buckets_mp_time_sec(out, t->before_sec, t->before_nsec);
    buckets_mp_cstr(out, "rst");
    buckets_mp_int(out, t->status);
    buckets_mp_cstr(out, "fs");
    buckets_mp_int(out, t->failed_size);
    buckets_mp_cstr(out, "frc");
    buckets_mp_int(out, t->failed_count);
    buckets_mp_cstr(out, "rs");
    buckets_mp_int(out, t->repl_size);
    buckets_mp_cstr(out, "rrc");
    buckets_mp_int(out, t->repl_count);
    buckets_mp_cstr(out, "bkt");
    buckets_mp_cstr(out, t->bucket);
    buckets_mp_cstr(out, "obj");
    buckets_mp_cstr(out, t->object);
  }
  buckets_mp_cstr(out, "id");
  buckets_mp_int(out, b->id);
  buckets_mp_cstr(out, "lu");
  buckets_mp_time_sec(out, b->lu_sec, b->lu_nsec);
}

static char *mp_strdup(buckets_mp_reader *r, bool *ok) {
  buckets_str s;
  if (buckets_mp_read_nil(r)) return buckets_xstrdup("");
  if (!buckets_mp_read_str(r, &s)) {
    *ok = false;
    return buckets_xstrdup("");
  }
  return buckets_str_dup(s);
}

static bool rs_decode(const void *data, size_t n, rs_bucket *b) {
  memset(b, 0, sizeof(*b));
  b->lu_sec = BUCKETS_GO_ZERO_SEC;
  const uint8_t *p = data;
  if (n <= 4 || p[0] != 1 || p[1] != 0 || p[2] != 1 || p[3] != 0) return false;
  buckets_mp_reader r = buckets_mp_reader_init(p + 4, n - 4);
  uint32_t nf;
  if (!buckets_mp_read_map(&r, &nf)) return false;
  bool ok = true;
  for (uint32_t i = 0; i < nf && ok; i++) {
    buckets_str k;
    if (!buckets_mp_read_str(&r, &k)) return false;
    if (buckets_str_eq_c(k, "v")) ok = buckets_mp_read_int(&r, &b->version);
    else if (buckets_str_eq_c(k, "id")) ok = buckets_mp_read_int(&r, &b->id);
    else if (buckets_str_eq_c(k, "lu")) ok = buckets_mp_read_time_sec(&r, &b->lu_sec, &b->lu_nsec);
    else if (buckets_str_eq_c(k, "brs")) {
      uint32_t nt;
      if (buckets_mp_read_nil(&r)) continue;
      if (!buckets_mp_read_map(&r, &nt)) return false;
      for (uint32_t j = 0; j < nt && ok; j++) {
        buckets_str arn;
        if (!buckets_mp_read_str(&r, &arn)) return false;
        char *a = buckets_str_dup(arn);
        rs_tgt *t = rs_find(b, a, true);
        free(a);
        uint32_t tf;
        if (!buckets_mp_read_map(&r, &tf)) return false;
        for (uint32_t m = 0; m < tf && ok; m++) {
          buckets_str f;
          if (!buckets_mp_read_str(&r, &f)) return false;
          if (buckets_str_eq_c(f, "st")) ok = buckets_mp_read_time_sec(&r, &t->start_sec, &t->start_nsec);
          else if (buckets_str_eq_c(f, "lst")) ok = buckets_mp_read_time_sec(&r, &t->lu_sec, &t->lu_nsec);
          else if (buckets_str_eq_c(f, "rdt")) ok = buckets_mp_read_time_sec(&r, &t->before_sec, &t->before_nsec);
          else if (buckets_str_eq_c(f, "id")) {
            free(t->id);
            t->id = mp_strdup(&r, &ok);
          } else if (buckets_str_eq_c(f, "rst")) ok = buckets_mp_read_int(&r, &t->status);
          else if (buckets_str_eq_c(f, "fs")) ok = buckets_mp_read_int(&r, &t->failed_size);
          else if (buckets_str_eq_c(f, "frc")) ok = buckets_mp_read_int(&r, &t->failed_count);
          else if (buckets_str_eq_c(f, "rs")) ok = buckets_mp_read_int(&r, &t->repl_size);
          else if (buckets_str_eq_c(f, "rrc")) ok = buckets_mp_read_int(&r, &t->repl_count);
          else if (buckets_str_eq_c(f, "bkt")) {
            free(t->bucket);
            t->bucket = mp_strdup(&r, &ok);
          } else if (buckets_str_eq_c(f, "obj")) {
            free(t->object);
            t->object = mp_strdup(&r, &ok);
          } else ok = buckets_mp_skip(&r);
        }
      }
    } else ok = buckets_mp_skip(&r);
  }
  if (!ok) rs_bucket_free(b);
  return ok;
}

static void rs_path(const char *bucket, char *out, size_t cap) {
  snprintf(out, cap, "buckets/%s/.replication/resync.bin", bucket);
}

static bool rs_load(buckets_s3_server *s, const char *bucket, rs_bucket *b) {
  char path[1200];
  rs_path(bucket, path, sizeof(path));
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_obj_err err = buckets_sysconfig_read(s->layer, path, &data, NULL);
  bool ok = true;
  if (err == BUCKETS_OBJ_OK) ok = rs_decode(data.data, data.len, b);
  else {
    memset(b, 0, sizeof(*b));
    b->version = 1;
    b->lu_sec = BUCKETS_GO_ZERO_SEC;
    ok = err == BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  buckets_buf_free(&data);
  return ok;
}

static void rs_save(buckets_s3_server *s, const char *bucket, const rs_bucket *b) {
  char path[1200];
  rs_path(bucket, path, sizeof(path));
  buckets_buf data = BUCKETS_BUF_INIT;
  rs_encode(b, &data);
  buckets_sysconfig_write(s->layer, path, data.data, data.len);
  buckets_buf_free(&data);
}

/* The status of one resync (in memory while it runs, saved as it goes). */
typedef struct {
  buckets_repl *r;
  char *bucket, *arn;
  bool heal; /* resuming after a restart: from the last object */
} rs_run;

static pthread_mutex_t g_rs_mu = PTHREAD_MUTEX_INITIALIZER;

/* Updates arn's status in the bucket's saved resync status. */
static void rs_update(buckets_s3_server *s, const char *bucket, const char *arn, int status, const char *object,
                      int64_t ok_size, int64_t ok_count, int64_t fail_size, int64_t fail_count) {
  pthread_mutex_lock(&g_rs_mu);
  rs_bucket b;
  if (rs_load(s, bucket, &b)) {
    rs_tgt *t = rs_find(&b, arn, true);
    if (status >= 0) t->status = status;
    if (object) {
      free(t->object);
      t->object = buckets_xstrdup(object);
      free(t->bucket);
      t->bucket = buckets_xstrdup(bucket);
    }
    t->repl_size += ok_size;
    t->repl_count += ok_count;
    t->failed_size += fail_size;
    t->failed_count += fail_count;
    rs_now(&t->lu_sec, &t->lu_nsec);
    rs_now(&b.lu_sec, &b.lu_nsec);
    rs_save(s, bucket, &b);
    rs_bucket_free(&b);
  }
  pthread_mutex_unlock(&g_rs_mu);
}

static void *rs_main(void *arg) {
  rs_run *run = arg;
  buckets_repl *r = run->r;
  buckets_s3_server *s = r->s;
  int final = RS_FAILED;
  buckets_repl_target *t = buckets_repl_target_get(r, run->bucket, run->arn);
  if (!t) goto done;
  rs_update(s, run->bucket, run->arn, RS_STARTED, NULL, 0, 0, 0, 0);
  char *checkpoint = NULL;
  if (run->heal) {
    rs_bucket b;
    pthread_mutex_lock(&g_rs_mu);
    if (rs_load(s, run->bucket, &b)) {
      rs_tgt *rt = rs_find(&b, run->arn, false);
      if (rt && rt->object && *rt->object) checkpoint = buckets_xstrdup(rt->object);
      rs_bucket_free(&b);
    }
    pthread_mutex_unlock(&g_rs_mu);
  }
  char *km = NULL, *vm = NULL;
  final = RS_COMPLETED;
  for (;;) {
    if (atomic_load(&r->stop)) {
      final = RS_FAILED;
      break;
    }
    buckets_obj_listing l;
    if (buckets_obj_list_versions(s->layer, run->bucket, "", km, vm, NULL, 1000, &l)) {
      final = RS_FAILED;
      break;
    }
    for (size_t i = 0; i < l.nobjects && !atomic_load(&r->stop); i++) {
      buckets_object_info *oi = &l.objects[i];
      if (checkpoint) {
        if (strcmp(checkpoint, oi->name) != 0) continue;
        free(checkpoint);
        checkpoint = NULL;
      }
      /* the listing's entry lacks the version's full metadata */
      buckets_object_info full;
      if (buckets_obj_stat(s->layer, run->bucket, oi->name, oi->version_id, &full)) continue;
      if (!version_needs_resync(s, run->bucket, &full, &t->t)) {
        buckets_object_info_free(&full);
        continue;
      }
      const char *ps = sys_str(&full, BUCKETS_META_PURGE_STATUS);
      bool purge = ps && *ps;
      job j = {.bucket = run->bucket, .object = full.name, .op = BUCKETS_REPL_EXISTING, .target_arn = run->arn,
               .event = full.delete_marker ? "replicate:existing:delete" : "replicate:existing", .retry = MRF_RETRY_LIMIT};
      snprintf(j.version_id, sizeof(j.version_id), "%s", full.version_id);
      if (full.delete_marker) {
        j.kind = JOB_DELETE;
        j.dm = !purge;
        j.dm_mtime = full.mod_time_ns;
        const char *rs = sys_str(&full, BUCKETS_META_REPL_STATUS);
        j.repl_status = (char *)(rs ? rs : "");
        j.purge_status = (char *)(purge ? ps : "");
        replicate_delete(r, &j);
      } else {
        j.kind = JOB_OBJECT;
        replicate_object(r, &j);
      }
      /* count it by what the target has now */
      char q[128];
      query_vid(q, sizeof(q), full.version_id);
      hdrs sh = {0};
      hset(&sh, BUCKETS_H_SRC_PROXY, "false");
      buckets_s3c_result res;
      bool there = buckets_s3c_do(t->c, "HEAD", t->t.target_bucket, full.name, q, sh.kv, sh.n, NULL, 0, &res);
      hfree(&sh);
      bool counted = there || (full.delete_marker && res.status == 405);
      int64_t sz = there ? full.size : 0;
      rs_update(s, run->bucket, run->arn, -1, full.name, counted ? sz : 0, counted, 0, !counted);
      buckets_s3c_result_free(&res);
      buckets_object_info_free(&full);
    }
    bool more = l.truncated;
    free(km);
    free(vm);
    km = more && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    vm = more && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!more) break;
  }
  free(km);
  free(vm);
  free(checkpoint);
done:
  if (t) buckets_repl_target_put(t);
  rs_update(s, run->bucket, run->arn, final, NULL, 0, 0, 0, 0);
  free(run->bucket);
  free(run->arn);
  free(run);
  return NULL;
}

static void rs_spawn(buckets_repl *r, const char *bucket, const char *arn, bool heal) {
  rs_run *run = buckets_xcalloc(1, sizeof(*run));
  run->r = r;
  run->bucket = buckets_xstrdup(bucket);
  run->arn = buckets_xstrdup(arn);
  run->heal = heal;
  pthread_t th;
  if (pthread_create(&th, NULL, rs_main, run) == 0) pthread_detach(th);
  else {
    free(run->bucket);
    free(run->arn);
    free(run);
  }
}

int buckets_repl_resync_start(buckets_repl *r, const char *bucket, const char *arn, const char *reset_id,
                              int64_t before_ns, char *err, size_t errlen) {
  buckets_s3_server *s = r->s;
  pthread_mutex_lock(&g_rs_mu);
  rs_bucket b;
  if (!rs_load(s, bucket, &b)) {
    pthread_mutex_unlock(&g_rs_mu);
    snprintf(err, errlen, "resyncMeta: unreadable");
    return -1;
  }
  rs_tgt *t = rs_find(&b, arn, false);
  if (t && (t->status == RS_STARTED || t->status == RS_PENDING)) {
    snprintf(err, errlen, "Resync of bucket %s is already in progress for remote bucket %s", bucket, arn);
    rs_bucket_free(&b);
    pthread_mutex_unlock(&g_rs_mu);
    return -1;
  }
  /* a fresh status for this target */
  if (t) {
    free(t->id);
    free(t->bucket);
    free(t->object);
    char *a = t->arn;
    memset(t, 0, sizeof(*t));
    t->arn = a;
  } else {
    t = rs_find(&b, arn, true);
    free(t->id);
    free(t->bucket);
    free(t->object);
  }
  t->id = buckets_xstrdup(reset_id);
  t->bucket = buckets_xstrdup(bucket);
  t->object = buckets_xstrdup("");
  t->before_sec = before_ns / 1000000000LL;
  t->before_nsec = (int32_t)(before_ns % 1000000000LL);
  rs_now(&t->start_sec, &t->start_nsec);
  t->lu_sec = BUCKETS_GO_ZERO_SEC;
  t->lu_nsec = 0;
  t->status = RS_PENDING;
  rs_save(s, bucket, &b);
  rs_bucket_free(&b);
  pthread_mutex_unlock(&g_rs_mu);
  rs_spawn(r, bucket, arn, false);
  return 0;
}

/* ResyncTargetsInfo JSON of a bucket's resync status (arn "" for all). */
bool buckets_repl_resync_status(buckets_repl *r, const char *bucket, const char *arn, buckets_buf *out, char *err,
                                size_t errlen) {
  rs_bucket b;
  pthread_mutex_lock(&g_rs_mu);
  bool ok = rs_load(r->s, bucket, &b);
  pthread_mutex_unlock(&g_rs_mu);
  if (!ok) {
    snprintf(err, errlen, "resyncMeta: unreadable");
    return false;
  }
  buckets_buf_append_c(out, "{");
  bool any = false;
  for (size_t i = 0; i < b.n; i++) {
    rs_tgt *t = &b.t[i];
    if (arn && *arn && strcmp(arn, t->arn) != 0) continue;
    buckets_buf_append_c(out, any ? "," : "\"target\":[");
    any = true;
    char st[BUCKETS_TIME_RFC3339_NANO_LEN + 1], et[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
    buckets_time_rfc3339_nano(t->start_sec, t->start_nsec, st);
    buckets_time_rfc3339_nano(t->lu_sec, t->lu_nsec, et);
    buckets_buf_append_c(out, "{\"arn\":");
    buckets_json_go_string(out, t->arn, strlen(t->arn));
    buckets_buf_append_c(out, ",\"resetid\":");
    buckets_json_go_string(out, t->id, strlen(t->id));
    buckets_buf_appendf(out, ",\"startTime\":\"%s\",\"endTime\":\"%s\"", st, et);
    const char *sn = rs_state_name((int)t->status);
    if (*sn) buckets_buf_appendf(out, ",\"resyncStatus\":\"%s\"", sn);
    buckets_buf_appendf(out,
                        ",\"completedReplicationSize\":%lld,\"failedReplicationSize\":%lld,\"failedReplicationCount\":%lld,"
                        "\"replicationCount\":%lld",
                        (long long)t->repl_size, (long long)t->failed_size, (long long)t->failed_count,
                        (long long)t->repl_count);
    if (*t->bucket) {
      buckets_buf_append_c(out, ",\"bucket\":");
      buckets_json_go_string(out, t->bucket, strlen(t->bucket));
    }
    if (*t->object) {
      buckets_buf_append_c(out, ",\"object\":");
      buckets_json_go_string(out, t->object, strlen(t->object));
    }
    buckets_buf_append_char(out, '}');
  }
  buckets_buf_append_c(out, any ? "]}" : "}");
  rs_bucket_free(&b);
  return true;
}

/* loadResync: resumes the resyncs that did not finish. */
void buckets_repl_resync_resume(buckets_repl *r) {
  buckets_s3_server *s = r->s;
  buckets_bucket_info *bl = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(s->layer, &bl, &nb)) return;
  for (size_t i = 0; i < nb; i++) {
    rs_bucket b;
    pthread_mutex_lock(&g_rs_mu);
    bool ok = rs_load(s, bl[i].name, &b);
    pthread_mutex_unlock(&g_rs_mu);
    if (!ok) continue;
    for (size_t k = 0; k < b.n; k++) {
      int st = (int)b.t[k].status;
      if (st == RS_FAILED || st == RS_STARTED || st == RS_PENDING) rs_spawn(r, bl[i].name, b.t[k].arn, true);
    }
    rs_bucket_free(&b);
  }
  buckets_bucket_info_free(bl, nb);
}

/* ---- healing (queueReplicationHeal, from the scanner) ---- */

void buckets_repl_heal(buckets_s3_server *s, const char *bucket, const buckets_object_info *oi, int retry) {
  if (!s->repl || !s->meta || !oi->mod_time_ns || !*oi->version_id || strcmp(oi->version_id, "null") == 0) return;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  if (!st->has_replication || !st->targets.n) {
    buckets_bucket_state_release(st);
    return;
  }
  bool versioned = buckets_versioning_enabled_for(&st->versioning, oi->name);
  const char *ps = sys_str(oi, BUCKETS_META_PURGE_STATUS);
  bool purge = ps && *ps;
  bool marker = oi->delete_marker && !purge;
  const char *internal = sys_str(oi, BUCKETS_META_REPL_STATUS);
  const char *status = buckets_repl_composite_status(internal ? internal : "");
  const char *pstatus = purge ? buckets_repl_composite_purge(ps) : "";
  /* the decision (checkReplicateDelete / mustReplicate for healing) */
  buckets_repl_dsc dsc = {0};
  if (marker || purge) {
    buckets_repl_check_delete(s, bucket, oi->name, oi->version_id, oi, versioned, false, &dsc);
  } else {
    buckets_repl_obj o = {.name = oi->name, .user_tags = buckets_object_meta(oi, "X-Amz-Tagging"),
                          .ssec = sys_ssec(oi->meta_sys, oi->nmeta_sys), .op = BUCKETS_REPL_HEAL};
    char **arns = NULL;
    size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
    for (size_t i = 0; i < na; i++) {
      o.target_arn = arns[i];
      dsc_set(&dsc, arns[i], buckets_replication_replicate(&st->replication, &o), target_sync(st, arns[i]));
    }
    buckets_replication_arns_free(arns, na);
  }
  if (!buckets_repl_dsc_any(&dsc)) {
    buckets_repl_dsc_free(&dsc);
    buckets_bucket_state_release(st);
    return;
  }
  /* existing-object resync, per target (rcfg.Resync) */
  char *resync_arn = NULL;
  size_t nresync = 0;
  for (size_t i = 0; i < st->targets.n; i++) {
    const buckets_bucket_target *t = &st->targets.t[i];
    bool rep = false;
    for (size_t k = 0; k < dsc.n; k++) rep |= strcmp(dsc.t[k].arn, t->arn) == 0 && dsc.t[k].replicate;
    if (!rep) continue;
    buckets_repl_obj eo = {.name = oi->name, .target_arn = t->arn, .existing = true};
    if (marker) {
      eo.delete_marker = true;
      eo.version_id = oi->version_id;
      eo.op = BUCKETS_REPL_DELETE;
    } else {
      eo.user_tags = buckets_object_meta(oi, "X-Amz-Tagging");
      eo.ssec = sys_ssec(oi->meta_sys, oi->nmeta_sys);
    }
    if (!buckets_replication_replicate(&st->replication, &eo)) continue;
    char tst[32];
    buckets_repl_target_status(internal, t->arn, tst, sizeof(tst));
    if (resync_target(oi, t, tst)) {
      nresync++;
      if (!resync_arn) resync_arn = buckets_xstrdup(t->arn);
    }
  }
  buckets_bucket_state_release(st);
  buckets_repl_dsc_free(&dsc);
  bool must_resync = nresync > 0;
  if (strcmp(status, BUCKETS_RS_COMPLETED) == 0 && !purge && !must_resync) goto out;
  job *j = buckets_xcalloc(1, sizeof(*j));
  j->bucket = buckets_xstrdup(bucket);
  j->object = buckets_xstrdup(oi->name);
  snprintf(j->version_id, sizeof(j->version_id), "%s", oi->version_id);
  j->retry = retry;
  j->qsize = oi->size;
  if (marker || purge) {
    j->kind = JOB_DELETE;
    j->dm = marker;
    j->dm_mtime = oi->mod_time_ns;
    j->repl_status = buckets_xstrdup(internal ? internal : "");
    j->purge_status = buckets_xstrdup(purge ? ps : "");
    bool retry_it = strcmp(status, BUCKETS_RS_PENDING) == 0 || strcmp(status, BUCKETS_RS_FAILED) == 0 ||
                    strcmp(pstatus, BUCKETS_VPS_PENDING) == 0 || strcmp(pstatus, BUCKETS_VPS_FAILED) == 0;
    if (retry_it) {
      j->op = BUCKETS_REPL_HEAL;
      j->event = buckets_xstrdup("replicate:heal:delete");
    } else if (must_resync && (strcmp(status, BUCKETS_RS_COMPLETED) == 0 || !*status)) {
      j->op = BUCKETS_REPL_EXISTING;
      j->event = buckets_xstrdup("replicate:existing:delete");
      j->target_arn = resync_arn;
      resync_arn = NULL;
    } else {
      job_free(j);
      goto out;
    }
    enqueue(s->repl, j, false);
    goto out;
  }
  j->kind = JOB_OBJECT;
  j->op = must_resync ? BUCKETS_REPL_EXISTING : BUCKETS_REPL_HEAL;
  if (strcmp(status, BUCKETS_RS_PENDING) == 0 || strcmp(status, BUCKETS_RS_FAILED) == 0) {
    j->event = buckets_xstrdup("replicate:heal");
  } else if (must_resync) {
    j->event = buckets_xstrdup("replicate:existing");
  } else {
    job_free(j);
    goto out;
  }
  enqueue(s->repl, j, false);
out:
  free(resync_arn);
}

/* ---- ReplicationDiff and the MRF backlog ---- */

typedef struct {
  char arn[256];
  char rs[32], ds[32];
} diff_tgt;

static int diff_tgt_cmp(const void *a, const void *b) { return strcmp(((const diff_tgt *)a)->arn, ((const diff_tgt *)b)->arn); }

/* getReplicationDiff: one DiffInfo line per version not (yet) replicated. */
void buckets_repl_diff(buckets_s3_server *s, const char *bucket, const char *prefix, const char *arn, bool verbose,
                       buckets_buf *out) {
  char *km = NULL, *vm = NULL;
  for (;;) {
    buckets_obj_listing l;
    if (buckets_obj_list_versions(s->layer, bucket, prefix ? prefix : "", km, vm, NULL, 1000, &l)) break;
    for (size_t i = 0; i < l.nobjects; i++) {
      buckets_object_info oi;
      if (buckets_obj_stat(s->layer, bucket, l.objects[i].name, l.objects[i].version_id, &oi)) continue;
      buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
      bool suspended = buckets_versioning_suspended_for(&st->versioning, oi.name);
      bool must_resync = false;
      const char *internal = sys_str(&oi, BUCKETS_META_REPL_STATUS);
      for (size_t t = 0; t < st->targets.n && !must_resync; t++) {
        char tst[32];
        buckets_repl_target_status(internal, st->targets.t[t].arn, tst, sizeof(tst));
        must_resync = version_needs_resync(s, bucket, &oi, &st->targets.t[t]);
      }
      buckets_bucket_state_release(st);
      if (suspended) {
        buckets_object_info_free(&oi);
        continue;
      }
      char cst[32];
      const char *status = buckets_repl_version_status(&oi, cst, sizeof(cst));
      if (!status) status = "";
      bool done = strcmp(status, BUCKETS_RS_COMPLETED) == 0 || strcmp(status, BUCKETS_RS_REPLICA) == 0;
      if ((done && !verbose) || (!done && !*status && !must_resync)) {
        buckets_object_info_free(&oi);
        continue;
      }
      /* the targets' statuses */
      diff_tgt *tg = NULL;
      size_t nt = 0;
      const char *ps = sys_str(&oi, BUCKETS_META_PURGE_STATUS);
      for (int pass = 0; pass < 2; pass++) {
        const char *src = pass ? (ps ? ps : "") : (internal ? internal : "");
        const char *p = src;
        while (*p) {
          const char *eq = strchr(p, '='), *semi = eq ? strchr(eq, ';') : NULL;
          if (!eq || !semi) break;
          char a[256], v[32];
          snprintf(a, sizeof(a), "%.*s", (int)(eq - p), p);
          snprintf(v, sizeof(v), "%.*s", (int)(semi - eq - 1), eq + 1);
          p = semi + 1;
          if (arn && *arn && strcmp(arn, a) != 0) continue;
          if (!verbose && (pass ? strcmp(v, BUCKETS_VPS_COMPLETE) == 0
                                : (strcmp(v, BUCKETS_RS_COMPLETED) == 0 || strcmp(v, BUCKETS_RS_REPLICA) == 0)))
            continue;
          diff_tgt *d = NULL;
          for (size_t k = 0; k < nt; k++)
            if (strcmp(tg[k].arn, a) == 0) d = &tg[k];
          if (!d) {
            tg = buckets_xrealloc(tg, (nt + 1) * sizeof(*tg));
            d = &tg[nt++];
            memset(d, 0, sizeof(*d));
            snprintf(d->arn, sizeof(d->arn), "%s", a);
          }
          snprintf(pass ? d->ds : d->rs, sizeof(d->rs), "%s", v);
        }
      }
      if (nt > 1) qsort(tg, nt, sizeof(*tg), diff_tgt_cmp);
      buckets_buf_append_c(out, "{\"object\":");
      buckets_json_go_string(out, oi.name, strlen(oi.name));
      buckets_buf_append_c(out, ",\"versionId\":");
      buckets_json_go_string(out, oi.version_id, strlen(oi.version_id));
      if (nt) {
        buckets_buf_append_c(out, ",\"targets\":{");
        for (size_t k = 0; k < nt; k++) {
          if (k) buckets_buf_append_char(out, ',');
          buckets_json_go_string(out, tg[k].arn, strlen(tg[k].arn));
          buckets_buf_append_c(out, ":{");
          if (tg[k].rs[0]) buckets_buf_appendf(out, "\"rStatus\":\"%s\"", tg[k].rs);
          if (tg[k].ds[0]) buckets_buf_appendf(out, "%s\"drStatus\":\"%s\"", tg[k].rs[0] ? "," : "", tg[k].ds);
          buckets_buf_append_char(out, '}');
        }
        buckets_buf_append_char(out, '}');
      }
      if (*status) buckets_buf_appendf(out, ",\"rStatus\":\"%s\"", status);
      const char *pc = ps && *ps ? buckets_repl_composite_purge(ps) : "";
      if (*pc) buckets_buf_appendf(out, ",\"dStatus\":\"%s\"", pc);
      char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1], lm[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
      const char *rts = sys_str(&oi, BUCKETS_META_REPL_TS);
      long long sec;
      long nsec;
      if (rts && buckets_time_parse_rfc3339(rts, &sec, &nsec)) buckets_time_rfc3339_nano(sec, nsec, ts);
      else buckets_time_rfc3339_nano(BUCKETS_GO_ZERO_SEC, 0, ts);
      rfc3339nano(oi.mod_time_ns, lm);
      buckets_buf_appendf(out, ",\"replTimestamp\":\"%s\",\"lastModified\":\"%s\",\"deletemarker\":%s}\n", ts, lm,
                          oi.delete_marker ? "true" : "false");
      free(tg);
      buckets_object_info_free(&oi);
    }
    bool more = l.truncated;
    free(km);
    free(vm);
    km = more && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    vm = more && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!more) break;
  }
  free(km);
  free(vm);
}

/* The retries waiting in the MRF queue, as madmin.ReplicationMRF lines. */
void buckets_repl_mrf_json(buckets_repl *r, const char *bucket, const char *node_name, buckets_buf *out) {
  if (!r) return;
  pthread_mutex_lock(&r->mrf.mu);
  for (job *j = r->mrf.head; j; j = j->next) {
    if (bucket && *bucket && strcmp(j->bucket, bucket) != 0) continue;
    buckets_buf_append_c(out, "{\"nodeName\":");
    buckets_json_go_string(out, node_name, strlen(node_name));
    buckets_buf_append_c(out, ",\"bucket\":");
    buckets_json_go_string(out, j->bucket, strlen(j->bucket));
    buckets_buf_append_c(out, ",\"object\":");
    buckets_json_go_string(out, j->object, strlen(j->object));
    buckets_buf_append_c(out, ",\"versionId\":");
    buckets_json_go_string(out, j->version_id, strlen(j->version_id));
    buckets_buf_appendf(out, ",\"retryCount\":%d}\n", j->retry);
  }
  pthread_mutex_unlock(&r->mrf.mu);
}

/* ---- the MRF on disk (persistMRF / loadMRF) ----
 * .minio.sys/buckets/.replication/mrf/<sha256(node) hex>.bin on the first
 * local drive: LE uint16 format 1 and version 1, then msgp
 * MRFReplicateEntries {"e": {versionID: {"b","o","rc"}}, "v": 1}. */

static void mrf_path(buckets_repl *r, char *out, size_t cap) {
  const char *ep = r->s->endpoint, *h = strstr(ep, "://");
  const char *node = h ? h + 3 : ep;
  uint8_t sum[32];
  buckets_sha256(node, strlen(node), sum);
  char hex[65];
  buckets_hex_encode(sum, 32, hex);
  snprintf(out, cap, "buckets/.replication/mrf/%s.bin", hex);
}

static buckets_drive *local_drive(buckets_objlayer *L) {
  for (size_t i = 0; L && i < L->nall; i++)
    if (L->all[i] && !L->all[i]->remote) return L->all[i];
  return NULL;
}

/* Saves what waits in the MRF queue (at shutdown). */
static void mrf_save(buckets_repl *r) {
  buckets_objlayer *L = r->s->layer;
  buckets_drive *d = local_drive(L);
  if (!d) return;
  size_t n = 0;
  for (job *j = r->mrf.head; j; j = j->next) n++;
  if (!n) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  uint8_t hdr[4] = {1, 0, 1, 0};
  buckets_buf_append(&b, hdr, 4);
  buckets_mp_map(&b, 2);
  buckets_mp_cstr(&b, "e");
  /* one entry per version (a map: the last retry of a version wins) */
  size_t unique = 0;
  for (job *j = r->mrf.head; j; j = j->next) {
    bool later = false;
    for (job *k = j->next; k && !later; k = k->next) later = strcmp(k->version_id, j->version_id) == 0;
    unique += !later;
  }
  buckets_mp_map(&b, (uint32_t)unique);
  for (job *j = r->mrf.head; j; j = j->next) {
    bool later = false;
    for (job *k = j->next; k && !later; k = k->next) later = strcmp(k->version_id, j->version_id) == 0;
    if (later) continue;
    buckets_mp_cstr(&b, j->version_id);
    buckets_mp_map(&b, 3);
    buckets_mp_cstr(&b, "b");
    buckets_mp_cstr(&b, j->bucket);
    buckets_mp_cstr(&b, "o");
    buckets_mp_cstr(&b, j->object);
    buckets_mp_cstr(&b, "rc");
    buckets_mp_int(&b, j->retry);
  }
  buckets_mp_cstr(&b, "v");
  buckets_mp_int(&b, 1);
  char path[400];
  mrf_path(r, path, sizeof(path));
  buckets_drive_write_all(d, ".minio.sys", path, b.data, b.len);
  buckets_buf_free(&b);
}

/* loadMRF + queueMRFHeal: re-checks the versions saved at the last shutdown. */
static void mrf_load(buckets_repl *r) {
  buckets_objlayer *L = r->s->layer;
  char path[400];
  mrf_path(r, path, sizeof(path));
  for (size_t i = 0; L && i < L->nall; i++) {
    buckets_drive *d = L->all[i];
    if (!d || d->remote) continue;
    buckets_buf data = BUCKETS_BUF_INIT;
    if (buckets_drive_read_all(d, ".minio.sys", path, &data) != BUCKETS_DRIVE_OK) {
      buckets_buf_free(&data);
      continue;
    }
    buckets_drive_delete(d, ".minio.sys", path, false, false);
    const uint8_t *p = (const uint8_t *)data.data;
    if (data.len > 4 && p[0] == 1 && p[1] == 0 && p[2] == 1 && p[3] == 0) {
      buckets_mp_reader rd = buckets_mp_reader_init(p + 4, data.len - 4);
      uint32_t nf;
      if (buckets_mp_read_map(&rd, &nf)) {
        for (uint32_t f = 0; f < nf; f++) {
          buckets_str k;
          if (!buckets_mp_read_str(&rd, &k)) break;
          if (!buckets_str_eq_c(k, "e")) {
            if (!buckets_mp_skip(&rd)) break;
            continue;
          }
          uint32_t ne;
          if (!buckets_mp_read_map(&rd, &ne)) break;
          for (uint32_t e = 0; e < ne; e++) {
            buckets_str vid;
            uint32_t nk;
            if (!buckets_mp_read_str(&rd, &vid) || !buckets_mp_read_map(&rd, &nk)) break;
            char *bucket = NULL, *object = NULL;
            int64_t rc = 0;
            for (uint32_t m = 0; m < nk; m++) {
              buckets_str fk, fv;
              if (!buckets_mp_read_str(&rd, &fk)) break;
              if (buckets_str_eq_c(fk, "b") && buckets_mp_read_str(&rd, &fv)) bucket = buckets_str_dup(fv);
              else if (buckets_str_eq_c(fk, "o") && buckets_mp_read_str(&rd, &fv)) object = buckets_str_dup(fv);
              else if (buckets_str_eq_c(fk, "rc")) buckets_mp_read_int(&rd, &rc);
              else buckets_mp_skip(&rd);
            }
            char *v = buckets_str_dup(vid);
            buckets_object_info oi;
            if (bucket && object && buckets_obj_stat(L, bucket, object, v, &oi) == BUCKETS_OBJ_OK) {
              buckets_repl_heal(r->s, bucket, &oi, (int)rc);
              buckets_object_info_free(&oi);
            }
            free(v);
            free(bucket);
            free(object);
          }
        }
      }
    }
    buckets_buf_free(&data);
    break;
  }
}

/* ---- batch replication (ReplicateToTarget) ------------------------------------------------ */

int buckets_repl_batch_put(buckets_s3_server *s, buckets_s3c *c, const char *bucket, const char *object,
                           const char *version_id, const char *tgt_bucket, const char *tgt_object, bool plain,
                           bool retry, char *err, size_t errlen) {
  src_info si;
  buckets_obj_err oerr;
  if (!src_stat(s, bucket, object, version_id, &si, &oerr)) {
    if (oerr == BUCKETS_OBJ_ERR_NO_SUCH_KEY || oerr == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) return BUCKETS_REPL_BATCH_SKIP;
    snprintf(err, errlen, "%s", buckets_obj_strerror(oerr));
    return BUCKETS_REPL_BATCH_FAILED;
  }
  buckets_s3c_result res;
  if (retry && !plain) { /* already there from an earlier attempt? */
    hdrs mh = {0};
    char etag[160];
    snprintf(etag, sizeof(etag), "\"%s\"", si.oi.etag);
    hset(&mh, "If-Match", etag);
    bool there = buckets_s3c_do(c, "HEAD", tgt_bucket, tgt_object, NULL, mh.kv, mh.n, NULL, 0, &res);
    buckets_s3c_result_free(&res);
    hfree(&mh);
    if (there) {
      src_info_free(&si);
      return BUCKETS_REPL_BATCH_OK;
    }
  }
  hdrs h = {0};
  bool mp = false;
  put_headers(&si, NULL, &h, &mp);
  /* batchReplicationOpts: no replica status; S3 targets get none of the
   * internal headers */
  hdel(&h, BUCKETS_H_REPL_STATUS);
  if (plain) {
    static const char *const internal[] = {BUCKETS_H_SRC_MTIME, BUCKETS_H_SRC_ETAG, BUCKETS_H_SRC_REPL_REQUEST,
                                           BUCKETS_H_SRC_TAG_TS, BUCKETS_H_SRC_RET_TS, BUCKETS_H_SRC_LH_TS};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(internal); i++) hdel(&h, internal[i]);
  }
  dest d = {c, tgt_bucket, tgt_object, "batch", 0, NULL, false, plain};
  tinfo ti = {0};
  bool ok = mp ? multipart_put(s, &d, bucket, object, &si, &h, &ti) : single_put(s, &d, bucket, object, &si, &h, &ti);
  hfree(&h);
  src_info_free(&si);
  if (strcmp(ti.code, "PreconditionFailed") == 0) return BUCKETS_REPL_BATCH_SKIP;
  if (!ok) {
    snprintf(err, errlen, "%s", ti.err);
    return BUCKETS_REPL_BATCH_FAILED;
  }
  return BUCKETS_REPL_BATCH_OK;
}

int buckets_repl_batch_delete(buckets_s3c *c, const char *tgt_bucket, const char *tgt_object, const char *version_id,
                              int64_t mod_time_ns, bool plain, bool retry, char *err, size_t errlen) {
  char q[128] = "";
  if (!plain) query_vid(q, sizeof(q), version_id);
  buckets_s3c_result res;
  if (retry && !plain) {
    hdrs sh = {0};
    hset(&sh, BUCKETS_H_SRC_PROXY, "false");
    buckets_s3c_do(c, "HEAD", tgt_bucket, tgt_object, q, sh.kv, sh.n, NULL, 0, &res);
    hfree(&sh);
    bool there = res.status == 405; /* the marker is there */
    buckets_s3c_result_free(&res);
    if (there) return BUCKETS_REPL_BATCH_OK;
  }
  hdrs h = {0};
  if (!plain) hset(&h, "X-Minio-Source-Deletemarker", "true");
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  rfc3339nano(mod_time_ns, ts);
  hset(&h, BUCKETS_H_SRC_MTIME, ts);
  hset(&h, BUCKETS_H_REPL_STATUS, BUCKETS_RS_REPLICA);
  hset(&h, BUCKETS_H_SRC_REPL_REQUEST, "true");
  bool ok = buckets_s3c_do(c, "DELETE", tgt_bucket, tgt_object, q[0] ? q : NULL, h.kv, h.n, NULL, 0, &res);
  hfree(&h);
  if (!ok) snprintf(err, errlen, "%s", buckets_s3c_error(&res));
  buckets_s3c_result_free(&res);
  return ok ? BUCKETS_REPL_BATCH_OK : BUCKETS_REPL_BATCH_FAILED;
}
