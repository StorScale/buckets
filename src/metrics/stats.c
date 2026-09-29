/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "metrics/stats.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"

/* The handler names of MinIO's router (s3APIMiddleware), lowercase as
 * getHandlerName leaves them, then the rejected APIs' names as written. */
static const char *const k_api[] = {
    "abortmultipartupload", "completemultipartupload", "copyobject", "copyobjectpart", "deletebucket",
    "deletebucketcors", "deletebucketencryption", "deletebucketlifecycle", "deletebucketpolicy",
    "deletebucketreplicationconfig", "deletebuckettagging", "deletebucketwebsite", "deletemultipleobjects",
    "deleteobject", "deleteobjecttagging", "getbucketacl", "getbucketaccelerate", "getbucketcors",
    "getbucketencryption", "getbucketlifecycle", "getbucketlocation", "getbucketlogging", "getbucketnotification",
    "getbucketobjectlockconfig", "getbucketpolicy", "getbucketpolicystatus", "getbucketreplicationconfig",
    "getbucketreplicationmetrics", "getbucketreplicationmetricsv2", "getbucketrequestpayment", "getbuckettagging",
    "getbucketversioning", "getbucketwebsite", "getobject", "getobjectacl", "getobjectattributes", "getobjectlambda",
    "getobjectlegalhold", "getobjectretention", "getobjecttagging", "headbucket", "headobject", "listbuckets",
    "listmultipartuploads", "listobjectparts", "listobjectversions", "listobjectversionsm", "listobjectsv1",
    "listobjectsv2", "listobjectsv2m", "listennotification", "newmultipartupload", "postpolicybucket",
    "postrestoreobject", "putbucket", "putbucketacl", "putbucketcors", "putbucketencryption", "putbucketlifecycle",
    "putbucketnotification", "putbucketobjectlockconfig", "putbucketpolicy", "putbucketreplicationconfig",
    "putbuckettagging", "putbucketversioning", "putobject", "putobjectacl", "putobjectextract", "putobjectlegalhold",
    "putobjectpart", "putobjectretention", "putobjecttagging", "resetbucketreplicationstart",
    "resetbucketreplicationstatus", "selectobjectcontent", "validatebucketreplicationcreds",
    /* rejectedObjAPIs and rejectedBucketAPIs */
    "torrent", "acl", "inventory", "cors", "metrics", "website", "logging", "accelerate", "requestPayment",
    "publicAccessBlock", "ownershipControls", "intelligent-tiering", "analytics"};
#define NAPI BUCKETS_ARRAY_LEN(k_api)

/* The same, as the handlers are named (metrics v3 does not lowercase them). */
static const char *const k_api_handler[] = {
    "AbortMultipartUpload",
    "CompleteMultipartUpload",
    "CopyObject",
    "CopyObjectPart",
    "DeleteBucket",
    "DeleteBucketCors",
    "DeleteBucketEncryption",
    "DeleteBucketLifecycle",
    "DeleteBucketPolicy",
    "DeleteBucketReplicationConfig",
    "DeleteBucketTagging",
    "DeleteBucketWebsite",
    "DeleteMultipleObjects",
    "DeleteObject",
    "DeleteObjectTagging",
    "GetBucketACL",
    "GetBucketAccelerate",
    "GetBucketCors",
    "GetBucketEncryption",
    "GetBucketLifecycle",
    "GetBucketLocation",
    "GetBucketLogging",
    "GetBucketNotification",
    "GetBucketObjectLockConfig",
    "GetBucketPolicy",
    "GetBucketPolicyStatus",
    "GetBucketReplicationConfig",
    "GetBucketReplicationMetrics",
    "GetBucketReplicationMetricsV2",
    "GetBucketRequestPayment",
    "GetBucketTagging",
    "GetBucketVersioning",
    "GetBucketWebsite",
    "GetObject",
    "GetObjectACL",
    "GetObjectAttributes",
    "GetObjectLambda",
    "GetObjectLegalHold",
    "GetObjectRetention",
    "GetObjectTagging",
    "HeadBucket",
    "HeadObject",
    "ListBuckets",
    "ListMultipartUploads",
    "ListObjectParts",
    "ListObjectVersions",
    "ListObjectVersionsM",
    "ListObjectsV1",
    "ListObjectsV2",
    "ListObjectsV2M",
    "ListenNotification",
    "NewMultipartUpload",
    "PostPolicyBucket",
    "PostRestoreObject",
    "PutBucket",
    "PutBucketACL",
    "PutBucketCors",
    "PutBucketEncryption",
    "PutBucketLifecycle",
    "PutBucketNotification",
    "PutBucketObjectLockConfig",
    "PutBucketPolicy",
    "PutBucketReplicationConfig",
    "PutBucketTagging",
    "PutBucketVersioning",
    "PutObject",
    "PutObjectACL",
    "PutObjectExtract",
    "PutObjectLegalHold",
    "PutObjectPart",
    "PutObjectRetention",
    "PutObjectTagging",
    "ResetBucketReplicationStart",
    "ResetBucketReplicationStatus",
    "SelectObjectContent",
    "ValidateBucketReplicationCreds",
    "torrent",
    "acl",
    "inventory",
    "cors",
    "metrics",
    "website",
    "logging",
    "accelerate",
    "requestPayment",
    "publicAccessBlock",
    "ownershipControls",
    "intelligent-tiering",
    "analytics"};
_Static_assert(BUCKETS_ARRAY_LEN(k_api_handler) == NAPI, "API name tables differ");

const double buckets_ttfb_bounds[BUCKETS_TTFB_NBOUNDS] = {.05, .1, .25, .5, 1, 2.5, 5, 10};

int buckets_api_index(const char *name) {
  for (size_t i = 0; i < NAPI; i++)
    if (strcmp(k_api[i], name) == 0) return (int)i;
  return -1;
}

const char *buckets_api_name(int api) { return api >= 0 && (size_t)api < NAPI ? k_api[api] : ""; }
const char *buckets_api_handler_name(int api) { return api >= 0 && (size_t)api < NAPI ? k_api_handler[api] : ""; }
size_t buckets_api_count(void) { return NAPI; }

typedef struct {
  _Atomic uint64_t total, errors, err4xx, err5xx, canceled;
  _Atomic int64_t inflight;
  _Atomic uint64_t ttfb[BUCKETS_TTFB_NBOUNDS + 1];
  _Atomic uint64_t ttfb_sum_us;
} api_counters;

static api_counters g_api[NAPI];
static _Atomic uint64_t g_rejected[BUCKETS_REJECT__N];
static _Atomic int64_t g_waiting;
static _Atomic uint64_t g_incoming;
static _Atomic uint64_t g_rx, g_tx;

typedef struct bucket_entry {
  struct bucket_entry *next;
  char *bucket;
  buckets_api_stats api[NAPI];
  uint64_t rx, tx;
} bucket_entry;

static pthread_mutex_t g_bmu = PTHREAD_MUTEX_INITIALIZER;
static bucket_entry *g_buckets;

static bucket_entry *bucket_of(const char *bucket) {
  for (bucket_entry *b = g_buckets; b; b = b->next)
    if (strcmp(b->bucket, bucket) == 0) return b;
  bucket_entry *b = buckets_xcalloc(1, sizeof(*b));
  b->bucket = buckets_xstrdup(bucket);
  b->next = g_buckets;
  g_buckets = b;
  return b;
}

static int ttfb_slot(double s) {
  for (int i = 0; i < BUCKETS_TTFB_NBOUNDS; i++)
    if (s <= buckets_ttfb_bounds[i]) return i;
  return BUCKETS_TTFB_NBOUNDS;
}

void buckets_stats_begin(int api, const char *bucket) {
  if (api < 0 || (size_t)api >= NAPI) return;
  atomic_fetch_add(&g_incoming, 1);
  atomic_fetch_add(&g_api[api].inflight, 1);
  if (bucket) {
    pthread_mutex_lock(&g_bmu);
    bucket_of(bucket)->api[api].inflight++;
    pthread_mutex_unlock(&g_bmu);
  }
}

/* updateStats: 499 counts as canceled, other statuses >= 400 as errors */
static void count_status(buckets_api_stats *s, int status) {
  if (status == 499) s->canceled++;
  else if (status >= 400) {
    s->errors++;
    if (status >= 500) s->err5xx++;
    else s->err4xx++;
  }
}

void buckets_stats_end(int api, const char *bucket, int status, double ttfb_s, uint64_t rx, uint64_t tx) {
  if (api < 0 || (size_t)api >= NAPI) return;
  api_counters *a = &g_api[api];
  atomic_fetch_sub(&a->inflight, 1);
  atomic_fetch_add(&a->total, 1);
  if (status == 499) atomic_fetch_add(&a->canceled, 1);
  else if (status >= 400) {
    atomic_fetch_add(&a->errors, 1);
    atomic_fetch_add(status >= 500 ? &a->err5xx : &a->err4xx, 1);
  }
  int slot = ttfb_slot(ttfb_s);
  atomic_fetch_add(&a->ttfb[slot], 1);
  atomic_fetch_add(&a->ttfb_sum_us, (uint64_t)(ttfb_s * 1e6));
  atomic_fetch_add(&g_rx, rx);
  atomic_fetch_add(&g_tx, tx);
  if (bucket) {
    pthread_mutex_lock(&g_bmu);
    bucket_entry *b = bucket_of(bucket);
    buckets_api_stats *s = &b->api[api];
    s->inflight--;
    s->total++;
    count_status(s, status);
    s->ttfb[slot]++;
    s->ttfb_sum += ttfb_s;
    b->rx += rx;
    b->tx += tx;
    pthread_mutex_unlock(&g_bmu);
  }
}

void buckets_stats_reject(buckets_reject_kind k) {
  if (k < BUCKETS_REJECT__N) atomic_fetch_add(&g_rejected[k], 1);
}

void buckets_stats_waiting(int delta) { atomic_fetch_add(&g_waiting, delta); }

void buckets_stats_get(buckets_stats_snapshot *out) {
  memset(out, 0, sizeof(*out));
  out->api = buckets_xcalloc(NAPI, sizeof(*out->api));
  for (size_t i = 0; i < NAPI; i++) {
    buckets_api_stats *s = &out->api[i];
    api_counters *a = &g_api[i];
    s->total = atomic_load(&a->total);
    s->errors = atomic_load(&a->errors);
    s->err4xx = atomic_load(&a->err4xx);
    s->err5xx = atomic_load(&a->err5xx);
    s->canceled = atomic_load(&a->canceled);
    s->inflight = atomic_load(&a->inflight);
    for (int j = 0; j <= BUCKETS_TTFB_NBOUNDS; j++) s->ttfb[j] = atomic_load(&a->ttfb[j]);
    s->ttfb_sum = (double)atomic_load(&a->ttfb_sum_us) / 1e6;
  }
  for (int k = 0; k < BUCKETS_REJECT__N; k++) out->rejected[k] = atomic_load(&g_rejected[k]);
  out->waiting = atomic_load(&g_waiting);
  out->incoming = (int64_t)atomic_exchange(&g_incoming, 0); /* since the last read, as MinIO */
  out->rx = atomic_load(&g_rx);
  out->tx = atomic_load(&g_tx);
}

void buckets_stats_snapshot_free(buckets_stats_snapshot *s) {
  free(s->api);
  s->api = NULL;
}

static int bs_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_bucket_stats *)a)->bucket, ((const buckets_bucket_stats *)b)->bucket);
}

size_t buckets_stats_buckets(buckets_bucket_stats **out) {
  pthread_mutex_lock(&g_bmu);
  size_t n = 0;
  for (bucket_entry *b = g_buckets; b; b = b->next) n++;
  buckets_bucket_stats *v = buckets_xcalloc(n ? n : 1, sizeof(*v));
  size_t i = 0;
  for (bucket_entry *b = g_buckets; b; b = b->next, i++) {
    v[i].bucket = buckets_xstrdup(b->bucket);
    v[i].api = buckets_xcalloc(NAPI, sizeof(*v[i].api));
    memcpy(v[i].api, b->api, sizeof(b->api));
    v[i].rx = b->rx;
    v[i].tx = b->tx;
  }
  pthread_mutex_unlock(&g_bmu);
  qsort(v, n, sizeof(*v), bs_cmp);
  *out = v;
  return n;
}

void buckets_stats_buckets_free(buckets_bucket_stats *v, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(v[i].bucket);
    free(v[i].api);
  }
  free(v);
}

void buckets_stats_forget_bucket(const char *bucket) {
  pthread_mutex_lock(&g_bmu);
  for (bucket_entry **p = &g_buckets; *p; p = &(*p)->next) {
    if (strcmp((*p)->bucket, bucket) == 0) {
      bucket_entry *b = *p;
      *p = b->next;
      free(b->bucket);
      free(b);
      break;
    }
  }
  pthread_mutex_unlock(&g_bmu);
}

int64_t buckets_stats_inflight(void) {
  int64_t n = 0;
  for (size_t i = 0; i < NAPI; i++) n += atomic_load(&g_api[i].inflight);
  return n;
}
