/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Which of MinIO's S3 API routes a request takes (cmd/api-router.go, in
 * its match order), for the request statistics that metrics label by API. */
#include <string.h>
#include <strings.h>

#include "metrics/stats.h"
#include "s3/internal.h"

static bool has(const s3_ctx *c, const char *k) { return buckets_query_has(&c->q, k); }

static bool is(const s3_ctx *c, const char *k, const char *v) {
  const char *x = buckets_query_get(&c->q, k);
  return x && strcmp(x, v) == 0;
}

static bool header(const s3_ctx *c, const char *name) { return buckets_http_header_get(c->req, name).p != NULL; }

/* HeadersRegexp(X-Amz-Copy-Source, ".*?(\/|%2F).*?") */
static bool copy_source(const s3_ctx *c) {
  buckets_str v = buckets_http_header_get(c->req, "X-Amz-Copy-Source");
  if (!v.p) return false;
  for (size_t i = 0; i < v.n; i++) {
    if (v.p[i] == '/') return true;
    if (i + 2 < v.n && v.p[i] == '%' && v.p[i + 1] == '2' && (v.p[i + 2] == 'F' || v.p[i + 2] == 'f')) return true;
  }
  return false;
}

/* isRequestPostPolicySignatureV4: a multipart/form-data POST */
static bool post_form(const s3_ctx *c) {
  buckets_str ct = buckets_http_header_get(c->req, "Content-Type");
  if (!ct.p) return false;
  size_t n = 0;
  while (n < ct.n && ct.p[n] != ';' && ct.p[n] != ' ') n++;
  return n == 19 && strncasecmp(ct.p, "multipart/form-data", 19) == 0;
}

static const char *object_route(const s3_ctx *c, const char *m) {
  bool get = strcmp(m, "GET") == 0, put = strcmp(m, "PUT") == 0, post = strcmp(m, "POST") == 0,
       del = strcmp(m, "DELETE") == 0;
  /* rejectedObjAPIs */
  if ((put || del || get) && has(c, "torrent")) return "torrent";
  if (del && has(c, "acl")) return "acl";
  if (strcmp(m, "HEAD") == 0) return "headobject";
  if (get && has(c, "attributes")) return "getobjectattributes";
  bool part = has(c, "partNumber") && has(c, "uploadId");
  if (put && part && copy_source(c)) return "copyobjectpart";
  if (put && part) return "putobjectpart";
  if (get && has(c, "uploadId")) return "listobjectparts";
  if (post && has(c, "uploadId")) return "completemultipartupload";
  if (post && has(c, "uploads")) return "newmultipartupload";
  if (del && has(c, "uploadId")) return "abortmultipartupload";
  if (get && has(c, "acl")) return "getobjectacl";
  if (put && has(c, "acl")) return "putobjectacl";
  if (get && has(c, "tagging")) return "getobjecttagging";
  if (put && has(c, "tagging")) return "putobjecttagging";
  if (del && has(c, "tagging")) return "deleteobjecttagging";
  if (post && has(c, "select") && is(c, "select-type", "2")) return "selectobjectcontent";
  if (get && has(c, "retention")) return "getobjectretention";
  if (get && has(c, "legal-hold")) return "getobjectlegalhold";
  if (get && has(c, "lambdaArn")) return "getobjectlambda";
  if (get) return "getobject";
  if (put && copy_source(c)) return "copyobject";
  if (put && has(c, "retention")) return "putobjectretention";
  if (put && has(c, "legal-hold")) return "putobjectlegalhold";
  if (put) {
    buckets_str x = buckets_http_header_get(c->req, "X-Amz-Snowball-Extract");
    if (x.p && buckets_str_eq_c(x, "true")) return "putobjectextract";
    if (header(c, "X-Amz-Write-Offset-Bytes")) return NULL; /* errorResponseHandler */
    return "putobject";
  }
  if (del) return "deleteobject";
  if (post && has(c, "restore")) return "postrestoreobject";
  return ""; /* no object route: the bucket routes match any path */
}

static const char *bucket_route(const s3_ctx *c, const char *m) {
  bool get = strcmp(m, "GET") == 0, put = strcmp(m, "PUT") == 0, post = strcmp(m, "POST") == 0,
       del = strcmp(m, "DELETE") == 0;
  static const struct {
    const char *q, *api;
  } gets1[] = {{"location", "getbucketlocation"},     {"policy", "getbucketpolicy"},
               {"lifecycle", "getbucketlifecycle"},   {"encryption", "getbucketencryption"},
               {"object-lock", "getbucketobjectlockconfig"}, {"replication", "getbucketreplicationconfig"},
               {"versioning", "getbucketversioning"}, {"notification", "getbucketnotification"},
               {"events", "listennotification"},      {"replication-reset-status", "resetbucketreplicationstatus"}};
  if (get)
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(gets1); i++)
      if (has(c, gets1[i].q)) return gets1[i].api;
  if (get && has(c, "acl")) return "getbucketacl";
  if (put && has(c, "acl")) return "putbucketacl";
  if (get && has(c, "cors")) return "getbucketcors";
  if (put && has(c, "cors")) return "putbucketcors";
  if (del && has(c, "cors")) return "deletebucketcors";
  if (get && has(c, "website")) return "getbucketwebsite";
  if (get && has(c, "accelerate")) return "getbucketaccelerate";
  if (get && has(c, "requestPayment")) return "getbucketrequestpayment";
  if (get && has(c, "logging")) return "getbucketlogging";
  if (get && has(c, "tagging")) return "getbuckettagging";
  if (del && has(c, "website")) return "deletebucketwebsite";
  if (del && has(c, "tagging")) return "deletebuckettagging";
  if (get && has(c, "uploads")) return "listmultipartuploads";
  if (get && is(c, "list-type", "2") && is(c, "metadata", "true")) return "listobjectsv2m";
  if (get && is(c, "list-type", "2")) return "listobjectsv2";
  if (get && has(c, "versions") && is(c, "metadata", "true")) return "listobjectversionsm";
  if (get && has(c, "versions")) return "listobjectversions";
  if (get && has(c, "policyStatus")) return "getbucketpolicystatus";
  static const struct {
    const char *q, *api;
  } puts1[] = {{"lifecycle", "putbucketlifecycle"},   {"replication", "putbucketreplicationconfig"},
               {"encryption", "putbucketencryption"}, {"policy", "putbucketpolicy"},
               {"object-lock", "putbucketobjectlockconfig"}, {"tagging", "putbuckettagging"},
               {"versioning", "putbucketversioning"}, {"notification", "putbucketnotification"},
               {"replication-reset", "resetbucketreplicationstart"}};
  if (put) {
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(puts1); i++)
      if (has(c, puts1[i].q)) return puts1[i].api;
    return "putbucket";
  }
  if (strcmp(m, "HEAD") == 0) return "headbucket";
  if (post && post_form(c)) return "postpolicybucket";
  if (post && has(c, "delete")) return "deletemultipleobjects";
  if (del && has(c, "policy")) return "deletebucketpolicy";
  if (del && has(c, "replication")) return "deletebucketreplicationconfig";
  if (del && has(c, "lifecycle")) return "deletebucketlifecycle";
  if (del && has(c, "encryption")) return "deletebucketencryption";
  if (del) return "deletebucket";
  if (get && is(c, "replication-metrics", "2")) return "getbucketreplicationmetricsv2";
  if (get && has(c, "replication-metrics")) return "getbucketreplicationmetrics";
  if (get && has(c, "replication-check")) return "validatebucketreplicationcreds";
  /* rejectedBucketAPIs (the ones not already routed above) */
  static const struct {
    const char *q;
    bool get, put, del;
  } rej[] = {{"inventory", 1, 1, 1},      {"cors", 0, 1, 1},          {"metrics", 1, 1, 1},
             {"website", 0, 1, 0},        {"logging", 0, 1, 1},       {"accelerate", 0, 1, 1},
             {"requestPayment", 0, 1, 1}, {"acl", 0, 0, 1},           {"publicAccessBlock", 1, 1, 1},
             {"ownershipControls", 1, 1, 1}, {"intelligent-tiering", 1, 1, 1}, {"analytics", 1, 1, 1}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(rej); i++)
    if (((get && rej[i].get) || (put && rej[i].put) || (del && rej[i].del)) && has(c, rej[i].q)) return rej[i].q;
  if (get) return "listobjectsv1";
  return NULL;
}

int buckets_s3_api_index(const s3_ctx *c) {
  char m[16];
  size_t n = c->req->method.n < sizeof(m) - 1 ? c->req->method.n : sizeof(m) - 1;
  memcpy(m, c->req->method.p, n);
  m[n] = '\0';
  const char *api = NULL;
  if (!c->bucket || !*c->bucket) {
    if (strcmp(m, "GET") == 0) api = has(c, "events") ? "listennotification" : "listbuckets";
  } else {
    api = c->object && *c->object ? object_route(c, m) : "";
    if (api && !*api) api = bucket_route(c, m);
  }
  return api ? buckets_api_index(api) : -1;
}
