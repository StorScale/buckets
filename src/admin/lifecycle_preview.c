/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* What a draft lifecycle configuration would do to a bucket (docs/design/lifecycle-replication-editor.md), a
 * Buckets extension to the admin API:
 *   POST /minio/admin/v3/buckets/lifecycle-preview?bucket=   body: the draft's XML
 *       s3:GetLifecycleConfiguration and s3:ListBucketVersions on the bucket
 *   -> {"scanned", "complete", "opensIncident", "actions": [{"rule", "action", "when", "objects", "bytes",
 *       "examples"}]}
 * Every version is evaluated as the scanner evaluates it (s3/server.c), now and 7 and 30 days ahead; nothing is
 * changed. The walk stops after 1,000,000 versions or 30 seconds ("complete": false). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "bucket/lifecycle.h"
#include "bucket/metasys.h"
#include "bucket/versioning.h"
#include "s3/internal.h"
#include "tier/tier.h"

#define MAX_VERSIONS 1000000
#define MAX_SECONDS 30
#define PAGE 1000
#define EXAMPLES 3
#define DAY_NS (86400LL * 1000000000LL)

static const int64_t k_ahead[] = {0, 7 * DAY_NS, 30 * DAY_NS};
static const char *const k_when[] = {"next-run", "7d", "30d"};

static const char *action_name(buckets_lc_action a) {
  switch (a) {
    case BUCKETS_LC_DELETE: return "expire";
    case BUCKETS_LC_DELETE_VERSION: return "delete-version";
    case BUCKETS_LC_TRANSITION: return "transition";
    case BUCKETS_LC_TRANSITION_VERSION: return "transition-version";
    case BUCKETS_LC_DELETE_ALL_VERSIONS: return "delete-all-versions";
    case BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS: return "delete-marker-all-versions";
    default: return NULL; /* restored copies expiring, or nothing */
  }
}

typedef struct {
  char *rule;
  const char *action, *when;
  uint64_t objects, bytes;
  char *examples[EXAMPLES];
  size_t nexamples;
} tally;

typedef struct {
  tally *t;
  size_t n;
} tallies;

static void count(tallies *ts, const char *rule, const char *action, const char *when, const char *key,
                  int64_t size) {
  tally *t = NULL;
  for (size_t i = 0; i < ts->n && !t; i++)
    if (!strcmp(ts->t[i].rule, rule) && ts->t[i].action == action && ts->t[i].when == when) t = &ts->t[i];
  if (!t) {
    ts->t = buckets_xrealloc(ts->t, (ts->n + 1) * sizeof(*ts->t));
    t = &ts->t[ts->n++];
    *t = (tally){.rule = buckets_xstrdup(rule), .action = action, .when = when};
  }
  t->objects++;
  t->bytes += size > 0 ? (uint64_t)size : 0;
  bool seen = false;
  for (size_t i = 0; i < t->nexamples; i++) seen |= !strcmp(t->examples[i], key);
  if (!seen && t->nexamples < EXAMPLES) t->examples[t->nexamples++] = buckets_xstrdup(key);
}

/* One key's versions (newest first): each version counts once, under the first horizon at which a rule acts. */
static void eval_key(const buckets_lifecycle *lc, const buckets_bucket_state *st,
                     const buckets_object_info *v, size_t n, int64_t now, tallies *ts) {
  bool enabled = buckets_versioning_enabled_for(&st->versioning, v[0].name);
  bool suspended = buckets_versioning_suspended_for(&st->versioning, v[0].name);
  buckets_lc_obj *objs = buckets_xcalloc(n, sizeof(*objs));
  buckets_lc_event *ev = buckets_xcalloc(n, sizeof(*ev));
  bool *done = buckets_xcalloc(n, sizeof(*done));
  for (size_t h = 0; h < BUCKETS_ARRAY_LEN(k_ahead); h++) {
    int64_t t = now + k_ahead[h];
    buckets_s3_lc_objs(v, n, enabled, suspended, t, objs);
    buckets_lifecycle_eval_versions(lc, st->lock_enabled, objs, n, t, ev);
    for (size_t i = 0; i < n; i++) {
      const char *a = action_name(ev[i].action);
      if (done[i] || !a) continue;
      done[i] = true;
      bool all = ev[i].action == BUCKETS_LC_DELETE_ALL_VERSIONS ||
                 ev[i].action == BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS;
      if (all) { /* every version of the key goes */
        for (size_t j = 0; j < n; j++) {
          if (j != i && done[j]) continue;
          done[j] = true;
          count(ts, ev[i].rule_id ? ev[i].rule_id : "", a, k_when[h], v[j].name, v[j].size);
        }
      } else {
        count(ts, ev[i].rule_id ? ev[i].rule_id : "", a, k_when[h], v[i].name, v[i].size);
      }
    }
  }
  free(done);
  free(ev);
  free(objs);
}

static bool tier_valid(void *ud, const char *tier) {
  return buckets_tiers_valid(((buckets_s3_server *)ud)->tiers, tier);
}

void buckets_admin_lifecycle_preview(s3_ctx *c) {
  const char *bucket = buckets_query_get(&c->q, "bucket");
  static const char *const actions[] = {"s3:GetLifecycleConfiguration", "s3:ListBucketVersions"};
  if (!bucket || !*bucket) {
    buckets_admin_custom_error(c, 400, "InvalidArgument", "bucket is required");
    return;
  }
  if (!buckets_admin_authorize_bucket(c, bucket, actions, 2)) return;
  buckets_s3_server *s = c->s;
  if (buckets_obj_stat_bucket(s->layer, bucket) != BUCKETS_OBJ_OK) {
    buckets_admin_custom_error(c, 404, "NoSuchBucket", "The specified bucket does not exist");
    return;
  }
  if (c->req->body_len > 1024 * 1024) {
    buckets_admin_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }
  buckets_s3_error re = buckets_s3_read_doc(c);
  if (re) {
    buckets_admin_error(c, re);
    return;
  }
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  buckets_lifecycle lc;
  buckets_lc_error e;
  if (!buckets_lifecycle_parse(c->doc.data ? c->doc.data : "", c->doc.len, true, &lc, &e)) {
    buckets_bucket_state_release(st);
    buckets_admin_custom_error(c, 400, "InvalidArgument", *e.msg ? e.msg : "The XML is not well-formed");
    return;
  }
  if (!buckets_lifecycle_validate(&lc, st->lock_enabled, tier_valid, s, &e)) {
    buckets_bucket_state_release(st);
    buckets_lifecycle_free(&lc);
    buckets_admin_custom_error(c, 400, "InvalidArgument",
                               e.code == BUCKETS_LC_ERR_STORAGE_CLASS ? "No such tier" : e.msg);
    return;
  }
  bool opens = buckets_lifecycle_destroying_rules(&lc) >
               buckets_lifecycle_destroying_rules(st->has_lifecycle ? &st->lifecycle : NULL);
  struct timespec ts0;
  clock_gettime(CLOCK_REALTIME, &ts0);
  int64_t now = (int64_t)ts0.tv_sec * 1000000000LL + ts0.tv_nsec;
  time_t start = time(NULL);
  const char *mv = getenv("BUCKETS_LIFECYCLE_PREVIEW_MAX"); /* for tests */
  size_t max_versions = mv && atol(mv) > 0 ? (size_t)atol(mv) : MAX_VERSIONS;
  tallies ts = {0};
  size_t scanned = 0;
  bool complete = true;
  char *key_marker = NULL, *ver_marker = NULL;
  for (;;) {
    if (scanned >= max_versions || time(NULL) - start >= MAX_SECONDS) {
      complete = false;
      break;
    }
    buckets_obj_listing l = {0};
    if (buckets_obj_list_versions(s->layer, bucket, "", key_marker ? key_marker : "",
                                  ver_marker ? ver_marker : "", NULL, PAGE, &l) != BUCKETS_OBJ_OK) {
      complete = false;
      break;
    }
    /* A key's versions may run on into the next page: unless the page is all one key, its last key waits for the
     * next page, which then starts at that key's first version. */
    size_t end = l.nobjects;
    if (l.truncated && end) {
      size_t k = end;
      while (k > 0 && !strcmp(l.objects[k - 1].name, l.objects[end - 1].name)) k--;
      if (k > 0) end = k;
    }
    bool stop = false;
    for (size_t i = 0; i < end;) {
      if (scanned >= max_versions || time(NULL) - start >= MAX_SECONDS) {
        complete = false;
        stop = true;
        break;
      }
      size_t j = i + 1;
      while (j < end && !strcmp(l.objects[j].name, l.objects[i].name)) j++;
      eval_key(&lc, st, &l.objects[i], j - i, now, &ts);
      scanned += j - i;
      i = j;
    }
    bool more = !stop && l.truncated && l.nobjects;
    free(key_marker);
    free(ver_marker);
    key_marker = ver_marker = NULL;
    if (more) {
      if (end < l.nobjects) { /* resume after the last whole key */
        key_marker = buckets_xstrdup(l.objects[end - 1].name);
      } else {
        key_marker = buckets_xstrdup(l.next_marker ? l.next_marker : l.objects[end - 1].name);
        ver_marker =
            buckets_xstrdup(l.next_version_marker ? l.next_version_marker : l.objects[end - 1].version_id);
      }
    }
    buckets_obj_list_free(&l);
    if (!more) break;
  }
  free(key_marker);
  free(ver_marker);
  buckets_bucket_state_release(st);

  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d), *arr = yyjson_mut_arr(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_uint(d, root, "scanned", scanned);
  yyjson_mut_obj_add_bool(d, root, "complete", complete);
  yyjson_mut_obj_add_bool(d, root, "opensIncident", opens);
  for (size_t i = 0; i < ts.n; i++) {
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, o, "rule", ts.t[i].rule);
    yyjson_mut_obj_add_str(d, o, "action", ts.t[i].action);
    yyjson_mut_obj_add_str(d, o, "when", ts.t[i].when);
    yyjson_mut_obj_add_uint(d, o, "objects", ts.t[i].objects);
    yyjson_mut_obj_add_uint(d, o, "bytes", ts.t[i].bytes);
    yyjson_mut_val *ex = yyjson_mut_obj_add_arr(d, o, "examples");
    for (size_t k = 0; k < ts.t[i].nexamples; k++) yyjson_mut_arr_add_strcpy(d, ex, ts.t[i].examples[k]);
  }
  yyjson_mut_obj_add_val(d, root, "actions", arr);
  size_t len;
  char *j = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  if (j) buckets_buf_append(&c->resp->body, j, len);
  free(j);
  yyjson_mut_doc_free(d);
  for (size_t i = 0; i < ts.n; i++) {
    free(ts.t[i].rule);
    for (size_t k = 0; k < ts.t[i].nexamples; k++) free(ts.t[i].examples[k]);
  }
  free(ts.t);
  buckets_lifecycle_free(&lc);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
