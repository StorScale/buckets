/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/ransomguard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "admin/info.h"
#include "bucket/notification.h"
#include "core/common.h"
#include "core/log.h"
#include "core/uuid.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "iam/iam.h"
#include "notify/event.h"
#include "object/sysconfig.h"
#include "ransomware/ransomware.h"
#include "s3/internal.h"
#include "usage/history.h"
#include "usage/store.h"

#define QUIET_S (15 * 60)   /* an incident closes after this long without a burst */
#define KEEP_S (90 * 86400) /* closed incidents are kept this long */
#define BASELINE_S 3600     /* the usual rates are worked out again after this long */

struct buckets_ransomguard {
  buckets_buf *records; /* the last 14 days' traffic records (one per server and day), and their days back */
  int *day;
  size_t nrecords;
  int64_t loaded_at;
  char today[11];
};

buckets_ransomguard *buckets_ransomguard_new(void) { return buckets_xcalloc(1, sizeof(buckets_ransomguard)); }

static void records_free(buckets_ransomguard *g) {
  for (size_t i = 0; i < g->nrecords; i++) buckets_buf_free(&g->records[i]);
  free(g->records);
  free(g->day);
  g->records = NULL, g->day = NULL, g->nrecords = 0;
}

void buckets_ransomguard_free(buckets_ransomguard *g) {
  if (!g) return;
  records_free(g);
  free(g);
}

/* ---- the peer side ---------------------------------------------------------------------------------------- */

bool buckets_ransomguard_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                              buckets_http_response *resp) {
  if (strcmp(op, "ransomware") != 0) return false;
  const char *w = buckets_query_get(q, "window"), *since = buckets_query_get(q, "since");
  buckets_rw_snapshot(s->cluster && s->cluster->self ? s->cluster->self : "", w ? atoi(w) : 5,
                      since ? strtoull(since, NULL, 10) : 0, (int64_t)time(NULL), &resp->body);
  resp->status = 200;
  return true;
}

/* ---- usual rates ------------------------------------------------------------------------------------------ */

static void load_history(buckets_s3_server *s, buckets_ransomguard *g, int64_t now) {
  char today[11];
  buckets_usage_today(today);
  if (g->loaded_at && now - g->loaded_at < BASELINE_S && !strcmp(today, g->today)) return;
  records_free(g);
  buckets_usage_source src = buckets_usage_store_source(s->layer);
  int64_t t0;
  if (!buckets_usage_day_parse(today, &t0)) return;
  for (int d = 1; d <= 14; d++) { /* the 14 days before today: an attack under way is in today's record */
    char day[11];
    buckets_usage_day(t0 - (int64_t)d * 86400, day);
    buckets_buf *tr = NULL;
    size_t nt = src.traffic(src.ud, day, &tr);
    for (size_t i = 0; i < nt; i++) {
      g->records = buckets_xrealloc(g->records, (g->nrecords + 1) * sizeof(*g->records));
      g->day = buckets_xrealloc(g->day, (g->nrecords + 1) * sizeof(*g->day));
      g->records[g->nrecords] = tr[i];
      g->day[g->nrecords++] = d - 1;
    }
    free(tr);
  }
  g->loaded_at = now;
  snprintf(g->today, sizeof(g->today), "%s", today);
}

typedef struct {
  buckets_ransomguard *g;
  int window;
} usual_ctx;

static uint64_t usual_of(void *ud, const char *bucket, buckets_rw_incident_kind kind) {
  usual_ctx *u = ud;
  return buckets_rw_usual_from_history(u->g->records, u->g->day, u->g->nrecords, bucket, kind, u->window);
}

/* ---- response --------------------------------------------------------------------------------------------- */

const char *buckets_ransomguard_disable(buckets_s3_server *s, const char *access_key, const char *user,
                                        const char *type, char *err, size_t errlen) {
  *err = '\0';
  buckets_iam_err e = BUCKETS_IAM_OK;
  const char *action = "none";
  if (!strcmp(type, "access-key")) {
    e = buckets_iam_update_svc(s->iam, access_key, &(buckets_iam_svc_update){.status = "off"}, err, errlen);
    action = "disabled";
  } else if (!strcmp(type, "user")) {
    e = buckets_iam_set_user_status(s->iam, access_key, false);
    action = "disabled";
  } else if (!strcmp(type, "sts")) {
    e = buckets_iam_revoke_tokens(s->iam, user, NULL); /* every session of the person */
    action = "revoked";
  } else {
    snprintf(err, errlen, "%s credentials are never turned off", *type ? type : "these");
    return "none";
  }
  if (e != BUCKETS_IAM_OK) {
    if (!*err) snprintf(err, errlen, "%s", buckets_iam_strerror(e));
    return "none";
  }
  return action;
}

bool buckets_ransomguard_undo(buckets_s3_server *s, const char *action, const char *access_key,
                              const char *type, char *err, size_t errlen) {
  *err = '\0';
  if (!action || strcmp(action, "disabled") != 0) {
    snprintf(err, errlen,
             !action || !strcmp(action, "none")
                 ? "nothing was turned off"
                 : "revoked sessions can't be restored: the person signs in again");
    return false;
  }
  buckets_iam_err e =
      !strcmp(type, "access-key")
          ? buckets_iam_update_svc(s->iam, access_key, &(buckets_iam_svc_update){.status = "on"}, err, errlen)
          : buckets_iam_set_user_status(s->iam, access_key, true);
  if (e != BUCKETS_IAM_OK) {
    if (!*err) snprintf(err, errlen, "%s", buckets_iam_strerror(e));
    return false;
  }
  return true;
}

/* ---- incidents -------------------------------------------------------------------------------------------- */

static const char *str_of(yyjson_mut_val *o, const char *k) {
  const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(o, k));
  return v ? v : "";
}

static void new_id(char out[24]) {
  char u[37];
  buckets_uuid_v4(u);
  snprintf(out, 24, "%.8s%.4s", u, u + 9);
}

static int event_of(buckets_rw_incident_kind k) {
  return k == BUCKETS_RW_MASS_DELETE      ? BUCKETS_EV_BUCKETS_MASS_DELETE
         : k == BUCKETS_RW_MASS_OVERWRITE ? BUCKETS_EV_BUCKETS_MASS_OVERWRITE
                                          : BUCKETS_EV_BUCKETS_PROTECTION_REMOVED;
}

/* The incident's event to bucket's targets, its details as metadata. */
static void send_incident(buckets_s3_server *s, const char *bucket, yyjson_mut_val *x,
                          buckets_rw_incident_kind kind, uint64_t count, int window) {
  yyjson_mut_val *c0 = yyjson_mut_arr_get_first(yyjson_mut_obj_get(x, "credentials"));
  const char *ak = yyjson_mut_get_str(yyjson_mut_obj_get(c0, "accessKey"));
  char cnt[32], usual[32], win[16];
  snprintf(cnt, sizeof(cnt), "%llu", (unsigned long long)count);
  snprintf(usual, sizeof(usual), "%llu",
           (unsigned long long)yyjson_mut_get_uint(yyjson_mut_obj_get(x, "usual")));
  snprintf(win, sizeof(win), "%dm", window);
  const char *action = yyjson_mut_get_str(yyjson_mut_obj_get(x, "action"));
  buckets_event_kv kv[] = {
      {"x-buckets-incident-id", str_of(x, "id")},
      {"x-buckets-incident-kind", buckets_rw_kind_name(kind)},
      {"x-buckets-credential", ak ? ak : ""},
      {"x-buckets-user", str_of(c0, "user")},
      {"x-buckets-credential-type", str_of(c0, "type")},
      {"x-buckets-objects", cnt},
      {"x-buckets-usual", usual},
      {"x-buckets-window", win},
      {"x-buckets-change", str_of(x, "change")},
      {"x-buckets-detail", str_of(x, "detail")},
      {"x-buckets-action", action ? action : "none"},
  };
  buckets_s3_send_incident_event(s, event_of(kind), bucket, ak, kv, BUCKETS_ARRAY_LEN(kv));
}

/* A new burst's incident: the response, the log, the events. */
static void opened(buckets_s3_server *s, yyjson_mut_doc *d, yyjson_mut_val *x, const buckets_rw_burst *b,
                   const buckets_rw_row *rows, size_t nrows, int window) {
  const buckets_rw_row *who = b->nwho ? b->who[0] : NULL;
  const char *resp = getenv("BUCKETS_RANSOMWARE_RESPONSE");
  if (who && resp && !strcmp(resp, "disable")) {
    char err[256];
    const char *action =
        buckets_ransomguard_disable(s, who->access_key, who->user, who->cred_type, err, sizeof(err));
    yyjson_mut_obj_remove_key(x, "action");
    yyjson_mut_obj_add_str(d, x, "action", action);
    if (*err) {
      yyjson_mut_obj_add_strcpy(d, x, "actionError", err);
      buckets_log_warn("ransomware: could not turn off %s: %s", who->access_key, err);
    }
  }
  const char *action = yyjson_mut_get_str(yyjson_mut_obj_get(x, "action"));
  buckets_log_warn("ransomware: %s %s%s: %llu objects in %d minutes (usually %llu), %s by %s (%s, %s)%s%s",
                   b->kind == BUCKETS_RW_MASS_DELETE ? "mass delete" : "mass overwrite",
                   b->bucket ? "in bucket " : "", b->bucket ? b->bucket : "across buckets",
                   (unsigned long long)b->count, window, (unsigned long long)b->usual,
                   b->nwho > 1 ? "mostly" : "all", who ? who->access_key : "?", who ? who->user : "?",
                   who ? who->cred_type : "?", action ? "; credential " : "", action ? action : "");
  s->rw_incidents[b->kind]++;
  if (b->bucket) {
    send_incident(s, b->bucket, x, b->kind, b->count, window);
  } else { /* a credential's, over several buckets: to each of them */
    for (size_t i = 0; who && i < nrows; i++)
      if (!strcmp(rows[i].access_key, who->access_key) &&
          rows[i].n[b->kind == BUCKETS_RW_MASS_DELETE ? 0 : 2])
        send_incident(s, rows[i].bucket, x, b->kind, b->count, window);
  }
}

/* A protection change from a server's snapshot: a new incident, or one more on the open one for the same bucket
 * and change (a governance bypass comes once per version). */
static bool protection(buckets_s3_server *s, yyjson_mut_doc *d, yyjson_val *c, const char *node,
                       int64_t now) {
  const char *bucket = yyjson_get_str(yyjson_obj_get(c, "b")),
             *change = yyjson_get_str(yyjson_obj_get(c, "change"));
  if (!bucket || !change || buckets_rw_excluded(bucket)) return false;
  yyjson_mut_val *arr = yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents");
  size_t i, max;
  yyjson_mut_val *x;
  yyjson_mut_arr_foreach(arr, i, max, x) {
    if (yyjson_mut_get_sint(yyjson_mut_obj_get(x, "closed"))) continue;
    const char *k = yyjson_mut_get_str(yyjson_mut_obj_get(x, "kind")),
               *b = yyjson_mut_get_str(yyjson_mut_obj_get(x, "bucket"));
    const char *ch = yyjson_mut_get_str(yyjson_mut_obj_get(x, "change"));
    if (!k || strcmp(k, "protection-removed") || !b || strcmp(b, bucket) || !ch || strcmp(ch, change))
      continue;
    yyjson_mut_val *counts = yyjson_mut_obj_get(x, "counts");
    uint64_t n = yyjson_mut_get_uint(yyjson_mut_obj_get(counts, "changes")) + 1;
    yyjson_mut_obj_remove_key(counts, "changes");
    yyjson_mut_obj_add_uint(d, counts, "changes", n);
    yyjson_mut_obj_remove_key(x, "lastSeen");
    yyjson_mut_obj_add_sint(d, x, "lastSeen", now);
    return true;
  }
  char id[24], source[300];
  new_id(id);
  snprintf(source, sizeof(source), "%s/%llu", node,
           (unsigned long long)yyjson_get_uint(yyjson_obj_get(c, "seq")));
  x = yyjson_mut_arr_add_obj(d, arr);
  yyjson_mut_obj_add_strcpy(d, x, "id", id);
  yyjson_mut_obj_add_str(d, x, "kind", "protection-removed");
  yyjson_mut_obj_add_strcpy(d, x, "bucket", bucket);
  yyjson_mut_obj_add_strcpy(d, x, "change", change);
  const char *detail = yyjson_get_str(yyjson_obj_get(c, "detail"));
  yyjson_mut_obj_add_strcpy(d, x, "detail", detail ? detail : "");
  yyjson_mut_val *cs = yyjson_mut_obj_add_arr(d, x, "credentials"), *c0 = yyjson_mut_arr_add_obj(d, cs);
  static const char *const ck[][2] = {{"k", "accessKey"}, {"u", "user"}, {"t", "type"}};
  for (size_t j = 0; j < 3; j++) {
    const char *v = yyjson_get_str(yyjson_obj_get(c, ck[j][0]));
    yyjson_mut_obj_add_strcpy(d, c0, ck[j][1], v ? v : "");
  }
  yyjson_mut_obj_add_uint(d, c0, "count", 1);
  int64_t at = yyjson_get_sint(yyjson_obj_get(c, "at"));
  yyjson_mut_obj_add_sint(d, x, "opened", at ? at : now);
  yyjson_mut_obj_add_sint(d, x, "lastSeen", now);
  yyjson_mut_obj_add_sint(d, x, "closed", 0);
  yyjson_mut_obj_add_uint(d, yyjson_mut_obj_add_obj(d, x, "counts"), "changes", 1);
  yyjson_mut_obj_add_uint(d, x, "usual", 0);
  yyjson_mut_obj_add_null(d, x, "action"); /* never automatic: an admin making a change is the usual case */
  yyjson_mut_obj_add_bool(d, x, "undone", false);
  yyjson_mut_obj_add_bool(d, x, "falseAlarm", false);
  yyjson_mut_obj_add_strcpy(d, x, "source", source);
  const char *ak = yyjson_get_str(yyjson_obj_get(c, "k")), *user = yyjson_get_str(yyjson_obj_get(c, "u"));
  buckets_log_warn("ransomware: protection removed from bucket %s: %s (%s), by %s (%s)", bucket, change,
                   detail ? detail : "", ak && *ak ? ak : "anonymous", user ? user : "");
  s->rw_incidents[BUCKETS_RW_PROTECTION_REMOVED]++;
  send_incident(s, bucket, x, BUCKETS_RW_PROTECTION_REMOVED, 1, 0);
  return true;
}

/* ---- a round ---------------------------------------------------------------------------------------------- */

void buckets_ransomguard_run(buckets_s3_server *s, buckets_ransomguard *g) {
  buckets_objlayer *L = s->layer;
  if (!L || !buckets_objlayer_set_is_led_here(L, 0, 0) || !buckets_iam_ready(s->iam)) return;
  buckets_rw_rule rule;
  buckets_rw_rule_from_env(&rule);
  int64_t now = (int64_t)time(NULL);
  const char *self = s->cluster && s->cluster->self ? s->cluster->self : "";

  /* the stored incidents, and how far each server's protection changes were read */
  buckets_buf raw = BUCKETS_BUF_INIT;
  buckets_sysconfig_read(L, BUCKETS_RW_INCIDENTS_PATH, &raw, NULL);
  yyjson_mut_doc *d = buckets_rw_incidents_parse(raw.data, raw.len);
  yyjson_doc *rd = raw.len ? yyjson_read(raw.data, raw.len, 0) : NULL;
  yyjson_mut_val *since = yyjson_mut_obj(d);
  if (yyjson_is_obj(yyjson_obj_get(yyjson_doc_get_root(rd), "since")))
    since = yyjson_val_mut_copy(d, yyjson_obj_get(yyjson_doc_get_root(rd), "since"));
  yyjson_doc_free(rd);
  buckets_buf_free(&raw);

  /* every server's snapshot */
  size_t nnodes = s->cluster && s->cluster->nnodes ? s->cluster->nnodes : 1;
  yyjson_doc **snaps = buckets_xcalloc(nnodes, sizeof(*snaps));
  for (size_t i = 0; i < nnodes; i++) {
    const char *node = s->cluster && s->cluster->nnodes ? s->cluster->nodes[i] : self;
    uint64_t seen = yyjson_mut_get_uint(yyjson_mut_obj_get(since, node));
    buckets_buf body = BUCKETS_BUF_INIT;
    if (!strcmp(node, self) || !s->peers) {
      buckets_rw_snapshot(self, rule.window_min, seen, now, &body);
    } else {
      char target[512];
      snprintf(target, sizeof(target),
               BUCKETS_INTERNODE_PREFIX "peer/admin?op=ransomware&window=%d&since=%llu", rule.window_min,
               (unsigned long long)seen);
      int status = 0;
      if (!buckets_peer_call(s->peers, node, target, &status, &body) || status != 200)
        buckets_buf_reset(&body);
    }
    snaps[i] = body.len ? yyjson_read(body.data, body.len, 0) : NULL;
    buckets_buf_free(&body);
  }

  /* protection changes, in each server's order */
  bool changed = false;
  for (size_t i = 0; i < nnodes; i++) {
    yyjson_val *root = yyjson_doc_get_root(snaps[i]);
    if (!root) continue;
    const char *node = yyjson_get_str(yyjson_obj_get(root, "node"));
    if (!node) continue;
    uint64_t seen = yyjson_mut_get_uint(yyjson_mut_obj_get(since, node)), top = seen;
    size_t j, jm;
    yyjson_val *c;
    yyjson_arr_foreach(yyjson_obj_get(root, "changes"), j, jm, c) {
      uint64_t seq = yyjson_get_uint(yyjson_obj_get(c, "seq"));
      if (seq <= seen) continue;
      changed |= protection(s, d, c, node, now);
      if (seq > top) top = seq;
    }
    /* a server restarted: its numbering starts again */
    uint64_t cur = yyjson_get_uint(yyjson_obj_get(root, "seq"));
    if (cur < seen) top = cur;
    if (top != seen) {
      yyjson_mut_obj_remove_key(since, node);
      yyjson_mut_obj_add(since, yyjson_mut_strcpy(d, node), yyjson_mut_uint(d, top));
      changed = true;
    }
  }

  /* bursts */
  buckets_rw_row *rows = NULL;
  size_t nrows = 0;
  for (size_t i = 0; i < nnodes; i++)
    if (snaps[i]) buckets_rw_rows_add(&rows, &nrows, yyjson_doc_get_root(snaps[i]));
  if (nrows) {
    load_history(s, g, now);
    usual_ctx u = {g, rule.window_min};
    buckets_rw_burst *bursts;
    size_t nb = buckets_rw_detect(rows, nrows, &rule, usual_of, &u, &bursts);
    for (size_t b = 0; b < nb; b++) {
      char id[24];
      new_id(id);
      bool is_new;
      yyjson_mut_val *x = buckets_rw_incident_record(d, &bursts[b], id, now, &is_new);
      if (is_new) opened(s, d, x, &bursts[b], rows, nrows, rule.window_min);
      changed = true;
    }
    free(bursts);
  }
  size_t before = yyjson_mut_arr_size(yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents"));
  buckets_rw_incidents_age(d, now, QUIET_S, KEEP_S);
  /* closing one changes it too: compare the open count before and after */
  size_t i, max;
  yyjson_mut_val *x;
  yyjson_mut_arr_foreach(yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents"), i, max, x) {
    if (yyjson_mut_get_sint(yyjson_mut_obj_get(x, "closed")) == now) changed = true;
  }
  if (yyjson_mut_arr_size(yyjson_mut_obj_get(yyjson_mut_doc_get_root(d), "incidents")) != before)
    changed = true;
  if (changed) {
    yyjson_mut_obj_remove_key(yyjson_mut_doc_get_root(d), "since");
    yyjson_mut_obj_add_val(d, yyjson_mut_doc_get_root(d), "since", since);
    size_t len;
    char *j = yyjson_mut_write(d, 0, &len);
    buckets_obj_err e =
        j ? buckets_sysconfig_write(L, BUCKETS_RW_INCIDENTS_PATH, j, len) : BUCKETS_OBJ_ERR_IO;
    if (e) buckets_log_warn("ransomware: storing the incidents: %s", buckets_obj_strerror(e));
    free(j);
  }
  buckets_rw_rows_free(rows, nrows);
  for (size_t k = 0; k < nnodes; k++) yyjson_doc_free(snaps[k]);
  free(snaps);
  yyjson_mut_doc_free(d);
}
