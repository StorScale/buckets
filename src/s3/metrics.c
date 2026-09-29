/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Prometheus metrics v2 (cmd/metrics-v2.go, metrics-resource.go): the
 * /minio/v2/metrics/{cluster,node,bucket,resource} endpoints, with MinIO's
 * metric groups, their conditions and labels. Names, types and help come
 * from MinIO's catalog (metrics/catalog.inc). */
#include <math.h>
#include <stdatomic.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <yyjson.h>
#include <sys/statvfs.h>
#include <time.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "crypto/base64.h"
#include "crypto/jwt.h"
#include "dist/dsync.h"
#include "dist/peer.h"
#include "heal/healer.h"
#include "iam/plugins.h"
#include "net/client.h"
#include "bucket/metasys.h"
#include "bucket/quota.h"
#include "core/log.h"
#include "kms/kms.h"
#include "logger/logger.h"
#include "metrics/expo.h"
#include "metrics/stats.h"
#include "metrics/sys.h"
#include "notify/notifier.h"
#include "s3/replicate.h"
#include "s3/tiering.h"
#include "s3/batch.h"
#include "tier/tier.h"
#include "object/epool.h"
#include "s3/internal.h"
#include "s3/metrics.h"
#include "scanner/scanner.h"
#include "scanner/usage.h"
#include "storage/drivestats.h"

#ifndef BUCKETS_COMMIT
#define BUCKETS_COMMIT "DEVELOPMENT.GOGET"
#endif

typedef struct {
  buckets_s3_server *s;
  buckets_expo *e;
  const char *server; /* the "server" label */
} mctx;

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* A sample with the server label and up to three more label pairs. */
static void add(mctx *m, const char *name, double v, const char *k1, const char *v1, const char *k2, const char *v2,
                const char *k3, const char *v3) {
  const char *l[8] = {"server", m->server};
  size_t n = 1;
  if (k1) l[2 * n] = k1, l[2 * n + 1] = v1, n++;
  if (k2) l[2 * n] = k2, l[2 * n + 1] = v2, n++;
  if (k3) l[2 * n] = k3, l[2 * n + 1] = v3, n++;
  buckets_expo_add(m->e, name, v, l, n);
}
#define ADD0(m, name, v) add(m, name, v, NULL, NULL, NULL, NULL, NULL, NULL)
#define ADD1(m, name, v, k1, v1) add(m, name, v, k1, v1, NULL, NULL, NULL, NULL)
#define ADD2(m, name, v, k1, v1, k2, v2) add(m, name, v, k1, v1, k2, v2, NULL, NULL)

/* ---- the drives ------------------------------------------------------------ */

typedef struct {
  const buckets_info_endpoint *ep;
  buckets_drive *d; /* NULL: offline / unknown */
  bool online, local;
  size_t pool, set, index; /* index within its set */
  uint64_t total, free_b, avail, used_inodes, free_inodes;
} drive_view;

static size_t drives_of(buckets_s3_server *s, drive_view **out) {
  const buckets_cluster_info *ci = s->cluster;
  buckets_objlayer *L = s->layer;
  size_t n = ci ? ci->neps : 0;
  drive_view *v = buckets_xcalloc(n ? n : 1, sizeof(*v));
  for (size_t i = 0; i < n; i++) {
    const buckets_info_endpoint *ep = &ci->eps[i];
    drive_view *dv = &v[i];
    dv->ep = ep;
    dv->local = ep->local;
    dv->pool = ep->pool;
    for (size_t j = 0; L && j < L->nall; j++) {
      buckets_drive *d = L->all[j];
      if (!d || !(strcmp(d->root, ep->local ? ep->path : ep->endpoint) == 0 || strcmp(d->root, ep->endpoint) == 0))
        continue;
      buckets_drive_place pl;
      buckets_objlayer_place(L, j, &pl);
      dv->d = d;
      dv->set = pl.set;
      dv->index = (j - pl.pool_first) % pl.set_size;
      break;
    }
    struct statvfs sv;
    if (dv->d && ep->local && statvfs(ep->path, &sv) == 0) {
      dv->online = true;
      dv->total = (uint64_t)sv.f_blocks * sv.f_frsize;
      dv->free_b = (uint64_t)sv.f_bfree * sv.f_frsize;
      dv->avail = (uint64_t)sv.f_bavail * sv.f_frsize;
      dv->used_inodes = (uint64_t)(sv.f_files - sv.f_ffree);
      dv->free_inodes = (uint64_t)sv.f_ffree;
    } else if (dv->d && !ep->local) {
      uint64_t total = 0, free_b = 0;
      dv->online = buckets_drive_disk_info(dv->d, &total, &free_b) == BUCKETS_DRIVE_OK;
      dv->total = total, dv->free_b = free_b, dv->avail = free_b;
    }
  }
  *out = v;
  return n;
}

/* Data drives of each pool (StandardSCData), for usable capacity. */
static size_t pool_data_drives(buckets_objlayer *L, size_t pool) {
  if (!L || pool >= L->npools || !L->pools[pool]->nsets) return 0;
  buckets_eset *es = &L->pools[pool]->sets[0];
  return es->n - (size_t)es->parity;
}

/* ---- metric groups (metrics-v2.go) ---------------------------------------- */

/* getNodeHealthMetrics */
static void node_health(mctx *m) {
  const buckets_cluster_info *ci = m->s->cluster;
  size_t up = 1, down = 0; /* this node */
  for (size_t i = 0; ci && i < ci->nnodes; i++) {
    if (strcmp(ci->nodes[i], ci->self) == 0) continue;
    if (m->s->peers && buckets_peer_node_online(m->s->peers, ci->nodes[i])) up++;
    else down++;
  }
  ADD0(m, "minio_cluster_nodes_online_total", (double)up);
  ADD0(m, "minio_cluster_nodes_offline_total", (double)down);
}

/* getClusterStorageMetrics */
static void cluster_storage(mctx *m, const drive_view *dv, size_t n) {
  uint64_t raw_total = 0, raw_free = 0, usable_total = 0, usable_free = 0;
  size_t online = 0;
  for (size_t i = 0; i < n; i++) {
    online += dv[i].online;
    raw_total += dv[i].total;
    raw_free += dv[i].avail;
    if (dv[i].d && dv[i].index < pool_data_drives(m->s->layer, dv[i].pool)) {
      usable_total += dv[i].total;
      usable_free += dv[i].avail;
    }
  }
  ADD0(m, "minio_cluster_capacity_raw_total_bytes", (double)raw_total);
  ADD0(m, "minio_cluster_capacity_raw_free_bytes", (double)raw_free);
  ADD0(m, "minio_cluster_capacity_usable_total_bytes", (double)usable_total);
  ADD0(m, "minio_cluster_capacity_usable_free_bytes", (double)usable_free);
  ADD0(m, "minio_cluster_drive_offline_total", (double)(n - online));
  ADD0(m, "minio_cluster_drive_online_total", (double)online);
  ADD0(m, "minio_cluster_drive_total", (double)n);
}

typedef struct {
  size_t pool, set, drives, online, healing;
  int parity;
  int read_quorum, write_quorum;
  bool healthy;
} set_health;

/* objLayer.Health: per erasure set, and the cluster's write quorum */
static size_t sets_health(buckets_s3_server *s, const drive_view *dv, size_t n, set_health **out, int *write_quorum) {
  buckets_objlayer *L = s->layer;
  size_t total = 0;
  for (size_t p = 0; L && p < L->npools; p++) total += L->pools[p]->nsets;
  set_health *h = buckets_xcalloc(total ? total : 1, sizeof(*h));
  size_t k = 0;
  *write_quorum = 0;
  for (size_t p = 0; L && p < L->npools; p++) {
    for (size_t si = 0; si < L->pools[p]->nsets; si++) {
      buckets_eset *es = &L->pools[p]->sets[si];
      set_health *x = &h[k++];
      x->pool = p, x->set = si, x->drives = es->n, x->parity = es->parity;
      int data = (int)es->n - es->parity;
      x->read_quorum = data;
      x->write_quorum = data == es->parity ? data + 1 : data;
      for (size_t i = 0; i < n; i++)
        if (dv[i].d && dv[i].pool == p && dv[i].set == si && dv[i].online) x->online++;
      x->healthy = (int)x->online >= x->write_quorum;
      if (x->write_quorum > *write_quorum) *write_quorum = x->write_quorum;
    }
  }
  *out = h;
  return k;
}

/* getClusterHealthMetrics */
static void cluster_health(mctx *m, const drive_view *dv, size_t n) {
  set_health *h;
  int wq;
  size_t k = sets_health(m->s, dv, n, &h, &wq);
  bool healthy = true;
  for (size_t i = 0; i < k; i++) healthy &= h[i].healthy;
  ADD0(m, "minio_cluster_write_quorum", wq);
  ADD0(m, "minio_cluster_health_status", healthy);
  for (size_t i = 0; i < k; i++) {
    char pool[16], set[16];
    snprintf(pool, sizeof(pool), "%zu", h[i].pool);
    snprintf(set, sizeof(set), "%zu", h[i].set);
    ADD2(m, "minio_cluster_health_erasure_set_read_quorum", h[i].read_quorum, "pool", pool, "set", set);
    ADD2(m, "minio_cluster_health_erasure_set_write_quorum", h[i].write_quorum, "pool", pool, "set", set);
    ADD2(m, "minio_cluster_health_erasure_set_online_drives", (double)h[i].online, "pool", pool, "set", set);
    ADD2(m, "minio_cluster_health_erasure_set_healing_drives", (double)h[i].healing, "pool", pool, "set", set);
    ADD2(m, "minio_cluster_health_erasure_set_status", h[i].healthy, "pool", pool, "set", set);
  }
  free(h);
}

static bool usage_of(buckets_s3_server *s, buckets_data_usage *u) {
  return s->usage && buckets_usage_cache_get(s->usage, u) && u->last_update_ns;
}

static void histogram_range(mctx *m, const char *name, const uint64_t *v, size_t n, bool sizes, const char *bucket) {
  for (size_t i = 0; i < n; i++) {
    const char *range = sizes ? buckets_usage_size_bin_name(i) : buckets_usage_version_bin_name(i);
    if (bucket) ADD2(m, name, (double)v[i], "bucket", bucket, "range", range);
    else ADD1(m, name, (double)v[i], "range", range);
  }
}

/* getClusterUsageMetrics */
/* getBatchJobsMetrics: every node's batch jobs */
static void batch_one(mctx *m, const char *type, const char *bucket, const char *id, double objects, double failed) {
  char name[128];
  snprintf(name, sizeof(name), "minio_bucket_batch_%s_objects", type);
  ADD2(m, name, objects, "bucket", bucket, "jobId", id);
  snprintf(name, sizeof(name), "minio_bucket_batch_%s_objects_failed", type);
  ADD2(m, name, failed, "bucket", bucket, "jobId", id);
}

static void cluster_batch(mctx *m) {
  if (!m->s->batch) return;
  buckets_batch_metric *bm;
  size_t n = buckets_batch_metrics(m->s->batch, &bm);
  for (size_t i = 0; i < n; i++) batch_one(m, bm[i].type, bm[i].bucket, bm[i].id, bm[i].objects, bm[i].failed);
  free(bm);
  size_t np = 0;
  buckets_peer_info *pi = m->s->peers ? buckets_peer_batch_metrics(m->s->peers, &np) : NULL;
  for (size_t i = 0; i < np; i++) {
    yyjson_doc *d = pi[i].json ? yyjson_read(pi[i].json, strlen(pi[i].json), 0) : NULL;
    yyjson_val *root = d ? yyjson_doc_get_root(d) : NULL;
    yyjson_obj_iter it = yyjson_obj_iter_with(root);
    yyjson_val *k;
    while (yyjson_is_obj(root) && (k = yyjson_obj_iter_next(&it))) {
      yyjson_val *v = yyjson_obj_iter_get_val(k);
      const char *type = yyjson_get_str(yyjson_obj_get(v, "jobType"));
      if (!type) continue;
      yyjson_val *sub = yyjson_obj_get(v, strcmp(type, "replicate") == 0   ? "replicate"
                                          : strcmp(type, "keyrotate") == 0 ? "rotation"
                                                                           : "expired");
      const char *bucket = yyjson_get_str(yyjson_obj_get(sub, "lastBucket"));
      batch_one(m, type, bucket ? bucket : "", yyjson_get_str(k), yyjson_get_num(yyjson_obj_get(sub, "objects")),
                yyjson_get_num(yyjson_obj_get(sub, "objectsFailed")));
    }
    yyjson_doc_free(d);
  }
  buckets_peer_info_free(pi, np);
}

/* getClusterTierMetrics: the stored usage's tierStats, while tiers exist */
static void cluster_tier(mctx *m) {
  if (buckets_tiers_empty(m->s->tiers)) return;
  buckets_data_usage u;
  if (!usage_of(m->s, &u)) return;
  for (size_t i = 0; i < u.ntiers; i++) {
    ADD1(m, "minio_cluster_ilm_transitioned_bytes", (double)u.tiers[i].size, "tier", u.tiers[i].name);
    ADD1(m, "minio_cluster_ilm_transitioned_objects", (double)u.tiers[i].objects, "tier", u.tiers[i].name);
    ADD1(m, "minio_cluster_ilm_transitioned_versions", (double)u.tiers[i].versions, "tier", u.tiers[i].name);
  }
  buckets_data_usage_free(&u);
}

/* getTierMetrics (tierMetrics.Report): reads served from each tier */
static void tier_node_metrics(mctx *m) {
  static const double bounds[10] = {0.01, 0.1, 1, 2, 5, 10, 60, 300, 900, 1800};
  buckets_tier_request_stats *st;
  size_t n = buckets_tiering_request_stats(&st);
  for (size_t i = 0; i < n; i++) {
    for (int b = 0; b <= 10; b++) {
      char le[16];
      if (b < 10) snprintf(le, sizeof(le), "%.3f", bounds[b]);
      else snprintf(le, sizeof(le), "+Inf");
      ADD2(m, "minio_node_tier_ttlb_seconds_distribution", (double)st[i].ttlb_buckets[b], "tier", st[i].tier, "le", le);
    }
    ADD1(m, "minio_node_tier_requests_success", (double)st[i].success, "tier", st[i].tier);
    ADD1(m, "minio_node_tier_requests_failure", (double)st[i].failure, "tier", st[i].tier);
  }
  free(st);
}

static void cluster_usage(mctx *m) {
  buckets_data_usage u;
  if (!usage_of(m->s, &u)) return;
  ADD0(m, "minio_usage_last_activity_nano_seconds", (double)(now_ns() - u.last_update_ns));
  uint64_t sizes[BUCKETS_USAGE_SIZE_BINS] = {0}, versions[BUCKETS_USAGE_VERSION_BINS] = {0};
  for (size_t b = 0; b < u.nbuckets; b++) {
    for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++) sizes[i] += u.buckets[b].sizes[i];
    for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++) versions[i] += u.buckets[b].version_counts[i];
  }
  ADD0(m, "minio_cluster_usage_total_bytes", (double)u.total_size);
  ADD0(m, "minio_cluster_usage_object_total", (double)u.objects);
  ADD0(m, "minio_cluster_usage_version_total", (double)u.versions);
  ADD0(m, "minio_cluster_usage_deletemarker_total", (double)u.delete_markers);
  histogram_range(m, "minio_cluster_objects_size_distribution", sizes, BUCKETS_USAGE_SIZE_BINS, true, NULL);
  histogram_range(m, "minio_cluster_objects_version_distribution", versions, BUCKETS_USAGE_VERSION_BINS, false, NULL);
  ADD0(m, "minio_cluster_bucket_total", (double)u.nbuckets);
  buckets_data_usage_free(&u);
}

/* getKMSMetrics */
static void kms_metrics(mctx *m) {
  if (!m->s->kms) return;
  buckets_kms_metrics km;
  buckets_kms_metrics_get(m->s->kms, &km);
  ADD0(m, "minio_cluster_kms_online", 1); /* the built-in and static KMS are local */
  ADD0(m, "minio_cluster_kms_request_success", (double)km.ok);
  ADD0(m, "minio_cluster_kms_request_error", (double)km.err);
  ADD0(m, "minio_cluster_kms_request_failure", (double)km.fail);
}

/* getGoMetrics: the goroutines are our threads */
static void go_metrics(mctx *m, const buckets_proc_stats *ps) {
  ADD0(m, "minio_node_go_routine_total", (double)ps->threads);
}

static void api_rows(mctx *m, const buckets_api_stats *api, const char *bucket) {
  for (size_t i = 0; i < buckets_api_count(); i++) {
    const buckets_api_stats *a = &api[i];
    bool seen = a->total || a->inflight;
    if (!seen) continue;
    const char *name = buckets_api_name((int)i);
    if (bucket) {
      ADD2(m, "minio_bucket_requests_inflight_total", (double)a->inflight, "bucket", bucket, "api", name);
      if (a->total) ADD2(m, "minio_bucket_requests_total", (double)a->total, "bucket", bucket, "api", name);
      if (a->canceled) ADD2(m, "minio_bucket_requests_canceled_total", (double)a->canceled, "bucket", bucket, "api", name);
      if (a->err4xx) ADD2(m, "minio_bucket_requests_4xx_errors_total", (double)a->err4xx, "bucket", bucket, "api", name);
      if (a->err5xx) ADD2(m, "minio_bucket_requests_5xx_errors_total", (double)a->err5xx, "bucket", bucket, "api", name);
      continue;
    }
    ADD1(m, "minio_s3_requests_inflight_total", (double)a->inflight, "api", name);
    if (a->total) ADD1(m, "minio_s3_requests_total", (double)a->total, "api", name);
    if (a->errors) ADD1(m, "minio_s3_requests_errors_total", (double)a->errors, "api", name);
    if (a->err5xx) ADD1(m, "minio_s3_requests_5xx_errors_total", (double)a->err5xx, "api", name);
    if (a->err4xx) ADD1(m, "minio_s3_requests_4xx_errors_total", (double)a->err4xx, "api", name);
    if (a->canceled) ADD1(m, "minio_s3_requests_canceled_total", (double)a->canceled, "api", name);
  }
}

/* getHTTPMetrics (server-wide) */
static void http_metrics(mctx *m, const buckets_stats_snapshot *st) {
  ADD0(m, "minio_s3_requests_rejected_auth_total", (double)st->rejected[BUCKETS_REJECT_AUTH]);
  ADD0(m, "minio_s3_requests_rejected_timestamp_total", (double)st->rejected[BUCKETS_REJECT_TIMESTAMP]);
  ADD0(m, "minio_s3_requests_rejected_header_total", (double)st->rejected[BUCKETS_REJECT_HEADER]);
  ADD0(m, "minio_s3_requests_rejected_invalid_total", (double)st->rejected[BUCKETS_REJECT_INVALID]);
  ADD0(m, "minio_s3_requests_waiting_total", (double)st->waiting);
  ADD0(m, "minio_s3_requests_incoming_total", (double)st->incoming);
  api_rows(m, st->api, NULL);
}

/* getHistogramMetrics: cumulative buckets labelled le="%.3f", then +Inf */
static void ttfb_rows(mctx *m, const char *name, const buckets_api_stats *api, const char *bucket) {
  for (size_t i = 0; i < buckets_api_count(); i++) {
    const buckets_api_stats *a = &api[i];
    if (!a->total) continue;
    uint64_t cum = 0;
    for (int b = 0; b <= BUCKETS_TTFB_NBOUNDS; b++) {
      cum += a->ttfb[b];
      char le[16];
      if (b < BUCKETS_TTFB_NBOUNDS) snprintf(le, sizeof(le), "%.3f", buckets_ttfb_bounds[b]);
      else snprintf(le, sizeof(le), "+Inf");
      if (bucket) add(m, name, (double)cum, "api", buckets_api_name((int)i), "bucket", bucket, "le", le);
      else ADD2(m, name, (double)cum, "api", buckets_api_name((int)i), "le", le);
    }
  }
}

/* CurrentStats' key: "sys_<type>_<n>" for server log targets (the console
 * is sys_console_0), "audit_<type>_<n>" for audit ones, counted by type. */
static const char *logger_stats_id(const buckets_logger_target_info *lt, size_t n, size_t i) {
  static _Thread_local char id[64];
  size_t k = 0;
  for (size_t j = 0; j < i && j < n; j++) k += lt[j].audit == lt[i].audit && lt[j].kafka == lt[i].kafka;
  snprintf(id, sizeof(id), "%s_%s_%zu", lt[i].audit ? "audit" : "sys", lt[i].kafka ? "kafka" : "http", k);
  return id;
}

/* getNotificationMetrics: event targets, lambdas (none) and audit targets */
static void notification_metrics(mctx *m) {
  buckets_notifier_target_info *ti = NULL;
  size_t nt = m->s->notifier ? buckets_notifier_target_info_get(m->s->notifier, m->s->region, false, &ti) : 0;
  if (m->s->notifier) {
    uint64_t sent = 0, errors = 0, skipped = 0;
    for (size_t i = 0; i < nt; i++) {
      sent += ti[i].st.sent + ti[i].st.failed;
      errors += ti[i].st.failed;
      skipped += ti[i].st.dropped;
    }
    ADD0(m, "minio_notify_current_send_in_progress", 0);
    ADD0(m, "minio_notify_events_skipped_total", (double)skipped);
    ADD0(m, "minio_notify_events_errors_total", (double)errors);
    ADD0(m, "minio_notify_events_sent_total", (double)sent);
    for (size_t i = 0; i < nt; i++) {
      /* arn:minio:sqs:<region>:<id>:<type> */
      char id[256] = "", type[64] = "";
      const char *t = strrchr(ti[i].arn, ':');
      const char *s = t;
      if (t) {
        snprintf(type, sizeof(type), "%s", t + 1);
        while (s > ti[i].arn && *(s - 1) != ':') s--;
        snprintf(id, sizeof(id), "%.*s", (int)(t - s), s);
      }
      ADD2(m, "minio_notify_target_total_events", (double)(ti[i].st.sent + ti[i].st.failed), "target_id", id,
           "target_name", type);
      ADD2(m, "minio_notify_target_failed_events", (double)ti[i].st.failed, "target_id", id, "target_name", type);
      ADD2(m, "minio_notify_target_current_send_in_progress", 0, "target_id", id, "target_name", type);
      ADD2(m, "minio_notify_target_queue_length", (double)ti[i].st.queued, "target_id", id, "target_name", type);
    }
  }
  free(ti);
  /* logger.CurrentStats: the console target is always there */
  ADD1(m, "minio_audit_target_queue_length", 0, "target_id", "sys_console_0");
  ADD1(m, "minio_audit_total_messages", (double)buckets_log_problems(), "target_id", "sys_console_0");
  ADD1(m, "minio_audit_failed_messages", 0, "target_id", "sys_console_0");
  buckets_logger_target_info *lt;
  size_t nl = buckets_logger_targets(m->s->logger, &lt);
  for (size_t i = 0; i < nl; i++) {
    const char *id = logger_stats_id(lt, nl, i);
    ADD1(m, "minio_audit_target_queue_length", (double)lt[i].st.queued, "target_id", id);
    ADD1(m, "minio_audit_total_messages", (double)lt[i].st.total, "target_id", id);
    ADD1(m, "minio_audit_failed_messages", (double)lt[i].st.failed, "target_id", id);
  }
  free(lt);
}

/* getMinioProcMetrics (Linux only, as MinIO) */
static void proc_metrics(mctx *m, const buckets_proc_stats *ps) {
#ifdef __linux__
  if (ps->open_fds) ADD0(m, "minio_node_file_descriptor_open_total", (double)ps->open_fds);
  if (ps->max_fds) ADD0(m, "minio_node_file_descriptor_limit_total", (double)ps->max_fds);
  if (ps->syscr) ADD0(m, "minio_node_syscall_read_total", (double)ps->syscr);
  if (ps->syscw) ADD0(m, "minio_node_syscall_write_total", (double)ps->syscw);
  if (ps->read_bytes) ADD0(m, "minio_node_io_read_bytes", (double)ps->read_bytes);
  if (ps->write_bytes) ADD0(m, "minio_node_io_write_bytes", (double)ps->write_bytes);
  if (ps->rchar) ADD0(m, "minio_node_io_rchar_bytes", (double)ps->rchar);
  if (ps->wchar) ADD0(m, "minio_node_io_wchar_bytes", (double)ps->wchar);
  if (ps->start_time > 0) ADD0(m, "minio_node_process_starttime_seconds", ps->start_time);
  ADD0(m, "minio_node_process_uptime_seconds", (double)now_ns() / 1e9 - ps->start_time);
  ADD0(m, "minio_node_process_cpu_total_seconds", ps->cpu_seconds);
  if (ps->have_memory) ADD0(m, "minio_node_process_resident_memory_bytes", (double)ps->resident);
#else
  (void)m, (void)ps;
#endif
}

/* getMinioVersionMetrics */
static void version_metrics(mctx *m) {
  ADD1(m, "minio_software_commit_info", 1, "commit", BUCKETS_COMMIT);
  ADD1(m, "minio_software_version_info", 1, "version", BUCKETS_VERSION);
}

/* rest.GetRPCStats and the internode byte counts, over the clients to the other nodes */
typedef struct {
  uint64_t errors, dial_errors, sent, received;
  double dial_avg_ns;
} internode_stats;

static void internode_of(buckets_s3_server *s, internode_stats *out) {
  memset(out, 0, sizeof(*out));
  uint64_t dials = 0, dial_ns = 0;
  for (size_t i = 0; i < s->ninternode; i++) {
    buckets_http_client_stats cs;
    buckets_http_client_stats_get(s->internode[i], &cs);
    out->errors += cs.errors;
    out->dial_errors += cs.dial_errors;
    out->sent += cs.sent;
    out->received += cs.received;
    dials += cs.dials;
    dial_ns += cs.dial_ns;
  }
  out->dial_avg_ns = dials ? (double)dial_ns / (double)dials : 0;
}

/* getNetworkMetrics */
static void network_metrics(mctx *m, const buckets_stats_snapshot *st) {
  if (m->s->cluster && m->s->cluster->distributed) {
    internode_stats is;
    internode_of(m->s, &is);
    ADD0(m, "minio_inter_node_traffic_errors_total", (double)is.errors);
    ADD0(m, "minio_inter_node_traffic_dial_errors", (double)is.dial_errors);
    ADD0(m, "minio_inter_node_traffic_dial_avg_time", round(is.dial_avg_ns));
    ADD0(m, "minio_inter_node_traffic_sent_bytes", (double)is.sent);
    ADD0(m, "minio_inter_node_traffic_received_bytes", (double)is.received);
  }
  ADD0(m, "minio_s3_traffic_sent_bytes", (double)st->tx);
  ADD0(m, "minio_s3_traffic_received_bytes", (double)st->rx);
}

/* getILMNodeMetrics and getScannerNodeMetrics */
static void ilm_scanner_metrics(mctx *m) {
  ADD0(m, "minio_node_ilm_expiry_pending_tasks", 0);
  ADD0(m, "minio_node_ilm_expiry_missed_tasks", 0);
  ADD0(m, "minio_node_ilm_expiry_missed_freeversions", 0);
  ADD0(m, "minio_node_ilm_expiry_missed_tierjournal_tasks", 0);
  ADD0(m, "minio_node_ilm_expiry_num_workers", 0);
  buckets_tiering_stats ts;
  buckets_tiering_stats_get(m->s->tiering, &ts);
  ADD0(m, "minio_node_ilm_transition_pending_tasks", (double)ts.pending);
  ADD0(m, "minio_node_ilm_transition_active_tasks", (double)ts.active);
  ADD0(m, "minio_node_ilm_transition_missed_immediate_tasks", (double)ts.missed_immediate);
  buckets_scanner_stats sc = {0};
  buckets_scanner *scn = atomic_load(&m->s->scanner);
  if (scn) buckets_scanner_stats_get(scn, &sc);
  ADD0(m, "minio_node_scanner_objects_scanned", (double)sc.objects);
  ADD0(m, "minio_node_scanner_versions_scanned", 0); /* scannerMetricApplyVersion: MinIO never counts it */
  ADD0(m, "minio_node_scanner_directories_scanned", (double)sc.folders);
  ADD0(m, "minio_node_scanner_bucket_scans_started", (double)sc.bucket_scans_started);
  ADD0(m, "minio_node_scanner_bucket_scans_finished", (double)sc.bucket_scans_finished);
  ADD0(m, "minio_node_ilm_versions_scanned", (double)sc.versions); /* every version the scanner checks */
  static const char *const actions[] = {"none_action", "delete_action", "delete_version_action", "transition_action",
                                        "transition_version_action", "delete_restored_action",
                                        "delete_restored_version_action", "delete_all_versions_action",
                                        "del_marker_delete_all_versions_action"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(actions) && i < BUCKETS_ARRAY_LEN(m->s->ilm_actions); i++) {
    uint64_t v = atomic_load(&m->s->ilm_actions[i]);
    if (!v) continue;
    char name[128];
    snprintf(name, sizeof(name), "minio_node_ilm_action_count_%s", actions[i]);
    ADD0(m, name, (double)v);
  }
}

/* getWebhookMetrics: logger (system and audit) webhook targets; the
 * console's HTTP target is always there */
static void webhook_metrics(mctx *m) {
  ADD2(m, "minio_cluster_webhook_online", 1, "name", "console+http", "endpoint", "");
  ADD2(m, "minio_cluster_webhook_queue_length", 0, "name", "console+http", "endpoint", "");
  ADD2(m, "minio_cluster_webhook_total_messages", (double)buckets_log_problems(), "name", "console+http", "endpoint", "");
  ADD2(m, "minio_cluster_webhook_failed_messages", 0, "name", "console+http", "endpoint", "");
  buckets_logger_target_info *lt;
  size_t nl = buckets_logger_targets(m->s->logger, &lt);
  for (size_t i = 0; i < nl; i++) {
    ADD2(m, "minio_cluster_webhook_online", lt[i].st.online, "name", lt[i].name, "endpoint", lt[i].endpoint);
    ADD2(m, "minio_cluster_webhook_queue_length", (double)lt[i].st.queued, "name", lt[i].name, "endpoint", lt[i].endpoint);
    ADD2(m, "minio_cluster_webhook_total_messages", (double)lt[i].st.total, "name", lt[i].name, "endpoint", lt[i].endpoint);
    ADD2(m, "minio_cluster_webhook_failed_messages", (double)lt[i].st.failed, "name", lt[i].name, "endpoint",
         lt[i].endpoint);
  }
  free(lt);
}

/* getLocalStorageMetrics */
static void local_storage(mctx *m, const drive_view *dv, size_t n) {
  size_t total = 0, online = 0;
  for (size_t i = 0; i < n; i++) {
    if (!dv[i].local) continue;
    total++;
    online += dv[i].online;
    const char *path = dv[i].ep->path;
    ADD1(m, "minio_node_drive_used_bytes", (double)(dv[i].total - dv[i].free_b), "drive", path);
    ADD1(m, "minio_node_drive_free_bytes", (double)dv[i].avail, "drive", path);
    ADD1(m, "minio_node_drive_total_bytes", (double)dv[i].total, "drive", path);
    ADD1(m, "minio_node_drive_free_inodes", (double)dv[i].free_inodes, "drive", path);
    if (!dv[i].d) continue;
    buckets_drive_stats_view sv;
    buckets_drive_stats_get(dv[i].d, &sv);
    ADD1(m, "minio_node_drive_errors_timeout", (double)sv.errors_timeout, "drive", path);
    ADD1(m, "minio_node_drive_errors_ioerror", (double)(sv.errors_availability - sv.errors_timeout), "drive", path);
    ADD1(m, "minio_node_drive_errors_availability", (double)sv.errors_availability, "drive", path);
    ADD1(m, "minio_node_drive_io_waiting", (double)sv.waiting, "drive", path);
    for (int op = 0; op < BUCKETS_DOP__N; op++) {
      if (!sv.count[op]) continue;
      char api[64];
      snprintf(api, sizeof(api), "storage.%s", buckets_drive_op_name((buckets_drive_op)op));
      ADD2(m, "minio_node_drive_latency_us", round(sv.avg_us[op]), "drive", path, "api", api);
    }
  }
  ADD0(m, "minio_node_drive_offline_total", (double)(total - online));
  ADD0(m, "minio_node_drive_online_total", (double)online);
  ADD0(m, "minio_node_drive_total", (double)total);
  buckets_objlayer *L = m->s->layer;
  int std_parity = L && L->npools && L->pools[0]->nsets ? L->pools[0]->sets[0].parity : 0;
  ADD0(m, "minio_node_storage_class_standard_parity", std_parity);
  ADD0(m, "minio_node_storage_class_rrs_parity", std_parity > 1 ? 1 : std_parity);
}

/* getReplicationNodeMetrics: the operational gauges, always published */
static void replication_node(mctx *m) {
  static const char *const names[] = {
      "minio_node_replication_average_active_workers", "minio_node_replication_average_queued_bytes",
      "minio_node_replication_average_queued_count",   "minio_node_replication_average_transfer_rate",
      "minio_node_replication_current_active_workers", "minio_node_replication_current_transfer_rate",
      "minio_node_replication_last_minute_queued_bytes", "minio_node_replication_last_minute_queued_count",
      "minio_node_replication_max_active_workers",     "minio_node_replication_max_queued_bytes",
      "minio_node_replication_max_queued_count",       "minio_node_replication_max_transfer_rate",
      "minio_node_replication_recent_backlog_count"};
  buckets_repl_node_stats ns;
  buckets_repl_stats_node(&ns);
  double tot_curr = ns.xfer[0][0] + ns.xfer[1][0], tot_avg = ns.xfer[0][1] + ns.xfer[1][1];
  double tot_max = ns.xfer[0][2] > ns.xfer[1][2] ? ns.xfer[0][2] : ns.xfer[1][2];
  const double v[] = {ns.workers_avg, ns.q_avg_bytes, ns.q_avg_count, tot_avg,
                      (double)ns.workers_curr, tot_curr, (double)ns.q_bytes, (double)ns.q_count,
                      (double)ns.workers_max, (double)ns.q_max_bytes, (double)ns.q_max_count, tot_max,
                      (double)ns.mrf_failed_last5};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(names); i++) ADD0(m, names[i], v[i]);
  /* each replication target endpoint's link health */
  buckets_repl_ep_health *eh;
  size_t ne = buckets_repl_health_list(m->s->repl, &eh);
  for (size_t i = 0; i < ne; i++) {
    const char *ep = eh[i].endpoint;
    ADD1(m, "minio_node_replication_current_link_latency_ms", (double)(eh[i].lat_curr / 1000000), "endpoint", ep);
    ADD1(m, "minio_node_replication_average_link_latency_ms", (double)(eh[i].lat_avg / 1000000), "endpoint", ep);
    ADD1(m, "minio_node_replication_max_link_latency_ms", (double)(eh[i].lat_max / 1000000), "endpoint", ep);
    ADD1(m, "minio_node_replication_link_online", eh[i].online ? 1 : 0, "endpoint", ep);
    double curr_down = 0;
    if (!eh[i].online && eh[i].last_online_sec) curr_down = (double)(time(NULL) - eh[i].last_online_sec);
    ADD1(m, "minio_node_replication_link_offline_duration_seconds", curr_down, "endpoint", ep);
    double down = (double)(eh[i].offline_ns / 1000000000LL);
    ADD1(m, "minio_node_replication_link_downtime_duration_seconds", down > curr_down ? down : curr_down, "endpoint", ep);
  }
  free(eh);
}

/* the per-target replication statistics of a bucket (hasReplicationUsage) */
static void replication_bucket(mctx *m, const char *bucket, const buckets_repl_bucket_stats *st) {
  for (size_t i = 0; i < st->n; i++) {
    const buckets_repl_target_stats *t = &st->t[i];
    if (!(t->fail_total_count > 0 || t->repl_size > 0)) continue;
    const char *arn = t->arn;
    ADD2(m, "minio_bucket_replication_last_minute_failed_bytes", (double)t->fail_min_bytes, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_last_minute_failed_count", (double)t->fail_min_count, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_last_hour_failed_bytes", (double)t->fail_hour_bytes, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_last_hour_failed_count", (double)t->fail_hour_count, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_total_failed_bytes", (double)t->fail_total_bytes, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_total_failed_count", (double)t->fail_total_count, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_sent_bytes", (double)t->repl_size, "bucket", bucket, "targetArn", arn);
    ADD2(m, "minio_bucket_replication_sent_count", (double)t->repl_count, "bucket", bucket, "targetArn", arn);
    const char *tags[6];
    uint64_t ms[6];
    buckets_repl_stats_upload_latency(t, tags, ms);
    for (int k = 0; k < 6; k++) {
      const char *l[] = {"server", m->server, "bucket", bucket, "operation", "upload", "range", tags[k], "targetArn", arn};
      buckets_expo_add(m->e, "minio_bucket_replication_latency_ms", (double)ms[k], l, 5);
    }
  }
}

/* client_golang's process collector (namespace "minio"), without the server label */
static void process_collector(mctx *m, const buckets_proc_stats *ps) {
  buckets_expo_addl(m->e, "minio_process_cpu_seconds_total", ps->cpu_seconds, NULL);
  buckets_expo_addl(m->e, "minio_process_open_fds", (double)ps->open_fds, NULL);
  buckets_expo_addl(m->e, "minio_process_max_fds", (double)ps->max_fds, NULL);
  buckets_expo_addl(m->e, "minio_process_start_time_seconds", ps->start_time, NULL);
  buckets_expo_addl(m->e, "minio_process_virtual_memory_max_bytes", ps->vm_max, NULL);
#ifdef __linux__
  if (ps->have_memory) {
    buckets_expo_addl(m->e, "minio_process_virtual_memory_bytes", (double)ps->virtual_size, NULL);
    buckets_expo_addl(m->e, "minio_process_resident_memory_bytes", (double)ps->resident, NULL);
  }
  buckets_expo_addl(m->e, "minio_process_network_receive_bytes_total", 0, NULL);
  buckets_expo_addl(m->e, "minio_process_network_transmit_bytes_total", 0, NULL);
#endif
}

/* client_golang's Go collector: the C runtime's nearest figures */
void buckets_metrics_go_collector(buckets_expo *e) {
  buckets_proc_stats ps;
  buckets_proc_stats_get(&ps);
  const char *q[][2] = {{"quantile", "0"}, {"quantile", "0.25"}, {"quantile", "0.5"}, {"quantile", "0.75"},
                        {"quantile", "1"}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(q); i++) buckets_expo_add(e, "go_gc_duration_seconds", 0, q[i], 1);
  buckets_expo_add_suffixed(e, "go_gc_duration_seconds", "_sum", 0, NULL, 0);
  buckets_expo_add_suffixed(e, "go_gc_duration_seconds", "_count", 0, NULL, 0);
  buckets_expo_addl(e, "go_gc_gogc_percent", 100, NULL);
  buckets_expo_addl(e, "go_gc_gomemlimit_bytes", 9223372036854775807.0, NULL);
  buckets_expo_addl(e, "go_goroutines", (double)ps.threads, NULL);
  buckets_expo_addl(e, "go_info", 1, "version", "c17", NULL);
  double inuse = (double)ps.heap_in_use, sys = (double)(ps.heap_system ? ps.heap_system : ps.resident);
  buckets_expo_addl(e, "go_memstats_alloc_bytes", inuse, NULL);
  buckets_expo_addl(e, "go_memstats_alloc_bytes_total", inuse, NULL);
  buckets_expo_addl(e, "go_memstats_buck_hash_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_frees_total", (double)ps.frees, NULL);
  buckets_expo_addl(e, "go_memstats_gc_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_heap_alloc_bytes", inuse, NULL);
  buckets_expo_addl(e, "go_memstats_heap_idle_bytes", sys > inuse ? sys - inuse : 0, NULL);
  buckets_expo_addl(e, "go_memstats_heap_inuse_bytes", inuse, NULL);
  buckets_expo_addl(e, "go_memstats_heap_objects", (double)ps.allocations, NULL);
  buckets_expo_addl(e, "go_memstats_heap_released_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_heap_sys_bytes", sys, NULL);
  buckets_expo_addl(e, "go_memstats_last_gc_time_seconds", 0, NULL);
  buckets_expo_addl(e, "go_memstats_mallocs_total", (double)ps.allocations, NULL);
  buckets_expo_addl(e, "go_memstats_mcache_inuse_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_mcache_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_mspan_inuse_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_mspan_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_next_gc_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_other_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_stack_inuse_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_stack_sys_bytes", 0, NULL);
  buckets_expo_addl(e, "go_memstats_sys_bytes", (double)ps.resident, NULL);
  buckets_expo_addl(e, "go_sched_gomaxprocs_threads", (double)sysconf(_SC_NPROCESSORS_ONLN), NULL);
  buckets_expo_addl(e, "go_threads", (double)ps.threads, NULL);
}

/* getBucketUsageMetrics, getHTTPMetrics(bucketOnly), getBucketTTFBMetric */
static void bucket_metrics(mctx *m) {
  buckets_data_usage u;
  if (usage_of(m->s, &u)) {
    ADD0(m, "minio_bucket_usage_last_activity_nano_seconds", (double)(now_ns() - u.last_update_ns));
    for (size_t b = 0; b < u.nbuckets; b++) {
      const buckets_bucket_usage *bu = &u.buckets[b];
      ADD1(m, "minio_bucket_usage_total_bytes", (double)bu->size, "bucket", bu->name);
      ADD1(m, "minio_bucket_usage_object_total", (double)bu->objects, "bucket", bu->name);
      ADD1(m, "minio_bucket_usage_version_total", (double)bu->versions, "bucket", bu->name);
      ADD1(m, "minio_bucket_usage_deletemarker_total", (double)bu->delete_markers, "bucket", bu->name);
      if (m->s->meta) {
        buckets_bucket_state *st = buckets_metasys_get(m->s->meta, bu->name);
        uint64_t q = st->has_quota ? (st->quota.quota ? st->quota.quota : st->quota.size) : 0;
        if (q > 0) ADD1(m, "minio_bucket_quota_total_bytes", (double)q, "bucket", bu->name);
        buckets_bucket_state_release(st);
      }
      /* replication statistics, kept for every bucket */
      buckets_repl_bucket_stats rst;
      buckets_repl_stats_get(bu->name, &rst);
      ADD1(m, "minio_bucket_replication_received_bytes", (double)rst.replica_size, "bucket", bu->name);
      ADD1(m, "minio_bucket_replication_received_count", (double)rst.replica_count, "bucket", bu->name);
      static const char *const proxied[] = {"get", "head", "put_tagging", "get_tagging", "delete_tagging"};
      for (size_t i = 0; i < BUCKETS_ARRAY_LEN(proxied); i++) {
        char name[128];
        snprintf(name, sizeof(name), "minio_bucket_replication_proxied_%s_requests_total", proxied[i]);
        ADD1(m, name, (double)rst.proxy[i][0], "bucket", bu->name);
        snprintf(name, sizeof(name), "minio_bucket_replication_proxied_%s_requests_failures", proxied[i]);
        ADD0(m, name, (double)rst.proxy[i][1]); /* MinIO leaves the bucket label off these */
      }
      replication_bucket(m, bu->name, &rst);
      buckets_repl_bucket_stats_free(&rst);
      histogram_range(m, "minio_bucket_objects_size_distribution", bu->sizes, BUCKETS_USAGE_SIZE_BINS, true, bu->name);
      histogram_range(m, "minio_bucket_objects_version_distribution", bu->version_counts, BUCKETS_USAGE_VERSION_BINS,
                      false, bu->name);
    }
    buckets_data_usage_free(&u);
  }
  buckets_bucket_stats *bs;
  size_t nb = buckets_stats_buckets(&bs);
  for (size_t b = 0; b < nb; b++) {
    if (bs[b].rx) ADD1(m, "minio_bucket_traffic_received_bytes", (double)bs[b].rx, "bucket", bs[b].bucket);
    if (bs[b].tx) ADD1(m, "minio_bucket_traffic_sent_bytes", (double)bs[b].tx, "bucket", bs[b].bucket);
    api_rows(m, bs[b].api, bs[b].bucket);
    ttfb_rows(m, "minio_bucket_requests_ttfb_seconds_distribution", bs[b].api, bs[b].bucket);
  }
  buckets_stats_buckets_free(bs, nb);
}

/* ---- resource metrics (metrics-resource.go) --------------------------------- */

typedef struct {
  char key[512]; /* subsystem, name and label value */
  char subsys[16], name[32], label_key[16], label_value[400];
  double current, cumulative, max, sum;
  uint64_t count;
} resource_metric;

static pthread_mutex_t g_res_mu = PTHREAD_MUTEX_INITIALIZER;
static resource_metric *g_res;
static size_t g_nres, g_capres;
static struct {
  char drive[400];
  buckets_disk_io io;
  double at;
} g_last_io[64];
static size_t g_nlast_io;

/* updateResourceMetrics */
static void res_update(const char *subsys, const char *name, double v, const char *lk, const char *lv, bool cumulative) {
  char key[512];
  snprintf(key, sizeof(key), "%s/%s/%s", subsys, name, lv ? lv : "");
  resource_metric *r = NULL;
  for (size_t i = 0; i < g_nres && !r; i++)
    if (strcmp(g_res[i].key, key) == 0) r = &g_res[i];
  if (!r) {
    if (g_nres == g_capres) {
      g_capres = g_capres ? g_capres * 2 : 64;
      g_res = buckets_xrealloc(g_res, g_capres * sizeof(*g_res));
    }
    r = &g_res[g_nres++];
    memset(r, 0, sizeof(*r));
    snprintf(r->key, sizeof(r->key), "%s", key);
    snprintf(r->subsys, sizeof(r->subsys), "%s", subsys);
    snprintf(r->name, sizeof(r->name), "%s", name);
    if (lk) snprintf(r->label_key, sizeof(r->label_key), "%s", lk);
    if (lv) snprintf(r->label_value, sizeof(r->label_value), "%s", lv);
  }
  if (cumulative) {
    r->current = v - r->cumulative;
    r->cumulative = v;
  } else {
    r->current = v;
  }
  if (r->current > r->max) r->max = r->current;
  r->sum += r->current;
  r->count++;
}

static double round2(double v) { return round(v * 100) / 100; }

/* collectLocalResourceMetrics: once at start, then every minute */
void buckets_metrics_resource_collect(buckets_s3_server *s) {
  pthread_mutex_lock(&g_res_mu);
  buckets_net_stats ns;
  if (buckets_net_stats_get(&ns)) {
    res_update("if", "rx_bytes", (double)ns.rx_bytes, "interface", ns.name, true);
    res_update("if", "rx_errors", (double)ns.rx_errors, "interface", ns.name, true);
    res_update("if", "tx_bytes", (double)ns.tx_bytes, "interface", ns.name, true);
    res_update("if", "tx_errors", (double)ns.tx_errors, "interface", ns.name, true);
  }
  buckets_mem_stats mem;
  if (buckets_mem_stats_get(&mem)) {
    res_update("mem", "total", (double)mem.total, NULL, NULL, false);
    res_update("mem", "used", (double)mem.used, NULL, NULL, false);
    res_update("mem", "used_perc", round((double)mem.used * 100 * 100 / (double)mem.total) / 100, NULL, NULL, false);
    res_update("mem", "free", (double)mem.free, NULL, NULL, false);
    res_update("mem", "shared", (double)mem.shared, NULL, NULL, false);
    res_update("mem", "buffers", (double)mem.buffers, NULL, NULL, false);
    res_update("mem", "available", (double)mem.available, NULL, NULL, false);
    res_update("mem", "cache", (double)mem.cache, NULL, NULL, false);
  }
  buckets_cpu_stats cpu;
  if (buckets_cpu_stats_get(&cpu)) {
    if (cpu.have_times) {
      double tot = cpu.user + cpu.system + cpu.idle + cpu.iowait + cpu.nice + cpu.steal;
      if (tot > 0) {
        res_update("cpu_avg", "user", round2(cpu.user / tot * 100), NULL, NULL, false);
        res_update("cpu_avg", "system", round2(cpu.system / tot * 100), NULL, NULL, false);
        res_update("cpu_avg", "idle", round2(cpu.idle / tot * 100), NULL, NULL, false);
        res_update("cpu_avg", "iowait", round2(cpu.iowait / tot * 100), NULL, NULL, false);
        res_update("cpu_avg", "nice", round2(cpu.nice / tot * 100), NULL, NULL, false);
        res_update("cpu_avg", "steal", round2(cpu.steal / tot * 100), NULL, NULL, false);
      }
    }
    res_update("cpu_avg", "load1", cpu.load1, NULL, NULL, false);
    res_update("cpu_avg", "load5", cpu.load5, NULL, NULL, false);
    res_update("cpu_avg", "load15", cpu.load15, NULL, NULL, false);
    if (cpu.cpus > 0) {
      res_update("cpu_avg", "load1_perc", round(cpu.load1 * 100 * 100 / cpu.cpus) / 100, NULL, NULL, false);
      res_update("cpu_avg", "load5_perc", round(cpu.load5 * 100 * 100 / cpu.cpus) / 100, NULL, NULL, false);
      res_update("cpu_avg", "load15_perc", round(cpu.load15 * 100 * 100 / cpu.cpus) / 100, NULL, NULL, false);
    }
  }
  /* collectDriveMetrics: I/O rates since the last collection, then space */
  drive_view *dv;
  size_t n = drives_of(s, &dv);
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  double now = (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
  for (size_t i = 0; i < n; i++) {
    if (!dv[i].local) continue;
    const char *path = dv[i].ep->path;
    buckets_disk_io io;
    bool have = buckets_disk_io_get(path, &io);
    size_t j = 0;
    while (j < g_nlast_io && strcmp(g_last_io[j].drive, path) != 0) j++;
    if (j == g_nlast_io && g_nlast_io < BUCKETS_ARRAY_LEN(g_last_io)) {
      /* initLatestValues: the baseline the first rates are taken against */
      snprintf(g_last_io[g_nlast_io].drive, sizeof(g_last_io[0].drive), "%s", path);
      g_last_io[g_nlast_io].io = io;
      g_last_io[g_nlast_io].at = now;
      g_nlast_io++;
    }
    if (j < g_nlast_io) {
      /* updateDriveIOStats */
      buckets_disk_io *p = &g_last_io[j].io;
      double secs = now - g_last_io[j].at;
      double reads = have ? (double)(io.reads - p->reads) : 0, writes = have ? (double)(io.writes - p->writes) : 0;
      double rsec = have ? (double)(io.read_sectors - p->read_sectors) : 0;
      double wsec = have ? (double)(io.write_sectors - p->write_sectors) : 0;
      double rms = have ? (double)(io.read_ms - p->read_ms) : 0, wms = have ? (double)(io.write_ms - p->write_ms) : 0;
      double busy = have ? (double)(io.busy_ms - p->busy_ms) : 0;
      if (secs <= 0) secs = 1;
      res_update("drive", "reads_per_sec", round2(reads / secs), "drive", path, false);
      res_update("drive", "reads_kb_per_sec", round2(rsec * 512 / 1024 / secs), "drive", path, false);
      res_update("drive", "reads_await", reads > 0 ? round2(rms / reads) : 0, "drive", path, false);
      res_update("drive", "writes_per_sec", round2(writes / secs), "drive", path, false);
      res_update("drive", "writes_kb_per_sec", round2(wsec * 512 / 1024 / secs), "drive", path, false);
      res_update("drive", "writes_await", writes > 0 ? round2(wms / writes) : 0, "drive", path, false);
      res_update("drive", "perc_util", round2(busy / (secs * 10)), "drive", path, false);
      g_last_io[j].io = io;
      g_last_io[j].at = now;
    }
    if (dv[i].online) {
      res_update("drive", "used_bytes", (double)(dv[i].total - dv[i].free_b), "drive", path, false);
      res_update("drive", "total_bytes", (double)dv[i].total, "drive", path, false);
      res_update("drive", "used_inodes", (double)dv[i].used_inodes, "drive", path, false);
      res_update("drive", "total_inodes", (double)(dv[i].free_inodes + dv[i].used_inodes), "drive", path, false);
    }
  }
  free(dv);
  pthread_mutex_unlock(&g_res_mu);
}

/* getResourceMetrics */
static void resource_metrics(mctx *m) {
  pthread_mutex_lock(&g_res_mu);
  for (size_t i = 0; i < g_nres; i++) {
    const resource_metric *r = &g_res[i];
    char name[128];
    snprintf(name, sizeof(name), "minio_node_%s_%s", r->subsys, r->name);
    const char *lk = *r->label_key ? r->label_key : NULL;
    ADD1(m, name, r->current, lk, r->label_value);
    if (strcmp(r->subsys, "drive") != 0) {
      snprintf(name, sizeof(name), "minio_node_%s_%s_avg", r->subsys, r->name);
      ADD1(m, name, r->count ? round2(r->sum / (double)r->count) : 0, lk, r->label_value);
      snprintf(name, sizeof(name), "minio_node_%s_%s_max", r->subsys, r->name);
      ADD1(m, name, r->max, lk, r->label_value);
    }
  }
  pthread_mutex_unlock(&g_res_mu);
}

/* ---- the endpoints ---------------------------------------------------------- */

/* getMinioHealingMetrics: once the healer has handled an object */
static void healing_metrics(mctx *m) {
  buckets_healer *h = atomic_load(&m->s->healer);
  if (!h) return;
  buckets_healer_stats hs;
  buckets_healer_stats_get(h, &hs);
  if (!hs.last_activity_ns) return;
  ADD0(m, "minio_heal_time_last_activity_nano_seconds", (double)(now_ns() - hs.last_activity_ns));
  ADD1(m, "minio_heal_objects_total", (double)(hs.healed + hs.failed + hs.drive_objects_healed), "type", "object");
  ADD1(m, "minio_heal_objects_heal_total", (double)(hs.healed + hs.drive_objects_healed), "type", "object");
  if (hs.failed) ADD1(m, "minio_heal_objects_errors_total", (double)hs.failed, "type", "object");
}

/* getIAMNodeMetrics: only when the identity plugin is configured */
static void iam_node_metrics(mctx *m) {
  buckets_plugins *pl = buckets_s3_plugins(m->s);
  bool on = buckets_idp_plugin_enabled(pl);
  buckets_idp_plugin_metrics pm;
  buckets_idp_plugin_metrics_get(pl, &pm);
  buckets_plugins_release(pl);
  if (!on) return;
  buckets_iam_refresh_stats rs;
  buckets_iam_refresh_stats_get(&rs);
  ADD0(m, "minio_node_iam_last_sync_duration_millis", (double)rs.last_duration_ms);
  ADD0(m, "minio_node_iam_since_last_sync_millis", rs.last_ns ? (double)((uint64_t)now_ns() - rs.last_ns) / 1e6 : 0);
  ADD0(m, "minio_node_iam_sync_successes", (double)rs.successes);
  ADD0(m, "minio_node_iam_sync_failures", (double)rs.failures);
  ADD0(m, "minio_node_iam_plugin_authn_service_last_succ_seconds", pm.last_reachable_secs);
  ADD0(m, "minio_node_iam_plugin_authn_service_last_fail_seconds", pm.last_unreachable_secs);
  ADD0(m, "minio_node_iam_plugin_authn_service_total_requests_minute", (double)pm.total_requests);
  ADD0(m, "minio_node_iam_plugin_authn_service_failed_requests_minute", (double)pm.failed_requests);
  ADD0(m, "minio_node_iam_plugin_authn_service_succ_avg_rtt_ms_minute", pm.avg_rtt_ms);
  ADD0(m, "minio_node_iam_plugin_authn_service_succ_max_rtt_ms_minute", pm.max_rtt_ms);
}

/* getDistLockMetrics (distributed) */
static void lock_metrics(mctx *m) {
  if (!m->s->lock_server) return;
  size_t total, reads, writes;
  buckets_lock_server_stats(m->s->lock_server, &total, &reads, &writes);
  ADD0(m, "minio_locks_total", (double)total);
  ADD0(m, "minio_locks_write_total", (double)writes);
  ADD0(m, "minio_locks_read_total", (double)reads);
}

/* peerMetricsGroups: what every node contributes to the cluster endpoint */
static void peer_groups(mctx *m, const buckets_stats_snapshot *st, const buckets_proc_stats *ps) {
  go_metrics(m, ps);
  http_metrics(m, st);
  notification_metrics(m);
  proc_metrics(m, ps);
  version_metrics(m);
  network_metrics(m, st);
  ttfb_rows(m, "minio_s3_requests_ttfb_seconds_distribution", st->api, NULL);
  ilm_scanner_metrics(m);
  iam_node_metrics(m);
  healing_metrics(m);
  webhook_metrics(m);
  tier_node_metrics(m);
}

/* A peer's samples (Prometheus text) into e. */
static void expo_parse(buckets_expo *e, const char *text) {
  for (const char *line = text; *line;) {
    const char *end = strchr(line, '\n');
    size_t n = end ? (size_t)(end - line) : strlen(line);
    if (n && line[0] != '#') {
      char *l = buckets_xstrndup(line, n);
      char *brace = strchr(l, '{'), *sp = strrchr(l, ' ');
      const char *labels[32];
      size_t nl = 0;
      if (sp) {
        *sp = '\0';
        double v = strtod(sp + 1, NULL);
        if (brace) {
          *brace = '\0';
          /* k="v",... with \\, \" and \n escapes */
          char *p = brace + 1;
          while (*p && *p != '}' && nl + 2 <= BUCKETS_ARRAY_LEN(labels)) {
            char *eq = strchr(p, '=');
            if (!eq || eq[1] != '"') break;
            *eq = '\0';
            labels[nl++] = p;
            char *w = eq + 2, *r = eq + 2;
            for (; *r && *r != '"'; r++) {
              if (*r == '\\' && r[1]) {
                r++;
                *w++ = *r == 'n' ? '\n' : *r;
              } else {
                *w++ = *r;
              }
            }
            bool closed = *r == '"'; /* before the terminator may land on the quote */
            *w = '\0';
            labels[nl++] = eq + 2;
            p = closed ? r + 1 : r;
            if (*p == ',') p++;
          }
        }
        buckets_expo_add(e, l, v, labels, nl / 2);
      }
      free(l);
    }
    line = end ? end + 1 : line + n;
  }
}

char *buckets_s3_peer_metrics(void *server) {
  buckets_s3_server *s = server;
  mctx m = {s, buckets_expo_new(BUCKETS_CATALOG_V2), s->cluster && s->cluster->self ? s->cluster->self : ""};
  buckets_stats_snapshot st;
  buckets_stats_get(&st);
  buckets_proc_stats ps;
  buckets_proc_stats_get(&ps);
  peer_groups(&m, &st, &ps);
  buckets_stats_snapshot_free(&st);
  buckets_buf out = BUCKETS_BUF_INIT;
  buckets_expo_write(m.e, &out);
  buckets_expo_free(m.e);
  return out.data ? buckets_buf_detach(&out) : buckets_xstrdup("");
}

bool buckets_metrics_v2(buckets_s3_server *s, const char *which, buckets_buf *out) {
  bool cluster = strcmp(which, "cluster") == 0, node = strcmp(which, "node") == 0;
  bool bucket = strcmp(which, "bucket") == 0, resource = strcmp(which, "resource") == 0;
  if (!cluster && !node && !bucket && !resource) return false;
  mctx m = {s, buckets_expo_new(resource ? BUCKETS_CATALOG_V2_RESOURCE : BUCKETS_CATALOG_V2),
            s->cluster && s->cluster->self ? s->cluster->self : ""};
  if (resource) {
    resource_metrics(&m);
  } else if (bucket) {
    bucket_metrics(&m);
  } else {
    buckets_stats_snapshot st;
    buckets_stats_get(&st);
    buckets_proc_stats ps;
    buckets_proc_stats_get(&ps);
    drive_view *dv;
    size_t nd = drives_of(s, &dv);
    node_health(&m);
    if (cluster) {
      /* clusterMetricsGroups, then peerMetricsGroups from this node and every peer */
      cluster_storage(&m, dv, nd);
      cluster_tier(&m);
      cluster_usage(&m);
      kms_metrics(&m);
      cluster_health(&m, dv, nd);
      cluster_batch(&m);
      peer_groups(&m, &st, &ps);
      size_t np = 0;
      buckets_peer_info *pi = s->peers ? buckets_peer_metrics(s->peers, &np) : NULL;
      for (size_t i = 0; i < np; i++)
        if (pi[i].json) expo_parse(m.e, pi[i].json);
      buckets_peer_info_free(pi, np);
    } else {
      http_metrics(&m, &st);
      network_metrics(&m, &st);
      version_metrics(&m);
      ttfb_rows(&m, "minio_s3_requests_ttfb_seconds_distribution", st.api, NULL);
      tier_node_metrics(&m);
      notification_metrics(&m);
      lock_metrics(&m);
      iam_node_metrics(&m);
      local_storage(&m, dv, nd);
      replication_node(&m);
      process_collector(&m, &ps);
      buckets_metrics_go_collector(m.e);
    }
    free(dv);
    buckets_stats_snapshot_free(&st);
  }
  buckets_expo_write(m.e, out);
  if (buckets_expo_dropped(m.e)) buckets_log_warn("metrics: %zu samples outside the catalog", buckets_expo_dropped(m.e));
  buckets_expo_free(m.e);
  return true;
}

/* ---- the HTTP endpoints ------------------------------------------------------ */

/* AuthMiddleware: MINIO_PROMETHEUS_AUTH_TYPE=public, or a bearer JWT issued
 * by "prometheus", signed with the secret of its accessKey/sub, whose owner
 * may admin:Prometheus. */
static bool metrics_auth(s3_ctx *c) {
  const char *type = getenv("BUCKETS_PROMETHEUS_AUTH_TYPE");
  if (!type) type = getenv("MINIO_PROMETHEUS_AUTH_TYPE");
  if (type && strcasecmp(type, "public") == 0) return true;
  buckets_str h = buckets_http_header_get(c->req, "Authorization");
  char *tok = NULL;
  if (h.p && h.n > 7 && strncasecmp(h.p, "Bearer ", 7) == 0) tok = buckets_xstrndup(h.p + 7, h.n - 7);
  bool ok = false;
  const char *dot1 = tok ? strchr(tok, '.') : NULL, *dot2 = dot1 ? strchr(dot1 + 1, '.') : NULL;
  if (dot2) {
    /* the claims, unverified, to find whose secret signed them */
    size_t plen = (size_t)(dot2 - dot1 - 1);
    buckets_buf payload = BUCKETS_BUF_INIT;
    buckets_buf_reserve(&payload, plen + 4);
    long dn = buckets_base64url_raw_decode(dot1 + 1, plen, (uint8_t *)payload.data);
    if (dn >= 0) payload.len = (size_t)dn;
    if (dn >= 0) {
      yyjson_doc *d = yyjson_read(payload.data, payload.len, 0);
      yyjson_val *r = yyjson_doc_get_root(d);
      const char *ak = yyjson_get_str(yyjson_obj_get(r, "accessKey"));
      if (!ak) ak = yyjson_get_str(yyjson_obj_get(r, "sub"));
      buckets_iam_ident *id = NULL;
      if (ak && buckets_iam_get_key(c->s->iam, ak, &id) == BUCKETS_IAM_KEY_OK) {
        yyjson_doc *claims = buckets_jwt_verify(tok, id->secret_key, (long long)time(NULL));
        const char *iss = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(claims), "iss"));
        if (claims && iss && strcmp(iss, "prometheus") == 0) {
          bool owner = false;
          buckets_iam_check_token(c->s->iam, id, NULL, &owner);
          c->ident = id;
          c->owner = owner;
          id = NULL;
          ok = buckets_s3_allowed(c, "admin:Prometheus", "", "", false);
        }
        yyjson_doc_free(claims);
      }
      buckets_iam_ident_release(id);
      yyjson_doc_free(d);
    }
    buckets_buf_free(&payload);
  }
  free(tok);
  if (!ok)
    buckets_admin_error_msg(c, BUCKETS_ERR_ACCESS_DENIED, "Access Denied. (Authentication failed, check your access credentials)");
  return ok;
}

bool buckets_s3_metrics_handle(s3_ctx *c) {
  buckets_str p = c->req->path;
  bool v2 = buckets_str_has_prefix(p, "/minio/v2/metrics/");
  bool v3 = buckets_str_eq_c(p, "/minio/metrics/v3") || buckets_str_has_prefix(p, "/minio/metrics/v3/");
  if (!v2 && !v3) return false;
  if (!buckets_str_eq_c(c->req->method, "GET")) return false;
  if (!metrics_auth(c)) return true;
  char *path = buckets_str_dup(p);
  buckets_buf *out = &c->resp->body;
  bool found = v2 ? buckets_metrics_v2(c->s, path + strlen("/minio/v2/metrics/"), out)
                  : buckets_metrics_v3(c->s, path + strlen("/minio/metrics/v3"), out);
  free(path);
  if (!found && v3) { /* http.Error(w, "Metrics Resource Not found", 404) */
    buckets_buf_reset(out);
    buckets_buf_append_c(out, "Metrics Resource Not found\n");
    c->resp->status = 404;
    buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
    return true;
  }
  if (!found) {
    buckets_buf_reset(out);
    return false;
  }
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; version=0.0.4; charset=utf-8");
  return true;
}

/* ---- metrics v3 (metrics-v3*.go) ------------------------------------------------ */

/* MetricValues.Set: only positive values are kept; groups outside /cluster
 * carry the server label. */
typedef struct {
  buckets_s3_server *s;
  buckets_expo *e;
  const char *server; /* NULL for cluster groups */
} m3ctx;

static void set3(m3ctx *m, const char *name, double v, const char *const *labels, size_t n) {
  if (!(v > 0)) return;
  const char *l[16];
  size_t k = 0;
  for (size_t i = 0; i < n && k + 1 < BUCKETS_ARRAY_LEN(l) / 2; i++, k++) l[2 * k] = labels[2 * i], l[2 * k + 1] = labels[2 * i + 1];
  if (m->server) l[2 * k] = "server", l[2 * k + 1] = m->server, k++;
  buckets_expo_add(m->e, name, v, l, k);
}
#define SET0(m, name, v) set3(m, name, v, NULL, 0)
#define SETL(m, name, v, ...) \
  do { \
    const char *_l[] = {__VA_ARGS__}; \
    set3(m, name, v, _l, BUCKETS_ARRAY_LEN(_l) / 2); \
  } while (0)

static void v3_api_rows(m3ctx *m, const char *prefix, const buckets_api_stats *api, const char *bucket) {
  char name[128];
  for (size_t i = 0; i < buckets_api_count(); i++) {
    const buckets_api_stats *a = &api[i];
    const char *h = buckets_api_handler_name((int)i);
    struct {
      const char *suffix;
      double v;
    } rows[] = {{"inflight_total", (double)a->inflight}, {"total", (double)a->total},
                {"errors_total", bucket ? 0 : (double)a->errors}, {"5xx_errors_total", (double)a->err5xx},
                {"4xx_errors_total", (double)a->err4xx}, {"canceled_total", (double)a->canceled}};
    for (size_t r = 0; r < BUCKETS_ARRAY_LEN(rows); r++) {
      snprintf(name, sizeof(name), "%s_%s", prefix, rows[r].suffix);
      if (bucket) SETL(m, name, rows[r].v, "bucket", bucket, "name", h, "type", "s3");
      else SETL(m, name, rows[r].v, "name", h, "type", "s3");
    }
    /* SetHistogram: the cumulative buckets, api renamed to name */
    uint64_t cum = 0;
    snprintf(name, sizeof(name), "%s_ttfb_seconds_distribution", prefix);
    for (int b = 0; b <= BUCKETS_TTFB_NBOUNDS; b++) {
      cum += a->ttfb[b];
      char le[16];
      if (b < BUCKETS_TTFB_NBOUNDS) snprintf(le, sizeof(le), "%.3f", buckets_ttfb_bounds[b]);
      else snprintf(le, sizeof(le), "+Inf");
      if (bucket) SETL(m, name, (double)cum, "bucket", bucket, "le", le, "name", h, "type", "s3");
      else SETL(m, name, (double)cum, "le", le, "name", h, "type", "s3");
    }
  }
}

/* /api/requests */
static void v3_api_requests(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_stats_snapshot st;
  buckets_stats_get(&st);
  SETL(m, "minio_api_requests_rejected_auth_total", (double)st.rejected[BUCKETS_REJECT_AUTH], "type", "s3");
  SETL(m, "minio_api_requests_rejected_timestamp_total", (double)st.rejected[BUCKETS_REJECT_TIMESTAMP], "type", "s3");
  SETL(m, "minio_api_requests_rejected_header_total", (double)st.rejected[BUCKETS_REJECT_HEADER], "type", "s3");
  SETL(m, "minio_api_requests_rejected_invalid_total", (double)st.rejected[BUCKETS_REJECT_INVALID], "type", "s3");
  SETL(m, "minio_api_requests_waiting_total", (double)st.waiting, "type", "s3");
  SETL(m, "minio_api_requests_incoming_total", (double)st.incoming, "type", "s3");
  v3_api_rows(m, "minio_api_requests", st.api, NULL);
  SETL(m, "minio_api_requests_traffic_sent_bytes", (double)st.tx, "type", "s3");
  SETL(m, "minio_api_requests_traffic_received_bytes", (double)st.rx, "type", "s3");
  buckets_stats_snapshot_free(&st);
}

/* /bucket/api/<bucket> */
static void v3_bucket_api(m3ctx *m, const char *bucket) {
  buckets_bucket_stats *bs;
  size_t nb = buckets_stats_buckets(&bs);
  for (size_t b = 0; b < nb; b++) {
    if (strcmp(bs[b].bucket, bucket) != 0) continue;
    /* (MinIO labels the bytes received as sent, and the other way round) */
    SETL(m, "minio_bucket_api_traffic_sent_bytes", (double)bs[b].rx, "bucket", bucket, "type", "s3");
    SETL(m, "minio_bucket_api_traffic_received_bytes", (double)bs[b].tx, "bucket", bucket, "type", "s3");
    v3_api_rows(m, "minio_bucket_api", bs[b].api, bucket);
  }
  buckets_stats_buckets_free(bs, nb);
}

/* /bucket/replication/<bucket> (loadBucketReplicationMetrics) */
static void v3_bucket_replication(m3ctx *m, const char *bucket) {
  buckets_repl_bucket_stats st;
  if (!buckets_repl_stats_get(bucket, &st)) return;
  static const char *const px[] = {"get", "head", "put_tagging", "get_tagging", "delete_tagging"};
  for (size_t i = 0; i < st.n; i++) {
    const buckets_repl_target_stats *t = &st.t[i];
    if (!(t->fail_total_count > 0 || t->repl_size > 0)) continue;
    const char *arn = t->arn;
    SETL(m, "minio_bucket_replication_last_hour_failed_bytes", (double)t->fail_hour_bytes, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_last_hour_failed_count", (double)t->fail_hour_count, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_last_minute_failed_bytes", (double)t->fail_min_bytes, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_last_minute_failed_count", (double)t->fail_min_count, "bucket", bucket, "targetArn", arn);
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(px); k++) {
      char name[128];
      snprintf(name, sizeof(name), "minio_bucket_replication_proxied_%s_requests_total", px[k]);
      SETL(m, name, (double)st.proxy[k][0], "bucket", bucket, "targetArn", arn);
      snprintf(name, sizeof(name), "minio_bucket_replication_proxied_%s_requests_failures", px[k]);
      SETL(m, name, (double)st.proxy[k][1], "bucket", bucket, "targetArn", arn);
    }
    SETL(m, "minio_bucket_replication_sent_count", (double)t->repl_count, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_total_failed_bytes", (double)t->fail_total_bytes, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_total_failed_count", (double)t->fail_total_count, "bucket", bucket, "targetArn", arn);
    SETL(m, "minio_bucket_replication_sent_bytes", (double)t->repl_size, "bucket", bucket, "targetArn", arn);
    const char *tags[6];
    uint64_t ms[6];
    buckets_repl_stats_upload_latency(t, tags, ms);
    for (int k = 0; k < 6; k++)
      SETL(m, "minio_bucket_replication_latency_ms", (double)ms[k], "bucket", bucket, "operation", "upload", "range",
           tags[k], "targetArn", arn);
  }
  buckets_repl_bucket_stats_free(&st);
}

/* /audit */
static void v3_audit(m3ctx *m, const char *bucket) {
  (void)bucket;
  SETL(m, "minio_audit_failed_messages", 0, "target_id", "sys_console_0");
  SETL(m, "minio_audit_target_queue_length", 0, "target_id", "sys_console_0");
  SETL(m, "minio_audit_total_messages", (double)buckets_log_problems(), "target_id", "sys_console_0");
  buckets_logger_target_info *lt;
  size_t nl = buckets_logger_targets(m->s->logger, &lt);
  for (size_t i = 0; i < nl; i++) {
    const char *id = logger_stats_id(lt, nl, i);
    SETL(m, "minio_audit_failed_messages", (double)lt[i].st.failed, "target_id", id);
    SETL(m, "minio_audit_target_queue_length", (double)lt[i].st.queued, "target_id", id);
    SETL(m, "minio_audit_total_messages", (double)lt[i].st.total, "target_id", id);
  }
  free(lt);
}

/* /cluster/config */
static void v3_cluster_config(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_objlayer *L = m->s->layer;
  int std_parity = L && L->npools && L->pools[0]->nsets ? L->pools[0]->sets[0].parity : 0;
  SET0(m, "minio_cluster_config_standard_parity", std_parity);
  SET0(m, "minio_cluster_config_rrs_parity", std_parity > 1 ? 1 : std_parity);
}

/* /cluster/erasure-set */
static void v3_cluster_erasure_set(m3ctx *m, const char *bucket) {
  (void)bucket;
  drive_view *dv;
  size_t nd = drives_of(m->s, &dv);
  set_health *h;
  int wq;
  size_t k = sets_health(m->s, dv, nd, &h, &wq);
  bool healthy = true;
  for (size_t i = 0; i < k; i++) healthy &= h[i].healthy;
  SET0(m, "minio_cluster_erasure_set_overall_write_quorum", wq);
  SET0(m, "minio_cluster_erasure_set_overall_health", healthy);
  for (size_t i = 0; i < k; i++) {
    char pool[16], set[16];
    snprintf(pool, sizeof(pool), "%zu", h[i].pool);
    snprintf(set, sizeof(set), "%zu", h[i].set);
    SETL(m, "minio_cluster_erasure_set_read_quorum", h[i].read_quorum, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_write_quorum", h[i].write_quorum, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_online_drives_count", (double)h[i].online, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_healing_drives_count", (double)h[i].healing, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_health", h[i].healthy, "pool_id", pool, "set_id", set);
    double rt = (double)h[i].online - h[i].read_quorum;
    SETL(m, "minio_cluster_erasure_set_read_tolerance", rt, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_read_health", rt >= 0, "pool_id", pool, "set_id", set);
    double wt = (double)(h[i].online + h[i].healing) - h[i].write_quorum;
    SETL(m, "minio_cluster_erasure_set_write_tolerance", wt, "pool_id", pool, "set_id", set);
    SETL(m, "minio_cluster_erasure_set_write_health", wt >= 0, "pool_id", pool, "set_id", set);
  }
  free(h);
  free(dv);
}

/* /cluster/health */
static void v3_cluster_health(m3ctx *m, const char *bucket) {
  (void)bucket;
  drive_view *dv;
  size_t n = drives_of(m->s, &dv);
  uint64_t raw_total = 0, raw_free = 0, usable_total = 0, usable_free = 0;
  size_t online = 0;
  for (size_t i = 0; i < n; i++) {
    online += dv[i].online;
    raw_total += dv[i].total;
    raw_free += dv[i].avail;
    if (dv[i].d && dv[i].index < pool_data_drives(m->s->layer, dv[i].pool)) {
      usable_total += dv[i].total;
      usable_free += dv[i].avail;
    }
  }
  free(dv);
  SET0(m, "minio_cluster_health_drives_offline_count", (double)(n - online));
  SET0(m, "minio_cluster_health_drives_online_count", (double)online);
  SET0(m, "minio_cluster_health_drives_count", (double)n);
  const buckets_cluster_info *ci = m->s->cluster;
  size_t up = 1, down = 0;
  for (size_t i = 0; ci && i < ci->nnodes; i++) {
    if (strcmp(ci->nodes[i], ci->self) == 0) continue;
    if (m->s->peers && buckets_peer_node_online(m->s->peers, ci->nodes[i])) up++;
    else down++;
  }
  SET0(m, "minio_cluster_health_nodes_offline_count", (double)down);
  SET0(m, "minio_cluster_health_nodes_online_count", (double)up);
  SET0(m, "minio_cluster_health_capacity_raw_total_bytes", (double)raw_total);
  SET0(m, "minio_cluster_health_capacity_raw_free_bytes", (double)raw_free);
  SET0(m, "minio_cluster_health_capacity_usable_total_bytes", (double)usable_total);
  SET0(m, "minio_cluster_health_capacity_usable_free_bytes", (double)usable_free);
}

/* /cluster/iam */
static void v3_cluster_iam(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_iam_refresh_stats rs;
  buckets_iam_refresh_stats_get(&rs);
  SET0(m, "minio_cluster_iam_last_sync_duration_millis", (double)rs.last_duration_ms);
  if (rs.last_ns) SET0(m, "minio_cluster_iam_since_last_sync_millis", (double)((uint64_t)now_ns() - rs.last_ns) / 1e6);
  SET0(m, "minio_cluster_iam_sync_failures", (double)rs.failures);
  SET0(m, "minio_cluster_iam_sync_successes", (double)rs.successes);
  buckets_plugins *pl = buckets_s3_plugins(m->s);
  buckets_idp_plugin_metrics pm;
  buckets_idp_plugin_metrics_get(pl, &pm);
  buckets_plugins_release(pl);
  SET0(m, "minio_cluster_iam_plugin_authn_service_failed_requests_minute", (double)pm.failed_requests);
  SET0(m, "minio_cluster_iam_plugin_authn_service_last_fail_seconds", pm.last_unreachable_secs);
  SET0(m, "minio_cluster_iam_plugin_authn_service_last_succ_seconds", pm.last_reachable_secs);
  SET0(m, "minio_cluster_iam_plugin_authn_service_succ_avg_rtt_ms_minute", pm.avg_rtt_ms);
  SET0(m, "minio_cluster_iam_plugin_authn_service_succ_max_rtt_ms_minute", pm.max_rtt_ms);
  SET0(m, "minio_cluster_iam_plugin_authn_service_total_requests_minute", (double)pm.total_requests);
}

/* /cluster/usage/objects */
static void v3_usage_objects(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_data_usage u;
  if (!usage_of(m->s, &u)) return;
  uint64_t sizes[BUCKETS_USAGE_SIZE_BINS] = {0}, versions[BUCKETS_USAGE_VERSION_BINS] = {0};
  for (size_t b = 0; b < u.nbuckets; b++) {
    for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++) sizes[i] += u.buckets[b].sizes[i];
    for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++) versions[i] += u.buckets[b].version_counts[i];
  }
  SET0(m, "minio_cluster_usage_objects_since_last_update_seconds", (double)(now_ns() - u.last_update_ns) / 1e9);
  SET0(m, "minio_cluster_usage_objects_total_bytes", (double)u.total_size);
  SET0(m, "minio_cluster_usage_objects_count", (double)u.objects);
  SET0(m, "minio_cluster_usage_objects_versions_count", (double)u.versions);
  SET0(m, "minio_cluster_usage_objects_delete_markers_count", (double)u.delete_markers);
  SET0(m, "minio_cluster_usage_objects_buckets_count", (double)u.nbuckets);
  for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++)
    SETL(m, "minio_cluster_usage_objects_size_distribution", (double)sizes[i], "range", buckets_usage_size_bin_name(i));
  for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++)
    SETL(m, "minio_cluster_usage_objects_version_count_distribution", (double)versions[i], "range",
         buckets_usage_version_bin_name(i));
  buckets_data_usage_free(&u);
}

/* /cluster/usage/buckets */
static void v3_usage_buckets(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_data_usage u;
  if (!usage_of(m->s, &u)) return;
  /* (MinIO sends nanoseconds here, under a _seconds name) */
  SET0(m, "minio_cluster_usage_buckets_since_last_update_seconds", (double)(now_ns() - u.last_update_ns));
  for (size_t b = 0; b < u.nbuckets; b++) {
    const buckets_bucket_usage *bu = &u.buckets[b];
    SETL(m, "minio_cluster_usage_buckets_total_bytes", (double)bu->size, "bucket", bu->name);
    SETL(m, "minio_cluster_usage_buckets_objects_count", (double)bu->objects, "bucket", bu->name);
    SETL(m, "minio_cluster_usage_buckets_versions_count", (double)bu->versions, "bucket", bu->name);
    SETL(m, "minio_cluster_usage_buckets_delete_markers_count", (double)bu->delete_markers, "bucket", bu->name);
    if (m->s->meta) {
      buckets_bucket_state *st = buckets_metasys_get(m->s->meta, bu->name);
      uint64_t q = st->has_quota ? (st->quota.quota ? st->quota.quota : st->quota.size) : 0;
      SETL(m, "minio_cluster_usage_buckets_quota_total_bytes", (double)q, "bucket", bu->name);
      buckets_bucket_state_release(st);
    }
    for (size_t i = 0; i < BUCKETS_USAGE_SIZE_BINS; i++)
      SETL(m, "minio_cluster_usage_buckets_object_size_distribution", (double)bu->sizes[i], "range",
           buckets_usage_size_bin_name(i), "bucket", bu->name);
    for (size_t i = 0; i < BUCKETS_USAGE_VERSION_BINS; i++)
      SETL(m, "minio_cluster_usage_buckets_object_version_count_distribution", (double)bu->version_counts[i], "range",
           buckets_usage_version_bin_name(i), "bucket", bu->name);
  }
  buckets_data_usage_free(&u);
}

/* /ilm */
static void v3_ilm(m3ctx *m, const char *bucket) {
  (void)bucket;
  SET0(m, "minio_ilm_expiry_pending_tasks", 0);
  buckets_tiering_stats ts;
  buckets_tiering_stats_get(m->s->tiering, &ts);
  SET0(m, "minio_ilm_transition_active_tasks", (double)ts.active);
  SET0(m, "minio_ilm_transition_pending_tasks", (double)ts.pending);
  SET0(m, "minio_ilm_transition_missed_immediate_tasks", (double)ts.missed_immediate);
  buckets_scanner_stats sc = {0};
  buckets_scanner *scn = atomic_load(&m->s->scanner);
  if (scn) buckets_scanner_stats_get(scn, &sc);
  SET0(m, "minio_ilm_versions_scanned", (double)sc.versions);
}

/* /logger/webhook */
static void v3_logger_webhook(m3ctx *m, const char *bucket) {
  (void)bucket;
  SETL(m, "minio_logger_webhook_failed_messages", 0, "name", "console+http", "endpoint", "");
  SETL(m, "minio_logger_webhook_queue_length", 0, "name", "console+http", "endpoint", "");
  SETL(m, "minio_logger_webhook_total_messages", (double)buckets_log_problems(), "name", "console+http", "endpoint", "");
  buckets_logger_target_info *lt;
  size_t nl = buckets_logger_targets(m->s->logger, &lt);
  for (size_t i = 0; i < nl; i++) {
    SETL(m, "minio_logger_webhook_failed_messages", (double)lt[i].st.failed, "name", lt[i].name, "endpoint", lt[i].endpoint);
    SETL(m, "minio_logger_webhook_queue_length", (double)lt[i].st.queued, "name", lt[i].name, "endpoint", lt[i].endpoint);
    SETL(m, "minio_logger_webhook_total_messages", (double)lt[i].st.total, "name", lt[i].name, "endpoint", lt[i].endpoint);
  }
  free(lt);
}

/* /notification */
static void v3_notification(m3ctx *m, const char *bucket) {
  (void)bucket;
  if (!m->s->notifier) return;
  buckets_notifier_target_info *ti = NULL;
  size_t nt = buckets_notifier_target_info_get(m->s->notifier, m->s->region, false, &ti);
  uint64_t sent = 0, errors = 0, skipped = 0;
  for (size_t i = 0; i < nt; i++) {
    sent += ti[i].st.sent + ti[i].st.failed;
    errors += ti[i].st.failed;
    skipped += ti[i].st.dropped;
  }
  free(ti);
  SET0(m, "minio_notification_current_send_in_progress", 0);
  SET0(m, "minio_notification_events_errors_total", (double)errors);
  SET0(m, "minio_notification_events_sent_total", (double)sent);
  SET0(m, "minio_notification_events_skipped_total", (double)skipped);
}

/* /scanner */
static void v3_scanner(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_scanner_stats sc = {0};
  buckets_scanner *scn = atomic_load(&m->s->scanner);
  if (scn) buckets_scanner_stats_get(scn, &sc);
  SET0(m, "minio_scanner_bucket_scans_finished", (double)sc.bucket_scans_finished);
  SET0(m, "minio_scanner_bucket_scans_started", (double)sc.bucket_scans_started);
  SET0(m, "minio_scanner_directories_scanned", (double)sc.folders);
  SET0(m, "minio_scanner_objects_scanned", (double)sc.objects);
  SET0(m, "minio_scanner_versions_scanned", 0); /* scannerMetricApplyVersion: MinIO never counts it */
  buckets_data_usage u;
  if (usage_of(m->s, &u)) {
    SET0(m, "minio_scanner_last_activity_seconds", (double)(now_ns() - u.last_update_ns) / 1e9);
    buckets_data_usage_free(&u);
  }
}

/* /system/cpu */
static void v3_system_cpu(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_cpu_stats cpu;
  if (!buckets_cpu_stats_get(&cpu)) return;
  SET0(m, "minio_system_cpu_load", cpu.load1);
  if (cpu.cpus > 0) SET0(m, "minio_system_cpu_load_perc", round(cpu.load1 * 100 / cpu.cpus * 100) / 100);
  if (cpu.have_times) {
    double tot = cpu.user + cpu.system + cpu.idle + cpu.iowait + cpu.nice + cpu.steal;
    if (tot > 0) {
      SET0(m, "minio_system_cpu_user", round2(cpu.user / tot * 100));
      SET0(m, "minio_system_cpu_system", round2(cpu.system / tot * 100));
      SET0(m, "minio_system_cpu_nice", round2(cpu.nice / tot * 100));
      SET0(m, "minio_system_cpu_steal", round2(cpu.steal / tot * 100));
    }
  }
  /* the resource sampler's averages */
  pthread_mutex_lock(&g_res_mu);
  for (size_t i = 0; i < g_nres; i++) {
    const resource_metric *r = &g_res[i];
    if (strcmp(r->subsys, "cpu_avg") != 0 || !r->count) continue;
    if (strcmp(r->name, "idle") == 0) SET0(m, "minio_system_cpu_avg_idle", round2(r->sum / (double)r->count));
    if (strcmp(r->name, "iowait") == 0) SET0(m, "minio_system_cpu_avg_iowait", round2(r->sum / (double)r->count));
  }
  pthread_mutex_unlock(&g_res_mu);
}

/* /system/memory */
static void v3_system_memory(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_mem_stats mem;
  if (!buckets_mem_stats_get(&mem)) return;
  SET0(m, "minio_system_memory_total", (double)mem.total);
  SET0(m, "minio_system_memory_used", (double)mem.used);
  SET0(m, "minio_system_memory_used_perc", (double)mem.used * 100 / (double)mem.total);
  SET0(m, "minio_system_memory_free", (double)mem.free);
  SET0(m, "minio_system_memory_buffers", (double)mem.buffers);
  SET0(m, "minio_system_memory_cache", (double)mem.cache);
  SET0(m, "minio_system_memory_shared", (double)mem.shared);
  SET0(m, "minio_system_memory_available", (double)mem.available);
}

/* /system/drive */
static void v3_system_drive(m3ctx *m, const char *bucket) {
  (void)bucket;
  drive_view *dv;
  size_t n = drives_of(m->s, &dv);
  size_t total = 0, online = 0;
  for (size_t i = 0; i < n; i++) {
    if (!dv[i].local) continue;
    total++;
    online += dv[i].online;
    char pool[16], set[16], idx[16];
    snprintf(pool, sizeof(pool), "%zu", dv[i].pool);
    snprintf(set, sizeof(set), "%zu", dv[i].set);
    snprintf(idx, sizeof(idx), "%zu", dv[i].index);
    const char *path = dv[i].ep->path;
#define DL "drive", path, "pool_index", pool, "set_index", set, "drive_index", idx
    SETL(m, "minio_system_drive_used_bytes", (double)(dv[i].total - dv[i].free_b), DL);
    SETL(m, "minio_system_drive_free_bytes", (double)dv[i].avail, DL);
    SETL(m, "minio_system_drive_total_bytes", (double)dv[i].total, DL);
    SETL(m, "minio_system_drive_used_inodes", (double)dv[i].used_inodes, DL);
    SETL(m, "minio_system_drive_free_inodes", (double)dv[i].free_inodes, DL);
    SETL(m, "minio_system_drive_total_inodes", (double)(dv[i].used_inodes + dv[i].free_inodes), DL);
    SETL(m, "minio_system_drive_health", dv[i].online ? 1 : 0, DL); /* offline 0, online 1, healing 2 */
    if (dv[i].d) {
      buckets_drive_stats_view sv;
      buckets_drive_stats_get(dv[i].d, &sv);
      SETL(m, "minio_system_drive_timeout_errors_total", (double)sv.errors_timeout, DL);
      SETL(m, "minio_system_drive_io_errors_total", (double)(sv.errors_availability - sv.errors_timeout), DL);
      SETL(m, "minio_system_drive_availability_errors_total", (double)sv.errors_availability, DL);
      SETL(m, "minio_system_drive_waiting_io", (double)sv.waiting, DL);
      for (int op = 0; op < BUCKETS_DOP__N; op++) {
        if (!sv.count[op]) continue;
        char api[64];
        snprintf(api, sizeof(api), "storage.%s", buckets_drive_op_name((buckets_drive_op)op));
        SETL(m, "minio_system_drive_api_latency_micros", round(sv.avg_us[op]), DL, "api", api);
      }
    }
    /* the I/O rates the resource sampler keeps */
    pthread_mutex_lock(&g_res_mu);
    for (size_t r = 0; r < g_nres; r++) {
      const resource_metric *rm = &g_res[r];
      if (strcmp(rm->subsys, "drive") != 0 || strcmp(rm->label_value, path) != 0) continue;
      static const char *const io[] = {"reads_per_sec", "reads_kb_per_sec", "reads_await", "writes_per_sec",
                                       "writes_kb_per_sec", "writes_await", "perc_util"};
      for (size_t k = 0; k < BUCKETS_ARRAY_LEN(io); k++) {
        if (strcmp(rm->name, io[k]) != 0) continue;
        char name[128];
        snprintf(name, sizeof(name), "minio_system_drive_%s", io[k]);
        SETL(m, name, rm->current, DL);
      }
    }
    pthread_mutex_unlock(&g_res_mu);
#undef DL
  }
  free(dv);
  SET0(m, "minio_system_drive_offline_count", (double)(total - online));
  SET0(m, "minio_system_drive_online_count", (double)online);
  SET0(m, "minio_system_drive_count", (double)total);
}

/* /system/network/internode */
static void v3_system_network(m3ctx *m, const char *bucket) {
  (void)bucket;
  if (!m->s->cluster || !m->s->cluster->distributed) return;
  internode_stats is;
  internode_of(m->s, &is);
  SET0(m, "minio_system_network_internode_errors_total", (double)is.errors);
  SET0(m, "minio_system_network_internode_dial_errors_total", (double)is.dial_errors);
  SET0(m, "minio_system_network_internode_dial_avg_time_nanos", round(is.dial_avg_ns));
  SET0(m, "minio_system_network_internode_sent_bytes_total", (double)is.sent);
  SET0(m, "minio_system_network_internode_recv_bytes_total", (double)is.received);
}

/* /system/process */
static void v3_system_process(m3ctx *m, const char *bucket) {
  (void)bucket;
  buckets_proc_stats ps;
  buckets_proc_stats_get(&ps);
  SET0(m, "minio_system_process_go_routine_total", (double)ps.threads);
  SET0(m, "minio_system_process_uptime_seconds", (double)now_ns() / 1e9 - ps.start_time);
#ifdef __linux__
  SET0(m, "minio_system_process_cpu_total_seconds", ps.cpu_seconds);
  if (ps.have_memory) {
    SET0(m, "minio_system_process_resident_memory_bytes", (double)ps.resident);
    SET0(m, "minio_system_process_virtual_memory_bytes", (double)ps.virtual_size);
  }
  SET0(m, "minio_system_process_start_time_seconds", ps.start_time);
  SET0(m, "minio_system_process_io_rchar_bytes", (double)ps.rchar);
  SET0(m, "minio_system_process_io_read_bytes", (double)ps.read_bytes);
  SET0(m, "minio_system_process_io_wchar_bytes", (double)ps.wchar);
  SET0(m, "minio_system_process_io_write_bytes", (double)ps.write_bytes);
  SET0(m, "minio_system_process_syscall_read_total", (double)ps.syscr);
  SET0(m, "minio_system_process_syscall_write_total", (double)ps.syscw);
  SET0(m, "minio_system_process_file_descriptor_limit_total", (double)ps.max_fds);
  if (ps.vm_max < 9.2e18) SET0(m, "minio_system_process_virtual_memory_max_bytes", ps.vm_max);
  SET0(m, "minio_system_process_file_descriptor_open_total", (double)ps.open_fds);
#endif
  if (m->s->lock_server) {
    size_t total, reads, writes;
    buckets_lock_server_stats(m->s->lock_server, &total, &reads, &writes);
    SET0(m, "minio_system_process_locks_read_total", (double)reads);
    SET0(m, "minio_system_process_locks_write_total", (double)writes);
  }
}

typedef struct {
  const char *path;
  void (*load)(m3ctx *m, const char *bucket);
  bool bucket; /* needs a bucket (the last path component) */
} v3_group;

static const v3_group k_v3_groups[] = {
    {"/api/requests", v3_api_requests, false},
    {"/audit", v3_audit, false},
    {"/bucket/api", v3_bucket_api, true},
    {"/bucket/replication", v3_bucket_replication, true},
    {"/cluster/config", v3_cluster_config, false},
    {"/cluster/erasure-set", v3_cluster_erasure_set, false},
    {"/cluster/health", v3_cluster_health, false},
    {"/cluster/iam", v3_cluster_iam, false},
    {"/cluster/usage/buckets", v3_usage_buckets, false},
    {"/cluster/usage/objects", v3_usage_objects, false},
    {"/debug/go", NULL, false},
    {"/ilm", v3_ilm, false},
    {"/logger/webhook", v3_logger_webhook, false},
    {"/notification", v3_notification, false},
    {"/scanner", v3_scanner, false},
    {"/system/cpu", v3_system_cpu, false},
    {"/system/drive", v3_system_drive, false},
    {"/system/memory", v3_system_memory, false},
    {"/system/network/internode", v3_system_network, false},
    {"/system/process", v3_system_process, false},
};

/* collectorPath.isDescendantOf */
static bool descendant_of(const char *p, const char *ancestor) {
  size_t n = strlen(ancestor);
  if (!n) return true;
  return strncmp(p, ancestor, n) == 0 && (p[n] == '\0' || p[n] == '/');
}

bool buckets_metrics_v3(buckets_s3_server *s, const char *path, buckets_buf *out) {
  if (strcmp(path, "/") == 0) return false;
  char req[512];
  snprintf(req, sizeof(req), "%s", path);
  const char *bucket = NULL;
  if (strncmp(req, "/bucket/", 8) == 0) { /* the bucket is the last component */
    char *last = strrchr(req, '/');
    bucket = last + 1;
    *last = '\0';
  }
  buckets_expo *e = buckets_expo_new(BUCKETS_CATALOG_V3);
  bool any = false;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_v3_groups); i++) {
    const v3_group *g = &k_v3_groups[i];
    if (!descendant_of(g->path, req)) continue;
    if (g->bucket && (!bucket || !*bucket)) continue;
    any = true;
    if (!g->load) {
      buckets_metrics_go_collector(e);
      continue;
    }
    m3ctx m = {s, e, strncmp(g->path, "/cluster", 8) == 0 ? NULL : (s->cluster ? s->cluster->self : "")};
    g->load(&m, bucket);
  }
  if (any) buckets_expo_write(e, out);
  if (buckets_expo_dropped(e)) buckets_log_warn("metrics: %zu samples outside the catalog", buckets_expo_dropped(e));
  buckets_expo_free(e);
  return any;
}
