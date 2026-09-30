/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* ServerInfo (mc admin info): madmin.InfoMessage, from this node's view
 * plus every peer's ServerProperties. Replaces MinIO's getServerInfo and
 * getLocalServerProperty (cmd/admin-handlers.go, cmd/admin-server-info.go). */
#include "admin/info.h"
#include "notify/notifier.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <ctype.h>
#include <unistd.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "dist/peer.h"
#include "heal/healer.h"
#include "iam/ldapidp.h"
#include "logger/logger.h"
#include "object/sysconfig.h"
#include "scanner/usage.h"
#include "s3/internal.h"
#include "storage/drivestats.h"

extern char **environ;

void buckets_cluster_info_free(buckets_cluster_info *ci) {
  if (!ci) return;
  free(ci->self);
  for (size_t i = 0; i < ci->nnodes; i++) free(ci->nodes[i]);
  free(ci->nodes);
  for (size_t i = 0; i < ci->neps; i++) {
    free(ci->eps[i].endpoint);
    free(ci->eps[i].path);
    free(ci->eps[i].node);
  }
  free(ci->eps);
  free(ci);
}

/* The layer slot serving an endpoint, or -1 (offline or never formatted). */
static long slot_of(const buckets_objlayer *L, const buckets_info_endpoint *ep) {
  if (!L) return -1;
  for (size_t i = 0; i < L->nall; i++) {
    const buckets_drive *d = L->all[i];
    if (!d) continue;
    if (strcmp(d->root, ep->local ? ep->path : ep->endpoint) == 0 || strcmp(d->root, ep->endpoint) == 0) return (long)i;
  }
  return -1;
}

static long long int_of(yyjson_mut_val *v) {
  if (yyjson_mut_is_uint(v)) return (long long)yyjson_mut_get_uint(v);
  if (yyjson_mut_is_sint(v)) return yyjson_mut_get_sint(v);
  return -1;
}

/* MinIO's storage API names for our drive ops (DiskMetrics keys); NULL
 * where MinIO has no such call. */
static const char *const k_minio_ops[BUCKETS_DOP__N] = {
    [BUCKETS_DOP_MAKE_VOL] = "MakeVol",         [BUCKETS_DOP_STAT_VOL] = "StatVol",
    [BUCKETS_DOP_DELETE_VOL] = "DeleteVol",     [BUCKETS_DOP_LIST_VOLS] = "ListVols",
    [BUCKETS_DOP_READ_ALL] = "ReadAll",         [BUCKETS_DOP_WRITE_ALL] = "WriteAll",
    [BUCKETS_DOP_CREATE_FILE] = "CreateFile",   [BUCKETS_DOP_APPEND_FILE] = "AppendFile",
    [BUCKETS_DOP_OPEN_FILE] = "ReadFileStream", [BUCKETS_DOP_READ_FILE] = "ReadFile",
    [BUCKETS_DOP_RENAME_DATA] = "RenameData",   [BUCKETS_DOP_DELETE] = "Delete",
    [BUCKETS_DOP_LIST_DIR] = "ListDir",         [BUCKETS_DOP_DISK_INFO] = "DiskInfo",
    [BUCKETS_DOP_STAT_FILE] = "StatInfoFile",   [BUCKETS_DOP_RENAME_FILE] = "RenameFile",
};
/* Every storageMetric MinIO counts, sorted (Go writes map keys in order). */
static const char *const k_minio_all[] = {
    "AppendFile",  "CheckParts",  "CreateFile",   "Delete",         "DeleteAbandonedParts", "DeleteBulk",
    "DeleteVersion", "DeleteVersions", "DeleteVol", "DiskInfo",     "ListDir",              "ListVols",
    "MakeVol",     "MakeVolBulk", "ReadAll",      "ReadFile",       "ReadFileStream",       "ReadMultiple",
    "ReadParts",   "ReadVersion", "ReadXL",       "RenameData",     "RenameFile",           "RenamePart",
    "StatInfoFile", "StatVol",    "UpdateMetadata", "VerifyFile",   "WalkDir",              "WriteAll",
    "WriteMetadata"};

size_t buckets_admin_drive_calls(buckets_drive *drv, const char *const **names, uint64_t *total, uint64_t *count,
                                 uint64_t *acc, buckets_drive_stats_view *sv) {
  buckets_drive_stats_get(drv, sv);
  size_t n = BUCKETS_ARRAY_LEN(k_minio_all);
  memset(total, 0, n * sizeof(*total));
  memset(count, 0, n * sizeof(*count));
  memset(acc, 0, n * sizeof(*acc));
  for (int op = 0; op < BUCKETS_DOP__N; op++) {
    if (!k_minio_ops[op]) continue;
    for (size_t k = 0; k < n; k++) {
      if (strcmp(k_minio_all[k], k_minio_ops[op]) != 0) continue;
      total[k] += sv->total[op], count[k] += sv->count[op], acc[k] += sv->acc_ns[op];
    }
  }
  *names = k_minio_all;
  return n;
}

/* madmin.DiskMetrics for a drive (xlStorageDiskIDCheck.getMetrics). */
static void add_drive_metrics(yyjson_mut_doc *d, yyjson_mut_val *o, buckets_drive *drv) {
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, o, "metrics");
  buckets_drive_stats_view sv;
  uint64_t total[BUCKETS_ADMIN_DRIVE_CALLS], count[BUCKETS_ADMIN_DRIVE_CALLS], acc[BUCKETS_ADMIN_DRIVE_CALLS];
  const char *const *names;
  buckets_admin_drive_calls(drv, &names, total, count, acc, &sv);
  yyjson_mut_val *lm = NULL;
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(k_minio_all); k++) {
    if (!count[k]) continue;
    if (!lm) lm = yyjson_mut_obj_add_obj(d, m, "lastMinute");
    yyjson_mut_val *t = yyjson_mut_obj_add_obj(d, lm, k_minio_all[k]);
    yyjson_mut_obj_add_uint(d, t, "count", count[k]);
    yyjson_mut_obj_add_uint(d, t, "acc_time_ns", acc[k]);
  }
  yyjson_mut_val *calls = yyjson_mut_obj_add_obj(d, m, "apiCalls");
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(k_minio_all); k++) yyjson_mut_obj_add_uint(d, calls, k_minio_all[k], total[k]);
  if (sv.waiting > 0) yyjson_mut_obj_add_uint(d, m, "totalWaiting", (uint64_t)sv.waiting);
  if (sv.errors_availability) yyjson_mut_obj_add_uint(d, m, "totalErrorsAvailability", sv.errors_availability);
  if (sv.errors_timeout) yyjson_mut_obj_add_uint(d, m, "totalErrorsTimeout", sv.errors_timeout);
}

/* madmin.HealingDisk from a drive's heal tracker, or NULL when it is not
 * being healed. */
static yyjson_mut_val *heal_info(yyjson_mut_doc *d, buckets_drive *drv, const buckets_info_endpoint *ep, long pool,
                                 long set, long disk) {
  if (!drv || drv->remote) return NULL;
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (buckets_drive_read_all(drv, BUCKETS_META_BUCKET, BUCKETS_HEALING_TRACKER, &raw) != BUCKETS_DRIVE_OK) {
    buckets_buf_free(&raw);
    return NULL;
  }
  yyjson_doc *doc = yyjson_read(raw.data, raw.len, 0);
  buckets_buf_free(&raw);
  yyjson_val *t = yyjson_doc_get_root(doc);
  const char *started = yyjson_get_str(yyjson_obj_get(t, "started"));
  const char *bucket = yyjson_get_str(yyjson_obj_get(t, "bucket")), *object = yyjson_get_str(yyjson_obj_get(t, "object"));
  yyjson_mut_val *h = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, h, "id", drv->drive_id);
  yyjson_mut_obj_add_str(d, h, "heal_id", "");
  yyjson_mut_obj_add_int(d, h, "pool_index", pool);
  yyjson_mut_obj_add_int(d, h, "set_index", set);
  yyjson_mut_obj_add_int(d, h, "disk_index", disk);
  yyjson_mut_obj_add_strcpy(d, h, "endpoint", ep->endpoint);
  yyjson_mut_obj_add_strcpy(d, h, "path", ep->path);
  yyjson_mut_obj_add_strcpy(d, h, "started", started ? started : "0001-01-01T00:00:00Z");
  yyjson_mut_obj_add_strcpy(d, h, "last_update", started ? started : "0001-01-01T00:00:00Z");
  yyjson_mut_obj_add_uint(d, h, "retry_attempts", 0);
  yyjson_mut_obj_add_uint(d, h, "objects_total_count", 0);
  yyjson_mut_obj_add_uint(d, h, "objects_total_size", 0);
  uint64_t healed = yyjson_get_uint(yyjson_obj_get(t, "healed")), failed = yyjson_get_uint(yyjson_obj_get(t, "failed"));
  yyjson_mut_obj_add_uint(d, h, "items_healed", healed);
  yyjson_mut_obj_add_uint(d, h, "items_failed", failed);
  yyjson_mut_obj_add_uint(d, h, "items_skipped", 0);
  yyjson_mut_obj_add_uint(d, h, "bytes_done", 0);
  yyjson_mut_obj_add_uint(d, h, "bytes_failed", 0);
  yyjson_mut_obj_add_uint(d, h, "bytes_skipped", 0);
  yyjson_mut_obj_add_uint(d, h, "objects_healed", healed);
  yyjson_mut_obj_add_uint(d, h, "objects_failed", failed);
  yyjson_mut_obj_add_strcpy(d, h, "current_bucket", bucket ? bucket : "");
  yyjson_mut_obj_add_strcpy(d, h, "current_object", object ? object : "");
  yyjson_mut_obj_add_null(d, h, "queued_buckets");
  yyjson_mut_obj_add_null(d, h, "healed_buckets");
  yyjson_mut_obj_add_bool(d, h, "finished", false);
  yyjson_doc_free(doc);
  return h;
}

static void add_drive(yyjson_mut_doc *d, yyjson_mut_val *arr, const buckets_objlayer *L, const buckets_info_endpoint *ep,
                      bool probe) {
  yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
  yyjson_mut_obj_add_strcpy(d, o, "endpoint", ep->endpoint);
  yyjson_mut_obj_add_strcpy(d, o, "path", ep->path);
  long slot = slot_of(L, ep);
  buckets_drive *drv = slot >= 0 ? L->all[slot] : NULL;
  long pool = -1, set = -1, disk = -1;
  if (slot >= 0) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, (size_t)slot, &pl);
    pool = (long)pl.pool;
    set = (long)pl.set;
    disk = (long)(((size_t)slot - pl.pool_first) % pl.set_size);
  }
  struct statvfs sv;
  bool ok = probe && slot >= 0 && statvfs(ep->path, &sv) == 0;
  yyjson_mut_val *hi = ok ? heal_info(d, drv, ep, pool, set, disk) : NULL;
  if (hi) yyjson_mut_obj_add_bool(d, o, "healing", true);
  yyjson_mut_obj_add_str(d, o, "state", ok ? "ok" : "offline");
  if (slot >= 0 && *drv->drive_id) yyjson_mut_obj_add_strcpy(d, o, "uuid", drv->drive_id);
  yyjson_mut_obj_add_uint(d, o, "major", 0);
  yyjson_mut_obj_add_uint(d, o, "minor", 0);
  if (ok) {
    uint64_t total = (uint64_t)sv.f_blocks * sv.f_frsize, free_b = (uint64_t)sv.f_bfree * sv.f_frsize;
    uint64_t avail = (uint64_t)sv.f_bavail * sv.f_frsize;
    yyjson_mut_obj_add_uint(d, o, "totalspace", total);
    yyjson_mut_obj_add_uint(d, o, "usedspace", total - free_b);
    yyjson_mut_obj_add_uint(d, o, "availspace", avail);
    add_drive_metrics(d, o, drv);
    if (hi) yyjson_mut_obj_add_val(d, o, "heal_info", hi);
    yyjson_mut_obj_add_uint(d, o, "used_inodes", (uint64_t)(sv.f_files - sv.f_ffree));
    yyjson_mut_obj_add_uint(d, o, "free_inodes", (uint64_t)sv.f_ffree);
  } else {
    yyjson_mut_obj_add_uint(d, o, "used_inodes", 0);
  }
  if (ep->local) yyjson_mut_obj_add_bool(d, o, "local", true);
  yyjson_mut_obj_add_int(d, o, "pool_index", pool);
  yyjson_mut_obj_add_int(d, o, "set_index", set);
  yyjson_mut_obj_add_int(d, o, "disk_index", disk);
}

static yyjson_mut_val *server_props(yyjson_mut_doc *d, buckets_s3_server *s, const char *node, bool online) {
  const buckets_cluster_info *ci = s->cluster;
  buckets_objlayer *L = s->layer;
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_str(d, o, "state", online ? "online" : "offline");
  yyjson_mut_obj_add_strcpy(d, o, "endpoint", node);
  if (online) {
    yyjson_mut_obj_add_int(d, o, "uptime", (int64_t)(time(NULL) - ci->started));
    yyjson_mut_obj_add_str(d, o, "version", BUCKETS_VERSION);
    yyjson_mut_obj_add_str(d, o, "commitID", "");
  }
  yyjson_mut_val *net = yyjson_mut_obj_add_obj(d, o, "network");
  for (size_t i = 0; i < ci->nnodes; i++) {
    bool up = strcmp(ci->nodes[i], node) == 0 ? online : online && buckets_peer_node_online(s->peers, ci->nodes[i]);
    yyjson_mut_obj_add_str(d, net, ci->nodes[i], up ? "online" : "offline");
  }
  yyjson_mut_val *drives = yyjson_mut_obj_add_arr(d, o, "drives");
  size_t pools[64], npools = 0;
  for (size_t i = 0; i < ci->neps; i++) {
    const buckets_info_endpoint *ep = &ci->eps[i];
    if (strcmp(ep->node, node) != 0) continue;
    add_drive(d, drives, L, ep, online);
    bool seen = false;
    for (size_t k = 0; k < npools; k++) seen |= pools[k] == ep->pool;
    if (!seen && npools < 64) pools[npools++] = ep->pool;
  }
  if (npools == 1) yyjson_mut_obj_add_int(d, o, "poolNumber", (int64_t)pools[0] + 1);
  yyjson_mut_val *pn = yyjson_mut_obj_add_arr(d, o, "poolNumbers");
  for (size_t k = 0; k < npools; k++) yyjson_mut_arr_add_int(d, pn, (int64_t)pools[k] + 1);
  yyjson_mut_val *mem = yyjson_mut_obj_add_obj(d, o, "mem_stats");
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#ifdef __APPLE__
  uint64_t rss = (uint64_t)ru.ru_maxrss;
#else
  uint64_t rss = (uint64_t)ru.ru_maxrss * 1024;
#endif
  yyjson_mut_obj_add_uint(d, mem, "Alloc", online ? rss : 0);
  yyjson_mut_obj_add_uint(d, mem, "TotalAlloc", online ? rss : 0);
  yyjson_mut_obj_add_uint(d, mem, "Mallocs", 0);
  yyjson_mut_obj_add_uint(d, mem, "Frees", 0);
  yyjson_mut_obj_add_uint(d, mem, "HeapAlloc", online ? rss : 0);
  if (online) {
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    yyjson_mut_obj_add_int(d, o, "go_max_procs", ncpu); /* the worker threads' scale */
    yyjson_mut_obj_add_int(d, o, "num_cpu", ncpu);
#ifdef __VERSION__
    yyjson_mut_obj_add_str(d, o, "runtime_version", "C17 " __VERSION__);
#endif
    /* the MINIO and BUCKETS variables, credentials redacted */
    yyjson_mut_val *env = yyjson_mut_obj_add_obj(d, o, "minio_env_vars");
    static const char *const sensitive[] = {"ACCESS_KEY", "SECRET_KEY", "ROOT_USER", "ROOT_PASSWORD", "SUBNET_API_KEY",
                                            "KMS_SECRET_KEY"};
    for (char **e = environ; e && *e; e++) {
      const char *v = *e;
      const char *name = strncmp(v, "_MINIO", 6) == 0 ? v + 7 : strncmp(v, "MINIO_", 6) == 0 ? v + 6
                         : strncmp(v, "BUCKETS_", 8) == 0 ? v + 8 : NULL;
      if (!name) continue;
      const char *eq = strchr(v, '=');
      if (!eq) continue;
      char key[256];
      snprintf(key, sizeof(key), "%.*s", (int)(eq - v), v);
      char lower[256];
      size_t kl = strlen(key);
      for (size_t i = 0; i <= kl; i++) lower[i] = (char)tolower((unsigned char)key[i]);
      bool hide = strstr(lower, "password") || (kl >= 3 && strcmp(lower + kl - 3, "key") == 0);
      for (size_t i = 0; i < BUCKETS_ARRAY_LEN(sensitive) && !hide; i++)
        hide = strncmp(name, sensitive[i], strlen(sensitive[i])) == 0 && name[strlen(sensitive[i])] == '=';
      yyjson_mut_obj_add(env, yyjson_mut_strcpy(d, key), yyjson_mut_strcpy(d, hide ? "*** EXISTS, REDACTED ***" : eq + 1));
    }
  }
  yyjson_mut_obj_add_str(d, o, "edition", ""); /* MinIO leaves it empty */
  yyjson_mut_obj_add_bool(d, o, "is_leader", false);
  yyjson_mut_obj_add_bool(d, o, "ilm_expiry_in_progress", false);
  return o;
}

char *buckets_admin_local_server_json(buckets_s3_server *s) {
  if (!s->cluster) return buckets_xstrdup("{}");
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, server_props(d, s, s->cluster->self, true));
  char *json = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return json;
}

void buckets_admin_server_info(s3_ctx *c) {
  buckets_s3_server *s = c->s;
  const buckets_cluster_info *ci = s->cluster;
  buckets_objlayer *L = s->layer;
  if (!ci) {
    buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "mode", L ? "online" : "initializing");
  if (*s->region) yyjson_mut_obj_add_str(d, root, "region", s->region);
  /* sqsARN: the notification targets */
  buckets_notifier_target_info *tinfo = NULL;
  size_t ntinfo = s->notifier ? buckets_notifier_target_info_get(s->notifier, s->region, true, &tinfo) : 0;
  if (ntinfo) {
    yyjson_mut_val *arns = yyjson_mut_obj_add_arr(d, root, "sqsARN");
    for (size_t i = 0; i < ntinfo; i++) yyjson_mut_arr_add_strcpy(d, arns, tinfo[i].arn);
  }
  if (L) yyjson_mut_obj_add_str(d, root, "deploymentID", L->deployment_id_str);

  /* Servers: the peers' own reports (or offline stand-ins), then ours. */
  yyjson_mut_val *servers = yyjson_mut_arr(d);
  size_t np = 0;
  buckets_peer_info *peers = buckets_peer_server_info(s->peers, &np);
  yyjson_doc **parsed = buckets_xcalloc(np ? np : 1, sizeof(*parsed));
  for (size_t i = 0; i < np; i++) {
    parsed[i] = peers[i].json ? yyjson_read(peers[i].json, strlen(peers[i].json), 0) : NULL;
    if (parsed[i]) yyjson_mut_arr_append(servers, yyjson_val_mut_copy(d, yyjson_doc_get_root(parsed[i])));
    else yyjson_mut_arr_append(servers, server_props(d, s, peers[i].node, false));
  }
  yyjson_mut_arr_append(servers, server_props(d, s, ci->self, true));
  /* Drive metrics only when asked for (madmin.WithDriveMetrics). */
  const char *mq = buckets_query_get(&c->q, "metrics");
  if (!mq || strcmp(mq, "true") != 0) {
    size_t si, smax, j, jmax;
    yyjson_mut_val *sv0, *dv;
    yyjson_mut_arr_foreach(servers, si, smax, sv0) {
      yyjson_mut_arr_foreach(yyjson_mut_obj_get(sv0, "drives"), j, jmax, dv) {
        if (!yyjson_mut_obj_get(dv, "metrics")) continue;
        yyjson_mut_obj_replace(dv, yyjson_mut_str(d, "metrics"), yyjson_mut_obj(d));
      }
    }
  }

  /* Buckets, objects, versions and usage: the scanner's data usage
   * (loadDataUsageFromBackend; zeros before its first cycle) */
  buckets_data_usage du;
  memset(&du, 0, sizeof(du));
  bool have_du = false;
  if (L) {
    buckets_buf raw = BUCKETS_BUF_INIT;
    if (buckets_sysconfig_read(L, BUCKETS_USAGE_PATH, &raw, NULL) == BUCKETS_OBJ_OK ||
        buckets_sysconfig_read(L, BUCKETS_USAGE_PATH ".bkp", &raw, NULL) == BUCKETS_OBJ_OK)
      have_du = buckets_data_usage_parse(raw.data, raw.len, &du);
    buckets_buf_free(&raw);
  }
  yyjson_mut_val *b = yyjson_mut_obj_add_obj(d, root, "buckets");
  yyjson_mut_obj_add_uint(d, b, "count", have_du ? du.buckets_count : 0);
  b = yyjson_mut_obj_add_obj(d, root, "objects");
  yyjson_mut_obj_add_uint(d, b, "count", have_du ? du.objects : 0);
  b = yyjson_mut_obj_add_obj(d, root, "versions");
  yyjson_mut_obj_add_uint(d, b, "count", have_du ? du.versions : 0);
  b = yyjson_mut_obj_add_obj(d, root, "deletemarkers");
  yyjson_mut_obj_add_uint(d, b, "count", have_du ? du.delete_markers : 0);
  b = yyjson_mut_obj_add_obj(d, root, "usage");
  yyjson_mut_obj_add_uint(d, b, "size", have_du ? du.total_size : 0);
  yyjson_mut_val *services = yyjson_mut_obj_add_obj(d, root, "services");
  yyjson_mut_obj_add_obj(d, services, "kms"); /* the deprecated field, always there */
  if (s->kms) { /* fetchKMSStatus: the built-in KMS answers here */
    yyjson_mut_val *ks = yyjson_mut_obj_add_arr(d, services, "kmsStatus");
    yyjson_mut_val *k1 = yyjson_mut_arr_add_obj(d, ks);
    char host[256];
    snprintf(host, sizeof(host), "%s", ci->self);
    char *colon = strrchr(host, ':');
    if (colon) *colon = '\0';
    yyjson_mut_obj_add_str(d, k1, "status", "online");
    yyjson_mut_obj_add_strcpy(d, k1, "endpoint", host);
  }
  yyjson_mut_val *ldap = yyjson_mut_obj_add_obj(d, services, "ldap");
  buckets_ldapidp *lp = buckets_s3_ldap(s);
  if (lp) {
    if (buckets_ldapidp_enabled(lp)) yyjson_mut_obj_add_str(d, ldap, "status", "online");
    buckets_ldapidp_release(lp);
  }
  /* fetchLoggerInfo: the logger targets, then the audit ones */
  buckets_logger_target_info *lt = NULL;
  size_t nl = s->logger ? buckets_logger_targets(s->logger, &lt) : 0;
  for (int audit = 0; audit < 2; audit++) {
    yyjson_mut_val *arr = NULL;
    for (size_t i = 0; i < nl; i++) {
      if (lt[i].audit != (audit == 1) || !*lt[i].endpoint) continue;
      if (!arr) arr = yyjson_mut_obj_add_arr(d, services, audit ? "audit" : "logger");
      yyjson_mut_val *st = yyjson_mut_obj(d);
      yyjson_mut_obj_add_str(d, st, "status", lt[i].st.online ? "online" : "offline");
      yyjson_mut_obj_add(yyjson_mut_arr_add_obj(d, arr), yyjson_mut_strcpy(d, lt[i].name), st);
    }
  }
  free(lt);
  /* notifications: [{"<type>": [{"<id>": {"status": "online"}}, ...]}, ...] (fetchLambdaInfo) */
  if (ntinfo) {
    yyjson_mut_val *notif = yyjson_mut_obj_add_arr(d, services, "notifications");
    for (size_t i = 0; i < ntinfo; i++) {
      /* arn:minio:sqs:<region>:<id>:<type> */
      char *type = strrchr(tinfo[i].arn, ':');
      if (!type) continue;
      char *id_end = type, *id = id_end - 1;
      while (id > tinfo[i].arn && *(id - 1) != ':') id--;
      char tid[256];
      snprintf(tid, sizeof(tid), "%.*s", (int)(id_end - id), id);
      yyjson_mut_val *group = NULL;
      size_t gi, gmax;
      yyjson_mut_val *gv;
      yyjson_mut_arr_foreach(notif, gi, gmax, gv) {
        if (yyjson_mut_obj_get(gv, type + 1)) group = yyjson_mut_obj_get(gv, type + 1);
      }
      if (!group) {
        group = yyjson_mut_arr(d);
        yyjson_mut_obj_add(yyjson_mut_arr_add_obj(d, notif), yyjson_mut_strcpy(d, type + 1), group);
      }
      yyjson_mut_val *st = yyjson_mut_obj(d);
      yyjson_mut_obj_add_str(d, st, "status", tinfo[i].st.online ? "online" : "offline");
      yyjson_mut_val *entry = yyjson_mut_arr_add_obj(d, group);
      yyjson_mut_obj_add(entry, yyjson_mut_strcpy(d, tid), st);
    }
  }
  free(tinfo);

  /* Backend: drives by state, and each pool's shape. */
  size_t online = 0, offline = 0;
  yyjson_mut_val *pools = yyjson_mut_obj(d);
  size_t it, max;
  yyjson_mut_val *sv;
  yyjson_mut_arr_foreach(servers, it, max, sv) {
    yyjson_mut_val *drives = yyjson_mut_obj_get(sv, "drives");
    size_t j, jmax;
    yyjson_mut_val *dv;
    yyjson_mut_arr_foreach(drives, j, jmax, dv) {
      const char *st = yyjson_mut_get_str(yyjson_mut_obj_get(dv, "state"));
      bool up = st && strcmp(st, "ok") == 0;
      up ? online++ : offline++;
      long long pool = int_of(yyjson_mut_obj_get(dv, "pool_index"));
      long long set = int_of(yyjson_mut_obj_get(dv, "set_index"));
      if (pool < 0 || set < 0) continue;
      char pk[24], sk[24];
      snprintf(pk, sizeof(pk), "%lld", pool);
      snprintf(sk, sizeof(sk), "%lld", set);
      yyjson_mut_val *pm = yyjson_mut_obj_get(pools, pk);
      if (!pm) {
        pm = yyjson_mut_obj(d);
        yyjson_mut_obj_add(pools, yyjson_mut_strcpy(d, pk), pm);
      }
      yyjson_mut_val *sm = yyjson_mut_obj_get(pm, sk);
      if (!sm) {
        sm = yyjson_mut_obj(d);
        yyjson_mut_obj_add(pm, yyjson_mut_strcpy(d, sk), sm);
        yyjson_mut_obj_add_int(d, sm, "id", set);
        yyjson_mut_obj_add_uint(d, sm, "rawUsage", 0);
        yyjson_mut_obj_add_uint(d, sm, "rawCapacity", 0);
        /* the set's data usage: with one set, the cluster's (no per-set cache is kept) */
        buckets_drive_place pl0;
        if (L) buckets_objlayer_place(L, 0, &pl0);
        bool one_set = L && L->npools == 1 && pl0.nsets == 1 && have_du;
        yyjson_mut_obj_add_uint(d, sm, "usage", one_set ? du.total_size : 0);
        yyjson_mut_obj_add_uint(d, sm, "objectsCount", one_set ? du.objects : 0);
        yyjson_mut_obj_add_uint(d, sm, "versionsCount", one_set ? du.versions : 0);
        yyjson_mut_obj_add_uint(d, sm, "deleteMarkersCount", one_set ? du.delete_markers : 0);
        yyjson_mut_obj_add_int(d, sm, "healDisks", 0);
      }
      uint64_t used = yyjson_mut_get_uint(yyjson_mut_obj_get(dv, "usedspace"));
      uint64_t total = yyjson_mut_get_uint(yyjson_mut_obj_get(dv, "totalspace"));
      yyjson_mut_val *ru = yyjson_mut_obj_get(sm, "rawUsage"), *rc = yyjson_mut_obj_get(sm, "rawCapacity");
      yyjson_mut_set_uint(ru, yyjson_mut_get_uint(ru) + used);
      yyjson_mut_set_uint(rc, yyjson_mut_get_uint(rc) + total);
    }
  }
  yyjson_mut_val *be = yyjson_mut_obj_add_obj(d, root, "backend");
  yyjson_mut_obj_add_str(d, be, "backendType", "Erasure");
  yyjson_mut_obj_add_uint(d, be, "onlineDisks", online);
  yyjson_mut_obj_add_uint(d, be, "offlineDisks", offline);
  int parity = 0;
  size_t nsets[64], dps[64], npl = 0;
  for (size_t p = 0, first = 0; L && p < L->npools && npl < 64; p++, npl++) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, first, &pl);
    nsets[npl] = pl.nsets;
    dps[npl] = pl.set_size;
    if (p == 0) parity = pl.parity;
    first += pl.pool_drives;
  }
  /* madmin.ErasureBackend's order */
  yyjson_mut_obj_add_int(d, be, "standardSCParity", parity);
  yyjson_mut_obj_add_int(d, be, "rrSCParity", parity > 1 ? 1 : parity);
  yyjson_mut_val *sets = yyjson_mut_obj_add_arr(d, be, "totalSets");
  yyjson_mut_val *dpsv = yyjson_mut_obj_add_arr(d, be, "totalDrivesPerSet");
  for (size_t p = 0; p < npl; p++) {
    yyjson_mut_arr_add_uint(d, sets, nsets[p]);
    yyjson_mut_arr_add_uint(d, dpsv, dps[p]);
  }
  yyjson_mut_obj_add_val(d, root, "servers", servers);
  yyjson_mut_obj_add_val(d, root, "pools", pools);

  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, json, len);
  free(json);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  yyjson_mut_doc_free(d);
  for (size_t i = 0; i < np; i++) yyjson_doc_free(parsed[i]);
  free(parsed);
  buckets_peer_info_free(peers, np);
  if (have_du) buckets_data_usage_free(&du);
}

/* The drives' order within a node: LocalStorageInfo walks pools, sets and
 * their drives. */
static int drive_cmp(const void *a, const void *b) {
  yyjson_mut_val *x = *(yyjson_mut_val *const *)a, *y = *(yyjson_mut_val *const *)b;
  static const char *const keys[] = {"pool_index", "set_index", "disk_index"};
  for (size_t k = 0; k < 3; k++) {
    long long p = int_of(yyjson_mut_obj_get(x, keys[k])), q = int_of(yyjson_mut_obj_get(y, keys[k]));
    if (p != q) return p < q ? -1 : 1;
  }
  return 0;
}

/* Every drive in the cluster, each node's in order: the peers' reports,
 * then this node's (NotificationSys.StorageInfo) -- or this node's first
 * (BgHealState.Merge onto the local state). */
static yyjson_mut_val *all_drives(yyjson_mut_doc *d, buckets_s3_server *s, bool local_first) {
  const buckets_cluster_info *ci = s->cluster;
  yyjson_mut_val *out = yyjson_mut_arr(d);
  size_t np = 0;
  buckets_peer_info *peers = buckets_peer_server_info(s->peers, &np);
  for (size_t k = 0; k <= np; k++) {
    size_t i = local_first ? (k == 0 ? np : k - 1) : k;
    yyjson_mut_val *props = NULL;
    yyjson_doc *parsed = NULL;
    if (i == np) props = server_props(d, s, ci->self, true);
    else if (peers[i].json && (parsed = yyjson_read(peers[i].json, strlen(peers[i].json), 0)))
      props = yyjson_val_mut_copy(d, yyjson_doc_get_root(parsed));
    else props = server_props(d, s, peers[i].node, false);
    yyjson_doc_free(parsed);
    yyjson_mut_val *drives = yyjson_mut_obj_get(props, "drives");
    size_t n = yyjson_mut_arr_size(drives), j, jmax;
    yyjson_mut_val **v = buckets_xcalloc(n ? n : 1, sizeof(*v)), *dv;
    yyjson_mut_arr_foreach(drives, j, jmax, dv) v[j] = dv;
    qsort(v, n, sizeof(*v), drive_cmp);
    yyjson_mut_arr_clear(drives);
    for (j = 0; j < n; j++) yyjson_mut_arr_append(out, v[j]);
    free(v);
  }
  buckets_peer_info_free(peers, np);
  return out;
}

/* madmin.BackendInfo (erasureServerPools.BackendInfo). */
static void add_backend(yyjson_mut_doc *d, yyjson_mut_val *root, const buckets_objlayer *L) {
  yyjson_mut_val *be = yyjson_mut_obj_add_obj(d, root, "Backend");
  yyjson_mut_obj_add_int(d, be, "Type", 2); /* madmin.Erasure */
  yyjson_mut_obj_add_bool(d, be, "GatewayOnline", false);
  yyjson_mut_obj_add_null(d, be, "OnlineDisks");
  yyjson_mut_obj_add_null(d, be, "OfflineDisks");
  int parity = -1, rrs = -1;
  size_t dps[64], sets[64], np = 0;
  for (size_t p = 0, first = 0; L && p < L->npools && np < 64; p++, np++) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, first, &pl);
    dps[np] = pl.set_size;
    sets[np] = pl.nsets;
    if (p == 0) parity = pl.parity;
    first += pl.pool_drives;
  }
  rrs = parity > 1 ? 1 : parity;
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, be, "StandardSCData");
  for (size_t p = 0; p < np; p++) yyjson_mut_arr_add_int(d, a, (int64_t)dps[p] - parity);
  yyjson_mut_obj_add_null(d, be, "StandardSCParities");
  a = yyjson_mut_obj_add_arr(d, be, "RRSCData");
  for (size_t p = 0; p < np; p++) yyjson_mut_arr_add_int(d, a, (int64_t)dps[p] - rrs);
  yyjson_mut_obj_add_null(d, be, "RRSCParities");
  a = yyjson_mut_obj_add_arr(d, be, "TotalSets");
  for (size_t p = 0; p < np; p++) yyjson_mut_arr_add_uint(d, a, sets[p]);
  a = yyjson_mut_obj_add_arr(d, be, "DrivesPerSet");
  for (size_t p = 0; p < np; p++) yyjson_mut_arr_add_uint(d, a, dps[p]);
  yyjson_mut_obj_add_int(d, be, "StandardSCParity", parity);
  yyjson_mut_obj_add_int(d, be, "RRSCParity", rrs);
}

static void send_json(s3_ctx *c, yyjson_mut_doc *d) {
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, json, len);
  free(json);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

void buckets_admin_storage_info(s3_ctx *c) {
  buckets_s3_server *s = c->s;
  if (!s->cluster || !s->layer) {
    buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_val(d, root, "Disks", all_drives(d, s, false));
  add_backend(d, root, s->layer);
  send_json(c, d);
  yyjson_mut_doc_free(d);
}

/* madmin.BgHealState: this node's sets and every peer's (their drives are
 * in the peers' reports), the drives being healed, the parity per storage
 * class. */
void buckets_admin_background_heal_status(s3_ctx *c) {
  buckets_s3_server *s = c->s;
  if (!s->cluster || !s->layer) {
    buckets_admin_error(c, BUCKETS_ERR_SERVER_NOT_INITIALIZED);
    return;
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_val *drives = all_drives(d, s, true);
  yyjson_mut_val *offline = yyjson_mut_arr(d), *heal_disks = yyjson_mut_arr(d);
  /* offline peers answer nothing: their endpoints are listed instead */
  size_t np = 0;
  buckets_peer_info *peers = buckets_peer_server_info(s->peers, &np);
  for (size_t i = 0; i < np; i++) {
    if (peers[i].json) continue;
    char ep[300];
    snprintf(ep, sizeof(ep), "%s://%s", s->cluster->secure ? "https" : "http", peers[i].node);
    yyjson_mut_arr_add_strcpy(d, offline, ep);
  }
  buckets_peer_info_free(peers, np);
  yyjson_mut_obj_add_val(d, root, "offline_nodes", yyjson_mut_arr_size(offline) ? offline : yyjson_mut_null(d));
  buckets_healer *h = atomic_load(&s->healer);
  buckets_healer_stats hs = {0};
  if (h) buckets_healer_stats_get(h, &hs);
  yyjson_mut_obj_add_int(d, root, "ScannedItemsCount", (int64_t)(hs.healed + hs.failed + hs.drive_objects_healed));
  yyjson_mut_val *sets = yyjson_mut_arr(d);
  size_t j, jmax;
  yyjson_mut_val *dv;
  /* by "pool-set" id, in id order (a string sort, as MinIO's) */
  char (*ids)[48] = NULL;
  size_t nids = 0;
  yyjson_mut_arr_foreach(drives, j, jmax, dv) {
    long long p = int_of(yyjson_mut_obj_get(dv, "pool_index")), st = int_of(yyjson_mut_obj_get(dv, "set_index"));
    if (p < 0 || st < 0) continue;
    char id[48];
    snprintf(id, sizeof(id), "%lld-%lld", p, st);
    bool seen = false;
    for (size_t k = 0; k < nids && !seen; k++) seen = strcmp(ids[k], id) == 0;
    if (seen) continue;
    ids = buckets_xrealloc(ids, (nids + 1) * sizeof(*ids));
    memcpy(ids[nids++], id, sizeof(id));
  }
  qsort(ids, nids, sizeof(*ids), (int (*)(const void *, const void *))strcmp);
  for (size_t k = 0; k < nids; k++) {
    long long p, st;
    sscanf(ids[k], "%lld-%lld", &p, &st);
    yyjson_mut_val *so = yyjson_mut_arr_add_obj(d, sets);
    yyjson_mut_obj_add_strcpy(d, so, "id", ids[k]);
    yyjson_mut_obj_add_int(d, so, "pool_index", p);
    yyjson_mut_obj_add_int(d, so, "set_index", st);
    yyjson_mut_val *hstat = yyjson_mut_obj_add_str(d, so, "heal_status", "") ? yyjson_mut_obj_get(so, "heal_status") : NULL;
    yyjson_mut_val *hprio = yyjson_mut_obj_add_str(d, so, "heal_priority", "") ? yyjson_mut_obj_get(so, "heal_priority") : NULL;
    yyjson_mut_obj_add_int(d, so, "total_objects", 0);
    yyjson_mut_val *sd = yyjson_mut_obj_add_arr(d, so, "disks");
    yyjson_mut_arr_foreach(drives, j, jmax, dv) {
      if (int_of(yyjson_mut_obj_get(dv, "pool_index")) != p || int_of(yyjson_mut_obj_get(dv, "set_index")) != st) continue;
      if (yyjson_mut_get_bool(yyjson_mut_obj_get(dv, "healing"))) {
        yyjson_mut_set_str(hstat, "Healing");
        yyjson_mut_set_str(hprio, "high");
        /* only this node's (the peers' lists are not merged) */
        if (yyjson_mut_get_bool(yyjson_mut_obj_get(dv, "local")))
          yyjson_mut_arr_add_strcpy(d, heal_disks, yyjson_mut_get_str(yyjson_mut_obj_get(dv, "endpoint")));
      }
      yyjson_mut_arr_append(sd, yyjson_mut_val_mut_copy(d, dv));
    }
  }
  free(ids);
  yyjson_mut_obj_add_val(d, root, "HealDisks", yyjson_mut_arr_size(heal_disks) ? heal_disks : yyjson_mut_null(d));
  yyjson_mut_obj_add_val(d, root, "sets", sets);
  /* Merge makes the map when there are peers */
  if (s->cluster->distributed) yyjson_mut_obj_add_obj(d, root, "mrf");
  else yyjson_mut_obj_add_null(d, root, "mrf");
  yyjson_mut_val *scp = yyjson_mut_obj_add_obj(d, root, "sc_parity");
  yyjson_mut_val *be = yyjson_mut_obj(d);
  add_backend(d, be, s->layer);
  yyjson_mut_val *b = yyjson_mut_obj_get(be, "Backend");
  yyjson_mut_obj_add_int(d, scp, "REDUCED_REDUNDANCY", int_of(yyjson_mut_obj_get(b, "RRSCParity")));
  yyjson_mut_obj_add_int(d, scp, "STANDARD", int_of(yyjson_mut_obj_get(b, "StandardSCParity")));
  send_json(c, d);
  /* json.NewEncoder(w).Encode: a newline, and no Content-Type (Go sniffs text) */
  buckets_buf_append_char(&c->resp->body, '\n');
  buckets_http_resp_header_set(c->resp, "Content-Type", "text/plain; charset=utf-8");
  yyjson_mut_doc_free(d);
}
