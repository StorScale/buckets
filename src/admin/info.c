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
#include <unistd.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "dist/peer.h"
#include "s3/internal.h"

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

static void add_drive(yyjson_mut_doc *d, yyjson_mut_val *arr, const buckets_objlayer *L, const buckets_info_endpoint *ep,
                      bool probe) {
  yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
  yyjson_mut_obj_add_strcpy(d, o, "endpoint", ep->endpoint);
  yyjson_mut_obj_add_strcpy(d, o, "path", ep->path);
  long slot = slot_of(L, ep);
  struct statvfs sv;
  bool ok = probe && slot >= 0 && statvfs(ep->path, &sv) == 0;
  yyjson_mut_obj_add_str(d, o, "state", ok ? "ok" : "offline");
  if (slot >= 0 && *L->all[slot]->drive_id) yyjson_mut_obj_add_strcpy(d, o, "uuid", L->all[slot]->drive_id);
  yyjson_mut_obj_add_uint(d, o, "major", 0);
  yyjson_mut_obj_add_uint(d, o, "minor", 0);
  if (ok) {
    uint64_t total = (uint64_t)sv.f_blocks * sv.f_frsize, free_b = (uint64_t)sv.f_bfree * sv.f_frsize;
    uint64_t avail = (uint64_t)sv.f_bavail * sv.f_frsize;
    yyjson_mut_obj_add_uint(d, o, "totalspace", total);
    yyjson_mut_obj_add_uint(d, o, "usedspace", total - free_b);
    yyjson_mut_obj_add_uint(d, o, "availspace", avail);
    yyjson_mut_obj_add_uint(d, o, "used_inodes", (uint64_t)(sv.f_files - sv.f_ffree));
    yyjson_mut_obj_add_uint(d, o, "free_inodes", (uint64_t)sv.f_ffree);
  } else {
    yyjson_mut_obj_add_uint(d, o, "used_inodes", 0);
  }
  if (ep->local) yyjson_mut_obj_add_bool(d, o, "local", true);
  long pool = -1, set = -1, disk = -1;
  if (slot >= 0) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, (size_t)slot, &pl);
    pool = (long)pl.pool;
    set = (long)pl.set;
    disk = (long)(((size_t)slot - pl.pool_first) % pl.set_size);
  }
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
  yyjson_mut_obj_add_str(d, o, "scheme", ci->secure ? "https" : "http");
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
  if (online) yyjson_mut_obj_add_int(d, o, "num_cpu", sysconf(_SC_NPROCESSORS_ONLN));
  yyjson_mut_obj_add_str(d, o, "edition", "AGPLv3");
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

  /* Buckets (usage and object counts come from the scanner's data usage). */
  size_t nb = 0;
  if (L) {
    buckets_bucket_info *vols;
    size_t n;
    if (buckets_obj_list_buckets(L, &vols, &n) == BUCKETS_OBJ_OK) {
      for (size_t i = 0; i < n; i++) nb += *vols[i].name != '.';
      buckets_bucket_info_free(vols, n);
    }
  }
  yyjson_mut_val *b = yyjson_mut_obj_add_obj(d, root, "buckets");
  yyjson_mut_obj_add_uint(d, b, "count", nb);
  yyjson_mut_obj_add_obj(d, root, "objects");
  yyjson_mut_obj_add_obj(d, root, "versions");
  yyjson_mut_obj_add_obj(d, root, "deletemarkers");
  yyjson_mut_obj_add_obj(d, root, "usage");
  yyjson_mut_val *services = yyjson_mut_obj_add_obj(d, root, "services");
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
        yyjson_mut_obj_add_uint(d, sm, "usage", 0);
        yyjson_mut_obj_add_uint(d, sm, "objectsCount", 0);
        yyjson_mut_obj_add_uint(d, sm, "versionsCount", 0);
        yyjson_mut_obj_add_uint(d, sm, "deleteMarkersCount", 0);
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
  yyjson_mut_val *sets = yyjson_mut_obj_add_arr(d, be, "totalSets");
  yyjson_mut_val *dps = yyjson_mut_obj_add_arr(d, be, "totalDrivesPerSet");
  int parity = 0;
  for (size_t p = 0, first = 0; L && p < L->npools; p++) {
    buckets_drive_place pl;
    buckets_objlayer_place(L, first, &pl);
    yyjson_mut_arr_add_uint(d, sets, pl.nsets);
    yyjson_mut_arr_add_uint(d, dps, pl.set_size);
    if (p == 0) parity = pl.parity;
    first += pl.pool_drives;
  }
  yyjson_mut_obj_add_int(d, be, "standardSCParity", parity);
  yyjson_mut_obj_add_int(d, be, "rrSCParity", parity > 0 ? 1 : 0);
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
}
