/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin top locks and mc admin unlock (MinIO's TopLocksHandler and
 * ForceUnlockHandler, registered only in a distributed setup): every node's
 * lock server is asked for its holders, which are merged by lock request;
 * a forced unlock drops the resources' holders on every node. */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "core/timefmt.h"
#include "dist/dsync.h"
#include "dist/internode.h"
#include "dist/peer.h"

typedef struct {
  char *resource, *uid, *owner, *source;
  bool writer;
  int64_t ts;
  int quorum;
  char **servers;
  size_t nservers;
} lock_entry;

typedef struct {
  lock_entry *v;
  size_t n;
} lock_entries;

/* lriToLockEntry, merged by "<resource>/<uid>" (topLockEntries). */
static void merge(lock_entries *all, const char *json, size_t len, const char *addr) {
  yyjson_doc *doc = yyjson_read(json, len, 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  size_t i, max;
  yyjson_val *k, *arr;
  yyjson_obj_foreach(root, i, max, k, arr) {
    const char *res = yyjson_get_str(k);
    size_t j, jmax;
    yyjson_val *h;
    yyjson_arr_foreach(arr, j, jmax, h) {
      const char *uid = yyjson_get_str(yyjson_obj_get(h, "uid"));
      if (!res || !uid) continue;
      lock_entry *e = NULL;
      for (size_t x = 0; x < all->n && !e; x++)
        if (strcmp(all->v[x].resource, res) == 0 && strcmp(all->v[x].uid, uid) == 0) e = &all->v[x];
      if (!e) {
        all->v = buckets_xrealloc(all->v, (all->n + 1) * sizeof(*all->v));
        e = &all->v[all->n++];
        memset(e, 0, sizeof(*e));
        const char *owner = yyjson_get_str(yyjson_obj_get(h, "owner"));
        const char *source = yyjson_get_str(yyjson_obj_get(h, "source"));
        e->resource = buckets_xstrdup(res);
        e->uid = buckets_xstrdup(uid);
        e->owner = buckets_xstrdup(owner ? owner : "");
        e->source = buckets_xstrdup(source ? source : "");
        e->writer = yyjson_get_bool(yyjson_obj_get(h, "writer"));
        e->ts = yyjson_get_sint(yyjson_obj_get(h, "ts"));
        e->quorum = (int)yyjson_get_sint(yyjson_obj_get(h, "quorum"));
      }
      e->servers = buckets_xrealloc(e->servers, (e->nservers + 1) * sizeof(char *));
      e->servers[e->nservers++] = buckets_xstrdup(addr);
    }
  }
  yyjson_doc_free(doc);
}

static int by_time(const void *a, const void *b) {
  const lock_entry *x = a, *y = b;
  return x->ts < y->ts ? -1 : x->ts > y->ts;
}

static void entries_free(lock_entries *all) {
  for (size_t i = 0; i < all->n; i++) {
    lock_entry *e = &all->v[i];
    free(e->resource);
    free(e->uid);
    free(e->owner);
    free(e->source);
    for (size_t k = 0; k < e->nservers; k++) free(e->servers[k]);
    free(e->servers);
  }
  free(all->v);
}

/* A peer's "host:port" as its client knows it. */
static void peer_node(buckets_http_client *pc, char *out, size_t cap) {
  snprintf(out, cap, "%s:%d", buckets_http_client_host(pc), buckets_http_client_port(pc));
}

void buckets_admin_top_locks(s3_ctx *c) {
  buckets_s3_server *s = c->s;
  if (!s->cluster || !s->cluster->distributed || !s->lock_server) {
    buckets_admin_unsupported(c);
    return;
  }
  if (!buckets_admin_authorize(c, "admin:TopLocksInfo")) return;
  long count = 10;
  const char *cs = buckets_query_get(&c->q, "count");
  if (cs && *cs) {
    /* strconv.Atoi: an optional sign, then digits */
    const char *dg = *cs == '+' || *cs == '-' ? cs + 1 : cs;
    bool syntax = *dg && strspn(dg, "0123456789") == strlen(dg);
    errno = 0;
    long long v = syntax ? strtoll(cs, NULL, 10) : 0;
    if (!syntax || errno == ERANGE) {
      char msg[512];
      snprintf(msg, sizeof(msg),
               "We encountered an internal error, please try again. (strconv.Atoi: parsing \"%s\": %s)", cs,
               syntax ? "value out of range" : "invalid syntax");
      buckets_admin_custom_error(c, 500, "InternalError", msg);
      return;
    }
    count = (long)v;
  }
  const char *st = buckets_query_get(&c->q, "stale");
  bool stale = st && strcmp(st, "true") == 0;

  lock_entries all = {0};
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  for (size_t i = 0; i < np; i++) {
    char node[300];
    peer_node(pcs[i], node, sizeof(node));
    buckets_buf body = BUCKETS_BUF_INIT;
    int status = 0;
    if (buckets_peer_call(s->peers, node, BUCKETS_INTERNODE_PREFIX "lock/dump", &status, &body) &&
        status == 200)
      merge(&all, body.data ? body.data : "{}", body.len, node);
    buckets_buf_free(&body);
  }
  /* this node, under the name the request used (getHostName) */
  buckets_str host = buckets_http_header_get(c->req, "Host");
  char self[300];
  snprintf(self, sizeof(self), "%.*s", host.p ? (int)host.n : 0, host.p ? host.p : "");
  buckets_buf local = BUCKETS_BUF_INIT;
  buckets_lock_server_dump(s->lock_server, &local);
  merge(&all, local.data, local.len, self);
  buckets_buf_free(&local);

  /* not stale: held by at least a quorum of the servers */
  size_t k = 0;
  for (size_t i = 0; i < all.n; i++) {
    if (stale || (int)all.v[i].nservers >= all.v[i].quorum) {
      lock_entry tmp = all.v[k];
      all.v[k++] = all.v[i];
      all.v[i] = tmp;
    }
  }
  qsort(all.v, k, sizeof(*all.v), by_time);
  size_t shown = count > 0 && (size_t)count < k ? (size_t)count : k;

  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  int64_t now_ns = (int64_t)now.tv_sec * 1000000000LL + now.tv_nsec;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *arr = shown ? yyjson_mut_arr(d) : yyjson_mut_null(d);
  yyjson_mut_doc_set_root(d, arr);
  for (size_t i = 0; i < shown; i++) {
    lock_entry *e = &all.v[i];
    yyjson_mut_val *o = yyjson_mut_arr_add_obj(d, arr);
    char t[64];
    buckets_time_rfc3339_nano((long long)(e->ts / 1000000000LL), (long)(e->ts % 1000000000LL), t);
    yyjson_mut_obj_add_strcpy(d, o, "time", t);
    yyjson_mut_obj_add_int(d, o, "elapsed", now_ns - e->ts);
    yyjson_mut_obj_add_strcpy(d, o, "resource", e->resource);
    yyjson_mut_obj_add_str(d, o, "type", e->writer ? "WRITE" : "READ");
    yyjson_mut_obj_add_strcpy(d, o, "source", e->source);
    yyjson_mut_val *sl = yyjson_mut_obj_add_arr(d, o, "serverlist");
    for (size_t x = 0; x < e->nservers; x++) yyjson_mut_arr_add_strcpy(d, sl, e->servers[x]);
    yyjson_mut_obj_add_strcpy(d, o, "owner", e->owner);
    yyjson_mut_obj_add_strcpy(d, o, "id", e->uid);
    yyjson_mut_obj_add_int(d, o, "quorum", e->quorum);
  }
  size_t len;
  char *json = yyjson_mut_write(d, 0, &len);
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, json, len);
  free(json);
  yyjson_mut_doc_free(d);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  entries_free(&all);
}

void buckets_admin_force_unlock(s3_ctx *c) {
  buckets_s3_server *s = c->s;
  /* the route wants a paths query (Queries("paths", ...)) */
  if (!s->cluster || !s->cluster->distributed || !s->lock_server || !buckets_query_has(&c->q, "paths")) {
    buckets_admin_unsupported(c);
    return;
  }
  if (!buckets_admin_authorize(c, "admin:ForceUnlock")) return;
  const char *paths = buckets_query_get(&c->q, "paths");
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  for (const char *p = paths ? paths : ""; *p;) {
    const char *comma = strchr(p, ',');
    size_t n = comma ? (size_t)(comma - p) : strlen(p);
    if (n) {
      char *res = buckets_xstrndup(p, n);
      buckets_lock_server_force_unlock(s->lock_server, res);
      for (size_t i = 0; i < np; i++) {
        char node[300];
        peer_node(pcs[i], node, sizeof(node));
        buckets_buf t = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
        buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "lock/force-unlock?res=");
        buckets_url_encode(&t, res, false);
        buckets_buf_append_char(&t, '\0');
        int status;
        buckets_peer_call(s->peers, node, t.data, &status, &body);
        buckets_buf_free(&t);
        buckets_buf_free(&body);
      }
      free(res);
    }
    if (!comma) break;
    p = comma + 1;
  }
  c->resp->status = 200;
}
