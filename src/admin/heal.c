/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* mc admin heal: POST /heal/[bucket[/prefix]]. A request without a client
 * token starts a heal sequence that walks the path in the background (the
 * config prefix, then every bucket, then their objects, one result item per
 * bucket and object version); requests with the token collect the items
 * gathered since the last one. Replaces MinIO's HealHandler and
 * cmd/admin-heal-ops.go (the sequence), healBucketLocal and
 * erasureServerPools.HealObjects. In a cluster the token names the node
 * running the sequence ("<uuid>:<index>"), and other nodes forward status
 * requests to it. */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "bucket/metasys.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "object/object.h"
#include "s3/bucketname.h"
#include "storage/drive.h"

#define MAX_UNCONSUMED 1000                      /* maxUnconsumedHealResultItems */
#define KEEP_ENDED_NS (10LL * 60 * 1000000000LL) /* keepHealSeqStateDuration */

typedef struct {
  bool recursive, dry_run, remove, recreate, update_parity, nolock;
  int scan_mode;
  int pool, set; /* -1: not given */
} heal_settings;

typedef struct heal_seq {
  struct heal_seq *next;
  buckets_s3_server *s;
  char *bucket, *prefix, *path;
  char token[BUCKETS_UUID_STR_LEN + 1];
  char client_addr[64];
  bool force_started;
  heal_settings hs;
  int64_t start_ns;        /* the sequence's creation (the start response) */
  int64_t status_start_ns; /* currentStatus.StartTime: when it began running (0 before) */
  int64_t end_ns;          /* 0 while running */
  const char *summary;
  char *detail;
  buckets_buf items; /* the unconsumed items' JSON, comma separated */
  size_t nitems;
  int64_t last_index; /* of the newest item (or the last one sent) */
  bool stop;
  pthread_t thread;
  bool joined;
} heal_seq;

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER; /* an item was consumed or a sequence ended */
static heal_seq *g_seqs;

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* time.Time as encoding/json writes it (UTC, RFC 3339 with trimmed nanoseconds). */
static void go_time(buckets_buf *b, int64_t ns) {
  if (!ns) {
    buckets_buf_append_c(b, "\"0001-01-01T00:00:00Z\"");
    return;
  }
  char t[64];
  buckets_time_rfc3339_nano((long long)(ns / 1000000000LL), (long)(ns % 1000000000LL), t);
  buckets_buf_appendf(b, "\"%s\"", t);
}

static void jstr(buckets_buf *b, const char *s) { buckets_json_go_string(b, s ? s : "", s ? strlen(s) : 0); }

/* madmin.HealOpts */
static void settings_json(buckets_buf *b, const heal_settings *h) {
  buckets_buf_appendf(b,
                      "{\"recursive\":%s,\"dryRun\":%s,\"remove\":%s,\"recreate\":%s,\"scanMode\":%d,"
                      "\"updateParity\":%s,\"nolock\":%s",
                      h->recursive ? "true" : "false", h->dry_run ? "true" : "false", h->remove ? "true" : "false",
                      h->recreate ? "true" : "false", h->scan_mode, h->update_parity ? "true" : "false",
                      h->nolock ? "true" : "false");
  if (h->pool >= 0) buckets_buf_appendf(b, ",\"pool\":%d", h->pool);
  if (h->set >= 0) buckets_buf_appendf(b, ",\"set\":%d", h->set);
  buckets_buf_append_char(b, '}');
}

/* path.Join as MinIO's pathJoin does it: a trailing slash on the last
 * element is kept, and nothing at all cleans to "." (so a cluster-wide
 * heal never overlaps a bucket's). */
static char *path_join(const char *bucket, const char *prefix) {
  buckets_buf b = BUCKETS_BUF_INIT;
  if (*bucket) buckets_buf_append_c(&b, bucket);
  if (*prefix) {
    if (b.len) buckets_buf_append_char(&b, '/');
    buckets_buf_append_c(&b, prefix);
  }
  buckets_buf_append_char(&b, '\0');
  /* clean: collapse "//" and drop "./" (the prefix was validated already) */
  char *s = b.data, *w = s;
  for (char *r = s; *r; r++) {
    if (*r == '/' && w > s && w[-1] == '/') continue;
    *w++ = *r;
  }
  *w = '\0';
  if (!*s) {
    free(s);
    return buckets_xstrdup(".");
  }
  return s;
}

/* ---- the sequence's items ------------------------------------------------------------------ */

static bool quitting(heal_seq *h) {
  pthread_mutex_lock(&g_mu);
  bool q = h->stop;
  pthread_mutex_unlock(&g_mu);
  return q;
}

/* pushHealResultItem: waits while the client has not collected
 * MAX_UNCONSUMED items. false: the sequence was stopped. */
static bool push_item(heal_seq *h, buckets_buf *item_tail) {
  pthread_mutex_lock(&g_mu);
  while (h->nitems >= MAX_UNCONSUMED && !h->stop) pthread_cond_wait(&g_cv, &g_mu);
  if (h->stop) {
    pthread_mutex_unlock(&g_mu);
    return false;
  }
  h->last_index++;
  if (h->nitems) buckets_buf_append_char(&h->items, ',');
  buckets_buf_appendf(&h->items, "{\"resultId\":%lld,", (long long)h->last_index);
  buckets_buf_append(&h->items, item_tail->data, item_tail->len);
  h->nitems++;
  pthread_mutex_unlock(&g_mu);
  return true;
}

static void drives_json(buckets_buf *b, const char *const *eps, const char *const *states, size_t n) {
  if (!n) {
    buckets_buf_append_c(b, "{\"drives\":null}");
    return;
  }
  buckets_buf_append_c(b, "{\"drives\":[");
  for (size_t i = 0; i < n; i++) {
    buckets_buf_append_c(b, i ? ",{\"uuid\":\"\",\"endpoint\":" : "{\"uuid\":\"\",\"endpoint\":");
    jstr(b, eps[i]);
    buckets_buf_append_c(b, ",\"state\":");
    jstr(b, states[i]);
    buckets_buf_append_char(b, '}');
  }
  buckets_buf_append_c(b, "]}");
}

/* The endpoints in node order (S3PeerSys asks every node, this one
 * included, for its drives' healBucketLocal). */
static size_t node_order(const buckets_cluster_info *ci, const buckets_info_endpoint **out) {
  size_t n = 0;
  for (size_t k = 0; k < (ci->nnodes ? ci->nnodes : 1); k++) {
    const char *node = ci->nnodes ? ci->nodes[k] : ci->self;
    for (size_t i = 0; i < ci->neps; i++)
      if (strcmp(ci->eps[i].node, node) == 0) out[n++] = &ci->eps[i];
  }
  return n;
}

static buckets_drive *drive_at(const buckets_objlayer *L, const buckets_info_endpoint *ep) {
  for (size_t i = 0; L && i < L->nall; i++) {
    const buckets_drive *d = L->all[i];
    if (d && (strcmp(d->root, ep->endpoint) == 0 || (ep->local && strcmp(d->root, ep->path) == 0)))
      return L->all[i];
  }
  return NULL;
}

/* HealBucket (S3PeerSys.HealBucket over each node's healBucketLocal): the
 * bucket's volume on every drive, created where it is missing. */
static bool heal_bucket(heal_seq *h, const char *bucket, const heal_settings *hs) {
  const buckets_cluster_info *ci = h->s->cluster;
  buckets_objlayer *L = h->s->layer;
  const buckets_info_endpoint **eps = buckets_xcalloc(ci->neps ? ci->neps : 1, sizeof(*eps));
  size_t n = node_order(ci, eps);
  const char **names = buckets_xcalloc(n ? n : 1, sizeof(char *));
  const char **before = buckets_xcalloc(n ? n : 1, sizeof(char *)), **after = buckets_xcalloc(n ? n : 1, sizeof(char *));
  bool any_found = false;
  for (size_t i = 0; i < n; i++) {
    names[i] = eps[i]->endpoint;
    buckets_drive *d = drive_at(L, eps[i]);
    before[i] = "ok";
    if (!d) before[i] = "offline";
    else if (strcmp(bucket, BUCKETS_META_BUCKET) != 0) {
      buckets_drive_err e = buckets_drive_stat_vol(d, bucket, NULL);
      if (e == BUCKETS_DRIVE_ERR_NOT_FOUND) before[i] = "missing";
      else if (e == BUCKETS_DRIVE_ERR_OFFLINE) before[i] = "offline";
      else if (e) before[i] = "corrupt";
    }
    any_found |= strcmp(before[i], "ok") == 0;
    after[i] = before[i];
  }
  /* no pool has the bucket: it is removed from the drives, not recreated */
  bool remove = hs->recreate ? hs->remove : !any_found;
  if (!hs->dry_run) {
    for (size_t i = 0; i < n; i++) {
      buckets_drive *d = drive_at(L, eps[i]);
      if (!d) continue;
      if (remove && strcmp(bucket, BUCKETS_META_BUCKET) != 0 && any_found) buckets_drive_delete_vol(d, bucket);
      if (!remove && strcmp(before[i], "missing") == 0 && buckets_drive_make_vol(d, bucket) == BUCKETS_DRIVE_OK)
        after[i] = "ok";
    }
  }
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "\"type\":\"bucket\",\"bucket\":");
  jstr(&b, bucket);
  buckets_buf_append_c(&b, ",\"object\":\"\",\"versionId\":\"\",\"detail\":\"\",\"diskCount\":0,\"setCount\":-1,\"before\":");
  drives_json(&b, names, before, hs->dry_run ? 0 : n);
  buckets_buf_append_c(&b, ",\"after\":");
  drives_json(&b, names, after, hs->dry_run ? 0 : n);
  buckets_buf_append_c(&b, ",\"objectSize\":0}");
  bool ok = push_item(h, &b);
  buckets_buf_free(&b);
  free(names);
  free(before);
  free(after);
  free(eps);
  return ok;
}

static const char *state_name(buckets_heal_state st) {
  switch (st) {
  case BUCKETS_HEAL_OK: return "ok";
  case BUCKETS_HEAL_OFFLINE: return "offline";
  case BUCKETS_HEAL_MISSING: return "missing";
  case BUCKETS_HEAL_CORRUPT: return "corrupt";
  }
  return "unknown";
}

/* A drive of pool/set by its position, named as the command line did. */
static const char *set_endpoint(const buckets_cluster_info *ci, size_t pool, size_t slot) {
  size_t k = 0;
  for (size_t i = 0; i < ci->neps; i++) {
    if (ci->eps[i].pool != pool) continue;
    if (k++ == slot) return ci->eps[i].endpoint;
  }
  return "";
}

/* toObjectErr's message for a heal failure. */
static void heal_error(buckets_buf *b, buckets_obj_err err, const char *bucket, const char *object,
                       const char *version) {
  switch (err) {
  case BUCKETS_OBJ_ERR_NO_SUCH_KEY: buckets_buf_appendf(b, "Object not found: %s/%s", bucket, object); break;
  case BUCKETS_OBJ_ERR_NO_SUCH_VERSION:
    buckets_buf_appendf(b, "Version not found: %s/%s(%s)", bucket, object, version);
    break;
  case BUCKETS_OBJ_ERR_NO_SUCH_BUCKET: buckets_buf_appendf(b, "Bucket not found: %s", bucket); break;
  case BUCKETS_OBJ_ERR_READ_QUORUM:
    buckets_buf_appendf(b, "Read failed. Insufficient number of drives online: %s/%s", bucket, object);
    break;
  case BUCKETS_OBJ_ERR_WRITE_QUORUM:
    buckets_buf_appendf(b, "Write failed. Insufficient number of drives online: %s/%s", bucket, object);
    break;
  default: buckets_buf_append_c(b, buckets_obj_strerror(err)); break;
  }
}

/* One version's HealObject, as queueHealTask reports it. */
static bool heal_object(heal_seq *h, const char *type, const char *bucket, const char *object, const char *version,
                        const heal_settings *hs) {
  buckets_objlayer *L = h->s->layer;
  buckets_heal_opts o = {.deep = hs->scan_mode == 2, .dry_run = hs->dry_run, .remove_dangling = true,
                         .scan_mode = hs->scan_mode};
  buckets_heal_result r;
  memset(&r, 0, sizeof(r));
  buckets_obj_err err = buckets_obj_heal(L, bucket, object, version, &o, &r);
  if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
    /* gone since it was listed: the item still reports it, as not found */
  }
  size_t n = r.ndrives;
  const char *eps[BUCKETS_MAX_SET_DRIVES], *before[BUCKETS_MAX_SET_DRIVES], *after[BUCKETS_MAX_SET_DRIVES];
  size_t ok_after = 0;
  for (size_t i = 0; i < n; i++) {
    eps[i] = set_endpoint(h->s->cluster, r.pool, r.set * n + i);
    before[i] = state_name(r.before[i]);
    after[i] = state_name(r.after[i]);
    ok_after += r.after[i] == BUCKETS_HEAL_OK;
  }
  buckets_buf b = BUCKETS_BUF_INIT, detail = BUCKETS_BUF_INIT;
  if (err) heal_error(&detail, err, bucket, object, version);
  if (r.parity_blocks > 0 && r.data_blocks > 0 && r.data_blocks > r.parity_blocks && ok_after < (size_t)r.parity_blocks) {
    buckets_buf_reset(&detail);
    buckets_buf_appendf(&detail, "quorum loss - expected %d minimum, got drive states in OK %zu", r.parity_blocks,
                        ok_after);
  }
  buckets_buf_append_c(&b, "\"type\":");
  jstr(&b, type);
  buckets_buf_append_c(&b, ",\"bucket\":");
  jstr(&b, bucket);
  buckets_buf_append_c(&b, ",\"object\":");
  jstr(&b, object);
  buckets_buf_append_c(&b, ",\"versionId\":");
  jstr(&b, version);
  buckets_buf_append_c(&b, ",\"detail\":");
  buckets_json_go_string(&b, detail.data ? detail.data : "", detail.len);
  if (r.parity_blocks) buckets_buf_appendf(&b, ",\"parityBlocks\":%d", r.parity_blocks);
  if (r.data_blocks) buckets_buf_appendf(&b, ",\"dataBlocks\":%d", r.data_blocks);
  buckets_buf_appendf(&b, ",\"diskCount\":%zu,\"setCount\":0,\"before\":", n);
  drives_json(&b, eps, before, n);
  buckets_buf_append_c(&b, ",\"after\":");
  drives_json(&b, eps, after, n);
  buckets_buf_appendf(&b, ",\"objectSize\":%lld}", (long long)r.size);
  bool ok = push_item(h, &b);
  buckets_buf_free(&b);
  buckets_buf_free(&detail);
  return ok;
}

/* HealObjects: every version under the prefix -- or, not recursive, only
 * the object named by the prefix itself (listAndHeal). false: stopped, or
 * the listing failed (*failed). */
static bool heal_objects(heal_seq *h, const char *type, const char *bucket, const char *prefix,
                         const heal_settings *hs, bool *failed) {
  buckets_objlayer *L = h->s->layer;
  char *key_marker = NULL, *ver_marker = NULL;
  bool ok = true;
  for (;;) {
    if (quitting(h)) {
      ok = false;
      break;
    }
    buckets_obj_listing l;
    buckets_obj_err e = buckets_obj_list_versions(L, bucket, prefix, key_marker, ver_marker, NULL, 1000, &l);
    if (e) {
      *failed = true;
      ok = false;
      break;
    }
    bool past = false;
    for (size_t i = 0; i < l.nobjects && ok && !past; i++) {
      const buckets_object_info *oi = &l.objects[i];
      if (!hs->recursive) {
        int c = strcmp(oi->name, prefix);
        if (c > 0) past = true;
        if (c) continue;
      }
      size_t nl = strlen(oi->name);
      if (nl && oi->name[nl - 1] == '/') continue; /* directories */
      if (strcmp(bucket, BUCKETS_META_BUCKET) == 0 &&
          (strncmp(oi->name, "tmp/", 4) == 0 || strncmp(oi->name, "multipart/", 10) == 0 ||
           strncmp(oi->name, "tmp-old/", 8) == 0 || strstr(oi->name, "/.metacache/")))
        continue;
      if (hs->pool >= 0 && hs->set >= 0 && L->npools > (size_t)hs->pool &&
          buckets_objlayer_object_set(L, (size_t)hs->pool, oi->name) != (size_t)hs->set)
        continue;
      ok = heal_object(h, type, bucket, oi->name, oi->version_id, hs);
    }
    free(key_marker);
    free(ver_marker);
    key_marker = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    ver_marker = l.truncated && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    bool more = l.truncated && key_marker && !past;
    buckets_obj_list_free(&l);
    if (!more || !ok) break;
  }
  free(key_marker);
  free(ver_marker);
  return ok;
}

typedef struct {
  buckets_bucket_info *b;
  int64_t created_ns; /* the bucket metadata's (ListBuckets reports it), else the volume's */
} dated_bucket;

static int newest_first(const void *a, const void *b) {
  const dated_bucket *x = a, *y = b;
  return x->created_ns < y->created_ns ? 1 : x->created_ns > y->created_ns ? -1 : strcmp(x->b->name, y->b->name);
}

static void sort_newest_first(buckets_s3_server *s, buckets_bucket_info *bk, size_t nb) {
  dated_bucket *d = buckets_xcalloc(nb ? nb : 1, sizeof(*d));
  for (size_t i = 0; i < nb; i++) {
    d[i].b = &bk[i];
    d[i].created_ns = (int64_t)bk[i].created * 1000000000LL;
    buckets_bucket_state *st = s->meta ? buckets_metasys_get(s->meta, bk[i].name) : NULL;
    if (st && st->exists) d[i].created_ns = buckets_bucket_meta_created_ns(&st->meta);
    if (st) buckets_bucket_state_release(st);
  }
  qsort(d, nb, sizeof(*d), newest_first);
  buckets_bucket_info *sorted = buckets_xcalloc(nb ? nb : 1, sizeof(*sorted));
  for (size_t i = 0; i < nb; i++) sorted[i] = *d[i].b;
  memcpy(bk, sorted, nb * sizeof(*bk));
  free(sorted);
  free(d);
}

/* healItems: the config prefix (for a cluster-wide heal), then the buckets.
 * Returns an error for the status's Detail, or NULL. */
static char *traverse(heal_seq *h) {
  heal_settings meta = h->hs, plain = h->hs;
  meta.recursive = true;
  meta.scan_mode = 1; /* HealNormalScan for items queued without options */
  plain.scan_mode = 1;
  bool failed = false;
  if (!*h->bucket) {
    if (!heal_objects(h, "bucket-metadata", BUCKETS_META_BUCKET, "config/", &meta, &failed) && !failed)
      return buckets_xstrdup("heal stop signaled");
    failed = false;
  }
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (*h->bucket) {
    bk = buckets_xcalloc(1, sizeof(*bk));
    bk->name = buckets_xstrdup(h->bucket);
    nb = 1;
  } else if (buckets_obj_list_buckets(h->s->layer, &bk, &nb) != BUCKETS_OBJ_OK) {
    return buckets_xstrdup("Heal internal error: XMinioInsufficientReadQuorum: Storage resources are insufficient "
                           "for the read operation.");
  } else {
    sort_newest_first(h->s, bk, nb);
  }
  char *err = NULL;
  for (size_t i = 0; i < nb && !err; i++) {
    if (quitting(h) || !heal_bucket(h, bk[i].name, &plain)) {
      err = buckets_xstrdup("heal stop signaled");
      break;
    }
    if (!heal_objects(h, "object", bk[i].name, h->prefix, &h->hs, &failed)) {
      if (failed && buckets_obj_stat_bucket(h->s->layer, bk[i].name) == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET)
        /* MinIO's text goes on with its listing options, pointers and all */
        err = buckets_xstrdup("Heal internal error: InternalError: We encountered an internal error, please try "
                              "again. (listPathRaw returned volume not found: opts(...))");
      else if (failed)
        err = buckets_xstrdup("Heal internal error: XMinioInsufficientReadQuorum: Storage resources are "
                              "insufficient for the read operation.");
      else
        err = buckets_xstrdup("heal stop signaled");
    }
  }
  buckets_bucket_info_free(bk, nb);
  return err;
}

/* healSequenceStart */
static void *run(void *arg) {
  heal_seq *h = arg;
  pthread_mutex_lock(&g_mu);
  h->summary = "running";
  h->status_start_ns = now_ns();
  pthread_mutex_unlock(&g_mu);
  char *err = traverse(h);
  pthread_mutex_lock(&g_mu);
  h->end_ns = now_ns();
  if (h->stop || !err) {
    h->summary = "finished"; /* a stop ends it as finished */
    free(err);
  } else {
    h->summary = "stopped";
    h->detail = err;
  }
  pthread_cond_broadcast(&g_cv);
  pthread_mutex_unlock(&g_mu);
  return NULL;
}

static void seq_free(heal_seq *h) {
  if (!h->joined) pthread_join(h->thread, NULL);
  free(h->bucket);
  free(h->prefix);
  free(h->path);
  free(h->detail);
  buckets_buf_free(&h->items);
  free(h);
}

/* Under g_mu: the sequence for a path, dropping those ended long ago. */
static heal_seq *find_path(const char *path) {
  int64_t now = now_ns();
  heal_seq *found = NULL;
  for (heal_seq **p = &g_seqs; *p;) {
    heal_seq *h = *p;
    if (h->end_ns && now - h->end_ns > KEEP_ENDED_NS) {
      *p = h->next;
      pthread_mutex_unlock(&g_mu);
      seq_free(h);
      pthread_mutex_lock(&g_mu);
      p = &g_seqs; /* the list may have changed meanwhile */
      found = NULL;
      continue;
    }
    if (strcmp(h->path, path) == 0) found = h;
    p = &h->next;
  }
  return found;
}

/* ---- the handler ------------------------------------------------------------------------------ */

/* This node's index among the cluster's nodes (GetProxyEndpointLocalIndex). */
static long local_index(const buckets_cluster_info *ci) {
  for (size_t i = 0; ci && i < ci->nnodes; i++)
    if (strcmp(ci->nodes[i], ci->self) == 0) return (long)i;
  return -1;
}

static void token_out(buckets_buf *b, const buckets_s3_server *s, const char *token) {
  if (s->cluster && s->cluster->distributed) {
    char t[80];
    snprintf(t, sizeof(t), "%s:%ld", token, local_index(s->cluster));
    jstr(b, t);
  } else {
    jstr(b, token);
  }
}

/* madmin.HealStartSuccess / HealStopSuccess */
static void start_success(buckets_buf *b, const buckets_s3_server *s, const char *token, const char *addr,
                          int64_t start) {
  buckets_buf_append_c(b, "{\"clientToken\":");
  token_out(b, s, token);
  buckets_buf_append_c(b, ",\"clientAddress\":");
  jstr(b, addr);
  buckets_buf_append_c(b, ",\"startTime\":");
  go_time(b, start);
  buckets_buf_append_char(b, '}');
}

static void reply_json(s3_ctx *c, buckets_buf *b) {
  buckets_buf_reset(&c->resp->body);
  buckets_buf_append(&c->resp->body, b->data, b->len);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
}

/* PopHealStatusJSON: the items since the last call. */
static buckets_s3_error pop_status(const char *path, const char *token, buckets_buf *out) {
  pthread_mutex_lock(&g_mu);
  heal_seq *h = find_path(path);
  if (!h) {
    pthread_mutex_unlock(&g_mu);
    heal_settings zero = {.pool = -1, .set = -1};
    buckets_buf_append_c(out, "{\"Summary\":\"finished\",\"StartTime\":\"0001-01-01T00:00:00Z\",\"Settings\":");
    settings_json(out, &zero);
    buckets_buf_append_c(out, ",\"Items\":null}");
    return BUCKETS_ERR_NONE;
  }
  if (strcmp(token, h->token) != 0) {
    pthread_mutex_unlock(&g_mu);
    return BUCKETS_ERR_HEAL_INVALID_CLIENT_TOKEN;
  }
  buckets_buf_append_c(out, "{\"Summary\":");
  jstr(out, h->summary);
  if (h->detail && *h->detail) {
    buckets_buf_append_c(out, ",\"Detail\":");
    jstr(out, h->detail);
  }
  buckets_buf_append_c(out, ",\"StartTime\":");
  go_time(out, h->status_start_ns);
  buckets_buf_append_c(out, ",\"Settings\":");
  settings_json(out, &h->hs);
  if (h->nitems) {
    buckets_buf_append_c(out, ",\"Items\":[");
    buckets_buf_append(out, h->items.data, h->items.len);
    buckets_buf_append_c(out, "]}");
  } else {
    buckets_buf_append_c(out, ",\"Items\":null}");
  }
  buckets_buf_reset(&h->items);
  h->nitems = 0;
  pthread_cond_broadcast(&g_cv);
  pthread_mutex_unlock(&g_mu);
  return BUCKETS_ERR_NONE;
}

/* stopHealSequence */
static void stop_seq(const buckets_s3_server *s, const char *path, buckets_buf *out) {
  pthread_mutex_lock(&g_mu);
  heal_seq *h = find_path(path);
  if (!h) {
    pthread_mutex_unlock(&g_mu);
    buckets_buf_append_c(out, "{\"clientToken\":\"unknown\",\"clientAddress\":\"\",\"startTime\":");
    go_time(out, now_ns());
    buckets_buf_append_char(out, '}');
    return;
  }
  start_success(out, s, h->token, h->client_addr, h->start_ns);
  h->stop = true;
  pthread_cond_broadcast(&g_cv);
  for (heal_seq **p = &g_seqs; *p; p = &(*p)->next) {
    if (*p == h) {
      *p = h->next;
      break;
    }
  }
  pthread_mutex_unlock(&g_mu);
  seq_free(h);
}

/* isReservedOrInvalidBucket(bucket, false) */
static bool reserved_or_invalid(const char *bucket) {
  char b[256];
  size_t n = strlen(bucket);
  if (n && bucket[n - 1] == '/') n--;
  if (n >= sizeof(b)) return true;
  memcpy(b, bucket, n);
  b[n] = '\0';
  return !buckets_bucket_name_valid(b) || buckets_bucket_name_reserved(b);
}

/* IsValidObjectPrefix */
static bool valid_prefix(const char *p) {
  if (!buckets_utf8_valid(p, strlen(p)) || strstr(p, "//")) return false;
  const char *s = p;
  while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
  for (;;) {
    const char *e = strchr(s, '/');
    size_t n = e ? (size_t)(e - s) : strlen(s);
    const char *a = s, *z = s + n;
    while (a < z && (*a == ' ' || *a == '\t')) a++;
    while (z > a && (z[-1] == ' ' || z[-1] == '\t' || z[-1] == '\n' || z[-1] == '\r')) z--;
    if ((z - a == 1 && a[0] == '.') || (z - a == 2 && a[0] == '.' && a[1] == '.')) return false;
    if (!e) break;
    s = e + 1;
  }
  return true;
}

static bool has_prefix(const char *s, const char *p) { return strncmp(s, p, strlen(p)) == 0; }

/* The heal settings in the request body (json.Decoder into madmin.HealOpts). */
static bool parse_settings(const char *body, size_t n, heal_settings *hs) {
  *hs = (heal_settings){.pool = -1, .set = -1};
  yyjson_doc *doc = yyjson_read_opts((char *)body, n, YYJSON_READ_STOP_WHEN_DONE, NULL, NULL);
  if (!doc) return false;
  yyjson_val *root = yyjson_doc_get_root(doc);
  bool ok = yyjson_is_obj(root) || yyjson_is_null(root);
  static const struct {
    const char *key;
    size_t off;
  } bools[] = {{"recursive", offsetof(heal_settings, recursive)},       {"dryRun", offsetof(heal_settings, dry_run)},
               {"remove", offsetof(heal_settings, remove)},             {"recreate", offsetof(heal_settings, recreate)},
               {"updateParity", offsetof(heal_settings, update_parity)}, {"nolock", offsetof(heal_settings, nolock)}};
  size_t idx, max;
  yyjson_val *k, *v;
  if (yyjson_is_obj(root)) {
    yyjson_obj_foreach(root, idx, max, k, v) {
      const char *key = yyjson_get_str(k);
      bool known = false;
      for (size_t i = 0; i < BUCKETS_ARRAY_LEN(bools); i++) {
        /* encoding/json matches field names case-insensitively */
        if (strcasecmp(key, bools[i].key) != 0) continue;
        known = true;
        if (yyjson_is_bool(v)) *(bool *)((char *)hs + bools[i].off) = yyjson_get_bool(v);
        else if (!yyjson_is_null(v)) ok = false;
      }
      if (known) continue;
      int *iv = strcasecmp(key, "scanMode") == 0 ? &hs->scan_mode
                : strcasecmp(key, "pool") == 0   ? &hs->pool
                : strcasecmp(key, "set") == 0    ? &hs->set
                                                 : NULL;
      if (!iv) continue;
      if (yyjson_is_int(v)) *iv = (int)yyjson_get_int(v);
      else if (yyjson_is_null(v)) continue;
      else ok = false;
    }
  }
  yyjson_doc_free(doc);
  return ok;
}

/* A status request for a sequence on another node: sent there. */
static bool forward_status(s3_ctx *c, const char *token, long idx, const char *path) {
  const buckets_cluster_info *ci = c->s->cluster;
  if (!ci || idx < 0 || (size_t)idx >= ci->nnodes) return false;
  buckets_buf t = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/admin?op=heal-status&path=");
  buckets_url_encode(&t, path, false);
  buckets_buf_append_c(&t, "&token=");
  buckets_url_encode(&t, token, false);
  buckets_buf_append_char(&t, '\0');
  int status = 0;
  bool ok = buckets_peer_call(c->s->peers, ci->nodes[idx], t.data, &status, &body);
  buckets_buf_free(&t);
  if (ok) {
    buckets_buf_reset(&c->resp->body);
    buckets_buf_append(&c->resp->body, body.data, body.len);
    c->resp->status = status;
    buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  }
  buckets_buf_free(&body);
  return ok;
}

void buckets_admin_heal_peer(buckets_s3_server *s, const buckets_query *q, int *status, buckets_buf *out) {
  (void)s;
  const char *op = buckets_query_get(q, "op");
  if (!op || strcmp(op, "heal-status") != 0) {
    *status = 400;
    return;
  }
  const char *path = buckets_query_get(q, "path"), *token = buckets_query_get(q, "token");
  buckets_s3_error e = pop_status(path ? path : "", token ? token : "", out);
  if (e) {
    const buckets_s3_error_info *ei = buckets_s3_error_get(e);
    *status = ei->status;
    buckets_buf_reset(out);
    buckets_buf_append_c(out, "{\"Code\":");
    jstr(out, ei->code);
    buckets_buf_append_c(out, ",\"Message\":");
    jstr(out, ei->message);
    buckets_buf_append_c(out, ",\"Resource\":\"\",\"RequestId\":\"\",\"HostId\":\"\"}");
  } else {
    *status = 200;
  }
}

/* writeErrorResponseJSON with the route's bucket variable. */
static void heal_err(s3_ctx *c, buckets_s3_error e, const char *bucket, const char *msg) {
  const buckets_s3_error_info *ei = buckets_s3_error_get(e);
  buckets_admin_json_error(c, ei->status, ei->code, msg ? msg : ei->message, NULL, bucket);
}

void buckets_admin_heal(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:Heal")) return;
  buckets_s3_server *s = c->s;
  /* /heal/[bucket[/prefix]] */
  buckets_str rest = c->req->path;
  const char *hp = memmem(rest.p, rest.n, "/heal/", 6);
  size_t off = hp ? (size_t)(hp - rest.p) + 6 : rest.n;
  buckets_buf raw = BUCKETS_BUF_INIT;
  buckets_buf_reserve(&raw, rest.n - off + 1);
  long dn = buckets_url_decode((buckets_str){rest.p + off, rest.n - off}, raw.data, false);
  raw.len = dn > 0 ? (size_t)dn : 0;
  buckets_buf_append_char(&raw, '\0');
  char *slash = strchr(raw.data, '/');
  char *bucket = buckets_xstrndup(raw.data, slash ? (size_t)(slash - raw.data) : strlen(raw.data));
  char *prefix = buckets_xstrdup(slash ? slash + 1 : "");
  buckets_buf_free(&raw);
  buckets_s3_error e = BUCKETS_ERR_NONE;
  if (!*bucket) {
    if (*prefix) e = BUCKETS_ERR_HEAL_MISSING_BUCKET;
  } else if (reserved_or_invalid(bucket)) {
    e = BUCKETS_ERR_INVALID_BUCKET_NAME;
  }
  if (!e && !valid_prefix(prefix)) e = BUCKETS_ERR_INVALID_OBJECT_NAME;
  const char *token = buckets_query_get(&c->q, "clientToken");
  bool has_token = buckets_query_has(&c->q, "clientToken");
  bool force_start = buckets_query_has(&c->q, "forceStart"), force_stop = buckets_query_has(&c->q, "forceStop");
  if (!token) token = "";
  if (!e && ((force_start && force_stop) || (*token && (force_start || force_stop)))) e = BUCKETS_ERR_INVALID_REQUEST;
  (void)has_token;
  heal_settings hs = {.pool = -1, .set = -1};
  if (!e && !*token) {
    buckets_s3_error de = buckets_s3_read_doc(c);
    if (de) e = de;
    else if (!parse_settings(c->doc.data ? c->doc.data : "", c->doc.len, &hs)) e = BUCKETS_ERR_REQUEST_BODY_PARSE;
  }
  if (e) {
    heal_err(c, e, bucket, NULL);
    free(bucket);
    free(prefix);
    return;
  }
  char *path = path_join(bucket, prefix);
  buckets_buf out = BUCKETS_BUF_INIT;

  /* a token naming another node: that node has the sequence */
  char tok[128];
  snprintf(tok, sizeof(tok), "%s", token);
  char *colon = strrchr(tok, ':');
  if (colon && s->cluster && s->cluster->distributed) {
    *colon = '\0';
    long idx = strtol(colon + 1, NULL, 10);
    if (idx != local_index(s->cluster) && forward_status(c, tok, idx, path)) goto done;
  }

  if (!*tok && !force_start && !force_stop) {
    /* a running sequence with results waiting: its token */
    pthread_mutex_lock(&g_mu);
    heal_seq *h = find_path(path);
    if (h && !h->end_ns && h->nitems) {
      start_success(&out, s, h->token, h->client_addr, h->start_ns);
      pthread_mutex_unlock(&g_mu);
      reply_json(c, &out);
      goto done;
    }
    pthread_mutex_unlock(&g_mu);
  }
  if (*tok && !force_start && !force_stop) {
    buckets_s3_error pe = pop_status(path, tok, &out);
    if (pe) heal_err(c, pe, bucket, NULL);
    else reply_json(c, &out);
    goto done;
  }
  if (force_stop) {
    stop_seq(s, path, &out);
    reply_json(c, &out);
    goto done;
  }

  /* LaunchNewHealSequence */
  heal_seq *nh = buckets_xcalloc(1, sizeof(*nh));
  nh->s = s;
  nh->bucket = bucket;
  nh->prefix = prefix;
  nh->path = buckets_xstrdup(path);
  bucket = prefix = NULL;
  buckets_uuid_v4(nh->token);
  buckets_s3_source_ip(c->req, nh->client_addr, sizeof(nh->client_addr));
  nh->force_started = force_start;
  nh->hs = hs;
  nh->start_ns = now_ns();
  nh->summary = "not started";
  if (force_start) {
    buckets_buf ignored = BUCKETS_BUF_INIT;
    stop_seq(s, path, &ignored);
    buckets_buf_free(&ignored);
  } else {
    pthread_mutex_lock(&g_mu);
    heal_seq *oh = find_path(path);
    bool running = oh && !oh->end_ns;
    pthread_mutex_unlock(&g_mu);
    if (running) {
      char msg[512], when[64];
      time_t t = (time_t)(nh->start_ns / 1000000000LL);
      struct tm tm;
      gmtime_r(&t, &tm);
      strftime(when, sizeof(when), "%a, %d %b %Y %H:%M:%S GMT", &tm);
      snprintf(msg, sizeof(msg),
               "Heal is already running on the given path (use force-start option to stop and start afresh). "
               "The heal was started by IP %s at %s, token is %s",
               nh->client_addr, when, nh->token);
      heal_err(c, BUCKETS_ERR_HEAL_ALREADY_RUNNING, NULL, msg); /* no bucket: written by the launcher */
      nh->joined = true;
      seq_free(nh);
      goto done;
    }
  }
  pthread_mutex_lock(&g_mu);
  for (heal_seq *h = g_seqs; h; h = h->next) {
    if (!h->end_ns && (has_prefix(h->path, nh->path) || has_prefix(nh->path, h->path))) {
      char msg[1200];
      snprintf(msg, sizeof(msg), "The provided heal sequence path overlaps with an existing heal path: %s", h->path);
      pthread_mutex_unlock(&g_mu);
      heal_err(c, BUCKETS_ERR_HEAL_OVERLAPPING_PATHS, NULL, msg);
      nh->joined = true;
      seq_free(nh);
      goto done;
    }
  }
  /* replaces an ended sequence on the same path */
  for (heal_seq **p = &g_seqs; *p; p = &(*p)->next) {
    if (strcmp((*p)->path, nh->path) == 0) {
      heal_seq *old = *p;
      *p = old->next;
      pthread_mutex_unlock(&g_mu);
      seq_free(old);
      pthread_mutex_lock(&g_mu);
      break;
    }
  }
  nh->next = g_seqs;
  g_seqs = nh;
  if (pthread_create(&nh->thread, NULL, run, nh) != 0) buckets_fatal("start heal sequence");
  start_success(&out, s, nh->token, nh->client_addr, nh->start_ns);
  pthread_mutex_unlock(&g_mu);
  reply_json(c, &out);
done:
  buckets_buf_free(&out);
  free(path);
  free(bucket);
  free(prefix);
}

void buckets_admin_heal_shutdown(void) {
  pthread_mutex_lock(&g_mu);
  heal_seq *all = g_seqs;
  g_seqs = NULL;
  for (heal_seq *h = all; h; h = h->next) h->stop = true;
  pthread_cond_broadcast(&g_cv);
  pthread_mutex_unlock(&g_mu);
  for (heal_seq *h = all, *next; h; h = next) {
    next = h->next;
    seq_free(h);
  }
}
