/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Server pools: routes the object API across pools, after MinIO's
 * cmd/erasure-server-pool.go. With a single pool every call goes straight
 * through. With several:
 *  - reads resolve the pool holding the newest copy of the object;
 *  - writes go to the pool already holding the object, else to a pool picked
 *    at random weighted by the free space of the set the object hashes to;
 *  - buckets exist on every pool; listings merge all pools. */
#include "core/auditctx.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/log.h"
#include "core/uuid.h"
#include "object/epool.h"
#include "object/nslock.h"
#include "object/object.h"
#include "storage/remote.h"

/* ---- layer ------------------------------------------------------------------ */

static void sync_buckets(buckets_objlayer *L);

buckets_objlayer *buckets_objlayer_new(buckets_format_result *f, size_t npools, int parity) {
  buckets_objlayer *L = buckets_xcalloc(1, sizeof(*L));
  L->locks = buckets_nslock_new();
  L->npools = npools;
  L->pools = buckets_xcalloc(npools, sizeof(buckets_epool *));
  for (size_t p = 0; p < npools; p++) {
    L->pools[p] = buckets_epool_new(L, p, &f[p], parity);
    L->nall += L->pools[p]->nall;
  }
  L->all = buckets_xcalloc(L->nall ? L->nall : 1, sizeof(buckets_drive *));
  size_t k = 0;
  for (size_t p = 0; p < npools; p++) {
    memcpy(L->all + k, L->pools[p]->all, L->pools[p]->nall * sizeof(buckets_drive *));
    k += L->pools[p]->nall;
  }
  memcpy(L->deployment_id, L->pools[0]->deployment_id, 16);
  memcpy(L->deployment_id_str, L->pools[0]->deployment_id_str, sizeof(L->deployment_id_str));
  if (npools > 1) sync_buckets(L);
  return L;
}

/* ---- the node's upload cache ----
 * erasureServerPools.mpCache: uploads created through this node, dropped
 * when completed or aborted, or after a day (stale_uploads_expiry). A
 * ListMultipartUploads without a prefix answers from it, as MinIO does. */

#define MP_CACHE_EXPIRY_NS (24LL * 3600 * 1000000000LL)

typedef struct {
  char *bucket;
  buckets_upload_info info;
} mp_entry;

struct buckets_mp_cache {
  pthread_mutex_t mu;
  mp_entry *e;
  size_t n, cap;
};

static struct buckets_mp_cache *mp_cache(buckets_objlayer *L) {
  static pthread_mutex_t init = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&init);
  if (!L->mp_cache) {
    L->mp_cache = buckets_xcalloc(1, sizeof(*L->mp_cache));
    pthread_mutex_init(&L->mp_cache->mu, NULL);
  }
  pthread_mutex_unlock(&init);
  return L->mp_cache;
}

static void mp_entry_free(mp_entry *e) {
  free(e->bucket);
  free(e->info.object);
}

static void mp_cache_add(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id) {
  struct buckets_mp_cache *c = mp_cache(L);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  pthread_mutex_lock(&c->mu);
  if (c->n == c->cap) {
    c->cap = c->cap ? c->cap * 2 : 16;
    c->e = buckets_xrealloc(c->e, c->cap * sizeof(mp_entry));
  }
  mp_entry *e = &c->e[c->n++];
  memset(e, 0, sizeof(*e));
  e->bucket = buckets_xstrdup(bucket);
  e->info.object = buckets_xstrdup(object);
  snprintf(e->info.upload_id, sizeof(e->info.upload_id), "%s", upload_id);
  e->info.initiated_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  pthread_mutex_unlock(&c->mu);
}

static void mp_cache_remove(buckets_objlayer *L, const char *upload_id) {
  struct buckets_mp_cache *c = mp_cache(L);
  pthread_mutex_lock(&c->mu);
  for (size_t i = 0; i < c->n; i++) {
    if (strcmp(c->e[i].info.upload_id, upload_id) != 0) continue;
    mp_entry_free(&c->e[i]);
    memmove(&c->e[i], &c->e[i + 1], (c->n - i - 1) * sizeof(mp_entry));
    c->n--;
    break;
  }
  pthread_mutex_unlock(&c->mu);
}

/* The bucket's cached uploads, oldest first (entries are kept in creation order). */
static void mp_cache_list(buckets_objlayer *L, const char *bucket, buckets_upload_info **out, size_t *n) {
  struct buckets_mp_cache *c = mp_cache(L);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  pthread_mutex_lock(&c->mu);
  size_t k = 0;
  for (size_t i = 0; i < c->n; i++) { /* cleanupStaleMPCache */
    if (now - c->e[i].info.initiated_ns >= MP_CACHE_EXPIRY_NS) mp_entry_free(&c->e[i]);
    else c->e[k++] = c->e[i];
  }
  c->n = k;
  *out = NULL;
  *n = 0;
  for (size_t i = 0; i < c->n; i++) {
    if (strcmp(c->e[i].bucket, bucket) != 0) continue;
    *out = buckets_xrealloc(*out, (*n + 1) * sizeof(buckets_upload_info));
    (*out)[*n] = c->e[i].info;
    (*out)[*n].object = buckets_xstrdup(c->e[i].info.object);
    (*n)++;
  }
  pthread_mutex_unlock(&c->mu);
}

void buckets_objlayer_free(buckets_objlayer *L) {
  if (!L) return;
  if (L->mp_cache) {
    for (size_t i = 0; i < L->mp_cache->n; i++) mp_entry_free(&L->mp_cache->e[i]);
    free(L->mp_cache->e);
    pthread_mutex_destroy(&L->mp_cache->mu);
    free(L->mp_cache);
  }
  for (size_t p = 0; p < L->npools; p++) buckets_epool_free(L->pools[p]);
  free(L->pools);
  free(L->all);
  buckets_nslock_free(L->locks);
  free(L);
}

void buckets_objlayer_set_degraded_hook(buckets_objlayer *L, buckets_degraded_fn fn, void *ud) {
  L->on_degraded = fn;
  L->on_degraded_ud = ud;
}

buckets_drive *buckets_objlayer_scratch(const buckets_objlayer *L) {
  for (size_t i = 0; i < L->nall; i++) {
    if (L->all[i] && !L->all[i]->remote) return L->all[i];
  }
  return NULL;
}

size_t buckets_objlayer_online(const buckets_objlayer *L) {
  size_t c = 0;
  for (size_t i = 0; i < L->nall; i++) c += L->all[i] != NULL;
  return c;
}

void buckets_objlayer_set_locker(buckets_objlayer *L, void *(*lock)(void *, const char *, bool, int),
                                 void (*unlock)(void *, void *), void *ud) {
  buckets_nslock_set_backend(L->locks, lock, unlock, ud);
}

bool buckets_objlayer_has_quorum(buckets_objlayer *L, bool write) {
  for (size_t p = 0; p < L->npools; p++) {
    buckets_epool *P = L->pools[p];
    for (size_t k = 0; k < P->nsets; k++) {
      buckets_eset *s = &P->sets[k];
      size_t online = 0;
      for (size_t i = 0; i < s->n; i++) online += buckets_drive_is_online(s->drives[i]);
      int data = (int)s->n - s->parity;
      int need = write ? data + (data == s->parity) : data;
      if ((int)online < need) return false;
    }
  }
  return true;
}

void buckets_objlayer_place(const buckets_objlayer *L, size_t i, buckets_drive_place *out) {
  memset(out, 0, sizeof(*out));
  size_t first = 0;
  for (size_t p = 0; p < L->npools; p++) {
    const buckets_epool *P = L->pools[p];
    if (i < first + P->nall) {
      out->pool = p;
      out->pool_first = first;
      out->pool_drives = P->nall;
      out->nsets = P->nsets;
      out->set_size = P->sets[0].n;
      out->set = (i - first) / out->set_size;
      out->parity = P->sets[out->set].parity;
      return;
    }
    first += P->nall;
  }
}

bool buckets_objlayer_set_is_led_here(const buckets_objlayer *L, size_t pool, size_t set) {
  const buckets_eset *s = &L->pools[pool]->sets[set];
  for (size_t i = 0; i < s->n; i++) {
    if (buckets_drive_is_online(s->drives[i])) return !s->drives[i]->remote;
  }
  return false;
}

size_t buckets_objlayer_object_set(const buckets_objlayer *L, size_t pool, const char *object) {
  buckets_epool *P = L->pools[pool];
  return (size_t)(buckets_ep_set_for(P, object) - P->sets);
}

/* A pool added to an existing deployment starts without the buckets. */
static void sync_buckets(buckets_objlayer *L) {
  for (size_t p = 0; p < L->npools; p++) {
    buckets_bucket_info *b;
    size_t n;
    if (buckets_ep_list_buckets(L->pools[p], &b, &n) != BUCKETS_OBJ_OK) continue;
    for (size_t i = 0; i < n; i++) {
      for (size_t q = 0; q < L->npools; q++) {
        if (q != p && buckets_ep_stat_bucket(L->pools[q], b[i].name) == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET) {
          buckets_ep_make_bucket(L->pools[q], b[i].name);
          buckets_log_info("created bucket %s on pool %zu", b[i].name, q + 1);
        }
      }
    }
    buckets_bucket_info_free(b, n);
  }
}

/* ---- pool selection ------------------------------------------------------------ */

typedef struct {
  int pool;             /* -1: in no pool */
  buckets_obj_err err;  /* OK, or why no pool was found */
} lookup;

/* getPoolInfoExistingWithOpts: the pool with the newest copy of the object
 * (or of version_id). A pool that sees the object but lacks read quorum is
 * returned too, so writes go where the object visibly lives. */
static lookup find_pool(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id) {
  lookup best = {-1, BUCKETS_OBJ_ERR_NO_SUCH_KEY};
  int64_t best_mtime = 0;
  bool other_err = false;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_object_info oi;
    buckets_obj_err err = buckets_ep_stat(L->pools[p], bucket, object, version_id, &oi);
    if (err == BUCKETS_OBJ_OK) {
      if (best.pool < 0 || best.err || oi.mod_time_ns > best_mtime) {
        best = (lookup){(int)p, BUCKETS_OBJ_OK};
        best_mtime = oi.mod_time_ns;
      }
      buckets_object_info_free(&oi);
    } else if (err == BUCKETS_OBJ_ERR_READ_QUORUM) {
      if (best.pool < 0) best = (lookup){(int)p, err};
    } else if (err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      if (!other_err && best.pool < 0) best.err = err;
      other_err = true;
    } else if (best.pool < 0 && !other_err) {
      best.err = err;
    }
  }
  return best;
}

/* getAvailablePoolIdx: random, weighted by the free space of the set the
 * object would land in; pools whose set cannot hold it are skipped. */
static int available_pool(buckets_objlayer *L, const char *object, int64_t size) {
  uint64_t avail[64] = {0}, total = 0;
  size_t np = BUCKETS_MIN(L->npools, (size_t)64);
  for (size_t p = 0; p < np; p++) {
    buckets_eset *s = buckets_ep_set_for(L->pools[p], object);
    uint64_t sum = 0;
    size_t online = 0;
    for (size_t i = 0; i < s->n; i++) {
      uint64_t t, f;
      if (s->drives[i] && buckets_drive_disk_info(s->drives[i], &t, &f) == BUCKETS_DRIVE_OK) {
        sum += f;
        online++;
      }
    }
    int data = (int)s->n - s->parity;
    /* Each drive stores about size/data; keep MinIO's 5% reserve per drive. */
    uint64_t per_drive = size > 0 ? (uint64_t)size / (uint64_t)(data > 0 ? data : 1) : 0;
    if (!online || sum / 20 + per_drive * online > sum) continue;
    avail[p] = sum;
    total += sum;
  }
  if (!total) return L->npools ? 0 : -1;
  uint64_t r;
  buckets_random_bytes(&r, sizeof(r));
  uint64_t choose = r % total, at = 0;
  for (size_t p = 0; p < np; p++) {
    at += avail[p];
    if (avail[p] && at > choose) return (int)p;
  }
  return 0;
}

/* getPoolIdx: where a write of object goes. */
static int write_pool(buckets_objlayer *L, const char *bucket, const char *object, int64_t size, buckets_obj_err *err) {
  *err = BUCKETS_OBJ_OK;
  if (L->npools == 1) return 0;
  lookup l = find_pool(L, bucket, object, NULL);
  if (l.pool >= 0) return l.pool;
  if (l.err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && l.err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
    *err = l.err;
    return -1;
  }
  return available_pool(L, object, size);
}


/* auditObjectErasureSet: the operation, with where the object lives */
static void audit_op(buckets_objlayer *L, const char *op, const char *bucket, const char *object, int pool) {
  /* the server's own metadata (MinIO reads and writes it outside the request's context) */
  buckets_audit_tags *at = buckets_audit_tags_current();
  if (!at || pool < 0 || (size_t)pool >= L->npools || (!at->sys_ops && strcmp(bucket, BUCKETS_META_BUCKET) == 0))
    return;
  char v[1400];
  snprintf(v, sizeof(v), "name=%s,pool=%d,set=%zu", object ? object : "", pool + 1,
           buckets_objlayer_object_set(L, (size_t)pool, object ? object : "") + 1);
  buckets_audit_tag(op, v);
}

/* ---- buckets ------------------------------------------------------------------- */

buckets_obj_err buckets_obj_make_bucket(buckets_objlayer *L, const char *bucket) {
  buckets_obj_err first = BUCKETS_OBJ_OK;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_obj_err err = buckets_ep_make_bucket(L->pools[p], bucket);
    if (p == 0) first = err;
    else if (err && err != BUCKETS_OBJ_ERR_BUCKET_EXISTS && !first) first = err;
  }
  return first;
}

buckets_obj_err buckets_obj_stat_bucket(buckets_objlayer *L, const char *bucket) {
  return buckets_ep_stat_bucket(L->pools[0], bucket);
}

buckets_obj_err buckets_obj_delete_bucket(buckets_objlayer *L, const char *bucket) {
  if (L->npools > 1) {
    for (size_t p = 0; p < L->npools; p++) {
      buckets_obj_listing l;
      if (buckets_ep_list_versions(L->pools[p], bucket, "", NULL, NULL, NULL, 1, &l) == BUCKETS_OBJ_OK) {
        bool empty = l.nobjects == 0;
        buckets_obj_list_free(&l);
        if (!empty) return BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY;
      }
    }
  }
  buckets_obj_err first = BUCKETS_OBJ_OK;
  for (size_t p = L->npools; p-- > 0;) { /* pool 0 last: it answers stat_bucket */
    buckets_obj_err err = buckets_ep_delete_bucket(L->pools[p], bucket);
    if (p == 0 || (err && err != BUCKETS_OBJ_ERR_NO_SUCH_BUCKET && !first)) first = err;
  }
  return first;
}

buckets_obj_err buckets_obj_list_buckets(buckets_objlayer *L, buckets_bucket_info **out, size_t *n) {
  return buckets_ep_list_buckets(L->pools[0], out, n);
}

size_t buckets_obj_heal_bucket(buckets_objlayer *L, const char *bucket) {
  size_t made = 0;
  for (size_t p = 0; p < L->npools; p++) made += buckets_ep_heal_bucket(L->pools[p], bucket);
  return made;
}

/* ---- objects ------------------------------------------------------------------- */

buckets_obj_err buckets_obj_put(buckets_objlayer *L, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out) {
  buckets_obj_err err;
  int p = write_pool(L, bucket, object, size, &err);
  if (p < 0) return err;
  audit_op(L, "PutObject", bucket, object, p);
  return buckets_ep_put(L->pools[p], bucket, object, rd, rd_ud, size, opts, out);
}

buckets_obj_err buckets_obj_stat(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out) {
  if (L->npools == 1) {
    audit_op(L, "GetObjectInfo", bucket, object, 0);
    return buckets_ep_stat(L->pools[0], bucket, object, version_id, out);
  }
  lookup l = find_pool(L, bucket, object, version_id);
  if (l.pool < 0 || l.err) return l.err;
  audit_op(L, "GetObjectInfo", bucket, object, l.pool);
  return buckets_ep_stat(L->pools[l.pool], bucket, object, version_id, out);
}

buckets_obj_err buckets_obj_open(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info) {
  if (L->npools == 1) {
    audit_op(L, "GetObject", bucket, object, 0);
    return buckets_ep_open(L->pools[0], bucket, object, version_id, offset, length, out, info);
  }
  lookup l = find_pool(L, bucket, object, version_id);
  if (l.pool < 0 || l.err) return l.err;
  audit_op(L, "GetObject", bucket, object, l.pool);
  return buckets_ep_open(L->pools[l.pool], bucket, object, version_id, offset, length, out, info);
}

/* Deletes from every pool holding the object, so a duplicate left by racing
 * writers to different pools cannot resurface. */
buckets_obj_err buckets_obj_delete(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id) {
  if (L->npools == 1) return buckets_ep_delete(L->pools[0], bucket, object, version_id);
  buckets_obj_err result = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  bool found = false;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_obj_err err = buckets_ep_delete(L->pools[p], bucket, object, version_id);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      if (!found) result = err;
      continue;
    }
    if (!found || err) result = err;
    found = true;
  }
  return result;
}

/* A delete marker goes to the pool where the object lives (or, for a key
 * that exists nowhere, where a new object would); explicit versions are
 * removed from every pool that has them. */
buckets_obj_err buckets_obj_delete_ex(buckets_objlayer *L, const char *bucket, const char *object,
                                      const buckets_delete_opts *opts, buckets_delete_result *res) {
  buckets_audit_tags *at = buckets_audit_tags_current();
  const char *dop = at && at->delete_op ? at->delete_op : "DeleteObject";
  if (L->npools == 1) {
    buckets_obj_err err = buckets_ep_delete_ex(L->pools[0], bucket, object, opts, res);
    if (err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) audit_op(L, dop, bucket, object, 0);
    return err;
  }
  audit_op(L, dop, bucket, object, 0);
  if (opts->replica_marker || opts->replica || opts->decide || (opts->repl_status && *opts->repl_status) ||
      (opts->purge_status && *opts->purge_status)) {
    /* replication: the pool holding the object (version), else where it would go */
    lookup l = find_pool(L, bucket, object, opts->version_id && *opts->version_id ? opts->version_id : NULL);
    int p = l.pool;
    buckets_obj_err err = BUCKETS_OBJ_OK;
    if (p < 0) p = write_pool(L, bucket, object, 0, &err);
    if (p < 0) return err;
    return buckets_ep_delete_ex(L->pools[p], bucket, object, opts, res);
  }
  bool marker = !(opts->version_id && *opts->version_id) && (opts->versioned || opts->suspended);
  if (marker) {
    buckets_obj_err err;
    int p = write_pool(L, bucket, object, 0, &err);
    if (p < 0) return err;
    return buckets_ep_delete_ex(L->pools[p], bucket, object, opts, res);
  }
  buckets_obj_err result = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  bool found = false;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_delete_result r;
    buckets_obj_err err = buckets_ep_delete_ex(L->pools[p], bucket, object, opts, &r);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      if (!found) {
        result = err;
        *res = r;
      }
      continue;
    }
    if (!found || err) result = err;
    if (!found) *res = r;
    found = true;
  }
  return result;
}

buckets_obj_err buckets_obj_update_meta(buckets_objlayer *L, const char *bucket, const char *object,
                                        const char *version_id, buckets_meta_edit_fn fn, void *ud,
                                        buckets_object_info *out) {
  if (L->npools == 1) return buckets_ep_update_meta(L->pools[0], bucket, object, version_id, fn, ud, out);
  lookup l = find_pool(L, bucket, object, version_id);
  if (l.pool < 0 || l.err) return l.err;
  return buckets_ep_update_meta(L->pools[l.pool], bucket, object, version_id, fn, ud, out);
}

buckets_obj_err buckets_obj_list_versions(buckets_objlayer *L, const char *bucket, const char *prefix,
                                          const char *key_marker, const char *version_marker, const char *delimiter,
                                          int max_keys, buckets_obj_listing *out) {
  if (L->npools == 1)
    return buckets_ep_list_versions(L->pools[0], bucket, prefix, key_marker, version_marker, delimiter, max_keys, out);
  memset(out, 0, sizeof(*out));
  buckets_obj_listing *src = buckets_xcalloc(L->npools, sizeof(*src));
  buckets_obj_err err = BUCKETS_OBJ_OK;
  for (size_t p = 0; p < L->npools && !err; p++)
    err = buckets_ep_list_versions(L->pools[p], bucket, prefix, key_marker, version_marker, delimiter, max_keys, &src[p]);
  if (!err) buckets_obj_listing_merge_versions(src, L->npools, max_keys > BUCKETS_MAX_LIST_KEYS ? BUCKETS_MAX_LIST_KEYS : max_keys, out);
  for (size_t p = 0; p < L->npools; p++) buckets_obj_list_free(&src[p]);
  free(src);
  return err;
}

typedef struct {
  const char *key;
  bool is_prefix;
  size_t src, idx;
} pmerged;

static int pmerged_cmp(const void *a, const void *b) {
  const pmerged *x = a, *y = b;
  int c = strcmp(x->key, y->key);
  if (c) return c;
  if (x->is_prefix != y->is_prefix) return x->is_prefix ? 1 : -1;
  return x->src < y->src ? -1 : x->src > y->src;
}

buckets_obj_err buckets_obj_list(buckets_objlayer *L, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out) {
  if (L->npools == 1) return buckets_ep_list(L->pools[0], bucket, prefix, marker, delimiter, max_keys, out);
  memset(out, 0, sizeof(*out));
  buckets_obj_listing *src = buckets_xcalloc(L->npools, sizeof(*src));
  bool truncated = false;
  size_t total = 0;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_obj_err err = buckets_ep_list(L->pools[p], bucket, prefix, marker, delimiter, max_keys, &src[p]);
    if (err) {
      for (size_t q = 0; q < p; q++) buckets_obj_list_free(&src[q]);
      free(src);
      return err;
    }
    truncated |= src[p].truncated;
    total += src[p].nobjects + src[p].nprefixes;
  }
  pmerged *all = buckets_xcalloc(total ? total : 1, sizeof(pmerged));
  size_t na = 0;
  for (size_t p = 0; p < L->npools; p++) {
    for (size_t j = 0; j < src[p].nobjects; j++) all[na++] = (pmerged){src[p].objects[j].name, false, p, j};
    for (size_t j = 0; j < src[p].nprefixes; j++) all[na++] = (pmerged){src[p].prefixes[j], true, p, j};
  }
  qsort(all, na, sizeof(pmerged), pmerged_cmp);
  const char *last = NULL;
  size_t emitted = 0;
  for (size_t i = 0; i < na;) {
    /* Entries with the same key: one per pool at most; keep the newest object. */
    size_t j = i + 1;
    while (j < na && all[j].is_prefix == all[i].is_prefix && strcmp(all[j].key, all[i].key) == 0) j++;
    if ((int)emitted == max_keys) {
      truncated = true;
      break;
    }
    if (all[i].is_prefix) {
      out->prefixes = buckets_xrealloc(out->prefixes, (out->nprefixes + 1) * sizeof(char *));
      out->prefixes[out->nprefixes++] = buckets_xstrdup(all[i].key);
    } else {
      size_t pick = i;
      for (size_t k = i + 1; k < j; k++) {
        if (src[all[k].src].objects[all[k].idx].mod_time_ns > src[all[pick].src].objects[all[pick].idx].mod_time_ns) {
          pick = k;
        }
      }
      buckets_object_info *from = &src[all[pick].src].objects[all[pick].idx];
      out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
      out->objects[out->nobjects++] = *from;
      memset(from, 0, sizeof(*from)); /* moved */
    }
    last = all[i].key;
    emitted++;
    i = j;
  }
  out->truncated = truncated;
  if (truncated && last) out->next_marker = buckets_xstrdup(last);
  free(all);
  for (size_t p = 0; p < L->npools; p++) buckets_obj_list_free(&src[p]);
  free(src);
  return BUCKETS_OBJ_OK;
}

/* Heals the object in every pool that has it. */
buckets_obj_err buckets_obj_heal(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 const buckets_heal_opts *opts, buckets_heal_result *res) {
  if (L->npools == 1) return buckets_ep_heal(L->pools[0], bucket, object, version_id, opts, res);
  buckets_obj_err result = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  bool found = false;
  buckets_heal_result tmp;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_obj_err err = buckets_ep_heal(L->pools[p], bucket, object, version_id, opts, found ? &tmp : res);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      if (!found) result = err;
      continue;
    }
    if (!found || err) result = err;
    if (found && res) {
      res->healed += tmp.healed;
      res->dangling += tmp.dangling;
      res->versions += tmp.versions;
    }
    found = true;
  }
  return result;
}

const char *buckets_obj_scan_drive(buckets_objlayer *L, const char *bucket, const char *object, int64_t *meta_size) {
  return buckets_ep_scan_drive(L->pools[0], object, bucket, meta_size);
}

/* ---- multipart ------------------------------------------------------------------- */

buckets_obj_err buckets_obj_mpu_new(buckets_objlayer *L, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]) {
  buckets_obj_err err;
  int p = write_pool(L, bucket, object, -1, &err);
  if (p < 0) return err;
  audit_op(L, "NewMultipartUpload", bucket, object, p);
  err = buckets_ep_mpu_new(L->pools[p], bucket, object, meta, nmeta, upload_id);
  if (!err) mp_cache_add(L, bucket, object, upload_id);
  return err;
}

/* The upload lives in exactly one pool: try each until one knows it. */
#define IN_UPLOAD_POOL(op, call)                                               \
  do {                                                                         \
    buckets_obj_err err_ = BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;                     \
    for (size_t p = 0; p < L->npools; p++) {                                   \
      buckets_epool *P = L->pools[p];                                          \
      audit_op(L, op, bucket, object, (int)p);                                         \
      err_ = (call);                                                           \
      if (err_ != BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD) return err_;                 \
    }                                                                          \
    return err_;                                                               \
  } while (0)

buckets_obj_err buckets_obj_mpu_put_part(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out) {
  if (L->npools == 1) {
    audit_op(L, "PutObjectPart", bucket, object, 0);
    return buckets_ep_mpu_put_part(L->pools[0], bucket, object, upload_id, part_number, rd, rd_ud, size, opts, out);
  }
  /* The body can be read only once: find the pool before sending it. */
  for (size_t p = 0; p < L->npools; p++) {
    bool t;
    buckets_part_info *parts = NULL;
    size_t n = 0;
    buckets_obj_err err = buckets_ep_mpu_list_parts(L->pools[p], bucket, object, upload_id, 0, 1, &parts, &n, &t);
    free(parts);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD) continue;
    if (err) return err;
    audit_op(L, "PutObjectPart", bucket, object, (int)p);
    return buckets_ep_mpu_put_part(L->pools[p], bucket, object, upload_id, part_number, rd, rd_ud, size, opts, out);
  }
  return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
}

buckets_obj_err buckets_obj_mpu_list_parts(buckets_objlayer *L, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated) {
  IN_UPLOAD_POOL("ListObjectParts", buckets_ep_mpu_list_parts(P, bucket, object, upload_id, marker, max, parts, n, truncated));
}

static buckets_obj_err mpu_abort(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id) {
  IN_UPLOAD_POOL("AbortMultipartUpload", buckets_ep_mpu_abort(P, bucket, object, upload_id));
}

buckets_obj_err buckets_obj_mpu_abort(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id) {
  buckets_obj_err err = mpu_abort(L, bucket, object, upload_id);
  if (!err) mp_cache_remove(L, upload_id);
  return err;
}

static buckets_obj_err mpu_complete(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                    const buckets_complete_part *parts, size_t nparts, const buckets_checksum *want,
                                    const buckets_complete_opts *co, buckets_object_info *out) {
  IN_UPLOAD_POOL("CompleteMultipartUpload", buckets_ep_mpu_complete(P, bucket, object, upload_id, parts, nparts, want, co, out));
}

buckets_obj_err buckets_obj_mpu_complete(buckets_objlayer *L, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *parts, size_t nparts,
                                         const buckets_checksum *want, const buckets_complete_opts *co,
                                         buckets_object_info *out) {
  buckets_obj_err err = mpu_complete(L, bucket, object, upload_id, parts, nparts, want, co, out);
  if (!err) mp_cache_remove(L, upload_id);
  return err;
}

buckets_obj_err buckets_obj_mpu_stat(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                     buckets_object_info *out) {
  IN_UPLOAD_POOL("GetMultipartInfo", buckets_ep_mpu_stat(P, bucket, object, upload_id, out));
}

static int upload_cmp(const void *a, const void *b) {
  const buckets_upload_info *x = a, *y = b;
  int c = strcmp(x->object, y->object);
  if (c) return c;
  return x->initiated_ns < y->initiated_ns ? -1 : x->initiated_ns > y->initiated_ns;
}

buckets_obj_err buckets_obj_mpu_list_uploads(buckets_objlayer *L, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n) {
  if (!object || !*object) { /* no prefix: this node's upload cache */
    *uploads = NULL;
    *n = 0;
    buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
    if (err) return err;
    mp_cache_list(L, bucket, uploads, n);
    return BUCKETS_OBJ_OK;
  }
  audit_op(L, "ListMultipartUploads", bucket, object, 0);
  if (L->npools == 1) return buckets_ep_mpu_list_uploads(L->pools[0], bucket, object, uploads, n);
  *uploads = NULL;
  *n = 0;
  for (size_t p = 0; p < L->npools; p++) {
    buckets_upload_info *u = NULL;
    size_t k = 0;
    buckets_obj_err err = buckets_ep_mpu_list_uploads(L->pools[p], bucket, object, &u, &k);
    if (err) {
      buckets_upload_info_free(*uploads, *n);
      *uploads = NULL;
      *n = 0;
      return err;
    }
    *uploads = buckets_xrealloc(*uploads, (*n + k + 1) * sizeof(buckets_upload_info));
    memcpy(*uploads + *n, u, k * sizeof(*u));
    *n += k;
    free(u);
  }
  qsort(*uploads, *n, sizeof(**uploads), upload_cmp);
  return BUCKETS_OBJ_OK;
}
