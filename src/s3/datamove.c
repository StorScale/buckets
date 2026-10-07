/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Pool decommission and rebalance (MinIO's cmd/erasure-server-pool-decom.go,
 * erasure-server-pool-rebalance.go, rebalance-admin.go and
 * admin-handlers-pools.go). */
#include "s3/datamove.h"

#include <inttypes.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "admin/info.h"
#include "bucket/metasys.h"
#include "core/auditctx.h"
#include "core/log.h"
#include "core/msgpack.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "core/wpool.h"
#include "dist/peer.h"
#include "notify/event.h"
#include "object/epool.h"
#include "object/object.h"
#include "dist/internode.h"
#include "s3/internal.h"
#include "trace/trace.h"

#define POOL_META "pool.bin"
#define REBAL_META "rebalance.bin"
#define GO_ZERO_SEC BUCKETS_GO_ZERO_TIME_SEC
#define LIST_PAGE 1000

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static char *dupz(const char *s) { return buckets_xstrdup(s ? s : ""); }

/* ---- times as msgp and JSON (0: Go's zero time) ---- */

static void mp_time(buckets_buf *b, int64_t ns) {
  if (!ns) buckets_mp_time_sec(b, GO_ZERO_SEC, 0);
  else buckets_mp_time(b, ns);
}

static bool rd_time(buckets_mp_reader *r, int64_t *ns) {
  if (buckets_mp_read_nil(r)) return true;
  int64_t sec;
  int32_t nsec;
  if (!buckets_mp_read_time_sec(r, &sec, &nsec)) return false;
  *ns = sec == GO_ZERO_SEC && nsec == 0 ? 0 : sec * 1000000000LL + nsec;
  return true;
}

static void json_time(buckets_buf *b, int64_t ns) {
  char t[64];
  if (!ns) snprintf(t, sizeof(t), "0001-01-01T00:00:00Z");
  else buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), t);
  buckets_buf_appendf(b, "\"%s\"", t);
}

static bool rd_str(buckets_mp_reader *r, char **out) {
  if (buckets_mp_read_nil(r)) return true;
  buckets_str s;
  if (!buckets_mp_read_str(r, &s)) return false;
  free(*out);
  *out = buckets_xstrndup(s.p, s.n);
  return true;
}

static bool rd_int(buckets_mp_reader *r, int64_t *v) { return buckets_mp_read_nil(r) || buckets_mp_read_int(r, v); }
static bool rd_uint(buckets_mp_reader *r, uint64_t *v) { return buckets_mp_read_nil(r) || buckets_mp_read_uint(r, v); }

typedef struct {
  char **v;
  size_t n;
} strs;

static void strs_free(strs *s) {
  for (size_t i = 0; i < s->n; i++) free(s->v[i]);
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void strs_add(strs *s, const char *v) {
  s->v = buckets_xrealloc(s->v, (s->n + 1) * sizeof(char *));
  s->v[s->n++] = buckets_xstrdup(v);
}

static bool strs_has(const strs *s, const char *v) {
  for (size_t i = 0; i < s->n; i++)
    if (strcmp(s->v[i], v) == 0) return true;
  return false;
}

static void strs_remove(strs *s, const char *v) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->v[i], v) != 0) continue;
    free(s->v[i]);
    memmove(&s->v[i], &s->v[i + 1], (s->n - i - 1) * sizeof(char *));
    s->n--;
    return;
  }
}

static void strs_copy(strs *dst, const strs *src) {
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < src->n; i++) strs_add(dst, src->v[i]);
}

static void mp_strs(buckets_buf *b, const strs *s) {
  buckets_mp_array(b, (uint32_t)s->n);
  for (size_t i = 0; i < s->n; i++) buckets_mp_cstr(b, s->v[i]);
}

static bool rd_strs(buckets_mp_reader *r, strs *s) {
  if (buckets_mp_read_nil(r)) return true;
  uint32_t n;
  if (!buckets_mp_read_array(r, &n) || n > buckets_mp_remaining(r)) return false;
  strs_free(s);
  for (uint32_t i = 0; i < n; i++) {
    char *v = NULL;
    if (!rd_str(r, &v)) return false;
    strs_add(s, v ? v : "");
    free(v);
  }
  return true;
}

#define MAP_EACH(r, ok, k, body)                                    \
  do {                                                              \
    uint32_t n_##k;                                                 \
    if (buckets_mp_read_nil(r)) break;                              \
    if (!buckets_mp_read_map(r, &n_##k)) {                          \
      ok = false;                                                   \
      break;                                                        \
    }                                                               \
    for (uint32_t i_##k = 0; i_##k < n_##k && ok; i_##k++) {        \
      buckets_str k;                                                \
      if (!buckets_mp_read_str(r, &k)) {                            \
        ok = false;                                                 \
        break;                                                      \
      }                                                             \
      body                                                          \
    }                                                               \
  } while (0)
#define IS(k, lit) buckets_str_eq_c((k), (lit))

/* ---- pool.bin (poolMeta) ------------------------------------------------------------------------------ */

typedef struct {
  int64_t start_time, start_size, total_size, current_size;
  bool complete, failed, canceled;
  strs queued, done;
  char *bucket, *prefix, *object;
  int64_t items, items_failed, bytes_done, bytes_failed;
} decom_info;

typedef struct {
  int64_t id;
  char *cmdline;
  int64_t last_update;
  decom_info *dec;
} pool_status;

typedef struct {
  int64_t version;
  pool_status *pools;
  size_t n;
} pool_meta;

static void decom_free(decom_info *d) {
  if (!d) return;
  strs_free(&d->queued);
  strs_free(&d->done);
  free(d->bucket);
  free(d->prefix);
  free(d->object);
  free(d);
}

static decom_info *decom_clone(const decom_info *d) {
  if (!d) return NULL;
  decom_info *c = buckets_xcalloc(1, sizeof(*c));
  *c = *d;
  strs_copy(&c->queued, &d->queued);
  strs_copy(&c->done, &d->done);
  c->bucket = dupz(d->bucket);
  c->prefix = dupz(d->prefix);
  c->object = dupz(d->object);
  return c;
}

static void pool_meta_free(pool_meta *m) {
  for (size_t i = 0; i < m->n; i++) {
    free(m->pools[i].cmdline);
    decom_free(m->pools[i].dec);
  }
  free(m->pools);
  memset(m, 0, sizeof(*m));
}

static void pool_meta_encode(const pool_meta *m, buckets_buf *out) {
  const uint8_t hdr[4] = {1, 0, 1, 0};
  buckets_buf_append(out, hdr, 4);
  buckets_mp_map(out, 2);
  buckets_mp_cstr(out, "v");
  buckets_mp_int(out, m->version);
  buckets_mp_cstr(out, "pls");
  buckets_mp_array(out, (uint32_t)m->n);
  for (size_t i = 0; i < m->n; i++) {
    const pool_status *p = &m->pools[i];
    buckets_mp_map(out, 4);
    buckets_mp_cstr(out, "id");
    buckets_mp_int(out, p->id);
    buckets_mp_cstr(out, "cl");
    buckets_mp_cstr(out, p->cmdline ? p->cmdline : "");
    buckets_mp_cstr(out, "lu");
    mp_time(out, p->last_update);
    buckets_mp_cstr(out, "dec");
    const decom_info *d = p->dec;
    if (!d) {
      buckets_mp_nil(out);
      continue;
    }
    buckets_mp_map(out, 16);
    buckets_mp_cstr(out, "st");
    mp_time(out, d->start_time);
    buckets_mp_cstr(out, "ss");
    buckets_mp_int(out, d->start_size);
    buckets_mp_cstr(out, "ts");
    buckets_mp_int(out, d->total_size);
    buckets_mp_cstr(out, "cs");
    buckets_mp_int(out, d->current_size);
    buckets_mp_cstr(out, "cmp");
    buckets_mp_bool(out, d->complete);
    buckets_mp_cstr(out, "fl");
    buckets_mp_bool(out, d->failed);
    buckets_mp_cstr(out, "cnl");
    buckets_mp_bool(out, d->canceled);
    buckets_mp_cstr(out, "bkts");
    mp_strs(out, &d->queued);
    buckets_mp_cstr(out, "dbkts");
    mp_strs(out, &d->done);
    buckets_mp_cstr(out, "bkt");
    buckets_mp_cstr(out, d->bucket ? d->bucket : "");
    buckets_mp_cstr(out, "pfx");
    buckets_mp_cstr(out, d->prefix ? d->prefix : "");
    buckets_mp_cstr(out, "obj");
    buckets_mp_cstr(out, d->object ? d->object : "");
    buckets_mp_cstr(out, "id");
    buckets_mp_int(out, d->items);
    buckets_mp_cstr(out, "idf");
    buckets_mp_int(out, d->items_failed);
    buckets_mp_cstr(out, "bd");
    buckets_mp_int(out, d->bytes_done);
    buckets_mp_cstr(out, "bf");
    buckets_mp_int(out, d->bytes_failed);
  }
}

static bool pool_meta_decode(const void *p, size_t n, pool_meta *m, char *err, size_t errlen) {
  memset(m, 0, sizeof(*m));
  const uint8_t *b = p;
  if (n == 0) return true;
  if (n <= 4) return snprintf(err, errlen, "poolMeta: no data"), false;
  if ((b[0] | b[1] << 8) != 1) return snprintf(err, errlen, "poolMeta: unknown format: %d", b[0] | b[1] << 8), false;
  if ((b[2] | b[3] << 8) != 1) return snprintf(err, errlen, "poolMeta: unknown version: %d", b[2] | b[3] << 8), false;
  buckets_mp_reader r = buckets_mp_reader_init(b + 4, n - 4);
  bool ok = true;
  MAP_EACH(&r, ok, k, {
    if (IS(k, "v")) {
      ok = rd_int(&r, &m->version);
    } else if (IS(k, "pls")) {
      uint32_t np;
      if (buckets_mp_read_nil(&r)) continue;
      if (!buckets_mp_read_array(&r, &np) || np > buckets_mp_remaining(&r)) {
        ok = false;
        break;
      }
      m->pools = buckets_xcalloc(np + 1, sizeof(*m->pools));
      for (uint32_t i = 0; i < np && ok; i++) {
        pool_status *ps = &m->pools[m->n++];
        MAP_EACH(&r, ok, k2, {
          if (IS(k2, "id")) {
            ok = rd_int(&r, &ps->id);
          } else if (IS(k2, "cl")) {
            ok = rd_str(&r, &ps->cmdline);
          } else if (IS(k2, "lu")) {
            ok = rd_time(&r, &ps->last_update);
          } else if (IS(k2, "dec")) {
            if (buckets_mp_read_nil(&r)) continue;
            decom_info *d = ps->dec = buckets_xcalloc(1, sizeof(*d));
            MAP_EACH(&r, ok, k3, {
              if (IS(k3, "st")) ok = rd_time(&r, &d->start_time);
              else if (IS(k3, "ss")) ok = rd_int(&r, &d->start_size);
              else if (IS(k3, "ts")) ok = rd_int(&r, &d->total_size);
              else if (IS(k3, "cs")) ok = rd_int(&r, &d->current_size);
              else if (IS(k3, "cmp")) ok = buckets_mp_read_bool(&r, &d->complete);
              else if (IS(k3, "fl")) ok = buckets_mp_read_bool(&r, &d->failed);
              else if (IS(k3, "cnl")) ok = buckets_mp_read_bool(&r, &d->canceled);
              else if (IS(k3, "bkts")) ok = rd_strs(&r, &d->queued);
              else if (IS(k3, "dbkts")) ok = rd_strs(&r, &d->done);
              else if (IS(k3, "bkt")) ok = rd_str(&r, &d->bucket);
              else if (IS(k3, "pfx")) ok = rd_str(&r, &d->prefix);
              else if (IS(k3, "obj")) ok = rd_str(&r, &d->object);
              else if (IS(k3, "id")) ok = rd_int(&r, &d->items);
              else if (IS(k3, "idf")) ok = rd_int(&r, &d->items_failed);
              else if (IS(k3, "bd")) ok = rd_int(&r, &d->bytes_done);
              else if (IS(k3, "bf")) ok = rd_int(&r, &d->bytes_failed);
              else ok = buckets_mp_skip(&r);
            });
          } else {
            ok = buckets_mp_skip(&r);
          }
        });
      }
    } else {
      ok = buckets_mp_skip(&r);
    }
  });
  if (!ok) {
    pool_meta_free(m);
    snprintf(err, errlen, "poolMeta: msgp decode error");
    return false;
  }
  if (m->version != 1) {
    snprintf(err, errlen, "unexpected pool meta version: %" PRId64, m->version);
    pool_meta_free(m);
    return false;
  }
  return true;
}

/* ---- rebalance.bin (rebalanceMeta) ----------------------------------------------------------------------- */

enum { REBAL_NONE, REBAL_STARTED, REBAL_COMPLETED, REBAL_STOPPED, REBAL_FAILED };
static const char *const k_rebal_status[] = {"None", "Started", "Completed", "Stopped", "Failed"};

typedef struct {
  uint64_t init_free, init_capacity;
  strs buckets, rebalanced;
  char *bucket, *object;
  uint64_t objects, versions, bytes;
  bool participating;
  int64_t start_time, end_time;
  uint64_t status;
} rebal_stats;

typedef struct {
  int64_t stopped_at;
  char *id;
  double percent_free_goal;
  rebal_stats **stats; /* NULL entries allowed */
  size_t n;
} rebal_meta;

static void rebal_stats_free(rebal_stats *st) {
  if (!st) return;
  strs_free(&st->buckets);
  strs_free(&st->rebalanced);
  free(st->bucket);
  free(st->object);
  free(st);
}

static rebal_stats *rebal_stats_clone(const rebal_stats *st) {
  if (!st) return NULL;
  rebal_stats *c = buckets_xcalloc(1, sizeof(*c));
  *c = *st;
  strs_copy(&c->buckets, &st->buckets);
  strs_copy(&c->rebalanced, &st->rebalanced);
  c->bucket = dupz(st->bucket);
  c->object = dupz(st->object);
  return c;
}

static void rebal_meta_free(rebal_meta *m) {
  if (!m) return;
  for (size_t i = 0; i < m->n; i++) rebal_stats_free(m->stats[i]);
  free(m->stats);
  free(m->id);
  free(m);
}

static rebal_meta *rebal_meta_clone(const rebal_meta *m) {
  if (!m) return NULL;
  rebal_meta *c = buckets_xcalloc(1, sizeof(*c));
  c->stopped_at = m->stopped_at;
  c->id = dupz(m->id);
  c->percent_free_goal = m->percent_free_goal;
  c->n = m->n;
  c->stats = buckets_xcalloc(m->n + 1, sizeof(*c->stats));
  for (size_t i = 0; i < m->n; i++) c->stats[i] = rebal_stats_clone(m->stats[i]);
  return c;
}

static void rebal_meta_encode(const rebal_meta *m, buckets_buf *out) {
  const uint8_t hdr[4] = {1, 0, 1, 0};
  buckets_buf_append(out, hdr, 4);
  buckets_mp_map(out, 4);
  buckets_mp_cstr(out, "stopTs");
  mp_time(out, m->stopped_at);
  buckets_mp_cstr(out, "id");
  buckets_mp_cstr(out, m->id ? m->id : "");
  buckets_mp_cstr(out, "pf");
  buckets_mp_float64(out, m->percent_free_goal);
  buckets_mp_cstr(out, "rss");
  buckets_mp_array(out, (uint32_t)m->n);
  for (size_t i = 0; i < m->n; i++) {
    const rebal_stats *st = m->stats[i];
    if (!st) {
      buckets_mp_nil(out);
      continue;
    }
    buckets_mp_map(out, 11);
    buckets_mp_cstr(out, "ifs");
    buckets_mp_uint(out, st->init_free);
    buckets_mp_cstr(out, "ic");
    buckets_mp_uint(out, st->init_capacity);
    buckets_mp_cstr(out, "bus");
    mp_strs(out, &st->buckets);
    buckets_mp_cstr(out, "rbs");
    mp_strs(out, &st->rebalanced);
    buckets_mp_cstr(out, "bu");
    buckets_mp_cstr(out, st->bucket ? st->bucket : "");
    buckets_mp_cstr(out, "ob");
    buckets_mp_cstr(out, st->object ? st->object : "");
    buckets_mp_cstr(out, "no");
    buckets_mp_uint(out, st->objects);
    buckets_mp_cstr(out, "nv");
    buckets_mp_uint(out, st->versions);
    buckets_mp_cstr(out, "bs");
    buckets_mp_uint(out, st->bytes);
    buckets_mp_cstr(out, "par");
    buckets_mp_bool(out, st->participating);
    buckets_mp_cstr(out, "inf");
    buckets_mp_map(out, 3);
    buckets_mp_cstr(out, "startTs");
    mp_time(out, st->start_time);
    buckets_mp_cstr(out, "stopTs");
    mp_time(out, st->end_time);
    buckets_mp_cstr(out, "status");
    buckets_mp_uint(out, st->status);
  }
}

static rebal_meta *rebal_meta_decode(const void *p, size_t n, char *err, size_t errlen) {
  const uint8_t *b = p;
  rebal_meta *m = buckets_xcalloc(1, sizeof(*m));
  if (n == 0) return m;
  if (n <= 4) {
    snprintf(err, errlen, "rebalanceMeta: no data");
    rebal_meta_free(m);
    return NULL;
  }
  if ((b[0] | b[1] << 8) != 1 || (b[2] | b[3] << 8) != 1) {
    snprintf(err, errlen, "rebalanceMeta: unknown format or version");
    rebal_meta_free(m);
    return NULL;
  }
  buckets_mp_reader r = buckets_mp_reader_init(b + 4, n - 4);
  bool ok = true;
  MAP_EACH(&r, ok, k, {
    if (IS(k, "stopTs")) {
      ok = rd_time(&r, &m->stopped_at);
    } else if (IS(k, "id")) {
      ok = rd_str(&r, &m->id);
    } else if (IS(k, "pf")) {
      ok = buckets_mp_read_float64(&r, &m->percent_free_goal);
    } else if (IS(k, "rss")) {
      uint32_t np;
      if (buckets_mp_read_nil(&r)) continue;
      if (!buckets_mp_read_array(&r, &np) || np > buckets_mp_remaining(&r)) {
        ok = false;
        break;
      }
      m->stats = buckets_xcalloc(np + 1, sizeof(*m->stats));
      for (uint32_t i = 0; i < np && ok; i++) {
        m->n++;
        if (buckets_mp_read_nil(&r)) continue;
        rebal_stats *st = m->stats[i] = buckets_xcalloc(1, sizeof(*st));
        MAP_EACH(&r, ok, k2, {
          if (IS(k2, "ifs")) {
            ok = rd_uint(&r, &st->init_free);
          } else if (IS(k2, "ic")) {
            ok = rd_uint(&r, &st->init_capacity);
          } else if (IS(k2, "bus")) {
            ok = rd_strs(&r, &st->buckets);
          } else if (IS(k2, "rbs")) {
            ok = rd_strs(&r, &st->rebalanced);
          } else if (IS(k2, "bu")) {
            ok = rd_str(&r, &st->bucket);
          } else if (IS(k2, "ob")) {
            ok = rd_str(&r, &st->object);
          } else if (IS(k2, "no")) {
            ok = rd_uint(&r, &st->objects);
          } else if (IS(k2, "nv")) {
            ok = rd_uint(&r, &st->versions);
          } else if (IS(k2, "bs")) {
            ok = rd_uint(&r, &st->bytes);
          } else if (IS(k2, "par")) {
            ok = buckets_mp_read_bool(&r, &st->participating);
          } else if (IS(k2, "inf")) {
            MAP_EACH(&r, ok, k3, {
              if (IS(k3, "startTs")) ok = rd_time(&r, &st->start_time);
              else if (IS(k3, "stopTs")) ok = rd_time(&r, &st->end_time);
              else if (IS(k3, "status")) ok = rd_uint(&r, &st->status);
              else ok = buckets_mp_skip(&r);
            });
          } else {
            ok = buckets_mp_skip(&r);
          }
        });
      }
    } else {
      ok = buckets_mp_skip(&r);
    }
  });
  if (!ok) {
    snprintf(err, errlen, "rebalanceMeta: msgp decode error");
    rebal_meta_free(m);
    return NULL;
  }
  return m;
}

/* ---- state -------------------------------------------------------------------------------------------------- */

struct buckets_datamove {
  buckets_s3_server *s;
  pthread_mutex_t mu; /* pm, rm, the cancel flags */
  pthread_cond_t cv;
  pool_meta pm;
  _Atomic bool *decom_cancel; /* per pool, while this node decommissions it */
  bool *decom_running;
  rebal_meta *rm;
  _Atomic bool rebal_cancel;
  int rebal_running; /* local pool workers */
  pthread_mutex_t rebal_save_mu;
  bool stop;
  int threads; /* running workers */
  pthread_t init_thread;
  bool init_started;
};

static buckets_objlayer *layer(buckets_datamove *d) { return d->s->layer; }
static size_t npools(buckets_datamove *d) { return layer(d)->npools; }

/* the pool's first drive is on this node (the decommission runs there) */
static bool pool_local(buckets_datamove *d, size_t pool) {
  buckets_cluster_info *ci = d->s->cluster;
  if (!ci || !ci->distributed) return true;
  for (size_t i = 0; i < ci->neps; i++)
    if (ci->eps[i].pool == pool) return ci->eps[i].local;
  return true;
}

static const char *pool_node(buckets_datamove *d, size_t pool) {
  buckets_cluster_info *ci = d->s->cluster;
  if (!ci) return NULL;
  for (size_t i = 0; i < ci->neps; i++)
    if (ci->eps[i].pool == pool) return ci->eps[i].node;
  return NULL;
}

static bool dec_running(const decom_info *di) { return di && !di->complete && !di->failed && !di->canceled; }

/* suspension follows pool.bin; rebalancing follows rebalance.bin (locked) */
static void apply_pool_state_locked(buckets_datamove *d) {
  buckets_objlayer *L = layer(d);
  for (size_t p = 0; p < L->npools; p++) {
    bool susp = p < d->pm.n && d->pm.pools[p].dec != NULL;
    bool reb = false;
    if (d->rm && !d->rm->stopped_at && p < d->rm->n && d->rm->stats[p])
      reb = d->rm->stats[p]->participating && d->rm->stats[p]->status == REBAL_STARTED;
    buckets_objlayer_set_pool_state(L, p, susp, reb);
  }
}

static bool pool_meta_load(buckets_datamove *d, pool_meta *out) {
  buckets_buf data = BUCKETS_BUF_INIT;
  memset(out, 0, sizeof(*out));
  buckets_obj_err err = buckets_obj_pool_config_read(layer(d), 0, POOL_META, &data);
  if (err) {
    buckets_buf_free(&data);
    return err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  }
  char e[256];
  bool ok = pool_meta_decode(data.data, data.len, out, e, sizeof(e));
  if (!ok) buckets_log_warn("decommission: %s", e);
  buckets_buf_free(&data);
  return ok;
}

/* poolMeta.save: the same pool.bin into every pool (lock held) */
static bool pool_meta_save_locked(buckets_datamove *d) {
  buckets_buf data = BUCKETS_BUF_INIT;
  pool_meta_encode(&d->pm, &data);
  bool ok = true;
  for (size_t p = 0; p < npools(d); p++) {
    buckets_obj_err err = buckets_obj_pool_config_write(layer(d), p, POOL_META, data.data, data.len);
    if (err) {
      buckets_log_warn("saving pool.bin for pool index %zu failed with: %s", p, buckets_obj_strerror(err));
      ok = false;
      break;
    }
  }
  buckets_buf_free(&data);
  return ok;
}

static void notify_pool_meta(buckets_datamove *d) {
  if (d->s->peers) buckets_peer_notify_iam(d->s->peers, "pool-meta", "");
}

/* poolMeta.validate and newPoolMeta: the remembered pools, by command line,
 * against the ones given now */
static void pool_meta_reconcile(buckets_datamove *d, pool_meta *old) {
  buckets_objlayer *L = layer(d);
  bool update = old->n != L->npools;
  for (size_t p = 0; p < L->npools && !update; p++) {
    const char *cl = buckets_objlayer_pool_cmdline(L, p);
    bool found = false;
    for (size_t i = 0; i < old->n; i++) {
      if (strcmp(old->pools[i].cmdline ? old->pools[i].cmdline : "", cl) != 0) continue;
      found = true;
      if (i != p) update = true;
    }
    if (!found) update = true;
  }
  for (size_t i = 0; i < old->n; i++)
    if (old->pools[i].dec && old->pools[i].dec->complete)
      for (size_t p = 0; p < L->npools; p++)
        if (strcmp(old->pools[i].cmdline ? old->pools[i].cmdline : "", buckets_objlayer_pool_cmdline(L, p)) == 0)
          buckets_log_warn("pool(%zu) = %s is decommissioned, please remove from server command line", i + 1,
                           old->pools[i].cmdline);
  pool_meta_free(&d->pm); /* the one made with the server, from the command line alone */
  if (!update) {
    d->pm = *old;
    memset(old, 0, sizeof(*old));
    return;
  }
  pool_meta nm = {.version = 1, .pools = buckets_xcalloc(L->npools + 1, sizeof(pool_status)), .n = L->npools};
  for (size_t p = 0; p < L->npools; p++) {
    const char *cl = buckets_objlayer_pool_cmdline(L, p);
    pool_status *ps = &nm.pools[p];
    ps->id = (int64_t)p;
    ps->cmdline = buckets_xstrdup(cl);
    ps->last_update = now_ns();
    for (size_t i = 0; i < old->n; i++) {
      if (strcmp(old->pools[i].cmdline ? old->pools[i].cmdline : "", cl) != 0) continue;
      ps->last_update = old->pools[i].last_update;
      ps->dec = decom_clone(old->pools[i].dec);
      break;
    }
  }
  pool_meta_free(old);
  d->pm = nm;
  if (L->npools > 1) pool_meta_save_locked(d);
}

/* ---- trace ---- */

static void dm_trace(uint64_t type, const char *func, size_t pool, int64_t start, const char *path, const char *err,
                     int64_t bytes) {
  if (!buckets_trace_wanted(type)) return;
  int64_t dur = now_ns() - start;
  char when[64];
  buckets_time_rfc3339_nano(start / 1000000000LL, (long)(start % 1000000000LL), when);
  buckets_buf b = BUCKETS_BUF_INIT, f = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&f, "%s (pool-id=%zu)", func, pool);
  buckets_buf_appendf(&b, "{\"type\":%" PRIu64 ",\"nodename\":", type);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&b, node, strlen(node));
  buckets_buf_append_c(&b, ",\"funcname\":");
  buckets_json_go_string(&b, f.data, f.len);
  buckets_buf_appendf(&b, ",\"time\":\"%s\",\"path\":", when);
  buckets_json_go_string(&b, path, strlen(path));
  buckets_buf_appendf(&b, ",\"dur\":%" PRId64, dur);
  if (bytes) buckets_buf_appendf(&b, ",\"bytes\":%" PRId64, bytes);
  if (err && *err) {
    buckets_buf_append_c(&b, ",\"error\":");
    buckets_json_go_string(&b, err, strlen(err));
  }
  buckets_buf_append_c(&b, "}");
  buckets_trace_meta tm = {.type = type, .dur_ns = dur};
  buckets_trace_publish(&tm, b.data, b.len);
  buckets_buf_free(&b);
  buckets_buf_free(&f);
}

static void audit_move(const char *event, const char *api, const char *bucket, const char *object, const char *vid,
                       const char *err) {
  const char *keys[1] = {"version-id"}, *vals[1] = {vid ? vid : ""};
  buckets_audit_internal(event, api, bucket, object, vid, err, keys, vals, 1);
}

/* ---- walking one pool's keys ---- */

typedef void (*key_fn)(void *ud, const char *bucket, buckets_object_info *v, size_t n);

/* Every key under bucket/prefix in one pool, its versions newest first. */
static bool walk_pool(buckets_datamove *d, size_t pool, const char *bucket, const char *prefix, _Atomic bool *cancel,
                      key_fn fn, void *ud) {
  char *km = NULL, *vm = NULL;
  buckets_object_info *group = NULL;
  size_t ng = 0, cap = 0;
  bool ok = true;
  for (;;) {
    if ((cancel && atomic_load(cancel)) || d->stop) {
      ok = false;
      break;
    }
    buckets_obj_listing l;
    buckets_obj_err err = buckets_obj_pool_list_versions(layer(d), pool, bucket, prefix ? prefix : "", km, vm,
                                                         LIST_PAGE, &l);
    if (err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET) break; /* errVolumeNotFound */
    if (err) {
      buckets_log_warn("listing %s in pool %zu failed with %s", bucket, pool + 1, buckets_obj_strerror(err));
      ok = false;
      break;
    }
    for (size_t i = 0; i < l.nobjects; i++) {
      if (ng && strcmp(group[0].name, l.objects[i].name) != 0) {
        fn(ud, bucket, group, ng);
        for (size_t k = 0; k < ng; k++) buckets_object_info_free(&group[k]);
        ng = 0;
      }
      if (ng == cap) {
        cap = cap ? cap * 2 : 8;
        group = buckets_xrealloc(group, cap * sizeof(*group));
      }
      group[ng++] = l.objects[i];
      memset(&l.objects[i], 0, sizeof(l.objects[i]));
    }
    free(km);
    free(vm);
    km = l.truncated && l.next_marker ? buckets_xstrdup(l.next_marker) : NULL;
    vm = l.truncated && l.next_version_marker ? buckets_xstrdup(l.next_version_marker) : NULL;
    buckets_obj_list_free(&l);
    if (!km) break;
  }
  if (ok && ng) fn(ud, bucket, group, ng);
  for (size_t k = 0; k < ng; k++) buckets_object_info_free(&group[k]);
  free(group);
  free(km);
  free(vm);
  return ok;
}

/* a whole key's versions, copied for a worker */
typedef struct {
  char *bucket;
  buckets_object_info *v;
  size_t n;
} key_job;

static void key_job_free(key_job *k) {
  for (size_t i = 0; i < k->n; i++) buckets_object_info_free(&k->v[i]);
  free(k->v);
  free(k->bucket);
  free(k);
}

static void oi_copy(buckets_object_info *dst, const buckets_object_info *src) {
  memset(dst, 0, sizeof(*dst));
  dst->name = buckets_xstrdup(src->name);
  memcpy(dst->version_id, src->version_id, sizeof(dst->version_id));
  dst->size = src->size;
  dst->mod_time_ns = src->mod_time_ns;
  memcpy(dst->etag, src->etag, sizeof(dst->etag));
  dst->delete_marker = src->delete_marker;
  dst->is_latest = src->is_latest;
  dst->data_blocks = src->data_blocks;
  dst->parity_blocks = src->parity_blocks;
  for (size_t i = 0; i < src->nmeta; i++)
    buckets_xl_kv_set(&dst->meta, &dst->nmeta, src->meta[i].key, src->meta[i].value, src->meta[i].value_len);
  for (size_t i = 0; i < src->nmeta_sys; i++)
    buckets_xl_kv_set(&dst->meta_sys, &dst->nmeta_sys, src->meta_sys[i].key, src->meta_sys[i].value,
                      src->meta_sys[i].value_len);
}

static key_job *key_job_new(const char *bucket, buckets_object_info *v, size_t n) {
  key_job *k = buckets_xcalloc(1, sizeof(*k));
  k->bucket = buckets_xstrdup(bucket);
  k->v = buckets_xcalloc(n, sizeof(*k->v));
  for (size_t i = 0; i < n; i++) oi_copy(&k->v[i], &v[i]);
  k->n = n;
  return k;
}

static bool is_gone(buckets_obj_err e) {
  return e == BUCKETS_OBJ_ERR_NO_SUCH_KEY || e == BUCKETS_OBJ_ERR_NO_SUCH_VERSION || e == BUCKETS_OBJ_ERR_DATA_MOVEMENT;
}

static int worker_count(const char *env, size_t sets) {
  const char *v = getenv(env);
  int n = v ? atoi(v) : 0;
  if (n <= 0) n = (int)sets;
  return n + (int)sets;
}

static size_t pool_sets(buckets_datamove *d, size_t pool) {
  buckets_objlayer *L = layer(d);
  return pool < L->npools ? L->pools[pool]->nsets : 1;
}

/* ---- decommission ---------------------------------------------------------------------------------------------- */

typedef struct {
  buckets_datamove *d;
  size_t pool;
  bool has_repl; /* the bucket replicates (lone markers move too) */
} decom_ctx;

static void decom_count(buckets_datamove *d, size_t pool, int64_t size, bool failed) {
  pthread_mutex_lock(&d->mu);
  decom_info *di = pool < d->pm.n ? d->pm.pools[pool].dec : NULL;
  if (di) {
    if (failed) di->items_failed++, di->bytes_failed += size;
    else di->items++, di->bytes_done += size;
  }
  pthread_mutex_unlock(&d->mu);
}

/* updateAfter: pool.bin saved at most every 30 seconds */
static void decom_track(buckets_datamove *d, size_t pool, const char *bucket, const char *object) {
  pthread_mutex_lock(&d->mu);
  pool_status *ps = pool < d->pm.n ? &d->pm.pools[pool] : NULL;
  bool saved = false;
  if (ps && ps->dec) {
    free(ps->dec->bucket);
    free(ps->dec->object);
    ps->dec->bucket = dupz(bucket);
    ps->dec->object = dupz(object);
    int64_t now = now_ns();
    if (now - ps->last_update >= 30000000000LL) {
      ps->last_update = now;
      saved = pool_meta_save_locked(d);
    }
  }
  pthread_mutex_unlock(&d->mu);
  if (saved) notify_pool_meta(d);
}

typedef struct {
  decom_ctx *c;
  key_job *k;
} decom_task;

/* decommissionEntry: a key's versions, oldest first */
static void decom_entry(void *arg) {
  decom_task *t = arg;
  buckets_datamove *d = t->c->d;
  size_t pool = t->c->pool;
  key_job *k = t->k;
  buckets_objlayer *L = layer(d);
  bool *due = buckets_xcalloc(k->n + 1, sizeof(bool));
  buckets_s3_lifecycle_due(d->s, k->bucket, k->v, k->n, due);
  size_t decommissioned = 0, expired = 0;
  for (size_t j = k->n; j-- > 0;) { /* oldest first */
    buckets_object_info *v = &k->v[j];
    int64_t start = now_ns();
    char path[1200];
    snprintf(path, sizeof(path), "%s %s %s", k->bucket, v->name, v->version_id);
    if (due[j]) {
      expired++;
      decommissioned++;
      dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path,
               "ILM expired object/version will be skipped", v->size);
      continue;
    }
    size_t remaining = k->n - expired;
    if (v->delete_marker && remaining == 1 && !t->c->has_repl) {
      decommissioned++;
      dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path,
               "DELETE marked object with no other non-current versions will be skipped", v->size);
      continue;
    }
    if (v->delete_marker) {
      buckets_obj_err err = buckets_obj_move_version(L, pool, k->bucket, v->name, v->version_id, NULL);
      if (is_gone(err)) {
        dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path, NULL, 0);
        continue;
      }
      dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path,
               err ? buckets_obj_strerror(err) : NULL, v->size);
      if (err) buckets_log_warn("decommission: %s/%s: %s", k->bucket, v->name, buckets_obj_strerror(err));
      decom_count(d, pool, 0, err != BUCKETS_OBJ_OK);
      if (!err) decommissioned++;
      audit_move("decommission", "DecomCopyDeleteMarker", k->bucket, v->name, v->version_id,
                 err ? buckets_obj_strerror(err) : NULL);
      continue;
    }
    bool failure = false, ignore = false;
    for (int attempt = 0; attempt < 3; attempt++) {
      int64_t moved = 0;
      buckets_obj_err err = buckets_obj_move_version(L, pool, k->bucket, v->name, v->version_id, &moved);
      if (is_gone(err)) {
        ignore = true;
        dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path, NULL, 0);
        break;
      }
      audit_move("decommission", "DecomCopyData", k->bucket, v->name, v->version_id,
                 err ? buckets_obj_strerror(err) : NULL);
      if (err) {
        failure = true;
        buckets_log_warn("decommission: %s/%s: %s", k->bucket, v->name, buckets_obj_strerror(err));
        dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path,
                 buckets_obj_strerror(err), v->size);
        continue;
      }
      dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionObject", pool, start, path, NULL, v->size);
      failure = false;
      break;
    }
    if (ignore) continue;
    decom_count(d, pool, v->size, failure);
    if (failure) break; /* out on the first error */
    decommissioned++;
  }
  if (decommissioned == k->n) {
    int64_t start = now_ns();
    buckets_obj_err err = buckets_obj_pool_delete_object(L, pool, k->bucket, k->v[0].name);
    char path[1100];
    snprintf(path, sizeof(path), "%s %s", k->bucket, k->v[0].name);
    dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionRemoveObject", pool, start, path,
             err ? buckets_obj_strerror(err) : NULL, 0);
    audit_move("decommission", "DecomDeleteObject", k->bucket, k->v[0].name, "", err ? buckets_obj_strerror(err) : NULL);
  }
  decom_track(d, pool, k->bucket, k->v[0].name);
  free(due);
  key_job_free(k);
  free(t);
}

typedef struct {
  decom_ctx *c;
  buckets_wpool *wk;
} decom_walk;

static void decom_visit(void *ud, const char *bucket, buckets_object_info *v, size_t n) {
  decom_walk *w = ud;
  decom_task *t = buckets_xcalloc(1, sizeof(*t));
  t->c = w->c;
  t->k = key_job_new(bucket, v, n);
  buckets_wpool_go(w->wk, decom_entry, t);
}

static bool bucket_replicates(buckets_datamove *d, const char *bucket) {
  if (!d->s->meta || strcmp(bucket, BUCKETS_META_BUCKET) == 0) return false;
  buckets_bucket_state *st = buckets_metasys_get(d->s->meta, bucket);
  bool r = st->has_replication;
  buckets_bucket_state_release(st);
  return r;
}

/* decommissionPool: one bucket (with prefix) of the pool */
static bool decom_bucket(buckets_datamove *d, size_t pool, const char *bucket, const char *prefix) {
  decom_ctx c = {d, pool, bucket_replicates(d, bucket)};
  buckets_wpool wk;
  buckets_wpool_init(&wk, worker_count("_MINIO_DECOMMISSION_WORKERS", pool_sets(d, pool)));
  decom_walk w = {&c, &wk};
  bool ok = walk_pool(d, pool, bucket, prefix, &d->decom_cancel[pool], decom_visit, &w);
  buckets_wpool_wait(&wk);
  buckets_wpool_close(&wk);
  return ok;
}

/* getBucketsToDecommission: the configuration first, then every bucket */
static void buckets_to_move(buckets_datamove *d, strs *out, bool with_meta) {
  memset(out, 0, sizeof(*out));
  if (with_meta) {
    strs_add(out, BUCKETS_META_BUCKET "/config");
    strs_add(out, BUCKETS_META_BUCKET "/buckets");
  }
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(layer(d), &bk, &nb) == BUCKETS_OBJ_OK) {
    for (size_t i = 0; i < nb; i++) strs_add(out, bk[i].name);
    buckets_bucket_info_free(bk, nb);
  }
}

static void split_bucket(const char *s, char **bucket, char **prefix) {
  const char *slash = strchr(s, '/');
  *bucket = slash ? buckets_xstrndup(s, (size_t)(slash - s)) : buckets_xstrdup(s);
  *prefix = buckets_xstrdup(slash ? slash + 1 : "");
}

typedef struct {
  buckets_datamove *d;
  size_t pool;
  int64_t found;
} check_ctx;

static void check_visit(void *ud, const char *bucket, buckets_object_info *v, size_t n) {
  check_ctx *c = ud;
  if (strcmp(bucket, BUCKETS_META_BUCKET) == 0 && strstr(v[0].name, ".usage-cache.bin")) return;
  bool *due = buckets_xcalloc(n + 1, sizeof(bool));
  buckets_s3_lifecycle_due(c->d->s, bucket, v, n, due);
  size_t ignored = 0;
  for (size_t i = 0; i < n; i++) ignored += due[i] || v[i].delete_marker;
  c->found += (int64_t)(n - ignored);
  free(due);
}

/* checkAfterDecom: nothing but expired versions and markers may be left */
static bool check_after(buckets_datamove *d, size_t pool, char *err, size_t errlen) {
  strs all;
  buckets_to_move(d, &all, true);
  bool ok = true;
  for (size_t i = 0; i < all.n && ok; i++) {
    char *bucket, *prefix;
    split_bucket(all.v[i], &bucket, &prefix);
    check_ctx c = {d, pool, 0};
    if (!walk_pool(d, pool, bucket, prefix, &d->decom_cancel[pool], check_visit, &c)) {
      snprintf(err, errlen, "listing %s after decommissioning failed", all.v[i]);
      ok = false;
    } else if (c.found > 0) {
      snprintf(err, errlen, "at least %" PRId64 " object(s)/version(s) were found in bucket `%s` after decommissioning",
               c.found, bucket);
      ok = false;
    }
    free(bucket);
    free(prefix);
  }
  strs_free(&all);
  return ok;
}

static void decom_finish(buckets_datamove *d, size_t pool, bool failed) {
  pthread_mutex_lock(&d->mu);
  decom_info *di = pool < d->pm.n ? d->pm.pools[pool].dec : NULL;
  bool changed = false;
  if (di && failed && !di->failed) {
    d->pm.pools[pool].last_update = now_ns();
    di->start_time = 0;
    di->complete = di->canceled = false;
    di->failed = changed = true;
  } else if (di && !failed && !di->complete) {
    d->pm.pools[pool].last_update = now_ns();
    di->complete = changed = true;
    di->failed = di->canceled = false;
  }
  if (changed) pool_meta_save_locked(d);
  pthread_mutex_unlock(&d->mu);
  if (changed) notify_pool_meta(d);
}

/* doDecommissionInRoutine */
static void decom_run(buckets_datamove *d, size_t pool) {
  const char *cmdline = buckets_objlayer_pool_cmdline(layer(d), pool);
  bool failed = false;
  for (;;) {
    pthread_mutex_lock(&d->mu);
    decom_info *di = pool < d->pm.n ? d->pm.pools[pool].dec : NULL;
    char *next = di && di->queued.n ? buckets_xstrdup(di->queued.v[0]) : NULL;
    bool done_already = next && strs_has(&di->done, next);
    pthread_mutex_unlock(&d->mu);
    if (!next) break;
    if (!done_already) {
      char *bucket, *prefix;
      split_bucket(next, &bucket, &prefix);
      int64_t start = now_ns();
      bool ok = decom_bucket(d, pool, bucket, prefix);
      dm_trace(BUCKETS_TRACE_DECOMMISSION, "decommission.DecommissionBucket", pool, start, bucket, ok ? NULL : "failed",
               0);
      free(bucket);
      free(prefix);
      if (!ok) {
        free(next);
        failed = true;
        break;
      }
    }
    pthread_mutex_lock(&d->mu);
    di = pool < d->pm.n ? d->pm.pools[pool].dec : NULL;
    if (di) { /* bucketPop */
      strs_add(&di->done, next);
      strs_remove(&di->queued, next);
      free(di->bucket);
      free(di->prefix);
      free(di->object);
      di->bucket = dupz(""), di->prefix = dupz(""), di->object = dupz("");
      pool_meta_save_locked(d);
    }
    pthread_mutex_unlock(&d->mu);
    free(next);
  }
  if (atomic_load(&d->decom_cancel[pool]) || d->stop) return; /* canceled: pool.bin says so already */
  pthread_mutex_lock(&d->mu);
  decom_info *di = pool < d->pm.n ? d->pm.pools[pool].dec : NULL;
  failed |= di && di->items_failed > 0;
  pthread_mutex_unlock(&d->mu);
  if (!failed) {
    buckets_log_info("Decommissioning complete for pool '%s', verifying for any pending objects", cmdline);
    char err[512];
    if (!check_after(d, pool, err, sizeof(err))) {
      buckets_log_warn("decommission: %s", err);
      failed = true;
    }
  }
  decom_finish(d, pool, failed);
}

typedef struct {
  buckets_datamove *d;
  size_t *pools;
  size_t n;
} decom_args;

static void *decom_main(void *arg) {
  decom_args *a = arg;
  buckets_datamove *d = a->d;
  for (size_t i = 0; i < a->n && !d->stop; i++) {
    decom_run(d, a->pools[i]);
    pthread_mutex_lock(&d->mu);
    d->decom_running[a->pools[i]] = false;
    pthread_mutex_unlock(&d->mu);
  }
  pthread_mutex_lock(&d->mu);
  d->threads--;
  pthread_cond_broadcast(&d->cv);
  pthread_mutex_unlock(&d->mu);
  free(a->pools);
  free(a);
  return NULL;
}

static void decom_spawn(buckets_datamove *d, const size_t *pools, size_t n) {
  decom_args *a = buckets_xcalloc(1, sizeof(*a));
  a->d = d;
  a->pools = buckets_xcalloc(n, sizeof(size_t));
  memcpy(a->pools, pools, n * sizeof(size_t));
  a->n = n;
  pthread_mutex_lock(&d->mu);
  for (size_t i = 0; i < n; i++) {
    atomic_store(&d->decom_cancel[pools[i]], false);
    d->decom_running[pools[i]] = true;
  }
  d->threads++;
  pthread_mutex_unlock(&d->mu);
  pthread_t th;
  pthread_attr_t at;
  pthread_attr_init(&at);
  pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
  if (pthread_create(&th, &at, decom_main, a) != 0) {
    pthread_mutex_lock(&d->mu);
    d->threads--;
    for (size_t i = 0; i < n; i++) d->decom_running[pools[i]] = false;
    pthread_mutex_unlock(&d->mu);
    free(a->pools);
    free(a);
  }
  pthread_attr_destroy(&at);
}

static bool any_decom_running_locked(buckets_datamove *d) {
  for (size_t p = 0; p < d->pm.n; p++)
    if (dec_running(d->pm.pools[p].dec)) return true;
  return false;
}

/* StartDecommission: pool.bin records the pools and the buckets to move */
static bool decom_start(buckets_datamove *d, const size_t *pools, size_t n, bool fresh, buckets_datamove_result *out) {
  strs all;
  buckets_to_move(d, &all, true);
  for (size_t i = 0; i < all.n; i++) {
    char *b, *p;
    split_bucket(all.v[i], &b, &p);
    buckets_obj_heal_bucket(layer(d), b);
    free(b);
    free(p);
  }
  pthread_mutex_lock(&d->mu);
  for (size_t i = 0; i < n; i++) {
    size_t idx = pools[i];
    pool_status *ps = &d->pm.pools[idx];
    if (dec_running(ps->dec)) {
      if (fresh) {
        pthread_mutex_unlock(&d->mu);
        strs_free(&all);
        out->status = 400;
        snprintf(out->code, sizeof(out->code), "XMinioDecommissionNotAllowed");
        snprintf(out->message, sizeof(out->message), "decommission is already in progress");
        return false;
      }
      continue;
    }
    uint64_t ut, uf;
    buckets_objlayer_pool_space(layer(d), idx, &ut, &uf, NULL, NULL);
    decom_free(ps->dec);
    ps->last_update = now_ns();
    ps->dec = buckets_xcalloc(1, sizeof(*ps->dec));
    ps->dec->start_time = ps->last_update;
    ps->dec->start_size = ps->dec->current_size = (int64_t)uf;
    ps->dec->total_size = (int64_t)ut;
    ps->dec->bucket = dupz(""), ps->dec->prefix = dupz(""), ps->dec->object = dupz("");
    for (size_t k = 0; k < all.n; k++) { /* bucketPush */
      if (strs_has(&ps->dec->queued, all.v[k])) continue;
      strs_add(&ps->dec->queued, all.v[k]);
      char *b, *p;
      split_bucket(all.v[k], &b, &p);
      free(ps->dec->bucket);
      free(ps->dec->prefix);
      ps->dec->bucket = b, ps->dec->prefix = p;
    }
  }
  apply_pool_state_locked(d);
  bool saved = pool_meta_save_locked(d);
  pthread_mutex_unlock(&d->mu);
  strs_free(&all);
  if (!saved) {
    out->status = 500;
    snprintf(out->code, sizeof(out->code), "InternalError");
    snprintf(out->message, sizeof(out->message), "We encountered an internal error, please try again.");
    return false;
  }
  notify_pool_meta(d);
  decom_spawn(d, pools, n);
  return true;
}

/* ---- rebalance ----------------------------------------------------------------------------------------------------- */

static bool rebal_load(buckets_datamove *d, rebal_meta **out, bool *missing) {
  *out = NULL;
  if (missing) *missing = false;
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_obj_err err = buckets_obj_pool_config_read(layer(d), 0, REBAL_META, &data);
  if (err) {
    buckets_buf_free(&data);
    if (missing) *missing = err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
    return false;
  }
  char e[256];
  *out = rebal_meta_decode(data.data, data.len, e, sizeof(e));
  if (!*out) buckets_log_warn("rebalance: %s", e);
  buckets_buf_free(&data);
  return *out != NULL;
}

static bool rebal_save(buckets_datamove *d, const rebal_meta *m) {
  buckets_buf data = BUCKETS_BUF_INIT;
  rebal_meta_encode(m, &data);
  buckets_obj_err err = buckets_obj_pool_config_write(layer(d), 0, REBAL_META, data.data, data.len);
  buckets_buf_free(&data);
  if (err) buckets_log_warn("rebalance: saving %s: %s", REBAL_META, buckets_obj_strerror(err));
  return !err;
}

enum { SAVE_STATS, SAVE_STOPPED };

/* saveRebalanceStats: this node's view of one pool, or the stop time, into
 * what is stored */
static bool rebal_save_stats(buckets_datamove *d, size_t pool, int what) {
  pthread_mutex_lock(&d->rebal_save_mu);
  rebal_meta *disk = NULL;
  bool missing = false;
  if (!rebal_load(d, &disk, &missing) && !missing) {
    pthread_mutex_unlock(&d->rebal_save_mu);
    return false;
  }
  pthread_mutex_lock(&d->mu);
  if (!disk) disk = rebal_meta_clone(d->rm);
  if (!disk) {
    pthread_mutex_unlock(&d->mu);
    pthread_mutex_unlock(&d->rebal_save_mu);
    return false;
  }
  if (what == SAVE_STOPPED) {
    disk->stopped_at = now_ns();
  } else if (d->rm && pool < d->rm->n && pool < disk->n) {
    rebal_stats_free(disk->stats[pool]);
    disk->stats[pool] = rebal_stats_clone(d->rm->stats[pool]);
  }
  rebal_meta_free(d->rm);
  d->rm = rebal_meta_clone(disk);
  apply_pool_state_locked(d);
  pthread_mutex_unlock(&d->mu);
  bool ok = rebal_save(d, disk);
  rebal_meta_free(disk);
  pthread_mutex_unlock(&d->rebal_save_mu);
  return ok;
}

static void notify_rebalance(buckets_datamove *d, bool start) {
  if (d->s->peers) buckets_peer_notify_iam(d->s->peers, "rebalance-meta", start ? "start" : "");
}

/* the raw space of every pool's drives */
static void pools_space(buckets_datamove *d, uint64_t *total, uint64_t *avail) {
  for (size_t p = 0; p < npools(d); p++) buckets_objlayer_pool_space(layer(d), p, NULL, NULL, &total[p], &avail[p]);
}

/* checkIfRebalanceDone */
static bool rebal_done(buckets_datamove *d, size_t pool) {
  pthread_mutex_lock(&d->mu);
  bool done = true;
  if (d->rm && pool < d->rm->n && d->rm->stats[pool]) {
    rebal_stats *st = d->rm->stats[pool];
    if (st->status == REBAL_COMPLETED) {
      done = true;
    } else {
      double pfi = st->init_capacity ? (double)(st->init_free + st->bytes) / (double)st->init_capacity : 1;
      done = fabs(pfi - d->rm->percent_free_goal) <= 0.05;
      if (done) {
        st->status = REBAL_COMPLETED;
        st->end_time = now_ns();
      }
    }
  }
  pthread_mutex_unlock(&d->mu);
  return done;
}

static void rebal_update(buckets_datamove *d, size_t pool, const char *bucket, const buckets_object_info *v) {
  pthread_mutex_lock(&d->mu);
  if (d->rm && pool < d->rm->n && d->rm->stats[pool]) {
    rebal_stats *st = d->rm->stats[pool];
    if (v->is_latest) st->objects++;
    st->versions++;
    int data = v->data_blocks, parity = v->parity_blocks;
    if (data <= 0 && pool < layer(d)->npools) { /* listings leave them out: the pool's own */
      const buckets_eset *es = &layer(d)->pools[pool]->sets[0];
      data = (int)es->n - es->parity;
      parity = es->parity;
    }
    if (!v->delete_marker && data > 0) st->bytes += (uint64_t)(v->size * (data + parity) / data);
    free(st->bucket);
    free(st->object);
    st->bucket = dupz(bucket);
    st->object = dupz(v->name);
  }
  pthread_mutex_unlock(&d->mu);
}

typedef struct {
  buckets_datamove *d;
  size_t pool;
  key_job *k;
} rebal_task;

/* rebalanceEntry */
static void rebal_entry(void *arg) {
  rebal_task *t = arg;
  buckets_datamove *d = t->d;
  size_t pool = t->pool;
  key_job *k = t->k;
  buckets_objlayer *L = layer(d);
  if (rebal_done(d, pool) || atomic_load(&d->rebal_cancel)) {
    key_job_free(k);
    free(t);
    return;
  }
  bool *due = buckets_xcalloc(k->n + 1, sizeof(bool));
  buckets_s3_lifecycle_due(d->s, k->bucket, k->v, k->n, due);
  size_t rebalanced = 0, expired = 0;
  for (size_t j = k->n; j-- > 0;) {
    buckets_object_info *v = &k->v[j];
    int64_t start = now_ns();
    char path[1200];
    snprintf(path, sizeof(path), "%s %s %s", k->bucket, v->name, v->version_id);
    if (buckets_object_is_remote(v)) {
      dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceObject", pool, start, path,
               "ILM Tiered version will be skipped for now", v->size);
      continue;
    }
    if (due[j]) {
      expired++;
      dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceObject", pool, start, path,
               "ILM expired object/version will be skipped", v->size);
      continue;
    }
    size_t remaining = k->n - expired;
    if (v->delete_marker && remaining == 1) {
      rebalanced++;
      dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceObject", pool, start, path,
               "DELETE marked object with no other non-current versions will be skipped", v->size);
      continue;
    }
    if (v->delete_marker) {
      buckets_obj_err err = buckets_obj_move_version(L, pool, k->bucket, v->name, v->version_id, NULL);
      if (is_gone(err)) continue;
      dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceObject", pool, start, path,
               err ? buckets_obj_strerror(err) : NULL, v->size);
      if (!err) {
        rebal_update(d, pool, k->bucket, v);
        rebalanced++;
      }
      audit_move("rebalance", "Rebalance:DeleteMarker", k->bucket, v->name, v->version_id,
                 err ? buckets_obj_strerror(err) : NULL);
      continue;
    }
    bool failure = false, ignore = false;
    for (int attempt = 0; attempt < 3; attempt++) {
      buckets_obj_err err = buckets_obj_move_version(L, pool, k->bucket, v->name, v->version_id, NULL);
      if (is_gone(err)) {
        ignore = true;
        break;
      }
      audit_move("rebalance", "RebalanceCopyData", k->bucket, v->name, v->version_id,
                 err ? buckets_obj_strerror(err) : NULL);
      dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceObject", pool, start, path,
               err ? buckets_obj_strerror(err) : NULL, v->size);
      failure = err != BUCKETS_OBJ_OK;
      if (!failure) break;
      buckets_log_warn("rebalance: %s/%s: %s", k->bucket, v->name, buckets_obj_strerror(err));
    }
    if (ignore) continue;
    if (failure) break;
    rebal_update(d, pool, k->bucket, v);
    rebalanced++;
  }
  if (rebalanced == k->n) {
    int64_t start = now_ns();
    buckets_obj_err err = buckets_obj_pool_delete_object(L, pool, k->bucket, k->v[0].name);
    char path[1100];
    snprintf(path, sizeof(path), "%s %s", k->bucket, k->v[0].name);
    dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceRemoveObject", pool, start, path,
             err ? buckets_obj_strerror(err) : NULL, 0);
    audit_move("rebalance", "Rebalance:DeleteObject", k->bucket, k->v[0].name, "", err ? buckets_obj_strerror(err) : NULL);
  }
  free(due);
  key_job_free(k);
  free(t);
}

typedef struct {
  buckets_datamove *d;
  size_t pool;
  buckets_wpool *wk;
} rebal_walk;

static void rebal_visit(void *ud, const char *bucket, buckets_object_info *v, size_t n) {
  rebal_walk *w = ud;
  rebal_task *t = buckets_xcalloc(1, sizeof(*t));
  t->d = w->d;
  t->pool = w->pool;
  t->k = key_job_new(bucket, v, n);
  buckets_wpool_go(w->wk, rebal_entry, t);
}

typedef struct {
  buckets_datamove *d;
  size_t pool;
  bool done;
  pthread_mutex_t mu;
  pthread_cond_t cv;
} rebal_saver;

static void *rebal_saver_main(void *arg) {
  rebal_saver *sv = arg;
  for (;;) {
    pthread_mutex_lock(&sv->mu);
    uint64_t r;
    buckets_random_bytes(&r, sizeof(r));
    int64_t wait = 5000000000LL + (int64_t)(r % 5000000000ULL);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    int64_t t = (int64_t)until.tv_sec * 1000000000LL + until.tv_nsec + wait;
    until.tv_sec = t / 1000000000LL, until.tv_nsec = t % 1000000000LL;
    while (!sv->done && pthread_cond_timedwait(&sv->cv, &sv->mu, &until) == 0) {
    }
    bool done = sv->done;
    pthread_mutex_unlock(&sv->mu);
    if (done) break;
    int64_t start = now_ns();
    bool ok = rebal_save_stats(sv->d, sv->pool, SAVE_STATS);
    dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.SaveMetadata", sv->pool, start, "saved", ok ? NULL : "failed", 0);
  }
  return NULL;
}

/* rebalanceBuckets: the pool's buckets, one after the other */
static void rebal_run(buckets_datamove *d, size_t pool) {
  rebal_saver sv = {.d = d, .pool = pool};
  pthread_mutex_init(&sv.mu, NULL);
  pthread_cond_init(&sv.cv, NULL);
  pthread_t th;
  bool saver = pthread_create(&th, NULL, rebal_saver_main, &sv) == 0;
  buckets_log_info("Pool %zu rebalancing is started", pool + 1);
  bool failed = false;
  for (;;) {
    if (atomic_load(&d->rebal_cancel) || d->stop) break;
    pthread_mutex_lock(&d->mu);
    rebal_stats *st = d->rm && pool < d->rm->n ? d->rm->stats[pool] : NULL;
    char *bucket = st && st->status != REBAL_COMPLETED && st->participating && st->buckets.n
                       ? buckets_xstrdup(st->buckets.v[0])
                       : NULL;
    pthread_mutex_unlock(&d->mu);
    if (!bucket) break;
    buckets_wpool wk;
    buckets_wpool_init(&wk, worker_count("_MINIO_REBALANCE_WORKERS", pool_sets(d, pool)));
    rebal_walk w = {d, pool, &wk};
    int64_t start = now_ns();
    bool ok = walk_pool(d, pool, bucket, "", &d->rebal_cancel, rebal_visit, &w);
    buckets_wpool_wait(&wk);
    buckets_wpool_close(&wk);
    dm_trace(BUCKETS_TRACE_REBALANCE, "rebalance.RebalanceBucket", pool, start, bucket, ok ? NULL : "failed", 0);
    if (!ok && !atomic_load(&d->rebal_cancel) && !d->stop) {
      failed = true;
      free(bucket);
      break;
    }
    if (ok) { /* bucketRebalanceDone */
      pthread_mutex_lock(&d->mu);
      st = d->rm && pool < d->rm->n ? d->rm->stats[pool] : NULL;
      if (st) {
        strs_remove(&st->buckets, bucket);
        strs_add(&st->rebalanced, bucket);
      }
      pthread_mutex_unlock(&d->mu);
    }
    free(bucket);
  }
  bool canceled = atomic_load(&d->rebal_cancel) || d->stop;
  pthread_mutex_lock(&d->mu);
  rebal_stats *st = d->rm && pool < d->rm->n ? d->rm->stats[pool] : NULL;
  if (st) {
    st->status = canceled ? REBAL_STOPPED : failed ? REBAL_FAILED : REBAL_COMPLETED;
    st->end_time = now_ns();
  }
  pthread_mutex_unlock(&d->mu);
  pthread_mutex_lock(&sv.mu);
  sv.done = true;
  pthread_cond_broadcast(&sv.cv);
  pthread_mutex_unlock(&sv.mu);
  if (saver) pthread_join(th, NULL);
  pthread_mutex_destroy(&sv.mu);
  pthread_cond_destroy(&sv.cv);
  if (rebal_save_stats(d, pool, SAVE_STATS)) notify_rebalance(d, false);
  buckets_log_info("Pool %zu rebalancing is done", pool + 1);
}

typedef struct {
  buckets_datamove *d;
  size_t pool;
} rebal_args;

static void *rebal_main(void *arg) {
  rebal_args *a = arg;
  buckets_datamove *d = a->d;
  rebal_run(d, a->pool);
  pthread_mutex_lock(&d->mu);
  d->rebal_running--;
  d->threads--;
  pthread_cond_broadcast(&d->cv);
  pthread_mutex_unlock(&d->mu);
  free(a);
  return NULL;
}

/* StartRebalance: the participating pools local to this node */
static void rebal_start_local(buckets_datamove *d) {
  pthread_mutex_lock(&d->mu);
  if (!d->rm || d->rm->stopped_at || d->rebal_running) {
    pthread_mutex_unlock(&d->mu);
    return;
  }
  atomic_store(&d->rebal_cancel, false);
  size_t n = d->rm->n;
  bool *go = buckets_xcalloc(n + 1, sizeof(bool));
  for (size_t p = 0; p < n; p++)
    go[p] = d->rm->stats[p] && d->rm->stats[p]->status == REBAL_STARTED && d->rm->stats[p]->participating &&
            pool_local(d, p);
  apply_pool_state_locked(d);
  pthread_mutex_unlock(&d->mu);
  for (size_t p = 0; p < n; p++) {
    if (!go[p]) continue;
    rebal_args *a = buckets_xcalloc(1, sizeof(*a));
    a->d = d;
    a->pool = p;
    pthread_mutex_lock(&d->mu);
    d->rebal_running++;
    d->threads++;
    pthread_mutex_unlock(&d->mu);
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&th, &at, rebal_main, a) != 0) {
      pthread_mutex_lock(&d->mu);
      d->rebal_running--;
      d->threads--;
      pthread_mutex_unlock(&d->mu);
      free(a);
    }
    pthread_attr_destroy(&at);
  }
  free(go);
}

/* IsRebalanceStarted (from what is stored) */
static bool rebal_started(buckets_datamove *d) {
  rebal_meta *m = NULL;
  if (rebal_load(d, &m, NULL)) {
    pthread_mutex_lock(&d->mu);
    rebal_meta_free(d->rm);
    d->rm = m;
    apply_pool_state_locked(d);
    pthread_mutex_unlock(&d->mu);
  }
  pthread_mutex_lock(&d->mu);
  bool started = false;
  if (d->rm && !d->rm->stopped_at)
    for (size_t p = 0; p < d->rm->n; p++)
      if (d->rm->stats[p] && d->rm->stats[p]->participating && d->rm->stats[p]->status != REBAL_COMPLETED) started = true;
  pthread_mutex_unlock(&d->mu);
  return started;
}

/* ---- the admin API's side --------------------------------------------------------------------------------------------- */

static void set_err(buckets_datamove_result *out, int status, const char *code, const char *msg) {
  out->status = status;
  snprintf(out->code, sizeof(out->code), "%s", code);
  snprintf(out->message, sizeof(out->message), "%s", msg);
}

/* toAdminAPIErr(errInvalidArgument): the description with the cause */
static void invalid_arg(buckets_datamove_result *out) {
  set_err(out, 400, "XMinioAdminInvalidArgument", "Invalid arguments specified. (Invalid arguments specified)");
}

static void not_implemented(buckets_datamove_result *out) {
  set_err(out, 501, "NotImplemented", "A header you provided implies functionality that is not implemented");
}

/* GetPoolIdx, or the index itself with by-id */
static long pool_index(buckets_datamove *d, const char *v, bool by_id) {
  if (!v) return -1;
  if (by_id) {
    char *end;
    long i = strtol(v, &end, 10);
    return *v && !*end && i >= 0 && (size_t)i < npools(d) ? i : -1;
  }
  for (size_t p = 0; p < npools(d); p++)
    if (strcmp(buckets_objlayer_pool_cmdline(layer(d), p), v) == 0) return (long)p;
  return -1;
}

static void status_json(buckets_datamove *d, size_t idx, buckets_buf *out) {
  uint64_t ut, uf;
  buckets_objlayer_pool_space(layer(d), idx, &ut, &uf, NULL, NULL);
  pthread_mutex_lock(&d->mu);
  pool_status *ps = idx < d->pm.n ? &d->pm.pools[idx] : NULL;
  const char *cl = ps && ps->cmdline ? ps->cmdline : buckets_objlayer_pool_cmdline(layer(d), idx);
  buckets_buf_appendf(out, "{\"id\":%zu,\"cmdline\":", idx);
  buckets_json_go_string(out, cl, strlen(cl));
  buckets_buf_append_c(out, ",\"lastUpdate\":");
  json_time(out, ps ? ps->last_update : 0);
  const decom_info *di = ps ? ps->dec : NULL;
  buckets_buf_append_c(out, ",\"decommissionInfo\":{\"startTime\":");
  json_time(out, di ? di->start_time : 0);
  buckets_buf_appendf(out,
                      ",\"startSize\":%" PRId64 ",\"totalSize\":%" PRIu64 ",\"currentSize\":%" PRIu64
                      ",\"complete\":%s,\"failed\":%s,\"canceled\":%s,\"objectsDecommissioned\":%" PRId64
                      ",\"objectsDecommissionedFailed\":%" PRId64 ",\"bytesDecommissioned\":%" PRId64
                      ",\"bytesDecommissionedFailed\":%" PRId64 "}}",
                      di ? di->start_size : 0, ut, uf, di && di->complete ? "true" : "false",
                      di && di->failed ? "true" : "false", di && di->canceled ? "true" : "false",
                      di ? di->items : 0, di ? di->items_failed : 0, di ? di->bytes_done : 0,
                      di ? di->bytes_failed : 0);
  pthread_mutex_unlock(&d->mu);
}

/* Go's encoding of a float64 (strconv 'f' -1, 'e' below 1e-6 or from 1e21) */
static void go_float(buckets_buf *out, double v) {
  if (v != v || isinf(v)) {
    buckets_buf_append_c(out, "0");
    return;
  }
  char b[64];
  for (int p = 1; p <= 17; p++) {
    snprintf(b, sizeof(b), "%.*g", p, v);
    if (strtod(b, NULL) == v) break;
  }
  double a = fabs(v);
  if (a != 0 && (a < 1e-6 || a >= 1e21)) {
    buckets_buf_append_c(out, b);
    return;
  }
  char *e = strchr(b, 'e');
  if (!e) {
    buckets_buf_append_c(out, b);
    return;
  }
  /* %g chose an exponent Go would not: print the same digits positionally */
  int prec = 0;
  const char *dot = strchr(b, '.');
  if (dot) prec = (int)(e - dot - 1);
  int ex = atoi(e + 1);
  int decimals = prec - ex > 0 ? prec - ex : 0;
  snprintf(b, sizeof(b), "%.*f", decimals, v);
  buckets_buf_append_c(out, b);
}

static void rebal_status_json(buckets_datamove *d, const rebal_meta *m, buckets_buf *out) {
  size_t np = npools(d);
  uint64_t *total = buckets_xcalloc(np + 1, sizeof(uint64_t)), *avail = buckets_xcalloc(np + 1, sizeof(uint64_t));
  pools_space(d, total, avail);
  buckets_buf_append_c(out, "{\"ID\":");
  buckets_json_go_string(out, m->id ? m->id : "", strlen(m->id ? m->id : ""));
  buckets_buf_append_c(out, ",\"pools\":[");
  int64_t now = now_ns();
  for (size_t i = 0; i < m->n; i++) {
    const rebal_stats *st = m->stats[i];
    if (i) buckets_buf_append_c(out, ",");
    buckets_buf_appendf(out, "{\"id\":%zu,\"status\":\"%s\",\"used\":", i,
                        st && st->status < 5 ? k_rebal_status[st->status] : "None");
    double used = i < np && total[i] ? (double)(total[i] - avail[i]) / (double)total[i] : 0;
    go_float(out, used);
    uint64_t objects = 0, versions = 0, bytes = 0;
    int64_t elapsed = 0, eta = 0;
    if (st && st->participating) {
      objects = st->objects, versions = st->versions, bytes = st->bytes;
      double to_move = (double)st->init_capacity * m->percent_free_goal - (double)st->init_free;
      elapsed = now - st->start_time;
      eta = bytes ? (int64_t)(to_move * (double)elapsed / (double)bytes) : INT64_MAX;
      int64_t stop = st->end_time ? st->end_time : m->stopped_at;
      if (stop) {
        elapsed = stop - st->start_time;
        eta = 0;
      }
    }
    buckets_buf_appendf(out,
                        ",\"progress\":{\"objects\":%" PRIu64 ",\"versions\":%" PRIu64 ",\"bytes\":%" PRIu64
                        ",\"bucket\":\"\",\"object\":\"\",\"elapsed\":%" PRId64 ",\"eta\":%" PRId64 "}}",
                        objects, versions, bytes, elapsed, eta);
  }
  buckets_buf_append_c(out, "],\"stoppedAt\":");
  json_time(out, m->stopped_at);
  buckets_buf_append_c(out, "}");
  free(total);
  free(avail);
}

/* sends the operation to the node that runs it (proxyDecommissionRequest,
 * proxyRequestByNodeIndex) */
static bool forward(buckets_datamove *d, size_t pool, const char *op, const buckets_query *q,
                    buckets_datamove_result *out) {
  if (pool_local(d, pool) || !d->s->peers) return false;
  const char *node = pool_node(d, pool);
  if (!node) return false;
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&t, BUCKETS_INTERNODE_PREFIX "peer/datamove?op=");
  buckets_url_encode(&t, op, false);
  const char *pv = buckets_query_get(q, "pool"), *byid = buckets_query_get(q, "by-id");
  if (pv) {
    buckets_buf_append_c(&t, "&pool=");
    buckets_url_encode(&t, pv, false);
  }
  if (byid) {
    buckets_buf_append_c(&t, "&by-id=");
    buckets_url_encode(&t, byid, false);
  }
  buckets_buf_append_char(&t, '\0');
  buckets_buf body = BUCKETS_BUF_INIT;
  int status = 0;
  bool ok = buckets_peer_call(d->s->peers, node, t.data, &status, &body);
  buckets_buf_free(&t);
  if (!ok) {
    buckets_buf_free(&body);
    return false;
  }
  out->status = status;
  if (status >= 300) { /* {"Code":..,"Message":..} */
    char *code = NULL, *msg = NULL;
    const char *cp = body.data ? strstr(body.data, "\"Code\":\"") : NULL;
    const char *mp = body.data ? strstr(body.data, "\"Message\":\"") : NULL;
    if (cp) code = buckets_xstrndup(cp + 8, strcspn(cp + 8, "\""));
    if (mp) msg = buckets_xstrndup(mp + 11, strcspn(mp + 11, "\""));
    snprintf(out->code, sizeof(out->code), "%s", code ? code : "InternalError");
    snprintf(out->message, sizeof(out->message), "%s", msg ? msg : "");
    free(code);
    free(msg);
  } else {
    buckets_buf_append(&out->body, body.data, body.len);
  }
  buckets_buf_free(&body);
  return true;
}

void buckets_datamove_op(buckets_datamove *d, const char *op, const buckets_query *q, bool forwarded,
                         buckets_datamove_result *out) {
  memset(out, 0, sizeof(*out));
  out->status = 200;
  buckets_objlayer *L = layer(d);
  const char *pv = buckets_query_get(q, "pool");
  const char *byid = buckets_query_get(q, "by-id");
  bool by_id = byid && strcmp(byid, "true") == 0;
  if (strcmp(op, "decom-start") == 0) {
    if (L->legacy || L->npools == 1) {
      not_implemented(out);
      return;
    }
    pthread_mutex_lock(&d->mu);
    bool running = any_decom_running_locked(d);
    pthread_mutex_unlock(&d->mu);
    if (running) {
      set_err(out, 400, "XMinioDecommissionNotAllowed", "decommission is already in progress");
      return;
    }
    if (rebal_started(d)) {
      set_err(out, 409, "XMinioAdminRebalanceAlreadyStarted", "Pool rebalance is already started");
      return;
    }
    size_t *idx = buckets_xcalloc(npools(d) + 8, sizeof(size_t));
    size_t n = 0;
    char *list = buckets_xstrdup(pv ? pv : ""), *save = NULL;
    bool bad = false;
    for (char *tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
      long i = pool_index(d, tok, by_id);
      if (i < 0 || n >= npools(d) + 8) {
        bad = true;
        break;
      }
      idx[n++] = (size_t)i;
    }
    free(list);
    if (bad || !n) {
      free(idx);
      {
      invalid_arg(out);
      return;
    }
    }
    if (!forwarded && forward(d, idx[0], op, q, out)) {
      free(idx);
      return;
    }
    decom_start(d, idx, n, true, out);
    free(idx);
    return;
  }
  if (strcmp(op, "decom-cancel") == 0) {
    if (L->legacy) {
      not_implemented(out);
      return;
    }
    long i = pool_index(d, pv, by_id);
    if (i < 0) {
      invalid_arg(out);
      return;
    }
    if (!forwarded && forward(d, (size_t)i, op, q, out)) return;
    if (L->npools == 1) {
      invalid_arg(out);
      return;
    }
    pthread_mutex_lock(&d->mu);
    if (!d->decom_running[i]) {
      pthread_mutex_unlock(&d->mu);
      {
      set_err(out, 500, "InternalError",
                     "We encountered an internal error, please try again.: cause(decommission is not in progress)");
      return;
    }
    }
    atomic_store(&d->decom_cancel[i], true);
    decom_info *di = d->pm.pools[i].dec;
    bool changed = false;
    if (di && !di->canceled) {
      d->pm.pools[i].last_update = now_ns();
      di->start_time = 0;
      di->complete = di->failed = false;
      di->canceled = changed = true;
      pool_meta_save_locked(d);
    }
    pthread_mutex_unlock(&d->mu);
    if (changed) notify_pool_meta(d);
    return;
  }
  if (strcmp(op, "decom-status") == 0) {
    if (L->legacy) {
      not_implemented(out);
      return;
    }
    long i = pool_index(d, pv, by_id);
    if (i < 0) {
      char msg[512];
      snprintf(msg, sizeof(msg), "specified pool '%s' not found, please specify a valid pool", pv ? pv : "");
      {
      set_err(out, 400, "XMinioAdminInvalidArgument", msg);
      return;
    }
    }
    status_json(d, (size_t)i, &out->body);
    buckets_buf_append_c(&out->body, "\n");
    return;
  }
  if (strcmp(op, "pools-list") == 0) {
    if (L->legacy) {
      not_implemented(out);
      return;
    }
    buckets_buf_append_c(&out->body, "[");
    for (size_t p = 0; p < npools(d); p++) {
      if (p) buckets_buf_append_c(&out->body, ",");
      status_json(d, p, &out->body);
    }
    buckets_buf_append_c(&out->body, "]\n");
    return;
  }
  if (strcmp(op, "rebal-start") == 0) {
    if (!forwarded && forward(d, 0, op, q, out)) return;
    if (L->npools == 1) {
      not_implemented(out);
      return;
    }
    pthread_mutex_lock(&d->mu);
    bool running = any_decom_running_locked(d);
    pthread_mutex_unlock(&d->mu);
    if (running)
      {
      set_err(out, 400, "XMinioRebalanceNotAllowed", "Rebalance cannot be started, decommission is already in progress");
      return;
    }
    if (rebal_started(d)) {
      set_err(out, 409, "XMinioAdminRebalanceAlreadyStarted", "Pool rebalance is already started");
      return;
    }
    strs buckets;
    buckets_to_move(d, &buckets, false);
    size_t np = npools(d);
    uint64_t *total = buckets_xcalloc(np + 1, sizeof(uint64_t)), *avail = buckets_xcalloc(np + 1, sizeof(uint64_t));
    pools_space(d, total, avail);
    uint64_t cap = 0, fr = 0;
    for (size_t p = 0; p < np; p++) cap += total[p], fr += avail[p];
    rebal_meta *m = buckets_xcalloc(1, sizeof(*m));
    char id[23];
    buckets_shortuuid(id);
    m->id = buckets_xstrdup(id);
    m->percent_free_goal = cap ? (double)fr / (double)cap : 0;
    m->n = np;
    m->stats = buckets_xcalloc(np + 1, sizeof(*m->stats));
    int64_t now = now_ns();
    for (size_t p = 0; p < np; p++) {
      rebal_stats *st = m->stats[p] = buckets_xcalloc(1, sizeof(*st));
      strs_copy(&st->buckets, &buckets);
      st->init_free = avail[p];
      st->init_capacity = total[p];
      st->bucket = dupz(""), st->object = dupz("");
      double pfi = total[p] ? (double)avail[p] / (double)total[p] : 1;
      if (pfi < m->percent_free_goal) {
        st->participating = true;
        st->start_time = now;
        st->status = REBAL_STARTED;
      }
    }
    free(total);
    free(avail);
    strs_free(&buckets);
    if (!rebal_save(d, m)) {
      rebal_meta_free(m);
      {
      set_err(out, 500, "InternalError", "We encountered an internal error, please try again.");
      return;
    }
    }
    pthread_mutex_lock(&d->mu);
    rebal_meta_free(d->rm);
    d->rm = m;
    pthread_mutex_unlock(&d->mu);
    rebal_start_local(d);
    buckets_buf_append_c(&out->body, "{\"id\":");
    buckets_json_go_string(&out->body, id, strlen(id));
    buckets_buf_append_c(&out->body, "}");
    notify_rebalance(d, true);
    return;
  }
  if (strcmp(op, "rebal-status") == 0) {
    if (!forwarded && forward(d, 0, op, q, out)) return;
    rebal_meta *m = NULL;
    if (!rebal_load(d, &m, NULL))
      {
      set_err(out, 404, "XMinioAdminRebalanceNotStarted", "Pool rebalance is not started");
      return;
    }
    rebal_status_json(d, m, &out->body);
    buckets_buf_append_c(&out->body, "\n");
    rebal_meta_free(m);
    return;
  }
  if (strcmp(op, "rebal-stop") == 0) {
    if (L->npools == 1) {
      not_implemented(out);
      return;
    }
    if (d->s->peers) buckets_peer_notify_iam(d->s->peers, "rebalance-stop", "");
    buckets_datamove_stop_rebalance(d);
    rebal_save_stats(d, 0, SAVE_STOPPED);
    notify_rebalance(d, false);
    return;
  }
  invalid_arg(out);
}

/* ---- peers and startup ---------------------------------------------------------------------------------------- */

void buckets_datamove_reload_pool_meta(buckets_datamove *d) {
  pool_meta m;
  if (!pool_meta_load(d, &m)) return;
  pthread_mutex_lock(&d->mu);
  if (m.n) {
    pool_meta_free(&d->pm);
    d->pm = m;
    if (d->pm.n < npools(d)) { /* keep one entry per pool */
      d->pm.pools = buckets_xrealloc(d->pm.pools, (npools(d) + 1) * sizeof(pool_status));
      for (size_t p = d->pm.n; p < npools(d); p++) memset(&d->pm.pools[p], 0, sizeof(pool_status));
      d->pm.n = npools(d);
    }
  } else {
    pool_meta_free(&m);
  }
  apply_pool_state_locked(d);
  pthread_mutex_unlock(&d->mu);
}

void buckets_datamove_reload_rebalance(buckets_datamove *d, bool start) {
  rebal_meta *m = NULL;
  if (!rebal_load(d, &m, NULL)) return;
  pthread_mutex_lock(&d->mu);
  rebal_meta_free(d->rm);
  d->rm = m;
  apply_pool_state_locked(d);
  pthread_mutex_unlock(&d->mu);
  if (start) rebal_start_local(d);
}

void buckets_datamove_stop_rebalance(buckets_datamove *d) {
  atomic_store(&d->rebal_cancel, true);
  pthread_mutex_lock(&d->mu);
  while (d->rebal_running) pthread_cond_wait(&d->cv, &d->mu);
  pthread_mutex_unlock(&d->mu);
}

static bool init_sleep(buckets_datamove *d, int64_t ns) {
  pthread_mutex_lock(&d->mu);
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  int64_t t = (int64_t)until.tv_sec * 1000000000LL + until.tv_nsec + ns;
  until.tv_sec = t / 1000000000LL, until.tv_nsec = t % 1000000000LL;
  while (!d->stop && pthread_cond_timedwait(&d->cv, &d->mu, &until) == 0) {
  }
  bool go = !d->stop;
  pthread_mutex_unlock(&d->mu);
  return go;
}

/* erasureServerPools.Init: rebalance resumes now, a decommission (of pools
 * this node runs) after a pause (_BUCKETS_DECOM_RESUME_DELAY, 3m) */
static void *init_main(void *arg) {
  buckets_datamove *d = arg;
  rebal_meta *rm = NULL;
  if (rebal_load(d, &rm, NULL)) {
    pthread_mutex_lock(&d->mu);
    d->rm = rm;
    /* one stats entry per pool */
    if (d->rm->n < npools(d)) {
      d->rm->stats = buckets_xrealloc(d->rm->stats, (npools(d) + 1) * sizeof(*d->rm->stats));
      for (size_t p = d->rm->n; p < npools(d); p++) d->rm->stats[p] = buckets_xcalloc(1, sizeof(rebal_stats));
      d->rm->n = npools(d);
    }
    pthread_mutex_unlock(&d->mu);
    rebal_start_local(d);
  }
  pool_meta old;
  if (!pool_meta_load(d, &old)) memset(&old, 0, sizeof(old));
  pthread_mutex_lock(&d->mu);
  pool_meta_reconcile(d, &old);
  apply_pool_state_locked(d);
  size_t *resume = buckets_xcalloc(d->pm.n + 1, sizeof(size_t));
  size_t nr = 0;
  for (size_t p = 0; p < d->pm.n; p++) {
    const decom_info *di = d->pm.pools[p].dec;
    if (di && !di->complete && !di->canceled) resume[nr++] = p;
  }
  pthread_mutex_unlock(&d->mu);
  pool_meta_free(&old);
  if (nr && pool_local(d, resume[0])) {
    const char *v = getenv("_BUCKETS_DECOM_RESUME_DELAY");
    int64_t delay = 180000000000LL;
    if (v) buckets_go_duration_parse(v, &delay);
    if (init_sleep(d, delay)) {
      buckets_datamove_result r = {0};
      decom_start(d, resume, nr, false, &r);
      buckets_buf_free(&r.body);
    }
  }
  free(resume);
  return NULL;
}

buckets_datamove *buckets_datamove_new(buckets_s3_server *s) {
  buckets_datamove *d = buckets_xcalloc(1, sizeof(*d));
  d->s = s;
  pthread_mutex_init(&d->mu, NULL);
  pthread_mutex_init(&d->rebal_save_mu, NULL);
  pthread_cond_init(&d->cv, NULL);
  size_t np = s->layer->npools;
  d->decom_cancel = buckets_xcalloc(np + 1, sizeof(*d->decom_cancel));
  d->decom_running = buckets_xcalloc(np + 1, sizeof(bool));
  d->pm.version = 1;
  d->pm.n = np;
  d->pm.pools = buckets_xcalloc(np + 1, sizeof(pool_status));
  for (size_t p = 0; p < np; p++) {
    d->pm.pools[p].id = (int64_t)p;
    d->pm.pools[p].cmdline = buckets_xstrdup(buckets_objlayer_pool_cmdline(s->layer, p));
  }
  d->init_started = pthread_create(&d->init_thread, NULL, init_main, d) == 0;
  return d;
}

void buckets_datamove_free(buckets_datamove *d) {
  if (!d) return;
  buckets_datamove_stop(d);
  pool_meta_free(&d->pm);
  rebal_meta_free(d->rm);
  free((void *)d->decom_cancel);
  free(d->decom_running);
  pthread_mutex_destroy(&d->mu);
  pthread_mutex_destroy(&d->rebal_save_mu);
  pthread_cond_destroy(&d->cv);
  free(d);
}

void buckets_datamove_stop(buckets_datamove *d) {
  if (!d) return;
  pthread_mutex_lock(&d->mu);
  d->stop = true;
  atomic_store(&d->rebal_cancel, true);
  for (size_t p = 0; p < npools(d); p++) atomic_store(&d->decom_cancel[p], true);
  pthread_cond_broadcast(&d->cv);
  pthread_mutex_unlock(&d->mu);
  if (d->init_started) pthread_join(d->init_thread, NULL);
  d->init_started = false;
  pthread_mutex_lock(&d->mu);
  while (d->threads) pthread_cond_wait(&d->cv, &d->mu);
  pthread_mutex_unlock(&d->mu);
}
