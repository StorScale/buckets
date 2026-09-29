/* Erasure-coded object layer over sets of drives (MinIO cmd/erasure-object.go,
 * erasure-multipart.go, erasure-sets.go, erasure-server-pool.go subset).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <pthread.h>
#ifdef __APPLE__
#include <pthread/qos.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/auditctx.h"
#include "core/buf.h"
#include "notify/event.h"
#include "core/timefmt.h"
#include "trace/trace.h"
#include "core/log.h"
#include "core/msgpack.h"
#include "core/pool.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/highwayhash.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "erasure/layout.h"
#include "erasure/rs.h"
#include "object/nslock.h"
#include "object/epool.h"
#include "object/object.h"
#include "bucket/replication.h"
#include "bucket/targets.h"

#define XL_META "xl.meta"
#define DIR_SUFFIX "__XLDIR__"
#define HASH_LEN 32
#define MAX_SET 16
#define ACTUAL_SIZE_KEY "X-Minio-Internal-actual-size"

const char *buckets_obj_strerror(buckets_obj_err e) {
  static const char *const names[] = {
      "ok", "no such bucket", "no such key", "no such version", "invalid object name", "object name too long",
      "object name has a leading slash", "object name conflicts with a directory", "content-md5 mismatch",
      "content-sha256 mismatch", "incomplete body", "data source failed", "corrupt data", "I/O error",
      "no such upload", "invalid part", "parts out of order", "part too small", "checksum mismatch",
      "read quorum not met", "write quorum not met", "bucket exists", "bucket not empty",
      "namespace lock timed out", "method not allowed on a delete marker", "remote tier failure",
      "storage full", "data movement would overwrite the source pool"};
  return (size_t)e < BUCKETS_ARRAY_LEN(names) ? names[e] : "unknown";
}

/* ---- names ----------------------------------------------------------------- */

static bool valid_utf8(const unsigned char *s) {
  while (*s) {
    if (*s < 0x80) {
      s++;
      continue;
    }
    int n = (*s & 0xe0) == 0xc0 ? 1 : (*s & 0xf0) == 0xe0 ? 2 : (*s & 0xf8) == 0xf0 ? 3 : -1;
    if (n < 0 || (n == 1 && *s < 0xc2)) return false;
    unsigned cp = *s & (0x3f >> n);
    for (int i = 1; i <= n; i++) {
      if ((s[i] & 0xc0) != 0x80) return false;
      cp = cp << 6 | (s[i] & 0x3f);
    }
    if ((n == 2 && cp < 0x800) || (n == 3 && (cp < 0x10000 || cp > 0x10ffff)) || (cp >= 0xd800 && cp <= 0xdfff)) {
      return false;
    }
    s += n + 1;
  }
  return true;
}

buckets_obj_err buckets_obj_check_name(const char *object) {
  size_t n = strlen(object);
  if (n == 0) return BUCKETS_OBJ_ERR_INVALID_NAME;
  if (n > BUCKETS_MAX_OBJECT_NAME) return BUCKETS_OBJ_ERR_NAME_TOO_LONG;
  if (object[0] == '/') return BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH;
  if (strstr(object, "//") || !valid_utf8((const unsigned char *)object)) return BUCKETS_OBJ_ERR_INVALID_NAME;
  for (const char *p = object; *p;) {
    const char *seg = p;
    while (*p && *p != '/') p++;
    size_t len = (size_t)(p - seg);
    if ((len == 1 && seg[0] == '.') || (len == 2 && seg[0] == '.' && seg[1] == '.')) {
      return BUCKETS_OBJ_ERR_INVALID_NAME;
    }
    if (*p == '/') p++;
  }
  if (strstr(object, DIR_SUFFIX)) return BUCKETS_OBJ_ERR_INVALID_NAME;
  return BUCKETS_OBJ_OK;
}

/* Path of an object inside its bucket (trailing-slash keys -> name__XLDIR__). */
static char *obj_path(const char *object) {
  buckets_buf p = BUCKETS_BUF_INIT;
  size_t n = strlen(object);
  if (n && object[n - 1] == '/') buckets_buf_appendf(&p, "%.*s" DIR_SUFFIX, (int)(n - 1), object);
  else buckets_buf_append_c(&p, object);
  return p.data;
}

static char *join(const char *a, const char *b) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "%s/%s", a, b);
  return p.data;
}

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* ---- layer ----------------------------------------------------------------- */

buckets_epool *buckets_epool_new(struct buckets_objlayer *top, size_t index, buckets_format_result *f, int parity) {
  buckets_epool *L = buckets_xcalloc(1, sizeof(*L));
  L->top = top;
  L->index = index;
  L->nsets = f->nsets;
  L->sets = buckets_xcalloc(f->nsets, sizeof(buckets_eset));
  L->nall = f->nsets * f->set_size;
  L->all = f->slots;
  f->slots = NULL;
  for (size_t s = 0; s < f->nsets; s++) {
    L->sets[s].drives = L->all + s * f->set_size;
    L->sets[s].n = f->set_size;
    int p = parity >= 0 ? parity : buckets_default_parity((int)f->set_size);
    if ((size_t)p > f->set_size / 2) p = (int)(f->set_size / 2);
    L->sets[s].parity = p;
  }
  memcpy(L->deployment_id, f->deployment_id_bytes, 16);
  memcpy(L->deployment_id_str, f->deployment_id, sizeof(L->deployment_id_str));
  return L;
}

void buckets_epool_free(buckets_epool *L) {
  if (!L) return;
  for (size_t i = 0; i < L->nall; i++) buckets_drive_close(L->all[i]);
  free(L->all);
  free(L->sets);
  free(L);
}

size_t buckets_ep_online(const buckets_epool *L) {
  size_t c = 0;
  for (size_t i = 0; i < L->nall; i++) c += L->all[i] != NULL;
  return c;
}

buckets_eset *buckets_ep_set_for(buckets_epool *L, const char *object) {
  return &L->sets[L->nsets == 1 ? 0 : buckets_set_index(object, L->nsets, L->deployment_id)];
}

static int set_data(const buckets_eset *s) { return (int)s->n - s->parity; }
static int write_quorum(int data, int parity) { return data + (data == parity ? 1 : 0); }

/* ---- buckets --------------------------------------------------------------- */

void buckets_bucket_info_free(buckets_bucket_info *b, size_t n) {
  for (size_t i = 0; i < n; i++) free(b[i].name);
  free(b);
}

static size_t bucket_quorum(const buckets_epool *L) { return L->nall / 2 + 1; }

buckets_obj_err buckets_ep_stat_bucket(buckets_epool *L, const char *bucket) {
  size_t ok = 0, missing = 0;
  for (size_t i = 0; i < L->nall; i++) {
    if (!L->all[i]) continue;
    buckets_drive_err e = buckets_drive_stat_vol(L->all[i], bucket, NULL);
    if (e == BUCKETS_DRIVE_OK) ok++;
    else if (e == BUCKETS_DRIVE_ERR_NOT_FOUND) missing++;
  }
  if (ok && ok >= missing) return BUCKETS_OBJ_OK;
  if (missing) return BUCKETS_OBJ_ERR_NO_SUCH_BUCKET;
  return BUCKETS_OBJ_ERR_READ_QUORUM;
}

buckets_obj_err buckets_ep_make_bucket(buckets_epool *L, const char *bucket) {
  size_t made = 0, exists = 0;
  for (size_t i = 0; i < L->nall; i++) {
    if (!L->all[i]) continue;
    buckets_drive_err e = buckets_drive_make_vol(L->all[i], bucket);
    if (e == BUCKETS_DRIVE_OK) made++;
    else if (e == BUCKETS_DRIVE_ERR_EXISTS) exists++;
  }
  if (exists && exists >= made) return BUCKETS_OBJ_ERR_BUCKET_EXISTS;
  return made + exists >= bucket_quorum(L) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

buckets_obj_err buckets_ep_list_buckets(buckets_epool *L, buckets_bucket_info **out, size_t *n) {
  *out = NULL;
  *n = 0;
  /* Union across drives; a bucket counts if a quorum of drives has it. */
  size_t cap = 0;
  size_t *votes = NULL;
  bool any = false;
  for (size_t i = 0; i < L->nall; i++) {
    if (!L->all[i]) continue;
    buckets_vol_info *v;
    size_t nv;
    if (buckets_drive_list_vols(L->all[i], &v, &nv) != BUCKETS_DRIVE_OK) continue;
    any = true;
    for (size_t k = 0; k < nv; k++) {
      size_t j = 0;
      for (; j < *n; j++) {
        if (strcmp((*out)[j].name, v[k].name) == 0) break;
      }
      if (j == *n) {
        if (*n == cap) {
          cap = cap ? cap * 2 : 16;
          *out = buckets_xrealloc(*out, cap * sizeof(buckets_bucket_info));
          votes = buckets_xrealloc(votes, cap * sizeof(size_t));
        }
        (*out)[*n] = (buckets_bucket_info){buckets_xstrdup(v[k].name), v[k].created};
        votes[(*n)++] = 0;
      }
      votes[j]++;
    }
    buckets_vol_info_free(v, nv);
  }
  size_t need = L->nall / 2 ? L->nall / 2 : 1, w = 0;
  for (size_t j = 0; j < *n; j++) {
    if (votes[j] >= need) (*out)[w++] = (*out)[j];
    else free((*out)[j].name);
  }
  *n = w;
  free(votes);
  return any ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_READ_QUORUM;
}

/* ---- namespace locks ------------------------------------------------------ */

/* How long a request waits for a namespace lock: the floor of MinIO's
 * globalOperationTimeout (a dynamic 10 minutes, adapting down to 5), so a
 * writer outlasts a stalled reader (dropped after 60s) as with MinIO.
 * BUCKETS_LOCK_TIMEOUT (seconds) overrides it. */
static int lock_timeout_ms(void) {
  static int ms;
  if (!ms) {
    const char *e = getenv("BUCKETS_LOCK_TIMEOUT");
    int v = e ? atoi(e) : 0;
    ms = v > 0 ? v * 1000 : 5 * 60 * 1000;
  }
  return ms;
}
#define LOCK_TIMEOUT_MS lock_timeout_ms()

static buckets_nslock_entry *lock_ns(buckets_epool *L, const char *vol, const char *path, bool write) {
  buckets_nslock_entry *e = buckets_nslock_lock(L->top->locks, vol, path, write, LOCK_TIMEOUT_MS);
  if (!e) buckets_log_warn("timed out waiting for %s lock on %s/%s", write ? "write" : "read", vol, path);
  return e;
}

/* ---- healing hand-off --------------------------------------------------- */

/* An object that is readable but not whole on every online drive. version_id
 * is the canonical string ("null" for the null version). */
static void report_degraded(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                            bool deep) {
  if (L->top->on_degraded) {
    L->top->on_degraded(L->top->on_degraded_ud, bucket, object, version_id, deep);
  }
}

/* ---- metadata quorum ------------------------------------------------------- */

typedef struct {
  buckets_xlmeta x;
  bool loaded;  /* xl.meta parsed */
  bool missing; /* no xl.meta on this drive */
} dmeta;

typedef struct {
  buckets_eset *s;
  const char *vol, *path;
  dmeta *m;
} load_ctx;

static void load_one(void *ctx, size_t i) {
  load_ctx *c = ctx;
  dmeta *m = &c->m[i];
  memset(m, 0, sizeof(*m));
  if (!c->s->drives[i]) return;
  buckets_buf raw = BUCKETS_BUF_INIT;
  buckets_drive_err e = buckets_drive_read_all(c->s->drives[i], c->vol, c->path, &raw);
  if (e == BUCKETS_DRIVE_ERR_NOT_FOUND) m->missing = true;
  else if (e == BUCKETS_DRIVE_OK) m->loaded = buckets_xlmeta_parse(raw.data, raw.len, &m->x) == BUCKETS_XL_OK;
  buckets_buf_free(&raw);
}

static void load_metas(buckets_eset *s, const char *vol, const char *dir, dmeta *m) {
  char *path = join(dir, XL_META);
  load_ctx c = {s, vol, path, m};
  buckets_io_parallel(s->n, load_one, &c);
  free(path);
}

static void free_metas(dmeta *m, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (m[i].loaded) buckets_xlmeta_free(&m[i].x);
  }
}

static bool same_header(const buckets_xl_header *a, const buckets_xl_header *b) {
  return memcmp(a->version_id, b->version_id, 16) == 0 && a->mod_time == b->mod_time &&
         memcmp(a->signature, b->signature, 4) == 0 && a->type == b->type;
}

/* The newest version that is not a free version, or -1. */
static long first_visible(const buckets_xlmeta *x) {
  for (size_t k = 0; k < x->n; k++)
    if (!buckets_xl_is_free_version(&x->versions[k].hdr)) return (long)k;
  return -1;
}

/* Picks the version (latest, or by ID) that enough drives agree on.
 * vidx[i] is the version's index on drive i, or -1 if drive i disagrees. */
static buckets_obj_err quorum_version(const dmeta *m, size_t n, const char *version_id, buckets_xl_object *out,
                                      long *vidx) {
  uint8_t want_id[16];
  bool by_id = version_id && *version_id;
  if (by_id && !buckets_xl_version_id_parse(version_id, want_id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  const buckets_xl_header *cand[MAX_SET];
  size_t missing = 0;
  for (size_t i = 0; i < n; i++) {
    cand[i] = NULL;
    vidx[i] = -1;
    if (m[i].missing) missing++;
    if (!m[i].loaded) continue;
    long k = by_id ? buckets_xlmeta_find(&m[i].x, want_id) : first_visible(&m[i].x);
    if (k < 0) {
      missing++;
      continue;
    }
    cand[i] = &m[i].x.versions[k].hdr;
    vidx[i] = k;
  }
  int best = -1;
  size_t best_votes = 0;
  for (size_t i = 0; i < n; i++) {
    if (!cand[i]) continue;
    size_t votes = 0;
    for (size_t j = 0; j < n; j++) votes += cand[j] && same_header(cand[i], cand[j]);
    size_t need = cand[i]->type == BUCKETS_XL_TYPE_OBJECT && cand[i]->ec_m ? cand[i]->ec_m : n / 2 + (n == 1);
    if (votes < need) continue;
    if (best < 0 || cand[i]->mod_time > cand[best]->mod_time ||
        (cand[i]->mod_time == cand[best]->mod_time && votes > best_votes)) {
      best = (int)i;
      best_votes = votes;
    }
  }
  if (best < 0) {
    if (missing * 2 >= n || missing == n) {
      return by_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
    }
    return BUCKETS_OBJ_ERR_READ_QUORUM;
  }
  for (size_t i = 0; i < n; i++) {
    if (cand[i] && !same_header(cand[i], cand[best])) vidx[i] = -1;
    if (!cand[i]) vidx[i] = -1;
  }
  if (buckets_xl_object_decode(&m[best].x.versions[vidx[best]], out) != BUCKETS_XL_OK) return BUCKETS_OBJ_ERR_CORRUPT;
  return BUCKETS_OBJ_OK;
}

/* ---- object info ------------------------------------------------------------ */

/* Where the resolved version sits among its key's versions (FileInfo's
 * IsLatest, NumVersions and SuccessorModTime). */
static void fill_position(buckets_object_info *oi, const dmeta *m, const long *vidx, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (vidx[i] < 0) continue;
    const buckets_xlmeta *x = &m[i].x;
    long prev = -1; /* free versions are not counted */
    size_t visible = 0;
    for (size_t k = 0; k < x->n; k++) {
      if (buckets_xl_is_free_version(&x->versions[k].hdr)) continue;
      visible++;
      if ((long)k < vidx[i]) prev = (long)k;
    }
    oi->is_latest = prev < 0;
    oi->num_versions = visible;
    oi->successor_mod_time_ns = prev >= 0 ? x->versions[prev].hdr.mod_time : 0;
    return;
  }
}

void buckets_object_info_free(buckets_object_info *oi) {
  free(oi->name);
  for (size_t i = 0; i < oi->nmeta; i++) {
    free(oi->meta[i].key);
    free(oi->meta[i].value);
  }
  free(oi->meta);
  for (size_t i = 0; i < oi->nmeta_sys; i++) {
    free(oi->meta_sys[i].key);
    free(oi->meta_sys[i].value);
  }
  free(oi->meta_sys);
  free(oi->checksum);
  for (size_t i = 0; i < oi->nparts; i++) free(oi->parts[i].index);
  free(oi->parts);
  memset(oi, 0, sizeof(*oi));
}

const char *buckets_object_meta(const buckets_object_info *oi, const char *key) {
  const buckets_xl_kv *kv = buckets_xl_kv_get(oi->meta, oi->nmeta, key);
  return kv ? (const char *)kv->value : NULL;
}

const buckets_xl_kv *buckets_object_sys(const buckets_object_info *oi, const char *key) {
  return buckets_xl_kv_get(oi->meta_sys, oi->nmeta_sys, key);
}

const char *buckets_object_tier(const buckets_object_info *oi, const char **remote, const char **version) {
  const buckets_xl_kv *st = buckets_object_sys(oi, BUCKETS_XL_META_TIER_STATUS);
  if (!st || st->value_len != 8 || memcmp(st->value, "complete", 8) != 0) return NULL;
  const buckets_xl_kv *t = buckets_object_sys(oi, BUCKETS_XL_META_TIER_NAME);
  const buckets_xl_kv *r = buckets_object_sys(oi, BUCKETS_XL_META_TIER_OBJECT);
  const buckets_xl_kv *v = buckets_object_sys(oi, BUCKETS_XL_META_TIER_VERSION);
  if (remote) *remote = r ? (const char *)r->value : "";
  if (version) *version = v ? (const char *)v->value : "";
  return t ? (const char *)t->value : "";
}

void buckets_object_restore_state(const buckets_object_info *oi, bool *ongoing, int64_t *expires) {
  *ongoing = false;
  *expires = 0;
  for (size_t i = 0; i < oi->nmeta; i++) {
    if (strcasecmp(oi->meta[i].key, "x-amz-restore") != 0) continue;
    if (!buckets_restore_parse((const char *)oi->meta[i].value, ongoing, expires)) *ongoing = false, *expires = 0;
    return;
  }
}

bool buckets_object_is_remote(const buckets_object_info *oi) {
  if (!buckets_object_tier(oi, NULL, NULL)) return false;
  bool ongoing;
  int64_t exp;
  buckets_object_restore_state(oi, &ongoing, &exp);
  return ongoing || exp <= (int64_t)time(NULL);
}

static void fill_info(buckets_object_info *oi, const char *name, const buckets_xl_object *o) {
  memset(oi, 0, sizeof(*oi));
  oi->name = buckets_xstrdup(name);
  buckets_xl_version_id_string(o->version_id, oi->version_id);
  oi->size = o->size;
  oi->mod_time_ns = o->mod_time;
  oi->nparts = o->nparts;
  if (o->nparts) {
    oi->parts = buckets_xcalloc(o->nparts, sizeof(buckets_xl_part));
    for (size_t i = 0; i < o->nparts; i++) {
      oi->parts[i] = (buckets_xl_part){o->parts[i].number, o->parts[i].size, o->parts[i].actual_size, NULL, NULL, 0};
      buckets_xl_part_set_index(&oi->parts[i], o->parts[i].index, o->parts[i].index_len);
    }
  }
  /* FileInfo.Deleted: a version pending purge (a replicated versioned
   * delete not yet done on every target) reads like a delete marker */
  const buckets_xl_kv *ps = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, "x-minio-internal-purgestatus");
  oi->delete_marker = o->type == BUCKETS_XL_TYPE_DELETE || (ps && ps->value_len);
  oi->data_blocks = o->ec_m;
  oi->parity_blocks = o->ec_n;
  for (size_t i = 0; i < o->nmeta_user; i++) {
    if (strcmp(o->meta_user[i].key, "etag") == 0) {
      snprintf(oi->etag, sizeof(oi->etag), "%s", (const char *)o->meta_user[i].value);
      continue;
    }
    buckets_xl_kv_set(&oi->meta, &oi->nmeta, o->meta_user[i].key, o->meta_user[i].value, o->meta_user[i].value_len);
  }
  for (size_t i = 0; i < o->nmeta_sys; i++) {
    buckets_xl_kv_set(&oi->meta_sys, &oi->nmeta_sys, o->meta_sys[i].key, o->meta_sys[i].value, o->meta_sys[i].value_len);
  }
  const buckets_xl_kv *crc = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, "x-minio-internal-crc");
  if (crc && crc->value_len) {
    oi->checksum = buckets_xmalloc(crc->value_len);
    memcpy(oi->checksum, crc->value, crc->value_len);
    oi->checksum_len = crc->value_len;
  }
}

/* ---- data sources ------------------------------------------------------------ */

typedef struct {
  buckets_read_fn rd;
  void *ud;
  int64_t remaining;
  buckets_md5_ctx md5;
  buckets_sha256_ctx sha;
  bool want_sha;
  buckets_cksum_hasher cks;
  bool want_cks;
  bool unknown; /* size -1: read to EOF (compressed streams) */
  bool eof;
  int64_t total; /* bytes read */
  buckets_obj_err err;
} source;

static size_t source_read(source *s, uint8_t *buf, size_t n) {
  size_t want = (size_t)BUCKETS_MIN((int64_t)n, s->remaining), got = 0;
  while (got < want) {
    long r = s->rd(s->ud, buf + got, want - got);
    if (r < 0) {
      s->err = BUCKETS_OBJ_ERR_READER;
      return got;
    }
    if (r == 0) {
      if (s->unknown) {
        s->eof = true;
        break;
      }
      s->err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
      return got;
    }
    got += (size_t)r;
  }
  s->remaining -= (int64_t)got;
  s->total += (int64_t)got;
  return got; /* hashed by source_hash, in parallel with the block's writes */
}

/* Payload hash i (0 MD5, 1 SHA-256, 2 additional checksum) over one block. */
static void source_hash(source *s, int i, const uint8_t *buf, size_t n) {
  if (i == 0) buckets_md5_update(&s->md5, buf, n);
  else if (i == 1 && s->want_sha) buckets_sha256_update(&s->sha, buf, n);
  else if (i == 2 && s->want_cks) buckets_cksum_hasher_update(&s->cks, buf, n);
}

/* ---- erasure encoding -------------------------------------------------------- */

static int64_t ceil_div(int64_t a, int64_t b) { return (a + b - 1) / b; }

/* Erasure.ShardFileSize */
static int64_t shard_file_size(int64_t total, int data) {
  if (total <= 0) return 0;
  int64_t shard = ceil_div(BUCKETS_BLOCK_SIZE, data);
  return (total / BUCKETS_BLOCK_SIZE) * shard + ceil_div(total % BUCKETS_BLOCK_SIZE, data);
}

typedef struct {
  buckets_eset *set;
  int data, parity;
  int dist[MAX_SET];
  bool inline_mode;
  bool alive[MAX_SET];
  buckets_drive_writer *w[MAX_SET];
  buckets_buf ibuf[MAX_SET]; /* inline shards */
  /* per-stage scratch shared with the I/O workers */
  const char *file;
  uint8_t **shards;
  size_t sl;
  bool abort_writes;
  buckets_rs *rs;
} encoder;

static void enc_open(void *ctx, size_t i) {
  encoder *e = ctx;
  buckets_eset *s = e->set;
  e->alive[i] = s->drives[i] != NULL;
  e->ibuf[i] = BUCKETS_BUF_INIT;
  e->w[i] = NULL;
  if (e->alive[i] && !e->inline_mode &&
      buckets_drive_create_file(s->drives[i], BUCKETS_META_BUCKET, e->file, &e->w[i]) != BUCKETS_DRIVE_OK) {
    e->alive[i] = false;
  }
}

/* Hashes drive i's shard of the current block and appends hash + shard. */
static void enc_write(void *ctx, size_t i) {
  encoder *e = ctx;
  if (!e->alive[i]) return;
  const uint8_t *shard = e->shards[e->dist[i] - 1];
  uint8_t h[HASH_LEN];
  buckets_hh256(buckets_bitrot_key, shard, e->sl, h);
  if (e->inline_mode) {
    buckets_buf_append(&e->ibuf[i], h, HASH_LEN);
    buckets_buf_append(&e->ibuf[i], shard, e->sl);
  } else if (buckets_drive_writer_write(e->w[i], h, HASH_LEN) != BUCKETS_DRIVE_OK ||
             buckets_drive_writer_write(e->w[i], shard, e->sl) != BUCKETS_DRIVE_OK) {
    buckets_log_warn("write to %s failed; continuing with the remaining drives", e->set->drives[i]->root);
    buckets_drive_writer_abort(e->w[i]);
    e->w[i] = NULL;
    e->alive[i] = false;
  }
}

#define RS_CHUNKS 4

/* ---- payload hashing, one block behind --------------------------------------
 * MD5 (the ETag), and SHA-256 / a checksum when asked for, are serial per
 * object and the slowest step of a PUT. They run as one background task per
 * block, overlapping the next block's read, parity and writes; the encoder
 * alternates two block buffers and waits for the task before reusing one. */

/* The hashes get a thread of their own for multi-block objects: queued on
 * the drive I/O pool they would wait behind shard writes, and the whole
 * PUT runs at the speed of MD5. Blocks circulate through a ring of
 * HASH_RING buffers, so neither side waits on the other block by block. */
#define HASH_RING 4

typedef struct {
  source *src;
  uint8_t *bufs[HASH_RING];
  size_t lens[HASH_RING];
  uint64_t submitted, hashed; /* blocks handed over / finished */
  pthread_mutex_t mu;
  pthread_cond_t cv;
  bool stop, threaded;
  pthread_t thread;
} hasher;

static void hash_block(hasher *h, uint64_t b) {
  for (int k = 0; k < 3; k++) source_hash(h->src, k, h->bufs[b % HASH_RING], h->lens[b % HASH_RING]);
}

static void *hash_thread(void *arg) {
  hasher *h = arg;
#ifdef __APPLE__
  /* The PUT's critical path: keep it on a performance core. */
  pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
  pthread_mutex_lock(&h->mu);
  for (;;) {
    while (h->hashed == h->submitted && !h->stop) pthread_cond_wait(&h->cv, &h->mu);
    if (h->hashed == h->submitted) break;
    uint64_t b = h->hashed;
    pthread_mutex_unlock(&h->mu);
    hash_block(h, b);
    pthread_mutex_lock(&h->mu);
    h->hashed++;
    pthread_cond_broadcast(&h->cv);
  }
  pthread_mutex_unlock(&h->mu);
  return NULL;
}

static void hasher_init(hasher *h, source *src, bool threaded) {
  memset(h, 0, sizeof(*h));
  h->src = src;
  for (int i = 0; i < (threaded ? HASH_RING : 1); i++) h->bufs[i] = buckets_xmalloc(BUCKETS_BLOCK_SIZE);
  pthread_mutex_init(&h->mu, NULL);
  pthread_cond_init(&h->cv, NULL);
  h->threaded = threaded && pthread_create(&h->thread, NULL, hash_thread, h) == 0;
}

/* The buffer for the next block, once the thread is done with its old contents. */
static uint8_t *hasher_next_buffer(hasher *h) {
  if (!h->threaded) return h->bufs[0];
  pthread_mutex_lock(&h->mu);
  while (h->submitted - h->hashed >= HASH_RING) pthread_cond_wait(&h->cv, &h->mu);
  uint8_t *buf = h->bufs[h->submitted % HASH_RING];
  pthread_mutex_unlock(&h->mu);
  return buf;
}

/* Hands the block just read into hasher_next_buffer() over for hashing. */
static void hasher_submit(hasher *h, size_t len) {
  if (!h->threaded) {
    h->lens[0] = len;
    hash_block(h, 0);
    return;
  }
  pthread_mutex_lock(&h->mu);
  h->lens[h->submitted % HASH_RING] = len;
  h->submitted++;
  pthread_cond_broadcast(&h->cv);
  pthread_mutex_unlock(&h->mu);
}

static void hasher_destroy(hasher *h) {
  if (h->threaded) {
    pthread_mutex_lock(&h->mu);
    h->stop = true;
    pthread_cond_broadcast(&h->cv);
    pthread_mutex_unlock(&h->mu);
    pthread_join(h->thread, NULL); /* finishes every submitted block first */
  }
  for (int i = 0; i < HASH_RING; i++) free(h->bufs[i]);
  pthread_cond_destroy(&h->cv);
  pthread_mutex_destroy(&h->mu);
}

/* Parity for one byte range (parity bytes depend only on the data bytes at
 * the same offset, so ranges encode in parallel). */
static void enc_parity(void *ctx, size_t k) {
  encoder *e = ctx;
  size_t per = ((size_t)ceil_div((int64_t)e->sl, RS_CHUNKS) + 63) & ~(size_t)63;
  size_t off = k * per;
  if (off >= e->sl) return;
  size_t len = BUCKETS_MIN(per, e->sl - off);
  uint8_t *part[MAX_SET];
  for (int j = 0; j < e->data + e->parity; j++) part[j] = e->shards[j] + off;
  buckets_rs_encode(e->rs, part, len);
}

/* Writing a shard into a buffered writer is cheap: one pool task per few
 * drives keeps the pool's lock out of the way. */
#define WRITE_GROUP 4

static void enc_write_group(void *ctx, size_t g) {
  encoder *e = ctx;
  for (size_t i = g * WRITE_GROUP; i < BUCKETS_MIN((g + 1) * WRITE_GROUP, e->set->n); i++) enc_write(ctx, i);
}

/* Flushes (fsync) and closes drive i's file, or aborts it. */
static void enc_close(void *ctx, size_t i) {
  encoder *e = ctx;
  if (!e->w[i]) return;
  if (e->abort_writes) buckets_drive_writer_abort(e->w[i]);
  else if (buckets_drive_writer_close(e->w[i]) != BUCKETS_DRIVE_OK) e->alive[i] = false;
  e->w[i] = NULL;
}

/* Streams `size` bytes from src, erasure-coded across the set: drive i
 * receives shard dist[i]-1 of every block, each preceded by its bitrot hash,
 * either into <.minio.sys>/<file> or an in-memory inline buffer. */
static buckets_obj_err encode_stream(encoder *e, source *src, int64_t size, const char *file) {
  buckets_eset *s = e->set;
  int total = e->data + e->parity;
  e->file = file;
  buckets_io_parallel(s->n, enc_open, e);
  buckets_rs *rs = buckets_rs_new(e->data, e->parity);
  size_t shard_cap = (size_t)ceil_div(BUCKETS_BLOCK_SIZE, e->data);
  uint8_t *shards[MAX_SET];
  for (int k = 0; k < total; k++) shards[k] = buckets_xmalloc(shard_cap);
  e->shards = shards;
  hasher h;
  hasher_init(&h, src, size < 0 || size > BUCKETS_BLOCK_SIZE);
  buckets_obj_err err = BUCKETS_OBJ_OK;
  int wq = write_quorum(e->data, e->parity);
  while (src->remaining > 0 && !src->eof && !err) {
    uint8_t *block = hasher_next_buffer(&h);
    size_t n = source_read(src, block, BUCKETS_BLOCK_SIZE);
    if (src->err) {
      err = src->err;
      break;
    }
    if (n == 0) break; /* a stream of unknown size ended at a block boundary */
    size_t sl = (size_t)ceil_div((int64_t)n, e->data);
    for (int k = 0; k < e->data; k++) {
      size_t off = (size_t)k * sl;
      size_t take = off < n ? BUCKETS_MIN(sl, n - off) : 0;
      if (take) memcpy(shards[k], block + off, take);
      memset(shards[k] + take, 0, sl - take);
    }
    hasher_submit(&h, n);
    e->sl = sl;
    e->rs = rs;
    if (e->parity) buckets_io_parallel(RS_CHUNKS, enc_parity, e);
    buckets_io_parallel((s->n + WRITE_GROUP - 1) / WRITE_GROUP, enc_write_group, e);
    int ok = 0;
    for (size_t i = 0; i < s->n; i++) ok += e->alive[i];
    if (ok < wq) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
  }
  hasher_destroy(&h);
  if (!err) {
    uint8_t one;
    long extra = src->rd(src->ud, &one, 1); /* must be at EOF; lets chunked decoders read trailers */
    if (extra > 0) err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
    else if (extra < 0) err = BUCKETS_OBJ_ERR_READER;
  }
  e->abort_writes = err != BUCKETS_OBJ_OK;
  buckets_io_parallel(s->n, enc_close, e);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) ok += e->alive[i];
  if (!err && ok < wq) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
  for (int k = 0; k < total; k++) free(shards[k]);
  buckets_rs_free(rs);
  return err;
}

static void encoder_free(encoder *e) {
  for (size_t i = 0; i < e->set->n; i++) buckets_buf_free(&e->ibuf[i]);
}

/* ---- commit -------------------------------------------------------------------- */

/* Rejects keys whose parent path is an object, or that shadow a non-empty prefix. */
static buckets_obj_err check_namespace(buckets_eset *s, const char *bucket, const char *object) {
  buckets_drive *d = NULL;
  for (size_t i = 0; i < s->n && !d; i++) d = s->drives[i];
  if (!d) return BUCKETS_OBJ_ERR_WRITE_QUORUM;
  for (const char *p = object; (p = strchr(p, '/')) != NULL && p[1]; p++) {
    buckets_buf parent = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&parent, "%.*s/" XL_META, (int)(p - object), object);
    int st = buckets_drive_stat(d, bucket, parent.data);
    buckets_buf_free(&parent);
    if (st == 1) return BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
  }
  char *op = obj_path(object);
  char *meta = join(op, XL_META);
  buckets_obj_err err = BUCKETS_OBJ_OK;
  if (buckets_drive_stat(d, bucket, op) == 2 && buckets_drive_stat(d, bucket, meta) != 1) {
    buckets_dir_list l;
    if (buckets_drive_list_dir(d, bucket, op, &l) == BUCKETS_DRIVE_OK) {
      if (l.n) err = BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
      buckets_dir_list_free(&l);
    }
  } else if (buckets_drive_stat(d, bucket, op) == 1) {
    err = BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY;
  }
  free(meta);
  free(op);
  return err;
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *object, *op, *src_dir;
  const buckets_xl_object *o;
  const int *dist;
  const bool *alive;
  const buckets_buf *ibuf;
  bool has_data_dir;
  char key[37], data_dir[37];
  const uint8_t *fv_id; /* free version for a replaced transitioned version */
  bool ok[MAX_SET];
} commit_ctx;

static void new_uuid_bytes(uint8_t id[16], char str[37]);
static void add_free_version(buckets_xlmeta *x, const buckets_xl_object *cur, const uint8_t *fv_id);

static void commit_one(void *ctx, size_t i) {
  commit_ctx *c = ctx;
  c->ok[i] = false;
  if (!c->alive[i] || !c->s->drives[i]) return;
  buckets_drive *d = c->s->drives[i];
  buckets_buf raw = BUCKETS_BUF_INIT;
  char *mpath = join(c->op, XL_META);
  buckets_xlmeta x;
  memset(&x, 0, sizeof(x));
  if (buckets_drive_read_all(d, c->bucket, mpath, &raw) == BUCKETS_DRIVE_OK &&
      buckets_xlmeta_parse(raw.data, raw.len, &x) != BUCKETS_XL_OK) {
    memset(&x, 0, sizeof(x)); /* unreadable: replaced (healing would do the same) */
  }
  buckets_buf_free(&raw);
  free(mpath);
  char old_dir[37] = "";
  long prev = buckets_xlmeta_find(&x, c->o->version_id);
  if (prev >= 0) {
    buckets_xl_object po;
    if (buckets_xl_object_decode(&x.versions[prev], &po) == BUCKETS_XL_OK) {
      if (po.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(po.meta_sys, po.nmeta_sys, BUCKETS_XL_META_INLINE)) {
        buckets_xl_version_id_string(po.data_dir, old_dir);
      }
      /* an overwritten transitioned version: its remote copy is swept
       * later (not when the same version is reinstalled: heal, restore) */
      const buckets_xl_kv *was = buckets_xl_kv_get(po.meta_sys, po.nmeta_sys, BUCKETS_XL_META_TIER_OBJECT);
      const buckets_xl_kv *now = buckets_xl_kv_get(c->o->meta_sys, c->o->nmeta_sys, BUCKETS_XL_META_TIER_OBJECT);
      bool same = was && now && was->value_len == now->value_len && memcmp(was->value, now->value, was->value_len) == 0;
      if (!same) add_free_version(&x, &po, c->fv_id);
      buckets_xl_object_free(&po);
    }
  }
  buckets_xl_object mine = *c->o; /* shallow: only this drive's EcIndex differs */
  mine.ec_index = c->dist[i];
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(&mine, &meta, &hdr);
  buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)meta.data, meta.len);
  if (c->ibuf) buckets_xlmeta_inline_put(&x, c->key, c->ibuf[i].data ? c->ibuf[i].data : "", c->ibuf[i].len);
  else buckets_xlmeta_inline_remove(&x, c->key);
  buckets_buf bytes = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(&x, &bytes);
  buckets_xlmeta_free(&x);
  if (buckets_drive_rename_data(d, BUCKETS_META_BUCKET, c->src_dir, c->has_data_dir ? c->data_dir : NULL, c->bucket,
                                c->op, bytes.data, bytes.len) == BUCKETS_DRIVE_OK) {
    c->ok[i] = true;
    if (old_dir[0] && strcmp(old_dir, c->data_dir) != 0) {
      char *stale = join(c->op, old_dir);
      buckets_drive_delete(d, c->bucket, stale, true, false);
      free(stale);
    }
  } else {
    buckets_log_warn("commit of %s/%s failed on %s", c->bucket, c->object, d->root);
  }
  buckets_buf_free(&bytes);
}

/* Installs version o on every live drive: merges it into that drive's xl.meta
 * (with the drive's own EcIndex and inline shard) and moves the staged data
 * directory <.minio.sys>/<src_dir>/<data_dir> into place. */
static buckets_obj_err commit_version(buckets_eset *s, const char *bucket, const char *object, buckets_xl_object *o,
                                      const int *dist, const bool *alive, const buckets_buf *ibuf,
                                      const char *src_dir, bool has_data_dir, int quorum, size_t *committed) {
  char *op = obj_path(object);
  uint8_t fv_id[16];
  char fv_s[37];
  new_uuid_bytes(fv_id, fv_s);
  commit_ctx c = {.s = s, .bucket = bucket, .object = object, .op = op, .src_dir = src_dir, .o = o,
                  .dist = dist, .alive = alive, .ibuf = ibuf, .has_data_dir = has_data_dir, .fv_id = fv_id};
  buckets_xl_version_id_string(o->version_id, c.key);
  buckets_xl_version_id_string(o->data_dir, c.data_dir);
  buckets_io_parallel(s->n, commit_one, &c);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) ok += c.ok[i];
  if (committed) *committed = (size_t)ok;
  free(op);
  return ok >= quorum ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

typedef struct {
  buckets_eset *s;
  const char *tmp_dir;
} cleanup_ctx;

static void cleanup_one(void *ctx, size_t i) {
  cleanup_ctx *c = ctx;
  if (c->s->drives[i]) buckets_drive_delete(c->s->drives[i], BUCKETS_META_BUCKET, c->tmp_dir, true, false);
}

/* A write that reached quorum but not every online drive goes to the MRF queue. */
static void report_partial(buckets_epool *L, buckets_eset *s, const char *bucket, const char *object,
                           const buckets_xl_object *o, size_t committed) {
  size_t online = 0;
  for (size_t i = 0; i < s->n; i++) online += s->drives[i] != NULL;
  if (committed >= online) return;
  char vid[37];
  buckets_xl_version_id_string(o->version_id, vid);
  report_degraded(L, bucket, object, vid, false);
}

static void cleanup_tmp(buckets_eset *s, const char *tmp_dir) {
  cleanup_ctx c = {s, tmp_dir};
  buckets_io_parallel(s->n, cleanup_one, &c);
}

static void new_uuid_bytes(uint8_t id[16], char str[37]) {
  buckets_random_bytes(id, 16);
  id[6] = (uint8_t)((id[6] & 0x0f) | 0x40);
  id[8] = (uint8_t)((id[8] & 0x3f) | 0x80);
  buckets_xl_version_id_string(id, str);
}

static void init_version(buckets_xl_object *o, const uint8_t data_dir[16], int64_t size, int data, int parity,
                         const int *dist, size_t n) {
  memset(o, 0, sizeof(*o));
  o->type = BUCKETS_XL_TYPE_OBJECT;
  memcpy(o->data_dir, data_dir, 16);
  o->mod_time = now_ns();
  o->size = size;
  o->ec_m = data;
  o->ec_n = parity;
  o->ec_block_size = BUCKETS_BLOCK_SIZE;
  o->ec_index = 1;
  for (size_t i = 0; i < n; i++) o->ec_dist[i] = (uint8_t)dist[i];
  o->ec_dist_n = n;
}

/* xlMetaV2Object.InitFreeVersion: a transitioned version that goes away
 * leaves a free version (fv_id, same on every drive) naming its remote
 * copy, for the scanner to delete. Nothing when fv_id is NULL (skipped). */
static void add_free_version(buckets_xlmeta *x, const buckets_xl_object *cur, const uint8_t *fv_id) {
  if (!fv_id || cur->type != BUCKETS_XL_TYPE_OBJECT || !buckets_xl_transitioned(cur)) return;
  buckets_xl_object fv;
  memset(&fv, 0, sizeof(fv));
  fv.type = BUCKETS_XL_TYPE_DELETE;
  memcpy(fv.version_id, fv_id, 16);
  fv.mod_time = cur->mod_time;
  buckets_xl_kv_set(&fv.meta_sys, &fv.nmeta_sys, BUCKETS_XL_META_FREE_VERSION, "", 0);
  static const char *const keep[] = {BUCKETS_XL_META_TIER_NAME, BUCKETS_XL_META_TIER_OBJECT,
                                     BUCKETS_XL_META_TIER_VERSION};
  for (size_t k = 0; k < 3; k++) {
    const buckets_xl_kv *kv = buckets_xl_kv_get(cur->meta_sys, cur->nmeta_sys, keep[k]);
    if (kv) buckets_xl_kv_set(&fv.meta_sys, &fv.nmeta_sys, kv->key, kv->value, kv->value_len);
  }
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(&fv, &meta, &hdr);
  buckets_xlmeta_put_version(x, &hdr, (uint8_t *)meta.data, meta.len);
  buckets_xl_object_free(&fv);
}

/* ---- put --------------------------------------------------------------------------- */

buckets_obj_err buckets_ep_put(buckets_epool *L, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = buckets_ep_set_for(L, object);

  encoder e = {.set = s, .parity = s->parity, .data = set_data(s)};
  char *key = join(bucket, object);
  buckets_hash_order(key, (int)s->n, e.dist);
  free(key);
  if (size >= 0) {
    e.inline_mode = shard_file_size(size, e.data) <= BUCKETS_INLINE_THRESHOLD;
  } else {
    /* A compressed stream: decide by the plaintext size, as MinIO does. */
    int64_t sz = opts && opts->actual_size > 0 ? shard_file_size(opts->actual_size, e.data) : -1;
    e.inline_mode = sz > 0 && sz <= BUCKETS_INLINE_THRESHOLD;
  }

  uint8_t data_dir[16];
  char data_dir_s[37];
  new_uuid_bytes(data_dir, data_dir_s);
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf file = BUCKETS_BUF_INIT, tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  buckets_buf_appendf(&file, "tmp/%s/%s/part.1", tmp_id, data_dir_s);
  free(tmp_id);

  source src = {.rd = rd, .ud = rd_ud, .remaining = size < 0 ? INT64_MAX : size, .unknown = size < 0,
                .want_sha = opts && opts->want_sha256};
  buckets_md5_init(&src.md5);
  buckets_sha256_init(&src.sha);
  uint32_t ctype = opts ? opts->checksum_type & BUCKETS_CKSUM_BASE_MASK : 0;
  src.want_cks = ctype != 0;
  buckets_cksum_hasher_init(&src.cks, ctype);

  err = encode_stream(&e, &src, size, file.data);
  size = src.total;
  uint8_t md5[16], sha[32];
  buckets_md5_final(&src.md5, md5);
  buckets_sha256_final(&src.sha, sha);
  buckets_checksum cks = {0};
  if (src.want_cks) {
    cks.type = ctype;
    cks.raw_len = buckets_cksum_hasher_final(&src.cks, cks.raw);
  }
  if (!err && opts && opts->want_md5 && memcmp(md5, opts->want_md5, 16) != 0) err = BUCKETS_OBJ_ERR_BAD_DIGEST;
  if (!err && opts && opts->want_sha256 && memcmp(sha, opts->want_sha256, 32) != 0) {
    err = BUCKETS_OBJ_ERR_SHA256_MISMATCH;
  }
  if (!err) {
    buckets_xl_object o;
    init_version(&o, data_dir, size, e.data, e.parity, e.dist, s->n);
    if (opts && opts->version_id && *opts->version_id) {
      if (!buckets_xl_version_id_parse(opts->version_id, o.version_id)) err = BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
    } else if (opts && opts->versioned) {
      char vs[37];
      new_uuid_bytes(o.version_id, vs);
    }
    if (opts && opts->mod_time_ns) o.mod_time = opts->mod_time_ns;
    buckets_xl_part_add(&o, 1, size, size, NULL);
    for (size_t i = 0; opts && i < opts->nmeta; i++) {
      /* AddVersion: reserved keys are system metadata */
      bool internal = strncasecmp(opts->meta[i].key, BUCKETS_XL_RESERVED_PREFIX, strlen(BUCKETS_XL_RESERVED_PREFIX)) == 0;
      if (internal) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, opts->meta[i].key, opts->meta[i].value, opts->meta[i].value_len);
      else buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, opts->meta[i].key, opts->meta[i].value, opts->meta[i].value_len);
    }
    char etag[33];
    buckets_hex_encode(md5, 16, etag);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", etag, 32);
    if (e.inline_mode) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE, "true", 4);
    if (!err && opts && opts->pre_commit) err = opts->pre_commit(opts->pre_commit_ud, &cks, &o);
    if (!err && opts && opts->preserve_etag && *opts->preserve_etag)
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", opts->preserve_etag, strlen(opts->preserve_etag));
    if (!err) {
      /* Like MinIO, only the commit is locked: the data is already staged. */
      buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
      size_t committed = 0;
      /* The namespace check runs under the lock: a concurrent commit of this
       * key briefly leaves its directory without xl.meta. */
      err = !lk ? BUCKETS_OBJ_ERR_TIMEOUT : check_namespace(s, bucket, object);
      if (!err) {
        err = commit_version(s, bucket, object, &o, e.dist, e.alive, e.inline_mode ? e.ibuf : NULL, tmp_dir.data,
                             !e.inline_mode, write_quorum(e.data, e.parity), &committed);
      }
      buckets_nslock_unlock(lk);
      if (!err && committed < s->n) report_partial(L, s, bucket, object, &o, committed);
    }
    if (!err && out) {
      o.ec_index = 1;
      fill_info(out, object, &o);
    }
    buckets_xl_object_free(&o);
  }
  if (!e.inline_mode || err) cleanup_tmp(s, tmp_dir.data);
  encoder_free(&e);
  buckets_buf_free(&file);
  buckets_buf_free(&tmp_dir);
  return err;
}

/* ---- read ----------------------------------------------------------------------------- */

struct buckets_obj_reader {
  buckets_epool *L;
  buckets_eset *set;
  char *bucket, *object, *op;
  char data_dir[37], version_id[37];
  bool degraded; /* a drive was outdated, unreadable or rotten: report for healing */
  bool quiet;    /* healing's own reader: never report */
  bool bitrot;   /* a shard failed its hash check */
  int64_t total_size;
  int data, parity, total;
  buckets_rs *rs;
  int drive_of_shard[MAX_SET]; /* -1 when no agreeing drive holds it */
  bool bad[MAX_SET];           /* drive failed a read or bitrot check */
  uint8_t *inl[MAX_SET];       /* inline shard per drive */
  size_t inl_len[MAX_SET];
  bool is_inline;
  buckets_xl_part *parts;
  size_t nparts, part;
  int64_t part_off, remaining;
  size_t shard_cap;
  uint8_t *frames[MAX_SET]; /* bitrot hash + shard, as stored */
  uint8_t *shards[MAX_SET]; /* frames[k] + HASH_LEN */
  size_t block_sl; /* shard length of the loaded block */
  /* read-ahead of the next block into a second buffer set */
  uint8_t *pf_frames[MAX_SET], *pf_shards[MAX_SET];
  int64_t pf_index; /* -1: none */
  bool pf_busy, pf_ok;
  size_t pf_sl, pf_len;
  pthread_mutex_t pf_mu;
  pthread_cond_t pf_cv;
  int64_t block_index;
  size_t block_len;
  buckets_nslock_entry *lk; /* read lock, held until EOF or free */
  buckets_drive_file *fh[MAX_SET]; /* open part file per drive */
  int fh_part[MAX_SET];            /* the part number fh[i] has open */
  /* a transitioned version: its bytes come from the remote tier */
  void *remote;
  long (*remote_read)(void *, void *, size_t);
  void (*remote_free)(void *);
};

static bool prefetch_wait(buckets_obj_reader *r, int64_t bi);

void buckets_obj_reader_free(buckets_obj_reader *r) {
  if (!r) return;
  if (r->remote) r->remote_free(r->remote);
  prefetch_wait(r, -1);
  pthread_cond_destroy(&r->pf_cv);
  pthread_mutex_destroy(&r->pf_mu);
  for (int i = 0; i < MAX_SET; i++) free(r->pf_frames[i]);
  buckets_nslock_unlock(r->lk);
  for (int i = 0; i < MAX_SET; i++) buckets_drive_file_close(r->fh[i]);
  for (int i = 0; i < MAX_SET; i++) r->degraded |= r->bad[i];
  if (r->degraded && !r->quiet) report_degraded(r->L, r->bucket, r->object, r->version_id, r->bitrot);
  for (int i = 0; i < MAX_SET; i++) {
    free(r->inl[i]);
    free(r->frames[i]);
  }

  free(r->parts);
  free(r->bucket);
  free(r->object);
  free(r->op);
  buckets_rs_free(r->rs);
  free(r);
}

static buckets_obj_err resolve(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                               buckets_eset **set, dmeta *m, long *vidx, buckets_xl_object *o) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  *set = buckets_ep_set_for(L, object);
  char *op = obj_path(object);
  load_metas(*set, bucket, op, m);
  free(op);
  err = quorum_version(m, (*set)->n, version_id, o, vidx);
  if (!err && o->type == BUCKETS_XL_TYPE_DELETE &&
      buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, BUCKETS_XL_META_FREE_VERSION)) {
    buckets_xl_object_free(o);
    err = BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  }
  if (err) free_metas(m, (*set)->n);
  return err;
}

static buckets_obj_err obj_stat(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                buckets_object_info *out) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) return err;
  fill_info(out, object, &o);
  fill_position(out, m, vidx, s->n);
  buckets_xl_object_free(&o);
  free_metas(m, s->n);
  return BUCKETS_OBJ_OK;
}

/* A reader over version o, from the drives whose metadata agrees (vidx >= 0),
 * positioned at the start. */
static buckets_obj_reader *reader_new(buckets_epool *L, buckets_eset *s, const char *bucket, const char *object,
                                     const dmeta *m, const long *vidx, const buckets_xl_object *o) {
  buckets_obj_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->L = L;
  r->set = s;
  r->bucket = buckets_xstrdup(bucket);
  r->object = buckets_xstrdup(object);
  r->op = obj_path(object);
  buckets_xl_version_id_string(o->data_dir, r->data_dir);
  buckets_xl_version_id_string(o->version_id, r->version_id);
  r->data = o->ec_m > 0 ? o->ec_m : 1;
  r->parity = o->ec_n;
  r->total = r->data + r->parity;
  r->rs = buckets_rs_new(r->data, r->parity);
  r->is_inline = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, BUCKETS_XL_META_INLINE) != NULL;
  for (int k = 0; k < MAX_SET; k++) r->drive_of_shard[k] = -1;
  for (size_t i = 0; i < s->n; i++) {
    if (vidx[i] < 0) {
      if (s->drives[i]) r->degraded = true; /* online but outdated: worth a heal */
      continue;
    }
    buckets_xl_object mine;
    if (buckets_xl_object_decode(&m[i].x.versions[vidx[i]], &mine) != BUCKETS_XL_OK) continue;
    /* shuffleDisks: the drive's shard follows the version's distribution
     * (MinIO's metadata-only rewrites leave EcIndex at the drive's position) */
    int shard = i < (size_t)o->ec_dist_n && o->ec_dist[i] > 0 ? o->ec_dist[i] - 1 : mine.ec_index - 1;
    buckets_xl_object_free(&mine);
    if (shard < 0 || shard >= r->total || r->drive_of_shard[shard] >= 0) continue;
    if (r->is_inline) {
      buckets_str sh;
      if (!buckets_xlmeta_inline_get(&m[i].x, r->version_id, &sh)) continue;
      r->inl[i] = buckets_xmalloc(sh.n ? sh.n : 1);
      memcpy(r->inl[i], sh.p, sh.n);
      r->inl_len[i] = sh.n;
    }
    r->drive_of_shard[shard] = (int)i;
  }
  r->parts = buckets_xcalloc(o->nparts ? o->nparts : 1, sizeof(buckets_xl_part));
  for (size_t i = 0; i < o->nparts; i++) {
    r->parts[i] = (buckets_xl_part){o->parts[i].number, o->parts[i].size, o->parts[i].actual_size, NULL, NULL, 0};
    r->total_size += o->parts[i].size;
  }
  r->nparts = o->nparts;
  r->shard_cap = (size_t)ceil_div(BUCKETS_BLOCK_SIZE, r->data);
  for (int k = 0; k < r->total; k++) {
    r->frames[k] = buckets_xmalloc(r->shard_cap + HASH_LEN);
    r->shards[k] = r->frames[k] + HASH_LEN;
  }

  r->block_index = -1;
  r->pf_index = -1;
  pthread_mutex_init(&r->pf_mu, NULL);
  pthread_cond_init(&r->pf_cv, NULL);
  return r;
}

static buckets_obj_err obj_open(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                int64_t offset, int64_t length, buckets_obj_reader **out, buckets_object_info *info) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) return err;
  if (o.type == BUCKETS_XL_TYPE_DELETE) {
    buckets_xl_object_free(&o);
    free_metas(m, s->n);
    return version_id && *version_id ? BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  bool remote = buckets_xl_transitioned(&o) && !buckets_xl_restored_on_disk(&o);
  buckets_obj_reader *r = reader_new(L, s, bucket, object, m, vidx, &o);
  if (info) {
    fill_info(info, object, &o);
    fill_position(info, m, vidx, s->n);
  }
  if (remote) { /* getTransitionedObjectReader */
    const buckets_xl_kv *tier = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_TIER_NAME);
    const buckets_xl_kv *name = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_TIER_OBJECT);
    const buckets_xl_kv *rv = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_TIER_VERSION);
    int64_t len = offset >= r->total_size ? 0 : BUCKETS_MIN(length, r->total_size - offset);
    bool opened = len == 0 || (L->top->tier_open && tier && name &&
                               L->top->tier_open(L->top->tier_ud, (const char *)tier->value, (const char *)name->value,
                                                 rv ? (const char *)rv->value : "", offset, len, &r->remote_read,
                                                 &r->remote_free, &r->remote));
    buckets_xl_object_free(&o);
    free_metas(m, s->n);
    if (!opened) {
      if (info) buckets_object_info_free(info);
      buckets_obj_reader_free(r);
      return BUCKETS_OBJ_ERR_TIER;
    }
    r->remaining = len;
    *out = r;
    return BUCKETS_OBJ_OK;
  }
  buckets_xl_object_free(&o);
  free_metas(m, s->n);

  int64_t off = offset;
  while (r->part < r->nparts && off >= r->parts[r->part].size && r->parts[r->part].size > 0) {
    off -= r->parts[r->part].size;
    r->part++;
  }
  r->part_off = off;
  r->remaining = offset >= r->total_size ? 0 : BUCKETS_MIN(length, r->total_size - offset);
  *out = r;
  return BUCKETS_OBJ_OK;
}

/* Reads one verified shard block from the drive holding shard k into frames[k]. */
static bool read_shard(buckets_obj_reader *r, uint8_t *const *frames, int k, int64_t bi, size_t sl) {
  int i = r->drive_of_shard[k];
  if (i < 0 || r->bad[i] || !r->set->drives[i]) return false;
  uint8_t *frame = frames[k];
  size_t flen = HASH_LEN + sl;
  int64_t foff = bi * (int64_t)(r->shard_cap + HASH_LEN);
  if (r->is_inline) {
    if (!r->inl[i] || (size_t)foff + flen > r->inl_len[i]) {
      r->bad[i] = true;
      return false;
    }
    memcpy(frame, r->inl[i] + foff, flen);
  } else {
    int pn = r->parts[r->part].number;
    buckets_drive_err e = BUCKETS_DRIVE_OK;
    if (!r->fh[i] || r->fh_part[i] != pn) {
      buckets_drive_file_close(r->fh[i]);
      r->fh[i] = NULL;
      buckets_buf path = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&path, "%s/%s/part.%d", r->op, r->data_dir, pn);
      e = buckets_drive_open_file(r->set->drives[i], r->bucket, path.data, &r->fh[i]);
      buckets_buf_free(&path);
      r->fh_part[i] = pn;
    }
    size_t got = 0;
    if (!e) e = buckets_drive_file_read_at(r->fh[i], foff, frame, flen, &got);
    if (e || got != flen) {
      r->bad[i] = true;
      return false;
    }
  }
  uint8_t h[HASH_LEN];
  buckets_hh256(buckets_bitrot_key, frame + HASH_LEN, sl, h);
  if (!buckets_ct_equal(h, frame, HASH_LEN)) {
    buckets_log_warn("bitrot detected in %s/%s on %s (shard %d, block %lld)", r->bucket, r->op,
                     r->set->drives[i]->root, k, (long long)bi);
    r->bad[i] = true;
    r->bitrot = true;
    return false;
  }
  return true;
}

typedef struct {
  buckets_obj_reader *r;
  uint8_t *const *frames;
  int64_t bi;
  size_t sl;
  int want[MAX_SET];
  bool got[MAX_SET];
} fetch_ctx;

static void fetch_one(void *ctx, size_t j) {
  fetch_ctx *c = ctx;
  c->got[j] = read_shard(c->r, c->frames, c->want[j], c->bi, c->sl);
}

/* Loads and verifies block bi of the current part into the given buffer
 * set, reconstructing missing data shards. */
static bool load_block_into(buckets_obj_reader *r, int64_t bi, uint8_t *const *frames, uint8_t *const *shards,
                            size_t *out_sl, size_t *out_len) {
  int64_t ps = r->parts[r->part].size;
  size_t blen = (size_t)BUCKETS_MIN((int64_t)BUCKETS_BLOCK_SIZE, ps - bi * BUCKETS_BLOCK_SIZE);
  size_t sl = (size_t)ceil_div((int64_t)blen, r->data);
  bool present[MAX_SET] = {false}, tried[MAX_SET] = {false};
  int have = 0;
  fetch_ctx c = {.r = r, .frames = frames, .bi = bi, .sl = sl};
  /* Data shards first, all at once; then as many parity shards as are still
   * missing, in waves, until enough verified shards are in hand. */
  for (;;) {
    size_t nw = 0;
    for (int k = 0; k < r->total && have + (int)nw < r->data; k++) {
      if (tried[k]) continue;
      tried[k] = true;
      int i = r->drive_of_shard[k];
      if (i >= 0 && !r->bad[i] && r->set->drives[i]) c.want[nw++] = k;
    }
    if (nw == 0) break;
    buckets_io_parallel(nw, fetch_one, &c);
    for (size_t j = 0; j < nw; j++) {
      if (c.got[j]) {
        present[c.want[j]] = true;
        have++;
      }
    }
    if (have >= r->data) break;
  }
  if (have < r->data) return false;
  bool missing_data = false;
  for (int k = 0; k < r->data; k++) missing_data |= !present[k];
  if (missing_data && !buckets_rs_reconstruct(r->rs, shards, present, sl, true)) return false;
  *out_sl = sl;
  *out_len = blen;
  return true;
}

/* The block is the data shards back to back; reads copy straight out of
 * them rather than assembling it first. */
static bool load_block(buckets_obj_reader *r, int64_t bi) {
  size_t sl, blen;
  if (!load_block_into(r, bi, r->frames, r->shards, &sl, &blen)) return false;
  r->block_index = bi;
  r->block_len = blen;
  r->block_sl = sl;
  return true;
}

/* ---- read-ahead: the next block loads while this one is copied out ---- */

static void prefetch_task(void *ctx, size_t i) {
  buckets_obj_reader *r = ctx;
  (void)i;
  size_t sl = 0, blen = 0;
  bool ok = load_block_into(r, r->pf_index, r->pf_frames, r->pf_shards, &sl, &blen);
  pthread_mutex_lock(&r->pf_mu);
  r->pf_ok = ok;
  r->pf_sl = sl;
  r->pf_len = blen;
  r->pf_busy = false;
  pthread_cond_broadcast(&r->pf_cv);
  pthread_mutex_unlock(&r->pf_mu);
}

/* Waits out an in-flight read-ahead. Returns whether it holds block bi. */
static bool prefetch_wait(buckets_obj_reader *r, int64_t bi) {
  if (r->pf_index < 0) return false;
  pthread_mutex_lock(&r->pf_mu);
  while (r->pf_busy) pthread_cond_wait(&r->pf_cv, &r->pf_mu);
  pthread_mutex_unlock(&r->pf_mu);
  bool hit = r->pf_index == bi && r->pf_ok;
  r->pf_index = -1;
  return hit;
}

static void prefetch_start(buckets_obj_reader *r, int64_t bi) {
  if (!buckets_io_pool() || r->is_inline || bi * BUCKETS_BLOCK_SIZE >= r->parts[r->part].size) return;
  if (!r->pf_frames[0]) {
    for (int k = 0; k < r->total; k++) {
      r->pf_frames[k] = buckets_xmalloc(r->shard_cap + HASH_LEN);
      r->pf_shards[k] = r->pf_frames[k] + HASH_LEN;
    }
  }
  r->pf_index = bi;
  r->pf_busy = true;
  buckets_pool_submit(buckets_io_pool(), prefetch_task, r);
}

/* Makes block bi current: from the read-ahead when it has it, else loaded
 * now; then starts reading the block after it. */
static bool next_block(buckets_obj_reader *r, int64_t bi) {
  if (prefetch_wait(r, bi)) {
    for (int k = 0; k < r->total; k++) { /* swap the buffer sets */
      uint8_t *f = r->frames[k], *sh = r->shards[k];
      r->frames[k] = r->pf_frames[k];
      r->shards[k] = r->pf_shards[k];
      r->pf_frames[k] = f;
      r->pf_shards[k] = sh;
    }
    r->block_index = bi;
    r->block_len = r->pf_len;
    r->block_sl = r->pf_sl;
  } else if (!load_block(r, bi)) {
    return false;
  }
  prefetch_start(r, bi + 1);
  return true;
}

buckets_obj_err buckets_ep_stat(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, false);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_obj_err err = obj_stat(L, bucket, object, version_id, out);
  buckets_nslock_unlock(lk);
  return err;
}

buckets_obj_err buckets_ep_open(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, false);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_obj_err err = obj_open(L, bucket, object, version_id, offset, length, out, info);
  if (err) {
    buckets_nslock_unlock(lk);
    return err;
  }
  /* Load the first block now: an unreadable object fails before any
   * response headers are committed, as in MinIO. */
  buckets_obj_reader *r = *out;
  if (r->remote || !r->remaining) {
    if (r->remaining > 0) r->lk = lk;
    else buckets_nslock_unlock(lk);
    return BUCKETS_OBJ_OK;
  }
  while (r->part < r->nparts && r->part_off >= r->parts[r->part].size && r->remaining > 0) {
    r->part++;
    r->part_off = 0;
  }
  if (r->remaining > 0 && (r->part >= r->nparts || !next_block(r, r->part_off / BUCKETS_BLOCK_SIZE))) {
    buckets_log_error("cannot read %s/%s: fewer than %d intact shards", bucket, object, r->data);
    r->degraded = true;
    buckets_obj_reader_free(r);
    *out = NULL;
    buckets_nslock_unlock(lk);
    return BUCKETS_OBJ_ERR_READ_QUORUM;
  }
  /* Released at EOF, so a reader drained before a write (CopyObject onto
   * itself) never blocks that write's commit. */
  if ((*out)->remaining > 0) (*out)->lk = lk;
  else buckets_nslock_unlock(lk);
  return BUCKETS_OBJ_OK;
}

long buckets_obj_read(buckets_obj_reader *r, void *buf, size_t n) {
  if (r->remote) {
    if (r->remaining <= 0) return 0;
    long k = r->remote_read(r->remote, buf, (size_t)BUCKETS_MIN((int64_t)n, r->remaining));
    if (k > 0) r->remaining -= k;
    else if (k == 0) return -1; /* the remote copy ended early */
    if (r->remaining == 0) {
      buckets_nslock_unlock(r->lk);
      r->lk = NULL;
    }
    return k;
  }
  size_t done = 0;
  while (done < n && r->remaining > 0) {
    if (r->part >= r->nparts) return -1;
    int64_t ps = r->parts[r->part].size;
    if (r->part_off >= ps) {
      prefetch_wait(r, -1);
      r->part++;
      r->part_off = 0;
      r->block_index = -1;
      memset(r->bad, 0, sizeof(r->bad));
      continue;
    }
    int64_t bi = r->part_off / BUCKETS_BLOCK_SIZE;
    if (bi != r->block_index && !next_block(r, bi)) {
      buckets_log_error("cannot read %s/%s: fewer than %d intact shards (part %d, block %lld)", r->bucket, r->op,
                        r->data, r->parts[r->part].number, (long long)bi);
      return -1;
    }
    size_t in_block = (size_t)(r->part_off - bi * BUCKETS_BLOCK_SIZE);
    size_t take = BUCKETS_MIN(r->block_len - in_block, n - done);
    take = (size_t)BUCKETS_MIN((int64_t)take, r->remaining);
    for (size_t copied = 0; copied < take;) {
      size_t at = in_block + copied, k = at / r->block_sl, o = at % r->block_sl;
      size_t chunk = BUCKETS_MIN(take - copied, r->block_sl - o);
      memcpy((uint8_t *)buf + done + copied, r->shards[k] + o, chunk);
      copied += chunk;
    }
    done += take;
    r->part_off += (int64_t)take;
    r->remaining -= (int64_t)take;
  }
  if (r->remaining == 0 && r->lk) {
    buckets_nslock_unlock(r->lk);
    r->lk = NULL;
  }
  return (long)done;
}

/* ---- delete -------------------------------------------------------------------------- */

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  dmeta *m;
  uint8_t id[16];
  char key[37];
  const uint8_t *fv_id; /* NULL: SkipFreeVersion */
  bool found[MAX_SET], done[MAX_SET];
} del_ctx;

/* Removes the version from drive i's xl.meta, and the object dir with its last version. */
static void delete_one(void *ctx, size_t i) {
  del_ctx *c = ctx;
  dmeta *m = &c->m[i];
  c->found[i] = c->done[i] = false;
  if (!m->loaded) return;
  long k = buckets_xlmeta_find(&m->x, c->id);
  if (k < 0) return;
  c->found[i] = true;
  char dd[37] = "";
  buckets_xl_object o;
  bool decoded = buckets_xl_object_decode(&m->x.versions[k], &o) == BUCKETS_XL_OK;
  if (decoded && o.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE)) {
    buckets_xl_version_id_string(o.data_dir, dd);
  }
  buckets_xlmeta_remove_version(&m->x, c->id);
  buckets_xlmeta_inline_remove(&m->x, c->key);
  if (decoded) {
    add_free_version(&m->x, &o, c->fv_id);
    buckets_xl_object_free(&o);
  }
  buckets_drive *d = c->s->drives[i];
  buckets_drive_err de;
  if (m->x.n == 0) {
    de = buckets_drive_delete(d, c->bucket, c->op, true, true);
  } else {
    buckets_buf bytes = BUCKETS_BUF_INIT;
    buckets_xlmeta_serialize(&m->x, &bytes);
    char *mp = join(c->op, XL_META);
    de = buckets_drive_write_all(d, c->bucket, mp, bytes.data, bytes.len);
    free(mp);
    buckets_buf_free(&bytes);
    if (!de && dd[0]) {
      char *dp = join(c->op, dd);
      buckets_drive_delete(d, c->bucket, dp, true, false);
      free(dp);
    }
  }
  c->done[i] = de == BUCKETS_DRIVE_OK;
}

static buckets_obj_err obj_delete(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                  bool skip_free) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  uint8_t id[16] = {0};
  if (version_id && *version_id && !buckets_xl_version_id_parse(version_id, id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  buckets_eset *s = buckets_ep_set_for(L, object);
  char *op = obj_path(object);
  dmeta m[MAX_SET];
  load_metas(s, bucket, op, m);
  uint8_t fv_id[16];
  char fv_s[37];
  new_uuid_bytes(fv_id, fv_s);
  del_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m, .fv_id = skip_free ? NULL : fv_id};
  memcpy(c.id, id, 16);
  buckets_xl_version_id_string(id, c.key);
  buckets_io_parallel(s->n, delete_one, &c);
  size_t found = 0, done = 0;
  for (size_t i = 0; i < s->n; i++) {
    found += c.found[i];
    done += c.done[i];
  }
  free_metas(m, s->n);
  free(op);
  if (found == 0) return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  return (int)done >= write_quorum(set_data(s), s->parity) || done == found ? BUCKETS_OBJ_OK
                                                                              : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

buckets_obj_err buckets_ep_delete(buckets_epool *L, const char *bucket, const char *object, const char *version_id) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_obj_err err = obj_delete(L, bucket, object, version_id, false);
  buckets_nslock_unlock(lk);
  return err;
}

/* ---- delete markers ---------------------------------------------------------------- */

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  dmeta *m;
  const buckets_xl_object *dm;
  char key[37];
  const uint8_t *fv_id;
  bool ok[MAX_SET];
} marker_ctx;

/* Adds the delete marker to drive i's xl.meta (creating it for a key that
 * does not exist), replacing any version with its ID and that version's data. */
static void marker_one(void *ctx, size_t i) {
  marker_ctx *c = ctx;
  c->ok[i] = false;
  buckets_drive *d = c->s->drives[i];
  if (!d) return;
  dmeta *m = &c->m[i];
  buckets_xlmeta x;
  if (m->loaded) {
    x = m->x;
    memset(&m->x, 0, sizeof(m->x));
    m->loaded = false;
  } else {
    memset(&x, 0, sizeof(x));
  }
  char old_dir[37] = "";
  long prev = buckets_xlmeta_find(&x, c->dm->version_id);
  if (prev >= 0) {
    buckets_xl_object po;
    if (buckets_xl_object_decode(&x.versions[prev], &po) == BUCKETS_XL_OK) {
      if (po.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(po.meta_sys, po.nmeta_sys, BUCKETS_XL_META_INLINE)) {
        buckets_xl_version_id_string(po.data_dir, old_dir);
      }
      add_free_version(&x, &po, c->fv_id);
      buckets_xl_object_free(&po);
    }
  }
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(c->dm, &meta, &hdr);
  buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)meta.data, meta.len);
  buckets_xlmeta_inline_remove(&x, c->key);
  buckets_buf bytes = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(&x, &bytes);
  buckets_xlmeta_free(&x);
  char *mp = join(c->op, XL_META);
  c->ok[i] = buckets_drive_write_all(d, c->bucket, mp, bytes.data, bytes.len) == BUCKETS_DRIVE_OK;
  free(mp);
  buckets_buf_free(&bytes);
  if (c->ok[i] && old_dir[0]) {
    char *dp = join(c->op, old_dir);
    buckets_drive_delete(d, c->bucket, dp, true, false);
    free(dp);
  }
}

static buckets_obj_err add_delete_marker(buckets_epool *L, const char *bucket, const char *object, bool versioned,
                                         buckets_delete_result *res) {
  buckets_eset *s = buckets_ep_set_for(L, object);
  buckets_xl_object dm;
  memset(&dm, 0, sizeof(dm));
  dm.type = BUCKETS_XL_TYPE_DELETE;
  dm.mod_time = now_ns();
  char vs[37] = "null";
  if (versioned) new_uuid_bytes(dm.version_id, vs);
  char *op = obj_path(object);
  dmeta m[MAX_SET];
  load_metas(s, bucket, op, m);
  uint8_t fv_id[16];
  char fv_s[37];
  new_uuid_bytes(fv_id, fv_s);
  marker_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m, .dm = &dm, .fv_id = fv_id};
  buckets_xl_version_id_string(dm.version_id, c.key);
  buckets_io_parallel(s->n, marker_one, &c);
  free_metas(m, s->n);
  free(op);
  int ok = 0;
  size_t online = 0;
  for (size_t i = 0; i < s->n; i++) {
    ok += c.ok[i];
    online += s->drives[i] != NULL;
  }
  if (ok < write_quorum(set_data(s), s->parity)) return BUCKETS_OBJ_ERR_WRITE_QUORUM;
  if ((size_t)ok < online) report_degraded(L, bucket, object, vs, false);
  res->delete_marker = true;
  snprintf(res->version_id, sizeof(res->version_id), "%s", vs);
  return BUCKETS_OBJ_OK;
}

static buckets_obj_err delete_repl(buckets_epool *L, const char *bucket, const char *object,
                                   const buckets_delete_opts *opts, buckets_delete_result *res);

buckets_obj_err buckets_ep_delete_ex(buckets_epool *L, const char *bucket, const char *object,
                                     const buckets_delete_opts *opts, buckets_delete_result *res) {
  memset(res, 0, sizeof(*res));
  snprintf(res->version_id, sizeof(res->version_id), "null");
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  const char *vid = opts->version_id && *opts->version_id ? opts->version_id : NULL;
  uint8_t id[16];
  if (vid && !buckets_xl_version_id_parse(vid, id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  if (opts->replica_marker || opts->replica || opts->decide || (opts->repl_status && *opts->repl_status) ||
      (opts->purge_status && *opts->purge_status)) {
    err = delete_repl(L, bucket, object, opts, res);
  } else if (vid || (!opts->versioned && !opts->suspended)) {
    /* A version removed for good: say whether it was a delete marker. */
    buckets_object_info oi;
    if (obj_stat(L, bucket, object, vid ? vid : "null", &oi) == BUCKETS_OBJ_OK) {
      res->delete_marker = oi.delete_marker;
      buckets_object_info_free(&oi);
    }
    if (vid) buckets_xl_version_id_string(id, res->version_id);
    err = obj_delete(L, bucket, object, vid ? vid : NULL, opts->skip_free_version);
  } else {
    /* MinIO's DeleteObject: a key with no versions at all gets no marker
     * (a key whose latest version is a marker does). */
    buckets_object_info oi;
    err = obj_stat(L, bucket, object, NULL, &oi);
    if (!err) buckets_object_info_free(&oi);
    if (!err) err = add_delete_marker(L, bucket, object, opts->versioned, res);
  }
  buckets_nslock_unlock(lk);
  return err;
}

/* ---- deletes with replication state ------------------------------------------------
 * MinIO's erasureObjects.DeleteObject and xlMetaV2.DeleteVersion, for
 * deletes that carry replication state: delete markers and versioned
 * deletes queued for replication (their status recorded on the version),
 * their completion, and incoming replicated deletes. */

typedef struct {
  bool has_id;
  uint8_t id[16];
  bool deleted, mark_deleted;
  int64_t mod_time;
  const char *repl_internal; /* ReplicationStatusInternal */
  int64_t repl_ts;           /* 0: Go's zero time */
  bool replica;              /* ReplicaStatus REPLICA */
  int64_t replica_ts;
  const char *purge_internal;
  const char *const *reset_keys, *const *reset_values;
  size_t nreset;
  const uint8_t *fv_id; /* free version of a removed transitioned version (NULL: skip) */
} delfi;

/* ReplicationState.CompositeReplicationStatus (ReplicaTimeStamp aside) */
static const char *rs_composite(const delfi *f) {
  if (f->repl_internal && *f->repl_internal) return buckets_repl_composite_status(f->repl_internal);
  return f->replica ? BUCKETS_RS_REPLICA : "";
}

static const char *rs_purge(const delfi *f) {
  return f->purge_internal && *f->purge_internal ? buckets_repl_composite_purge(f->purge_internal) : "";
}

/* FileInfo.DeleteMarkerReplicationStatus */
static const char *dm_status(const delfi *f) { return f->deleted ? rs_composite(f) : ""; }

static void set_ts(buckets_xl_kv **kv, size_t *n, const char *key, int64_t ns) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  if (ns) buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), ts);
  else buckets_time_rfc3339_nano(BUCKETS_GO_ZERO_SEC, 0, ts);
  buckets_xl_kv_set(kv, n, key, ts, strlen(ts));
}

static void set_str(buckets_xl_kv **kv, size_t *n, const char *key, const char *v) {
  buckets_xl_kv_set(kv, n, key, v ? v : "", v ? strlen(v) : 0);
}

/* The replication keys DeleteVersion puts on a delete marker. */
static void marker_meta(const delfi *f, buckets_xl_kv **kv, size_t *n) {
  const char *dm = dm_status(f);
  if (*dm) {
    if (strcmp(dm, BUCKETS_RS_REPLICA) == 0) {
      set_str(kv, n, BUCKETS_META_REPLICA_STATUS, BUCKETS_RS_REPLICA);
      set_ts(kv, n, BUCKETS_META_REPLICA_TS, f->replica_ts);
    } else {
      set_str(kv, n, BUCKETS_META_REPL_STATUS, f->repl_internal);
      set_ts(kv, n, BUCKETS_META_REPL_TS, f->repl_ts);
    }
  }
  if (*rs_purge(f)) set_str(kv, n, BUCKETS_META_PURGE_STATUS, f->purge_internal);
  for (size_t i = 0; i < f->nreset; i++) set_str(kv, n, f->reset_keys[i], f->reset_values[i]);
}

static void put_decoded(buckets_xlmeta *x, const buckets_xl_object *o) {
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(o, &meta, &hdr);
  buckets_xlmeta_put_version(x, &hdr, (uint8_t *)meta.data, meta.len);
}

/* Whether another version shares data_dir (SharedDataDirCount > 0). */
static bool shared_data_dir(const buckets_xlmeta *x, const uint8_t id[16], const uint8_t dd[16]) {
  for (size_t i = 0; i < x->n; i++) {
    if (x->versions[i].hdr.type != BUCKETS_XL_TYPE_OBJECT || memcmp(x->versions[i].hdr.version_id, id, 16) == 0)
      continue;
    buckets_xl_object o;
    if (buckets_xl_object_decode(&x->versions[i], &o) != BUCKETS_XL_OK) continue;
    bool same = memcmp(o.data_dir, dd, 16) == 0 && !buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE);
    buckets_xl_object_free(&o);
    if (same) return true;
  }
  return false;
}

/* xlMetaV2.DeleteVersion. Returns false for errFileVersionNotFound; dd
 * receives a data directory to remove ("" for none). */
static bool xl_delete_version(buckets_xlmeta *x, const delfi *f, char dd[37]) {
  dd[0] = '\0';
  uint8_t uv[16] = {0};
  if (f->has_id) memcpy(uv, f->id, 16);
  buckets_xl_object ventry;
  memset(&ventry, 0, sizeof(ventry));
  if (f->deleted) {
    ventry.type = BUCKETS_XL_TYPE_DELETE;
    memcpy(ventry.version_id, uv, 16);
    ventry.mod_time = f->mod_time;
    marker_meta(f, &ventry.meta_sys, &ventry.nmeta_sys);
  }
  const char *dm = dm_status(f), *ps = rs_purge(f);
  bool update = false;
  if (!*ps && (strcmp(dm, BUCKETS_RS_REPLICA) == 0 || !*dm)) {
    update = f->mark_deleted;
  } else {
    if (f->deleted && strcmp(ps, BUCKETS_VPS_COMPLETE) != 0 && (*ps || !*dm)) update = true;
    if (*ps && strcmp(ps, BUCKETS_VPS_COMPLETE) != 0) update = true;
  }
  bool ok = true, done = false;
  for (size_t i = 0; i < x->n && !done; i++) {
    if (memcmp(x->versions[i].hdr.version_id, uv, 16) != 0) continue;
    uint8_t type = x->versions[i].hdr.type;
    if (type == BUCKETS_XL_TYPE_DELETE) {
      if (update) {
        buckets_xl_object cur;
        if (buckets_xl_object_decode(&x->versions[i], &cur) == BUCKETS_XL_OK) {
          if (*dm) {
            if (strcmp(dm, BUCKETS_RS_REPLICA) == 0) {
              set_str(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_REPLICA_STATUS, BUCKETS_RS_REPLICA);
              set_ts(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_REPLICA_TS, f->replica_ts);
            } else {
              set_str(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_REPL_STATUS, f->repl_internal);
              set_ts(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_REPL_TS, f->repl_ts);
            }
          }
          if (*ps) set_str(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_PURGE_STATUS, f->purge_internal);
          for (size_t k = 0; k < f->nreset; k++) set_str(&cur.meta_sys, &cur.nmeta_sys, f->reset_keys[k], f->reset_values[k]);
          put_decoded(x, &cur);
          buckets_xl_object_free(&cur);
        }
        buckets_xl_object_free(&ventry);
        return true;
      }
      buckets_xlmeta_remove_version(x, uv);
      bool zero = !f->has_id;
      if (f->mark_deleted && strcmp(ps, BUCKETS_VPS_COMPLETE) != 0) {
        if (f->deleted) put_decoded(x, &ventry);
      } else if (f->deleted && zero) {
        put_decoded(x, &ventry);
      }
      buckets_xl_object_free(&ventry);
      return true;
    }
    if (type == BUCKETS_XL_TYPE_OBJECT && update && !f->deleted) {
      buckets_xl_object cur;
      if (buckets_xl_object_decode(&x->versions[i], &cur) == BUCKETS_XL_OK) {
        set_str(&cur.meta_sys, &cur.nmeta_sys, BUCKETS_META_PURGE_STATUS, f->purge_internal);
        for (size_t k = 0; k < f->nreset; k++) set_str(&cur.meta_sys, &cur.nmeta_sys, f->reset_keys[k], f->reset_values[k]);
        put_decoded(x, &cur);
        buckets_xl_object_free(&cur);
      }
      buckets_xl_object_free(&ventry);
      return true;
    }
    done = type == BUCKETS_XL_TYPE_OBJECT;
    if (done) { /* the second loop: remove the object version */
      buckets_xl_object cur;
      bool dec = buckets_xl_object_decode(&x->versions[i], &cur) == BUCKETS_XL_OK;
      bool inl = dec && buckets_xl_kv_get(cur.meta_sys, cur.nmeta_sys, BUCKETS_XL_META_INLINE);
      uint8_t ddir[16] = {0};
      if (dec) memcpy(ddir, cur.data_dir, 16);
      char key[37];
      buckets_xl_version_id_string(uv, key);
      buckets_xlmeta_remove_version(x, uv);
      buckets_xlmeta_inline_remove(x, key);
      if (dec) add_free_version(x, &cur, f->fv_id);
      if (f->deleted) put_decoded(x, &ventry);
      if (dec && !inl && !shared_data_dir(x, uv, ddir)) buckets_xl_version_id_string(ddir, dd);
      if (strcmp(dd, "null") == 0) dd[0] = '\0';
      if (dec) buckets_xl_object_free(&cur);
      buckets_xl_object_free(&ventry);
      return true;
    }
  }
  if (f->deleted) {
    put_decoded(x, &ventry);
    ok = true;
  } else {
    ok = false;
  }
  buckets_xl_object_free(&ventry);
  return ok;
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  dmeta *m;
  const delfi *f;
  bool force_marker;
  bool ok[MAX_SET], notfound[MAX_SET];
} rdel_ctx;

/* xlStorage.DeleteVersion on drive i. */
static void rdel_one(void *ctx, size_t i) {
  rdel_ctx *c = ctx;
  c->ok[i] = c->notfound[i] = false;
  buckets_drive *d = c->s->drives[i];
  if (!d) return;
  dmeta *m = &c->m[i];
  buckets_xlmeta x;
  if (m->loaded) {
    x = m->x;
    memset(&m->x, 0, sizeof(m->x));
    m->loaded = false;
  } else if (m->missing && c->force_marker && c->f->deleted) {
    memset(&x, 0, sizeof(x)); /* a new xl.meta holding just the marker */
  } else {
    c->notfound[i] = m->missing;
    return;
  }
  char dd[37];
  if (!xl_delete_version(&x, c->f, dd)) {
    buckets_xlmeta_free(&x);
    c->notfound[i] = true;
    return;
  }
  buckets_drive_err de;
  if (x.n == 0) {
    de = buckets_drive_delete(d, c->bucket, c->op, true, true);
  } else {
    buckets_buf bytes = BUCKETS_BUF_INIT;
    buckets_xlmeta_serialize(&x, &bytes);
    char *mp = join(c->op, XL_META);
    de = buckets_drive_write_all(d, c->bucket, mp, bytes.data, bytes.len);
    free(mp);
    buckets_buf_free(&bytes);
    if (!de && dd[0]) {
      char *dp = join(c->op, dd);
      buckets_drive_delete(d, c->bucket, dp, true, false);
      free(dp);
    }
  }
  buckets_xlmeta_free(&x);
  c->ok[i] = de == BUCKETS_DRIVE_OK || de == BUCKETS_DRIVE_ERR_NOT_FOUND;
}

static buckets_obj_err delete_repl(buckets_epool *L, const char *bucket, const char *object,
                                   const buckets_delete_opts *opts, buckets_delete_result *res) {
  const char *vid = opts->version_id && *opts->version_id ? opts->version_id : NULL;
  bool null_vid = vid && strcmp(vid, "null") == 0;
  /* getObjectInfoAndQuorum(opts.VersionID): a delete marker or a version
   * pending purge is still "found" (MinIO returns its info with the error) */
  buckets_object_info goi;
  memset(&goi, 0, sizeof(goi));
  buckets_obj_err gerr = obj_stat(L, bucket, object, vid ? vid : NULL, &goi);
  bool found = gerr == BUCKETS_OBJ_OK, version_found = true;
  if (!found) {
    if (gerr != BUCKETS_OBJ_ERR_NO_SUCH_KEY && gerr != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) return gerr;
    if (opts->replica_marker) version_found = false;
    else return gerr;
  }
  char *dec_repl = NULL, *dec_purge = NULL;
  if (opts->decide) opts->decide(opts->decide_ud, found ? &goi : NULL, found, &dec_repl, &dec_purge);
  uint8_t fv_id[16];
  char fv_s[37];
  new_uuid_bytes(fv_id, fv_s);
  delfi f = {.repl_internal = opts->repl_status, .repl_ts = opts->repl_ts_ns, .replica = opts->replica,
             .replica_ts = opts->replica ? now_ns() : 0, .purge_internal = opts->purge_status,
             .reset_keys = opts->reset_keys, .reset_values = opts->reset_values, .nreset = opts->nreset,
             .fv_id = opts->skip_free_version ? NULL : fv_id};
  /* SetDeleteReplicationState */
  if (dec_repl && *dec_repl) {
    if (vid) f.purge_internal = dec_repl;
    else f.repl_internal = dec_repl;
  }
  if (dec_purge && *dec_purge) f.purge_internal = dec_purge;
  bool mark_delete = found && goi.version_id[0];
  bool delete_marker = opts->versioned;
  const char *goi_purge = "";
  const buckets_xl_kv *gps = found ? buckets_object_sys(&goi, BUCKETS_META_PURGE_STATUS) : NULL;
  if (gps && gps->value_len) goi_purge = (const char *)gps->value;
  bool goi_is_marker = found && goi.delete_marker && !*goi_purge;
  if (vid) {
    const char *dmr = rs_composite(&f), *vps = rs_purge(&f);
    if (version_found && strcmp(dmr, BUCKETS_RS_REPLICA) == 0) mark_delete = false;
    if (!*vps && !*dmr) mark_delete = false;
    if (strcmp(vps, BUCKETS_VPS_COMPLETE) == 0) mark_delete = false;
    if (version_found && found) {
      if (*goi_purge) delete_marker = false;
      else if (!goi_is_marker) delete_marker = false;
    }
  }
  f.mod_time = opts->mod_time_ns ? opts->mod_time_ns : now_ns();
  if (mark_delete && (opts->versioned || opts->suspended)) {
    if (!delete_marker) delete_marker = opts->suspended && !vid;
    f.deleted = delete_marker;
    f.mark_deleted = true;
    if (vid && !null_vid) {
      f.has_id = buckets_xl_version_id_parse(vid, f.id);
    } else if (!vid && opts->versioned) {
      char vs[37];
      new_uuid_bytes(f.id, vs);
      f.has_id = true;
    }
  } else {
    f.deleted = delete_marker;
    f.mark_deleted = mark_delete;
    if (vid && !null_vid) f.has_id = buckets_xl_version_id_parse(vid, f.id);
  }
  buckets_eset *s = buckets_ep_set_for(L, object);
  char *op = obj_path(object);
  dmeta m[MAX_SET];
  load_metas(s, bucket, op, m);
  rdel_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m, .f = &f, .force_marker = opts->replica_marker};
  buckets_io_parallel(s->n, rdel_one, &c);
  free_metas(m, s->n);
  free(op);
  size_t ok = 0, notfound = 0, online = 0;
  for (size_t i = 0; i < s->n; i++) {
    ok += c.ok[i];
    notfound += c.notfound[i];
    online += s->drives[i] != NULL;
  }
  buckets_obj_err err = BUCKETS_OBJ_OK;
  int wq = (int)(s->n / 2 + 1);
  if ((int)ok < wq) {
    if ((int)notfound >= wq) err = vid ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
    else err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
  }
  if (!err) {
    char vs[37] = "null";
    if (f.has_id) buckets_xl_version_id_string(f.id, vs);
    if (ok < online) report_degraded(L, bucket, object, vs, false);
    res->delete_marker = f.deleted;
    snprintf(res->version_id, sizeof(res->version_id), "%s", vs);
    res->mod_time_ns = f.mod_time;
    snprintf(res->repl_status, sizeof(res->repl_status), "%s", f.deleted && f.repl_internal ? f.repl_internal : "");
    snprintf(res->purge_status, sizeof(res->purge_status), "%s", f.purge_internal ? f.purge_internal : "");
  }
  free(dec_repl);
  free(dec_purge);
  if (found) buckets_object_info_free(&goi);
  return err;
}

/* ---- metadata updates ------------------------------------------------------------- */

static void kvs_clear(buckets_xl_kv **kv, size_t *n) {
  for (size_t i = 0; i < *n; i++) {
    free((*kv)[i].key);
    free((*kv)[i].value);
  }
  free(*kv);
  *kv = NULL;
  *n = 0;
}

static void kvs_copy(const buckets_xl_kv *src, size_t n, buckets_xl_kv **dst, size_t *dn) {
  kvs_clear(dst, dn);
  for (size_t i = 0; i < n; i++) buckets_xl_kv_set(dst, dn, src[i].key, src[i].value, src[i].value_len);
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  dmeta *m;
  const long *vidx;
  const buckets_xl_object *o; /* the edited version */
  bool ok[MAX_SET];
} meta_ctx;

/* Replaces drive i's copy of the version (keeping its own EcIndex) with the edited metadata. */
static void meta_one(void *ctx, size_t i) {
  meta_ctx *c = ctx;
  c->ok[i] = false;
  if (c->vidx[i] < 0 || !c->s->drives[i] || !c->m[i].loaded) return;
  buckets_xlmeta *x = &c->m[i].x;
  buckets_xl_object mine;
  if (buckets_xl_object_decode(&x->versions[c->vidx[i]], &mine) != BUCKETS_XL_OK) return;
  kvs_copy(c->o->meta_user, c->o->nmeta_user, &mine.meta_user, &mine.nmeta_user);
  kvs_copy(c->o->meta_sys, c->o->nmeta_sys, &mine.meta_sys, &mine.nmeta_sys);
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(&mine, &meta, &hdr);
  buckets_xl_object_free(&mine);
  buckets_xlmeta_put_version(x, &hdr, (uint8_t *)meta.data, meta.len);
  buckets_buf bytes = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(x, &bytes);
  char *mp = join(c->op, XL_META);
  c->ok[i] = buckets_drive_write_all(c->s->drives[i], c->bucket, mp, bytes.data, bytes.len) == BUCKETS_DRIVE_OK;
  free(mp);
  buckets_buf_free(&bytes);
}

buckets_obj_err buckets_ep_update_meta(buckets_epool *L, const char *bucket, const char *object,
                                       const char *version_id, buckets_meta_edit_fn fn, void *ud,
                                       buckets_object_info *out) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) {
    buckets_nslock_unlock(lk);
    return err;
  }
  if (o.type == BUCKETS_XL_TYPE_DELETE) {
    err = BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED;
  } else {
    buckets_object_info cur;
    fill_info(&cur, object, &o);
    err = fn(ud, &cur, &o.meta_user, &o.nmeta_user, &o.meta_sys, &o.nmeta_sys);
    buckets_object_info_free(&cur);
  }
  if (!err) {
    char *op = obj_path(object);
    meta_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m, .vidx = vidx, .o = &o};
    buckets_io_parallel(s->n, meta_one, &c);
    free(op);
    int ok = 0;
    for (size_t i = 0; i < s->n; i++) ok += c.ok[i];
    if (ok < write_quorum(o.ec_m, o.ec_n)) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
    if (!err && out) fill_info(out, object, &o);
  }
  buckets_xl_object_free(&o);
  free_metas(m, s->n);
  buckets_nslock_unlock(lk);
  return err;
}

/* ---- tiering ------------------------------------------------------------------------ */

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  dmeta *m;
  const long *vidx;
  const buckets_xl_object *o; /* the version as it is to be */
  bool drop_data;             /* its data (inline shard or data dir) goes */
  bool ok[MAX_SET];
} tier_ctx;

/* Drive i's copy of the version becomes o (keeping its EcIndex); with
 * drop_data, its inline shard and data dir are removed. */
static void tier_one(void *ctx, size_t i) {
  tier_ctx *c = ctx;
  c->ok[i] = false;
  if (c->vidx[i] < 0 || !c->s->drives[i] || !c->m[i].loaded) return;
  buckets_xlmeta *x = &c->m[i].x;
  buckets_xl_object mine;
  if (buckets_xl_object_decode(&x->versions[c->vidx[i]], &mine) != BUCKETS_XL_OK) return;
  bool was_inline = buckets_xl_kv_get(mine.meta_sys, mine.nmeta_sys, BUCKETS_XL_META_INLINE) != NULL;
  char dd[37];
  buckets_xl_version_id_string(mine.data_dir, dd);
  kvs_copy(c->o->meta_user, c->o->nmeta_user, &mine.meta_user, &mine.nmeta_user);
  kvs_copy(c->o->meta_sys, c->o->nmeta_sys, &mine.meta_sys, &mine.nmeta_sys);
  buckets_buf meta = BUCKETS_BUF_INIT;
  buckets_xl_header hdr;
  buckets_xl_object_encode(&mine, &meta, &hdr);
  char vkey[37];
  buckets_xl_version_id_string(mine.version_id, vkey);
  buckets_xl_object_free(&mine);
  buckets_xlmeta_put_version(x, &hdr, (uint8_t *)meta.data, meta.len);
  if (c->drop_data) buckets_xlmeta_inline_remove(x, vkey);
  buckets_buf bytes = BUCKETS_BUF_INIT;
  buckets_xlmeta_serialize(x, &bytes);
  char *mp = join(c->op, XL_META);
  c->ok[i] = buckets_drive_write_all(c->s->drives[i], c->bucket, mp, bytes.data, bytes.len) == BUCKETS_DRIVE_OK;
  free(mp);
  buckets_buf_free(&bytes);
  if (c->ok[i] && c->drop_data && !was_inline && strcmp(dd, "null") != 0 && !shared_data_dir(x, c->o->version_id, c->o->data_dir)) {
    char *dp = join(c->op, dd);
    buckets_drive_delete(c->s->drives[i], c->bucket, dp, true, false);
    free(dp);
  }
}

static buckets_obj_err tier_commit(buckets_eset *s, const char *bucket, const char *object, dmeta *m, const long *vidx,
                                   const buckets_xl_object *o, bool drop_data) {
  char *op = obj_path(object);
  tier_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m, .vidx = vidx, .o = o, .drop_data = drop_data};
  buckets_io_parallel(s->n, tier_one, &c);
  free(op);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) ok += c.ok[i];
  return ok >= write_quorum(o->ec_m, o->ec_n) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

static long plain_reader(void *ud, void *buf, size_t n) { return buckets_obj_read(ud, buf, n); }

buckets_obj_err buckets_ep_transition(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                      int64_t mod_time_ns, const char *etag, const char *tier,
                                      buckets_tier_upload_fn upload, void *ud, buckets_object_info *out) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) {
    buckets_nslock_unlock(lk);
    return err;
  }
  if (o.type == BUCKETS_XL_TYPE_DELETE) {
    err = version_id && *version_id ? BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
    goto out;
  }
  /* the object queued for transition must be the one on disk */
  const buckets_xl_kv *et = buckets_xl_kv_get(o.meta_user, o.nmeta_user, "etag");
  if (o.mod_time != mod_time_ns || !et || strcasecmp((const char *)et->value, etag ? etag : "") != 0) {
    err = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
    goto out;
  }
  if (buckets_xl_transitioned(&o)) goto out; /* already done */
  buckets_obj_reader *r = reader_new(L, s, bucket, object, m, vidx, &o);
  r->remaining = r->total_size;
  char remote[512] = "", rv[256] = "";
  err = upload(ud, plain_reader, r, r->total_size, remote, sizeof(remote), rv, sizeof(rv));
  buckets_obj_reader_free(r);
  if (err) goto out;
  buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_TIER_STATUS, "complete", 8);
  buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_TIER_OBJECT, remote, strlen(remote));
  buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_TIER_VERSION, rv, strlen(rv));
  buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_TIER_NAME, tier, strlen(tier));
  /* ResetInlineData */
  buckets_xl_object tmp = {0};
  for (size_t i = 0; i < o.nmeta_sys; i++)
    if (strcmp(o.meta_sys[i].key, BUCKETS_XL_META_INLINE) != 0)
      buckets_xl_kv_set(&tmp.meta_sys, &tmp.nmeta_sys, o.meta_sys[i].key, o.meta_sys[i].value, o.meta_sys[i].value_len);
  kvs_clear(&o.meta_sys, &o.nmeta_sys);
  o.meta_sys = tmp.meta_sys;
  o.nmeta_sys = tmp.nmeta_sys;
  err = tier_commit(s, bucket, object, m, vidx, &o, true);
out:
  if (!err && out) {
    fill_info(out, object, &o);
    fill_position(out, m, vidx, s->n);
  }
  buckets_xl_object_free(&o);
  free_metas(m, s->n);
  buckets_nslock_unlock(lk);
  return err;
}

/* The stored bytes of one part: a window of the remote stream. */
typedef struct {
  buckets_read_fn rd;
  void *ud;
  int64_t left;
} part_src;

static long part_read(void *ud, void *buf, size_t n) {
  part_src *p = ud;
  if (p->left <= 0) return 0;
  long k = p->rd(p->ud, buf, (size_t)BUCKETS_MIN((int64_t)n, p->left));
  if (k > 0) p->left -= k;
  return k;
}

buckets_obj_err buckets_ep_rehydrate(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                     buckets_read_fn rd, void *rd_ud, const char *restore_hdr) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) return err;
  free_metas(m, s->n);
  if (o.type != BUCKETS_XL_TYPE_OBJECT || !buckets_xl_transitioned(&o)) {
    buckets_xl_object_free(&o);
    return BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED;
  }
  encoder e = {.set = s, .parity = o.ec_n, .data = o.ec_m > 0 ? o.ec_m : 1};
  for (size_t i = 0; i < s->n; i++) e.dist[i] = i < o.ec_dist_n ? o.ec_dist[i] : (int)i + 1;
  e.inline_mode = o.nparts == 1 && shard_file_size(o.size, e.data) <= BUCKETS_INLINE_THRESHOLD;
  uint8_t data_dir[16];
  char data_dir_s[37];
  new_uuid_bytes(data_dir, data_dir_s);
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  free(tmp_id);
  bool alive_all[MAX_SET];
  for (size_t i = 0; i < s->n; i++) alive_all[i] = s->drives[i] != NULL;
  for (size_t p = 0; p < o.nparts && !err; p++) {
    buckets_buf file = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&file, "%s/%s/part.%d", tmp_dir.data, data_dir_s, o.parts[p].number);
    part_src ps = {rd, rd_ud, o.parts[p].size};
    source src = {.rd = part_read, .ud = &ps, .remaining = o.parts[p].size};
    buckets_md5_init(&src.md5);
    buckets_sha256_init(&src.sha);
    buckets_cksum_hasher_init(&src.cks, 0);
    err = encode_stream(&e, &src, o.parts[p].size, file.data);
    if (!err && src.total != o.parts[p].size) err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
    for (size_t i = 0; i < s->n; i++) alive_all[i] &= e.alive[i];
    buckets_buf_free(&file);
  }
  if (!err) {
    memcpy(o.data_dir, data_dir, 16);
    if (e.inline_mode) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE, "true", 4);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "x-amz-restore", restore_hdr, strlen(restore_hdr));
    buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
    size_t committed = 0;
    err = !lk ? BUCKETS_OBJ_ERR_TIMEOUT
              : commit_version(s, bucket, object, &o, e.dist, alive_all, e.inline_mode ? e.ibuf : NULL, tmp_dir.data,
                               !e.inline_mode, write_quorum(e.data, e.parity), &committed);
    buckets_nslock_unlock(lk);
  }
  if (!e.inline_mode || err) cleanup_tmp(s, tmp_dir.data);
  encoder_free(&e);
  buckets_buf_free(&tmp_dir);
  buckets_xl_object_free(&o);
  return err;
}

/* ---- moving versions between pools (decommission, rebalance) ---------------------------- */

buckets_obj_err buckets_ep_version_record(buckets_epool *L, const char *bucket, const char *object,
                                          const char *version_id, buckets_xl_object *out) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, out);
  if (err) return err;
  free_metas(m, s->n);
  return BUCKETS_OBJ_OK;
}

static void remove_kv_xl(buckets_xl_kv **kv, size_t *n, const char *key) {
  size_t k = 0;
  for (size_t i = 0; i < *n; i++) {
    if (strcmp((*kv)[i].key, key) == 0) {
      free((*kv)[i].key);
      free((*kv)[i].value);
      continue;
    }
    (*kv)[k++] = (*kv)[i];
  }
  *n = k;
}

static void copy_record(const buckets_xl_object *src, buckets_xl_object *dst) {
  *dst = *src;
  dst->meta_user = NULL, dst->nmeta_user = 0;
  dst->meta_sys = NULL, dst->nmeta_sys = 0;
  kvs_copy(src->meta_user, src->nmeta_user, &dst->meta_user, &dst->nmeta_user);
  kvs_copy(src->meta_sys, src->nmeta_sys, &dst->meta_sys, &dst->nmeta_sys);
  dst->parts = src->nparts ? buckets_xcalloc(src->nparts, sizeof(*dst->parts)) : NULL;
  for (size_t i = 0; i < src->nparts; i++) {
    dst->parts[i] = src->parts[i];
    dst->parts[i].etag = src->parts[i].etag ? buckets_xstrdup(src->parts[i].etag) : NULL;
    dst->parts[i].index = NULL, dst->parts[i].index_len = 0;
    if (src->parts[i].index) buckets_xl_part_set_index(&dst->parts[i], src->parts[i].index, src->parts[i].index_len);
  }
}

buckets_obj_err buckets_ep_import_version(buckets_epool *L, const char *bucket, const char *object,
                                          const buckets_xl_object *src, buckets_read_fn rd, void *rd_ud) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = buckets_ep_set_for(L, object);
  buckets_xl_object o;
  copy_record(src, &o);
  encoder e = {.set = s, .parity = s->parity, .data = set_data(s)};
  char *key = join(bucket, object);
  buckets_hash_order(key, (int)s->n, e.dist);
  free(key);
  /* the data moves unless the version has none here (markers, remote tiers) */
  bool has_data = o.type == BUCKETS_XL_TYPE_OBJECT && buckets_xl_object_uses_data_dir(&o) && rd;
  e.inline_mode = has_data && o.nparts == 1 && shard_file_size(o.size, e.data) <= BUCKETS_INLINE_THRESHOLD;
  if (o.type == BUCKETS_XL_TYPE_OBJECT) {
    o.ec_m = e.data;
    o.ec_n = e.parity;
    o.ec_block_size = BUCKETS_BLOCK_SIZE;
    for (size_t i = 0; i < s->n; i++) o.ec_dist[i] = (uint8_t)e.dist[i];
    o.ec_dist_n = s->n;
  }
  remove_kv_xl(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE);
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  free(tmp_id);
  bool alive_all[MAX_SET];
  for (size_t i = 0; i < s->n; i++) alive_all[i] = s->drives[i] != NULL;
  if (has_data) {
    uint8_t data_dir[16];
    char data_dir_s[37];
    new_uuid_bytes(data_dir, data_dir_s);
    memcpy(o.data_dir, data_dir, 16);
    for (size_t p = 0; p < o.nparts && !err; p++) {
      buckets_buf file = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&file, "%s/%s/part.%d", tmp_dir.data, data_dir_s, o.parts[p].number);
      part_src ps = {rd, rd_ud, o.parts[p].size};
      source srcr = {.rd = part_read, .ud = &ps, .remaining = o.parts[p].size};
      buckets_md5_init(&srcr.md5);
      buckets_sha256_init(&srcr.sha);
      buckets_cksum_hasher_init(&srcr.cks, 0);
      err = encode_stream(&e, &srcr, o.parts[p].size, file.data);
      if (!err && srcr.total != o.parts[p].size) err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
      for (size_t i = 0; i < s->n; i++) alive_all[i] &= e.alive[i];
      buckets_buf_free(&file);
    }
    if (!err && e.inline_mode) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE, "true", 4);
  } else if (o.type == BUCKETS_XL_TYPE_OBJECT) {
    memset(o.data_dir, 0, 16);
  }
  if (!err) {
    buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
    size_t committed = 0;
    int q = o.type == BUCKETS_XL_TYPE_OBJECT ? write_quorum(e.data, e.parity) : write_quorum(set_data(s), s->parity);
    err = !lk ? BUCKETS_OBJ_ERR_TIMEOUT
              : commit_version(s, bucket, object, &o, e.dist, alive_all, e.inline_mode ? e.ibuf : NULL, tmp_dir.data,
                               has_data && !e.inline_mode, q, &committed);
    buckets_nslock_unlock(lk);
    if (!err) report_partial(L, s, bucket, object, &o, committed);
  }
  if (!has_data || !e.inline_mode || err) cleanup_tmp(s, tmp_dir.data);
  encoder_free(&e);
  buckets_buf_free(&tmp_dir);
  buckets_xl_object_free(&o);
  return err;
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  bool ok[MAX_SET];
} purge_all_ctx;

static void purge_all_one(void *ctx, size_t i) {
  purge_all_ctx *c = ctx;
  c->ok[i] = c->s->drives[i] &&
             buckets_drive_delete(c->s->drives[i], c->bucket, c->op, true, true) == BUCKETS_DRIVE_OK;
}

buckets_obj_err buckets_ep_delete_object_all(buckets_epool *L, const char *bucket, const char *object) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  buckets_eset *s = buckets_ep_set_for(L, object);
  char *op = obj_path(object);
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) {
    free(op);
    return BUCKETS_OBJ_ERR_TIMEOUT;
  }
  purge_all_ctx c = {.s = s, .bucket = bucket, .op = op};
  buckets_io_parallel(s->n, purge_all_one, &c);
  buckets_nslock_unlock(lk);
  free(op);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) ok += c.ok[i];
  return ok >= write_quorum(set_data(s), s->parity) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

/* x-amz-restore and its companions (RemoveRestoreHdrs) */
static void remove_restore_headers(buckets_xl_object *o) {
  buckets_xl_object tmp = {0};
  for (size_t i = 0; i < o->nmeta_user; i++) {
    const char *k = o->meta_user[i].key;
    if (strcasecmp(k, "x-amz-restore") == 0 || strcasecmp(k, "X-Amz-Restore-Expiry-Days") == 0 ||
        strcasecmp(k, "X-Amz-Restore-Request-Date") == 0)
      continue;
    buckets_xl_kv_set(&tmp.meta_user, &tmp.nmeta_user, k, o->meta_user[i].value, o->meta_user[i].value_len);
  }
  kvs_clear(&o->meta_user, &o->nmeta_user);
  o->meta_user = tmp.meta_user;
  o->nmeta_user = tmp.nmeta_user;
}

buckets_obj_err buckets_ep_expire_restored(buckets_epool *L, const char *bucket, const char *object,
                                           const char *version_id) {
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) {
    buckets_nslock_unlock(lk);
    return err;
  }
  if (o.type != BUCKETS_XL_TYPE_OBJECT || !buckets_xl_transitioned(&o)) {
    err = BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED;
  } else {
    remove_restore_headers(&o);
    /* the local copy goes with the headers (UsesDataDir is false again) */
    buckets_xl_object tmp = {0};
    for (size_t i = 0; i < o.nmeta_sys; i++)
      if (strcmp(o.meta_sys[i].key, BUCKETS_XL_META_INLINE) != 0)
        buckets_xl_kv_set(&tmp.meta_sys, &tmp.nmeta_sys, o.meta_sys[i].key, o.meta_sys[i].value, o.meta_sys[i].value_len);
    kvs_clear(&o.meta_sys, &o.nmeta_sys);
    o.meta_sys = tmp.meta_sys;
    o.nmeta_sys = tmp.nmeta_sys;
    err = tier_commit(s, bucket, object, m, vidx, &o, true);
  }
  buckets_xl_object_free(&o);
  free_metas(m, s->n);
  buckets_nslock_unlock(lk);
  return err;
}

buckets_obj_err buckets_ep_delete_free_version(buckets_epool *L, const char *bucket, const char *object,
                                               const char *version_id) {
  uint8_t id[16];
  if (!version_id || !buckets_xl_version_id_parse(version_id, id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (!err) {
    buckets_eset *s = buckets_ep_set_for(L, object);
    char *op = obj_path(object);
    dmeta m[MAX_SET];
    load_metas(s, bucket, op, m);
    /* only a free version by that ID goes */
    bool is_free = false;
    for (size_t i = 0; i < s->n && !is_free; i++) {
      long k = m[i].loaded ? buckets_xlmeta_find(&m[i].x, id) : -1;
      is_free = k >= 0 && buckets_xl_is_free_version(&m[i].x.versions[k].hdr);
    }
    if (!is_free) {
      err = BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
    } else {
      del_ctx c = {.s = s, .bucket = bucket, .op = op, .m = m};
      memcpy(c.id, id, 16);
      buckets_xl_version_id_string(id, c.key);
      buckets_io_parallel(s->n, delete_one, &c);
      size_t found = 0, done = 0;
      for (size_t i = 0; i < s->n; i++) {
        found += c.found[i];
        done += c.done[i];
      }
      if (!found) err = BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
      else if ((int)done < write_quorum(set_data(s), s->parity) && done != found) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
    }
    free_metas(m, s->n);
    free(op);
  }
  buckets_nslock_unlock(lk);
  return err;
}

/* ---- listing ------------------------------------------------------------------------- */

typedef struct {
  char *key;
  bool is_obj;
} entry;

/* By key; a directory object ("a/", stored as a__XLDIR__) before the prefix
 * "a/" it shares its key with, since it sorts before everything under it. */
static int entry_cmp(const void *a, const void *b) {
  const entry *x = a, *y = b;
  int c = strcmp(x->key, y->key);
  return c ? c : (int)y->is_obj - (int)x->is_obj;
}

typedef struct {
  buckets_drive *d;
  const char *bucket;
  const char *prefix;
  const char *marker;
  const char *delim;
  size_t delim_len;
  char *skip_prefix;
  int max_keys;
  buckets_obj_listing *out;
  size_t count;
  bool done;
  char *last_prefix;
  bool versions;         /* every version of each key */
  bool incl_free;        /* versions: free versions too (the scanner sweeps them) */
  const char *vmarker;   /* versions: resume after this version of the marker key */
} list_ctx;

static void emit_prefix(list_ctx *lc, const char *cp, size_t n) {
  if (lc->last_prefix && strlen(lc->last_prefix) == n && memcmp(lc->last_prefix, cp, n) == 0) return;
  if (lc->skip_prefix && strlen(lc->skip_prefix) == n && memcmp(lc->skip_prefix, cp, n) == 0) return;
  if ((int)lc->count == lc->max_keys) {
    lc->out->truncated = true;
    lc->done = true;
    return;
  }
  free(lc->last_prefix);
  lc->last_prefix = buckets_xstrndup(cp, n);
  buckets_obj_listing *o = lc->out;
  o->prefixes = buckets_xrealloc(o->prefixes, (o->nprefixes + 1) * sizeof(char *));
  o->prefixes[o->nprefixes++] = buckets_xstrndup(cp, n);
  lc->count++;
}

static void emit_versions(list_ctx *lc, const char *key, const buckets_xlmeta *x) {
  bool skipping = lc->marker && lc->vmarker && strcmp(key, lc->marker) == 0;
  long latest = first_visible(x);
  for (size_t v = 0; v < x->n && !lc->done; v++) {
    bool free_version = buckets_xl_is_free_version(&x->versions[v].hdr);
    if (free_version && !lc->incl_free) continue;
    buckets_xl_object o;
    if (buckets_xl_object_decode(&x->versions[v], &o) != BUCKETS_XL_OK) continue;
    char vs[37];
    buckets_xl_version_id_string(o.version_id, vs);
    if (skipping) {
      if (strcmp(vs, lc->vmarker) == 0) skipping = false;
      buckets_xl_object_free(&o);
      continue;
    }
    if ((int)lc->count == lc->max_keys) {
      lc->out->truncated = true;
      lc->done = true;
    } else {
      buckets_obj_listing *out = lc->out;
      out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
      buckets_object_info *oi = &out->objects[out->nobjects++];
      fill_info(oi, key, &o);
      oi->is_latest = (long)v == latest;
      oi->free_version = free_version;
      lc->count++;
    }
    buckets_xl_object_free(&o);
  }
}

static void emit_object(list_ctx *lc, const char *key, const char *dir) {
  if (lc->versions) {
    if (lc->marker && (strcmp(key, lc->marker) < 0 || (strcmp(key, lc->marker) == 0 && !lc->vmarker))) return;
  } else if (lc->marker && strcmp(key, lc->marker) <= 0) {
    return;
  }
  if (strncmp(key, lc->prefix, strlen(lc->prefix)) != 0) return;
  if (lc->delim_len) {
    const char *hit = strstr(key + strlen(lc->prefix), lc->delim);
    if (hit) {
      emit_prefix(lc, key, (size_t)(hit - key) + lc->delim_len);
      return;
    }
  }
  if ((int)lc->count == lc->max_keys) {
    lc->out->truncated = true;
    lc->done = true;
    return;
  }
  buckets_buf raw = BUCKETS_BUF_INIT;
  char *mp = join(dir, XL_META);
  buckets_xlmeta x;
  if (buckets_drive_read_all(lc->d, lc->bucket, mp, &raw) == BUCKETS_DRIVE_OK &&
      buckets_xlmeta_parse(raw.data, raw.len, &x) == BUCKETS_XL_OK) {
    buckets_xl_object o;
    if (lc->versions) {
      emit_versions(lc, key, &x);
    } else if (first_visible(&x) >= 0 && buckets_xl_object_decode(&x.versions[first_visible(&x)], &o) == BUCKETS_XL_OK) {
      if (o.type == BUCKETS_XL_TYPE_OBJECT) {
        buckets_obj_listing *out = lc->out;
        out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
        fill_info(&out->objects[out->nobjects++], key, &o);
        lc->count++;
      }
      buckets_xl_object_free(&o);
    }
    buckets_xlmeta_free(&x);
  }
  free(mp);
  buckets_buf_free(&raw);
}

static void walk(list_ctx *lc, const char *rel, const char *name_filter) {
  buckets_dir_list dl;
  const char *dir = *rel ? rel : "";
  if (buckets_drive_list_dir(lc->d, lc->bucket, dir, &dl) != BUCKETS_DRIVE_OK) return;
  entry *ents = buckets_xcalloc(dl.n ? dl.n : 1, sizeof(entry));
  size_t n = 0;
  for (size_t i = 0; i < dl.n; i++) {
    char *nm = dl.names[i];
    size_t nl = strlen(nm);
    if (!nl || nm[nl - 1] != '/') continue; /* objects and prefixes are directories */
    nm[--nl] = '\0';
    if (!*rel && strcmp(nm, BUCKETS_META_BUCKET) == 0) continue;
    if (name_filter && strncmp(nm, name_filter, strlen(name_filter)) != 0) continue;
    buckets_buf mp = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&mp, "%s%s/" XL_META, rel, nm);
    bool obj = buckets_drive_stat(lc->d, lc->bucket, mp.data) == 1;
    buckets_buf_free(&mp);
    size_t sl = strlen(DIR_SUFFIX);
    buckets_buf k = BUCKETS_BUF_INIT;
    if (obj && nl > sl && strcmp(nm + nl - sl, DIR_SUFFIX) == 0) buckets_buf_appendf(&k, "%.*s/", (int)(nl - sl), nm);
    else if (obj) buckets_buf_append_c(&k, nm);
    else buckets_buf_appendf(&k, "%s/", nm);
    ents[n++] = (entry){k.data, obj};
  }
  buckets_dir_list_free(&dl);
  if (n) qsort(ents, n, sizeof(entry), entry_cmp);
  for (size_t i = 0; i < n && !lc->done; i++) {
    buckets_buf key = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&key, "%s%s", rel, ents[i].key);
    if (ents[i].is_obj) {
      char *op = obj_path(key.data);
      emit_object(lc, key.data, op);
      free(op);
    } else {
      bool before_marker = lc->marker && strcmp(key.data, lc->marker) < 0 && strncmp(lc->marker, key.data, key.len) != 0;
      size_t pl = strlen(lc->prefix);
      bool matches = strncmp(key.data, lc->prefix, BUCKETS_MIN(pl, key.len)) == 0;
      if (!before_marker && matches) {
        if (lc->delim_len == 1 && lc->delim[0] == '/' && key.len > pl) {
          if (!lc->marker || strcmp(key.data, lc->marker) > 0) emit_prefix(lc, key.data, key.len);
        } else {
          walk(lc, key.data, NULL);
        }
      }
    }
    buckets_buf_free(&key);
  }
  for (size_t i = 0; i < n; i++) free(ents[i].key);
  free(ents);
}

/* Lists one drive (the first max_keys entries after the marker). */
static void list_drive(buckets_drive *d, const char *bucket, const char *prefix, const char *marker,
                       const char *vmarker, bool versions, bool incl_free, const char *delimiter, int max_keys,
                       buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  list_ctx lc = {.d = d, .bucket = bucket, .prefix = prefix, .marker = marker && *marker ? marker : NULL,
                 .delim = delimiter ? delimiter : "", .delim_len = delimiter ? strlen(delimiter) : 0,
                 .max_keys = max_keys, .out = out, .versions = versions, .incl_free = incl_free,
                 .vmarker = vmarker && *vmarker ? vmarker : NULL};
  if (lc.marker && lc.delim_len) {
    size_t pl = strlen(prefix);
    if (strncmp(lc.marker, prefix, pl) == 0) {
      const char *hit = strstr(lc.marker + pl, lc.delim);
      if (hit) lc.skip_prefix = buckets_xstrndup(lc.marker, (size_t)(hit - lc.marker) + lc.delim_len);
    }
  }
  const char *slash = strrchr(prefix, '/');
  char *base = slash ? buckets_xstrndup(prefix, (size_t)(slash - prefix) + 1) : buckets_xstrdup("");
  const char *filter = slash ? slash + 1 : prefix;
  if (!*base || buckets_obj_check_name(base) == BUCKETS_OBJ_OK) {
    if (*base && !*filter) {
      buckets_buf fo = BUCKETS_BUF_INIT, meta = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&fo, "%.*s" DIR_SUFFIX, (int)strlen(base) - 1, base);
      buckets_buf_appendf(&meta, "%s/" XL_META, fo.data);
      if (buckets_drive_stat(d, bucket, meta.data) == 1) emit_object(&lc, base, fo.data);
      buckets_buf_free(&fo);
      buckets_buf_free(&meta);
    }
    walk(&lc, base, *filter ? filter : NULL);
  }
  free(base);
  free(lc.last_prefix);
  free(lc.skip_prefix);
}

typedef struct {
  const char *key;
  bool is_prefix;
  size_t src, idx;
} merged;

static int merged_cmp(const void *a, const void *b) {
  const merged *x = a, *y = b;
  int c = strcmp(x->key, y->key);
  return c ? c : (int)y->is_prefix - (int)x->is_prefix;
}

buckets_obj_err buckets_ep_list(buckets_epool *L, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if (max_keys <= 0) return BUCKETS_OBJ_OK;
  if (max_keys > BUCKETS_MAX_LIST_KEYS) max_keys = BUCKETS_MAX_LIST_KEYS;
  if (!prefix) prefix = "";
  /* The union of each drive's first max_keys entries contains the global first
   * max_keys, so merging per-drive listings is exact. */
  size_t nsrc = 0;
  buckets_obj_listing *src = buckets_xcalloc(L->nall ? L->nall : 1, sizeof(buckets_obj_listing));
  bool any_truncated = false;
  for (size_t s = 0; s < L->nsets; s++) {
    for (size_t i = 0; i < L->sets[s].n; i++) {
      buckets_drive *d = L->sets[s].drives[i];
      if (!d) continue;
      list_drive(d, bucket, prefix, marker, NULL, false, false, delimiter, max_keys, &src[nsrc]);
      any_truncated |= src[nsrc].truncated;
      nsrc++;
    }
  }
  size_t total = 0;
  for (size_t k = 0; k < nsrc; k++) total += src[k].nobjects + src[k].nprefixes;
  merged *all = buckets_xcalloc(total ? total : 1, sizeof(merged));
  size_t na = 0;
  for (size_t k = 0; k < nsrc; k++) {
    for (size_t j = 0; j < src[k].nobjects; j++) all[na++] = (merged){src[k].objects[j].name, false, k, j};
    for (size_t j = 0; j < src[k].nprefixes; j++) all[na++] = (merged){src[k].prefixes[j], true, k, j};
  }
  qsort(all, na, sizeof(merged), merged_cmp);
  size_t emitted = 0;
  const char *last = NULL;
  for (size_t i = 0; i < na; i++) {
    if (i && strcmp(all[i].key, all[i - 1].key) == 0 && all[i].is_prefix == all[i - 1].is_prefix) continue;
    if ((int)emitted == max_keys) {
      out->truncated = true;
      break;
    }
    if (all[i].is_prefix) {
      out->prefixes = buckets_xrealloc(out->prefixes, (out->nprefixes + 1) * sizeof(char *));
      out->prefixes[out->nprefixes++] = buckets_xstrdup(all[i].key);
    } else {
      buckets_object_info *from = &src[all[i].src].objects[all[i].idx];
      out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
      out->objects[out->nobjects++] = *from;
      memset(from, 0, sizeof(*from)); /* moved */
    }
    last = all[i].key;
    emitted++;
  }
  if (any_truncated) out->truncated = true;
  if (out->truncated && last) out->next_marker = buckets_xstrdup(last);
  free(all);
  for (size_t k = 0; k < nsrc; k++) buckets_obj_list_free(&src[k]);
  free(src);
  return BUCKETS_OBJ_OK;
}

typedef struct {
  const char *key;
  bool is_prefix;
  const buckets_object_info *o;
  size_t src, idx;
} vmerged;

/* key ascending, prefixes before a same-named key; within a key, newest first */
static int vmerged_cmp(const void *a, const void *b) {
  const vmerged *x = a, *y = b;
  int c = strcmp(x->key, y->key);
  if (c) return c;
  if (x->is_prefix != y->is_prefix) return x->is_prefix ? -1 : 1;
  if (x->is_prefix) return 0;
  if (x->o->mod_time_ns != y->o->mod_time_ns) return x->o->mod_time_ns > y->o->mod_time_ns ? -1 : 1;
  return strcmp(y->o->version_id, x->o->version_id);
}

void buckets_obj_listing_merge_versions(buckets_obj_listing *src, size_t nsrc, int max_keys, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  size_t total = 0;
  bool any_truncated = false;
  for (size_t k = 0; k < nsrc; k++) {
    total += src[k].nobjects + src[k].nprefixes;
    any_truncated |= src[k].truncated;
  }
  vmerged *all = buckets_xcalloc(total ? total : 1, sizeof(vmerged));
  size_t na = 0;
  for (size_t k = 0; k < nsrc; k++) {
    for (size_t j = 0; j < src[k].nobjects; j++) all[na++] = (vmerged){src[k].objects[j].name, false, &src[k].objects[j], k, j};
    for (size_t j = 0; j < src[k].nprefixes; j++) all[na++] = (vmerged){src[k].prefixes[j], true, NULL, k, j};
  }
  qsort(all, na, sizeof(vmerged), vmerged_cmp);
  size_t emitted = 0;
  const char *last_key = NULL, *last_vid = NULL;
  bool last_prefix = false;
  for (size_t i = 0; i < na; i++) {
    const vmerged *e = &all[i];
    if (last_key && strcmp(e->key, last_key) == 0 && e->is_prefix == last_prefix &&
        (e->is_prefix || strcmp(e->o->version_id, last_vid) == 0))
      continue;
    if ((int)emitted == max_keys) {
      out->truncated = true;
      break;
    }
    if (e->is_prefix) {
      out->prefixes = buckets_xrealloc(out->prefixes, (out->nprefixes + 1) * sizeof(char *));
      out->prefixes[out->nprefixes++] = buckets_xstrdup(e->key);
      last_key = out->prefixes[out->nprefixes - 1];
      last_vid = NULL;
    } else {
      buckets_object_info *from = &src[e->src].objects[e->idx];
      out->objects = buckets_xrealloc(out->objects, (out->nobjects + 1) * sizeof(buckets_object_info));
      out->objects[out->nobjects++] = *from;
      memset(from, 0, sizeof(*from)); /* moved */
      last_key = out->objects[out->nobjects - 1].name;
      last_vid = out->objects[out->nobjects - 1].version_id;
    }
    last_prefix = e->is_prefix;
    emitted++;
  }
  if (any_truncated && (int)emitted == max_keys) out->truncated = true;
  if (out->truncated && last_key) {
    out->next_marker = buckets_xstrdup(last_key);
    if (!last_prefix) out->next_version_marker = buckets_xstrdup(last_vid);
  }
  free(all);
}

buckets_obj_err buckets_ep_list_versions(buckets_epool *L, const char *bucket, const char *prefix,
                                         const char *key_marker, const char *version_marker, const char *delimiter,
                                         int max_keys, bool incl_free, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if (max_keys <= 0) return BUCKETS_OBJ_OK;
  if (max_keys > BUCKETS_MAX_LIST_KEYS) max_keys = BUCKETS_MAX_LIST_KEYS;
  size_t nsrc = 0;
  buckets_obj_listing *src = buckets_xcalloc(L->nall ? L->nall : 1, sizeof(buckets_obj_listing));
  for (size_t s = 0; s < L->nsets; s++) {
    for (size_t i = 0; i < L->sets[s].n; i++) {
      buckets_drive *d = L->sets[s].drives[i];
      if (!d) continue;
      list_drive(d, bucket, prefix ? prefix : "", key_marker, version_marker, true, incl_free, delimiter, max_keys,
                 &src[nsrc++]);
    }
  }
  buckets_obj_listing_merge_versions(src, nsrc, max_keys, out);
  for (size_t k = 0; k < nsrc; k++) buckets_obj_list_free(&src[k]);
  free(src);
  return BUCKETS_OBJ_OK;
}

void buckets_obj_list_free(buckets_obj_listing *l) {
  for (size_t i = 0; i < l->nobjects; i++) buckets_object_info_free(&l->objects[i]);
  free(l->objects);
  for (size_t i = 0; i < l->nprefixes; i++) free(l->prefixes[i]);
  free(l->prefixes);
  free(l->next_marker);
  free(l->next_version_marker);
  memset(l, 0, sizeof(*l));
}

buckets_obj_err buckets_ep_delete_bucket(buckets_epool *L, const char *bucket) {
  buckets_obj_listing l;
  buckets_obj_err err = buckets_ep_list_versions(L, bucket, "", NULL, NULL, NULL, 1, false, &l);
  if (err) return err;
  bool empty = l.nobjects == 0 && l.nprefixes == 0;
  buckets_obj_list_free(&l);
  if (!empty) return BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY;
  size_t ok = 0;
  for (size_t i = 0; i < L->nall; i++) {
    if (!L->all[i]) continue;
    /* No objects remain; leftover empty prefix directories go too. */
    if (buckets_drive_delete(L->all[i], bucket, "", true, false) == BUCKETS_DRIVE_OK) ok++;
  }
  return ok >= bucket_quorum(L) || ok == buckets_ep_online(L) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

/* ---- multipart ------------------------------------------------------------------------- */

static char *sha_dir(const char *bucket, const char *object) {
  buckets_buf key = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&key, "%s/%s", bucket, object);
  uint8_t sum[32];
  char hex[65];
  buckets_sha256(key.data, key.len, sum);
  buckets_hex_encode(sum, 32, hex);
  buckets_buf_free(&key);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, "multipart/%s", hex);
  return p.data;
}

static bool safe_upload_uuid(const char *s) {
  if (!*s || strlen(s) > 80) return false;
  for (; *s; s++) {
    if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || *s == '-' || *s == 'x')) return false;
  }
  return true;
}

/* multipart/<sha>/<upload-uuid>, or NULL for a malformed upload ID. */
static char *upload_dir(const char *bucket, const char *object, const char *upload_id) {
  size_t n = strlen(upload_id);
  if (n == 0 || n >= BUCKETS_UPLOAD_ID_MAX) return NULL;
  uint8_t *raw = buckets_xmalloc(n + 4);
  long rl = buckets_base64url_raw_decode(upload_id, n, raw);
  char *uuid = NULL;
  if (rl > 0) {
    char *dec = buckets_xstrndup((char *)raw, (size_t)rl);
    char *dot = strchr(dec, '.');
    if (dot && safe_upload_uuid(dot + 1)) uuid = buckets_xstrdup(dot + 1);
    free(dec);
  }
  free(raw);
  if (!uuid) return NULL;
  char *sd = sha_dir(bucket, object);
  char *p = join(sd, uuid);
  free(sd);
  free(uuid);
  return p;
}

typedef struct {
  buckets_eset *set;
  buckets_xl_object up; /* the upload's version (quorum) */
  char data_dir[37];
  int dist[MAX_SET];
  bool has[MAX_SET]; /* drive holds the upload */
} upload;

static buckets_obj_err load_upload(buckets_epool *L, const char *bucket, const char *object, const char *dir,
                                   upload *u) {
  memset(u, 0, sizeof(*u));
  u->set = buckets_ep_set_for(L, object);
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  load_metas(u->set, BUCKETS_META_BUCKET, dir, m);
  buckets_obj_err err = quorum_version(m, u->set->n, NULL, &u->up, vidx);
  if (err == BUCKETS_OBJ_OK) {
    buckets_xl_version_id_string(u->up.data_dir, u->data_dir);
    for (size_t i = 0; i < u->set->n; i++) {
      u->has[i] = vidx[i] >= 0;
      u->dist[i] = i < u->up.ec_dist_n ? u->up.ec_dist[i] : (int)i + 1;
    }
  }
  free_metas(m, u->set->n);
  if (err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION) err = BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  return err;
}

buckets_obj_err buckets_ep_mpu_new(buckets_epool *L, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = buckets_ep_set_for(L, object);
  if ((err = check_namespace(s, bucket, object)) != BUCKETS_OBJ_OK) return err;
  int data = set_data(s), dist[MAX_SET];
  char *key = join(bucket, object);
  buckets_hash_order(key, (int)s->n, dist);
  free(key);
  uint8_t dd[16];
  char dd_s[37];
  new_uuid_bytes(dd, dd_s);
  buckets_xl_object o;
  init_version(&o, dd, 0, data, s->parity, dist, s->n);
  for (size_t i = 0; i < nmeta; i++) {
    /* xlMetaV2 keeps x-minio-internal-* keys in MetaSys */
    bool internal = strncasecmp(meta[i].key, BUCKETS_XL_RESERVED_PREFIX, strlen(BUCKETS_XL_RESERVED_PREFIX)) == 0;
    if (internal) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, meta[i].key, meta[i].value, meta[i].value_len);
    else buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, meta[i].key, meta[i].value, meta[i].value_len);
  }
  char uuid[BUCKETS_UUID_STR_LEN + 1], upload_uuid[80], plain[160];
  buckets_uuid_v4(uuid);
  snprintf(upload_uuid, sizeof(upload_uuid), "%sx%lld", uuid, (long long)o.mod_time);
  int pl = snprintf(plain, sizeof(plain), "%s.%s", L->deployment_id_str, upload_uuid);
  buckets_base64url_raw_encode((const uint8_t *)plain, (size_t)pl, upload_id);
  char *sd = sha_dir(bucket, object);
  char *dir = join(sd, upload_uuid);
  char *mp = join(dir, XL_META);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (!s->drives[i]) continue;
    o.ec_index = dist[i];
    buckets_xlmeta x = {0};
    buckets_buf enc = BUCKETS_BUF_INIT, bytes = BUCKETS_BUF_INIT;
    buckets_xl_header hdr;
    buckets_xl_object_encode(&o, &enc, &hdr);
    buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)enc.data, enc.len);
    buckets_xlmeta_serialize(&x, &bytes);
    buckets_xlmeta_free(&x);
    if (buckets_drive_write_all(s->drives[i], BUCKETS_META_BUCKET, mp, bytes.data, bytes.len) == BUCKETS_DRIVE_OK) ok++;
    buckets_buf_free(&bytes);
  }
  free(mp);
  free(dir);
  free(sd);
  buckets_xl_object_free(&o);
  return ok >= write_quorum(data, s->parity) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

static void encode_part_meta(buckets_buf *b, const buckets_part_info *p) {
  buckets_mp_map(b, 5 + (p->index_len > 0) + (p->cksum.type != 0));
  buckets_mp_cstr(b, "e");
  buckets_mp_cstr(b, p->etag);
  buckets_mp_cstr(b, "n");
  buckets_mp_int(b, p->number);
  buckets_mp_cstr(b, "s");
  buckets_mp_int(b, p->size);
  buckets_mp_cstr(b, "as");
  buckets_mp_int(b, p->actual_size);
  buckets_mp_cstr(b, "mt");
  buckets_mp_time(b, p->mod_time_ns);
  if (p->index_len) {
    buckets_mp_cstr(b, "i");
    buckets_mp_bin(b, p->index, p->index_len);
  }
  if (p->cksum.type) {
    char enc[64];
    buckets_checksum_encode(&p->cksum, enc);
    buckets_mp_cstr(b, "crc");
    buckets_mp_map(b, 1);
    buckets_mp_cstr(b, buckets_cksum_type_name(p->cksum.type));
    buckets_mp_cstr(b, enc);
  }
}

static bool decode_part_meta(const buckets_buf *raw, buckets_part_info *p) {
  memset(p, 0, sizeof(*p));
  buckets_mp_reader r = buckets_mp_reader_init(raw->data, raw->len);
  uint32_t fields;
  if (!buckets_mp_read_map(&r, &fields)) return false;
  for (uint32_t i = 0; i < fields; i++) {
    buckets_str k, s;
    int64_t v;
    if (!buckets_mp_read_str(&r, &k)) return false;
    if (buckets_str_eq_c(k, "e")) {
      if (!buckets_mp_read_str(&r, &s) || s.n >= sizeof(p->etag)) return false;
      memcpy(p->etag, s.p, s.n);
      p->etag[s.n] = '\0';
    } else if (buckets_str_eq_c(k, "n")) {
      if (!buckets_mp_read_int(&r, &v)) return false;
      p->number = (int)v;
    } else if (buckets_str_eq_c(k, "s")) {
      if (!buckets_mp_read_int(&r, &p->size)) return false;
    } else if (buckets_str_eq_c(k, "as")) {
      if (!buckets_mp_read_int(&r, &p->actual_size)) return false;
    } else if (buckets_str_eq_c(k, "mt")) {
      if (!buckets_mp_read_time(&r, &p->mod_time_ns)) return false;
    } else if (buckets_str_eq_c(k, "crc") && !buckets_mp_read_nil(&r)) {
      uint32_t cnt;
      if (!buckets_mp_read_map(&r, &cnt)) return false;
      for (uint32_t j = 0; j < cnt; j++) {
        buckets_str name, val;
        if (!buckets_mp_read_str(&r, &name) || !buckets_mp_read_str(&r, &val)) return false;
        char *nm = buckets_str_dup(name), *vv = buckets_str_dup(val);
        uint32_t t = buckets_cksum_type_parse(nm, NULL);
        if (!p->cksum.type && t && t != BUCKETS_CKSUM_INVALID) buckets_checksum_parse_value(t, vv, &p->cksum);
        free(nm);
        free(vv);
      }
    } else if (!buckets_mp_skip(&r)) {
      return false;
    }
  }
  return !r.err;
}

static buckets_obj_err mpu_put_part(buckets_epool *L, const char *bucket, const char *object, const char *upload_id,
                                    int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if (part_number < 1 || part_number > BUCKETS_MAX_PARTS) return BUCKETS_OBJ_ERR_INVALID_PART;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  if ((err = load_upload(L, bucket, object, dir, &u)) != BUCKETS_OBJ_OK) {
    free(dir);
    return err;
  }
  uint32_t ctype = opts ? opts->checksum_type & BUCKETS_CKSUM_BASE_MASK : 0;
  if (!ctype) {
    const buckets_xl_kv *alg = buckets_xl_kv_get(u.up.meta_user, u.up.nmeta_user, BUCKETS_MPU_CKSUM_META);
    if (alg) {
      uint32_t t = buckets_cksum_type_parse((const char *)alg->value, NULL);
      if (t != BUCKETS_CKSUM_INVALID) ctype = t & BUCKETS_CKSUM_BASE_MASK;
    }
  }
  encoder e = {.set = u.set, .data = u.up.ec_m, .parity = u.up.ec_n};
  memcpy(e.dist, u.dist, sizeof(e.dist));
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf tmp_file = BUCKETS_BUF_INIT, tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  buckets_buf_appendf(&tmp_file, "tmp/%s/part.%d", tmp_id, part_number);
  free(tmp_id);
  source src = {.rd = rd, .ud = rd_ud, .remaining = size < 0 ? INT64_MAX : size, .unknown = size < 0,
                .want_sha = opts && opts->want_sha256, .want_cks = ctype != 0};
  buckets_md5_init(&src.md5);
  buckets_sha256_init(&src.sha);
  buckets_cksum_hasher_init(&src.cks, ctype);
  err = encode_stream(&e, &src, size, tmp_file.data);
  size = src.total;
  uint8_t md5[16], sha[32];
  buckets_md5_final(&src.md5, md5);
  buckets_sha256_final(&src.sha, sha);
  buckets_checksum cks = {0};
  if (ctype) {
    cks.type = ctype;
    cks.raw_len = buckets_cksum_hasher_final(&src.cks, cks.raw);
  }
  if (!err && opts && opts->want_md5 && memcmp(md5, opts->want_md5, 16) != 0) err = BUCKETS_OBJ_ERR_BAD_DIGEST;
  if (!err && opts && opts->want_sha256 && memcmp(sha, opts->want_sha256, 32) != 0) err = BUCKETS_OBJ_ERR_SHA256_MISMATCH;
  if (!err && opts && opts->pre_commit) err = opts->pre_commit(opts->pre_commit_ud, &cks, NULL);
  if (!err) {
    buckets_part_info pi = {.number = part_number, .size = size, .actual_size = size, .mod_time_ns = now_ns(), .cksum = cks};
    buckets_hex_encode(md5, 16, pi.etag);
    if (opts && opts->part_commit) opts->part_commit(opts->part_commit_ud, &pi);
    buckets_buf pm = BUCKETS_BUF_INIT, dst = BUCKETS_BUF_INIT, dstmeta = BUCKETS_BUF_INIT;
    encode_part_meta(&pm, &pi);
    pi.index = NULL, pi.index_len = 0; /* borrowed from the hook */
    buckets_buf_appendf(&dst, "%s/%s/part.%d", dir, u.data_dir, part_number);
    buckets_buf_appendf(&dstmeta, "%s.meta", dst.data);
    int ok = 0;
    for (size_t i = 0; i < u.set->n; i++) {
      if (!e.alive[i] || !u.set->drives[i]) continue;
      buckets_drive *d = u.set->drives[i];
      if (buckets_drive_rename_file(d, BUCKETS_META_BUCKET, tmp_file.data, BUCKETS_META_BUCKET, dst.data) == BUCKETS_DRIVE_OK &&
          buckets_drive_write_all(d, BUCKETS_META_BUCKET, dstmeta.data, pm.data, pm.len) == BUCKETS_DRIVE_OK) {
        ok++;
      }
    }
    if (ok < write_quorum(e.data, e.parity)) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
    else if (out) *out = pi;
    buckets_buf_free(&pm);
    buckets_buf_free(&dst);
    buckets_buf_free(&dstmeta);
  }
  cleanup_tmp(u.set, tmp_dir.data);
  encoder_free(&e);
  buckets_buf_free(&tmp_file);
  buckets_buf_free(&tmp_dir);
  buckets_xl_object_free(&u.up);
  free(dir);
  return err;
}

/* The compression index ("i") of a part record, from the first drive that has it. */
static void read_part_index(const upload *u, const char *dir, int number, buckets_buf *out) {
  for (size_t i = 0; i < u->set->n; i++) {
    if (!u->has[i] || !u->set->drives[i]) continue;
    buckets_buf mp = BUCKETS_BUF_INIT, raw = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&mp, "%s/%s/part.%d.meta", dir, u->data_dir, number);
    bool read = buckets_drive_read_all(u->set->drives[i], BUCKETS_META_BUCKET, mp.data, &raw) == BUCKETS_DRIVE_OK;
    if (read) {
      buckets_mp_reader r = buckets_mp_reader_init(raw.data, raw.len);
      uint32_t fields;
      if (buckets_mp_read_map(&r, &fields)) {
        for (uint32_t f = 0; f < fields; f++) {
          buckets_str k, v;
          if (!buckets_mp_read_str(&r, &k)) break;
          if (buckets_str_eq_c(k, "i")) {
            if (buckets_mp_read_bin(&r, &v)) buckets_buf_append(out, v.p, v.n);
            break;
          }
          if (!buckets_mp_skip(&r)) break;
        }
      }
    }
    buckets_buf_free(&mp);
    buckets_buf_free(&raw);
    if (read) return;
  }
}

static int part_cmp(const void *a, const void *b) {
  return ((const buckets_part_info *)a)->number - ((const buckets_part_info *)b)->number;
}

/* Part records from the first drive holding the upload (they are identical on all). */
static void read_parts(const upload *u, const char *dir, buckets_part_info **parts, size_t *n) {
  *parts = NULL;
  *n = 0;
  for (size_t i = 0; i < u->set->n; i++) {
    if (!u->has[i] || !u->set->drives[i]) continue;
    buckets_drive *d = u->set->drives[i];
    buckets_buf pdir = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&pdir, "%s/%s", dir, u->data_dir);
    buckets_dir_list dl;
    if (buckets_drive_list_dir(d, BUCKETS_META_BUCKET, pdir.data, &dl) == BUCKETS_DRIVE_OK) {
      size_t cap = 0;
      for (size_t k = 0; k < dl.n; k++) {
        int num;
        char tail[8];
        if (sscanf(dl.names[k], "part.%d%7s", &num, tail) != 2 || strcmp(tail, ".meta") != 0) continue;
        buckets_buf mp = BUCKETS_BUF_INIT, raw = BUCKETS_BUF_INIT;
        buckets_buf_appendf(&mp, "%s/%s", pdir.data, dl.names[k]);
        buckets_part_info pi;
        if (buckets_drive_read_all(d, BUCKETS_META_BUCKET, mp.data, &raw) == BUCKETS_DRIVE_OK && decode_part_meta(&raw, &pi) &&
            pi.number == num) {
          if (*n == cap) {
            cap = cap ? cap * 2 : 16;
            *parts = buckets_xrealloc(*parts, cap * sizeof(buckets_part_info));
          }
          (*parts)[(*n)++] = pi;
        }
        buckets_buf_free(&mp);
        buckets_buf_free(&raw);
      }
      buckets_dir_list_free(&dl);
    }
    buckets_buf_free(&pdir);
    break;
  }
  if (*n) qsort(*parts, *n, sizeof(buckets_part_info), part_cmp);
}

buckets_obj_err buckets_ep_mpu_list_parts(buckets_epool *L, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated) {
  *parts = NULL;
  *n = 0;
  *truncated = false;
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  if ((err = load_upload(L, bucket, object, dir, &u)) != BUCKETS_OBJ_OK) {
    free(dir);
    return err;
  }
  buckets_part_info *all;
  size_t total;
  read_parts(&u, dir, &all, &total);
  size_t start = 0;
  while (start < total && all[start].number <= marker) start++;
  size_t count = total - start;
  if (max >= 0 && count > (size_t)max) {
    count = (size_t)max;
    *truncated = true;
  }
  if (count) {
    *parts = buckets_xmalloc(count * sizeof(buckets_part_info));
    memcpy(*parts, all + start, count * sizeof(buckets_part_info));
  }
  *n = count;
  free(all);
  buckets_xl_object_free(&u.up);
  free(dir);
  return BUCKETS_OBJ_OK;
}

static buckets_obj_err mpu_abort(buckets_epool *L, const char *bucket, const char *object, const char *upload_id) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  if ((err = load_upload(L, bucket, object, dir, &u)) == BUCKETS_OBJ_OK) {
    for (size_t i = 0; i < u.set->n; i++) {
      if (u.set->drives[i]) buckets_drive_delete(u.set->drives[i], BUCKETS_META_BUCKET, dir, true, true);
    }
    buckets_xl_object_free(&u.up);
  }
  free(dir);
  return err;
}

static void canonical_etag(const char *in, char *out, size_t cap) {
  while (*in == '"') in++;
  size_t n = strlen(in);
  while (n && in[n - 1] == '"') n--;
  snprintf(out, cap, "%.*s", (int)n, in);
}

static buckets_obj_err mpu_complete(buckets_epool *L, const char *bucket, const char *object,
                                    const char *upload_id, const buckets_complete_part *req, size_t nreq,
                                    const buckets_checksum *want, const buckets_complete_opts *co, buckets_object_info *out) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  if ((err = load_upload(L, bucket, object, dir, &u)) != BUCKETS_OBJ_OK) {
    free(dir);
    return err;
  }
  buckets_part_info *have;
  size_t nhave;
  read_parts(&u, dir, &have, &nhave);

  uint32_t ctype = 0;
  const buckets_xl_kv *alg = buckets_xl_kv_get(u.up.meta_user, u.up.nmeta_user, BUCKETS_MPU_CKSUM_META);
  if (alg) {
    const buckets_xl_kv *ot = buckets_xl_kv_get(u.up.meta_user, u.up.nmeta_user, BUCKETS_MPU_CKSUM_TYPE_META);
    ctype = buckets_cksum_type_parse((const char *)alg->value, ot ? (const char *)ot->value : NULL);
    if (ctype == BUCKETS_CKSUM_INVALID) ctype = 0;
  }
  bool full = (ctype & (BUCKETS_CKSUM_FULL_OBJECT | BUCKETS_CKSUM_CRC64NVME)) != 0;
  size_t clen = buckets_cksum_raw_len(ctype);
  buckets_buf combined = BUCKETS_BUF_INIT;
  uint8_t merged_ck[32];

  buckets_xl_object o;
  init_version(&o, u.up.data_dir, 0, u.up.ec_m, u.up.ec_n, u.dist, u.set->n);
  if ((co && co->versioned)) {
    char vs[37];
    new_uuid_bytes(o.version_id, vs);
  }
  buckets_md5_ctx etag_md5;
  buckets_md5_init(&etag_md5);
  int64_t total = 0, actual_total = 0;
  bool compressed = false;
  for (size_t i = 0; i < u.up.nmeta_sys && !compressed; i++)
    compressed = strcasecmp(u.up.meta_sys[i].key, "X-Minio-Internal-compression") == 0;
  if (nreq == 0) err = BUCKETS_OBJ_ERR_INVALID_PART;
  for (size_t i = 0; i < nreq && !err; i++) {
    if (i > 0 && req[i].number <= req[i - 1].number) {
      err = BUCKETS_OBJ_ERR_INVALID_PART_ORDER;
      break;
    }
    const buckets_part_info *p = NULL;
    for (size_t j = 0; j < nhave; j++) {
      if (have[j].number == req[i].number) p = &have[j];
    }
    char want_etag[128], have_etag[128] = "";
    canonical_etag(req[i].etag ? req[i].etag : "", want_etag, sizeof(want_etag));
    if (p) {
      if (co && co->client_etag) co->client_etag(co->ud, p->etag, have_etag);
      else snprintf(have_etag, sizeof(have_etag), "%s", p->etag);
    }
    if (!p || strcmp(have_etag, want_etag) != 0) {
      err = BUCKETS_OBJ_ERR_INVALID_PART;
      break;
    }
    if (ctype) {
      char have_enc[64] = "";
      if (p->cksum.type & ctype & BUCKETS_CKSUM_BASE_MASK) buckets_checksum_encode(&p->cksum, have_enc);
      if (!have_enc[0] || !req[i].checksum || strcmp(req[i].checksum, have_enc) != 0) {
        err = BUCKETS_OBJ_ERR_INVALID_PART;
        break;
      }
      if (full && combined.len) buckets_cksum_combine(ctype, merged_ck, p->cksum.raw, p->actual_size);
      else if (full) memcpy(merged_ck, p->cksum.raw, clen);
      buckets_buf_append(&combined, p->cksum.raw, clen);
    }
    if (i + 1 < nreq && p->actual_size < BUCKETS_MIN_PART_SIZE) {
      err = BUCKETS_OBJ_ERR_PART_TOO_SMALL;
      break;
    }
    /* etag.Multipart: over the ETags clients know */
    uint8_t raw[16];
    for (int k = 0; k < 16; k++) {
      unsigned v;
      sscanf(have_etag + 2 * k, "%2x", &v);
      raw[k] = (uint8_t)v;
    }
    buckets_md5_update(&etag_md5, raw, 16);
    buckets_xl_part_add(&o, p->number, p->size, p->actual_size, NULL);
    if (compressed) {
      buckets_buf idx = BUCKETS_BUF_INIT;
      read_part_index(&u, dir, p->number, &idx);
      buckets_xl_part_set_index(&o.parts[o.nparts - 1], idx.data, idx.len);
      buckets_buf_free(&idx);
    }
    total += p->size;
    actual_total += p->actual_size;
  }
  if (!err) {
    o.size = total;
    for (size_t i = 0; i < u.up.nmeta_user; i++) {
      const char *k = u.up.meta_user[i].key;
      if (strcmp(k, BUCKETS_MPU_CKSUM_META) == 0 || strcmp(k, BUCKETS_MPU_CKSUM_TYPE_META) == 0) continue;
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, k, u.up.meta_user[i].value, u.up.meta_user[i].value_len);
    }
    for (size_t i = 0; i < u.up.nmeta_sys; i++) /* encryption keys and the like carry over */
      buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, u.up.meta_sys[i].key, u.up.meta_sys[i].value, u.up.meta_sys[i].value_len);
    if (ctype) {
      buckets_checksum fin = {.type = ctype | BUCKETS_CKSUM_MULTIPART | BUCKETS_CKSUM_INCLUDES_MULTIPART,
                              .raw_len = clen, .want_parts = (int)nreq};
      if (full) {
        memcpy(fin.raw, merged_ck, clen);
      } else {
        buckets_cksum_hasher h;
        buckets_cksum_hasher_init(&h, ctype);
        buckets_cksum_hasher_update(&h, combined.data, combined.len);
        buckets_cksum_hasher_final(&h, fin.raw);
      }
      if (want && want->type) {
        bool ok = want->raw_len == clen && memcmp(want->raw, fin.raw, clen) == 0 &&
                  (full || want->want_parts == 0 || want->want_parts == (int)nreq);
        if (!ok) err = BUCKETS_OBJ_ERR_BAD_CHECKSUM;
      }
      buckets_buf stored = BUCKETS_BUF_INIT;
      buckets_checksum_append(&fin, (const uint8_t *)combined.data, combined.len, &stored);
      buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, "x-minio-internal-crc", stored.data, stored.len);
      buckets_buf_free(&stored);
    }
  }
  if (!err) {
    uint8_t sum[16];
    char etag[48];
    buckets_md5_final(&etag_md5, sum);
    buckets_hex_encode(sum, 16, etag);
    snprintf(etag + 32, sizeof(etag) - 32, "-%zu", nreq);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", etag, strlen(etag));
    char actual[32];
    int al = snprintf(actual, sizeof(actual), "%lld", (long long)actual_total);
    buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, ACTUAL_SIZE_KEY, actual, (size_t)al);
    if (co && co->pre_commit) err = co->pre_commit(co->ud, &o);
  }
  if (!err) {
    /* Drop part.N.meta files and parts left out, then install on every drive. */
    for (size_t i = 0; i < u.set->n; i++) {
      if (!u.has[i] || !u.set->drives[i]) continue;
      for (size_t j = 0; j < nhave; j++) {
        buckets_buf f = BUCKETS_BUF_INIT;
        buckets_buf_appendf(&f, "%s/%s/part.%d.meta", dir, u.data_dir, have[j].number);
        buckets_drive_delete(u.set->drives[i], BUCKETS_META_BUCKET, f.data, false, false);
        bool used = false;
        for (size_t k = 0; k < nreq; k++) used |= req[k].number == have[j].number;
        if (!used) {
          buckets_buf_reset(&f);
          buckets_buf_appendf(&f, "%s/%s/part.%d", dir, u.data_dir, have[j].number);
          buckets_drive_delete(u.set->drives[i], BUCKETS_META_BUCKET, f.data, false, false);
        }
        buckets_buf_free(&f);
      }
    }
    buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
    size_t committed = 0;
    err = !lk ? BUCKETS_OBJ_ERR_TIMEOUT : check_namespace(u.set, bucket, object);
    if (!err) {
      err = commit_version(u.set, bucket, object, &o, u.dist, u.has, NULL, dir, true,
                           write_quorum(u.up.ec_m, u.up.ec_n), &committed);
    }
    buckets_nslock_unlock(lk);
    if (!err && committed < u.set->n) report_partial(L, u.set, bucket, object, &o, committed);
    if (!err) {
      for (size_t i = 0; i < u.set->n; i++) {
        if (u.set->drives[i]) buckets_drive_delete(u.set->drives[i], BUCKETS_META_BUCKET, dir, true, true);
      }
      if (out) {
        o.ec_index = 1;
        fill_info(out, object, &o);
      }
    }
  }
  buckets_xl_object_free(&o);
  buckets_xl_object_free(&u.up);
  buckets_buf_free(&combined);
  free(have);
  free(dir);
  return err;
}

/* Upload-ID locks: parts share a read lock, abort/complete take it exclusively. */
static buckets_nslock_entry *lock_upload(buckets_epool *L, const char *bucket, const char *object,
                                        const char *upload_id, bool write, buckets_obj_err *err) {
  char *dir = upload_dir(bucket, object, upload_id);
  *err = BUCKETS_OBJ_OK;
  if (!dir) return NULL; /* invalid ID: the operation reports NoSuchUpload */
  buckets_nslock_entry *lk = lock_ns(L, BUCKETS_META_BUCKET, dir, write);
  if (!lk) *err = BUCKETS_OBJ_ERR_TIMEOUT;
  free(dir);
  return lk;
}

buckets_obj_err buckets_ep_mpu_put_part(buckets_epool *L, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out) {
  buckets_obj_err err;
  buckets_nslock_entry *lk = lock_upload(L, bucket, object, upload_id, false, &err);
  if (!err) err = mpu_put_part(L, bucket, object, upload_id, part_number, rd, rd_ud, size, opts, out);
  buckets_nslock_unlock(lk);
  return err;
}

buckets_obj_err buckets_ep_mpu_abort(buckets_epool *L, const char *bucket, const char *object, const char *upload_id) {
  buckets_obj_err err;
  buckets_nslock_entry *lk = lock_upload(L, bucket, object, upload_id, true, &err);
  if (!err) err = mpu_abort(L, bucket, object, upload_id);
  buckets_nslock_unlock(lk);
  return err;
}

buckets_obj_err buckets_ep_mpu_complete(buckets_epool *L, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *req, size_t nreq,
                                         const buckets_checksum *want, const buckets_complete_opts *co,
                                         buckets_object_info *out) {
  buckets_obj_err err;
  buckets_nslock_entry *lk = lock_upload(L, bucket, object, upload_id, true, &err);
  if (!err) err = mpu_complete(L, bucket, object, upload_id, req, nreq, want, co, out);
  buckets_nslock_unlock(lk);
  return err;
}

buckets_obj_err buckets_ep_mpu_stat(buckets_epool *L, const char *bucket, const char *object, const char *upload_id,
                                    buckets_object_info *out) {
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  err = load_upload(L, bucket, object, dir, &u);
  free(dir);
  if (err) return err;
  fill_info(out, object, &u.up);
  buckets_xl_object_free(&u.up);
  return BUCKETS_OBJ_OK;
}

buckets_obj_err buckets_ep_mpu_list_uploads(buckets_epool *L, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n) {
  *uploads = NULL;
  *n = 0;
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if (!object || !*object || buckets_obj_check_name(object) != BUCKETS_OBJ_OK) return BUCKETS_OBJ_OK;
  buckets_eset *s = buckets_ep_set_for(L, object);
  char *sd = sha_dir(bucket, object);
  size_t cap = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (!s->drives[i]) continue;
    buckets_dir_list dl;
    if (buckets_drive_list_dir(s->drives[i], BUCKETS_META_BUCKET, sd, &dl) != BUCKETS_DRIVE_OK) continue;
    for (size_t k = 0; k < dl.n; k++) {
      char *nm = dl.names[k];
      size_t nl = strlen(nm);
      if (!nl || nm[nl - 1] != '/') continue;
      nm[nl - 1] = '\0';
      if (!safe_upload_uuid(nm)) continue;
      char plain[160], id[BUCKETS_UPLOAD_ID_MAX];
      int pl = snprintf(plain, sizeof(plain), "%s.%s", L->deployment_id_str, nm);
      buckets_base64url_raw_encode((const uint8_t *)plain, (size_t)pl, id);
      bool dup = false;
      for (size_t j = 0; j < *n; j++) dup |= strcmp((*uploads)[j].upload_id, id) == 0;
      if (dup) continue;
      char *dir = join(sd, nm);
      upload u;
      if (load_upload(L, bucket, object, dir, &u) == BUCKETS_OBJ_OK) {
        if (*n == cap) {
          cap = cap ? cap * 2 : 8;
          *uploads = buckets_xrealloc(*uploads, cap * sizeof(buckets_upload_info));
        }
        buckets_upload_info *ui = &(*uploads)[(*n)++];
        ui->object = buckets_xstrdup(object);
        ui->initiated_ns = u.up.mod_time;
        memcpy(ui->upload_id, id, sizeof(ui->upload_id));
        buckets_xl_object_free(&u.up);
      }
      free(dir);
    }
    buckets_dir_list_free(&dl);
  }
  free(sd);
  return BUCKETS_OBJ_OK;
}

void buckets_upload_info_free(buckets_upload_info *u, size_t n) {
  for (size_t i = 0; i < n; i++) free(u[i].object);
  free(u);
}

/* ---- healing ------------------------------------------------------------------------ */

typedef struct {
  buckets_eset *s;
  const char *bucket, *op, *data_dir, *vkey;
  const buckets_xl_object *o;
  const long *vidx;
  const dmeta *m;
  bool deep, is_inline;
  int data;
  buckets_heal_state st[MAX_SET];
  int parts_not_found[MAX_SET]; /* part files absent (not merely corrupt) */
} check_ctx;

static bool verify_frames(const uint8_t *buf, int64_t len, int64_t size, int data) {
  int64_t shard_cap = ceil_div(BUCKETS_BLOCK_SIZE, data), off = 0;
  for (int64_t done = 0; done < size; done += BUCKETS_BLOCK_SIZE) {
    int64_t sl = ceil_div(BUCKETS_MIN((int64_t)BUCKETS_BLOCK_SIZE, size - done), data);
    if (off + HASH_LEN + sl > len) return false;
    uint8_t h[HASH_LEN];
    buckets_hh256(buckets_bitrot_key, buf + off + HASH_LEN, (size_t)sl, h);
    if (!buckets_ct_equal(h, buf + off, HASH_LEN)) return false;
    off += HASH_LEN + shard_cap;
  }
  return true;
}

/* xl-storage CheckParts / VerifyFile for one drive. */
static void check_one(void *ctx, size_t i) {
  check_ctx *c = ctx;
  buckets_drive *d = c->s->drives[i];
  if (!d) {
    c->st[i] = BUCKETS_HEAL_OFFLINE;
    return;
  }
  if (c->vidx[i] < 0) {
    c->st[i] = BUCKETS_HEAL_MISSING;
    return;
  }
  c->st[i] = BUCKETS_HEAL_OK;
  const buckets_xl_object *o = c->o;
  if (o->type != BUCKETS_XL_TYPE_OBJECT || !buckets_xl_object_uses_data_dir(o)) return; /* metadata only */
  if (c->is_inline) {
    buckets_str sh;
    if (!buckets_xlmeta_inline_get(&c->m[i].x, c->vkey, &sh) ||
        (int64_t)sh.n != shard_file_size(o->size, c->data) + ceil_div(o->size, BUCKETS_BLOCK_SIZE) * HASH_LEN ||
        (c->deep && !verify_frames((const uint8_t *)sh.p, (int64_t)sh.n, o->size, c->data))) {
      c->st[i] = BUCKETS_HEAL_CORRUPT;
    }
    return;
  }
  for (size_t p = 0; p < o->nparts && c->st[i] == BUCKETS_HEAL_OK; p++) {
    int64_t psize = o->parts[p].size;
    int64_t want = shard_file_size(psize, c->data) + ceil_div(psize, BUCKETS_BLOCK_SIZE) * HASH_LEN;
    buckets_buf path = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "%s/%s/part.%d", c->op, c->data_dir, o->parts[p].number);
    int64_t have = -1;
    buckets_drive_err fe = buckets_drive_file_size(d, c->bucket, path.data, &have);
    if (fe == BUCKETS_DRIVE_ERR_NOT_FOUND) c->parts_not_found[i]++;
    if (fe != BUCKETS_DRIVE_OK || have != want) {
      c->st[i] = BUCKETS_HEAL_CORRUPT;
    } else if (c->deep && want > 0) {
      uint8_t *buf = buckets_xmalloc((size_t)want);
      size_t got = 0;
      if (buckets_drive_read_at(d, c->bucket, path.data, 0, buf, (size_t)want, &got) != BUCKETS_DRIVE_OK ||
          (int64_t)got != want || !verify_frames(buf, want, psize, c->data)) {
        c->st[i] = BUCKETS_HEAL_CORRUPT;
      }
      free(buf);
    }
    buckets_buf_free(&path);
  }
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *op, *data_dir;
  const bool *outdated;
} stale_ctx;

/* rename_data cannot replace a non-empty data dir: clear the old copy first. */
static void remove_stale(void *ctx, size_t i) {
  stale_ctx *c = ctx;
  if (!c->outdated[i]) return;
  char *p = join(c->op, c->data_dir);
  buckets_drive_delete(c->s->drives[i], c->bucket, p, true, false);
  free(p);
}

/* Rebuilds the shards of version o on the outdated drives and commits them. */
static buckets_obj_err rebuild(buckets_epool *L, buckets_eset *s, const char *bucket, const char *object,
                               const dmeta *m, const long *vidx_good, const buckets_xl_object *o, bool is_inline,
                               bool *outdated, size_t *committed) {
  int dist[MAX_SET];
  for (size_t i = 0; i < s->n; i++) dist[i] = i < o->ec_dist_n ? o->ec_dist[i] : (int)i + 1;
  char data_dir[37];
  buckets_xl_version_id_string(o->data_dir, data_dir);
  char *op = obj_path(object);
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  free(tmp_id);
  bool with_data = o->type == BUCKETS_XL_TYPE_OBJECT && buckets_xl_object_uses_data_dir(o); /* not a remote copy */
  bool has_data = with_data && !is_inline && o->nparts > 0;
  encoder e = {.set = s, .data = o->ec_m > 0 ? o->ec_m : 1, .parity = o->ec_n, .inline_mode = is_inline};
  memcpy(e.dist, dist, sizeof(dist));
  buckets_obj_err err = BUCKETS_OBJ_OK;
  if (with_data) {
    buckets_obj_reader *r = reader_new(L, s, bucket, object, m, vidx_good, o);
    r->quiet = true;
    for (size_t p = 0; p < r->nparts && !err; p++) {
      buckets_buf file = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&file, "%s/%s/part.%d", tmp_dir.data, data_dir, r->parts[p].number);
      /* Open writers (or inline buffers) only on the outdated drives. */
      e.file = file.data;
      for (size_t i = 0; i < s->n; i++) {
        e.alive[i] = false;
        e.w[i] = NULL;
        if (p == 0) e.ibuf[i] = BUCKETS_BUF_INIT;
        if (!outdated[i]) continue;
        e.alive[i] = is_inline || buckets_drive_create_file(s->drives[i], BUCKETS_META_BUCKET, file.data, &e.w[i]) ==
                                      BUCKETS_DRIVE_OK;
        if (!e.alive[i]) outdated[i] = false;
      }
      r->part = p;
      r->block_index = -1;
      e.shards = r->shards;
      int64_t ps = r->parts[p].size;
      for (int64_t bi = 0; bi * BUCKETS_BLOCK_SIZE < ps; bi++) {
        if (!load_block(r, bi)) {
          err = BUCKETS_OBJ_ERR_READ_QUORUM;
          break;
        }
        e.sl = (size_t)ceil_div((int64_t)r->block_len, e.data);
        if (e.parity) buckets_rs_encode(r->rs, r->shards, e.sl); /* regenerate parity from the data */
        buckets_io_parallel(s->n, enc_write, &e);
      }
      e.abort_writes = err != BUCKETS_OBJ_OK;
      buckets_io_parallel(s->n, enc_close, &e);
      for (size_t i = 0; i < s->n; i++) outdated[i] &= e.alive[i];
      buckets_buf_free(&file);
    }
    buckets_obj_reader_free(r);
  }
  if (!err) {
    if (has_data) {
      stale_ctx sc = {s, bucket, op, data_dir, outdated};
      buckets_io_parallel(s->n, remove_stale, &sc);
    }
    buckets_xl_object copy = *o; /* commit_version only reads it */
    err = commit_version(s, bucket, object, &copy, dist, outdated, is_inline ? e.ibuf : NULL, tmp_dir.data, has_data, 1,
                         committed);
  }
  if (has_data || err) cleanup_tmp(s, tmp_dir.data);
  encoder_free(&e);
  buckets_buf_free(&tmp_dir);
  free(op);
  return err;
}

typedef struct {
  buckets_eset *s;
  const char *bucket, *op;
  uint8_t id[16];
  char key[37];
  const bool *has;
} purge_ctx;

static void purge_one(void *ctx, size_t i) {
  purge_ctx *c = ctx;
  if (!c->has[i]) return;
  /* Reuse DeleteObject's per-drive step on a fresh read of this drive. */
  dmeta m;
  memset(&m, 0, sizeof(m));
  char *mp = join(c->op, XL_META);
  buckets_buf raw = BUCKETS_BUF_INIT;
  if (buckets_drive_read_all(c->s->drives[i], c->bucket, mp, &raw) == BUCKETS_DRIVE_OK) {
    m.loaded = buckets_xlmeta_parse(raw.data, raw.len, &m.x) == BUCKETS_XL_OK;
  }
  buckets_buf_free(&raw);
  free(mp);
  del_ctx d = {.s = c->s, .bucket = c->bucket, .op = c->op};
  dmeta *arr = buckets_xcalloc(c->s->n, sizeof(dmeta));
  arr[i] = m;
  d.m = arr;
  memcpy(d.id, c->id, 16);
  memcpy(d.key, c->key, sizeof(d.key));
  delete_one(&d, i);
  if (arr[i].loaded) buckets_xlmeta_free(&arr[i].x);
  free(arr);
}

static buckets_obj_err heal_version(buckets_epool *L, buckets_eset *s, const char *bucket, const char *object,
                                    const uint8_t id[16], const buckets_heal_opts *opts, buckets_heal_result *res) {
  char *op = obj_path(object);
  dmeta m[MAX_SET];
  load_metas(s, bucket, op, m);
  char vkey[37];
  buckets_xl_version_id_string(id, vkey);
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = quorum_version(m, s->n, vkey, &o, vidx);
  res->versions++;
  res->ndrives = s->n;
  /* MinIO's isObjectDangling inputs: xl.meta that is definitely absent vs.
   * unknown (offline drive, unreadable file), from the drives' own copies. */
  bool has[MAX_SET];
  size_t nhas = 0, nf_meta = 0, na_meta = 0;
  const buckets_xl_header *valid = NULL;
  for (size_t i = 0; i < s->n; i++) {
    has[i] = false;
    long k = s->drives[i] && m[i].loaded ? buckets_xlmeta_find(&m[i].x, id) : -1;
    if (k >= 0) {
      has[i] = true;
      nhas++;
      if (!valid) valid = &m[i].x.versions[k].hdr;
    } else if (s->drives[i] && (m[i].missing || m[i].loaded)) {
      nf_meta++;
    } else {
      na_meta++;
    }
  }

  buckets_heal_state st[MAX_SET];
  bool dangling = false;
  size_t nf_parts = 0;
  if (err == BUCKETS_OBJ_OK) {
    bool is_inline = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE) != NULL;
    char data_dir[37];
    buckets_xl_version_id_string(o.data_dir, data_dir);
    check_ctx c = {.s = s, .bucket = bucket, .op = op, .data_dir = data_dir, .vkey = vkey, .o = &o, .vidx = vidx,
                   .m = m, .deep = opts && opts->deep, .is_inline = is_inline, .data = o.ec_m > 0 ? o.ec_m : 1};
    buckets_io_parallel(s->n, check_one, &c);
    memcpy(st, c.st, sizeof(st));
    for (size_t i = 0; i < s->n; i++) nf_parts = BUCKETS_MAX(nf_parts, (size_t)c.parts_not_found[i]);
    res->size = o.size;
    res->data_blocks = o.ec_m;
    res->parity_blocks = o.ec_n;
    long good[MAX_SET];
    bool outdated[MAX_SET];
    int ngood = 0, nbad = 0;
    for (size_t i = 0; i < s->n; i++) {
      good[i] = st[i] == BUCKETS_HEAL_OK ? vidx[i] : -1;
      ngood += st[i] == BUCKETS_HEAL_OK;
      nbad += st[i] == BUCKETS_HEAL_MISSING || st[i] == BUCKETS_HEAL_CORRUPT;
      outdated[i] = st[i] == BUCKETS_HEAL_MISSING || st[i] == BUCKETS_HEAL_CORRUPT;
    }
    if (o.type == BUCKETS_XL_TYPE_OBJECT && ngood < c.data) {
      err = BUCKETS_OBJ_ERR_READ_QUORUM; /* unless it proves dangling below */
      dangling = true;
    } else if (nbad && !(opts && opts->dry_run)) {
      size_t committed = 0;
      err = rebuild(L, s, bucket, object, m, good, &o, is_inline, outdated, &committed);
      for (size_t i = 0; i < s->n; i++) {
        if (outdated[i] && !err) res->healed++;
      }
      if (!err) {
        for (size_t i = 0; i < s->n; i++) {
          res->after[i] = outdated[i] ? BUCKETS_HEAL_OK : st[i];
          res->before[i] = st[i];
        }
      }
    }
    if (err || !nbad || (opts && opts->dry_run)) {
      for (size_t i = 0; i < s->n; i++) res->before[i] = res->after[i] = st[i];
    }
    buckets_xl_object_free(&o);
  } else if (nhas > 0) {
    dangling = true; /* some copies, but no quorum on them: maybe dangling */
    for (size_t i = 0; i < s->n; i++) {
      st[i] = !s->drives[i] ? BUCKETS_HEAL_OFFLINE : has[i] ? BUCKETS_HEAL_OK : BUCKETS_HEAL_MISSING;
      res->before[i] = res->after[i] = st[i];
    }
  }
  if (dangling) {
    /* isObjectDangling: never while any drive's answer is unknown; delete
     * markers need a majority missing; objects need more than `parity`
     * drives definitely without the metadata or without a part. Corrupt
     * shards never count: they prove the object existed. */
    int parity = valid ? valid->ec_n : 0;
    if (na_meta > 0) dangling = false;
    else if (valid && valid->type != BUCKETS_XL_TYPE_OBJECT) dangling = nf_meta > (s->n + 1) / 2;
    else dangling = nf_meta > (size_t)parity || nf_parts > (size_t)parity;
  }
  if (dangling) {
    if (opts && opts->remove_dangling && !opts->dry_run) {
      buckets_log_info("removing dangling %s/%s (version %s)", bucket, object, vkey);
      purge_ctx pc = {.s = s, .bucket = bucket, .op = op, .has = has};
      memcpy(pc.id, id, 16);
      memcpy(pc.key, vkey, sizeof(pc.key));
      buckets_io_parallel(s->n, purge_one, &pc);
      res->dangling++;
      for (size_t i = 0; i < s->n; i++) res->after[i] = s->drives[i] ? BUCKETS_HEAL_OK : BUCKETS_HEAL_OFFLINE;
      err = BUCKETS_OBJ_OK;
    } else {
      err = BUCKETS_OBJ_ERR_READ_QUORUM;
    }
  }
  free_metas(m, s->n);
  free(op);
  return err;
}

static const char *drive_state(buckets_heal_state st) {
  switch (st) {
  case BUCKETS_HEAL_OK: return "ok";
  case BUCKETS_HEAL_OFFLINE: return "offline";
  case BUCKETS_HEAL_MISSING: return "missing";
  case BUCKETS_HEAL_CORRUPT: return "corrupt";
  }
  return "unknown";
}

static void heal_drives(buckets_buf *b, buckets_epool *L, const buckets_eset *s, const buckets_heal_state *st, size_t n) {
  size_t set = (size_t)(s - L->sets);
  buckets_buf_append_c(b, "{\"drives\":[");
  for (size_t i = 0; i < n; i++) {
    const buckets_drive *d = s->drives[i] ? s->drives[i] : L->all[set * s->n + i];
    buckets_buf_append_c(b, i ? ",{\"uuid\":\"\",\"endpoint\":" : "{\"uuid\":\"\",\"endpoint\":");
    buckets_json_go_string(b, d && d->root ? d->root : "", d && d->root ? strlen(d->root) : 0);
    buckets_buf_appendf(b, ",\"state\":\"%s\"}", drive_state(st[i]));
  }
  buckets_buf_append_c(b, "]}");
}

/* healTrace and auditHealObject for one version (MinIO's healObject defers):
 * a heal.Object trace with its madmin.HealResultItem, and a HealObject
 * audit entry. The scanner's checks report only what needed healing. */
static void heal_report(buckets_epool *L, const buckets_eset *s, const char *bucket, const char *object,
                        const uint8_t id[16], const buckets_heal_opts *opts, const buckets_heal_result *r,
                        buckets_obj_err err, int64_t start) {
  if (opts && opts->quiet_clean && !err && !r->healed && !r->dangling) return;
  char vkey[37];
  buckets_xl_version_id_string(id, vkey);
  const char *errs = err ? buckets_obj_strerror(err) : NULL;
  if (buckets_trace_wanted(BUCKETS_TRACE_HEALING)) {
    int64_t dur = now_ns() - start;
    char when[64];
    buckets_time_rfc3339_nano((long long)(start / 1000000000LL), (long)(start % 1000000000LL), when);
    buckets_buf b = BUCKETS_BUF_INIT, path = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "%s/%s", bucket, object);
    buckets_buf_appendf(&b, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_HEALING);
    const char *node = buckets_trace_node();
    buckets_json_go_string(&b, node, strlen(node));
    buckets_buf_appendf(&b, ",\"funcname\":\"heal.Object\",\"time\":\"%s\",\"path\":", when);
    buckets_json_go_string(&b, path.data, path.len);
    buckets_buf_appendf(&b, ",\"dur\":%lld", (long long)dur);
    if (r->size) buckets_buf_appendf(&b, ",\"bytes\":%lld", (long long)r->size);
    if (errs) {
      buckets_buf_append_c(&b, ",\"error\":");
      buckets_json_go_string(&b, errs, strlen(errs));
    }
    bool dry = opts && opts->dry_run, remove = opts && opts->remove_dangling;
    buckets_buf_appendf(&b, ",\"custom\":{\"disks\":\"%zu\",\"dry\":\"%s\",\"mode\":\"%d\",\"remove\":\"%s\",\"version-id\":\"%s\"}",
                        s->n, dry ? "true" : "false", opts ? opts->scan_mode : 0, remove ? "true" : "false", vkey);
    buckets_buf_append_c(&b, ",\"healResult\":{\"resultId\":0,\"type\":\"object\",\"bucket\":");
    buckets_json_go_string(&b, bucket, strlen(bucket));
    buckets_buf_append_c(&b, ",\"object\":");
    buckets_json_go_string(&b, object, strlen(object));
    buckets_buf_appendf(&b, ",\"versionId\":\"%s\",\"detail\":\"\"", vkey);
    if (r->parity_blocks) buckets_buf_appendf(&b, ",\"parityBlocks\":%d", r->parity_blocks);
    if (r->data_blocks) buckets_buf_appendf(&b, ",\"dataBlocks\":%d", r->data_blocks);
    buckets_buf_appendf(&b, ",\"diskCount\":%zu,\"setCount\":0,\"before\":", s->n);
    heal_drives(&b, L, s, r->before, s->n);
    buckets_buf_append_c(&b, ",\"after\":");
    heal_drives(&b, L, s, r->after, s->n);
    buckets_buf_appendf(&b, ",\"objectSize\":%lld}}", (long long)r->size);
    buckets_trace_meta m = {.type = BUCKETS_TRACE_HEALING, .dur_ns = dur};
    buckets_trace_publish(&m, b.data, b.len);
    buckets_buf_free(&b);
    buckets_buf_free(&path);
  }
  /* auditHealObject: fully unhealable missing or corrupt blocks are errors */
  size_t mb = 0, ma = 0, cb = 0, ca = 0;
  for (size_t i = 0; i < s->n; i++) {
    mb += r->before[i] == BUCKETS_HEAL_MISSING, ma += r->after[i] == BUCKETS_HEAL_MISSING;
    cb += r->before[i] == BUCKETS_HEAL_CORRUPT, ca += r->after[i] == BUCKETS_HEAL_CORRUPT;
  }
  char msg[96];
  if (mb > 0 && mb == ma) snprintf(msg, sizeof(msg), "unable to heal %zu missing blocks on drives", mb), errs = msg;
  else if (cb > 0 && cb == ca) snprintf(msg, sizeof(msg), "unable to heal %zu corrupted blocks on drives", cb), errs = msg;
  char tag[1200];
  snprintf(tag, sizeof(tag), "name=%s,pool=%zu,set=%zu", object, L->index + 1, (size_t)(s - L->sets) + 1);
  const char *keys[] = {"healObject"}, *values[] = {tag};
  buckets_audit_internal("HealObject", "", bucket, object, vkey, errs, keys, values, 1);
}

buckets_obj_err buckets_ep_heal(buckets_epool *L, const char *bucket, const char *object, const char *version_id,
                                 const buckets_heal_opts *opts, buckets_heal_result *res) {
  buckets_heal_result local;
  if (!res) res = &local;
  memset(res, 0, sizeof(*res));
  buckets_obj_err err = buckets_ep_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = buckets_ep_set_for(L, object);
  buckets_nslock_entry *lk = lock_ns(L, bucket, object, true);
  if (!lk) return BUCKETS_OBJ_ERR_TIMEOUT;
  /* The versions to visit: one, or the union over every drive. */
  uint8_t (*ids)[16] = NULL;
  size_t nids = 0;
  if (version_id) {
    ids = buckets_xcalloc(1, 16);
    if (!buckets_xl_version_id_parse(version_id, ids[0])) err = BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
    nids = 1;
  } else {
    char *op = obj_path(object);
    dmeta m[MAX_SET];
    load_metas(s, bucket, op, m);
    free(op);
    for (size_t i = 0; i < s->n; i++) {
      for (size_t k = 0; m[i].loaded && k < m[i].x.n; k++) {
        bool seen = false;
        for (size_t j = 0; j < nids && !seen; j++) seen = memcmp(ids[j], m[i].x.versions[k].hdr.version_id, 16) == 0;
        if (seen) continue;
        ids = buckets_xrealloc(ids, (nids + 1) * 16);
        memcpy(ids[nids++], m[i].x.versions[k].hdr.version_id, 16);
      }
    }
    free_metas(m, s->n);
    if (!nids) err = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  for (size_t j = 0; j < nids && !err; j++) {
    buckets_heal_result one;
    memset(&one, 0, sizeof(one));
    int64_t start = now_ns();
    err = heal_version(L, s, bucket, object, ids[j], opts, &one);
    heal_report(L, s, bucket, object, ids[j], opts, &one, err, start);
    res->ndrives = one.ndrives;
    res->versions += one.versions;
    res->healed += one.healed;
    res->dangling += one.dangling;
    if (j == 0) {
      res->size = one.size;
      memcpy(res->before, one.before, sizeof(res->before));
      memcpy(res->after, one.after, sizeof(res->after));
    } else { /* worst state per drive across versions */
      for (size_t i = 0; i < one.ndrives; i++) {
        res->before[i] = BUCKETS_MAX(res->before[i], one.before[i]);
        res->after[i] = BUCKETS_MAX(res->after[i], one.after[i]);
      }
    }
  }
  free(ids);
  buckets_nslock_unlock(lk);
  return err;
}

const char *buckets_ep_scan_drive(buckets_epool *L, const char *object, const char *bucket, int64_t *meta_size) {
  buckets_eset *s = buckets_ep_set_for(L, object);
  for (size_t i = 0; i < s->n; i++) {
    buckets_drive *d = s->drives[i];
    if (!d) continue;
    if (meta_size) {
      char *op = obj_path(object), *mp = join(op, XL_META);
      if (buckets_drive_file_size(d, bucket, mp, meta_size) != BUCKETS_DRIVE_OK) *meta_size = 0;
      free(mp);
      free(op);
    }
    return d->root;
  }
  if (meta_size) *meta_size = 0;
  return "";
}

size_t buckets_ep_heal_bucket(buckets_epool *L, const char *bucket) {
  size_t made = 0;
  for (size_t i = 0; i < L->nall; i++) {
    if (!L->all[i]) continue;
    if (buckets_drive_stat_vol(L->all[i], bucket, NULL) == BUCKETS_DRIVE_ERR_NOT_FOUND &&
        buckets_drive_make_vol(L->all[i], bucket) == BUCKETS_DRIVE_OK) {
      made++;
    }
  }
  return made;
}
