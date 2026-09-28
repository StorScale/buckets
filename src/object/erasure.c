/* Erasure-coded object layer over sets of drives (MinIO cmd/erasure-object.go,
 * erasure-multipart.go, erasure-sets.go, erasure-server-pool.go subset).
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/buf.h"
#include "core/log.h"
#include "core/msgpack.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/highwayhash.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "erasure/layout.h"
#include "erasure/rs.h"
#include "object/object.h"

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
      "read quorum not met", "write quorum not met", "bucket exists", "bucket not empty"};
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

buckets_objlayer *buckets_objlayer_new(buckets_format_result *f, int parity) {
  buckets_objlayer *L = buckets_xcalloc(1, sizeof(*L));
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

void buckets_objlayer_free(buckets_objlayer *L) {
  if (!L) return;
  for (size_t i = 0; i < L->nall; i++) buckets_drive_close(L->all[i]);
  free(L->all);
  free(L->sets);
  free(L);
}

buckets_drive *buckets_objlayer_scratch(const buckets_objlayer *L) {
  for (size_t i = 0; i < L->nall; i++) {
    if (L->all[i]) return L->all[i];
  }
  return NULL;
}

size_t buckets_objlayer_online(const buckets_objlayer *L) {
  size_t c = 0;
  for (size_t i = 0; i < L->nall; i++) c += L->all[i] != NULL;
  return c;
}

static buckets_eset *set_for(buckets_objlayer *L, const char *object) {
  return &L->sets[L->nsets == 1 ? 0 : buckets_set_index(object, L->nsets, L->deployment_id)];
}

static int set_data(const buckets_eset *s) { return (int)s->n - s->parity; }
static int write_quorum(int data, int parity) { return data + (data == parity ? 1 : 0); }

/* ---- buckets --------------------------------------------------------------- */

void buckets_bucket_info_free(buckets_bucket_info *b, size_t n) {
  for (size_t i = 0; i < n; i++) free(b[i].name);
  free(b);
}

static size_t bucket_quorum(const buckets_objlayer *L) { return L->nall / 2 + 1; }

buckets_obj_err buckets_obj_stat_bucket(buckets_objlayer *L, const char *bucket) {
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

buckets_obj_err buckets_obj_make_bucket(buckets_objlayer *L, const char *bucket) {
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

buckets_obj_err buckets_obj_list_buckets(buckets_objlayer *L, buckets_bucket_info **out, size_t *n) {
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

/* ---- metadata quorum ------------------------------------------------------- */

typedef struct {
  buckets_xlmeta x;
  bool loaded;  /* xl.meta parsed */
  bool missing; /* no xl.meta on this drive */
} dmeta;

static void load_metas(buckets_eset *s, const char *vol, const char *dir, dmeta *m) {
  char *path = join(dir, XL_META);
  for (size_t i = 0; i < s->n; i++) {
    memset(&m[i], 0, sizeof(m[i]));
    if (!s->drives[i]) continue;
    buckets_buf raw = BUCKETS_BUF_INIT;
    buckets_drive_err e = buckets_drive_read_all(s->drives[i], vol, path, &raw);
    if (e == BUCKETS_DRIVE_ERR_NOT_FOUND) m[i].missing = true;
    else if (e == BUCKETS_DRIVE_OK) m[i].loaded = buckets_xlmeta_parse(raw.data, raw.len, &m[i].x) == BUCKETS_XL_OK;
    buckets_buf_free(&raw);
  }
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
    long k = by_id ? buckets_xlmeta_find(&m[i].x, want_id) : (m[i].x.n ? 0 : -1);
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

void buckets_object_info_free(buckets_object_info *oi) {
  free(oi->name);
  for (size_t i = 0; i < oi->nmeta; i++) {
    free(oi->meta[i].key);
    free(oi->meta[i].value);
  }
  free(oi->meta);
  free(oi->checksum);
  free(oi->parts);
  memset(oi, 0, sizeof(*oi));
}

const char *buckets_object_meta(const buckets_object_info *oi, const char *key) {
  const buckets_xl_kv *kv = buckets_xl_kv_get(oi->meta, oi->nmeta, key);
  return kv ? (const char *)kv->value : NULL;
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
      oi->parts[i] = (buckets_xl_part){o->parts[i].number, o->parts[i].size, o->parts[i].actual_size, NULL};
    }
  }
  oi->delete_marker = o->type == BUCKETS_XL_TYPE_DELETE;
  for (size_t i = 0; i < o->nmeta_user; i++) {
    if (strcmp(o->meta_user[i].key, "etag") == 0) {
      snprintf(oi->etag, sizeof(oi->etag), "%s", (const char *)o->meta_user[i].value);
      continue;
    }
    buckets_xl_kv_set(&oi->meta, &oi->nmeta, o->meta_user[i].key, o->meta_user[i].value, o->meta_user[i].value_len);
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
      s->err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
      return got;
    }
    got += (size_t)r;
  }
  buckets_md5_update(&s->md5, buf, got);
  if (s->want_sha) buckets_sha256_update(&s->sha, buf, got);
  if (s->want_cks) buckets_cksum_hasher_update(&s->cks, buf, got);
  s->remaining -= (int64_t)got;
  return got;
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
} encoder;

/* Streams `size` bytes from src, erasure-coded across the set: drive i
 * receives shard dist[i]-1 of every block, each preceded by its bitrot hash,
 * either into <.minio.sys>/<file> or an in-memory inline buffer. */
static buckets_obj_err encode_stream(encoder *e, source *src, int64_t size, const char *file) {
  buckets_eset *s = e->set;
  int total = e->data + e->parity;
  for (size_t i = 0; i < s->n; i++) {
    e->alive[i] = s->drives[i] != NULL;
    e->ibuf[i] = BUCKETS_BUF_INIT;
    e->w[i] = NULL;
    if (e->alive[i] && !e->inline_mode &&
        buckets_drive_create_file(s->drives[i], BUCKETS_META_BUCKET, file, &e->w[i]) != BUCKETS_DRIVE_OK) {
      e->alive[i] = false;
    }
  }
  buckets_rs *rs = buckets_rs_new(e->data, e->parity);
  size_t shard_cap = (size_t)ceil_div(BUCKETS_BLOCK_SIZE, e->data);
  uint8_t *block = buckets_xmalloc(BUCKETS_BLOCK_SIZE);
  uint8_t *shards[MAX_SET];
  for (int k = 0; k < total; k++) shards[k] = buckets_xmalloc(shard_cap);
  buckets_obj_err err = BUCKETS_OBJ_OK;
  int wq = write_quorum(e->data, e->parity);
  while (src->remaining > 0 && !err) {
    size_t n = source_read(src, block, BUCKETS_BLOCK_SIZE);
    if (src->err) {
      err = src->err;
      break;
    }
    size_t sl = (size_t)ceil_div((int64_t)n, e->data);
    for (int k = 0; k < e->data; k++) {
      size_t off = (size_t)k * sl;
      size_t take = off < n ? BUCKETS_MIN(sl, n - off) : 0;
      if (take) memcpy(shards[k], block + off, take);
      memset(shards[k] + take, 0, sl - take);
    }
    if (e->parity) buckets_rs_encode(rs, shards, sl);
    int ok = 0;
    for (size_t i = 0; i < s->n; i++) {
      if (!e->alive[i]) continue;
      const uint8_t *shard = shards[e->dist[i] - 1];
      uint8_t h[HASH_LEN];
      buckets_hh256(buckets_bitrot_key, shard, sl, h);
      if (e->inline_mode) {
        buckets_buf_append(&e->ibuf[i], h, HASH_LEN);
        buckets_buf_append(&e->ibuf[i], shard, sl);
      } else if (buckets_drive_writer_write(e->w[i], h, HASH_LEN) != BUCKETS_DRIVE_OK ||
                 buckets_drive_writer_write(e->w[i], shard, sl) != BUCKETS_DRIVE_OK) {
        buckets_log_warn("write to %s failed; continuing with the remaining drives", s->drives[i]->root);
        buckets_drive_writer_abort(e->w[i]);
        e->w[i] = NULL;
        e->alive[i] = false;
        continue;
      }
      ok++;
    }
    if (ok < wq) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
  }
  if (!err) {
    long extra = src->rd(src->ud, block, 1); /* must be at EOF; lets chunked decoders read trailers */
    if (extra > 0) err = BUCKETS_OBJ_ERR_INCOMPLETE_BODY;
    else if (extra < 0) err = BUCKETS_OBJ_ERR_READER;
  }
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (!e->w[i]) {
      ok += e->alive[i];
      continue;
    }
    if (err) {
      buckets_drive_writer_abort(e->w[i]);
    } else if (buckets_drive_writer_close(e->w[i]) != BUCKETS_DRIVE_OK) {
      e->alive[i] = false;
    } else {
      ok++;
    }
    e->w[i] = NULL;
  }
  if (!err && ok < wq) err = BUCKETS_OBJ_ERR_WRITE_QUORUM;
  for (int k = 0; k < total; k++) free(shards[k]);
  free(block);
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

/* Installs version o on every live drive: merges it into that drive's xl.meta
 * (with the drive's own EcIndex and inline shard) and moves the staged data
 * directory <.minio.sys>/<src_dir>/<data_dir> into place. */
static buckets_obj_err commit_version(buckets_eset *s, const char *bucket, const char *object, buckets_xl_object *o,
                                      const int *dist, const bool *alive, const buckets_buf *ibuf,
                                      const char *src_dir, bool has_data_dir, int quorum) {
  char *op = obj_path(object);
  char key[37], data_dir[37];
  buckets_xl_version_id_string(o->version_id, key);
  buckets_xl_version_id_string(o->data_dir, data_dir);
  int ok = 0;
  for (size_t i = 0; i < s->n; i++) {
    if (!alive[i] || !s->drives[i]) continue;
    buckets_drive *d = s->drives[i];
    buckets_buf raw = BUCKETS_BUF_INIT;
    char *mpath = join(op, XL_META);
    buckets_xlmeta x;
    memset(&x, 0, sizeof(x));
    if (buckets_drive_read_all(d, bucket, mpath, &raw) == BUCKETS_DRIVE_OK &&
        buckets_xlmeta_parse(raw.data, raw.len, &x) != BUCKETS_XL_OK) {
      memset(&x, 0, sizeof(x)); /* unreadable: replaced (healing would do the same) */
    }
    buckets_buf_free(&raw);
    free(mpath);
    char old_dir[37] = "";
    long prev = buckets_xlmeta_find(&x, o->version_id);
    if (prev >= 0) {
      buckets_xl_object po;
      if (buckets_xl_object_decode(&x.versions[prev], &po) == BUCKETS_XL_OK) {
        if (po.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(po.meta_sys, po.nmeta_sys, BUCKETS_XL_META_INLINE)) {
          buckets_xl_version_id_string(po.data_dir, old_dir);
        }
        buckets_xl_object_free(&po);
      }
    }
    o->ec_index = dist[i];
    buckets_buf meta = BUCKETS_BUF_INIT;
    buckets_xl_header hdr;
    buckets_xl_object_encode(o, &meta, &hdr);
    buckets_xlmeta_put_version(&x, &hdr, (uint8_t *)meta.data, meta.len);
    if (ibuf) buckets_xlmeta_inline_put(&x, key, ibuf[i].data ? ibuf[i].data : "", ibuf[i].len);
    else buckets_xlmeta_inline_remove(&x, key);
    buckets_buf bytes = BUCKETS_BUF_INIT;
    buckets_xlmeta_serialize(&x, &bytes);
    buckets_xlmeta_free(&x);
    if (buckets_drive_rename_data(d, BUCKETS_META_BUCKET, src_dir, has_data_dir ? data_dir : NULL, bucket, op,
                                  bytes.data, bytes.len) == BUCKETS_DRIVE_OK) {
      ok++;
      if (old_dir[0] && strcmp(old_dir, data_dir) != 0) {
        char *stale = join(op, old_dir);
        buckets_drive_delete(d, bucket, stale, true, false);
        free(stale);
      }
    } else {
      buckets_log_warn("commit of %s/%s failed on %s", bucket, object, d->root);
    }
    buckets_buf_free(&bytes);
  }
  free(op);
  return ok >= quorum ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

static void cleanup_tmp(buckets_eset *s, const char *tmp_dir) {
  for (size_t i = 0; i < s->n; i++) {
    if (s->drives[i]) buckets_drive_delete(s->drives[i], BUCKETS_META_BUCKET, tmp_dir, true, false);
  }
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

/* ---- put --------------------------------------------------------------------------- */

buckets_obj_err buckets_obj_put(buckets_objlayer *L, const char *bucket, const char *object, buckets_read_fn rd,
                                void *rd_ud, int64_t size, const buckets_put_opts *opts, buckets_object_info *out) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = set_for(L, object);
  if ((err = check_namespace(s, bucket, object)) != BUCKETS_OBJ_OK) return err;
  if (size < 0) return BUCKETS_OBJ_ERR_INCOMPLETE_BODY;

  encoder e = {.set = s, .parity = s->parity, .data = set_data(s)};
  char *key = join(bucket, object);
  buckets_hash_order(key, (int)s->n, e.dist);
  free(key);
  e.inline_mode = shard_file_size(size, e.data) <= BUCKETS_INLINE_THRESHOLD;

  uint8_t data_dir[16];
  char data_dir_s[37];
  new_uuid_bytes(data_dir, data_dir_s);
  char *tmp_id = buckets_drive_tmp_name();
  buckets_buf file = BUCKETS_BUF_INIT, tmp_dir = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&tmp_dir, "tmp/%s", tmp_id);
  buckets_buf_appendf(&file, "tmp/%s/%s/part.1", tmp_id, data_dir_s);
  free(tmp_id);

  source src = {.rd = rd, .ud = rd_ud, .remaining = size, .want_sha = opts && opts->want_sha256};
  buckets_md5_init(&src.md5);
  buckets_sha256_init(&src.sha);
  uint32_t ctype = opts ? opts->checksum_type & BUCKETS_CKSUM_BASE_MASK : 0;
  src.want_cks = ctype != 0;
  buckets_cksum_hasher_init(&src.cks, ctype);

  err = encode_stream(&e, &src, size, file.data);
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
    buckets_xl_part_add(&o, 1, size, size, NULL);
    for (size_t i = 0; opts && i < opts->nmeta; i++) {
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, opts->meta[i].key, opts->meta[i].value, opts->meta[i].value_len);
    }
    char etag[33];
    buckets_hex_encode(md5, 16, etag);
    buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, "etag", etag, 32);
    if (e.inline_mode) buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, BUCKETS_XL_META_INLINE, "true", 4);
    if (opts && opts->pre_commit) err = opts->pre_commit(opts->pre_commit_ud, &cks, &o);
    if (!err) {
      err = commit_version(s, bucket, object, &o, e.dist, e.alive, e.inline_mode ? e.ibuf : NULL, tmp_dir.data,
                           !e.inline_mode, write_quorum(e.data, e.parity));
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
  buckets_eset *set;
  char *bucket, *op;
  char data_dir[37];
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
  uint8_t *shards[MAX_SET];
  uint8_t *frame;
  uint8_t *block;
  int64_t block_index;
  size_t block_len;
};

void buckets_obj_reader_free(buckets_obj_reader *r) {
  if (!r) return;
  for (int i = 0; i < MAX_SET; i++) {
    free(r->inl[i]);
    free(r->shards[i]);
  }
  free(r->frame);
  free(r->block);
  free(r->parts);
  free(r->bucket);
  free(r->op);
  buckets_rs_free(r->rs);
  free(r);
}

static buckets_obj_err resolve(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                               buckets_eset **set, dmeta *m, long *vidx, buckets_xl_object *o) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  *set = set_for(L, object);
  char *op = obj_path(object);
  load_metas(*set, bucket, op, m);
  free(op);
  err = quorum_version(m, (*set)->n, version_id, o, vidx);
  if (err) free_metas(m, (*set)->n);
  return err;
}

buckets_obj_err buckets_obj_stat(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 buckets_object_info *out) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) return err;
  fill_info(out, object, &o);
  buckets_xl_object_free(&o);
  free_metas(m, s->n);
  return BUCKETS_OBJ_OK;
}

buckets_obj_err buckets_obj_open(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id,
                                 int64_t offset, int64_t length, buckets_obj_reader **out,
                                 buckets_object_info *info) {
  buckets_eset *s;
  dmeta m[MAX_SET];
  long vidx[MAX_SET];
  buckets_xl_object o;
  buckets_obj_err err = resolve(L, bucket, object, version_id, &s, m, vidx, &o);
  if (err) return err;
  if (o.type == BUCKETS_XL_TYPE_DELETE) {
    buckets_xl_object_free(&o);
    free_metas(m, s->n);
    return BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  buckets_obj_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->set = s;
  r->bucket = buckets_xstrdup(bucket);
  r->op = obj_path(object);
  buckets_xl_version_id_string(o.data_dir, r->data_dir);
  r->data = o.ec_m > 0 ? o.ec_m : 1;
  r->parity = o.ec_n;
  r->total = r->data + r->parity;
  r->rs = buckets_rs_new(r->data, r->parity);
  r->is_inline = buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE) != NULL;
  for (int k = 0; k < MAX_SET; k++) r->drive_of_shard[k] = -1;
  char key[37];
  buckets_xl_version_id_string(o.version_id, key);
  for (size_t i = 0; i < s->n; i++) {
    if (vidx[i] < 0) continue;
    buckets_xl_object mine;
    if (buckets_xl_object_decode(&m[i].x.versions[vidx[i]], &mine) != BUCKETS_XL_OK) continue;
    int shard = mine.ec_index - 1;
    buckets_xl_object_free(&mine);
    if (shard < 0 || shard >= r->total || r->drive_of_shard[shard] >= 0) continue;
    if (r->is_inline) {
      buckets_str sh;
      if (!buckets_xlmeta_inline_get(&m[i].x, key, &sh)) continue;
      r->inl[i] = buckets_xmalloc(sh.n ? sh.n : 1);
      memcpy(r->inl[i], sh.p, sh.n);
      r->inl_len[i] = sh.n;
    }
    r->drive_of_shard[shard] = (int)i;
  }
  r->parts = buckets_xcalloc(o.nparts ? o.nparts : 1, sizeof(buckets_xl_part));
  int64_t total_size = 0;
  for (size_t i = 0; i < o.nparts; i++) {
    r->parts[i] = (buckets_xl_part){o.parts[i].number, o.parts[i].size, o.parts[i].actual_size, NULL};
    total_size += o.parts[i].size;
  }
  r->nparts = o.nparts;
  if (info) fill_info(info, object, &o);
  buckets_xl_object_free(&o);
  free_metas(m, s->n);

  int64_t off = offset;
  while (r->part < r->nparts && off >= r->parts[r->part].size && r->parts[r->part].size > 0) {
    off -= r->parts[r->part].size;
    r->part++;
  }
  r->part_off = off;
  r->remaining = offset >= total_size ? 0 : BUCKETS_MIN(length, total_size - offset);
  r->shard_cap = (size_t)ceil_div(BUCKETS_BLOCK_SIZE, r->data);
  for (int k = 0; k < r->total; k++) r->shards[k] = buckets_xmalloc(r->shard_cap);
  r->frame = buckets_xmalloc(r->shard_cap + HASH_LEN);
  r->block = buckets_xmalloc(BUCKETS_BLOCK_SIZE);
  r->block_index = -1;
  *out = r;
  return BUCKETS_OBJ_OK;
}

/* Reads one verified shard block from the drive holding shard k. */
static bool read_shard(buckets_obj_reader *r, int k, int64_t bi, size_t sl) {
  int i = r->drive_of_shard[k];
  if (i < 0 || r->bad[i] || !r->set->drives[i]) return false;
  size_t flen = HASH_LEN + sl;
  int64_t foff = bi * (int64_t)(r->shard_cap + HASH_LEN);
  if (r->is_inline) {
    if (!r->inl[i] || (size_t)foff + flen > r->inl_len[i]) {
      r->bad[i] = true;
      return false;
    }
    memcpy(r->frame, r->inl[i] + foff, flen);
  } else {
    buckets_buf path = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "%s/%s/part.%d", r->op, r->data_dir, r->parts[r->part].number);
    size_t got = 0;
    buckets_drive_err e = buckets_drive_read_at(r->set->drives[i], r->bucket, path.data, foff, r->frame, flen, &got);
    buckets_buf_free(&path);
    if (e || got != flen) {
      r->bad[i] = true;
      return false;
    }
  }
  uint8_t h[HASH_LEN];
  buckets_hh256(buckets_bitrot_key, r->frame + HASH_LEN, sl, h);
  if (!buckets_ct_equal(h, r->frame, HASH_LEN)) {
    buckets_log_warn("bitrot detected in %s/%s on %s (shard %d, block %lld)", r->bucket, r->op,
                     r->set->drives[i]->root, k, (long long)bi);
    r->bad[i] = true;
    return false;
  }
  memcpy(r->shards[k], r->frame + HASH_LEN, sl);
  return true;
}

static bool load_block(buckets_obj_reader *r, int64_t bi) {
  int64_t ps = r->parts[r->part].size;
  size_t blen = (size_t)BUCKETS_MIN((int64_t)BUCKETS_BLOCK_SIZE, ps - bi * BUCKETS_BLOCK_SIZE);
  size_t sl = (size_t)ceil_div((int64_t)blen, r->data);
  bool present[MAX_SET] = {false};
  int have = 0;
  for (int k = 0; k < r->total && have < r->data; k++) {
    if (read_shard(r, k, bi, sl)) {
      present[k] = true;
      have++;
    }
  }
  if (have < r->data) return false;
  bool missing_data = false;
  for (int k = 0; k < r->data; k++) missing_data |= !present[k];
  if (missing_data && !buckets_rs_reconstruct(r->rs, r->shards, present, sl, true)) return false;
  for (int k = 0; k < r->data; k++) {
    size_t off = (size_t)k * sl;
    if (off >= blen) break;
    memcpy(r->block + off, r->shards[k], BUCKETS_MIN(sl, blen - off));
  }
  r->block_index = bi;
  r->block_len = blen;
  return true;
}

long buckets_obj_read(buckets_obj_reader *r, void *buf, size_t n) {
  size_t done = 0;
  while (done < n && r->remaining > 0) {
    if (r->part >= r->nparts) return -1;
    int64_t ps = r->parts[r->part].size;
    if (r->part_off >= ps) {
      r->part++;
      r->part_off = 0;
      r->block_index = -1;
      memset(r->bad, 0, sizeof(r->bad));
      continue;
    }
    int64_t bi = r->part_off / BUCKETS_BLOCK_SIZE;
    if (bi != r->block_index && !load_block(r, bi)) {
      buckets_log_error("cannot read %s/%s: fewer than %d intact shards (part %d, block %lld)", r->bucket, r->op,
                        r->data, r->parts[r->part].number, (long long)bi);
      return -1;
    }
    size_t in_block = (size_t)(r->part_off - bi * BUCKETS_BLOCK_SIZE);
    size_t take = BUCKETS_MIN(r->block_len - in_block, n - done);
    take = (size_t)BUCKETS_MIN((int64_t)take, r->remaining);
    memcpy((uint8_t *)buf + done, r->block + in_block, take);
    done += take;
    r->part_off += (int64_t)take;
    r->remaining -= (int64_t)take;
  }
  return (long)done;
}

/* ---- delete -------------------------------------------------------------------------- */

buckets_obj_err buckets_obj_delete(buckets_objlayer *L, const char *bucket, const char *object, const char *version_id) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  uint8_t id[16] = {0};
  if (version_id && *version_id && !buckets_xl_version_id_parse(version_id, id)) return BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  buckets_eset *s = set_for(L, object);
  char *op = obj_path(object);
  dmeta m[MAX_SET];
  load_metas(s, bucket, op, m);
  size_t found = 0, done = 0;
  char key[37];
  buckets_xl_version_id_string(id, key);
  for (size_t i = 0; i < s->n; i++) {
    if (!m[i].loaded) continue;
    long k = buckets_xlmeta_find(&m[i].x, id);
    if (k < 0) continue;
    found++;
    char dd[37] = "";
    buckets_xl_object o;
    if (buckets_xl_object_decode(&m[i].x.versions[k], &o) == BUCKETS_XL_OK) {
      if (o.type == BUCKETS_XL_TYPE_OBJECT && !buckets_xl_kv_get(o.meta_sys, o.nmeta_sys, BUCKETS_XL_META_INLINE)) {
        buckets_xl_version_id_string(o.data_dir, dd);
      }
      buckets_xl_object_free(&o);
    }
    buckets_xlmeta_remove_version(&m[i].x, id);
    buckets_xlmeta_inline_remove(&m[i].x, key);
    buckets_drive_err de;
    if (m[i].x.n == 0) {
      de = buckets_drive_delete(s->drives[i], bucket, op, true, true);
    } else {
      buckets_buf bytes = BUCKETS_BUF_INIT;
      buckets_xlmeta_serialize(&m[i].x, &bytes);
      char *mp = join(op, XL_META);
      de = buckets_drive_write_all(s->drives[i], bucket, mp, bytes.data, bytes.len);
      free(mp);
      buckets_buf_free(&bytes);
      if (!de && dd[0]) {
        char *dp = join(op, dd);
        buckets_drive_delete(s->drives[i], bucket, dp, true, false);
        free(dp);
      }
    }
    if (!de) done++;
  }
  free_metas(m, s->n);
  free(op);
  if (found == 0) return version_id && *version_id ? BUCKETS_OBJ_ERR_NO_SUCH_VERSION : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  return (int)done >= write_quorum(set_data(s), s->parity) || done == found ? BUCKETS_OBJ_OK
                                                                              : BUCKETS_OBJ_ERR_WRITE_QUORUM;
}

/* ---- listing ------------------------------------------------------------------------- */

typedef struct {
  char *key;
  bool is_obj;
} entry;

static int entry_cmp(const void *a, const void *b) { return strcmp(((const entry *)a)->key, ((const entry *)b)->key); }

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

static void emit_object(list_ctx *lc, const char *key, const char *dir) {
  if (lc->marker && strcmp(key, lc->marker) <= 0) return;
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
    if (x.n && buckets_xl_object_decode(&x.versions[0], &o) == BUCKETS_XL_OK) {
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
                       const char *delimiter, int max_keys, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  list_ctx lc = {.d = d, .bucket = bucket, .prefix = prefix, .marker = marker && *marker ? marker : NULL,
                 .delim = delimiter ? delimiter : "", .delim_len = delimiter ? strlen(delimiter) : 0,
                 .max_keys = max_keys, .out = out};
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

buckets_obj_err buckets_obj_list(buckets_objlayer *L, const char *bucket, const char *prefix, const char *marker,
                                 const char *delimiter, int max_keys, buckets_obj_listing *out) {
  memset(out, 0, sizeof(*out));
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
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
      list_drive(d, bucket, prefix, marker, delimiter, max_keys, &src[nsrc]);
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

void buckets_obj_list_free(buckets_obj_listing *l) {
  for (size_t i = 0; i < l->nobjects; i++) buckets_object_info_free(&l->objects[i]);
  free(l->objects);
  for (size_t i = 0; i < l->nprefixes; i++) free(l->prefixes[i]);
  free(l->prefixes);
  free(l->next_marker);
  memset(l, 0, sizeof(*l));
}

buckets_obj_err buckets_obj_delete_bucket(buckets_objlayer *L, const char *bucket) {
  buckets_obj_listing l;
  buckets_obj_err err = buckets_obj_list(L, bucket, "", NULL, NULL, 1, &l);
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
  return ok >= bucket_quorum(L) || ok == buckets_objlayer_online(L) ? BUCKETS_OBJ_OK : BUCKETS_OBJ_ERR_WRITE_QUORUM;
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

static buckets_obj_err load_upload(buckets_objlayer *L, const char *bucket, const char *object, const char *dir,
                                   upload *u) {
  memset(u, 0, sizeof(*u));
  u->set = set_for(L, object);
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

buckets_obj_err buckets_obj_mpu_new(buckets_objlayer *L, const char *bucket, const char *object, const buckets_xl_kv *meta,
                                    size_t nmeta, char upload_id[BUCKETS_UPLOAD_ID_MAX]) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  buckets_eset *s = set_for(L, object);
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
  for (size_t i = 0; i < nmeta; i++) buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, meta[i].key, meta[i].value, meta[i].value_len);
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
  buckets_mp_map(b, p->cksum.type ? 6 : 5);
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

buckets_obj_err buckets_obj_mpu_put_part(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id,
                                         int part_number, buckets_read_fn rd, void *rd_ud, int64_t size,
                                         const buckets_put_opts *opts, buckets_part_info *out) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
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
  source src = {.rd = rd, .ud = rd_ud, .remaining = size, .want_sha = opts && opts->want_sha256, .want_cks = ctype != 0};
  buckets_md5_init(&src.md5);
  buckets_sha256_init(&src.sha);
  buckets_cksum_hasher_init(&src.cks, ctype);
  err = encode_stream(&e, &src, size, tmp_file.data);
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
    buckets_buf pm = BUCKETS_BUF_INIT, dst = BUCKETS_BUF_INIT, dstmeta = BUCKETS_BUF_INIT;
    encode_part_meta(&pm, &pi);
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

buckets_obj_err buckets_obj_mpu_list_parts(buckets_objlayer *L, const char *bucket, const char *object,
                                           const char *upload_id, int marker, int max, buckets_part_info **parts,
                                           size_t *n, bool *truncated) {
  *parts = NULL;
  *n = 0;
  *truncated = false;
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
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

buckets_obj_err buckets_obj_mpu_abort(buckets_objlayer *L, const char *bucket, const char *object, const char *upload_id) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
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

buckets_obj_err buckets_obj_mpu_complete(buckets_objlayer *L, const char *bucket, const char *object,
                                         const char *upload_id, const buckets_complete_part *req, size_t nreq,
                                         const buckets_checksum *want, buckets_object_info *out) {
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if ((err = buckets_obj_check_name(object)) != BUCKETS_OBJ_OK) return err;
  char *dir = upload_dir(bucket, object, upload_id);
  if (!dir) return BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD;
  upload u;
  if ((err = load_upload(L, bucket, object, dir, &u)) != BUCKETS_OBJ_OK) {
    free(dir);
    return err;
  }
  if ((err = check_namespace(u.set, bucket, object)) != BUCKETS_OBJ_OK) {
    buckets_xl_object_free(&u.up);
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
  buckets_md5_ctx etag_md5;
  buckets_md5_init(&etag_md5);
  int64_t total = 0;
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
    char want_etag[80];
    canonical_etag(req[i].etag ? req[i].etag : "", want_etag, sizeof(want_etag));
    if (!p || strcmp(p->etag, want_etag) != 0) {
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
    uint8_t raw[16];
    for (int k = 0; k < 16; k++) {
      unsigned v;
      sscanf(p->etag + 2 * k, "%2x", &v);
      raw[k] = (uint8_t)v;
    }
    buckets_md5_update(&etag_md5, raw, 16);
    buckets_xl_part_add(&o, p->number, p->size, p->actual_size, NULL);
    total += p->size;
  }
  if (!err) {
    o.size = total;
    for (size_t i = 0; i < u.up.nmeta_user; i++) {
      const char *k = u.up.meta_user[i].key;
      if (strcmp(k, BUCKETS_MPU_CKSUM_META) == 0 || strcmp(k, BUCKETS_MPU_CKSUM_TYPE_META) == 0) continue;
      buckets_xl_kv_set(&o.meta_user, &o.nmeta_user, k, u.up.meta_user[i].value, u.up.meta_user[i].value_len);
    }
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
    int al = snprintf(actual, sizeof(actual), "%lld", (long long)total);
    buckets_xl_kv_set(&o.meta_sys, &o.nmeta_sys, ACTUAL_SIZE_KEY, actual, (size_t)al);
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
    err = commit_version(u.set, bucket, object, &o, u.dist, u.has, NULL, dir, true,
                         write_quorum(u.up.ec_m, u.up.ec_n));
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

buckets_obj_err buckets_obj_mpu_list_uploads(buckets_objlayer *L, const char *bucket, const char *object,
                                             buckets_upload_info **uploads, size_t *n) {
  *uploads = NULL;
  *n = 0;
  buckets_obj_err err = buckets_obj_stat_bucket(L, bucket);
  if (err) return err;
  if (!object || !*object || buckets_obj_check_name(object) != BUCKETS_OBJ_OK) return BUCKETS_OBJ_OK;
  buckets_eset *s = set_for(L, object);
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
