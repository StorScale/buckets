/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/compress.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "config/config.h"
#include "config/sys.h"
#include "crypto/dare.h"
#include "s3/sse.h"

/* Never compressed, whatever the configuration (standardExcludeCompress*).
 * The leading space in " application/x-compress" is MinIO's. */
static const char *const k_exclude_ext[] = {".gz", ".bz2", ".rar", ".zip", ".7z", ".xz", ".mp4", ".mkv", ".mov", ".jpg", ".png", ".gif"};
static const char *const k_exclude_types[] = {"video/*",           "audio/*",
                                              "application/zip",   "application/x-gzip",
                                              "application/x-zip-compressed", " application/x-compress",
                                              "application/x-spoon"};

/* wildcard.MatchSimple: '*' matches any run. */
static bool match_simple(const char *p, const char *s) {
  if (!*p) return !*s;
  if (strcmp(p, "*") == 0) return true;
  const char *star = NULL, *mark = NULL;
  while (*s) {
    if (*p == '*') {
      star = p++;
      mark = s;
    } else if (*p == *s) {
      p++, s++;
    } else if (star) {
      p = star + 1;
      s = ++mark;
    } else {
      return false;
    }
  }
  while (*p == '*') p++;
  return !*p;
}

static bool has_suffix_fold(const char *s, const char *suffix) {
  size_t n = strlen(s), m = strlen(suffix);
  return m <= n && strncasecmp(s + n - m, suffix, m) == 0;
}

/* hasStringSuffixInSlice over a comma separated list ("*" matches all). */
static bool suffix_in_list(const char *s, const char *list) {
  char *dup = buckets_xstrdup(list);
  bool found = false;
  for (char *save = NULL, *e = strtok_r(dup, ",", &save); e && !found; e = strtok_r(NULL, ",", &save))
    found = strcmp(e, "*") == 0 || has_suffix_fold(s, e);
  free(dup);
  return found;
}

static bool pattern_in_list(const char *s, const char *list) {
  char *dup = buckets_xstrdup(list);
  bool found = false;
  for (char *save = NULL, *e = strtok_r(dup, ",", &save); e && !found; e = strtok_r(NULL, ",", &save))
    found = match_simple(e, s);
  free(dup);
  return found;
}

bool buckets_s3_compress_excluded(const char *object, const char *content_type, bool enabled, bool allow_encrypted,
                                  bool encrypted, const char *extensions, const char *mime_types) {
  if (!enabled) return true;
  if (encrypted && !allow_encrypted) return true;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_exclude_ext); i++)
    if (has_suffix_fold(object, k_exclude_ext[i])) return true;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_exclude_types); i++)
    if (match_simple(k_exclude_types[i], content_type)) return true;
  bool have_ext = extensions && *extensions, have_mime = mime_types && *mime_types;
  if (!have_ext && !have_mime) return false;
  if (have_ext && suffix_in_list(object, extensions)) return false;
  if (have_mime && pattern_in_list(content_type, mime_types)) return false;
  return true;
}

static char *cfg_value(s3_ctx *c, const char *key) {
  return c->s->config ? buckets_config_sys_value(c->s->config, "compression", "", key) : NULL;
}

/* A boolean setting: its MINIO_COMPRESSION_ variable, else MinIO's legacy
 * ones, else the stored configuration. */
static bool cfg_bool(s3_ctx *c, const char *key, const char *env, const char *const *legacy) {
  const char *e = buckets_config_getenv(env);
  for (; !e && *legacy; legacy++) e = buckets_config_getenv(*legacy);
  char *v = e ? buckets_xstrdup(e) : cfg_value(c, key);
  bool on = v && buckets_config_parse_bool(v) == 1;
  free(v);
  return on;
}

bool buckets_s3_compressible(s3_ctx *c, const char *object, bool encrypted) {
  static const char *const legacy_enable[] = {"MINIO_COMPRESS_ENABLE", "MINIO_COMPRESS", NULL};
  static const char *const legacy_enc[] = {"MINIO_COMPRESS_ALLOW_ENCRYPTION", NULL};
  if (!cfg_bool(c, "enable", "MINIO_COMPRESSION_ENABLE", legacy_enable)) return false;
  bool allow_enc = cfg_bool(c, "allow_encryption", "MINIO_COMPRESSION_ALLOW_ENCRYPTION", legacy_enc);
  char *ext = cfg_value(c, "extensions"), *mime = cfg_value(c, "mime_types");
  buckets_str ct = buckets_http_header_get(c->req, "Content-Type");
  char *ctype = ct.p ? buckets_str_dup(ct) : buckets_xstrdup("");
  bool excluded = buckets_s3_compress_excluded(object, ctype, true, allow_enc, encrypted, ext, mime);
  free(ctype);
  free(ext);
  free(mime);
  return !excluded;
}

static const char *sys_str(const buckets_object_info *oi, const char *k) {
  const buckets_xl_kv *kv = buckets_object_sys(oi, k);
  return kv ? (const char *)kv->value : NULL;
}

bool buckets_s3_is_compressed(const buckets_object_info *oi) { return sys_str(oi, BUCKETS_COMPRESS_META) != NULL; }

static bool parse_i64(const char *s, int64_t *out) {
  if (!s || !*s) return false;
  char *end;
  long long v = strtoll(s, &end, 10);
  if (*end) return false;
  *out = v;
  return true;
}

int64_t buckets_s3_actual_size(const buckets_object_info *oi) {
  const char *as = sys_str(oi, BUCKETS_ACTUAL_SIZE_META);
  int64_t v;
  if (buckets_s3_is_compressed(oi)) {
    if (as && *as) return parse_i64(as, &v) ? v : -1;
    int64_t total = 0;
    for (size_t i = 0; i < oi->nparts; i++) total += oi->parts[i].actual_size;
    if (total == 0 && total != oi->size) return -1;
    return total;
  }
  if (buckets_s3_sse_encrypted(oi)) {
    if (as && *as) return parse_i64(as, &v) ? v : -1;
    int64_t d = buckets_s3_sse_actual_size(oi);
    if (d == 0 && d != oi->size) return -1;
    return d;
  }
  return oi->size;
}

void buckets_s3_compress_seal_index(const uint8_t key[32], const void *idx, size_t n, buckets_buf *out) {
  buckets_s3_meta_seal(key, "compression-index", idx, n, out);
}

bool buckets_s3_compress_open_index(const uint8_t key[32], const void *sealed, size_t n, buckets_buf *out) {
  return buckets_s3_meta_open(key, "compression-index", sealed, n, out);
}

void buckets_s3_compressed_range(const buckets_object_info *oi, const uint8_t *key, int64_t off, buckets_comp_range *out) {
  memset(out, 0, sizeof(*out));
  int64_t cumulative = 0, skip_len = 0;
  size_t first = 0;
  for (size_t i = 0; i < oi->nparts; i++) {
    cumulative += oi->parts[i].actual_size;
    if (cumulative <= off) {
      out->stored_off += oi->parts[i].size;
    } else {
      first = i;
      skip_len = cumulative - oi->parts[i].actual_size;
      break;
    }
  }
  out->first_part = first;
  out->part_skip = off - skip_len;
  if (out->part_skip <= 0 || first >= oi->nparts || !oi->parts[first].index_len) return;
  /* The part's index lets the read start at the block before the offset. */
  bool encrypted = buckets_s3_sse_encrypted(oi);
  buckets_buf idx = BUCKETS_BUF_INIT;
  const uint8_t *ib = oi->parts[first].index;
  size_t in = oi->parts[first].index_len;
  if (encrypted) {
    if (!key || !buckets_s3_compress_open_index(key, ib, in, &idx)) {
      buckets_buf_free(&idx);
      return;
    }
    ib = (const uint8_t *)idx.data, in = idx.len;
  }
  buckets_s2_index x = {0};
  int64_t comp_off, uncomp_off;
  if (buckets_s2_index_load(&x, ib, in) && buckets_s2_index_find(&x, out->part_skip, &comp_off, &uncomp_off) && comp_off > 0) {
    if (encrypted) {
      out->seq = (uint32_t)(comp_off / BUCKETS_DARE_PAYLOAD);
      out->decrypt_skip = comp_off % BUCKETS_DARE_PAYLOAD;
      out->stored_off += (comp_off / BUCKETS_DARE_PAYLOAD) * BUCKETS_DARE_PACKAGE;
    } else {
      out->stored_off += comp_off;
    }
    out->part_skip -= uncomp_off;
  }
  buckets_s2_index_free(&x);
  buckets_buf_free(&idx);
}

struct buckets_comp_reader {
  buckets_read_fn rd;
  void *rd_ud;
  void (*free_rd)(void *);
  buckets_sse_reader *sr;
  buckets_s2_reader *s2;
  int64_t skip, left;
  bool failed;
};

static long comp_src_read(void *ud, void *buf, size_t n) {
  buckets_comp_reader *r = ud;
  return r->sr ? buckets_sse_reader_read(r->sr, buf, n) : r->rd(r->rd_ud, buf, n);
}

/* The decrypted bytes from part first, package seq, to the end. */
static int64_t decrypted_rest(const buckets_object_info *oi, int64_t stored_size, size_t first, uint32_t seq) {
  uint64_t d, total = 0;
  if (buckets_s3_sse_is_multipart(oi)) {
    for (size_t i = first; i < oi->nparts; i++)
      if (buckets_dare_decrypted_size((uint64_t)oi->parts[i].size, &d)) total += d;
  } else if (buckets_dare_decrypted_size((uint64_t)stored_size, &d)) {
    total = d;
  }
  int64_t skipped = (int64_t)seq * BUCKETS_DARE_PAYLOAD;
  return (int64_t)total > skipped ? (int64_t)total - skipped : 0;
}

buckets_comp_reader *buckets_comp_reader_new(const buckets_object_info *oi, int64_t stored_size, const uint8_t *key,
                                             const buckets_comp_range *rg, int64_t len, buckets_read_fn rd, void *rd_ud,
                                             void (*free_rd)(void *)) {
  buckets_comp_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->rd = rd, r->rd_ud = rd_ud, r->free_rd = free_rd;
  if (buckets_s3_sse_encrypted(oi) && key) {
    buckets_sse_range srg = {.enc_off = rg->stored_off, .skip = rg->decrypt_skip, .seq = rg->seq, .part = rg->first_part};
    int64_t rest = decrypted_rest(oi, stored_size, rg->first_part, rg->seq) - rg->decrypt_skip;
    buckets_object_info tmp = *oi;
    tmp.size = stored_size;
    r->sr = buckets_sse_reader_new(&tmp, key, &srg, rest > 0 ? rest : 0, rd, rd_ud, free_rd);
    r->free_rd = NULL; /* the SSE reader owns rd now */
  }
  /* Reads that do not start at the beginning may start at a chunk. */
  r->s2 = buckets_s2_reader_new(comp_src_read, r, rg->stored_off > 0 || rg->part_skip > 0);
  r->skip = rg->part_skip;
  r->left = len;
  return r;
}

long buckets_comp_reader_read(void *ud, void *buf, size_t n) {
  buckets_comp_reader *r = ud;
  if (r->failed) return -1;
  if (r->skip > 0) {
    if (!buckets_s2_reader_skip(r->s2, r->skip)) {
      r->failed = true;
      return -1;
    }
    r->skip = 0;
  }
  if (r->left <= 0) return 0;
  if ((int64_t)n > r->left) n = (size_t)r->left;
  long k = buckets_s2_reader_read(r->s2, buf, n);
  if (k < 0 || (k == 0 && r->left > 0)) {
    r->failed = true; /* corrupt, or shorter than its recorded size */
    return -1;
  }
  r->left -= k;
  return k;
}

void buckets_comp_reader_free(void *ud) {
  buckets_comp_reader *r = ud;
  if (!r) return;
  buckets_s2_reader_free(r->s2);
  if (r->sr) buckets_sse_reader_free(r->sr);
  else if (r->free_rd) r->free_rd(r->rd_ud);
  free(r);
}
