/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* github.com/minio/zipindex: reading a zip archive's central directory
 * (archive/zip's rules), its four serialized forms, and File.Open. */
#include "s3/zipindex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

#include "core/common.h"
#include "core/msgpack.h"

#define FILE_HEADER_LEN 30
#define DIR_HEADER_LEN 46
#define DIR_END_LEN 22
#define DIR64_LOC_LEN 20
#define DIR64_END_LEN 56
#define DATA_DESC_LEN 16
#define SIG_FILE 0x04034b50u
#define SIG_DIR 0x02014b50u
#define SIG_END 0x06054b50u
#define SIG_END64_LOC 0x07064b50u
#define SIG_END64 0x06064b50u
#define SIG_DESC 0x08074b50u
#define METHOD_STORE 0
#define METHOD_DEFLATE 8
#define METHOD_ZSTD 93
#define MAX_INDEX (128 << 20)

void buckets_zipfiles_free(buckets_zipfiles *z) {
  for (size_t i = 0; i < z->n; i++) free(z->f[i].name);
  free(z->f);
  z->f = NULL;
  z->n = 0;
}

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t *p) { return (uint64_t)le32(p) | (uint64_t)le32(p + 4) << 32; }

static void push(buckets_zipfiles *z, size_t *cap, const buckets_zipfile *f) {
  if (z->n == *cap) z->f = buckets_xrealloc(z->f, (*cap = *cap ? *cap * 2 : 16) * sizeof(buckets_zipfile));
  z->f[z->n++] = *f;
}

static bool supported_method(uint16_t m) { return m == METHOD_STORE || m == METHOD_DEFLATE || m == METHOD_ZSTD; }

/* archive/zip's FileHeader.Mode(), reduced to "is it a regular file". */
static bool regular(uint16_t creator, uint32_t ext, const char *name, size_t n) {
  if (n && name[n - 1] == '/') return false;
  switch (creator >> 8) {
  case 3:   /* unix */
  case 19: { /* macOS */
    uint32_t m = (ext >> 16) & 0xf000;
    return m == 0 || m == 0x8000;
  }
  case 0:  /* FAT */
  case 11: /* NTFS */
  case 14: /* VFAT */
    return !(ext & 0x10);
  }
  return true;
}

buckets_zip_dir_status buckets_zipindex_read_dir(const uint8_t *buf, size_t n, int64_t size, buckets_zipfiles *out,
                                                 int64_t *need, char *err, size_t errcap) {
  memset(out, 0, sizeof(*out));
  *need = 0;
  if ((int64_t)n > size) {
    snprintf(err, errcap, "more bytes than total size provided");
    return BUCKETS_ZIP_DIR_BAD;
  }
  /* the end of central directory record, its comment inside the buffer */
  ssize_t at = -1;
  for (ssize_t i = (ssize_t)n - DIR_END_LEN; i >= 0; i--) {
    if (le32(buf + i) == SIG_END && (size_t)i + DIR_END_LEN + le16(buf + i + 20) <= n) {
      at = i;
      break;
    }
  }
  if (at < 0) {
    if ((int64_t)n < size && n < 65 * 1024 + DIR_END_LEN) {
      *need = size < 65 * 1024 + DIR_END_LEN ? size : 65 * 1024 + DIR_END_LEN;
      return BUCKETS_ZIP_DIR_MORE;
    }
    snprintf(err, errcap, "zip: not a valid zip file");
    return BUCKETS_ZIP_DIR_BAD;
  }
  const uint8_t *e = buf + at;
  uint64_t records = le16(e + 10), dsize = le32(e + 12), doff = le32(e + 16);
  if (records == 0xffff || dsize == 0xffff || doff == 0xffffffff) {
    /* zip64: the locator just before, and the record it points at */
    if (at >= DIR64_LOC_LEN && le32(e - DIR64_LOC_LEN) == SIG_END64_LOC) {
      int64_t end64 = (int64_t)le64(e - DIR64_LOC_LEN + 8);
      int64_t rel = end64 - (size - (int64_t)n);
      if (end64 < 0 || end64 >= size) {
        snprintf(err, errcap, "zip: not a valid zip file");
        return BUCKETS_ZIP_DIR_BAD;
      }
      if (rel < 0) {
        *need = size - end64;
        return BUCKETS_ZIP_DIR_MORE;
      }
      if ((size_t)rel + DIR64_END_LEN > n || le32(buf + rel) != SIG_END64) {
        snprintf(err, errcap, "zip: not a valid zip file");
        return BUCKETS_ZIP_DIR_BAD;
      }
      const uint8_t *r = buf + rel;
      records = le64(r + 32);
      dsize = le64(r + 40);
      doff = le64(r + 48);
    }
  }
  if ((int64_t)doff < 0 || (int64_t)doff >= size) {
    snprintf(err, errcap, "zip: not a valid zip file");
    return BUCKETS_ZIP_DIR_BAD;
  }
  if (records > (uint64_t)size / FILE_HEADER_LEN) {
    snprintf(err, errcap, "archive/zip: TOC declares impossible %llu files in %lld byte zip", (unsigned long long)records,
             (long long)size);
    return BUCKETS_ZIP_DIR_BAD;
  }
  int64_t want = size - (int64_t)doff;
  if (want > (int64_t)n) {
    *need = want;
    return BUCKETS_ZIP_DIR_MORE;
  }
  const uint8_t *p = buf + (n - (size_t)want), *end = buf + n;
  size_t cap = 0, entries = 0;
  (void)dsize;
  while (end - p >= DIR_HEADER_LEN && le32(p) == SIG_DIR) {
    uint16_t creator = le16(p + 4), flags = le16(p + 8), method = le16(p + 10);
    uint32_t crc = le32(p + 16);
    uint64_t csize = le32(p + 20), usize = le32(p + 24);
    size_t nl = le16(p + 28), el = le16(p + 30), cl = le16(p + 32);
    uint32_t ext = le32(p + 38);
    uint64_t off = le32(p + 42);
    if ((size_t)(end - p) < DIR_HEADER_LEN + nl + el + cl) break;
    const char *name = (const char *)p + DIR_HEADER_LEN;
    const uint8_t *x = p + DIR_HEADER_LEN + nl, *xe = x + el;
    bool need_u = usize == 0xffffffff, need_c = csize == 0xffffffff, need_o = off == 0xffffffff;
    while (xe - x >= 4) {
      uint16_t id = le16(x), len = le16(x + 2);
      const uint8_t *d = x + 4;
      if (len > xe - d) break;
      if (id == 1) { /* zip64 */
        const uint8_t *q = d, *qe = d + len;
        if (need_u && qe - q >= 8) usize = le64(q), q += 8;
        if (need_c && qe - q >= 8) csize = le64(q), q += 8;
        if (need_o && qe - q >= 8) off = le64(q), q += 8;
      }
      x = d + len;
    }
    p += DIR_HEADER_LEN + nl + el + cl;
    entries++;
    if (!regular(creator, ext, name, nl) || !supported_method(method)) continue;
    buckets_zipfile f = {0};
    f.name = buckets_xmalloc(nl + 1);
    memcpy(f.name, name, nl);
    f.name[nl] = 0;
    f.name_len = nl;
    f.csize = csize;
    f.usize = usize;
    f.offset = (int64_t)off;
    f.crc = crc;
    f.method = method;
    f.flags = flags;
    push(out, &cap, &f);
  }
  if ((uint16_t)entries != (uint16_t)records) {
    buckets_zipfiles_free(out);
    snprintf(err, errcap, "zip: not a valid zip file");
    return BUCKETS_ZIP_DIR_BAD;
  }
  return BUCKETS_ZIP_DIR_OK;
}

static int cmp_offset(const void *a, const void *b) {
  const buckets_zipfile *x = a, *y = b;
  return x->offset < y->offset ? -1 : x->offset > y->offset;
}

static int cmp_name(const void *a, const void *b) {
  const buckets_zipfile *x = a, *y = b;
  size_t n = x->name_len < y->name_len ? x->name_len : y->name_len;
  int c = memcmp(x->name, y->name, n);
  if (c) return c;
  if (x->name_len != y->name_len) return x->name_len < y->name_len ? -1 : 1;
  return x->offset < y->offset ? -1 : x->offset > y->offset;
}

void buckets_zipindex_optimize(buckets_zipfiles *z) {
  qsort(z->f, z->n, sizeof(buckets_zipfile), cmp_offset);
  for (size_t i = 0; i < z->n; i++)
    if (z->f[i].flags & 0x8) z->f[i].crc = 0;
}

/* ---- serialized forms ---- */

static void zstd_append(buckets_buf *out, const buckets_buf *payload) {
  size_t bound = ZSTD_compressBound(payload->len);
  buckets_buf_reserve(out, bound);
  ZSTD_CCtx *cc = ZSTD_createCCtx();
  ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, 7);
  ZSTD_CCtx_setParameter(cc, ZSTD_c_windowLog, 17); /* a 128 KiB window, as zipindex encodes */
  ZSTD_CCtx_setParameter(cc, ZSTD_c_contentSizeFlag, 1);
  size_t k = ZSTD_compress2(cc, out->data + out->len, bound, payload->data ? payload->data : "", payload->len);
  ZSTD_freeCCtx(cc);
  if (!ZSTD_isError(k)) out->len += k;
}

/* Struct-of-arrays (version 3), appended to out with its version byte. */
static void encode_aos(const buckets_zipfile *f, size_t n, buckets_buf *out) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_mp_array(&p, 8);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) buckets_mp_bin(&p, f[i].name, f[i].name_len);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++)
    buckets_mp_int(&p, i ? (int64_t)f[i].csize - (int64_t)f[i - 1].csize : (int64_t)f[i].csize);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) buckets_mp_int(&p, (int64_t)f[i].usize - (int64_t)f[i].csize);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) {
    int64_t o = f[i].offset;
    if (i) o -= f[i - 1].offset + (int64_t)f[i - 1].csize + FILE_HEADER_LEN + (int64_t)f[i - 1].name_len + DATA_DESC_LEN;
    buckets_mp_int(&p, o);
  }
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) buckets_mp_uint(&p, i ? (uint16_t)(f[i].method ^ f[i - 1].method) : f[i].method);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) buckets_mp_uint(&p, i ? (uint16_t)(f[i].flags ^ f[i - 1].flags) : f[i].flags);
  uint8_t *crcs = buckets_xmalloc(n * 4 + 1);
  for (size_t i = 0; i < n; i++) {
    crcs[i * 4] = (uint8_t)f[i].crc;
    crcs[i * 4 + 1] = (uint8_t)(f[i].crc >> 8);
    crcs[i * 4 + 2] = (uint8_t)(f[i].crc >> 16);
    crcs[i * 4 + 3] = (uint8_t)(f[i].crc >> 24);
  }
  buckets_mp_bin(&p, crcs, n * 4);
  free(crcs);
  buckets_mp_array(&p, (uint32_t)n);
  for (size_t i = 0; i < n; i++) buckets_mp_bin(&p, "", 0);
  buckets_buf_append_char(out, 3);
  zstd_append(out, &p);
  buckets_buf_free(&p);
}

void buckets_zipindex_serialize(const buckets_zipfiles *z, buckets_buf *out) {
  if (z->n < 10) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_mp_array(&p, (uint32_t)z->n);
    for (size_t i = 0; i < z->n; i++) {
      const buckets_zipfile *f = &z->f[i];
      buckets_mp_array(&p, 8);
      buckets_mp_str(&p, f->name, f->name_len);
      buckets_mp_uint(&p, f->csize);
      buckets_mp_uint(&p, f->usize);
      buckets_mp_int(&p, f->offset);
      buckets_mp_uint(&p, f->crc);
      buckets_mp_uint(&p, f->method);
      buckets_mp_uint(&p, f->flags);
      buckets_mp_map(&p, 0);
    }
    if (p.len < 200) {
      buckets_buf_append_char(out, 1);
      buckets_buf_append(out, p.data, p.len);
    } else {
      buckets_buf_append_char(out, 2);
      zstd_append(out, &p);
    }
    buckets_buf_free(&p);
    return;
  }
  const size_t chunk_n = 25000;
  if (z->n < chunk_n) {
    encode_aos(z->f, z->n, out);
    return;
  }
  /* chunked (version 4): by name, each chunk by offset */
  buckets_zipfile *s = buckets_xmalloc(z->n * sizeof(buckets_zipfile));
  memcpy(s, z->f, z->n * sizeof(buckets_zipfile));
  qsort(s, z->n, sizeof(buckets_zipfile), cmp_name);
  buckets_buf_append_char(out, 4);
  size_t left = z->n, at = 0;
  buckets_buf tmp = BUCKETS_BUF_INIT;
  while (left) {
    size_t todo = left;
    if (left < chunk_n * 2 && left > chunk_n) todo = left / 2;
    else if (left > chunk_n) todo = chunk_n;
    buckets_zipfile *c = s + at;
    buckets_mp_map(out, 4);
    buckets_mp_cstr(out, "Files");
    buckets_mp_int(out, (int64_t)todo);
    buckets_mp_cstr(out, "First");
    buckets_mp_str(out, c[0].name, c[0].name_len);
    buckets_mp_cstr(out, "Last");
    buckets_mp_str(out, c[todo - 1].name, c[todo - 1].name_len);
    qsort(c, todo, sizeof(buckets_zipfile), cmp_offset);
    buckets_buf_reset(&tmp);
    encode_aos(c, todo, &tmp);
    buckets_mp_cstr(out, "Payload");
    buckets_mp_bin(out, tmp.data, tmp.len);
    left -= todo;
    at += todo;
  }
  buckets_buf_free(&tmp);
  free(s);
}

static bool zstd_decode(const uint8_t *p, size_t n, buckets_buf *out) {
  ZSTD_DCtx *dc = ZSTD_createDCtx();
  ZSTD_DCtx_setParameter(dc, ZSTD_d_windowLogMax, 23); /* 8 MiB */
  uint8_t tmp[64 * 1024];
  ZSTD_inBuffer in = {p, n, 0};
  bool ok = true;
  while (ok) {
    ZSTD_outBuffer o = {tmp, sizeof(tmp), 0};
    size_t rc = ZSTD_decompressStream(dc, &o, &in);
    if (ZSTD_isError(rc)) ok = false;
    buckets_buf_append(out, tmp, o.pos);
    if (out->len > MAX_INDEX) ok = false;
    if (rc == 0 && in.pos == in.size) break;
    if (!o.pos && in.pos == in.size) {
      ok = rc == 0;
      break;
    }
  }
  ZSTD_freeDCtx(dc);
  return ok;
}

static bool decode_tuples(buckets_mp_reader *r, buckets_zipfiles *out) {
  uint32_t n;
  if (!buckets_mp_read_array(r, &n) || n > 100) return false;
  size_t cap = 0;
  for (uint32_t i = 0; i < n; i++) {
    uint32_t k;
    if (!buckets_mp_read_array(r, &k) || k != 8) return false;
    buckets_zipfile f = {0};
    buckets_str name;
    uint64_t crc, method, flags;
    if (!buckets_mp_read_str(r, &name) || !buckets_mp_read_uint(r, &f.csize) || !buckets_mp_read_uint(r, &f.usize) ||
        !buckets_mp_read_int(r, &f.offset) || !buckets_mp_read_uint(r, &crc) || !buckets_mp_read_uint(r, &method) ||
        !buckets_mp_read_uint(r, &flags) || !buckets_mp_skip(r))
      return false;
    f.crc = (uint32_t)crc;
    f.method = (uint16_t)method;
    f.flags = (uint16_t)flags;
    f.name = buckets_str_dup(name);
    f.name_len = name.n;
    push(out, &cap, &f);
  }
  return true;
}

/* The struct-of-arrays payload, appended to out. */
static bool decode_aos(const uint8_t *p, size_t len, buckets_zipfiles *out) {
  buckets_mp_reader r = buckets_mp_reader_init(p, len);
  uint32_t k, n, m;
  if (!buckets_mp_read_array(&r, &k) || k != 8 || !buckets_mp_read_array(&r, &n)) return false;
  size_t base = out->n, cap = out->n;
  out->f = buckets_xrealloc(out->f, (base + n + 1) * sizeof(buckets_zipfile));
  cap = base + n + 1;
  (void)cap;
  for (uint32_t i = 0; i < n; i++) {
    buckets_str name;
    if (!buckets_mp_read_bin(&r, &name) && !buckets_mp_read_str(&r, &name)) return false;
    buckets_zipfile *f = &out->f[base + i];
    memset(f, 0, sizeof(*f));
    f->name = buckets_str_dup(name);
    f->name_len = name.n;
    out->n = base + i + 1;
  }
  for (int field = 0; field < 7; field++) {
    if (field == 5) {
      buckets_str crcs;
      if (!buckets_mp_read_bin(&r, &crcs) || crcs.n != (size_t)n * 4) return false;
      for (uint32_t i = 0; i < n; i++) out->f[base + i].crc = le32((const uint8_t *)crcs.p + i * 4);
      continue;
    }
    if (!buckets_mp_read_array(&r, &m) || m != n) return false;
    for (uint32_t i = 0; i < n; i++) {
      buckets_zipfile *f = &out->f[base + i], *prev = i ? &out->f[base + i - 1] : NULL;
      int64_t v;
      uint64_t u;
      switch (field) {
      case 0:
        if (!buckets_mp_read_int(&r, &v)) return false;
        f->csize = (uint64_t)(prev ? (int64_t)prev->csize + v : v);
        break;
      case 1:
        if (!buckets_mp_read_int(&r, &v)) return false;
        f->usize = (uint64_t)((int64_t)f->csize + v);
        break;
      case 2:
        if (!buckets_mp_read_int(&r, &v)) return false;
        f->offset = prev ? v + prev->offset + (int64_t)prev->csize + FILE_HEADER_LEN + (int64_t)prev->name_len + DATA_DESC_LEN
                         : v;
        break;
      case 3:
        if (!buckets_mp_read_uint(&r, &u)) return false;
        f->method = (uint16_t)(prev ? prev->method ^ u : u);
        break;
      case 4:
        if (!buckets_mp_read_uint(&r, &u)) return false;
        f->flags = (uint16_t)(prev ? prev->flags ^ u : u);
        break;
      case 6:
        if (!buckets_mp_skip(&r)) return false;
        break;
      }
    }
  }
  return true;
}

bool buckets_zipindex_deserialize(const uint8_t *p, size_t n, buckets_zipfiles *out) {
  memset(out, 0, sizeof(*out));
  if (n < 1 || n > MAX_INDEX) return false;
  buckets_buf plain = BUCKETS_BUF_INIT;
  bool ok = false;
  switch (p[0]) {
  case 1: {
    buckets_mp_reader r = buckets_mp_reader_init(p + 1, n - 1);
    ok = decode_tuples(&r, out);
    break;
  }
  case 2:
    if (zstd_decode(p + 1, n - 1, &plain)) {
      buckets_mp_reader r = buckets_mp_reader_init(plain.data, plain.len);
      ok = decode_tuples(&r, out);
    }
    break;
  case 3: ok = zstd_decode(p + 1, n - 1, &plain) && decode_aos((const uint8_t *)plain.data, plain.len, out); break;
  case 4: {
    buckets_mp_reader r = buckets_mp_reader_init(p + 1, n - 1);
    ok = true;
    while (ok && buckets_mp_remaining(&r)) {
      uint32_t fields;
      if (!buckets_mp_read_map(&r, &fields)) {
        ok = false;
        break;
      }
      buckets_str payload = {NULL, 0};
      for (uint32_t i = 0; ok && i < fields; i++) {
        buckets_str key;
        if (!buckets_mp_read_str(&r, &key)) ok = false;
        else if (buckets_str_eq_c(key, "Payload")) ok = buckets_mp_read_bin(&r, &payload);
        else ok = buckets_mp_skip(&r);
      }
      if (!ok || !payload.n || ((const uint8_t *)payload.p)[0] != 3) {
        ok = false;
        break;
      }
      buckets_buf_reset(&plain);
      ok = zstd_decode((const uint8_t *)payload.p + 1, payload.n - 1, &plain) &&
           decode_aos((const uint8_t *)plain.data, plain.len, out);
    }
    break;
  }
  }
  buckets_buf_free(&plain);
  if (!ok) buckets_zipfiles_free(out);
  return ok;
}

const buckets_zipfile *buckets_zipindex_find(const buckets_zipfiles *z, const char *name, size_t n) {
  for (size_t i = 0; i < z->n; i++)
    if (z->f[i].name_len == n && !memcmp(z->f[i].name, name, n)) return &z->f[i];
  return NULL;
}

/* ---- File.Open ---- */

struct buckets_zip_reader {
  buckets_zipfile f;
  buckets_zip_read_fn rd;
  void *ud;
  bool started, failed, done;
  uint64_t cleft; /* compressed bytes still to take */
  uint64_t nread;
  uint32_t crc;
  z_stream z;
  bool z_init;
  ZSTD_DStream *zs;
  uint8_t in[64 * 1024];
  size_t in_pos, in_len;
};

buckets_zip_reader *buckets_zip_reader_new(const buckets_zipfile *f, buckets_zip_read_fn rd, void *ud) {
  buckets_zip_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->f = *f;
  r->f.name = NULL;
  r->rd = rd;
  r->ud = ud;
  r->cleft = f->csize;
  r->crc = (uint32_t)crc32(0, NULL, 0);
  return r;
}

void buckets_zip_reader_free(buckets_zip_reader *r) {
  if (!r) return;
  if (r->z_init) inflateEnd(&r->z);
  if (r->zs) ZSTD_freeDStream(r->zs);
  free(r);
}

static bool read_full(buckets_zip_reader *r, void *buf, size_t n) {
  uint8_t *p = buf;
  while (n) {
    long k = r->rd(r->ud, p, n);
    if (k <= 0) return false;
    p += k;
    n -= (size_t)k;
  }
  return true;
}

static bool skip_bytes(buckets_zip_reader *r, size_t n) {
  uint8_t tmp[4096];
  while (n) {
    size_t k = n < sizeof(tmp) ? n : sizeof(tmp);
    if (!read_full(r, tmp, k)) return false;
    n -= k;
  }
  return true;
}

/* Compressed input, at most what the entry has left. */
static bool fill_in(buckets_zip_reader *r) {
  if (r->in_pos < r->in_len) return true;
  if (!r->cleft) return false;
  size_t want = r->cleft < sizeof(r->in) ? (size_t)r->cleft : sizeof(r->in);
  long k = r->rd(r->ud, r->in, want);
  if (k <= 0) return false;
  r->cleft -= (uint64_t)k;
  r->in_pos = 0;
  r->in_len = (size_t)k;
  return true;
}

static long finish(buckets_zip_reader *r) {
  r->done = true;
  if (r->nread != r->f.usize) return r->failed = true, -1;
  uint32_t want = r->f.crc;
  if (r->f.flags & 0x8) {
    /* the rest of the compressed data, then the data descriptor */
    r->in_pos = r->in_len;
    while (fill_in(r)) r->in_pos = r->in_len;
    uint8_t d[12];
    if (!read_full(r, d, 4)) return r->failed = true, -1;
    size_t off = 0;
    if (le32(d) != SIG_DESC) off = 4;
    if (!read_full(r, d + off, 12 - off)) return r->failed = true, -1;
    uint32_t dcrc = le32(d);
    if (want == 0) want = dcrc;
    else if (dcrc != want) return r->failed = true, -1;
  }
  if (want != 0 && r->crc != want) return r->failed = true, -1;
  return 0;
}

long buckets_zip_reader_read(void *ud, void *buf, size_t n) {
  buckets_zip_reader *r = ud;
  if (r->failed) return -1;
  if (r->done || !n) return 0;
  if (!r->started) {
    r->started = true;
    uint8_t h[FILE_HEADER_LEN];
    if (!read_full(r, h, sizeof(h)) || le32(h) != SIG_FILE || !skip_bytes(r, (size_t)le16(h + 26) + le16(h + 28)))
      return r->failed = true, -1;
    if (r->f.method == METHOD_DEFLATE) {
      if (inflateInit2(&r->z, -MAX_WBITS) != Z_OK) return r->failed = true, -1;
      r->z_init = true;
    } else if (r->f.method == METHOD_ZSTD) {
      r->zs = ZSTD_createDStream();
    } else if (r->f.method != METHOD_STORE) {
      return r->failed = true, -1;
    }
  }
  size_t got = 0;
  for (;;) {
    if (r->f.method == METHOD_STORE) {
      if (!fill_in(r)) break;
      size_t k = r->in_len - r->in_pos < n ? r->in_len - r->in_pos : n;
      memcpy(buf, r->in + r->in_pos, k);
      r->in_pos += k;
      got = k;
      break;
    }
    if (!fill_in(r) && r->in_pos == r->in_len) {
      if (r->f.method == METHOD_DEFLATE) break; /* flate ends by itself; the input ran out first */
      break;
    }
    if (r->f.method == METHOD_DEFLATE) {
      r->z.next_in = r->in + r->in_pos;
      r->z.avail_in = (uInt)(r->in_len - r->in_pos);
      r->z.next_out = buf;
      r->z.avail_out = (uInt)n;
      int rc = inflate(&r->z, Z_NO_FLUSH);
      r->in_pos = r->in_len - r->z.avail_in;
      got = n - r->z.avail_out;
      if (rc == Z_STREAM_END) {
        if (got) break;
        return finish(r);
      }
      if (rc != Z_OK && rc != Z_BUF_ERROR) return r->failed = true, -1;
      if (got) break;
    } else {
      ZSTD_inBuffer in = {r->in, r->in_len, r->in_pos};
      ZSTD_outBuffer out = {buf, n, 0};
      size_t rc = ZSTD_decompressStream(r->zs, &out, &in);
      r->in_pos = in.pos;
      if (ZSTD_isError(rc)) return r->failed = true, -1;
      got = out.pos;
      if (got) break;
      if (rc == 0 && r->in_pos == r->in_len && !r->cleft) break;
    }
  }
  if (got) {
    r->crc = (uint32_t)crc32(r->crc, buf, (uInt)got);
    r->nread += got;
    if (r->nread > r->f.usize) return r->failed = true, -1;
    return (long)got;
  }
  return finish(r);
}
