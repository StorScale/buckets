/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "compress/stream.h"

#include <bzlib.h>
#define LZ4F_STATIC_LINKING_ONLY
#include <lz4frame.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <zstd.h>

#include "compress/s2.h"
#include "core/common.h"

#define IN_CAP (128 * 1024)

struct buckets_decomp {
  buckets_decomp_type t;
  buckets_decomp_read_fn src;
  void *src_ud;
  int64_t consumed;
  buckets_decomp_err err;
  bool src_eof, done;
  uint8_t *in;
  size_t in_pos, in_len;
  bool started; /* gzip, bzip2: a member or stream is open */
  z_stream z;
  bz_stream bz;
  ZSTD_DStream *zs;
  LZ4F_dctx *lz;
  bool frame_open; /* zstd, lz4: inside a frame */
  const char *msg;  /* Go's wording of the failure */
  char msgbuf[96];
  buckets_s2_reader *s2;
};

static long counted(void *ud, void *buf, size_t n) {
  buckets_decomp *d = ud;
  long k = d->src(d->src_ud, buf, n);
  if (k > 0) d->consumed += k;
  return k;
}

/* Tops up the input buffer; false when there is nothing more (d->err is set
 * on a source failure). */
static bool fill(buckets_decomp *d) {
  if (d->in_pos < d->in_len) return true;
  if (d->src_eof) return false;
  long k = counted(d, d->in, IN_CAP);
  if (k < 0) {
    d->err = BUCKETS_DECOMP_ERR_SOURCE;
    return false;
  }
  if (k == 0) {
    d->src_eof = true;
    return false;
  }
  d->in_pos = 0;
  d->in_len = (size_t)k;
  return true;
}

buckets_decomp *buckets_decomp_new(buckets_decomp_type t, buckets_decomp_read_fn src, void *src_ud) {
  buckets_decomp *d = buckets_xcalloc(1, sizeof(*d));
  d->t = t;
  d->src = src;
  d->src_ud = src_ud;
  switch (t) {
  case BUCKETS_DECOMP_S2:
  case BUCKETS_DECOMP_SNAPPY:
    d->s2 = buckets_s2_reader_new(counted, d, false);
    break;
  case BUCKETS_DECOMP_NONE:
    break;
  default:
    d->in = buckets_xmalloc(IN_CAP);
    break;
  }
  if (t == BUCKETS_DECOMP_ZSTD) {
    d->zs = ZSTD_createDStream();
    ZSTD_DCtx_setParameter(d->zs, ZSTD_d_windowLogMax, 26); /* a 64 MiB window at most, as MinIO */
  } else if (t == BUCKETS_DECOMP_LZ4) {
    LZ4F_createDecompressionContext(&d->lz, LZ4F_VERSION);
  }
  return d;
}

void buckets_decomp_free(buckets_decomp *d) {
  if (!d) return;
  if (d->started && d->t == BUCKETS_DECOMP_GZIP) inflateEnd(&d->z);
  if (d->started && d->t == BUCKETS_DECOMP_BZIP2) BZ2_bzDecompressEnd(&d->bz);
  if (d->zs) ZSTD_freeDStream(d->zs);
  if (d->lz) LZ4F_freeDecompressionContext(d->lz);
  if (d->s2) buckets_s2_reader_free(d->s2);
  free(d->in);
  free(d);
}

buckets_decomp_err buckets_decomp_error(const buckets_decomp *d) { return d->err; }
int64_t buckets_decomp_consumed(const buckets_decomp *d) { return d->consumed; }

static long fail(buckets_decomp *d, buckets_decomp_err e) {
  if (!d->err) {
    d->err = e;
    if (!d->msg) {
      if (e == BUCKETS_DECOMP_ERR_TRUNCATED) d->msg = "unexpected EOF";
      else if (e == BUCKETS_DECOMP_ERR_SOURCE) d->msg = "reading the object failed";
      else {
        switch (d->t) {
        case BUCKETS_DECOMP_GZIP: d->msg = d->started ? "flate: corrupt input" : "gzip: invalid header"; break;
        case BUCKETS_DECOMP_BZIP2: d->msg = "bzip2 data invalid: bad magic value"; break;
        case BUCKETS_DECOMP_ZSTD: d->msg = "invalid input: magic number mismatch"; break;
        case BUCKETS_DECOMP_LZ4: d->msg = "lz4: bad magic number"; break;
        default: d->msg = "s2: corrupt input"; break;
        }
      }
    }
  }
  return -1;
}

const char *buckets_decomp_message(const buckets_decomp *d) { return d->msg ? d->msg : ""; }

/* Another member or stream follows when input remains; otherwise the data
 * has ended cleanly. */
static bool next_member(buckets_decomp *d) { return fill(d); }

static long read_gzip(buckets_decomp *d, uint8_t *out, size_t n) {
  for (;;) {
    if (!d->started) {
      if (!fill(d)) return d->err ? -1 : (d->done = true, 0);
      memset(&d->z, 0, sizeof(d->z));
      if (inflateInit2(&d->z, 16 + MAX_WBITS) != Z_OK) return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
      d->started = true;
    }
    if (d->in_pos == d->in_len && !fill(d)) return d->err ? -1 : fail(d, BUCKETS_DECOMP_ERR_TRUNCATED);
    d->z.next_in = d->in + d->in_pos;
    d->z.avail_in = (uInt)(d->in_len - d->in_pos);
    d->z.next_out = out;
    d->z.avail_out = (uInt)n;
    int rc = inflate(&d->z, Z_NO_FLUSH);
    d->in_pos = d->in_len - d->z.avail_in;
    size_t got = n - d->z.avail_out;
    if (rc == Z_STREAM_END) {
      inflateEnd(&d->z);
      d->started = false;
      if (!next_member(d) && d->err) return -1;
      if (got) return (long)got;
      continue;
    }
    if (rc != Z_OK && rc != Z_BUF_ERROR) {
      if (rc == Z_DATA_ERROR && d->z.total_in >= 10) {
        /* flate's offset counts from the deflate data, after the header */
        snprintf(d->msgbuf, sizeof(d->msgbuf), "flate: corrupt input before offset %lu",
                 (unsigned long)(d->z.total_in - 10));
        d->msg = d->msgbuf;
      }
      return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
    }
    if (got) return (long)got;
  }
}

static long read_bzip2(buckets_decomp *d, uint8_t *out, size_t n) {
  for (;;) {
    if (!d->started) {
      if (!fill(d)) return d->err ? -1 : (d->done = true, 0);
      memset(&d->bz, 0, sizeof(d->bz));
      if (BZ2_bzDecompressInit(&d->bz, 0, 0) != BZ_OK) return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
      d->started = true;
    }
    if (d->in_pos == d->in_len && !fill(d)) return d->err ? -1 : fail(d, BUCKETS_DECOMP_ERR_TRUNCATED);
    d->bz.next_in = (char *)d->in + d->in_pos;
    d->bz.avail_in = (unsigned)(d->in_len - d->in_pos);
    d->bz.next_out = (char *)out;
    d->bz.avail_out = (unsigned)n;
    int rc = BZ2_bzDecompress(&d->bz);
    d->in_pos = d->in_len - d->bz.avail_in;
    size_t got = n - d->bz.avail_out;
    if (rc == BZ_STREAM_END) {
      BZ2_bzDecompressEnd(&d->bz);
      d->started = false;
      if (!next_member(d) && d->err) return -1;
      if (got) return (long)got;
      continue;
    }
    if (rc != BZ_OK) return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
    if (got) return (long)got;
  }
}

static long read_zstd(buckets_decomp *d, uint8_t *out, size_t n) {
  for (;;) {
    if (d->in_pos == d->in_len && !fill(d)) {
      if (d->err) return -1;
      if (d->frame_open) {
        /* flush what the decoder still holds */
        ZSTD_inBuffer ib = {NULL, 0, 0};
        ZSTD_outBuffer ob = {out, n, 0};
        size_t rc = ZSTD_decompressStream(d->zs, &ob, &ib);
        if (ZSTD_isError(rc)) return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
        if (ob.pos) return (long)ob.pos;
        return fail(d, BUCKETS_DECOMP_ERR_TRUNCATED);
      }
      return 0;
    }
    ZSTD_inBuffer ib = {d->in, d->in_len, d->in_pos};
    ZSTD_outBuffer ob = {out, n, 0};
    size_t rc = ZSTD_decompressStream(d->zs, &ob, &ib);
    d->in_pos = ib.pos;
    if (ZSTD_isError(rc)) {
      if (ZSTD_getErrorCode(rc) != ZSTD_error_prefix_unknown) d->msg = "invalid input: corrupt block";
      return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
    }
    d->frame_open = rc != 0;
    if (ob.pos) return (long)ob.pos;
  }
}

static long read_lz4(buckets_decomp *d, uint8_t *out, size_t n) {
  for (;;) {
    if (d->in_pos == d->in_len && !fill(d)) {
      if (d->err) return -1;
      return d->frame_open ? fail(d, BUCKETS_DECOMP_ERR_TRUNCATED) : 0;
    }
    size_t out_n = n, in_n = d->in_len - d->in_pos;
    size_t rc = LZ4F_decompress(d->lz, out, &out_n, d->in + d->in_pos, &in_n, NULL);
    d->in_pos += in_n;
    if (LZ4F_isError(rc)) {
      if (LZ4F_getErrorCode(rc) != LZ4F_ERROR_frameType_unknown) d->msg = "lz4: invalid block checksum";
      return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
    }
    d->frame_open = rc != 0;
    if (out_n) return (long)out_n;
  }
}

long buckets_decomp_read(void *ud, void *buf, size_t n) {
  buckets_decomp *d = ud;
  if (d->err) return -1;
  if (d->done || n == 0) return 0;
  switch (d->t) {
  case BUCKETS_DECOMP_NONE: {
    long k = counted(d, buf, n);
    if (k < 0) return fail(d, BUCKETS_DECOMP_ERR_SOURCE);
    return k;
  }
  case BUCKETS_DECOMP_GZIP:
    return read_gzip(d, buf, n);
  case BUCKETS_DECOMP_BZIP2:
    return read_bzip2(d, buf, n);
  case BUCKETS_DECOMP_ZSTD:
    return read_zstd(d, buf, n);
  case BUCKETS_DECOMP_LZ4:
    return read_lz4(d, buf, n);
  case BUCKETS_DECOMP_S2:
  case BUCKETS_DECOMP_SNAPPY: {
    long k = buckets_s2_reader_read(d->s2, buf, n);
    if (k < 0) return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
    return k;
  }
  }
  return fail(d, BUCKETS_DECOMP_ERR_FORMAT);
}

buckets_decomp_type buckets_decomp_detect(const uint8_t *p, size_t n) {
  if (n >= 2 && p[0] == 0x1f && p[1] == 0x8b) return BUCKETS_DECOMP_GZIP;
  if (n >= 4 && p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd) return BUCKETS_DECOMP_ZSTD;
  if (n >= 4 && p[0] == 0x04 && p[1] == 0x22 && p[2] == 0x4d && p[3] == 0x18) return BUCKETS_DECOMP_LZ4;
  if (n >= 3 && p[0] == 'B' && p[1] == 'Z' && p[2] == 'h') return BUCKETS_DECOMP_BZIP2;
  if (n >= 10 && p[0] == 0xff && memcmp(p + 4, "S2sTwO", 6) == 0) return BUCKETS_DECOMP_S2;
  if (n >= 10 && p[0] == 0xff && memcmp(p + 4, "sNaPpY", 6) == 0) return BUCKETS_DECOMP_SNAPPY;
  return BUCKETS_DECOMP_NONE;
}

/* bzip2 without stdio calls this on an internal inconsistency. */
void bz_internal_error(int errcode);
void bz_internal_error(int errcode) {
  (void)errcode;
  abort();
}
