/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/zip.h"

#include <libdeflate.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"

static void put16(buckets_buf *b, unsigned v) {
  unsigned char x[2] = {(unsigned char)v, (unsigned char)(v >> 8)};
  buckets_buf_append(b, x, 2);
}

static void put32(buckets_buf *b, uint32_t v) {
  unsigned char x[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
  buckets_buf_append(b, x, 4);
}

static unsigned get16(const unsigned char *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
static uint32_t get32(const unsigned char *p) {
  return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* MS-DOS date and time, local like Go's for time.Now(). */
static void dos_time(time_t t, unsigned *date, unsigned *tm) {
  struct tm u;
  localtime_r(&t, &u);
  if (u.tm_year < 80) {
    *date = (0 << 9) | (1 << 5) | 1;
    *tm = 0;
    return;
  }
  *date = (unsigned)((u.tm_year - 80) << 9 | (u.tm_mon + 1) << 5 | u.tm_mday);
  *tm = (unsigned)(u.tm_hour << 11 | u.tm_min << 5 | u.tm_sec / 2);
}

void buckets_zip_writer_init(buckets_zip_writer *w) { memset(w, 0, sizeof(*w)); }

void buckets_zip_add(buckets_zip_writer *w, const char *name, const void *data, size_t len, time_t mtime) {
  struct libdeflate_compressor *c = libdeflate_alloc_compressor(6);
  size_t bound = libdeflate_deflate_compress_bound(c, len);
  unsigned char *z = buckets_xmalloc(bound ? bound : 1);
  size_t zlen = libdeflate_deflate_compress(c, data, len, z, bound);
  libdeflate_free_compressor(c);
  uint32_t crc = libdeflate_crc32(0, data, len);
  unsigned date, tm;
  dos_time(mtime, &date, &tm);
  size_t nlen = strlen(name);
  uint32_t off = (uint32_t)w->out.len;
  /* local file header */
  put32(&w->out, 0x04034b50);
  put16(&w->out, 20);     /* version needed */
  put16(&w->out, 0x0800); /* UTF-8 names */
  put16(&w->out, 8);      /* deflate */
  put16(&w->out, tm);
  put16(&w->out, date);
  put32(&w->out, crc);
  put32(&w->out, (uint32_t)zlen);
  put32(&w->out, (uint32_t)len);
  put16(&w->out, (unsigned)nlen);
  put16(&w->out, 0);
  buckets_buf_append(&w->out, name, nlen);
  buckets_buf_append(&w->out, z, zlen);
  free(z);
  /* central directory entry */
  put32(&w->central, 0x02014b50);
  put16(&w->central, 0x0314); /* made by: Unix, 2.0 */
  put16(&w->central, 20);
  put16(&w->central, 0x0800);
  put16(&w->central, 8);
  put16(&w->central, tm);
  put16(&w->central, date);
  put32(&w->central, crc);
  put32(&w->central, (uint32_t)zlen);
  put32(&w->central, (uint32_t)len);
  put16(&w->central, (unsigned)nlen);
  put16(&w->central, 0); /* extra */
  put16(&w->central, 0); /* comment */
  put16(&w->central, 0); /* disk */
  put16(&w->central, 0); /* internal attributes */
  put32(&w->central, 0100600u << 16); /* regular file, 0600 */
  put32(&w->central, off);
  buckets_buf_append(&w->central, name, nlen);
  w->count++;
}

void buckets_zip_finish(buckets_zip_writer *w) {
  uint32_t cd_off = (uint32_t)w->out.len;
  buckets_buf_append(&w->out, w->central.data ? w->central.data : "", w->central.len);
  put32(&w->out, 0x06054b50);
  put16(&w->out, 0);
  put16(&w->out, 0);
  put16(&w->out, (unsigned)w->count);
  put16(&w->out, (unsigned)w->count);
  put32(&w->out, (uint32_t)w->central.len);
  put32(&w->out, cd_off);
  put16(&w->out, 0);
  buckets_buf_free(&w->central);
}

void buckets_zip_writer_free(buckets_zip_writer *w) {
  buckets_buf_free(&w->out);
  buckets_buf_free(&w->central);
}

bool buckets_zip_open(buckets_zip_reader *r, const void *data, size_t len) {
  memset(r, 0, sizeof(*r));
  const unsigned char *p = data;
  if (len < 22) return false;
  /* the end of central directory record, searching back over a comment */
  size_t min = len > 22 + 65535 ? len - 22 - 65535 : 0;
  for (size_t i = len - 22 + 1; i-- > min;) {
    if (get32(p + i) != 0x06054b50) continue;
    size_t count = get16(p + i + 10), size = get32(p + i + 12), off = get32(p + i + 16);
    if (off > i || size > i - off) return false;
    r->data = p;
    r->len = len;
    r->cd_off = off;
    r->cd_count = count;
    return true;
  }
  return false;
}

buckets_zip_status buckets_zip_read(const buckets_zip_reader *r, const char *name, buckets_buf *out) {
  const unsigned char *p = r->data;
  size_t pos = r->cd_off, nlen = strlen(name);
  for (size_t i = 0; i < r->cd_count; i++) {
    if (pos + 46 > r->len || get32(p + pos) != 0x02014b50) return BUCKETS_ZIP_CORRUPT;
    unsigned method = get16(p + pos + 10);
    uint32_t crc = get32(p + pos + 16), csize = get32(p + pos + 20), usize = get32(p + pos + 24);
    size_t fl = get16(p + pos + 28), el = get16(p + pos + 30), cl = get16(p + pos + 32);
    size_t loff = get32(p + pos + 42);
    if (pos + 46 + fl + el + cl > r->len) return BUCKETS_ZIP_CORRUPT;
    bool match = fl == nlen && memcmp(p + pos + 46, name, nlen) == 0;
    pos += 46 + fl + el + cl;
    if (!match) continue;
    if (loff + 30 > r->len || get32(p + loff) != 0x04034b50) return BUCKETS_ZIP_CORRUPT;
    size_t data_off = loff + 30 + get16(p + loff + 26) + get16(p + loff + 28);
    if (data_off > r->len || csize > r->len - data_off) return BUCKETS_ZIP_CORRUPT;
    buckets_buf_reset(out);
    buckets_buf_reserve(out, usize + 1);
    if (method == 0) {
      if (csize != usize) return BUCKETS_ZIP_CORRUPT;
      buckets_buf_append(out, p + data_off, csize);
    } else if (method == 8) {
      struct libdeflate_decompressor *d = libdeflate_alloc_decompressor();
      size_t got = 0;
      enum libdeflate_result res =
          libdeflate_deflate_decompress(d, p + data_off, csize, out->data, usize, &got);
      libdeflate_free_decompressor(d);
      if (res != LIBDEFLATE_SUCCESS || got != usize) return BUCKETS_ZIP_CORRUPT;
      out->len = usize;
    } else {
      return BUCKETS_ZIP_CORRUPT;
    }
    if (libdeflate_crc32(0, out->data, out->len) != crc) return BUCKETS_ZIP_CORRUPT;
    return BUCKETS_ZIP_OK;
  }
  return BUCKETS_ZIP_NOT_FOUND;
}
