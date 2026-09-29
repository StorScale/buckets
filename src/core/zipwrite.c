/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/zipwrite.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "core/common.h"

typedef struct {
  char *name;
  uint32_t crc, csize, usize, offset, attrs;
  uint16_t method;
  uint16_t dos_time, dos_date;
} entry;

struct buckets_zipw {
  buckets_buf *out;
  entry *e;
  size_t n;
};

static void le16(buckets_buf *b, uint16_t v) {
  uint8_t x[2] = {(uint8_t)v, (uint8_t)(v >> 8)};
  buckets_buf_append(b, x, 2);
}
static void le32(buckets_buf *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};
  buckets_buf_append(b, x, 4);
}

buckets_zipw *buckets_zipw_new(buckets_buf *out) {
  buckets_zipw *z = buckets_xcalloc(1, sizeof(*z));
  z->out = out;
  return z;
}

void buckets_zipw_add(buckets_zipw *z, const char *name, const void *data, size_t len, time_t mtime) {
  buckets_zipw_add_mode(z, name, data, len, mtime, 0600, false);
}

void buckets_zipw_add_mode(buckets_zipw *z, const char *name, const void *data, size_t len, time_t mtime,
                           uint32_t perm, bool dir) {
  z->e = buckets_xrealloc(z->e, (z->n + 1) * sizeof(*z->e));
  entry *e = &z->e[z->n++];
  memset(e, 0, sizeof(*e));
  e->name = buckets_xstrdup(name);
  /* FileHeader.SetMode: the Unix mode above, MS-DOS directory and read-only bits below */
  e->attrs = ((dir ? 040000u : 0100000u) | (perm & 07777)) << 16 | (dir ? 0x10 : 0) | (perm & 0200 ? 0 : 0x01);
  struct tm tm;
  localtime_r(&mtime, &tm); /* MS-DOS times are local, as Go's FileInfoHeader sets them */
  e->dos_time = (uint16_t)(tm.tm_hour << 11 | tm.tm_min << 5 | tm.tm_sec / 2);
  e->dos_date = (uint16_t)((tm.tm_year - 80) << 9 | (tm.tm_mon + 1) << 5 | tm.tm_mday);
  if (dir) len = 0; /* zip.Writer stores directories, empty */
  e->crc = len ? (uint32_t)crc32(0L, data, (uInt)len) : 0;
  e->usize = (uint32_t)len;
  e->method = dir ? 0 : 8;
  /* raw deflate */
  z_stream zs;
  memset(&zs, 0, sizeof(zs));
  deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
  uLong bound = deflateBound(&zs, (uLong)len);
  uint8_t *cbuf = buckets_xmalloc(bound + 16);
  if (dir) {
    e->csize = 0;
  } else {
    zs.next_in = (Bytef *)data;
    zs.avail_in = (uInt)len;
    zs.next_out = cbuf;
    zs.avail_out = (uInt)(bound + 16);
    deflate(&zs, Z_FINISH);
    e->csize = (uint32_t)zs.total_out;
  }
  deflateEnd(&zs);
  e->offset = (uint32_t)z->out->len;
  buckets_buf *b = z->out;
  le32(b, 0x04034b50);
  le16(b, 20); /* version needed */
  le16(b, 0x0800); /* UTF-8 names */
  le16(b, e->method);
  le16(b, e->dos_time);
  le16(b, e->dos_date);
  le32(b, e->crc);
  le32(b, e->csize);
  le32(b, e->usize);
  le16(b, (uint16_t)strlen(name));
  le16(b, 0);
  buckets_buf_append_c(b, name);
  buckets_buf_append(b, cbuf, e->csize);
  free(cbuf);
}

void buckets_zipw_finish(buckets_zipw *z) {
  buckets_buf *b = z->out;
  uint32_t cd = (uint32_t)b->len;
  for (size_t i = 0; i < z->n; i++) {
    entry *e = &z->e[i];
    le32(b, 0x02014b50);
    le16(b, 3 << 8 | 20); /* made by Unix, zip 2.0 */
    le16(b, 20);
    le16(b, 0x0800);
    le16(b, e->method);
    le16(b, e->dos_time);
    le16(b, e->dos_date);
    le32(b, e->crc);
    le32(b, e->csize);
    le32(b, e->usize);
    le16(b, (uint16_t)strlen(e->name));
    le16(b, 0);
    le16(b, 0);
    le16(b, 0);
    le16(b, 0);
    le32(b, e->attrs);
    le32(b, e->offset);
    buckets_buf_append_c(b, e->name);
    free(e->name);
  }
  uint32_t cd_size = (uint32_t)b->len - cd;
  le32(b, 0x06054b50);
  le16(b, 0);
  le16(b, 0);
  le16(b, (uint16_t)z->n);
  le16(b, (uint16_t)z->n);
  le32(b, cd_size);
  le32(b, cd);
  le16(b, 0);
  free(z->e);
  free(z);
}
