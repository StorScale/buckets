/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_COMPRESS_S2_H
#define BUCKETS_COMPRESS_S2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* S2 (github.com/klauspost/compress/s2), the Snappy extension MinIO stores
 * compressed objects in ("klauspost/compress/s2").
 *
 * Blocks: a uvarint decoded length, then literal and copy tags. S2 adds
 * repeat codes (copy1 with offset 0) and longer blocks to Snappy's format.
 * Streams: Snappy framing, i.e. a stream identifier ("S2sTwO", or Snappy's
 * "sNaPpY"), then chunks of type, 24-bit length and body: 0x00 compressed
 * and 0x01 uncompressed data (each with a masked CRC-32C of the decoded
 * bytes), 0xfe padding, 0x99 an index, 0x80-0xfd skippable, and 0x02-0x7f
 * unsupported. MinIO pads the streams of encrypted objects to 256 bytes and
 * keeps an index (headers removed) beside each part over 8 MiB. */

#define BUCKETS_S2_BLOCK_SIZE (1 << 20)     /* the writer's block size */
#define BUCKETS_S2_MAX_BLOCK_SIZE (4 << 20) /* the largest block a stream may hold */
#define BUCKETS_S2_MAGIC "\xff\x06\x00\x00S2sTwO"
#define BUCKETS_S2_MAGIC_LEN 10

typedef long (*buckets_s2_read_fn)(void *ud, void *buf, size_t n);

/* ---- blocks ---- */

/* MaxEncodedLen: the largest encoding of n bytes (body and length prefix). */
size_t buckets_s2_max_encoded_len(size_t n);
/* encodeBlock: the body of an encoding of src (no length prefix) into dst,
 * which holds buckets_s2_max_encoded_len(n) bytes. 0 when src does not
 * compress well enough to be worth a compressed chunk. */
size_t buckets_s2_encode_block(uint8_t *dst, const uint8_t *src, size_t n);
/* Encode: a complete block (length prefix and body; literals when src does
 * not compress). Returns its length. */
size_t buckets_s2_encode(uint8_t *dst, const uint8_t *src, size_t n);
/* The decoded length of a block and the size of its prefix. */
bool buckets_s2_decoded_len(const uint8_t *src, size_t n, size_t *len, size_t *prefix);
/* Decodes a whole block (with its prefix) into dst of cap bytes; returns the
 * decoded length, or -1 when the block is corrupt or does not fit. */
long buckets_s2_decode(uint8_t *dst, size_t cap, const uint8_t *src, size_t n);

/* The masked CRC-32C stored in data chunks. */
uint32_t buckets_s2_crc(const void *data, size_t n);

/* ---- index ---- */

typedef struct {
  int64_t total_uncompressed, total_compressed; /* -1: unknown */
  int64_t est_block_uncomp;
  int64_t *comp_off, *uncomp_off;
  size_t n, cap;
} buckets_s2_index;

void buckets_s2_index_free(buckets_s2_index *x);
/* Index.Load of an index with its headers removed (RestoreIndexHeaders +
 * Load, as MinIO keeps them in xl.meta). */
bool buckets_s2_index_load(buckets_s2_index *x, const uint8_t *b, size_t n);
/* Index.Find: the entry at or before the uncompressed offset. */
bool buckets_s2_index_find(const buckets_s2_index *x, int64_t offset, int64_t *comp_off, int64_t *uncomp_off);

/* ---- stream writer ----
 * Pulls plaintext from rd and yields the compressed stream. size is the
 * plaintext length (-1: read to EOF); a shorter body fails the read. */

typedef struct {
  buckets_s2_read_fn rd;
  void *rd_ud;
  int64_t remaining; /* -1: unknown */
  size_t pad;        /* pad the stream to a multiple of this (0/1: no padding) */
  bool header_done, eof, closed, failed;
  uint8_t *in, *out;
  size_t out_pos, out_len;
  size_t pending; /* a block read ahead with the stream header */
  bool has_pending;
  bool probed; /* read past a known size once, to see the source end */
  int64_t written, uncomp; /* stream bytes produced, plaintext bytes consumed */
  buckets_s2_index idx;
  uint64_t rng;
} buckets_s2_writer;

void buckets_s2_writer_init(buckets_s2_writer *w, buckets_s2_read_fn rd, void *rd_ud, int64_t size, size_t pad);
void buckets_s2_writer_free(buckets_s2_writer *w);
long buckets_s2_writer_read(void *ud, void *buf, size_t n);
/* After the stream ended: its index with the headers removed
 * (CloseIndex + RemoveIndexHeaders), for streams over min_size plaintext
 * bytes (MinIO: 8 MiB). False when none is due. */
bool buckets_s2_writer_index(buckets_s2_writer *w, int64_t min_size, buckets_buf *out);

/* ---- stream reader ----
 * Pulls a stream (or concatenated streams) from rd and yields the plaintext.
 * ignore_stream_id: the stream may start at a chunk instead of an identifier
 * (reads that begin mid-object). */

typedef struct buckets_s2_reader buckets_s2_reader;

buckets_s2_reader *buckets_s2_reader_new(buckets_s2_read_fn rd, void *rd_ud, bool ignore_stream_id);
void buckets_s2_reader_free(buckets_s2_reader *r);
/* 0 at the end of the stream, -1 when it is corrupt or the source fails. */
long buckets_s2_reader_read(void *ud, void *buf, size_t n);
/* Discards n plaintext bytes; false when the stream ends first or fails. */
bool buckets_s2_reader_skip(buckets_s2_reader *r, int64_t n);

#endif
