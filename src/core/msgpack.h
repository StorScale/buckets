/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_MSGPACK_H
#define BUCKETS_CORE_MSGPACK_H

#include "core/buf.h"
#include "core/str.h"

/* MessagePack encoder/decoder that reproduces the exact encodings chosen by
 * github.com/tinylib/msgp, which MinIO uses for xl.meta and bucket metadata.
 * Byte-exact output matters: xl.meta carries checksums over encoded bytes. */

/* ---- writer (appends to a buffer) ---- */
void buckets_mp_nil(buckets_buf *b);
void buckets_mp_bool(buckets_buf *b, bool v);
void buckets_mp_uint(buckets_buf *b, uint64_t v); /* msgp.AppendUint* */
void buckets_mp_int(buckets_buf *b, int64_t v);   /* msgp.AppendInt* */
void buckets_mp_str(buckets_buf *b, const char *s, size_t n);
void buckets_mp_cstr(buckets_buf *b, const char *s);
void buckets_mp_bin(buckets_buf *b, const void *p, size_t n);
void buckets_mp_array(buckets_buf *b, uint32_t n);
void buckets_mp_map(buckets_buf *b, uint32_t n);
/* msgp.AppendTime: ext8 type 5 carrying big-endian int64 seconds + int32 nanoseconds. */
void buckets_mp_time(buckets_buf *b, int64_t unix_ns);
/* Same with explicit seconds, which also covers Go's zero time (year 1). */
void buckets_mp_time_sec(buckets_buf *b, int64_t sec, int32_t nsec);
#define BUCKETS_GO_ZERO_TIME_SEC (-62135596800LL)
/* msgp.AppendFloat64: 0xcb and the big-endian IEEE 754 bits. */
void buckets_mp_float64(buckets_buf *b, double v);

/* ---- reader (cursor over an input slice) ---- */
typedef struct {
  const uint8_t *p;
  const uint8_t *end;
  bool err; /* sticky: once set, all reads fail */
} buckets_mp_reader;

typedef enum {
  BUCKETS_MP_NIL,
  BUCKETS_MP_BOOL,
  BUCKETS_MP_INT,  /* any integer encoding */
  BUCKETS_MP_FLOAT,
  BUCKETS_MP_STR,
  BUCKETS_MP_BIN,
  BUCKETS_MP_ARRAY,
  BUCKETS_MP_MAP,
  BUCKETS_MP_EXT,
  BUCKETS_MP_INVALID,
} buckets_mp_type;

static inline buckets_mp_reader buckets_mp_reader_init(const void *p, size_t n) {
  return (buckets_mp_reader){(const uint8_t *)p, (const uint8_t *)p + n, false};
}
static inline size_t buckets_mp_remaining(const buckets_mp_reader *r) { return (size_t)(r->end - r->p); }

buckets_mp_type buckets_mp_peek(const buckets_mp_reader *r);
bool buckets_mp_read_nil(buckets_mp_reader *r); /* true if a nil was consumed */
bool buckets_mp_read_bool(buckets_mp_reader *r, bool *v);
bool buckets_mp_read_int(buckets_mp_reader *r, int64_t *v);   /* accepts uint encodings that fit */
bool buckets_mp_read_uint(buckets_mp_reader *r, uint64_t *v); /* accepts non-negative int encodings */
bool buckets_mp_read_float64(buckets_mp_reader *r, double *v); /* also float32 and integers */
/* Zero-copy: *out points into the input. read_str also accepts bin and vice
 * versa, matching msgp's ReadMapKeyZC / ReadBytesZC leniency. */
bool buckets_mp_read_str(buckets_mp_reader *r, buckets_str *out);
bool buckets_mp_read_bin(buckets_mp_reader *r, buckets_str *out);
bool buckets_mp_read_array(buckets_mp_reader *r, uint32_t *n);
bool buckets_mp_read_map(buckets_mp_reader *r, uint32_t *n);
bool buckets_mp_read_time(buckets_mp_reader *r, int64_t *unix_ns);
bool buckets_mp_read_time_sec(buckets_mp_reader *r, int64_t *sec, int32_t *nsec);
/* Skips one complete value of any type (bounded nesting). */
bool buckets_mp_skip(buckets_mp_reader *r);

#endif
