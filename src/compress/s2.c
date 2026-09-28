/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "compress/s2.h"

#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "crypto/aead.h"
#include "crypto/crc.h"

enum { TAG_LITERAL = 0, TAG_COPY1 = 1, TAG_COPY2 = 2, TAG_COPY4 = 3 };
enum {
  CHUNK_COMPRESSED = 0x00,
  CHUNK_UNCOMPRESSED = 0x01,
  CHUNK_INDEX = 0x99,
  CHUNK_PADDING = 0xfe,
  CHUNK_STREAM_ID = 0xff,
};
#define CHECKSUM_SIZE 4
#define CHUNK_HEADER 4
#define MAX_CHUNK_SIZE ((1 << 24) - 1)
#define MAX_SNAPPY_BLOCK (1 << 16)
#define INPUT_MARGIN 8
#define MIN_NON_LITERAL_BLOCK 32
#define MAX_INDEX_ENTRIES (1 << 16)
#define MIN_INDEX_DIST (1 << 20)

static inline uint32_t load32(const uint8_t *b, size_t i) {
  return (uint32_t)b[i] | (uint32_t)b[i + 1] << 8 | (uint32_t)b[i + 2] << 16 | (uint32_t)b[i + 3] << 24;
}

static inline uint64_t load64(const uint8_t *b, size_t i) { return (uint64_t)load32(b, i) | (uint64_t)load32(b, i + 4) << 32; }

static size_t put_uvarint(uint8_t *dst, uint64_t v) {
  size_t i = 0;
  while (v >= 0x80) {
    dst[i++] = (uint8_t)(v | 0x80);
    v >>= 7;
  }
  dst[i++] = (uint8_t)v;
  return i;
}

/* binary.Uvarint: bytes used, 0 when short, or (size_t)-1 on overflow. */
static size_t get_uvarint(const uint8_t *b, size_t n, uint64_t *v) {
  uint64_t x = 0;
  unsigned s = 0;
  for (size_t i = 0; i < n && i < 10; i++) {
    if (b[i] < 0x80) {
      if (i == 9 && b[i] > 1) return (size_t)-1;
      *v = x | (uint64_t)b[i] << s;
      return i + 1;
    }
    x |= (uint64_t)(b[i] & 0x7f) << s;
    s += 7;
  }
  return n >= 10 ? (size_t)-1 : 0;
}

static size_t put_varint(uint8_t *dst, int64_t v) {
  uint64_t u = (uint64_t)v << 1;
  if (v < 0) u = ~u;
  return put_uvarint(dst, u);
}

static bool get_varint(const uint8_t **b, size_t *n, int64_t *v) {
  uint64_t u;
  size_t k = get_uvarint(*b, *n, &u);
  if (k == 0 || k == (size_t)-1) return false;
  *v = (int64_t)(u >> 1);
  if (u & 1) *v = ~*v;
  *b += k;
  *n -= k;
  return true;
}

uint32_t buckets_s2_crc(const void *data, size_t n) {
  uint32_t c = buckets_crc32c(0, data, n);
  return ((c >> 15) | (c << 17)) + 0xa282ead8u;
}

/* ---- block encoding (encodeBlockGo) ---- */

static size_t literal_extra(uint64_t n) {
  if (n == 0) return 0;
  if (n < 60) return 1;
  if (n < 1 << 8) return 2;
  if (n < 1 << 16) return 3;
  if (n < 1 << 24) return 4;
  return 5;
}

size_t buckets_s2_max_encoded_len(size_t n) {
  size_t bits = 0;
  for (uint64_t v = n; v; v >>= 1) bits++;
  return n + (bits + 7) / 7 + literal_extra(n);
}

static size_t emit_literal(uint8_t *dst, const uint8_t *lit, size_t len) {
  if (!len) return 0;
  size_t i, n = len - 1;
  if (n < 60) {
    dst[0] = (uint8_t)(n << 2 | TAG_LITERAL);
    i = 1;
  } else if (n < 1 << 8) {
    dst[0] = 60 << 2 | TAG_LITERAL, dst[1] = (uint8_t)n;
    i = 2;
  } else if (n < 1 << 16) {
    dst[0] = 61 << 2 | TAG_LITERAL, dst[1] = (uint8_t)n, dst[2] = (uint8_t)(n >> 8);
    i = 3;
  } else if (n < 1 << 24) {
    dst[0] = 62 << 2 | TAG_LITERAL, dst[1] = (uint8_t)n, dst[2] = (uint8_t)(n >> 8), dst[3] = (uint8_t)(n >> 16);
    i = 4;
  } else {
    dst[0] = 63 << 2 | TAG_LITERAL, dst[1] = (uint8_t)n, dst[2] = (uint8_t)(n >> 8), dst[3] = (uint8_t)(n >> 16);
    dst[4] = (uint8_t)(n >> 24);
    i = 5;
  }
  memcpy(dst + i, lit, len);
  return i + len;
}

static size_t emit_repeat(uint8_t *dst, size_t offset, size_t length) {
  length -= 4;
  if (length <= 4) {
    dst[0] = (uint8_t)(length << 2 | TAG_COPY1), dst[1] = 0;
    return 2;
  }
  if (length < 8 && offset < 2048) {
    dst[1] = (uint8_t)offset;
    dst[0] = (uint8_t)((offset >> 8) << 5 | length << 2 | TAG_COPY1);
    return 2;
  }
  if (length < (1 << 8) + 4) {
    length -= 4;
    dst[0] = 5 << 2 | TAG_COPY1, dst[1] = 0, dst[2] = (uint8_t)length;
    return 3;
  }
  if (length < (1 << 16) + (1 << 8)) {
    length -= 1 << 8;
    dst[0] = 6 << 2 | TAG_COPY1, dst[1] = 0, dst[2] = (uint8_t)length, dst[3] = (uint8_t)(length >> 8);
    return 4;
  }
  const size_t max_repeat = (1 << 24) - 1;
  length -= 1 << 16;
  size_t left = 0;
  if (length > max_repeat) {
    left = length - max_repeat + 4;
    length = max_repeat - 4;
  }
  dst[0] = 7 << 2 | TAG_COPY1, dst[1] = 0;
  dst[2] = (uint8_t)length, dst[3] = (uint8_t)(length >> 8), dst[4] = (uint8_t)(length >> 16);
  if (left) return 5 + emit_repeat(dst + 5, offset, left);
  return 5;
}

static size_t emit_copy(uint8_t *dst, size_t offset, size_t length) {
  if (offset >= 65536) {
    size_t i = 0;
    if (length > 64) {
      dst[0] = 63 << 2 | TAG_COPY4;
      dst[1] = (uint8_t)offset, dst[2] = (uint8_t)(offset >> 8), dst[3] = (uint8_t)(offset >> 16);
      dst[4] = (uint8_t)(offset >> 24);
      length -= 64;
      if (length >= 4) return 5 + emit_repeat(dst + 5, offset, length);
      i = 5;
    }
    if (!length) return i;
    dst[i] = (uint8_t)((length - 1) << 2 | TAG_COPY4);
    dst[i + 1] = (uint8_t)offset, dst[i + 2] = (uint8_t)(offset >> 8), dst[i + 3] = (uint8_t)(offset >> 16);
    dst[i + 4] = (uint8_t)(offset >> 24);
    return i + 5;
  }
  if (length > 64) {
    size_t off = 3;
    if (offset < 2048) {
      dst[1] = (uint8_t)offset;
      dst[0] = (uint8_t)((offset >> 8) << 5 | (8 - 4) << 2 | TAG_COPY1);
      length -= 8;
      off = 2;
    } else {
      dst[0] = 59 << 2 | TAG_COPY2, dst[1] = (uint8_t)offset, dst[2] = (uint8_t)(offset >> 8);
      length -= 60;
    }
    return off + emit_repeat(dst + off, offset, length);
  }
  if (length >= 12 || offset >= 2048) {
    dst[0] = (uint8_t)((length - 1) << 2 | TAG_COPY2), dst[1] = (uint8_t)offset, dst[2] = (uint8_t)(offset >> 8);
    return 3;
  }
  dst[1] = (uint8_t)offset;
  dst[0] = (uint8_t)((offset >> 8) << 5 | (length - 4) << 2 | TAG_COPY1);
  return 2;
}

#define TABLE_BITS 14

static inline uint32_t hash6(uint64_t u) {
  const uint64_t prime6 = 227718039650203ULL;
  return (uint32_t)(((u << 16) * prime6) >> (64 - TABLE_BITS));
}

static inline size_t ctz64(uint64_t x) { return (size_t)__builtin_ctzll(x); }

size_t buckets_s2_encode_block(uint8_t *dst, const uint8_t *src, size_t len) {
  if (len < MIN_NON_LITERAL_BLOCK) return 0;
  uint32_t *table = calloc(1u << TABLE_BITS, sizeof(uint32_t));
  if (!table) abort();
  const size_t s_limit = len - INPUT_MARGIN;
  const size_t dst_limit = len - (len >> 5) - 5;
  /* encodeBlockGo64K (blocks up to 64 KiB) skips ahead faster. */
  const unsigned skip_shift = len <= 64 << 10 ? 5 : 6;
  size_t d = 0, next_emit = 0, s = 1, repeat = 1, candidate;
  uint64_t cv = load64(src, s);
  for (;;) {
    for (;;) {
      size_t next_s = s + ((s - next_emit) >> skip_shift) + 4;
      if (next_s > s_limit) goto emit_remainder;
      uint32_t h0 = hash6(cv), h1 = hash6(cv >> 8);
      candidate = table[h0];
      size_t candidate2 = table[h1];
      table[h0] = (uint32_t)s;
      table[h1] = (uint32_t)(s + 1);
      uint32_t h2 = hash6(cv >> 16);
      /* A repeat at offset checkRep (1). */
      if ((uint32_t)(cv >> 8) == load32(src, s - repeat + 1)) {
        size_t base = s + 1;
        for (size_t i = base - repeat; base > next_emit && i > 0 && src[i - 1] == src[base - 1];) i--, base--;
        if (d + (base - next_emit) > dst_limit) goto fail;
        d += emit_literal(dst + d, src + next_emit, base - next_emit);
        size_t cand = s - repeat + 4 + 1;
        s += 4 + 1;
        while (s <= s_limit) {
          uint64_t diff = load64(src, s) ^ load64(src, cand);
          if (diff) {
            s += ctz64(diff) >> 3;
            break;
          }
          s += 8, cand += 8;
        }
        if (next_emit > 0) d += emit_repeat(dst + d, repeat, s - base);
        else d += emit_copy(dst + d, repeat, s - base);
        next_emit = s;
        if (s >= s_limit) goto emit_remainder;
        cv = load64(src, s);
        continue;
      }
      if ((uint32_t)cv == load32(src, candidate)) break;
      candidate = table[h2];
      if ((uint32_t)(cv >> 8) == load32(src, candidate2)) {
        table[h2] = (uint32_t)(s + 2);
        candidate = candidate2;
        s++;
        break;
      }
      table[h2] = (uint32_t)(s + 2);
      if ((uint32_t)(cv >> 16) == load32(src, candidate)) {
        s += 2;
        break;
      }
      cv = load64(src, next_s);
      s = next_s;
    }
    while (candidate > 0 && s > next_emit && src[candidate - 1] == src[s - 1]) candidate--, s--;
    if (d + (s - next_emit) > dst_limit) goto fail;
    d += emit_literal(dst + d, src + next_emit, s - next_emit);
    for (;;) {
      size_t base = s;
      repeat = base - candidate;
      s += 4, candidate += 4;
      while (s <= len - 8) {
        uint64_t diff = load64(src, s) ^ load64(src, candidate);
        if (diff) {
          s += ctz64(diff) >> 3;
          break;
        }
        s += 8, candidate += 8;
      }
      d += emit_copy(dst + d, repeat, s - base);
      next_emit = s;
      if (s >= s_limit) goto emit_remainder;
      if (d > dst_limit) goto fail;
      uint64_t x = load64(src, s - 2);
      uint32_t m2 = hash6(x), cur = hash6(x >> 16);
      candidate = table[cur];
      table[m2] = (uint32_t)(s - 2);
      table[cur] = (uint32_t)s;
      if ((uint32_t)(x >> 16) != load32(src, candidate)) {
        cv = load64(src, s + 1);
        s++;
        break;
      }
    }
  }
emit_remainder:
  if (next_emit < len) {
    if (d + len - next_emit > dst_limit) goto fail;
    d += emit_literal(dst + d, src + next_emit, len - next_emit);
  }
  free(table);
  return d;
fail:
  free(table);
  return 0;
}

size_t buckets_s2_encode(uint8_t *dst, const uint8_t *src, size_t n) {
  size_t d = put_uvarint(dst, n);
  if (!n) return d;
  size_t k = buckets_s2_encode_block(dst + d, src, n);
  return k ? d + k : d + emit_literal(dst + d, src, n);
}

/* ---- block decoding (s2Decode) ---- */

bool buckets_s2_decoded_len(const uint8_t *src, size_t n, size_t *len, size_t *prefix) {
  uint64_t v;
  size_t k = get_uvarint(src, n, &v);
  if (k == 0 || k == (size_t)-1 || k > 5 || v > 0xffffffffu) return false;
  *len = (size_t)v;
  *prefix = k;
  return true;
}

static bool decode_body(uint8_t *dst, size_t dlen, const uint8_t *src, size_t slen) {
  size_t d = 0, s = 0, offset = 0, length;
  while (s < slen) {
    uint8_t tag = src[s];
    switch (tag & 3) {
    case TAG_LITERAL: {
      uint32_t x = tag >> 2;
      if (x < 60) {
        s++;
      } else {
        size_t extra = x - 59;
        if (s + 1 + extra > slen) return false;
        x = 0;
        for (size_t i = 0; i < extra; i++) x |= (uint32_t)src[s + 1 + i] << (8 * i);
        s += 1 + extra;
      }
      length = (size_t)x + 1;
      if (length > dlen - d || length > slen - s) return false;
      memcpy(dst + d, src + s, length);
      d += length, s += length;
      continue;
    }
    case TAG_COPY1: {
      if (s + 2 > slen) return false;
      size_t toffset = (size_t)(src[s] & 0xe0) << 3 | src[s + 1];
      length = (src[s] >> 2) & 7;
      s += 2;
      if (toffset == 0) {
        /* A repeat of the last offset. */
        if (length == 5) {
          if (s + 1 > slen) return false;
          length = (size_t)src[s] + 4;
          s += 1;
        } else if (length == 6) {
          if (s + 2 > slen) return false;
          length = ((size_t)src[s] | (size_t)src[s + 1] << 8) + (1 << 8);
          s += 2;
        } else if (length == 7) {
          if (s + 3 > slen) return false;
          length = ((size_t)src[s] | (size_t)src[s + 1] << 8 | (size_t)src[s + 2] << 16) + (1 << 16);
          s += 3;
        }
      } else {
        offset = toffset;
      }
      length += 4;
      break;
    }
    case TAG_COPY2:
      if (s + 3 > slen) return false;
      offset = (size_t)src[s + 1] | (size_t)src[s + 2] << 8;
      length = 1 + (size_t)(tag >> 2);
      s += 3;
      break;
    default: /* TAG_COPY4 */
      if (s + 5 > slen) return false;
      offset = load32(src, s + 1);
      length = 1 + (size_t)(tag >> 2);
      s += 5;
      break;
    }
    if (offset == 0 || d < offset || length > dlen - d) return false;
    if (offset >= length) {
      memcpy(dst + d, dst + d - offset, length);
    } else {
      for (size_t i = 0; i < length; i++) dst[d + i] = dst[d - offset + i];
    }
    d += length;
  }
  return d == dlen;
}

long buckets_s2_decode(uint8_t *dst, size_t cap, const uint8_t *src, size_t n) {
  size_t len, prefix;
  if (!buckets_s2_decoded_len(src, n, &len, &prefix) || len > cap) return -1;
  if (!decode_body(dst, len, src + prefix, n - prefix)) return -1;
  return (long)len;
}

/* ---- index ---- */

void buckets_s2_index_free(buckets_s2_index *x) {
  free(x->comp_off);
  free(x->uncomp_off);
  memset(x, 0, sizeof(*x));
}

static void index_reset(buckets_s2_index *x, int64_t max_block) {
  x->est_block_uncomp = max_block;
  x->total_compressed = x->total_uncompressed = -1;
  x->n = 0;
}

static void index_add(buckets_s2_index *x, int64_t comp, int64_t uncomp) {
  if (x->n) {
    size_t last = x->n - 1;
    if (x->uncomp_off[last] == uncomp) {
      x->comp_off[last] = comp;
      return;
    }
    if (x->uncomp_off[last] + MIN_INDEX_DIST > uncomp) return;
  }
  if (x->n == x->cap) {
    x->cap = x->cap ? x->cap * 2 : 64;
    x->comp_off = buckets_xrealloc(x->comp_off, x->cap * sizeof(int64_t));
    x->uncomp_off = buckets_xrealloc(x->uncomp_off, x->cap * sizeof(int64_t));
  }
  x->comp_off[x->n] = comp;
  x->uncomp_off[x->n] = uncomp;
  x->n++;
}

/* Index.reduce: stay below maxIndexEntries. */
static void index_reduce(buckets_s2_index *x) {
  if (x->n < MAX_INDEX_ENTRIES && x->est_block_uncomp >= MIN_INDEX_DIST) return;
  size_t remove_n = (x->n + 1) / MAX_INDEX_ENTRIES, j = 0;
  while (x->est_block_uncomp * (int64_t)(remove_n + 1) < MIN_INDEX_DIST && x->n / (remove_n + 1) > 1000) remove_n++;
  for (size_t i = 0; i < x->n; i++) {
    x->comp_off[j] = x->comp_off[i];
    x->uncomp_off[j] = x->uncomp_off[i];
    j++;
    i += remove_n;
  }
  x->n = j;
  x->est_block_uncomp += x->est_block_uncomp * (int64_t)remove_n;
}

/* Index.appendTo without the headers RemoveIndexHeaders strips. */
static void index_append(buckets_s2_index *x, int64_t comp_total, int64_t uncomp_total, buckets_buf *out) {
  index_reduce(x);
  uint8_t tmp[10];
  buckets_buf_append(out, tmp, put_varint(tmp, uncomp_total));
  buckets_buf_append(out, tmp, put_varint(tmp, comp_total));
  buckets_buf_append(out, tmp, put_varint(tmp, x->est_block_uncomp));
  buckets_buf_append(out, tmp, put_varint(tmp, (int64_t)x->n));
  uint8_t has_uncomp = 0;
  for (size_t i = 0; i < x->n && !has_uncomp; i++) {
    if (i == 0) has_uncomp = x->uncomp_off[0] != 0;
    else has_uncomp = x->uncomp_off[i] != x->uncomp_off[i - 1] + x->est_block_uncomp;
  }
  buckets_buf_append(out, &has_uncomp, 1);
  if (has_uncomp) {
    for (size_t i = 0; i < x->n; i++) {
      int64_t u = x->uncomp_off[i];
      if (i) u -= x->uncomp_off[i - 1] + x->est_block_uncomp;
      buckets_buf_append(out, tmp, put_varint(tmp, u));
    }
  }
  int64_t predict = x->est_block_uncomp / 2;
  for (size_t i = 0; i < x->n; i++) {
    int64_t c = x->comp_off[i];
    if (i) {
      c -= x->comp_off[i - 1] + predict;
      predict += c / 2;
    }
    buckets_buf_append(out, tmp, put_varint(tmp, c));
  }
}

bool buckets_s2_index_load(buckets_s2_index *x, const uint8_t *b, size_t n) {
  index_reset(x, 0);
  int64_t v, entries;
  if (!get_varint(&b, &n, &v) || v < 0) return false;
  x->total_uncompressed = v;
  if (!get_varint(&b, &n, &x->total_compressed)) return false;
  if (!get_varint(&b, &n, &v) || v < 0) return false;
  x->est_block_uncomp = v;
  if (!get_varint(&b, &n, &entries) || entries < 0 || entries > MAX_INDEX_ENTRIES) return false;
  if ((size_t)entries > x->cap) {
    x->cap = (size_t)entries;
    x->comp_off = buckets_xrealloc(x->comp_off, x->cap * sizeof(int64_t));
    x->uncomp_off = buckets_xrealloc(x->uncomp_off, x->cap * sizeof(int64_t));
  }
  x->n = (size_t)entries;
  if (n < 1) return false;
  uint8_t has_uncomp = b[0];
  b++, n--;
  if ((has_uncomp & 1) != has_uncomp) return false;
  for (size_t i = 0; i < x->n; i++) {
    int64_t u = 0;
    if (has_uncomp && !get_varint(&b, &n, &u)) return false;
    if (i) {
      int64_t prev = x->uncomp_off[i - 1];
      u += prev + x->est_block_uncomp;
      if (u <= prev) return false;
    }
    if (u < 0) return false;
    x->uncomp_off[i] = u;
  }
  int64_t predict = x->est_block_uncomp / 2;
  for (size_t i = 0; i < x->n; i++) {
    int64_t c;
    if (!get_varint(&b, &n, &c)) return false;
    if (i) {
      int64_t next = predict + c / 2, prev = x->comp_off[i - 1];
      c += prev + predict;
      if (c <= prev) return false;
      predict = next;
    }
    if (c < 0) return false;
    x->comp_off[i] = c;
  }
  return true;
}

bool buckets_s2_index_find(const buckets_s2_index *x, int64_t offset, int64_t *comp_off, int64_t *uncomp_off) {
  *comp_off = *uncomp_off = 0;
  if (x->total_uncompressed < 0) return false;
  if (offset < 0) {
    offset += x->total_uncompressed;
    if (offset < 0) return false;
  }
  if (offset > x->total_uncompressed) return false;
  /* The last entry at or before offset (sort.Search for the first after it). */
  size_t lo = 0, hi = x->n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    if (x->uncomp_off[mid] > offset) hi = mid;
    else lo = mid + 1;
  }
  if (lo == 0) {
    if (x->n > 200 && x->n) lo = 1; /* Find clamps its binary search to the first entry */
    else return true;
  }
  *comp_off = x->comp_off[lo - 1];
  *uncomp_off = x->uncomp_off[lo - 1];
  return true;
}

/* ---- stream writer ---- */

void buckets_s2_writer_init(buckets_s2_writer *w, buckets_s2_read_fn rd, void *rd_ud, int64_t size, size_t pad) {
  memset(w, 0, sizeof(*w));
  w->rd = rd;
  w->rd_ud = rd_ud;
  w->remaining = size;
  w->pad = pad;
  w->in = buckets_xmalloc(BUCKETS_S2_BLOCK_SIZE);
  w->out = buckets_xmalloc(CHUNK_HEADER + CHECKSUM_SIZE + buckets_s2_max_encoded_len(BUCKETS_S2_BLOCK_SIZE));
  index_reset(&w->idx, BUCKETS_S2_BLOCK_SIZE);
  buckets_random(&w->rng, sizeof(w->rng));
  w->rng |= 1;
}

void buckets_s2_writer_free(buckets_s2_writer *w) {
  free(w->in);
  free(w->out);
  w->in = w->out = NULL;
  buckets_s2_index_free(&w->idx);
}

/* Fills in with up to one block of plaintext; 0 at the end, -1 on failure. */
static long fill_block(buckets_s2_writer *w) {
  if (w->remaining == 0 && !w->probed) {
    /* The source must end here (and chunked sources read their trailers). */
    uint8_t one;
    w->probed = true;
    if (w->rd(w->rd_ud, &one, 1) != 0) return -1;
  }
  size_t want = BUCKETS_S2_BLOCK_SIZE, got = 0;
  if (w->remaining >= 0 && (int64_t)want > w->remaining) want = (size_t)w->remaining;
  while (got < want) {
    long r = w->rd(w->rd_ud, w->in + got, want - got);
    if (r < 0) return -1;
    if (r == 0) {
      if (w->remaining >= 0) return -1; /* short body */
      break;
    }
    got += (size_t)r;
  }
  if (w->remaining >= 0) w->remaining -= (int64_t)got;
  return (long)got;
}

static uint64_t xorshift(uint64_t *s) {
  uint64_t x = *s;
  x ^= x << 13, x ^= x >> 7, x ^= x << 17;
  return *s = x;
}

/* The padding chunk that makes written a multiple of pad (calcSkippableFrame). */
static void padding_chunk(buckets_s2_writer *w) {
  w->out_len = w->out_pos = 0;
  if (w->pad <= 1 || w->written == 0) return;
  int64_t left = w->written % (int64_t)w->pad;
  if (!left) return;
  int64_t add = (int64_t)w->pad - left;
  while (add < CHUNK_HEADER) add += (int64_t)w->pad;
  size_t f = (size_t)add - CHUNK_HEADER;
  w->out[0] = CHUNK_PADDING;
  w->out[1] = (uint8_t)f, w->out[2] = (uint8_t)(f >> 8), w->out[3] = (uint8_t)(f >> 16);
  for (size_t i = 0; i < f; i++) w->out[CHUNK_HEADER + i] = (uint8_t)xorshift(&w->rng);
  w->out_len = (size_t)add;
  w->written += add;
}

/* Produces the next piece of output into out; false at the end. */
static bool next_output(buckets_s2_writer *w) {
  if (!w->header_done && !w->eof) {
    long n = fill_block(w);
    if (n < 0) {
      w->failed = true;
      return false;
    }
    if (n == 0) {
      w->eof = true;
    } else {
      w->header_done = true;
      memcpy(w->out, BUCKETS_S2_MAGIC, BUCKETS_S2_MAGIC_LEN);
      w->written = BUCKETS_S2_MAGIC_LEN;
      w->out_len = BUCKETS_S2_MAGIC_LEN;
      w->out_pos = 0;
      w->pending = (size_t)n;
      w->has_pending = true;
      return true;
    }
  }
  if (w->eof) {
    if (w->closed) return false;
    w->closed = true;
    padding_chunk(w);
    return w->out_len > 0;
  }
  long n;
  if (w->has_pending) {
    n = (long)w->pending;
    w->has_pending = false;
  } else {
    n = fill_block(w);
  }
  if (n < 0) {
    w->failed = true;
    return false;
  }
  if (n == 0) {
    w->eof = true;
    return next_output(w);
  }
  size_t len = (size_t)n;
  uint32_t crc = buckets_s2_crc(w->in, len);
  size_t hdr = CHUNK_HEADER + CHECKSUM_SIZE;
  size_t v = put_uvarint(w->out + hdr, len);
  size_t k = buckets_s2_encode_block(w->out + hdr + v, w->in, len);
  uint8_t type;
  size_t chunk_len;
  if (k) {
    type = CHUNK_COMPRESSED;
    chunk_len = CHECKSUM_SIZE + v + k;
  } else {
    type = CHUNK_UNCOMPRESSED;
    chunk_len = CHECKSUM_SIZE + len;
    memcpy(w->out + hdr, w->in, len);
  }
  w->out[0] = type;
  w->out[1] = (uint8_t)chunk_len, w->out[2] = (uint8_t)(chunk_len >> 8), w->out[3] = (uint8_t)(chunk_len >> 16);
  w->out[4] = (uint8_t)crc, w->out[5] = (uint8_t)(crc >> 8), w->out[6] = (uint8_t)(crc >> 16), w->out[7] = (uint8_t)(crc >> 24);
  index_add(&w->idx, w->written, w->uncomp);
  w->out_len = CHUNK_HEADER + chunk_len;
  w->out_pos = 0;
  w->written += (int64_t)w->out_len;
  w->uncomp += (int64_t)len;
  return true;
}

long buckets_s2_writer_read(void *ud, void *buf, size_t n) {
  buckets_s2_writer *w = ud;
  size_t done = 0;
  while (done < n) {
    if (w->out_pos == w->out_len) {
      if (w->failed) return -1;
      if (!next_output(w)) {
        if (w->failed) return done ? (long)done : -1;
        break;
      }
    }
    size_t k = w->out_len - w->out_pos;
    if (k > n - done) k = n - done;
    memcpy((uint8_t *)buf + done, w->out + w->out_pos, k);
    w->out_pos += k;
    done += k;
  }
  return (long)done;
}

bool buckets_s2_writer_index(buckets_s2_writer *w, int64_t min_size, buckets_buf *out) {
  if (!w->closed || w->failed || w->uncomp <= min_size) return false;
  int64_t comp = w->pad <= 1 ? w->written : -1;
  index_append(&w->idx, comp, w->uncomp, out);
  return true;
}

/* ---- stream reader ---- */

struct buckets_s2_reader {
  buckets_s2_read_fn rd;
  void *rd_ud;
  bool read_header, snappy, failed;
  uint8_t *buf; /* one chunk body */
  size_t buf_cap;
  uint8_t *decoded;
  size_t i, j;
};

buckets_s2_reader *buckets_s2_reader_new(buckets_s2_read_fn rd, void *rd_ud, bool ignore_stream_id) {
  buckets_s2_reader *r = buckets_xcalloc(1, sizeof(*r));
  r->rd = rd;
  r->rd_ud = rd_ud;
  r->read_header = ignore_stream_id;
  r->buf_cap = CHECKSUM_SIZE + buckets_s2_max_encoded_len(BUCKETS_S2_MAX_BLOCK_SIZE);
  r->buf = buckets_xmalloc(r->buf_cap);
  r->decoded = buckets_xmalloc(BUCKETS_S2_MAX_BLOCK_SIZE);
  return r;
}

void buckets_s2_reader_free(buckets_s2_reader *r) {
  if (!r) return;
  free(r->buf);
  free(r->decoded);
  free(r);
}

/* 1 read, 0 clean EOF (allowed only when allow_eof and nothing was read), -1 error. */
static int read_full(buckets_s2_reader *r, uint8_t *p, size_t n, bool allow_eof) {
  size_t got = 0;
  while (got < n) {
    long k = r->rd(r->rd_ud, p + got, n - got);
    if (k < 0) return -1;
    if (k == 0) return got == 0 && allow_eof ? 0 : -1;
    got += (size_t)k;
  }
  return 1;
}

static bool discard(buckets_s2_reader *r, size_t n) {
  while (n) {
    size_t k = n < r->buf_cap ? n : r->buf_cap;
    if (read_full(r, r->buf, k, false) != 1) return false;
    n -= k;
  }
  return true;
}

/* Loads the next data chunk into decoded: 1, 0 at the end, -1 on failure. */
static int next_chunk(buckets_s2_reader *r) {
  for (;;) {
    uint8_t h[CHUNK_HEADER];
    int st = read_full(r, h, CHUNK_HEADER, true);
    if (st <= 0) return st;
    uint8_t type = h[0];
    if (!r->read_header) {
      if (type != CHUNK_STREAM_ID) return -1;
      r->read_header = true;
    }
    size_t len = (size_t)h[1] | (size_t)h[2] << 8 | (size_t)h[3] << 16;
    if (type == CHUNK_COMPRESSED || type == CHUNK_UNCOMPRESSED) {
      if (len < CHECKSUM_SIZE || len > r->buf_cap) return -1;
      size_t n;
      uint8_t sum[CHECKSUM_SIZE];
      if (type == CHUNK_COMPRESSED) {
        if (read_full(r, r->buf, len, false) != 1) return -1;
        memcpy(sum, r->buf, CHECKSUM_SIZE);
        size_t dlen, prefix;
        if (!buckets_s2_decoded_len(r->buf + CHECKSUM_SIZE, len - CHECKSUM_SIZE, &dlen, &prefix)) return -1;
        if ((r->snappy && dlen > MAX_SNAPPY_BLOCK) || dlen > BUCKETS_S2_MAX_BLOCK_SIZE) return -1;
        long d = buckets_s2_decode(r->decoded, BUCKETS_S2_MAX_BLOCK_SIZE, r->buf + CHECKSUM_SIZE, len - CHECKSUM_SIZE);
        if (d < 0) return -1;
        n = (size_t)d;
      } else {
        n = len - CHECKSUM_SIZE;
        if ((r->snappy && n > MAX_SNAPPY_BLOCK) || n > BUCKETS_S2_MAX_BLOCK_SIZE) return -1;
        if (read_full(r, sum, CHECKSUM_SIZE, false) != 1 || read_full(r, r->decoded, n, false) != 1) return -1;
      }
      uint32_t want = load32(sum, 0);
      if (buckets_s2_crc(r->decoded, n) != want) return -1;
      r->i = 0, r->j = n;
      if (n) return 1;
      continue;
    }
    if (type == CHUNK_STREAM_ID) {
      if (len != 6 || read_full(r, r->buf, 6, false) != 1) return -1;
      if (memcmp(r->buf, "S2sTwO", 6) == 0) r->snappy = false;
      else if (memcmp(r->buf, "sNaPpY", 6) == 0) r->snappy = true;
      else return -1;
      continue;
    }
    if (type <= 0x7f) return -1; /* reserved unskippable */
    if (!discard(r, len)) return -1; /* padding, index and other skippable chunks */
  }
}

long buckets_s2_reader_read(void *ud, void *buf, size_t n) {
  buckets_s2_reader *r = ud;
  size_t done = 0;
  while (done < n) {
    if (r->i == r->j) {
      if (r->failed) return done ? (long)done : -1;
      int st = next_chunk(r);
      if (st < 0) {
        r->failed = true;
        return done ? (long)done : -1;
      }
      if (st == 0) break;
    }
    size_t k = r->j - r->i;
    if (k > n - done) k = n - done;
    memcpy((uint8_t *)buf + done, r->decoded + r->i, k);
    r->i += k;
    done += k;
  }
  return (long)done;
}

bool buckets_s2_reader_skip(buckets_s2_reader *r, int64_t n) {
  while (n > 0) {
    if (r->i == r->j) {
      if (r->failed || next_chunk(r) != 1) {
        r->failed = true;
        return false;
      }
    }
    size_t k = r->j - r->i;
    if ((int64_t)k > n) k = (size_t)n;
    r->i += k;
    n -= (int64_t)k;
  }
  return true;
}
