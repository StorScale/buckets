/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/msgpack.h"

#include <string.h>

/* ---- writer -------------------------------------------------------------- */

static void put_be(buckets_buf *b, uint8_t marker, uint64_t v, int bytes) {
  uint8_t tmp[9];
  tmp[0] = marker;
  for (int i = 0; i < bytes; i++) tmp[1 + i] = (uint8_t)(v >> (8 * (bytes - 1 - i)));
  buckets_buf_append(b, tmp, (size_t)bytes + 1);
}

void buckets_mp_nil(buckets_buf *b) { buckets_buf_append_char(b, (char)0xc0); }

void buckets_mp_bool(buckets_buf *b, bool v) { buckets_buf_append_char(b, (char)(v ? 0xc3 : 0xc2)); }

void buckets_mp_uint(buckets_buf *b, uint64_t v) {
  if (v <= 0x7f) {
    buckets_buf_append_char(b, (char)v);
  } else if (v <= 0xff) {
    put_be(b, 0xcc, v, 1);
  } else if (v <= 0xffff) {
    put_be(b, 0xcd, v, 2);
  } else if (v <= 0xffffffffull) {
    put_be(b, 0xce, v, 4);
  } else {
    put_be(b, 0xcf, v, 8);
  }
}

void buckets_mp_int(buckets_buf *b, int64_t v) {
  /* msgp.AppendInt64: non-negative values use *signed* markers past fixint. */
  if (v >= 0) {
    if (v <= 127) {
      buckets_buf_append_char(b, (char)v);
    } else if (v <= 32767) {
      put_be(b, 0xd1, (uint64_t)v, 2);
    } else if (v <= 2147483647LL) {
      put_be(b, 0xd2, (uint64_t)v, 4);
    } else {
      put_be(b, 0xd3, (uint64_t)v, 8);
    }
    return;
  }
  if (v >= -32) {
    buckets_buf_append_char(b, (char)(int8_t)v); /* negative fixint */
  } else if (v >= -128) {
    put_be(b, 0xd0, (uint64_t)v, 1);
  } else if (v >= -32768) {
    put_be(b, 0xd1, (uint64_t)v, 2);
  } else if (v >= -2147483648LL) {
    put_be(b, 0xd2, (uint64_t)v, 4);
  } else {
    put_be(b, 0xd3, (uint64_t)v, 8);
  }
}

void buckets_mp_str(buckets_buf *b, const char *s, size_t n) {
  if (n <= 31) {
    buckets_buf_append_char(b, (char)(0xa0 | n));
  } else if (n <= 0xff) {
    put_be(b, 0xd9, n, 1);
  } else if (n <= 0xffff) {
    put_be(b, 0xda, n, 2);
  } else {
    put_be(b, 0xdb, n, 4);
  }
  buckets_buf_append(b, s, n);
}

void buckets_mp_cstr(buckets_buf *b, const char *s) { buckets_mp_str(b, s, strlen(s)); }

void buckets_mp_bin(buckets_buf *b, const void *p, size_t n) {
  if (n <= 0xff) {
    put_be(b, 0xc4, n, 1);
  } else if (n <= 0xffff) {
    put_be(b, 0xc5, n, 2);
  } else {
    put_be(b, 0xc6, n, 4);
  }
  buckets_buf_append(b, p, n);
}

void buckets_mp_array(buckets_buf *b, uint32_t n) {
  if (n <= 15) {
    buckets_buf_append_char(b, (char)(0x90 | n));
  } else if (n <= 0xffff) {
    put_be(b, 0xdc, n, 2);
  } else {
    put_be(b, 0xdd, n, 4);
  }
}

void buckets_mp_map(buckets_buf *b, uint32_t n) {
  if (n <= 15) {
    buckets_buf_append_char(b, (char)(0x80 | n));
  } else if (n <= 0xffff) {
    put_be(b, 0xde, n, 2);
  } else {
    put_be(b, 0xdf, n, 4);
  }
}

/* ---- reader -------------------------------------------------------------- */

static bool need(buckets_mp_reader *r, size_t n) {
  if (r->err || (size_t)(r->end - r->p) < n) {
    r->err = true;
    return false;
  }
  return true;
}

static uint64_t get_be(const uint8_t *p, int bytes) {
  uint64_t v = 0;
  for (int i = 0; i < bytes; i++) v = v << 8 | p[i];
  return v;
}

buckets_mp_type buckets_mp_peek(const buckets_mp_reader *r) {
  if (r->err || r->p >= r->end) return BUCKETS_MP_INVALID;
  uint8_t c = *r->p;
  if (c <= 0x7f || c >= 0xe0) return BUCKETS_MP_INT;
  if ((c & 0xf0) == 0x80) return BUCKETS_MP_MAP;
  if ((c & 0xf0) == 0x90) return BUCKETS_MP_ARRAY;
  if ((c & 0xe0) == 0xa0) return BUCKETS_MP_STR;
  switch (c) {
    case 0xc0: return BUCKETS_MP_NIL;
    case 0xc2: case 0xc3: return BUCKETS_MP_BOOL;
    case 0xc4: case 0xc5: case 0xc6: return BUCKETS_MP_BIN;
    case 0xc7: case 0xc8: case 0xc9: case 0xd4: case 0xd5: case 0xd6: case 0xd7: case 0xd8: return BUCKETS_MP_EXT;
    case 0xca: case 0xcb: return BUCKETS_MP_FLOAT;
    case 0xcc: case 0xcd: case 0xce: case 0xcf: case 0xd0: case 0xd1: case 0xd2: case 0xd3: return BUCKETS_MP_INT;
    case 0xd9: case 0xda: case 0xdb: return BUCKETS_MP_STR;
    case 0xdc: case 0xdd: return BUCKETS_MP_ARRAY;
    case 0xde: case 0xdf: return BUCKETS_MP_MAP;
    default: return BUCKETS_MP_INVALID;
  }
}

bool buckets_mp_read_nil(buckets_mp_reader *r) {
  if (r->err || r->p >= r->end || *r->p != 0xc0) return false;
  r->p++;
  return true;
}

bool buckets_mp_read_bool(buckets_mp_reader *r, bool *v) {
  if (!need(r, 1)) return false;
  if (*r->p != 0xc2 && *r->p != 0xc3) {
    r->err = true;
    return false;
  }
  *v = *r->p++ == 0xc3;
  return true;
}

/* Decodes any integer into sign + magnitude. */
static bool read_integer(buckets_mp_reader *r, bool *neg, uint64_t *mag) {
  if (!need(r, 1)) return false;
  uint8_t c = *r->p;
  if (c <= 0x7f) {
    r->p++;
    *neg = false;
    *mag = c;
    return true;
  }
  if (c >= 0xe0) {
    r->p++;
    *neg = true;
    *mag = (uint64_t)(-(int64_t)(int8_t)c);
    return true;
  }
  int bytes;
  bool is_signed;
  switch (c) {
    case 0xcc: bytes = 1; is_signed = false; break;
    case 0xcd: bytes = 2; is_signed = false; break;
    case 0xce: bytes = 4; is_signed = false; break;
    case 0xcf: bytes = 8; is_signed = false; break;
    case 0xd0: bytes = 1; is_signed = true; break;
    case 0xd1: bytes = 2; is_signed = true; break;
    case 0xd2: bytes = 4; is_signed = true; break;
    case 0xd3: bytes = 8; is_signed = true; break;
    default: r->err = true; return false;
  }
  if (!need(r, 1 + (size_t)bytes)) return false;
  uint64_t raw = get_be(r->p + 1, bytes);
  r->p += 1 + bytes;
  if (!is_signed) {
    *neg = false;
    *mag = raw;
    return true;
  }
  int64_t sv;
  switch (bytes) {
    case 1: sv = (int8_t)raw; break;
    case 2: sv = (int16_t)raw; break;
    case 4: sv = (int32_t)raw; break;
    default: sv = (int64_t)raw; break;
  }
  *neg = sv < 0;
  *mag = sv < 0 ? (uint64_t)0 - (uint64_t)sv : (uint64_t)sv;
  return true;
}

bool buckets_mp_read_int(buckets_mp_reader *r, int64_t *v) {
  bool neg;
  uint64_t mag;
  if (!read_integer(r, &neg, &mag)) return false;
  if (!neg && mag > (uint64_t)INT64_MAX) {
    r->err = true;
    return false;
  }
  if (neg && mag > (uint64_t)INT64_MAX + 1) {
    r->err = true;
    return false;
  }
  *v = neg ? (int64_t)((uint64_t)0 - mag) : (int64_t)mag;
  return true;
}

bool buckets_mp_read_uint(buckets_mp_reader *r, uint64_t *v) {
  bool neg;
  uint64_t mag;
  if (!read_integer(r, &neg, &mag)) return false;
  if (neg && mag != 0) {
    r->err = true;
    return false;
  }
  *v = mag;
  return true;
}

static bool read_len_prefixed(buckets_mp_reader *r, buckets_str *out) {
  if (!need(r, 1)) return false;
  uint8_t c = *r->p;
  size_t hdr, len;
  if ((c & 0xe0) == 0xa0) {
    hdr = 1;
    len = c & 0x1f;
  } else {
    int bytes;
    switch (c) {
      case 0xc4: case 0xd9: bytes = 1; break;
      case 0xc5: case 0xda: bytes = 2; break;
      case 0xc6: case 0xdb: bytes = 4; break;
      default: r->err = true; return false;
    }
    if (!need(r, 1 + (size_t)bytes)) return false;
    hdr = 1 + (size_t)bytes;
    len = (size_t)get_be(r->p + 1, bytes);
  }
  if (!need(r, hdr) || (size_t)(r->end - r->p) - hdr < len) {
    r->err = true;
    return false;
  }
  out->p = (const char *)r->p + hdr;
  out->n = len;
  r->p += hdr + len;
  return true;
}

bool buckets_mp_read_str(buckets_mp_reader *r, buckets_str *out) { return read_len_prefixed(r, out); }

bool buckets_mp_read_bin(buckets_mp_reader *r, buckets_str *out) { return read_len_prefixed(r, out); }

static bool read_container(buckets_mp_reader *r, uint32_t *n, uint8_t fixmask, uint8_t m16, uint8_t m32) {
  if (!need(r, 1)) return false;
  uint8_t c = *r->p;
  if ((c & 0xf0) == fixmask) {
    *n = c & 0x0f;
    r->p++;
    return true;
  }
  int bytes = c == m16 ? 2 : c == m32 ? 4 : 0;
  if (!bytes || !need(r, 1 + (size_t)bytes)) {
    r->err = true;
    return false;
  }
  *n = (uint32_t)get_be(r->p + 1, bytes);
  r->p += 1 + bytes;
  return true;
}

bool buckets_mp_read_array(buckets_mp_reader *r, uint32_t *n) { return read_container(r, n, 0x90, 0xdc, 0xdd); }

bool buckets_mp_read_map(buckets_mp_reader *r, uint32_t *n) { return read_container(r, n, 0x80, 0xde, 0xdf); }

static bool skip_depth(buckets_mp_reader *r, int depth) {
  if (depth > 64) {
    r->err = true;
    return false;
  }
  buckets_str s;
  uint32_t n;
  bool bv;
  switch (buckets_mp_peek(r)) {
    case BUCKETS_MP_NIL: r->p++; return true;
    case BUCKETS_MP_BOOL: return buckets_mp_read_bool(r, &bv);
    case BUCKETS_MP_INT: {
      bool neg;
      uint64_t mag;
      return read_integer(r, &neg, &mag);
    }
    case BUCKETS_MP_FLOAT: {
      size_t sz = *r->p == 0xca ? 5 : 9;
      if (!need(r, sz)) return false;
      r->p += sz;
      return true;
    }
    case BUCKETS_MP_STR:
    case BUCKETS_MP_BIN: return read_len_prefixed(r, &s);
    case BUCKETS_MP_ARRAY:
      if (!buckets_mp_read_array(r, &n)) return false;
      for (uint32_t i = 0; i < n; i++) {
        if (!skip_depth(r, depth + 1)) return false;
      }
      return true;
    case BUCKETS_MP_MAP:
      if (!buckets_mp_read_map(r, &n)) return false;
      for (uint32_t i = 0; i < n; i++) {
        if (!skip_depth(r, depth + 1) || !skip_depth(r, depth + 1)) return false;
      }
      return true;
    case BUCKETS_MP_EXT: {
      uint8_t c = *r->p;
      size_t hdr, len;
      switch (c) {
        case 0xd4: hdr = 2; len = 1; break;
        case 0xd5: hdr = 2; len = 2; break;
        case 0xd6: hdr = 2; len = 4; break;
        case 0xd7: hdr = 2; len = 8; break;
        case 0xd8: hdr = 2; len = 16; break;
        default: {
          int bytes = c == 0xc7 ? 1 : c == 0xc8 ? 2 : 4;
          if (!need(r, 2 + (size_t)bytes)) return false;
          len = (size_t)get_be(r->p + 1, bytes);
          hdr = 2 + (size_t)bytes;
        }
      }
      if (!need(r, hdr) || (size_t)(r->end - r->p) - hdr < len) {
        r->err = true;
        return false;
      }
      r->p += hdr + len;
      return true;
    }
    default: r->err = true; return false;
  }
}

bool buckets_mp_skip(buckets_mp_reader *r) { return skip_depth(r, 0); }
