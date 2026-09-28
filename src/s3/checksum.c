/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/checksum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "crypto/base64.h"

static bool is(uint32_t c, uint32_t t) { return (c & t) == t; }

static const struct {
  uint32_t type;
  const char *name;
  const char *header;
  size_t len;
} k_types[] = {
    /* BaseChecksumTypes order, which getContentChecksum scans in. */
    {BUCKETS_CKSUM_SHA256, "SHA256", "X-Amz-Checksum-Sha256", 32},
    {BUCKETS_CKSUM_SHA1, "SHA1", "X-Amz-Checksum-Sha1", 20},
    {BUCKETS_CKSUM_CRC32, "CRC32", "X-Amz-Checksum-Crc32", 4},
    {BUCKETS_CKSUM_CRC64NVME, "CRC64NVME", "X-Amz-Checksum-Crc64nvme", 8},
    {BUCKETS_CKSUM_CRC32C, "CRC32C", "X-Amz-Checksum-Crc32c", 4},
};

/* ChecksumType.Key/String/RawByteLen test in this precedence order. */
static int base_index(uint32_t c) {
  static const uint32_t order[] = {BUCKETS_CKSUM_CRC32, BUCKETS_CKSUM_CRC32C, BUCKETS_CKSUM_SHA1,
                                   BUCKETS_CKSUM_SHA256, BUCKETS_CKSUM_CRC64NVME};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(order); i++) {
    if (is(c, order[i])) {
      for (int j = 0; j < (int)BUCKETS_ARRAY_LEN(k_types); j++) {
        if (k_types[j].type == order[i]) return j;
      }
    }
  }
  return -1;
}

const char *buckets_cksum_name(uint32_t type) {
  int i = base_index(type);
  return i < 0 ? "" : k_types[i].name;
}

const char *buckets_cksum_header(uint32_t type) {
  int i = base_index(type);
  return i < 0 ? "" : k_types[i].header;
}

static bool is_set(uint32_t c) { return !is(c, BUCKETS_CKSUM_INVALID) && (c & BUCKETS_CKSUM_BASE_MASK) != 0; }

static bool can_merge(uint32_t c) {
  return is(c, BUCKETS_CKSUM_CRC64NVME) || is(c, BUCKETS_CKSUM_CRC32C) || is(c, BUCKETS_CKSUM_CRC32);
}

static bool full_object(uint32_t c) {
  return is(c, BUCKETS_CKSUM_FULL_OBJECT) || is(c, BUCKETS_CKSUM_CRC64NVME);
}

static const char *obj_type(uint32_t c) {
  if (full_object(c)) return "FULL_OBJECT";
  if (is(c, BUCKETS_CKSUM_MULTIPART)) return is_set(c) ? "COMPOSITE" : "";
  return "FULL_OBJECT";
}

/* ---- request parsing ------------------------------------------------------ */

static uint32_t type_from_name(buckets_str alg) {
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_types); i++) {
    if (buckets_str_ieq_c(alg, k_types[i].name)) return k_types[i].type;
  }
  return alg.n ? BUCKETS_CKSUM_INVALID : 0;
}

buckets_s3_error buckets_checksum_from_request(const buckets_http_request *req, buckets_checksum *out) {
  memset(out, 0, sizeof(*out));
  buckets_str ctype = buckets_http_header_get(req, "X-Amz-Checksum-Type");
  bool full = ctype.p && buckets_str_eq_c(ctype, "FULL_OBJECT");
  if (ctype.p && ctype.n && !full && !buckets_str_eq_c(ctype, "COMPOSITE")) return BUCKETS_ERR_INVALID_CHECKSUM;

  /* Trailing checksum announced via x-amz-trailer. */
  buckets_str trailer = buckets_http_header_get(req, "X-Amz-Trailer");
  if (trailer.p && trailer.n) {
    uint32_t found = 0;
    buckets_str rest = trailer, item;
    while (rest.n) {
      buckets_str_cut(rest, ',', &item, &rest);
      item = buckets_str_trim(item);
      for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_types); i++) {
        if (buckets_str_ieq_c(item, k_types[i].header)) {
          if (found) return BUCKETS_ERR_INVALID_CHECKSUM;
          found = k_types[i].type;
        }
      }
    }
    if (found) {
      if (full) {
        if (!can_merge(found)) return BUCKETS_ERR_INVALID_CHECKSUM;
        found |= BUCKETS_CKSUM_FULL_OBJECT;
      }
      out->type = found | BUCKETS_CKSUM_TRAILING;
      return BUCKETS_ERR_NONE;
    }
  }

  uint32_t t = 0;
  char value[128] = "";
  buckets_str alg = buckets_http_header_get(req, "X-Amz-Checksum-Algorithm");
  if (alg.p && alg.n) {
    t = type_from_name(alg);
    if (full) {
      if (!can_merge(t)) return BUCKETS_ERR_INVALID_CHECKSUM;
      t |= BUCKETS_CKSUM_FULL_OBJECT;
    }
    if (t == BUCKETS_CKSUM_INVALID) return BUCKETS_ERR_INVALID_CHECKSUM;
    buckets_str v = buckets_http_header_get(req, buckets_cksum_header(t));
    if (!v.p || !v.n) return BUCKETS_ERR_NONE; /* algorithm only: nothing to verify */
    snprintf(value, sizeof(value), BUCKETS_STR_FMT, BUCKETS_STR_ARG(v));
  } else {
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_types); i++) {
      buckets_str v = buckets_http_header_get(req, k_types[i].header);
      if (!v.p || !v.n) continue;
      if (t) return BUCKETS_ERR_INVALID_CHECKSUM; /* more than one checksum header */
      t = k_types[i].type;
      if (full) {
        if (!can_merge(t)) return BUCKETS_ERR_INVALID_CHECKSUM;
        t |= BUCKETS_CKSUM_FULL_OBJECT;
      }
      snprintf(value, sizeof(value), BUCKETS_STR_FMT, BUCKETS_STR_ARG(v));
    }
    if (!t) return BUCKETS_ERR_NONE;
  }
  if (!buckets_checksum_parse_value(t, value, out)) return BUCKETS_ERR_INVALID_CHECKSUM;
  return BUCKETS_ERR_NONE;
}

/* ---- storage form --------------------------------------------------------- */

static bool get_uvarint(const uint8_t **p, const uint8_t *end, uint64_t *v) {
  uint64_t x = 0;
  for (int s = 0; *p < end && s < 64; s += 7) {
    uint8_t c = *(*p)++;
    x |= (uint64_t)(c & 0x7f) << s;
    if (!(c & 0x80)) {
      *v = x;
      return true;
    }
  }
  return false;
}

void buckets_checksum_write_headers(const uint8_t *b, size_t n, int part, buckets_http_response *resp) {
  const uint8_t *p = b, *end = b + n;
  while (p < end) {
    uint64_t t;
    if (!get_uvarint(&p, end, &t)) return;
    uint32_t typ = (uint32_t)t;
    size_t len = buckets_cksum_raw_len(typ);
    if (!len || (size_t)(end - p) < len) return;
    char enc[64];
    buckets_base64_encode(p, len, enc);
    p += len;
    char value[96];
    snprintf(value, sizeof(value), "%s", enc);
    if (is(typ, BUCKETS_CKSUM_MULTIPART)) {
      uint64_t cnt;
      if (!get_uvarint(&p, end, &cnt)) return;
      if (!full_object(typ)) snprintf(value, sizeof(value), "%s-%llu", enc, (unsigned long long)cnt);
      if (part > 0) value[0] = '\0';
      if (is(typ, BUCKETS_CKSUM_INCLUDES_MULTIPART)) {
        size_t want = (size_t)cnt * len;
        if ((size_t)(end - p) < want) return;
        if (part > 0 && (uint64_t)part <= cnt) buckets_base64_encode(p + (size_t)(part - 1) * len, len, value);
        p += want;
      }
    } else if (part > 1) {
      value[0] = '\0';
    }
    if (value[0]) {
      buckets_http_resp_header(resp, buckets_cksum_header(typ), value);
      const char *ot = obj_type(typ);
      if (*ot) buckets_http_resp_header(resp, "X-Amz-Checksum-Type", ot);
    }
  }
}
