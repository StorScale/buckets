/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "storage/xlmeta.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/msgpack.h"
#include "crypto/xxhash.h"

#define XL_HEADER_VERSION 3
#define XL_META_VERSION 3
#define XL_MAJOR 1
#define XL_MINOR 3

static const uint8_t k_zero_id[16];

/* ---- helpers ------------------------------------------------------------- */

void buckets_xl_version_id_string(const uint8_t id[16], char *out) {
  if (memcmp(id, k_zero_id, 16) == 0) {
    strcpy(out, "null");
    return;
  }
  snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2],
           id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
}

static int hexv(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool buckets_xl_version_id_parse(const char *s, uint8_t id[16]) {
  if (!s || !*s || strcmp(s, "null") == 0) {
    memset(id, 0, 16);
    return true;
  }
  if (strlen(s) != 36) return false;
  int o = 0;
  for (int i = 0; i < 36;) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (s[i++] != '-') return false;
      continue;
    }
    int hi = hexv(s[i]), lo = hexv(s[i + 1]);
    if (hi < 0 || lo < 0) return false;
    id[o++] = (uint8_t)(hi << 4 | lo);
    i += 2;
  }
  return true;
}

void buckets_xl_kv_set(buckets_xl_kv **kvs, size_t *n, const char *key, const void *value, size_t len) {
  for (size_t i = 0; i < *n; i++) {
    if (strcmp((*kvs)[i].key, key) == 0) {
      free((*kvs)[i].value);
      (*kvs)[i].value = (uint8_t *)buckets_xstrndup(value, len);
      (*kvs)[i].value_len = len;
      return;
    }
  }
  *kvs = buckets_xrealloc(*kvs, (*n + 1) * sizeof(buckets_xl_kv));
  (*kvs)[*n] = (buckets_xl_kv){buckets_xstrdup(key), (uint8_t *)buckets_xstrndup(value, len), len};
  (*n)++;
}

const buckets_xl_kv *buckets_xl_kv_get(const buckets_xl_kv *kvs, size_t n, const char *key) {
  for (size_t i = 0; i < n; i++) {
    if (strcmp(kvs[i].key, key) == 0) return &kvs[i];
  }
  return NULL;
}

static void kv_free(buckets_xl_kv *kvs, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(kvs[i].key);
    free(kvs[i].value);
  }
  free(kvs);
}

void buckets_xl_part_add(buckets_xl_object *o, int number, int64_t size, int64_t actual_size, const char *etag) {
  o->parts = buckets_xrealloc(o->parts, (o->nparts + 1) * sizeof(buckets_xl_part));
  o->parts[o->nparts++] = (buckets_xl_part){number, size, actual_size, etag && *etag ? buckets_xstrdup(etag) : NULL};
}

void buckets_xl_object_free(buckets_xl_object *o) {
  for (size_t i = 0; i < o->nparts; i++) free(o->parts[i].etag);
  free(o->parts);
  kv_free(o->meta_sys, o->nmeta_sys);
  kv_free(o->meta_user, o->nmeta_user);
  memset(o, 0, sizeof(*o));
}

/* ---- version ordering (xlMetaV2VersionHeader.sortsBefore) ---------------- */

static bool sorts_before(const buckets_xl_header *x, const buckets_xl_header *o) {
  if (x->mod_time != o->mod_time) return x->mod_time > o->mod_time;
  if (x->type != o->type) return x->type < o->type;
  int c = memcmp(x->signature, o->signature, 4);
  if (c) return c > 0;
  c = memcmp(x->version_id, o->version_id, 16);
  if (c) return c > 0;
  if (x->flags != o->flags) return x->flags > o->flags;
  return false;
}

static void sort_versions(buckets_xlmeta *x) {
  for (size_t i = 1; i < x->n; i++) { /* insertion sort: n is small and usually sorted */
    buckets_xl_version v = x->versions[i];
    size_t j = i;
    while (j > 0 && sorts_before(&v.hdr, &x->versions[j - 1].hdr)) {
      x->versions[j] = x->versions[j - 1];
      j--;
    }
    x->versions[j] = v;
  }
}

/* ---- container parse / serialize ----------------------------------------- */

static bool parse_header(buckets_str bin, buckets_xl_header *h) {
  buckets_mp_reader r = buckets_mp_reader_init(bin.p, bin.n);
  uint32_t n;
  buckets_str s;
  int64_t mt;
  uint64_t u;
  memset(h, 0, sizeof(*h));
  if (!buckets_mp_read_array(&r, &n) || n < 5) return false;
  if (!buckets_mp_read_bin(&r, &s) || s.n != 16) return false;
  memcpy(h->version_id, s.p, 16);
  if (!buckets_mp_read_int(&r, &mt)) return false;
  h->mod_time = mt;
  if (!buckets_mp_read_bin(&r, &s) || s.n != 4) return false;
  memcpy(h->signature, s.p, 4);
  if (!buckets_mp_read_uint(&r, &u)) return false;
  h->type = (uint8_t)u;
  if (!buckets_mp_read_uint(&r, &u)) return false;
  h->flags = (uint8_t)u;
  if (n >= 7) { /* header v3 adds EcN, EcM */
    if (!buckets_mp_read_uint(&r, &u)) return false;
    h->ec_n = (uint8_t)u;
    if (!buckets_mp_read_uint(&r, &u)) return false;
    h->ec_m = (uint8_t)u;
  }
  return !r.err;
}

static void encode_header(buckets_buf *b, const buckets_xl_header *h) {
  buckets_mp_array(b, 7);
  buckets_mp_bin(b, h->version_id, 16);
  buckets_mp_int(b, h->mod_time);
  buckets_mp_bin(b, h->signature, 4);
  buckets_mp_uint(b, h->type);
  buckets_mp_uint(b, h->flags);
  buckets_mp_uint(b, h->ec_n);
  buckets_mp_uint(b, h->ec_m);
}

static bool inline_valid(const uint8_t *p, size_t n) {
  if (n == 0) return true;
  if (p[0] != 1) return false;
  buckets_mp_reader r = buckets_mp_reader_init(p + 1, n - 1);
  uint32_t cnt;
  if (!buckets_mp_read_map(&r, &cnt)) return false;
  for (uint32_t i = 0; i < cnt; i++) {
    buckets_str k, v;
    if (!buckets_mp_read_str(&r, &k) || k.n == 0 || !buckets_mp_read_bin(&r, &v)) return false;
  }
  return true;
}

buckets_xl_err buckets_xlmeta_parse(const void *buf, size_t n, buckets_xlmeta *out) {
  memset(out, 0, sizeof(*out));
  const uint8_t *p = buf;
  if (n <= 8 || memcmp(p, "XL2 ", 4) != 0) return BUCKETS_XL_ERR_CORRUPT;
  unsigned major = (unsigned)(p[4] | p[5] << 8), minor = (unsigned)(p[6] | p[7] << 8);
  if (memcmp(p + 4, "1   ", 4) == 0) major = 1, minor = 0;
  if (major != XL_MAJOR || minor < 3) return BUCKETS_XL_ERR_UNSUPPORTED;

  buckets_mp_reader r = buckets_mp_reader_init(p + 8, n - 8);
  buckets_str meta;
  if (!buckets_mp_read_bin(&r, &meta)) return BUCKETS_XL_ERR_CORRUPT;
  uint64_t crc;
  if (!buckets_mp_read_uint(&r, &crc) || crc > 0xffffffffull) return BUCKETS_XL_ERR_CORRUPT;
  if ((uint32_t)buckets_xxh64(meta.p, meta.n) != (uint32_t)crc) return BUCKETS_XL_ERR_CORRUPT;
  const uint8_t *data = r.p;
  size_t data_len = buckets_mp_remaining(&r);

  buckets_mp_reader m = buckets_mp_reader_init(meta.p, meta.n);
  uint64_t hv, mv;
  int64_t nver;
  if (!buckets_mp_read_uint(&m, &hv) || !buckets_mp_read_uint(&m, &mv) || !buckets_mp_read_int(&m, &nver) ||
      hv > XL_HEADER_VERSION || mv > XL_META_VERSION || nver < 0 || (uint64_t)nver > meta.n) {
    return BUCKETS_XL_ERR_CORRUPT;
  }
  out->versions = buckets_xcalloc((size_t)nver ? (size_t)nver : 1, sizeof(buckets_xl_version));
  for (int64_t i = 0; i < nver; i++) {
    buckets_str hdr, ver;
    if (!buckets_mp_read_bin(&m, &hdr) || !buckets_mp_read_bin(&m, &ver)) goto corrupt;
    buckets_xl_version *v = &out->versions[out->n];
    if (!parse_header(hdr, &v->hdr)) goto corrupt;
    v->meta = buckets_xmalloc(ver.n ? ver.n : 1);
    memcpy(v->meta, ver.p, ver.n);
    v->meta_len = ver.n;
    out->n++;
  }
  /* MinIO repairs invalid inline data by dropping it; do the same. */
  if (data_len && inline_valid(data, data_len)) {
    out->inline_data = buckets_xmalloc(data_len);
    memcpy(out->inline_data, data, data_len);
    out->inline_len = data_len;
  }
  return BUCKETS_XL_OK;

corrupt:
  buckets_xlmeta_free(out);
  return BUCKETS_XL_ERR_CORRUPT;
}

void buckets_xlmeta_serialize(const buckets_xlmeta *x, buckets_buf *out) {
  buckets_buf_append(out, "XL2 ", 4);
  uint8_t ver[4] = {XL_MAJOR, 0, XL_MINOR, 0};
  buckets_buf_append(out, ver, 4);
  buckets_buf_append(out, "\xc6\0\0\0\0", 5); /* bin32, length patched below */
  size_t start = out->len;
  buckets_mp_uint(out, XL_HEADER_VERSION);
  buckets_mp_uint(out, XL_META_VERSION);
  buckets_mp_int(out, (int64_t)x->n);
  buckets_buf hdr = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < x->n; i++) {
    buckets_buf_reset(&hdr);
    encode_header(&hdr, &x->versions[i].hdr);
    buckets_mp_bin(out, hdr.data, hdr.len);
    buckets_mp_bin(out, x->versions[i].meta, x->versions[i].meta_len);
  }
  buckets_buf_free(&hdr);
  size_t len = out->len - start;
  for (int i = 0; i < 4; i++) out->data[start - 4 + i] = (char)(len >> (8 * (3 - i)));
  uint32_t crc = (uint32_t)buckets_xxh64(out->data + start, len);
  uint8_t c[5] = {0xce, (uint8_t)(crc >> 24), (uint8_t)(crc >> 16), (uint8_t)(crc >> 8), (uint8_t)crc};
  buckets_buf_append(out, c, 5);
  if (x->inline_len) buckets_buf_append(out, x->inline_data, x->inline_len);
}

void buckets_xlmeta_free(buckets_xlmeta *x) {
  for (size_t i = 0; i < x->n; i++) free(x->versions[i].meta);
  free(x->versions);
  free(x->inline_data);
  memset(x, 0, sizeof(*x));
}

long buckets_xlmeta_find(const buckets_xlmeta *x, const uint8_t version_id[16]) {
  for (size_t i = 0; i < x->n; i++) {
    if (memcmp(x->versions[i].hdr.version_id, version_id, 16) == 0) return (long)i;
  }
  return -1;
}

void buckets_xlmeta_put_version(buckets_xlmeta *x, const buckets_xl_header *hdr, uint8_t *meta, size_t meta_len) {
  long i = buckets_xlmeta_find(x, hdr->version_id);
  if (i >= 0) {
    free(x->versions[i].meta);
  } else {
    x->versions = buckets_xrealloc(x->versions, (x->n + 1) * sizeof(buckets_xl_version));
    i = (long)x->n++;
  }
  x->versions[i] = (buckets_xl_version){*hdr, meta, meta_len};
  sort_versions(x);
}

bool buckets_xlmeta_remove_version(buckets_xlmeta *x, const uint8_t version_id[16]) {
  long i = buckets_xlmeta_find(x, version_id);
  if (i < 0) return false;
  free(x->versions[i].meta);
  memmove(&x->versions[i], &x->versions[i + 1], (x->n - (size_t)i - 1) * sizeof(buckets_xl_version));
  x->n--;
  return true;
}

/* ---- inline data ---------------------------------------------------------- */

typedef struct {
  buckets_str key, val;
} inline_entry;

static size_t inline_entries(const buckets_xlmeta *x, inline_entry **out) {
  *out = NULL;
  if (x->inline_len < 2) return 0;
  buckets_mp_reader r = buckets_mp_reader_init(x->inline_data + 1, x->inline_len - 1);
  uint32_t cnt;
  if (!buckets_mp_read_map(&r, &cnt)) return 0;
  inline_entry *e = buckets_xcalloc(cnt ? cnt : 1, sizeof(*e));
  size_t n = 0;
  for (uint32_t i = 0; i < cnt; i++) {
    if (!buckets_mp_read_str(&r, &e[n].key) || !buckets_mp_read_bin(&r, &e[n].val)) break;
    n++;
  }
  *out = e;
  return n;
}

bool buckets_xlmeta_inline_get(const buckets_xlmeta *x, const char *key, buckets_str *out) {
  inline_entry *e;
  size_t n = inline_entries(x, &e);
  bool found = false;
  for (size_t i = 0; i < n && !found; i++) {
    if (buckets_str_eq_c(e[i].key, key)) {
      *out = e[i].val;
      found = true;
    }
  }
  free(e);
  return found;
}

static void inline_rebuild(buckets_xlmeta *x, const char *skip_key, const char *add_key, const void *data,
                           size_t len) {
  inline_entry *e;
  size_t n = inline_entries(x, &e);
  buckets_buf b = BUCKETS_BUF_INIT;
  uint32_t count = 0;
  for (size_t i = 0; i < n; i++) {
    if (!buckets_str_eq_c(e[i].key, skip_key)) count++;
  }
  if (add_key) count++;
  if (count == 0) {
    free(e);
    free(x->inline_data);
    x->inline_data = NULL;
    x->inline_len = 0;
    return;
  }
  buckets_buf_append_char(&b, 1);
  buckets_mp_map(&b, count);
  for (size_t i = 0; i < n; i++) {
    if (buckets_str_eq_c(e[i].key, skip_key)) continue;
    buckets_mp_str(&b, e[i].key.p, e[i].key.n);
    buckets_mp_bin(&b, e[i].val.p, e[i].val.n);
  }
  if (add_key) {
    buckets_mp_cstr(&b, add_key);
    buckets_mp_bin(&b, data, len);
  }
  free(e);
  free(x->inline_data);
  x->inline_data = (uint8_t *)b.data;
  x->inline_len = b.len;
}

void buckets_xlmeta_inline_put(buckets_xlmeta *x, const char *key, const void *data, size_t n) {
  inline_rebuild(x, key, key, data, n);
}

void buckets_xlmeta_inline_remove(buckets_xlmeta *x, const char *key) { inline_rebuild(x, key, NULL, NULL, 0); }

/* ---- object version encode / decode -------------------------------------- */

static uint64_t hash_det_kv(const buckets_xl_kv *kvs, size_t n, uint64_t seed) {
  uint64_t crc = seed;
  for (size_t i = 0; i < n; i++) {
    crc ^= (buckets_xxh3_64(kvs[i].key, strlen(kvs[i].key)) ^ 0x4ee3bbaf7ab2506bull) +
           (buckets_xxh3_64(kvs[i].value, kvs[i].value_len) ^ 0x8da4c8da66194257ull);
  }
  return crc;
}

/* Encodes xlMetaV2Object with tinylib/msgp's field order. With for_signature
 * set, applies the normalizations of xlMetaV2Object.Signature(). */
static void encode_v2obj(buckets_buf *b, const buckets_xl_object *o, bool for_signature) {
  bool any_etag = false;
  for (size_t i = 0; i < o->nparts; i++) any_etag |= o->parts[i].etag != NULL;

  buckets_mp_map(b, 17); /* 18 fields, PartIdx omitted (no compression yet) */
  buckets_mp_cstr(b, "ID");
  buckets_mp_bin(b, o->version_id, 16);
  buckets_mp_cstr(b, "DDir");
  buckets_mp_bin(b, o->data_dir, 16);
  buckets_mp_cstr(b, "EcAlgo");
  buckets_mp_uint(b, 1); /* ReedSolomon */
  buckets_mp_cstr(b, "EcM");
  buckets_mp_int(b, o->ec_m);
  buckets_mp_cstr(b, "EcN");
  buckets_mp_int(b, o->ec_n);
  buckets_mp_cstr(b, "EcBSize");
  buckets_mp_int(b, o->ec_block_size);
  buckets_mp_cstr(b, "EcIndex");
  buckets_mp_int(b, for_signature ? 0 : o->ec_index);
  buckets_mp_cstr(b, "EcDist");
  buckets_mp_array(b, (uint32_t)o->ec_dist_n);
  for (size_t i = 0; i < o->ec_dist_n; i++) buckets_mp_uint(b, o->ec_dist[i]);
  buckets_mp_cstr(b, "CSumAlgo");
  buckets_mp_uint(b, 1); /* HighwayHash */
  buckets_mp_cstr(b, "PartNums");
  buckets_mp_array(b, (uint32_t)o->nparts);
  for (size_t i = 0; i < o->nparts; i++) buckets_mp_int(b, o->parts[i].number);
  buckets_mp_cstr(b, "PartETags");
  if (!any_etag) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_array(b, (uint32_t)o->nparts);
    for (size_t i = 0; i < o->nparts; i++) buckets_mp_cstr(b, o->parts[i].etag ? o->parts[i].etag : "");
  }
  buckets_mp_cstr(b, "PartSizes");
  buckets_mp_array(b, (uint32_t)o->nparts);
  for (size_t i = 0; i < o->nparts; i++) buckets_mp_int(b, o->parts[i].size);
  buckets_mp_cstr(b, "PartASizes");
  if (for_signature && o->nparts == 0) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_array(b, (uint32_t)o->nparts);
    for (size_t i = 0; i < o->nparts; i++) buckets_mp_int(b, o->parts[i].actual_size);
  }
  buckets_mp_cstr(b, "Size");
  buckets_mp_int(b, o->size);
  buckets_mp_cstr(b, "MTime");
  buckets_mp_int(b, o->mod_time);
  buckets_mp_cstr(b, "MetaSys");
  if (for_signature) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, (uint32_t)o->nmeta_sys);
    for (size_t i = 0; i < o->nmeta_sys; i++) {
      buckets_mp_cstr(b, o->meta_sys[i].key);
      buckets_mp_bin(b, o->meta_sys[i].value, o->meta_sys[i].value_len);
    }
  }
  buckets_mp_cstr(b, "MetaUsr");
  if (for_signature) {
    buckets_mp_nil(b);
  } else {
    buckets_mp_map(b, (uint32_t)o->nmeta_user);
    for (size_t i = 0; i < o->nmeta_user; i++) {
      buckets_mp_cstr(b, o->meta_user[i].key);
      buckets_mp_str(b, (const char *)o->meta_user[i].value, o->meta_user[i].value_len);
    }
  }
}

void buckets_xl_object_encode(const buckets_xl_object *o, buckets_buf *meta, buckets_xl_header *hdr) {
  buckets_mp_map(meta, 3); /* Type, V2Obj, v */
  buckets_mp_cstr(meta, "Type");
  buckets_mp_uint(meta, BUCKETS_XL_TYPE_OBJECT);
  buckets_mp_cstr(meta, "V2Obj");
  encode_v2obj(meta, o, false);
  buckets_mp_cstr(meta, "v");
  buckets_mp_uint(meta, o->written_by ? o->written_by : BUCKETS_XL_WRITTEN_BY);

  buckets_buf sig = BUCKETS_BUF_INIT;
  encode_v2obj(&sig, o, true);
  uint64_t crc = hash_det_kv(o->meta_user, o->nmeta_user, 0xc2b40bbac11a7295ull);
  crc ^= hash_det_kv(o->meta_sys, o->nmeta_sys, 0x1bbc7e1dde654743ull);
  crc ^= buckets_xxh64(sig.data, sig.len);
  buckets_buf_free(&sig);
  uint32_t s32 = (uint32_t)(crc ^ (crc >> 32));

  memset(hdr, 0, sizeof(*hdr));
  memcpy(hdr->version_id, o->version_id, 16);
  hdr->mod_time = o->mod_time;
  for (int i = 0; i < 4; i++) hdr->signature[i] = (uint8_t)(s32 >> (8 * i));
  hdr->type = BUCKETS_XL_TYPE_OBJECT;
  hdr->flags = BUCKETS_XL_FLAG_USES_DATA_DIR; /* no tiering yet, so data always lives on the drive */
  if (buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, BUCKETS_XL_META_INLINE)) hdr->flags |= BUCKETS_XL_FLAG_INLINE_DATA;
  hdr->ec_m = (uint8_t)o->ec_m;
  hdr->ec_n = (uint8_t)o->ec_n;
}

static bool read_int_array(buckets_mp_reader *r, int64_t **out, size_t *n) {
  *out = NULL;
  *n = 0;
  if (buckets_mp_read_nil(r)) return true;
  uint32_t cnt;
  if (!buckets_mp_read_array(r, &cnt) || cnt > buckets_mp_remaining(r)) return false;
  *out = buckets_xcalloc(cnt ? cnt : 1, sizeof(int64_t));
  for (uint32_t i = 0; i < cnt; i++) {
    if (!buckets_mp_read_int(r, &(*out)[i])) return false;
  }
  *n = cnt;
  return true;
}

static bool read_kv_map(buckets_mp_reader *r, buckets_xl_kv **kvs, size_t *n) {
  if (buckets_mp_read_nil(r)) return true;
  uint32_t cnt;
  if (!buckets_mp_read_map(r, &cnt)) return false;
  for (uint32_t i = 0; i < cnt; i++) {
    buckets_str k, v;
    if (!buckets_mp_read_str(r, &k) || !buckets_mp_read_bin(r, &v)) return false;
    char *key = buckets_str_dup(k);
    buckets_xl_kv_set(kvs, n, key, v.p, v.n);
    free(key);
  }
  return true;
}

static buckets_xl_err decode_v2obj(buckets_mp_reader *r, buckets_xl_object *o) {
  uint32_t fields;
  if (!buckets_mp_read_map(r, &fields)) return BUCKETS_XL_ERR_CORRUPT;
  int64_t *nums = NULL, *sizes = NULL, *asizes = NULL;
  size_t nnums = 0, nsizes = 0, nasizes = 0;
  char **etags = NULL;
  size_t netags = 0;
  buckets_xl_err err = BUCKETS_XL_OK;
  for (uint32_t f = 0; f < fields && err == BUCKETS_XL_OK; f++) {
    buckets_str key, s;
    int64_t iv;
    uint64_t uv;
    if (!buckets_mp_read_str(r, &key)) {
      err = BUCKETS_XL_ERR_CORRUPT;
      break;
    }
    bool ok = true;
    if (buckets_str_eq_c(key, "ID") || buckets_str_eq_c(key, "DDir")) {
      ok = buckets_mp_read_bin(r, &s) && s.n == 16;
      if (ok) memcpy(buckets_str_eq_c(key, "ID") ? o->version_id : o->data_dir, s.p, 16);
    } else if (buckets_str_eq_c(key, "EcAlgo") || buckets_str_eq_c(key, "CSumAlgo")) {
      ok = buckets_mp_read_uint(r, &uv) && uv == 1;
    } else if (buckets_str_eq_c(key, "EcM")) {
      ok = buckets_mp_read_int(r, &iv);
      o->ec_m = (int)iv;
    } else if (buckets_str_eq_c(key, "EcN")) {
      ok = buckets_mp_read_int(r, &iv);
      o->ec_n = (int)iv;
    } else if (buckets_str_eq_c(key, "EcBSize")) {
      ok = buckets_mp_read_int(r, &o->ec_block_size);
    } else if (buckets_str_eq_c(key, "EcIndex")) {
      ok = buckets_mp_read_int(r, &iv);
      o->ec_index = (int)iv;
    } else if (buckets_str_eq_c(key, "EcDist")) {
      uint32_t cnt;
      ok = buckets_mp_read_array(r, &cnt) && cnt <= sizeof(o->ec_dist);
      for (uint32_t i = 0; ok && i < cnt; i++) {
        ok = buckets_mp_read_uint(r, &uv);
        o->ec_dist[i] = (uint8_t)uv;
      }
      if (ok) o->ec_dist_n = cnt;
    } else if (buckets_str_eq_c(key, "PartNums")) {
      ok = read_int_array(r, &nums, &nnums);
    } else if (buckets_str_eq_c(key, "PartSizes")) {
      ok = read_int_array(r, &sizes, &nsizes);
    } else if (buckets_str_eq_c(key, "PartASizes")) {
      ok = read_int_array(r, &asizes, &nasizes);
    } else if (buckets_str_eq_c(key, "PartETags")) {
      if (!buckets_mp_read_nil(r)) {
        uint32_t cnt;
        ok = buckets_mp_read_array(r, &cnt) && cnt <= buckets_mp_remaining(r);
        if (ok) etags = buckets_xcalloc(cnt ? cnt : 1, sizeof(char *));
        for (uint32_t i = 0; ok && i < cnt; i++) {
          ok = buckets_mp_read_str(r, &s);
          if (ok) etags[netags++] = buckets_str_dup(s);
        }
      }
    } else if (buckets_str_eq_c(key, "Size")) {
      ok = buckets_mp_read_int(r, &o->size);
    } else if (buckets_str_eq_c(key, "MTime")) {
      ok = buckets_mp_read_int(r, &o->mod_time);
    } else if (buckets_str_eq_c(key, "MetaSys")) {
      ok = read_kv_map(r, &o->meta_sys, &o->nmeta_sys);
    } else if (buckets_str_eq_c(key, "MetaUsr")) {
      ok = read_kv_map(r, &o->meta_user, &o->nmeta_user);
    } else {
      ok = buckets_mp_skip(r); /* PartIdx and future fields */
    }
    if (!ok) err = BUCKETS_XL_ERR_CORRUPT;
  }
  if (err == BUCKETS_XL_OK && (nsizes != nnums || (nasizes && nasizes != nnums) || (netags && netags != nnums))) {
    err = BUCKETS_XL_ERR_CORRUPT;
  }
  for (size_t i = 0; err == BUCKETS_XL_OK && i < nnums; i++) {
    buckets_xl_part_add(o, (int)nums[i], sizes[i], nasizes ? asizes[i] : sizes[i], netags ? etags[i] : NULL);
  }
  for (size_t i = 0; i < netags; i++) free(etags[i]);
  free(etags);
  free(nums);
  free(sizes);
  free(asizes);
  return err;
}

static buckets_xl_err decode_delobj(buckets_mp_reader *r, buckets_xl_object *o) {
  uint32_t fields;
  if (!buckets_mp_read_map(r, &fields)) return BUCKETS_XL_ERR_CORRUPT;
  for (uint32_t f = 0; f < fields; f++) {
    buckets_str key, s;
    if (!buckets_mp_read_str(r, &key)) return BUCKETS_XL_ERR_CORRUPT;
    bool ok;
    if (buckets_str_eq_c(key, "ID")) {
      ok = buckets_mp_read_bin(r, &s) && s.n == 16;
      if (ok) memcpy(o->version_id, s.p, 16);
    } else if (buckets_str_eq_c(key, "MTime")) {
      ok = buckets_mp_read_int(r, &o->mod_time);
    } else if (buckets_str_eq_c(key, "MetaSys")) {
      ok = read_kv_map(r, &o->meta_sys, &o->nmeta_sys);
    } else {
      ok = buckets_mp_skip(r);
    }
    if (!ok) return BUCKETS_XL_ERR_CORRUPT;
  }
  return BUCKETS_XL_OK;
}

buckets_xl_err buckets_xl_object_decode(const buckets_xl_version *v, buckets_xl_object *out) {
  memset(out, 0, sizeof(*out));
  buckets_mp_reader r = buckets_mp_reader_init(v->meta, v->meta_len);
  uint32_t fields;
  if (!buckets_mp_read_map(&r, &fields)) return BUCKETS_XL_ERR_CORRUPT;
  buckets_xl_err err = BUCKETS_XL_OK;
  for (uint32_t f = 0; f < fields && err == BUCKETS_XL_OK; f++) {
    buckets_str key;
    uint64_t uv;
    if (!buckets_mp_read_str(&r, &key)) {
      err = BUCKETS_XL_ERR_CORRUPT;
    } else if (buckets_str_eq_c(key, "Type")) {
      if (!buckets_mp_read_uint(&r, &uv)) err = BUCKETS_XL_ERR_CORRUPT;
      out->type = (uint8_t)uv;
    } else if (buckets_str_eq_c(key, "V2Obj")) {
      if (!buckets_mp_read_nil(&r)) err = decode_v2obj(&r, out);
    } else if (buckets_str_eq_c(key, "DelObj")) {
      if (!buckets_mp_read_nil(&r)) err = decode_delobj(&r, out);
    } else if (buckets_str_eq_c(key, "V1Obj")) {
      if (!buckets_mp_read_nil(&r)) err = BUCKETS_XL_ERR_UNSUPPORTED; /* legacy xl.json-era objects */
    } else if (buckets_str_eq_c(key, "v")) {
      if (!buckets_mp_read_uint(&r, &out->written_by)) err = BUCKETS_XL_ERR_CORRUPT;
    } else if (!buckets_mp_skip(&r)) {
      err = BUCKETS_XL_ERR_CORRUPT;
    }
  }
  if (err == BUCKETS_XL_OK && out->type != BUCKETS_XL_TYPE_OBJECT && out->type != BUCKETS_XL_TYPE_DELETE) {
    err = out->type == BUCKETS_XL_TYPE_LEGACY ? BUCKETS_XL_ERR_UNSUPPORTED : BUCKETS_XL_ERR_CORRUPT;
  }
  if (err != BUCKETS_XL_OK) buckets_xl_object_free(out);
  return err;
}
