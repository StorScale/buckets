/* S3 object handlers: Put/Get/Head/Delete/Copy, DeleteObjects, ListObjects v1/v2.
 * Mirrors MinIO cmd/object-handlers.go, bucket-listobjects-handlers.go.
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#include <ctype.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/objkey.h"
#include "crypto/sha256.h"
#include "s3/checksum.h"
#include "s3/chunked.h"
#include "notify/event.h"
#include "s3/internal.h"
#include "bucket/metasys.h"
#include "bucket/objectlock.h"
#include "crypto/md5.h"
#include "s3/compress.h"
#include "s3/sse.h"
#include "s3/replicate.h"
#include "s3/xml.h"

/* ---- error mapping -------------------------------------------------------- */

buckets_s3_error buckets_s3_obj_error(buckets_obj_err e) {
  switch (e) {
    case BUCKETS_OBJ_OK: return BUCKETS_ERR_NONE;
    case BUCKETS_OBJ_ERR_NO_SUCH_BUCKET: return BUCKETS_ERR_NO_SUCH_BUCKET;
    case BUCKETS_OBJ_ERR_NO_SUCH_KEY: return BUCKETS_ERR_NO_SUCH_KEY;
    case BUCKETS_OBJ_ERR_NO_SUCH_VERSION: return BUCKETS_ERR_NO_SUCH_VERSION;
    case BUCKETS_OBJ_ERR_INVALID_NAME: return BUCKETS_ERR_INVALID_OBJECT_NAME;
    case BUCKETS_OBJ_ERR_NAME_TOO_LONG: return BUCKETS_ERR_KEY_TOO_LONG_ERROR;
    case BUCKETS_OBJ_ERR_NAME_PREFIX_SLASH: return BUCKETS_ERR_INVALID_OBJECT_NAME_PREFIX_SLASH;
    case BUCKETS_OBJ_ERR_EXISTS_AS_DIRECTORY: return BUCKETS_ERR_OBJECT_EXISTS_AS_DIRECTORY;
    case BUCKETS_OBJ_ERR_BAD_DIGEST: return BUCKETS_ERR_BAD_DIGEST;
    case BUCKETS_OBJ_ERR_SHA256_MISMATCH: return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
    case BUCKETS_OBJ_ERR_INCOMPLETE_BODY: return BUCKETS_ERR_INCOMPLETE_BODY;
    case BUCKETS_OBJ_ERR_READER: return BUCKETS_ERR_INCOMPLETE_BODY;
    case BUCKETS_OBJ_ERR_CORRUPT: return BUCKETS_ERR_INTERNAL_ERROR;
    case BUCKETS_OBJ_ERR_IO: return BUCKETS_ERR_INTERNAL_ERROR;
    case BUCKETS_OBJ_ERR_NO_SUCH_UPLOAD: return BUCKETS_ERR_NO_SUCH_UPLOAD;
    case BUCKETS_OBJ_ERR_INVALID_PART: return BUCKETS_ERR_INVALID_PART;
    case BUCKETS_OBJ_ERR_INVALID_PART_ORDER: return BUCKETS_ERR_INVALID_PART_ORDER;
    case BUCKETS_OBJ_ERR_PART_TOO_SMALL: return BUCKETS_ERR_ENTITY_TOO_SMALL;
    case BUCKETS_OBJ_ERR_BAD_CHECKSUM: return BUCKETS_ERR_CONTENT_CHECKSUM_MISMATCH;
    case BUCKETS_OBJ_ERR_READ_QUORUM: return BUCKETS_ERR_SLOW_DOWN_READ;
    case BUCKETS_OBJ_ERR_WRITE_QUORUM: return BUCKETS_ERR_SLOW_DOWN_WRITE;
    case BUCKETS_OBJ_ERR_BUCKET_EXISTS: return BUCKETS_ERR_BUCKET_ALREADY_OWNED_BY_YOU;
    case BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY: return BUCKETS_ERR_BUCKET_NOT_EMPTY;
    case BUCKETS_OBJ_ERR_TIMEOUT: return BUCKETS_ERR_REQUEST_TIMEDOUT; /* MinIO: OperationTimedOut */
    case BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED: return BUCKETS_ERR_METHOD_NOT_ALLOWED;
  }
  return BUCKETS_ERR_INTERNAL_ERROR;
}

/* ---- helpers -------------------------------------------------------------- */

/* Go's http.CanonicalHeaderKey for ASCII token names. */
static void canonical_key(const char *in, char *out, size_t cap) {
  bool upper = true;
  size_t i = 0;
  for (; in[i] && i + 1 < cap; i++) {
    char ch = in[i];
    out[i] = upper ? (char)toupper((unsigned char)ch) : (char)tolower((unsigned char)ch);
    upper = ch == '-';
  }
  out[i] = '\0';
}

static bool has_prefix_fold(const char *s, const char *prefix) { return strncasecmp(s, prefix, strlen(prefix)) == 0; }

static bool is_hex64(const char *s) {
  if (strlen(s) != 64) return false;
  for (int i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

static bool hex_decode32(const char *s, uint8_t out[32]) {
  if (!is_hex64(s)) return false;
  for (int i = 0; i < 32; i++) {
    unsigned v;
    sscanf(s + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
  return true;
}

static void add_kv(buckets_xl_kv **kvs, size_t *n, const char *key, buckets_str value) {
  /* Repeated headers join with ',' like Go's strings.Join(values, ","). */
  const buckets_xl_kv *have = buckets_xl_kv_get(*kvs, *n, key);
  if (have) {
    buckets_buf joined = BUCKETS_BUF_INIT;
    buckets_buf_append(&joined, have->value, have->value_len);
    buckets_buf_append_char(&joined, ',');
    buckets_buf_append_str(&joined, value);
    buckets_xl_kv_set(kvs, n, key, joined.data, joined.len);
    buckets_buf_free(&joined);
    return;
  }
  buckets_xl_kv_set(kvs, n, key, value.p ? value.p : "", value.n);
}

static void remove_kv(buckets_xl_kv *kvs, size_t *n, const char *key) {
  for (size_t i = 0; i < *n;) {
    if (strcasecmp(kvs[i].key, key) != 0) {
      i++;
      continue;
    }
    free(kvs[i].key);
    free(kvs[i].value);
    memmove(&kvs[i], &kvs[i + 1], (*n - i - 1) * sizeof(*kvs));
    (*n)--;
  }
}

bool buckets_s3_enforce_quota(s3_ctx *c, const char *bucket, int64_t size) {
  if (!c->s->meta) return true;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  bool over = false;
  if (st->has_quota && buckets_quota_hard_limit(&st->quota)) {
    uint64_t used = c->s->bucket_usage ? c->s->bucket_usage(c->s->bucket_usage_ud, bucket) : 0;
    over = buckets_quota_exceeded(&st->quota, size, used);
  }
  buckets_bucket_state_release(st);
  if (over) buckets_s3_write_error(c, BUCKETS_ERR_ADMIN_BUCKET_QUOTA_EXCEEDED);
  return !over;
}

static void free_kvs(buckets_xl_kv *kvs, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(kvs[i].key);
    free(kvs[i].value);
  }
  free(kvs);
}

/* MinIO extractMetadata: supported headers under their MinIO spelling, user
 * metadata under the canonical header name, from query form then headers. */
static const char *const k_supported[] = {
    "content-type",        "cache-control", "content-language", "content-encoding", "content-disposition",
    "x-amz-storage-class", "X-Amz-Tagging", "expires", "X-Amz-Replication-Status",
};

/* replicationToInternalHeaders: what SSE-C replication sends, stored under
 * the internal names (the checksum keeps its name). */
static const struct {
  const char *header, *key;
} k_repl_headers[] = {
    {"X-Minio-Replication-Server-Side-Encryption-Sealed-Key", "X-Minio-Internal-Server-Side-Encryption-Sealed-Key"},
    {"X-Minio-Replication-Server-Side-Encryption-Seal-Algorithm", "X-Minio-Internal-Server-Side-Encryption-Seal-Algorithm"},
    {"X-Minio-Replication-Server-Side-Encryption-Iv", "X-Minio-Internal-Server-Side-Encryption-Iv"},
    {"X-Minio-Replication-Encrypted-Multipart", "X-Minio-Internal-Encrypted-Multipart"},
    {"X-Minio-Replication-Actual-Object-Size", "X-Minio-Internal-Actual-Object-Size"},
    {"X-Minio-Replication-Ssec-Crc", "X-Minio-Replication-Ssec-Crc"},
};

static void extract_one(buckets_xl_kv **kvs, size_t *n, buckets_str name, buckets_str value) {
  char key[256];
  char *raw = buckets_str_dup(name);
  canonical_key(raw, key, sizeof(key));
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_supported); i++) {
    char want[64];
    canonical_key(k_supported[i], want, sizeof(want));
    if (strcmp(want, key) == 0) add_kv(kvs, n, k_supported[i], value);
  }
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(k_repl_headers); i++)
    if (strcmp(key, k_repl_headers[i].header) == 0) add_kv(kvs, n, k_repl_headers[i].key, value);
  if (has_prefix_fold(raw, "x-amz-meta-") || has_prefix_fold(raw, "x-minio-meta-")) add_kv(kvs, n, key, value);
  free(raw);
}

static buckets_s3_error extract_metadata(s3_ctx *c, buckets_xl_kv **kvs, size_t *n) {
  for (size_t i = 0; i < c->q.n; i++) {
    extract_one(kvs, n, buckets_str_c(c->q.items[i].key), buckets_str_c(c->q.items[i].value));
  }
  for (size_t i = 0; i < c->req->nheaders; i++) {
    extract_one(kvs, n, c->req->headers[i].name, c->req->headers[i].value);
  }
  if (!buckets_xl_kv_get(*kvs, *n, "content-type")) buckets_xl_kv_set(kvs, n, "content-type", "binary/octet-stream", 19);

  /* aws-chunked is a transfer detail, not the object's content encoding. */
  const buckets_xl_kv *ce = buckets_xl_kv_get(*kvs, *n, "content-encoding");
  if (ce) {
    buckets_buf kept = BUCKETS_BUF_INIT;
    buckets_str rest = {(const char *)ce->value, ce->value_len}, part;
    while (rest.n) {
      buckets_str_cut(rest, ',', &part, &rest);
      part = buckets_str_trim(part);
      if (part.n == 0 || buckets_str_eq_c(part, "aws-chunked")) continue;
      if (kept.len) buckets_buf_append_char(&kept, ',');
      buckets_buf_append_str(&kept, part);
    }
    if (kept.len) {
      buckets_xl_kv_set(kvs, n, "content-encoding", kept.data, kept.len);
    } else {
      for (size_t i = 0; i < *n; i++) {
        if (strcmp((*kvs)[i].key, "content-encoding") == 0) {
          free((*kvs)[i].key);
          free((*kvs)[i].value);
          (*kvs)[i] = (*kvs)[--*n];
          break;
        }
      }
    }
    buckets_buf_free(&kept);
  }

  const buckets_xl_kv *sc = buckets_xl_kv_get(*kvs, *n, "x-amz-storage-class");
  if (sc) {
    const char *v = (const char *)sc->value;
    if (strcmp(v, "STANDARD") != 0 && strcmp(v, "REDUCED_REDUNDANCY") != 0) return BUCKETS_ERR_INVALID_STORAGE_CLASS;
    if (strcmp(v, "STANDARD") == 0) {
      for (size_t i = 0; i < *n; i++) {
        if (strcmp((*kvs)[i].key, "x-amz-storage-class") == 0) {
          free((*kvs)[i].key);
          free((*kvs)[i].value);
          (*kvs)[i] = (*kvs)[--*n];
          break;
        }
      }
    }
  }
  return BUCKETS_ERR_NONE;
}

/* An SSE-C replica's checksum arrives sealed, base64-encoded: stored as
 * the version's checksum. */
static void repl_ssec_checksum(buckets_xl_kv **kvs, size_t *n) {
  const buckets_xl_kv *kv = buckets_xl_kv_get(*kvs, *n, "X-Minio-Replication-Ssec-Crc");
  if (!kv) return;
  uint8_t *raw = buckets_xmalloc(kv->value_len + 3);
  long rn = buckets_base64_decode((const char *)kv->value, kv->value_len, raw);
  if (rn > 0) buckets_xl_kv_set(kvs, n, BUCKETS_CKSUM_META, raw, (size_t)rn);
  free(raw);
  remove_kv(*kvs, n, "X-Minio-Replication-Ssec-Crc");
}

static bool parse_content_md5(s3_ctx *c, uint8_t out[16], bool *present, buckets_s3_error *err) {
  buckets_str h = buckets_http_header_get(c->req, "Content-MD5");
  *present = h.p != NULL;
  if (!h.p) return true;
  uint8_t tmp[19];
  if (h.n != 24 || buckets_base64_decode(h.p, h.n, tmp) != 16) {
    *err = BUCKETS_ERR_INVALID_DIGEST;
    return false;
  }
  memcpy(out, tmp, 16);
  return true;
}

static void etag_header(buckets_http_response *r, const char *etag) {
  buckets_http_resp_headerf(r, "ETag", "\"%s\"", etag);
}

/* ---- body sources --------------------------------------------------------- */

static long body_source(void *ud, void *buf, size_t n) { return buckets_http_body_read(ud, buf, n); }

static long reader_source(void *ud, void *buf, size_t n) { return buckets_obj_read(ud, buf, n); }

/* ---- PutObject ------------------------------------------------------------ */

static void copy_object(s3_ctx *c);

/* The upload's version ID for a replicated upload (removed at completion). */
#define MPU_VID_META "x-minio-internal-buckets-replication-version-id"

/* The request body as a decoded data source: plain, or aws-chunked. */
typedef struct {
  buckets_read_fn rd;
  void *rd_ud;
  buckets_http_body_cursor cur;
  buckets_chunked *ch;
  int64_t size;
  uint8_t md5[16], sha[32];
  bool has_md5, want_sha;
} body_src;

static buckets_s3_error body_open(s3_ctx *c, body_src *b) {
  memset(b, 0, sizeof(*b));
  buckets_s3_error serr = BUCKETS_ERR_NONE;
  if (!parse_content_md5(c, b->md5, &b->has_md5, &serr)) return serr;
  b->size = c->req->body_len;
  b->cur = (buckets_http_body_cursor){c->req, 0};
  b->rd = body_source;
  b->rd_ud = &b->cur;
  buckets_str mode = buckets_http_header_get(c->req, "X-Amz-Content-Sha256");
  if (mode.p && buckets_str_has_prefix(mode, "STREAMING-")) {
    b->ch = buckets_chunked_new(c->req, mode, c->auth == BUCKETS_AUTH_SIGV4_STREAMING ? &c->sig : NULL);
    if (!b->ch) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
    buckets_str dl = buckets_http_header_get(c->req, "X-Amz-Decoded-Content-Length");
    char *s = dl.p ? buckets_str_dup(dl) : NULL;
    char *end = NULL;
    b->size = s ? strtoll(s, &end, 10) : -1;
    if (!s || !*s || *end) b->size = -1;
    free(s);
    if (b->size < 0) return BUCKETS_ERR_MISSING_CONTENT_LENGTH;
    b->rd = buckets_chunked_read;
    b->rd_ud = b->ch;
  } else if (c->sig.payload_hash[0] && strcmp(c->sig.payload_hash, BUCKETS_UNSIGNED_PAYLOAD) != 0) {
    if (!hex_decode32(c->sig.payload_hash, b->sha)) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
    b->want_sha = true;
  }
  return BUCKETS_ERR_NONE;
}

static void body_close(body_src *b) { buckets_chunked_free(b->ch); }

/* Maps an object-layer failure, preferring the chunk decoder's diagnosis. */
static buckets_s3_error body_error(const body_src *b, buckets_obj_err err) {
  if (err == BUCKETS_OBJ_ERR_READER && b->ch && buckets_chunked_error(b->ch)) return buckets_chunked_error(b->ch);
  return buckets_s3_obj_error(err);
}

/* x-amz-checksum-* verification, run by the object layer before commit. */
typedef struct {
  buckets_checksum want; /* from headers; TRAILING means "read it from the trailer" */
  buckets_chunked *ch;
  buckets_checksum result; /* what was stored / should be echoed */
  bool server_side;        /* store what is computed (a copy's checksum) rather than verify it */
} cks_ctx;

static buckets_s3_error cks_open(s3_ctx *c, body_src *b, cks_ctx *x, buckets_put_opts *opts) {
  memset(x, 0, sizeof(*x));
  x->ch = b->ch;
  buckets_s3_error e = buckets_checksum_from_request(c->req, &x->want);
  if (e) return e;
  if (!x->want.type) {
    /* getContentChecksum: an algorithm without its value asks for nothing,
     * but must name a known algorithm. */
    buckets_str alg = buckets_http_header_get(c->req, "X-Amz-Checksum-Algorithm");
    if (alg.p && alg.n) {
      char *a = buckets_str_dup(alg);
      uint32_t t = buckets_cksum_type_parse(a, NULL);
      free(a);
      if (t == BUCKETS_CKSUM_INVALID) return BUCKETS_ERR_INVALID_CHECKSUM;
    }
  }
  if ((x->want.type & BUCKETS_CKSUM_TRAILING) && !b->ch) return BUCKETS_ERR_INVALID_CHECKSUM;
  opts->checksum_type = x->want.type & BUCKETS_CKSUM_BASE_MASK;
  return BUCKETS_ERR_NONE;
}

static buckets_obj_err cks_pre_commit(void *ud, const buckets_checksum *computed, buckets_xl_object *o) {
  cks_ctx *x = ud;
  if (!x->want.type) return BUCKETS_OBJ_OK;
  buckets_checksum expect = x->want;
  if (x->server_side) { /* nothing to verify against */
    memcpy(expect.raw, computed->raw, computed->raw_len);
    expect.raw_len = computed->raw_len;
  }
  if (x->want.type & BUCKETS_CKSUM_TRAILING) {
    const char *v = buckets_chunked_trailer(x->ch, buckets_cksum_header(x->want.type));
    buckets_checksum parsed;
    if (!v || !buckets_checksum_parse_value(x->want.type & ~BUCKETS_CKSUM_TRAILING, v, &parsed)) {
      return BUCKETS_OBJ_ERR_BAD_CHECKSUM;
    }
    memcpy(expect.raw, parsed.raw, parsed.raw_len);
    expect.raw_len = parsed.raw_len;
  }
  if (expect.raw_len != computed->raw_len || memcmp(expect.raw, computed->raw, computed->raw_len) != 0) {
    return BUCKETS_OBJ_ERR_BAD_CHECKSUM;
  }
  x->result = expect;
  if (o) {
    buckets_buf stored = BUCKETS_BUF_INIT;
    buckets_checksum_append(&expect, NULL, 0, &stored);
    buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, BUCKETS_CKSUM_META, stored.data, stored.len);
    buckets_buf_free(&stored);
  }
  return BUCKETS_OBJ_OK;
}

static void cks_echo(buckets_http_response *resp, const cks_ctx *x) {
  if (!x->result.type) return;
  char enc[64];
  buckets_checksum_encode(&x->result, enc);
  buckets_http_resp_header(resp, buckets_cksum_header(x->result.type), enc);
}

/* The plaintext of a compressed write, hashed as the compressor reads it. */
typedef struct {
  buckets_read_fn rd;
  void *ud;
  buckets_md5_ctx md5;
  buckets_sha256_ctx sha;
  buckets_cksum_hasher cks;
  uint32_t cks_type;
  int64_t size;
} plain_hasher;

static void plain_hasher_init(plain_hasher *h, buckets_read_fn rd, void *ud, uint32_t cks_type) {
  memset(h, 0, sizeof(*h));
  h->rd = rd, h->ud = ud;
  buckets_md5_init(&h->md5);
  buckets_sha256_init(&h->sha);
  h->cks_type = cks_type;
  if (cks_type) buckets_cksum_hasher_init(&h->cks, cks_type);
}

static long plain_hasher_read(void *ud, void *buf, size_t n) {
  plain_hasher *h = ud;
  long k = h->rd(h->ud, buf, n);
  if (k > 0) {
    buckets_md5_update(&h->md5, buf, (size_t)k);
    buckets_sha256_update(&h->sha, buf, (size_t)k);
    if (h->cks_type) buckets_cksum_hasher_update(&h->cks, buf, (size_t)k);
    h->size += k;
  }
  return k;
}

/* Transformed writes (encrypted and/or compressed): the object layer stores
 * DARE packages or S2 streams, so the digests, checksum and ETag are
 * computed over the plaintext here and settled just before the version
 * commits. Compressed writes hash in ph ahead of the compressor, encrypted
 * ones otherwise in the SSE writer. */
typedef struct {
  cks_ctx *cx;
  buckets_sse_writer *w; /* encrypted writes */
  const body_src *b;
  uint8_t key[32]; /* the object key (parts are sealed with it too) */
  buckets_xl_kv *sys;
  size_t nsys;
  uint8_t md5[16]; /* of the plaintext, once read */
  plain_hasher ph;
  buckets_s2_writer cw;
  bool compressed;
  buckets_buf index; /* a compressed part's index, as recorded */
} sse_put;

/* The read end of a transformed write over rd (size plaintext bytes, -1
 * unknown): compress when p->compressed, then encrypt when p->nsys holds a
 * new key (key given for parts: a part key and its nonce). Returns the read
 * function; *size becomes the stored size (-1 when compressed). */
static buckets_read_fn xform_open(sse_put *p, buckets_read_fn rd, void *ud, int64_t *size, uint32_t cks_type,
                                  const uint8_t *enc_key, const uint8_t *nonce, bool encrypt, bool pad, void **out_ud) {
  if (p->compressed) {
    plain_hasher_init(&p->ph, rd, ud, cks_type);
    buckets_s2_writer_init(&p->cw, plain_hasher_read, &p->ph, *size, pad ? BUCKETS_COMPRESS_PAD_ENCRYPTED : 0);
    rd = buckets_s2_writer_read, ud = &p->cw;
    *size = -1;
  }
  if (encrypt) {
    buckets_sse_writer_init_nonce(p->w, enc_key, nonce, rd, ud, *size, p->compressed ? 0 : cks_type);
    p->w->no_hash = p->compressed;
    rd = buckets_sse_writer_read, ud = p->w;
    if (*size >= 0) *size = (int64_t)buckets_dare_encrypted_size((uint64_t)*size);
  } else {
    p->w = NULL;
  }
  *out_ud = ud;
  return rd;
}

static void xform_close(sse_put *p) {
  if (p->w) buckets_sse_writer_free(p->w);
  if (p->compressed) buckets_s2_writer_free(&p->cw);
  buckets_buf_free(&p->index);
}

/* The compressed stream's index, sealed with the object key when encrypted
 * (opts.IndexCB), into p->index; false when none is due. */
static bool xform_index(sse_put *p) {
  buckets_buf_free(&p->index);
  if (!p->compressed) return false;
  buckets_buf idx = BUCKETS_BUF_INIT;
  if (!buckets_s2_writer_index(&p->cw, BUCKETS_COMPRESS_MIN_INDEX_SIZE, &idx)) return false;
  if (p->w) buckets_s3_compress_seal_index(p->key, idx.data, idx.len, &p->index);
  else buckets_buf_append(&p->index, idx.data, idx.len);
  buckets_buf_free(&idx);
  return p->index.len > 0;
}

/* metadataEncrypter(key)("object-checksum", ...) over the stored checksum. */
static void seal_checksum_meta(const uint8_t key[32], buckets_xl_object *o) {
  const buckets_xl_kv *kv = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, BUCKETS_CKSUM_META);
  if (!kv || !kv->value_len) return;
  uint8_t k[32];
  buckets_hmac_sha256(key, 32, "object-checksum", 15, k);
  size_t n = buckets_dare_encrypted_size(kv->value_len);
  uint8_t *enc = buckets_xmalloc(n);
  buckets_dare_encrypt_buffer(k, kv->value, kv->value_len, enc);
  buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, BUCKETS_CKSUM_META, enc, n);
  free(enc);
}

static buckets_obj_err sse_pre_commit(void *ud, const buckets_checksum *computed, buckets_xl_object *o) {
  (void)computed;
  sse_put *p = ud;
  buckets_md5_ctx *mc = p->compressed ? &p->ph.md5 : &p->w->md5;
  buckets_sha256_ctx *sc = p->compressed ? &p->ph.sha : &p->w->sha;
  buckets_cksum_hasher *kc = p->compressed ? &p->ph.cks : &p->w->cks;
  int64_t plain_size = p->compressed ? p->ph.size : p->w->plain_size;
  uint8_t *md5 = p->md5, sha[32];
  buckets_md5_final(mc, md5);
  buckets_sha256_final(sc, sha);
  if (p->b->has_md5 && memcmp(md5, p->b->md5, 16) != 0) return BUCKETS_OBJ_ERR_BAD_DIGEST;
  if (p->b->want_sha && memcmp(sha, p->b->sha, 32) != 0) return BUCKETS_OBJ_ERR_SHA256_MISMATCH;
  if (p->cx->want.type) {
    buckets_checksum plain = {.type = p->cx->want.type & BUCKETS_CKSUM_BASE_MASK};
    plain.raw_len = buckets_cksum_hasher_final(kc, plain.raw);
    buckets_obj_err e = cks_pre_commit(p->cx, &plain, o);
    if (e) return e;
  }
  if (!o) return BUCKETS_OBJ_OK; /* a multipart part */
  if (p->w) {
    seal_checksum_meta(p->key, o);
    buckets_buf sealed = BUCKETS_BUF_INIT;
    buckets_objkey_seal_etag(p->key, md5, 16, &sealed);
    char hex[200];
    buckets_hex_encode((uint8_t *)sealed.data, sealed.len, hex);
    buckets_xl_kv_set(&o->meta_user, &o->nmeta_user, "etag", hex, strlen(hex));
    buckets_buf_free(&sealed);
    for (size_t i = 0; i < p->nsys; i++)
      buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, p->sys[i].key, p->sys[i].value, p->sys[i].value_len);
  } else {
    char hex[33];
    buckets_hex_encode(md5, 16, hex);
    buckets_xl_kv_set(&o->meta_user, &o->nmeta_user, "etag", hex, 32);
  }
  if (p->compressed) {
    char as[32];
    int n = snprintf(as, sizeof(as), "%lld", (long long)plain_size);
    buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, BUCKETS_COMPRESS_META, BUCKETS_COMPRESS_ALGO_V2,
                      strlen(BUCKETS_COMPRESS_ALGO_V2));
    buckets_xl_kv_set(&o->meta_sys, &o->nmeta_sys, BUCKETS_ACTUAL_SIZE_META, as, (size_t)n);
    if (o->nparts && xform_index(p)) buckets_xl_part_set_index(&o->parts[0], p->index.data, p->index.len);
  }
  if (o->nparts) o->parts[0].actual_size = plain_size;
  return BUCKETS_OBJ_OK;
}

/* An encrypted part records its sealed plaintext MD5, plaintext size and
 * plaintext checksum (the object layer saw only DARE packages). */
static void sse_part_commit(void *ud, buckets_part_info *pi) {
  sse_put *p = ud;
  if (p->w) {
    buckets_buf sealed = BUCKETS_BUF_INIT;
    buckets_objkey_seal_etag(p->key, p->md5, 16, &sealed);
    buckets_hex_encode((uint8_t *)sealed.data, sealed.len, pi->etag);
    buckets_buf_free(&sealed);
  } else {
    buckets_hex_encode(p->md5, 16, pi->etag);
  }
  pi->actual_size = p->compressed ? p->ph.size : p->w->plain_size;
  if (xform_index(p)) pi->index = (const uint8_t *)p->index.data, pi->index_len = p->index.len;
  if (p->cx && p->cx->result.type) pi->cksum = p->cx->result;
  else memset(&pi->cksum, 0, sizeof(pi->cksum));
}

/* tryDecryptETag: a stored (sealed) part ETag as clients were given it. */
static void sse_part_etag(const uint8_t *key, bool sse_s3, const char *stored, char out[128]) {
  size_t n = strlen(stored);
  snprintf(out, 128, "%s", stored);
  if (n <= 32) return;
  if (!sse_s3 || !key) {
    snprintf(out, 128, "%s", stored + n - 32);
    return;
  }
  uint8_t raw[64];
  buckets_buf plain = BUCKETS_BUF_INIT;
  if (n % 2 == 0 && n / 2 <= sizeof(raw) && buckets_hex_decode(stored, n, raw) &&
      buckets_objkey_unseal_etag(key, raw, n / 2, &plain) && plain.len <= 32)
    buckets_hex_encode((uint8_t *)plain.data, plain.len, out);
  buckets_buf_free(&plain);
}

/* The DARE nonce of a part: SHA-256(uploadID || partNumber)[:12], as MinIO derives it. */
static void part_nonce(const char *upload_id, int part, uint8_t nonce[12]) {
  char buf[256];
  int n = snprintf(buf, sizeof(buf), "%s%d", upload_id, part);
  uint8_t sum[32];
  buckets_sha256(buf, (size_t)n, sum);
  memcpy(nonce, sum, 12);
}

buckets_s3_error buckets_s3_sse_put(s3_ctx *c, const buckets_sse_req *r, const char *object, buckets_read_fn rd, void *ud,
                                    int64_t size, const buckets_xl_kv *meta, size_t nmeta, const buckets_checksum *want,
                                    buckets_object_info *out, char etag_out[80]) {
  cks_ctx cx = {0};
  if (want && want->type) cx.want = *want;
  body_src nob = {0};
  sse_put sp = {.cx = &cx, .b = &nob};
  buckets_s3_error e = buckets_s3_sse_new_key(c, r, c->bucket, object, sp.key, &sp.sys, &sp.nsys);
  if (e) return e;
  buckets_sse_writer w;
  buckets_sse_writer_init(&w, sp.key, rd, ud, size, cx.want.type & BUCKETS_CKSUM_BASE_MASK);
  sp.w = &w;
  buckets_put_opts opts = {.meta = meta, .nmeta = nmeta, .pre_commit = sse_pre_commit, .pre_commit_ud = &sp};
  bool suspended;
  buckets_s3_versioning(c, object, &opts.versioned, &suspended);
  buckets_obj_err err = buckets_obj_put(c->s->layer, c->bucket, object, buckets_sse_writer_read, &w,
                                        (int64_t)buckets_dare_encrypted_size((uint64_t)size), &opts, out);
  buckets_sse_writer_free(&w);
  free_kvs(sp.sys, sp.nsys);
  if (!err) buckets_s3_sse_client_etag(c, out, sp.key, etag_out);
  OPENSSL_cleanse(sp.key, sizeof(sp.key));
  return err ? buckets_s3_obj_error(err) : BUCKETS_ERR_NONE;
}

/* The response of an encrypted write: its SSE headers and the ETag clients see. */
static void sse_put_response(s3_ctx *c, const buckets_object_info *oi, const uint8_t key[32]) {
  char etag[80];
  buckets_s3_sse_client_etag(c, oi, key, etag);
  etag_header(c->resp, etag);
  buckets_s3_sse_headers(c, oi);
}

/* checkPreconditionsPUT (PutObject, CreateMultipartUpload and
 * CompleteMultipartUpload): If-Match / If-None-Match against the current
 * version's ETag, as clients see it. An If-Match on a missing object is
 * NoSuchKey. Returns true when a response was written. */
static bool etag_matches(const char *etag, buckets_str given);
static bool put_preconditions(s3_ctx *c, const char *object) {
  buckets_str im = buckets_http_header_get(c->req, "If-Match");
  buckets_str inm = buckets_http_header_get(c->req, "If-None-Match");
  bool has_im = im.p && im.n, has_inm = inm.p && inm.n;
  if (!has_im && !has_inm) return false;
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, object, NULL, &oi);
  if (!err && oi.delete_marker) {
    buckets_object_info_free(&oi);
    err = BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (err) {
    if (err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
      buckets_s3_write_error(c, buckets_s3_obj_error(err));
      return true;
    }
    if (has_im) {
      buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_KEY);
      return true;
    }
    return false;
  }
  if (buckets_s3_sse_encrypted(&oi)) {
    char etag[80];
    buckets_s3_sse_client_etag(c, &oi, NULL, etag);
    snprintf(oi.etag, sizeof(oi.etag), "%s", etag);
  }
  bool failed = (has_im && !etag_matches(oi.etag, im)) || (has_inm && etag_matches(oi.etag, inm));
  if (failed) {
    char lm[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http((time_t)(oi.mod_time_ns / 1000000000LL), lm);
    buckets_http_resp_header(c->resp, "Last-Modified", lm);
    if (oi.etag[0]) etag_header(c->resp, oi.etag);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
  }
  buckets_object_info_free(&oi);
  return failed;
}

static void put_object(s3_ctx *c) {
  if (buckets_http_header_get(c->req, "X-Amz-Copy-Source").p) {
    copy_object(c);
    return;
  }
  if (put_preconditions(c, c->object)) return;
  body_src b;
  buckets_s3_error serr = body_open(c, &b);
  if (!serr && b.size > BUCKETS_S3_MAX_OBJECT_SIZE) serr = BUCKETS_ERR_ENTITY_TOO_LARGE;
  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  if (!serr) serr = extract_metadata(c, &meta, &nmeta);
  if (!serr && !buckets_s3_check_tagging_header(c)) {
    free_kvs(meta, nmeta);
    body_close(&b);
    return;
  }
  if (!serr && !buckets_s3_enforce_quota(c, c->bucket, b.size)) {
    free_kvs(meta, nmeta);
    body_close(&b);
    return;
  }
  if (!serr) serr = buckets_s3_lock_put_meta(c, c->object, &meta, &nmeta);
  if (serr) {
    free_kvs(meta, nmeta);
    body_close(&b);
    buckets_s3_write_error(c, serr);
    return;
  }
  buckets_s3_repl_in ri;
  if (!buckets_s3_repl_in_parse(c, c->object, true, &ri)) {
    free_kvs(meta, nmeta);
    body_close(&b);
    return;
  }
  buckets_s3_repl_in_meta(c, &ri, &meta, &nmeta);
  repl_ssec_checksum(&meta, &nmeta);
  buckets_repl_dsc dsc;
  buckets_s3_repl_out_meta(c, c->object, &meta, &nmeta, ri.request, &dsc);
  buckets_put_opts opts = {
      .meta = meta,
      .nmeta = nmeta,
      .want_md5 = b.has_md5 ? b.md5 : NULL,
      .want_sha256 = b.want_sha ? b.sha : NULL,
      .pre_commit = cks_pre_commit,
      .version_id = ri.has_vid ? ri.version_id : NULL,
      .mod_time_ns = ri.mtime_ns,
  };
  bool suspended;
  buckets_s3_versioning(c, c->object, &opts.versioned, &suspended);
  cks_ctx cx;
  if ((serr = cks_open(c, &b, &cx, &opts)) != BUCKETS_ERR_NONE) {
    free_kvs(meta, nmeta);
    body_close(&b);
    buckets_s3_write_error(c, serr);
    return;
  }
  opts.pre_commit_ud = &cx;
  char why[200];
  if (!buckets_s3_sse_put_opts(c, why, sizeof(why))) {
    char msg[400];
    snprintf(msg, sizeof(msg), "Invalid arguments provided for %s/%s: (%s)", c->bucket, c->object, why);
    free_kvs(meta, nmeta);
    body_close(&b);
    buckets_s3_write_custom_error(c, 400, "InvalidArgument", msg);
    return;
  }
  buckets_sse_req sse;
  serr = buckets_s3_sse_parse(c, &sse);
  sse_put sp = {.cx = &cx, .b = &b};
  buckets_sse_writer w;
  bool encrypt = !serr && sse.kind;
  if (encrypt) serr = buckets_s3_sse_new_key(c, &sse, c->bucket, c->object, sp.key, &sp.sys, &sp.nsys);
  buckets_sse_req_free(&sse);
  if (serr) {
    free_kvs(meta, nmeta);
    free_kvs(sp.sys, sp.nsys);
    body_close(&b);
    buckets_s3_sse_write_error(c, serr);
    return;
  }
  buckets_read_fn rd = b.rd;
  void *rd_ud = b.rd_ud;
  int64_t size = b.size;
  sp.compressed = buckets_s3_compressible(c, c->object, encrypt) && b.size > BUCKETS_COMPRESS_MIN_SIZE;
  bool xform = encrypt || sp.compressed;
  if (xform) {
    sp.w = &w;
    rd = xform_open(&sp, b.rd, b.rd_ud, &size, cx.want.type & BUCKETS_CKSUM_BASE_MASK, sp.key, NULL, encrypt,
                    encrypt, &rd_ud);
    opts.want_md5 = opts.want_sha256 = NULL;
    opts.checksum_type = 0;
    opts.pre_commit = sse_pre_commit;
    opts.pre_commit_ud = &sp;
    opts.actual_size = b.size;
  }
  /* PreserveETag: a replica keeps its source's ETag, unless SSE-S3 re-encrypts it */
  if (ri.etag[0] && !(ri.request && encrypt && buckets_s3_sse_s3_or_kms_requested(c) && sp.nsys &&
                      buckets_xl_kv_get(sp.sys, sp.nsys, BUCKETS_SSE_META_SEALED_S3)))
    opts.preserve_etag = ri.etag;
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_put(c->s->layer, c->bucket, c->object, rd, rd_ud, size, &opts, &oi);
  free_kvs(meta, nmeta);
  if (xform) xform_close(&sp);
  if (err) {
    buckets_repl_dsc_free(&dsc);
    buckets_s3_write_error(c, body_error(&b, err));
  } else {
    if (encrypt) sse_put_response(c, &oi, sp.key);
    else etag_header(c->resp, oi.etag);
    buckets_s3_version_header(c, oi.version_id);
    oi.is_latest = true; /* the version just written */
    buckets_s3_expiration_header(c, &oi);
    cks_echo(c->resp, &cx);
    c->resp->status = 200;
    buckets_s3_send_event_early(c, BUCKETS_EV_OBJECT_CREATED_PUT, c->bucket, c->object, &oi, NULL);
    buckets_repl_schedule(c->s, c->bucket, &oi, &dsc, BUCKETS_REPL_OBJECT, "replicate:incoming");
    buckets_repl_dsc_free(&dsc);
    if (ri.replica) buckets_repl_stats_replica(c->bucket, b.size);
    buckets_object_info_free(&oi);
  }
  free_kvs(sp.sys, sp.nsys);
  OPENSSL_cleanse(sp.key, sizeof(sp.key));
  body_close(&b);
}

/* ---- GetObject / HeadObject ----------------------------------------------- */

typedef struct {
  bool present;
  bool suffix;
  int64_t start, end; /* end -1: open-ended; suffix: start = length */
} range_spec;

/* parseRequestRangeSpec: returns false only for errInvalidRange (416);
 * other malformed ranges are ignored like S3 does. */
static bool parse_range(buckets_str h, range_spec *rs) {
  memset(rs, 0, sizeof(*rs));
  if (!h.p || !buckets_str_has_prefix(h, "bytes=")) return true;
  char *s = buckets_xstrndup(h.p + 6, h.n - 6);
  char *dash = strchr(s, '-');
  bool ok = true;
  if (dash) {
    *dash = '\0';
    const char *a = s, *b = dash + 1;
    int64_t begin = -1, end = -1;
    char *e;
    bool valid = true;
    if (*a) {
      if (*a == '+' || !isdigit((unsigned char)*a)) valid = false;
      begin = strtoll(a, &e, 10);
      if (*e) valid = false;
    }
    if (*b) {
      if (*b == '+' || !isdigit((unsigned char)*b)) valid = false;
      end = strtoll(b, &e, 10);
      if (*e) valid = false;
    }
    if (valid) {
      if (begin > -1 && end > -1) {
        if (begin > end) ok = false;
        else *rs = (range_spec){true, false, begin, end};
      } else if (begin > -1) {
        *rs = (range_spec){true, false, begin, -1};
      } else if (end > -1) {
        if (end == 0) ok = false;
        else *rs = (range_spec){true, true, end, -1};
      }
    }
  }
  free(s);
  return ok;
}

/* GetOffsetLength. Returns false for an unsatisfiable range. */
static bool resolve_range(const range_spec *rs, int64_t size, int64_t *off, int64_t *len) {
  if (!rs->present) {
    *off = 0;
    *len = size;
    return true;
  }
  if (rs->suffix) {
    *len = BUCKETS_MIN(rs->start, size);
    *off = size - *len;
    return true;
  }
  if (rs->start >= size) return false;
  int64_t end = rs->end > -1 && rs->end < size ? rs->end : size - 1;
  *off = rs->start;
  *len = end - rs->start + 1;
  return true;
}

/* InvalidRange from HTTPRangeSpec.GetLength: the range as given (an open end
 * is -1) and the object's size. */
static void write_invalid_range(s3_ctx *c, const range_spec *rs, int64_t size) {
  char msg[160];
  snprintf(msg, sizeof(msg), "The requested range 'bytes=%lld-%lld' is not satisfiable", (long long)rs->start,
           (long long)rs->end);
  buckets_s3_write_error_msg(c, BUCKETS_ERR_INVALID_RANGE, msg);
  buckets_buf *b = &c->resp->body;
  if (b->len >= 8 && memcmp(b->data + b->len - 8, "</Error>", 8) == 0) b->len -= 8;
  buckets_buf_appendf(b, "<ActualObjectSize>%lld</ActualObjectSize><RangeRequested>%lld-%lld</RangeRequested></Error>",
                      (long long)size, (long long)rs->start, (long long)rs->end);
}

/* canonicalizeETag + isETagEqual */
static bool etag_matches(const char *etag, buckets_str given) {
  given = buckets_str_trim(given);
  if (buckets_str_eq_c(given, "*")) return true;
  while (given.n && given.p[0] == '"') {
    given.p++;
    given.n--;
  }
  while (given.n && given.p[given.n - 1] == '"') given.n--;
  return buckets_str_eq_c(given, etag);
}

static void write_object_headers_min(s3_ctx *c, const buckets_object_info *oi) {
  char lm[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http((time_t)(oi->mod_time_ns / 1000000000LL), lm);
  buckets_http_resp_header(c->resp, "Last-Modified", lm);
  if (oi->etag[0]) etag_header(c->resp, oi->etag);
  const char *cc = buckets_object_meta(oi, "cache-control");
  if (cc) buckets_http_resp_header(c->resp, "Cache-Control", cc);
}

/* checkPreconditions: returns true when a response was written. */
static bool check_preconditions(s3_ctx *c, const buckets_object_info *oi) {
  time_t mt = (time_t)(oi->mod_time_ns / 1000000000LL);
  buckets_str inm = buckets_http_header_get(c->req, "If-None-Match");
  if (inm.p && inm.n && etag_matches(oi->etag, inm)) {
    write_object_headers_min(c, oi);
    c->resp->status = 304;
    return true;
  }
  time_t t;
  buckets_str ims = buckets_http_header_get(c->req, "If-Modified-Since");
  if (ims.p && buckets_time_parse_http(ims, &t) && oi->mod_time_ns < (int64_t)(t + 1) * 1000000000LL) {
    write_object_headers_min(c, oi);
    c->resp->status = 304;
    return true;
  }
  buckets_str im = buckets_http_header_get(c->req, "If-Match");
  if (im.p && im.n && !etag_matches(oi->etag, im)) {
    write_object_headers_min(c, oi);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return true;
  }
  buckets_str ius = buckets_http_header_get(c->req, "If-Unmodified-Since");
  if (ius.p && !(im.p && im.n) && buckets_time_parse_http(ius, &t) &&
      oi->mod_time_ns >= (int64_t)(t + 1) * 1000000000LL) {
    write_object_headers_min(c, oi);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return true;
  }
  (void)mt;
  return false;
}

/* setObjectHeaders (user metadata as MinIO emits it). */
static void write_object_headers(s3_ctx *c, const buckets_object_info *oi) {
  write_object_headers_min(c, oi);
  const char *user_tags = buckets_object_meta(oi, "X-Amz-Tagging");
  int ntags = buckets_s3_tag_count(user_tags);
  if (ntags > 0) {
    char n[16];
    snprintf(n, sizeof(n), "%d", ntags);
    buckets_http_resp_header(c->resp, "x-amz-tagging-count", n);
    /* MinIO extension: the tags themselves, on request. */
    buckets_str d = buckets_http_header_get(c->req, "X-Amz-Tagging-Directive");
    if (d.p && buckets_str_eq_c(d, "ACCESS")) buckets_http_resp_header(c->resp, "X-Amz-Tagging", user_tags);
  }
  for (size_t i = 0; i < oi->nmeta; i++) {
    const char *k = oi->meta[i].key;
    const char *v = (const char *)oi->meta[i].value;
    if (has_prefix_fold(k, BUCKETS_XL_RESERVED_PREFIX) || strcasecmp(k, "expires") == 0 ||
        strcasecmp(k, "cache-control") == 0 || strcasecmp(k, "X-Amz-Tagging") == 0) {
      continue;
    }
    if (has_prefix_fold(k, "x-amz-meta-") || has_prefix_fold(k, "x-minio-meta-")) {
      char lower[256];
      size_t j = 0;
      for (; k[j] && j + 1 < sizeof(lower); j++) lower[j] = (char)tolower((unsigned char)k[j]);
      lower[j] = '\0';
      buckets_http_resp_header(c->resp, lower, v);
    } else {
      char canon[256];
      canonical_key(k, canon, sizeof(canon));
      buckets_http_resp_header(c->resp, canon, v);
    }
  }
  const char *exp = buckets_object_meta(oi, "expires");
  time_t et;
  if (exp && buckets_time_parse_http(buckets_str_c(exp), &et)) {
    char buf[BUCKETS_TIME_HTTP_LEN + 1];
    buckets_time_http(et, buf);
    buckets_http_resp_header(c->resp, "Expires", buf);
  }
}

/* response-* query overrides (setHeadGetRespHeaders). */
static void response_overrides(s3_ctx *c) {
  static const struct {
    const char *param, *header;
  } map[] = {{"response-content-type", "Content-Type"},
             {"response-content-language", "Content-Language"},
             {"response-expires", "Expires"},
             {"response-cache-control", "Cache-Control"},
             {"response-content-disposition", "Content-Disposition"},
             {"response-content-encoding", "Content-Encoding"}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(map); i++) {
    const char *v = buckets_query_get(&c->q, map[i].param);
    if (v) buckets_http_resp_header_set(c->resp, map[i].header, v);
  }
}

static void reader_free(void *ud) { buckets_obj_reader_free(ud); }

/* ---- active-active proxying (proxyGetToReplicationTarget) ---- */

static long proxy_read(void *ud, void *buf, size_t n) {
  buckets_repl_proxy *p = ud;
  return buckets_http_stream_read(p->body, buf, n);
}

static void proxy_free(void *ud) {
  buckets_repl_proxy *p = ud;
  buckets_repl_proxy_close(p);
  free(p);
}

/* A version missing here is served from a replication target, when the
 * request is not itself a proxied one. Returns true when answered. */
static bool proxy_to_target(s3_ctx *c, const char *version, bool head, buckets_str range) {
  if (!c->s->repl || buckets_http_header_get(c->req, BUCKETS_H_SRC_PROXY).p) return false;
  char *rg = range.p ? buckets_str_dup(range) : NULL;
  buckets_repl_proxy *p = buckets_xcalloc(1, sizeof(*p));
  bool ok = buckets_repl_proxy_open(c->s->repl, c->bucket, c->object, version, rg, head, p);
  free(rg);
  if (!ok) {
    free(p);
    return false;
  }
  static const char *const skip[] = {"Date", "Server", "Content-Length", "Connection", "Transfer-Encoding", "Keep-Alive",
                                     "X-Amz-Request-Id", "X-Amz-Id-2", "Vary", "Accept-Ranges",
                                     "Strict-Transport-Security", "X-Content-Type-Options", "X-Xss-Protection",
                                     "X-Ratelimit-Limit", "X-Ratelimit-Remaining"};
  buckets_str rest = buckets_buf_str(&p->res.headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str name, value;
    if (!buckets_str_cut(line, ':', &name, &value)) continue;
    name = buckets_str_trim(name);
    value = buckets_str_trim(value);
    if (value.n && value.p[value.n - 1] == '\r') value.n--;
    bool drop = false;
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(skip) && !drop; i++) drop = buckets_str_ieq_c(name, skip[i]);
    if (drop) continue;
    char *n = buckets_str_dup(name), *v = buckets_str_dup(value);
    buckets_http_resp_header(c->resp, n, v);
    free(n);
    free(v);
  }
  char cl[32];
  buckets_s3c_header_copy(&p->res, "Content-Length", cl, sizeof(cl));
  c->resp->status = p->res.status;
  c->resp->content_length = cl[0] ? strtoll(cl, NULL, 10) : 0;
  if (head || !p->body) {
    proxy_free(p);
  } else {
    c->resp->stream = (buckets_http_body_fn)proxy_read;
    c->resp->stream_ud = p;
    c->resp->stream_free = proxy_free;
  }
  return true;
}

static void get_object(s3_ctx *c, bool head) {
  /* "If SSE-S3 or SSE-KMS present -> AWS fails with undefined error" */
  if (buckets_s3_sse_s3_or_kms_requested(c)) {
    buckets_s3_write_error(c, BUCKETS_ERR_BAD_REQUEST);
    return;
  }
  buckets_s3_error oerr = buckets_s3_sse_get_opts(c);
  if (oerr) {
    buckets_s3_write_error(c, oerr);
    return;
  }
  const char *version = buckets_query_get(&c->q, "versionId");
  const char *pn_s = buckets_query_get(&c->q, "partNumber");
  long part_number = 0;
  if (pn_s) {
    char *end;
    part_number = strtol(pn_s, &end, 10);
    if (!*pn_s || *end || part_number < 1 || part_number > BUCKETS_MAX_PARTS) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_PART_NUMBER);
      return;
    }
    if (buckets_http_header_get(c->req, "Range").p) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_REQUEST); /* S3: Range and partNumber are exclusive */
      return;
    }
  }
  /* A malformed range fails before the object is looked up. */
  range_spec rs;
  if (!part_number && !parse_range(buckets_http_header_get(c->req, "Range"), &rs)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_RANGE);
    return;
  }
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, c->object, version, &oi);
  if ((err == BUCKETS_OBJ_ERR_NO_SUCH_KEY || err == BUCKETS_OBJ_ERR_NO_SUCH_VERSION ||
       err == BUCKETS_OBJ_ERR_READ_QUORUM) &&
      proxy_to_target(c, version, head, buckets_http_header_get(c->req, "Range")))
    return;
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  if (oi.delete_marker) {
    /* getObjectInfo: a delete marker is not found, or, asked for by its
     * version ID, not a method that applies; its headers say which. */
    const buckets_xl_kv *ps = buckets_object_sys(&oi, BUCKETS_META_PURGE_STATUS);
    char rst[32];
    if (ps && ps->value_len) {
      buckets_http_resp_header(c->resp, "X-Minio-Replication-Delete-Status",
                               buckets_repl_composite_purge((const char *)ps->value));
    } else if (buckets_repl_version_status(&oi, rst, sizeof(rst))) {
      buckets_http_resp_header(c->resp, "X-Minio-Replication-DeleteMarker-Status", rst);
    }
    if (strcmp(oi.version_id, "null") != 0) {
      buckets_http_resp_header(c->resp, "x-amz-version-id", oi.version_id);
      buckets_http_resp_header(c->resp, "x-amz-delete-marker", "true");
    }
    buckets_str rr = buckets_http_header_get(c->req, BUCKETS_H_CHECK_REPL_READY);
    if (rr.p && buckets_str_eq_c(rr, "true")) {
      /* the replicated marker may follow: the object has a version here */
      buckets_object_info latest;
      if (buckets_obj_stat(c->s->layer, c->bucket, c->object, NULL, &latest) == BUCKETS_OBJ_OK) {
        buckets_http_resp_header(c->resp, BUCKETS_H_REPL_READY, "true");
        buckets_object_info_free(&latest);
      }
    }
    buckets_s3_write_error(c, version && *version ? BUCKETS_ERR_METHOD_NOT_ALLOWED : BUCKETS_ERR_NO_SUCH_KEY);
    buckets_object_info_free(&oi);
    return;
  }
  {
    /* the replication status clients see (FileInfo's composite status) */
    char rst[32];
    if (buckets_repl_version_status(&oi, rst, sizeof(rst)))
      buckets_xl_kv_set(&oi.meta, &oi.nmeta, BUCKETS_H_REPL_STATUS, rst, strlen(rst));
  }
  /* DecryptObjectInfo: request checks, the key, and what clients see */
  buckets_s3_error serr = buckets_s3_sse_check_read(c, &oi, false);
  bool encrypted = !serr && buckets_s3_sse_encrypted(&oi);
  uint8_t key[32];
  bool have_key = false;
  if (!serr && encrypted && (buckets_s3_sse_kind_of(&oi) == BUCKETS_SSE_C || !head)) {
    serr = buckets_s3_sse_object_key(c, &oi, c->bucket, c->object, false, key);
    have_key = !serr;
  }
  if (serr) {
    buckets_object_info_free(&oi);
    buckets_s3_sse_write_error(c, serr);
    return;
  }
  int64_t stored_size = oi.size;
  bool compressed = buckets_s3_is_compressed(&oi);
  if (encrypted) {
    char etag[80];
    buckets_s3_sse_client_etag(c, &oi, have_key ? key : NULL, etag);
    snprintf(oi.etag, sizeof(oi.etag), "%s", etag);
  }
  if (encrypted || compressed) oi.size = buckets_s3_actual_size(&oi);
  if (part_number > 1) {
    bool found = false;
    for (size_t i = 0; i < oi.nparts; i++) found |= oi.parts[i].number == part_number;
    if (!found || (size_t)part_number > oi.nparts) {
      buckets_object_info_free(&oi);
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_PART_NUMBER);
      return;
    }
  }
  if (check_preconditions(c, &oi)) {
    buckets_object_info_free(&oi);
    return;
  }
  int64_t off = 0, len = oi.size;
  if (part_number > 0) {
    /* partNumberToRangeSpec: index-based over the object's parts. */
    int64_t start = 0;
    for (long i = 0; i < part_number - 1 && (size_t)i < oi.nparts; i++) start += oi.parts[i].actual_size;
    int64_t plen = oi.nparts >= (size_t)part_number ? oi.parts[part_number - 1].actual_size : oi.size;
    rs = (range_spec){true, false, start, start + plen - 1};
    if (plen == 0) rs.end = -1;
  }
  if (!resolve_range(&rs, oi.size, &off, &len)) {
    write_invalid_range(c, &rs, oi.size);
    buckets_object_info_free(&oi);
    return;
  }

  buckets_obj_reader *r = NULL;
  buckets_sse_reader *sr = NULL;
  buckets_comp_reader *cr = NULL;
  compressed = compressed && len > 0;
  if (!head) {
    buckets_object_info oi2;
    int64_t roff = off, rlen = len;
    buckets_sse_range rg;
    buckets_comp_range crg;
    if (compressed) {
      /* From the block (or part) holding off to the end of the stored object. */
      buckets_s3_compressed_range(&oi, have_key ? key : NULL, off, &crg);
      roff = crg.stored_off, rlen = stored_size - crg.stored_off;
    } else if (encrypted) {
      int64_t plain = oi.size;
      oi.size = stored_size;
      buckets_s3_sse_range(&oi, off, len, &rg);
      oi.size = plain;
      roff = rg.enc_off, rlen = rg.enc_len;
    }
    err = buckets_obj_open(c->s->layer, c->bucket, c->object, version, roff, rlen, &r, &oi2);
    if (err) {
      buckets_object_info_free(&oi);
      buckets_s3_write_error(c, buckets_s3_obj_error(err));
      return;
    }
    buckets_object_info_free(&oi2);
    if (compressed) {
      cr = buckets_comp_reader_new(&oi, stored_size, have_key ? key : NULL, &crg, len, (buckets_read_fn)reader_source, r,
                                   reader_free);
      r = NULL;
    } else if (encrypted) {
      int64_t plain = oi.size;
      oi.size = stored_size;
      sr = buckets_sse_reader_new(&oi, key, &rg, len, (buckets_read_fn)reader_source, r, reader_free);
      oi.size = plain;
      r = NULL;
    }
  }
  if (have_key) OPENSSL_cleanse(key, sizeof(key));
  const char *user_tags = buckets_object_meta(&oi, "X-Amz-Tagging");
  if (user_tags && *user_tags && !c->audit_tagging) c->audit_tagging = buckets_xstrdup(user_tags);
  buckets_s3_lock_filter_meta(c, &oi);
  write_object_headers(c, &oi);
  buckets_s3_version_header(c, oi.version_id);
  buckets_s3_expiration_header(c, &oi);
  if (encrypted) buckets_s3_sse_headers(c, &oi);
  if (rs.present) {
    buckets_http_resp_headerf(c->resp, "Content-Range", "bytes %lld-%lld/%lld", (long long)off,
                              (long long)(off + len - 1), (long long)oi.size);
  }
  if (part_number > 0 && oi.nparts > 1) buckets_http_resp_headerf(c->resp, "x-amz-mp-parts-count", "%zu", oi.nparts);
  buckets_str cm = buckets_http_header_get(c->req, "X-Amz-Checksum-Mode");
  bool cmode = cm.p && buckets_str_eq_c(cm, "ENABLED") && oi.checksum && (!rs.present || part_number > 0);
  if (cmode && encrypted) {
    uint8_t ck[32];
    bool ok = buckets_s3_sse_object_key(c, &oi, c->bucket, c->object, false, ck) == BUCKETS_ERR_NONE;
    if (ok) buckets_s3_sse_unseal_checksum(ck, &oi);
    else {
      free(oi.checksum);
      oi.checksum = NULL;
    }
    OPENSSL_cleanse(ck, sizeof(ck));
    cmode = oi.checksum != NULL;
  }
  if (cmode) {
    buckets_checksum_write_headers(oi.checksum, oi.checksum_len, (int)part_number, c->resp);
  }
  if (!head) response_overrides(c);
  c->resp->status = rs.present || part_number > 0 ? 206 : 200;
  c->resp->content_length = len;
  if (r) {
    c->resp->stream = (buckets_http_body_fn)reader_source;
    c->resp->stream_ud = r;
    c->resp->stream_free = reader_free;
  } else if (sr) {
    c->resp->stream = (buckets_http_body_fn)buckets_sse_reader_read;
    c->resp->stream_ud = sr;
    c->resp->stream_free = buckets_sse_reader_free;
  } else if (cr) {
    c->resp->stream = (buckets_http_body_fn)buckets_comp_reader_read;
    c->resp->stream_ud = cr;
    c->resp->stream_free = buckets_comp_reader_free;
  }
  buckets_s3_send_event(c, head ? BUCKETS_EV_OBJECT_ACCESSED_HEAD : BUCKETS_EV_OBJECT_ACCESSED_GET, c->bucket, c->object,
                        &oi, NULL);
  buckets_object_info_free(&oi);
}

/* ---- DeleteObject --------------------------------------------------------- */

/* EvalMetadataFn for deletes: checkReplicateDelete on the version found. */
typedef struct {
  s3_ctx *c;
  const char *version;
  bool versioned;
} del_decide;

static void delete_decide(void *ud, const buckets_object_info *goi, bool found, char **repl_status, char **purge_status) {
  del_decide *d = ud;
  (void)purge_status;
  buckets_repl_dsc dsc;
  buckets_repl_check_delete(d->c->s, d->c->bucket, d->c->object, d->version, found ? goi : NULL, d->versioned, false, &dsc);
  if (buckets_repl_dsc_any(&dsc)) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_repl_dsc_pending(&dsc, &p);
    buckets_buf_append_char(&p, '\0');
    *repl_status = buckets_buf_detach(&p);
  }
  buckets_repl_dsc_free(&dsc);
}

static bool bucket_replicates(s3_ctx *c) {
  if (!c->s->meta) return false;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool r = st->has_replication;
  buckets_bucket_state_release(st);
  return r;
}

static void delete_object(s3_ctx *c) {
  const char *version = buckets_query_get(&c->q, "versionId");
  if (version && *version && strcmp(version, "null") != 0) {
    uint8_t id[16];
    if (!buckets_xl_version_id_parse(version, id)) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_VERSION_ID);
      return;
    }
  }
  buckets_s3_repl_in ri;
  if (!buckets_s3_repl_in_parse(c, c->object, false, &ri)) return;
  /* a replicated delete marker is not there yet: no retention to check */
  buckets_s3_error lerr = ri.replica ? BUCKETS_ERR_NONE : buckets_s3_lock_check_delete(c, c->object, version);
  if (lerr) {
    buckets_s3_write_error(c, lerr);
    return;
  }
  buckets_delete_opts o = {.version_id = version, .replica = ri.replica, .replica_marker = ri.delete_marker,
                           .mod_time_ns = ri.mtime_ns};
  buckets_s3_versioning(c, c->object, &o.versioned, &o.suspended);
  if (ri.request) { /* delOpts: suspension applies at the bucket level only */
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
    o.suspended = st->versioning.status == BUCKETS_VERSIONING_SUSPENDED;
    buckets_bucket_state_release(st);
  }
  del_decide dd = {c, version, o.versioned};
  if (!ri.replica && o.versioned && bucket_replicates(c)) {
    o.decide = delete_decide;
    o.decide_ud = &dd;
  }
  buckets_delete_result res;
  buckets_obj_err err = buckets_obj_delete_ex(c->s->layer, c->bucket, c->object, &o, &res);
  /* S3 deletes are idempotent: a missing key still succeeds. */
  if (err && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  /* setPutObjHeaders(del): the version, and whether it is a delete marker, unless "null" */
  if (!err && strcmp(res.version_id, "null") != 0) {
    buckets_http_resp_header(c->resp, "x-amz-version-id", res.version_id);
    if (res.delete_marker) buckets_http_resp_header(c->resp, "x-amz-delete-marker", "true");
  }
  c->resp->status = 204;
  if (err) {
    buckets_s3_send_event_early(c, BUCKETS_EV_OBJECT_REMOVED_NOOP, c->bucket, c->object, NULL, version);
  } else {
    buckets_s3_send_event(c, res.delete_marker ? BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED
                                               : BUCKETS_EV_OBJECT_REMOVED_DELETE,
                          c->bucket, c->object, NULL, res.version_id);
    if (o.decide) buckets_repl_schedule_delete(c->s, c->bucket, c->object, &res, "replicate:incoming:delete");
  }
}

/* ---- CopyObject ----------------------------------------------------------- */

/* forward: helpers below copy_object use these */
/* A copy source read as plaintext: raw for plain objects, decrypted (with
 * the copy-source SSE-C key, or the KMS) for encrypted ones. */
typedef struct {
  buckets_obj_reader *r;
  buckets_sse_reader *sr;
  buckets_comp_reader *cr;
} src_stream;

static long src_read(void *ud, void *buf, size_t n) {
  src_stream *s = ud;
  if (s->cr) return buckets_comp_reader_read(s->cr, buf, n);
  return s->sr ? buckets_sse_reader_read(s->sr, buf, n) : buckets_obj_read(s->r, buf, n);
}

static void src_close(src_stream *s) {
  if (s->cr) buckets_comp_reader_free(s->cr);
  else if (s->sr) buckets_sse_reader_free(s->sr);
  else if (s->r) buckets_obj_reader_free(s->r);
  memset(s, 0, sizeof(*s));
}

/* Stats a copy source and prepares it: SSE request checks, its key, the
 * ETag clients see and its plaintext size (oi->size; stored_size keeps the
 * stored one). */
static buckets_s3_error prepare_source(s3_ctx *c, const char *b, const char *o, const char *v, buckets_object_info *oi,
                                       uint8_t key[32], bool *encrypted, int64_t *stored_size) {
  buckets_obj_err err = buckets_obj_stat(c->s->layer, b, o, v, oi);
  if (!err && oi->delete_marker) {
    buckets_object_info_free(oi);
    err = v && *v ? BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (err) return err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET ? BUCKETS_ERR_NO_SUCH_BUCKET : buckets_s3_obj_error(err);
  *stored_size = oi->size;
  buckets_s3_error e = buckets_s3_sse_check_read(c, oi, true);
  *encrypted = !e && buckets_s3_sse_encrypted(oi);
  if (!e && *encrypted) e = buckets_s3_sse_object_key(c, oi, b, o, true, key);
  if (e) {
    buckets_object_info_free(oi);
    return e;
  }
  if (*encrypted) {
    char etag[80];
    buckets_s3_sse_client_etag(c, oi, key, etag);
    snprintf(oi->etag, sizeof(oi->etag), "%s", etag);
  }
  if (*encrypted || buckets_s3_is_compressed(oi)) oi->size = buckets_s3_actual_size(oi);
  return BUCKETS_ERR_NONE;
}

/* Opens plaintext [off, off+len) of a prepared source. */
static buckets_s3_error open_source(s3_ctx *c, const char *b, const char *o, const char *v, buckets_object_info *oi,
                                    const uint8_t *key, bool encrypted, int64_t stored_size, int64_t off, int64_t len,
                                    src_stream *s) {
  memset(s, 0, sizeof(*s));
  int64_t roff = off, rlen = len;
  buckets_sse_range rg;
  buckets_comp_range crg;
  int64_t plain = oi->size;
  bool compressed = buckets_s3_is_compressed(oi) && len > 0;
  if (compressed) {
    buckets_s3_compressed_range(oi, encrypted ? key : NULL, off, &crg);
    roff = crg.stored_off, rlen = stored_size - crg.stored_off;
  } else if (encrypted) {
    oi->size = stored_size;
    buckets_s3_sse_range(oi, off, len, &rg);
    oi->size = plain;
    roff = rg.enc_off, rlen = rg.enc_len;
  }
  buckets_object_info tmp;
  buckets_obj_err err = buckets_obj_open(c->s->layer, b, o, v, roff, rlen, &s->r, &tmp);
  if (err) return err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET ? BUCKETS_ERR_NO_SUCH_BUCKET : buckets_s3_obj_error(err);
  buckets_object_info_free(&tmp);
  if (compressed) {
    s->cr = buckets_comp_reader_new(oi, stored_size, encrypted ? key : NULL, &crg, len, (buckets_read_fn)reader_source, s->r,
                                    reader_free);
    s->r = NULL;
  } else if (encrypted) {
    oi->size = stored_size;
    s->sr = buckets_sse_reader_new(oi, key, &rg, len, (buckets_read_fn)reader_source, s->r, reader_free);
    oi->size = plain;
    s->r = NULL;
  }
  return BUCKETS_ERR_NONE;
}

static bool parse_copy_source(buckets_str h, char **decoded, const char **bucket, const char **object,
                              const char **version);

/* ---- metadata replication (CopyObject onto the same version) ---- */

typedef struct {
  s3_ctx *c;
  buckets_xl_kv *lock; /* the retention and legal hold the request carries */
  size_t nlock;
  const char *tags;    /* X-Amz-Tagging when the tagging directive is REPLACE */
  bool replace_tags;
  int64_t tag_ts, ret_ts, lh_ts; /* the source's timestamps (0: none) */
} repl_copy;

static int64_t parse_ts(const char *v) {
  long long s;
  long n;
  if (!v || !*v || !buckets_time_parse_rfc3339(v, &s, &n)) return 0;
  return (int64_t)s * 1000000000LL + n;
}

static int64_t header_ts(s3_ctx *c, const char *name) {
  buckets_str h = buckets_http_header_get(c->req, name);
  if (!h.p) return 0;
  char *v = buckets_str_dup(h);
  int64_t ns = parse_ts(v);
  free(v);
  return ns;
}

static void set_ts_kv(buckets_xl_kv **kv, size_t *n, const char *key, int64_t ns) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), ts);
  buckets_xl_kv_set(kv, n, key, ts, strlen(ts));
}

/* CopyObjectHandler's metadata for a replicated metadata update. */
static buckets_obj_err repl_copy_edit(void *ud, const buckets_object_info *cur, buckets_xl_kv **user, size_t *nuser,
                                      buckets_xl_kv **sys, size_t *nsys) {
  repl_copy *rc = ud;
  (void)cur;
  const buckets_xl_kv *sc_h = NULL;
  (void)sc_h;
  if (rc->replace_tags && rc->tags && *rc->tags && rc->tag_ts) {
    const buckets_xl_kv *od = buckets_xl_kv_get(*sys, *nsys, BUCKETS_META_TAGGING_TS);
    int64_t ondisk = od ? parse_ts((const char *)od->value) : 0;
    if (!od || !ondisk || ondisk <= rc->tag_ts) {
      set_ts_kv(sys, nsys, BUCKETS_META_TAGGING_TS, rc->tag_ts);
      buckets_xl_kv_set(user, nuser, "X-Amz-Tagging", rc->tags, strlen(rc->tags));
    }
  }
  remove_kv(*user, nuser, BUCKETS_H_REPL_STATUS);
  /* FilterObjectLockMetadata, then what the request (newer) says */
  remove_kv(*user, nuser, BUCKETS_LOCK_MODE_META);
  remove_kv(*user, nuser, BUCKETS_LOCK_UNTIL_META);
  remove_kv(*user, nuser, BUCKETS_LOCK_HOLD_META);
  const buckets_xl_kv *mode = buckets_xl_kv_get(rc->lock, rc->nlock, BUCKETS_LOCK_MODE_META);
  const buckets_xl_kv *until = buckets_xl_kv_get(rc->lock, rc->nlock, BUCKETS_LOCK_UNTIL_META);
  const buckets_xl_kv *hold = buckets_xl_kv_get(rc->lock, rc->nlock, BUCKETS_LOCK_HOLD_META);
  if (mode && until && rc->ret_ts) {
    const buckets_xl_kv *od = buckets_xl_kv_get(*sys, *nsys, BUCKETS_META_RETENTION_TS);
    int64_t ondisk = od ? parse_ts((const char *)od->value) : 0;
    if (!ondisk || ondisk < rc->ret_ts) {
      buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_MODE_META, mode->value, mode->value_len);
      buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_UNTIL_META, until->value, until->value_len);
      set_ts_kv(sys, nsys, BUCKETS_META_RETENTION_TS, rc->ret_ts);
    }
  }
  if (hold && rc->lh_ts) {
    const buckets_xl_kv *od = buckets_xl_kv_get(*sys, *nsys, BUCKETS_META_LEGALHOLD_TS);
    int64_t ondisk = od ? parse_ts((const char *)od->value) : 0;
    if (!ondisk || ondisk < rc->lh_ts) {
      buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_HOLD_META, hold->value, hold->value_len);
      /* MinIO records the legal hold's time under the retention key */
      set_ts_kv(sys, nsys, BUCKETS_META_RETENTION_TS, rc->lh_ts);
    }
  }
  buckets_str rs = buckets_http_header_get(rc->c->req, BUCKETS_H_REPL_STATUS);
  if (rs.p && rs.n) {
    buckets_xl_kv_set(sys, nsys, BUCKETS_META_REPLICA_STATUS, BUCKETS_RS_REPLICA, strlen(BUCKETS_RS_REPLICA));
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    set_ts_kv(sys, nsys, BUCKETS_META_REPLICA_TS, (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    buckets_xl_kv_set(user, nuser, BUCKETS_H_REPL_STATUS, rs.p, rs.n);
  }
  return BUCKETS_OBJ_OK;
}

static void repl_copy_metadata(s3_ctx *c, const char *version) {
  buckets_s3_repl_in ri;
  if (!buckets_s3_repl_in_parse(c, c->object, false, &ri)) return;
  repl_copy rc = {.c = c};
  buckets_str td = buckets_http_header_get(c->req, "X-Amz-Tagging-Directive");
  rc.replace_tags = td.p && buckets_str_eq_c(td, "REPLACE");
  buckets_str th = buckets_http_header_get(c->req, "X-Amz-Tagging");
  char *tags = th.p ? buckets_str_dup(th) : buckets_xstrdup("");
  rc.tags = tags;
  rc.tag_ts = header_ts(c, BUCKETS_H_SRC_TAG_TS);
  rc.ret_ts = header_ts(c, BUCKETS_H_SRC_RET_TS);
  rc.lh_ts = header_ts(c, BUCKETS_H_SRC_LH_TS);
  buckets_s3_error serr = buckets_s3_lock_put_meta(c, c->object, &rc.lock, &rc.nlock);
  if (serr) {
    free(tags);
    free_kvs(rc.lock, rc.nlock);
    buckets_s3_write_error(c, serr);
    return;
  }
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_update_meta(c->s->layer, c->bucket, c->object, version, repl_copy_edit, &rc, &oi);
  free(tags);
  free_kvs(rc.lock, rc.nlock);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_s3_version_header(c, oi.version_id);
  char lm[BUCKETS_TIME_ISO8601_LEN + 1];
  buckets_time_iso8601_ns(oi.mod_time_ns, lm);
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "CopyObjectResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "LastModified", lm);
  buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", oi.etag);
  buckets_xml_close(b, "CopyObjectResult");
  buckets_s3_write_xml(c, 200);
  etag_header(c->resp, oi.etag);
  if (strcmp(version, "null") != 0) buckets_http_resp_header(c->resp, "x-amz-copy-source-version-id", version);
  buckets_object_info_free(&oi);
}

static void copy_object(s3_ctx *c) {
  buckets_str src_h = buckets_http_header_get(c->req, "X-Amz-Copy-Source");
  char *decoded;
  const char *src_bucket, *src_object, *version;
  if (!parse_copy_source(src_h, &decoded, &src_bucket, &src_object, &version)) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_SOURCE);
    return;
  }
  if (!buckets_s3_require(c, "s3:GetObject", src_bucket, src_object, NULL)) {
    free(decoded);
    return;
  }
  const char *dst_vid = buckets_query_get(&c->q, "versionId");
  if (buckets_s3_repl_request(c) && strcmp(src_bucket, c->bucket) == 0 && strcmp(src_object, c->object) == 0 &&
      version && *version && dst_vid && strcmp(dst_vid, version) == 0) {
    /* a metadata update replicated onto the same version (CopyObject metadataOnly) */
    char *v = buckets_xstrdup(version);
    free(decoded);
    repl_copy_metadata(c, v);
    free(v);
    return;
  }
  c->err_bucket = buckets_xstrdup(src_bucket);
  c->err_object = buckets_xstrdup(src_object);

  /* isDirectiveValid: absent, empty, COPY or REPLACE */
  buckets_str directive = buckets_http_header_get(c->req, "X-Amz-Metadata-Directive");
  bool replace = directive.p && buckets_str_eq_c(directive, "REPLACE");
  if (directive.n && !replace && !buckets_str_eq_c(directive, "COPY")) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_METADATA_DIRECTIVE);
    return;
  }
  buckets_str tag_directive = buckets_http_header_get(c->req, "X-Amz-Tagging-Directive");
  bool replace_tags = tag_directive.p && buckets_str_eq_c(tag_directive, "REPLACE");
  if (tag_directive.n && !replace_tags && !buckets_str_eq_c(tag_directive, "COPY")) {
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_TAG_DIRECTIVE);
    return;
  }
  if (replace_tags && !buckets_s3_check_tagging_header(c)) {
    free(decoded);
    return;
  }

  buckets_object_info src;
  uint8_t src_key[32], dst_key[32];
  bool src_enc = false;
  int64_t stored_size = 0;
  buckets_s3_error perr = prepare_source(c, src_bucket, src_object, version, &src, src_key, &src_enc, &stored_size);
  if (perr) {
    free(decoded);
    buckets_s3_sse_write_error(c, perr);
    return;
  }
  buckets_obj_err err;
  /* copying onto itself must change something: metadata, tags or encryption */
  if (strcmp(src_bucket, c->bucket) == 0 && strcmp(src_object, c->object) == 0 && !replace && !replace_tags &&
      !(version && *version) && !buckets_s3_sse_s3_or_kms_requested(c) &&
      !buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Algorithm").p && !src_enc) {
    buckets_object_info_free(&src);
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_DEST);
    return;
  }

  /* x-amz-copy-source-if-* preconditions */
  buckets_str h;
  time_t t;
  bool failed = false;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Match")).p && !etag_matches(src.etag, h)) failed = true;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-None-Match")).p && etag_matches(src.etag, h)) failed = true;
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Modified-Since")).p && buckets_time_parse_http(h, &t) &&
      src.mod_time_ns < (int64_t)(t + 1) * 1000000000LL) {
    failed = true;
  }
  if ((h = buckets_http_header_get(c->req, "X-Amz-Copy-Source-If-Unmodified-Since")).p &&
      buckets_time_parse_http(h, &t) && src.mod_time_ns >= (int64_t)(t + 1) * 1000000000LL) {
    failed = true;
  }
  if (failed) {
    buckets_object_info_free(&src);
    free(decoded);
    buckets_s3_write_error(c, BUCKETS_ERR_PRECONDITION_FAILED);
    return;
  }
  bool same = strcmp(src_bucket, c->bucket) == 0 && strcmp(src_object, c->object) == 0;
  if (!same && !buckets_s3_enforce_quota(c, c->bucket, src.size)) {
    buckets_object_info_free(&src);
    free(decoded);
    return;
  }

  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  buckets_s3_error serr = BUCKETS_ERR_NONE;
  if (replace) {
    serr = extract_metadata(c, &meta, &nmeta);
  } else {
    for (size_t i = 0; i < src.nmeta; i++) {
      const char *k = src.meta[i].key;
      /* FilterObjectLockMetadata(src, true, true): the copy gets its own lock */
      if (strcasecmp(k, BUCKETS_LOCK_MODE_META) == 0 || strcasecmp(k, BUCKETS_LOCK_UNTIL_META) == 0 ||
          strcasecmp(k, BUCKETS_LOCK_HOLD_META) == 0)
        continue;
      buckets_xl_kv_set(&meta, &nmeta, k, src.meta[i].value, src.meta[i].value_len);
    }
  }
  if (!serr) {
    /* The source's tags, unless x-amz-tagging-directive is REPLACE. */
    buckets_str th = buckets_http_header_get(c->req, "X-Amz-Tagging");
    char *tags = replace_tags ? (th.p ? buckets_str_dup(th) : buckets_xstrdup(""))
                              : buckets_xstrdup(buckets_object_meta(&src, "X-Amz-Tagging") ? buckets_object_meta(&src, "X-Amz-Tagging") : "");
    remove_kv(meta, &nmeta, "X-Amz-Tagging");
    if (*tags) buckets_xl_kv_set(&meta, &nmeta, "X-Amz-Tagging", tags, strlen(tags));
    free(tags);
  }
  if (!serr) serr = buckets_s3_lock_put_meta(c, c->object, &meta, &nmeta);
  /* the destination's encryption */
  char why[200];
  if (!serr && !buckets_s3_sse_put_opts(c, why, sizeof(why))) {
    char msg[400];
    snprintf(msg, sizeof(msg), "Invalid arguments provided for %s/%s: (%s)", c->bucket, c->object, why);
    free_kvs(meta, nmeta);
    buckets_object_info_free(&src);
    free(decoded);
    buckets_s3_write_custom_error(c, 400, "InvalidArgument", msg);
    return;
  }
  buckets_sse_req sse = {0};
  if (!serr) serr = buckets_s3_sse_parse_copy_dest(c, &sse);
  cks_ctx cx = {0};
  body_src nob = {0};
  sse_put sp = {.cx = &cx, .b = &nob};
  bool encrypt = !serr && sse.kind;
  if (encrypt) serr = buckets_s3_sse_new_key(c, &sse, c->bucket, c->object, dst_key, &sp.sys, &sp.nsys);
  buckets_sse_req_free(&sse);
  memcpy(sp.key, dst_key, 32);
  /* The destination's checksum (CopyObjectHandler): the algorithm asked for,
   * computed; else the source's, verified (a composite multipart one is
   * computed again whole); else a CRC64NVME computed server-side. */
  if (!serr) {
    buckets_str alg = buckets_http_header_get(c->req, "X-Amz-Checksum-Algorithm");
    uint32_t alg_type = 0;
    if (alg.p && alg.n) {
      char *a = buckets_str_dup(alg);
      alg_type = buckets_cksum_type_parse(a, NULL);
      free(a);
      if (alg_type == BUCKETS_CKSUM_INVALID) alg_type = 0; /* NewChecksumHeader: not set */
    }
    buckets_checksum sc;
    if (serr) {
    } else if (alg_type) {
      cx.want.type = alg_type;
      cx.server_side = true;
    } else if (!src_enc && src.checksum && buckets_checksum_read_stored(src.checksum, src.checksum_len, &sc)) {
      if ((sc.type & BUCKETS_CKSUM_MULTIPART) && !(sc.type & BUCKETS_CKSUM_FULL_OBJECT)) {
        cx.want.type = sc.type & BUCKETS_CKSUM_BASE_MASK;
        cx.server_side = true;
      } else {
        cx.want = sc;
        cx.want.type &= BUCKETS_CKSUM_BASE_MASK | BUCKETS_CKSUM_FULL_OBJECT;
      }
    } else {
      cx.want.type = BUCKETS_CKSUM_CRC64NVME | BUCKETS_CKSUM_FULL_OBJECT;
      cx.server_side = true;
    }
  }
  src_stream ss = {0};
  if (!serr) serr = open_source(c, src_bucket, src_object, version, &src, src_key, src_enc, stored_size, 0, src.size, &ss);
  buckets_object_info oi;
  buckets_sse_writer w;
  if (!serr) {
    buckets_put_opts opts = {.meta = meta, .nmeta = nmeta};
    bool suspended;
    buckets_s3_versioning(c, c->object, &opts.versioned, &suspended);
    buckets_read_fn rd = src_read;
    void *rd_ud = &ss;
    int64_t size = src.size;
    sp.compressed = buckets_s3_compressible(c, c->object, encrypt) && src.size > BUCKETS_COMPRESS_MIN_SIZE;
    bool xform = encrypt || sp.compressed;
    if (xform) {
      sp.w = &w;
      rd = xform_open(&sp, src_read, &ss, &size, cx.want.type & BUCKETS_CKSUM_BASE_MASK, dst_key, NULL, encrypt, encrypt,
                      &rd_ud);
      opts.pre_commit = sse_pre_commit;
      opts.pre_commit_ud = &sp;
      opts.actual_size = src.size;
    } else if (cx.want.type) {
      opts.checksum_type = cx.want.type & BUCKETS_CKSUM_BASE_MASK;
      opts.pre_commit = cks_pre_commit;
      opts.pre_commit_ud = &cx;
    }
    err = buckets_obj_put(c->s->layer, c->bucket, c->object, rd, rd_ud, size, &opts, &oi);
    if (xform) xform_close(&sp);
    serr = buckets_s3_obj_error(err);
  }
  src_close(&ss);
  OPENSSL_cleanse(src_key, sizeof(src_key));
  char src_vid[37];
  snprintf(src_vid, sizeof(src_vid), "%s", src.version_id);
  free_kvs(meta, nmeta);
  free_kvs(sp.sys, sp.nsys);
  buckets_object_info_free(&src);
  free(decoded);
  if (serr) {
    OPENSSL_cleanse(dst_key, sizeof(dst_key));
    buckets_s3_sse_write_error(c, serr);
    return;
  }
  if (buckets_s3_sse_encrypted(&oi)) { /* the ETag clients see; CopyObject sends no SSE headers */
    char etag[80];
    buckets_s3_sse_client_etag(c, &oi, dst_key, etag);
    snprintf(oi.etag, sizeof(oi.etag), "%s", etag);
  }
  OPENSSL_cleanse(dst_key, sizeof(dst_key));
  if (strcmp(src_vid, "null") != 0) buckets_http_resp_header(c->resp, "x-amz-copy-source-version-id", src_vid);
  buckets_s3_version_header(c, oi.version_id);
  oi.is_latest = true; /* the version just written */
  buckets_s3_expiration_header(c, &oi);
  char lm[BUCKETS_TIME_ISO8601_LEN + 1];
  buckets_time_iso8601_ns(oi.mod_time_ns, lm);
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "CopyObjectResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "LastModified", lm);
  buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", oi.etag);
  buckets_xml_close(b, "CopyObjectResult");
  buckets_s3_write_xml(c, 200);
  etag_header(c->resp, oi.etag); /* setPutObjHeaders: the ETag and the object's checksums */
  if (oi.checksum && !buckets_s3_sse_encrypted(&oi)) buckets_checksum_write_headers(oi.checksum, oi.checksum_len, 0, c->resp);
  buckets_s3_send_event(c, BUCKETS_EV_OBJECT_CREATED_COPY, c->bucket, c->object, &oi, NULL);
  buckets_object_info_free(&oi);
}

/* ---- multipart uploads ---------------------------------------------------- */

static void mpu_create(s3_ctx *c) {
  if (put_preconditions(c, c->object)) return;
  /* the upload's encryption: its key is sealed into the upload's metadata */
  buckets_sse_req sse;
  buckets_s3_error serr = buckets_s3_sse_parse(c, &sse);
  uint8_t key[32];
  buckets_xl_kv *sys = NULL;
  size_t nsys = 0;
  if (!serr && sse.kind) serr = buckets_s3_sse_new_key(c, &sse, c->bucket, c->object, key, &sys, &nsys);
  buckets_sse_req_free(&sse);
  OPENSSL_cleanse(key, sizeof(key));
  if (serr) {
    free_kvs(sys, nsys);
    buckets_s3_sse_write_error(c, serr);
    return;
  }
  if (nsys) buckets_xl_kv_set(&sys, &nsys, BUCKETS_SSE_META_MULTIPART, "", 0);
  /* Parts compress when the upload qualifies (no size threshold here). */
  if (buckets_s3_compressible(c, c->object, nsys > 0))
    buckets_xl_kv_set(&sys, &nsys, BUCKETS_COMPRESS_META, BUCKETS_COMPRESS_ALGO_V2, strlen(BUCKETS_COMPRESS_ALGO_V2));
  buckets_xl_kv *meta = NULL;
  size_t nmeta = 0;
  serr = extract_metadata(c, &meta, &nmeta);
  for (size_t i = 0; i < nsys; i++) buckets_xl_kv_set(&meta, &nmeta, sys[i].key, sys[i].value, sys[i].value_len);
  free_kvs(sys, nsys);
  if (!serr && !buckets_s3_check_tagging_header(c)) {
    free_kvs(meta, nmeta);
    return;
  }
  if (!serr) serr = buckets_s3_lock_put_meta(c, c->object, &meta, &nmeta);
  buckets_s3_repl_in ri;
  if (!serr && !buckets_s3_repl_in_parse(c, c->object, true, &ri)) {
    free_kvs(meta, nmeta);
    return;
  }
  if (!serr) {
    buckets_s3_repl_in_meta(c, &ri, &meta, &nmeta);
    buckets_repl_dsc dsc;
    buckets_s3_repl_out_meta(c, c->object, &meta, &nmeta, ri.request, &dsc);
    buckets_repl_dsc_free(&dsc);
    /* a replicated upload completes as the source's version */
    if (ri.has_vid) buckets_xl_kv_set(&meta, &nmeta, MPU_VID_META, ri.version_id, strlen(ri.version_id));
  }
  uint32_t ctype = 0;
  buckets_str alg = buckets_http_header_get(c->req, "X-Amz-Checksum-Algorithm");
  buckets_str ot = buckets_http_header_get(c->req, "X-Amz-Checksum-Type");
  if (!serr && ((alg.p && alg.n) || (ot.p && ot.n))) {
    char *a = alg.p ? buckets_str_dup(alg) : buckets_xstrdup("");
    char *t = ot.p ? buckets_str_dup(ot) : buckets_xstrdup("");
    ctype = buckets_cksum_type_parse(a, t);
    if (ctype == BUCKETS_CKSUM_INVALID) {
      serr = BUCKETS_ERR_INVALID_CHECKSUM;
    } else if (ctype) {
      const char *name = buckets_cksum_type_name(ctype);
      const char *objtype = (ctype & (BUCKETS_CKSUM_FULL_OBJECT | BUCKETS_CKSUM_CRC64NVME)) ? "FULL_OBJECT" : "COMPOSITE";
      buckets_xl_kv_set(&meta, &nmeta, BUCKETS_MPU_CKSUM_META, name, strlen(name));
      buckets_xl_kv_set(&meta, &nmeta, BUCKETS_MPU_CKSUM_TYPE_META, objtype, strlen(objtype));
    }
    free(a);
    free(t);
  }
  if (serr) {
    free_kvs(meta, nmeta);
    buckets_s3_write_error(c, serr);
    return;
  }
  char upload_id[BUCKETS_UPLOAD_ID_MAX];
  buckets_obj_err err = buckets_obj_mpu_new(c->s->layer, c->bucket, c->object, meta, nmeta, upload_id);
  free_kvs(meta, nmeta);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "InitiateMultipartUploadResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Bucket", c->bucket);
  buckets_xml_elem(b, "Key", c->object);
  buckets_xml_elem(b, "UploadId", upload_id);
  buckets_xml_close(b, "InitiateMultipartUploadResult");
  if (ctype) {
    buckets_http_resp_header(c->resp, "X-Amz-Checksum-Algorithm", buckets_cksum_type_name(ctype));
    buckets_http_resp_header(c->resp, "X-Amz-Checksum-Type",
                             (ctype & (BUCKETS_CKSUM_FULL_OBJECT | BUCKETS_CKSUM_CRC64NVME)) ? "FULL_OBJECT" : "COMPOSITE");
  }
  buckets_s3_write_xml(c, 200);
}

static bool parse_part_number(s3_ctx *c, int *out) {
  const char *s = buckets_query_get(&c->q, "partNumber");
  char *end = NULL;
  long v = s ? strtol(s, &end, 10) : 0;
  if (!s || !*s || *end || v < 1) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_PART);
    return false;
  }
  if (v > BUCKETS_MAX_PARTS) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_PARTS);
    return false;
  }
  *out = (int)v;
  return true;
}

/* x-amz-copy-source: "/bucket/key[?versionId=...]". As MinIO's url.Parse:
 * the query starts at the first literal '?' (one in a key comes encoded),
 * and only the path is URL-decoded. */
static bool parse_copy_source(buckets_str h, char **decoded, const char **bucket, const char **object,
                              const char **version) {
  *decoded = buckets_xmalloc(2 * h.n + 2);
  *version = NULL;
  const char *q = memchr(h.p, '?', h.n);
  size_t pn = q ? (size_t)(q - h.p) : h.n;
  long dn = buckets_url_decode((buckets_str){h.p, pn}, *decoded, false);
  if (dn < 0) return false;
  (*decoded)[dn] = '\0';
  if (q) { /* versionId from the query, stored after the path */
    buckets_str rest = {q + 1, h.n - pn - 1}, part;
    while (rest.n) {
      buckets_str_cut(rest, '&', &part, &rest);
      buckets_str k, v;
      if (!buckets_str_cut(part, '=', &k, &v)) k = part, v = (buckets_str){part.p + part.n, 0};
      if (!buckets_str_eq_c(k, "versionId")) continue;
      char *vs = *decoded + dn + 1;
      long vn = buckets_url_decode(v, vs, true);
      if (vn < 0) return false;
      vs[vn] = '\0';
      while (*vs == ' ') vs++;
      for (long e = (long)strlen(vs); e > 0 && vs[e - 1] == ' '; e--) vs[e - 1] = '\0';
      *version = vs;
      break;
    }
  }
  char *path = *decoded;
  while (*path == '/') path++;
  char *slash = strchr(path, '/');
  if (!slash || !slash[1]) return false;
  *slash = '\0';
  *bucket = path;
  *object = slash + 1;
  return true;
}

static void mpu_put_part(s3_ctx *c, const char *upload_id) {
  int part;
  if (!parse_part_number(c, &part)) return;

  buckets_str copy_src = buckets_http_header_get(c->req, "X-Amz-Copy-Source");
  if (copy_src.p) {
    /* UploadPartCopy */
    char *decoded;
    const char *sb, *so, *sv;
    if (!parse_copy_source(copy_src, &decoded, &sb, &so, &sv)) {
      free(decoded);
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_COPY_SOURCE);
      return;
    }
    if (!buckets_s3_require(c, "s3:GetObject", sb, so, NULL)) {
      free(decoded);
      return;
    }
    free(c->err_bucket);
    free(c->err_object);
    c->err_bucket = buckets_xstrdup(sb); /* errors name the source from here on, as MinIO's do */
    c->err_object = buckets_xstrdup(so);
    buckets_object_info src;
    uint8_t skey[32];
    bool senc = false;
    int64_t stored = 0;
    buckets_s3_error perr = prepare_source(c, sb, so, sv, &src, skey, &senc, &stored);
    if (perr) {
      free(decoded);
      buckets_s3_sse_write_error(c, perr);
      return;
    }
    buckets_obj_err err;
    int64_t off = 0, len = src.size;
    buckets_str rh = buckets_http_header_get(c->req, "X-Amz-Copy-Source-Range");
    if (rh.p) {
      /* parseCopyPartRangeSpec + checkCopyPartRangeWithSize */
      range_spec rs;
      buckets_s3_error re = BUCKETS_ERR_NONE;
      if (!parse_range(rh, &rs) || !rs.present || rs.suffix || rs.end < 0) re = BUCKETS_ERR_INVALID_COPY_PART_RANGE;
      else if (rs.start >= src.size || rs.end >= src.size) re = BUCKETS_ERR_INVALID_COPY_PART_RANGE_SOURCE;
      else resolve_range(&rs, src.size, &off, &len);
      if (re) {
        buckets_object_info_free(&src);
        free(decoded);
        buckets_s3_write_error(c, re);
        return;
      }
    }
    if (!buckets_s3_enforce_quota(c, c->bucket, len)) {
      buckets_object_info_free(&src);
      free(decoded);
      return;
    }
    src_stream ss;
    perr = open_source(c, sb, so, sv, &src, skey, senc, stored, off, len, &ss);
    OPENSSL_cleanse(skey, sizeof(skey));
    buckets_object_info_free(&src);
    free(decoded);
    if (perr) {
      buckets_s3_sse_write_error(c, perr);
      return;
    }
    buckets_part_info pi;
    buckets_object_info ui;
    bool upload_known = buckets_obj_mpu_stat(c->s->layer, c->bucket, c->object, upload_id, &ui) == BUCKETS_OBJ_OK;
    bool upload_enc = upload_known && buckets_s3_sse_encrypted(&ui);
    bool upload_comp = upload_known && buckets_s3_is_compressed(&ui);
    if (upload_enc || upload_comp) {
      body_src nob = {0};
      cks_ctx cx = {0};
      sse_put sp = {.cx = &cx, .b = &nob, .compressed = upload_comp};
      buckets_s3_error ke = upload_enc ? buckets_s3_sse_object_key(c, &ui, c->bucket, c->object, false, sp.key) : BUCKETS_ERR_NONE;
      if (ke) {
        buckets_object_info_free(&ui);
        src_close(&ss);
        buckets_s3_sse_write_error(c, ke);
        return;
      }
      uint8_t pk[32], nonce[12];
      if (upload_enc) {
        buckets_objkey_part_key(sp.key, (uint32_t)part, pk);
        part_nonce(upload_id, part, nonce);
      }
      buckets_sse_writer w;
      sp.w = &w;
      int64_t size = len;
      void *ud;
      buckets_read_fn rd = xform_open(&sp, src_read, &ss, &size, 0, pk, nonce, upload_enc,
                                      buckets_s3_sse_requested(c) || upload_enc, &ud);
      OPENSSL_cleanse(pk, sizeof(pk));
      buckets_put_opts po = {.pre_commit = sse_pre_commit, .pre_commit_ud = &sp, .part_commit = sse_part_commit,
                             .part_commit_ud = &sp, .actual_size = len};
      err = buckets_obj_mpu_put_part(c->s->layer, c->bucket, c->object, upload_id, part, rd, ud, size, &po, &pi);
      xform_close(&sp);
      if (!err && upload_enc) {
        char shown[128];
        sse_part_etag(sp.key, buckets_s3_sse_kind_of(&ui) == BUCKETS_SSE_S3, pi.etag, shown);
        snprintf(pi.etag, sizeof(pi.etag), "%s", shown);
      }
      OPENSSL_cleanse(sp.key, sizeof(sp.key));
    } else {
      err = buckets_obj_mpu_put_part(c->s->layer, c->bucket, c->object, upload_id, part, src_read, &ss, len, NULL, &pi);
    }
    if (upload_known) buckets_object_info_free(&ui);
    src_close(&ss);
    if (err) {
      buckets_s3_write_error(c, buckets_s3_obj_error(err));
      return;
    }
    char lm[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(pi.mod_time_ns, lm);
    buckets_buf *b = &c->resp->body;
    buckets_xml_header(b);
    buckets_xml_open_ns(b, "CopyPartResult", BUCKETS_S3_XMLNS);
    buckets_xml_elem(b, "LastModified", lm);
    buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", pi.etag);
    buckets_xml_close(b, "CopyPartResult");
    buckets_s3_write_xml(c, 200);
    return;
  }

  body_src bsrc;
  buckets_s3_error serr = body_open(c, &bsrc);
  if (!serr && bsrc.size > BUCKETS_MAX_PART_SIZE) serr = BUCKETS_ERR_ENTITY_TOO_LARGE;
  if (serr) {
    body_close(&bsrc);
    buckets_s3_write_error(c, serr);
    return;
  }
  if (!buckets_s3_enforce_quota(c, c->bucket, bsrc.size)) {
    body_close(&bsrc);
    return;
  }
  buckets_put_opts opts = {.want_md5 = bsrc.has_md5 ? bsrc.md5 : NULL,
                           .want_sha256 = bsrc.want_sha ? bsrc.sha : NULL,
                           .pre_commit = cks_pre_commit};
  cks_ctx cx;
  if ((serr = cks_open(c, &bsrc, &cx, &opts)) != BUCKETS_ERR_NONE) {
    body_close(&bsrc);
    buckets_s3_write_error(c, serr);
    return;
  }
  opts.pre_commit_ud = &cx;
  /* an encrypted upload: the part is sealed with its part key */
  buckets_object_info ui;
  bool upload_known = buckets_obj_mpu_stat(c->s->layer, c->bucket, c->object, upload_id, &ui) == BUCKETS_OBJ_OK;
  bool part_enc = upload_known && buckets_s3_sse_encrypted(&ui);
  bool part_comp = upload_known && buckets_s3_is_compressed(&ui);
  sse_put sp = {.cx = &cx, .b = &bsrc, .compressed = part_comp};
  buckets_sse_writer w;
  buckets_read_fn rd = bsrc.rd;
  void *rd_ud = bsrc.rd_ud;
  int64_t size = bsrc.size;
  uint8_t pk[32], nonce[12];
  if (part_enc) {
    buckets_sse_kind kind = buckets_s3_sse_kind_of(&ui);
    bool ssec = buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Algorithm").p != NULL;
    if ((kind == BUCKETS_SSE_C && !ssec) || (kind == BUCKETS_SSE_S3 && ssec)) serr = BUCKETS_ERR_SSE_MULTIPART_ENCRYPTED;
    if (!serr) serr = buckets_s3_sse_object_key(c, &ui, c->bucket, c->object, false, sp.key);
    if (serr) {
      buckets_object_info_free(&ui);
      body_close(&bsrc);
      buckets_s3_sse_write_error(c, serr);
      return;
    }
    buckets_objkey_part_key(sp.key, (uint32_t)part, pk);
    part_nonce(upload_id, part, nonce);
  }
  if (part_enc || part_comp) {
    sp.w = &w;
    /* PutObjectPart pads only when the part request itself carries SSE headers. */
    rd = xform_open(&sp, bsrc.rd, bsrc.rd_ud, &size, cx.want.type & BUCKETS_CKSUM_BASE_MASK, pk, nonce, part_enc,
                    buckets_s3_sse_requested(c), &rd_ud);
    OPENSSL_cleanse(pk, sizeof(pk));
    opts.actual_size = bsrc.size;
    opts.want_md5 = opts.want_sha256 = NULL;
    opts.checksum_type = 0;
    opts.pre_commit = sse_pre_commit;
    opts.pre_commit_ud = &sp;
    opts.part_commit = sse_part_commit;
    opts.part_commit_ud = &sp;
  }
  buckets_part_info pi;
  buckets_obj_err err = buckets_obj_mpu_put_part(c->s->layer, c->bucket, c->object, upload_id, part, rd, rd_ud, size,
                                                 &opts, &pi);
  if (part_enc || part_comp) xform_close(&sp);
  if (part_enc) {
    if (!err) {
      char shown[128];
      sse_part_etag(sp.key, buckets_s3_sse_kind_of(&ui) == BUCKETS_SSE_S3, pi.etag, shown);
      snprintf(pi.etag, sizeof(pi.etag), "%s", shown);
      buckets_s3_sse_headers(c, &ui);
    }
    OPENSSL_cleanse(sp.key, sizeof(sp.key));
  }
  if (upload_known) buckets_object_info_free(&ui);
  if (err) {
    buckets_s3_write_error(c, body_error(&bsrc, err));
  } else {
    etag_header(c->resp, pi.etag);
    if (pi.cksum.type) {
      char enc[64];
      buckets_checksum_encode(&pi.cksum, enc);
      buckets_http_resp_header(c->resp, buckets_cksum_header(pi.cksum.type), enc);
    }
    c->resp->status = 200;
  }
  body_close(&bsrc);
}

static void mpu_list_parts(s3_ctx *c, const char *upload_id) {
  const char *ms = buckets_query_get(&c->q, "max-parts");
  const char *pm = buckets_query_get(&c->q, "part-number-marker");
  long max = 10000, marker = 0; /* maxPartsList */
  char *end;
  if (ms) {
    max = strtol(ms, &end, 10);
    if (!*ms || *end || max < 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_PARTS);
      return;
    }
    if (max > 10000) max = 10000;
  }
  if (pm) {
    marker = strtol(pm, &end, 10);
    if (!*pm || *end || marker < 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_PART_NUMBER_MARKER);
      return;
    }
  }
  buckets_part_info *parts;
  size_t n;
  bool truncated;
  buckets_obj_err err = buckets_obj_mpu_list_parts(c->s->layer, c->bucket, c->object, upload_id, (int)marker,
                                                   (int)max, &parts, &n, &truncated);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  /* an encrypted upload: SSE-S3 parts are unsealed with the object key */
  uint8_t key[32];
  bool upload_enc = false, upload_comp = false, have_key = false, sse_s3 = false;
  buckets_object_info ui;
  char ck_alg[32] = "", ck_type[32] = "";
  if (buckets_obj_mpu_stat(c->s->layer, c->bucket, c->object, upload_id, &ui) == BUCKETS_OBJ_OK) {
    const char *a = buckets_object_meta(&ui, BUCKETS_MPU_CKSUM_META), *t = buckets_object_meta(&ui, BUCKETS_MPU_CKSUM_TYPE_META);
    snprintf(ck_alg, sizeof(ck_alg), "%s", a ? a : "");
    snprintf(ck_type, sizeof(ck_type), "%s", t ? t : "");
    upload_enc = buckets_s3_sse_encrypted(&ui);
    upload_comp = buckets_s3_is_compressed(&ui);
    sse_s3 = buckets_s3_sse_kind_of(&ui) == BUCKETS_SSE_S3;
    if (upload_enc && sse_s3) {
      buckets_s3_error ke = buckets_s3_sse_object_key(c, &ui, c->bucket, c->object, false, key);
      if (ke) {
        buckets_object_info_free(&ui);
        free(parts);
        buckets_s3_sse_write_error(c, ke);
        return;
      }
      have_key = true;
    }
    buckets_object_info_free(&ui);
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListPartsResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Bucket", c->bucket);
  buckets_xml_elem(b, "Key", c->object);
  buckets_xml_elem(b, "UploadId", upload_id);
  for (int who = 0; who < 2; who++) {
    buckets_xml_open(b, who ? "Owner" : "Initiator");
    buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
    buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_ID); /* MinIO shows the ID here */
    buckets_xml_close(b, who ? "Owner" : "Initiator");
  }
  buckets_xml_elem(b, "StorageClass", "STANDARD");
  buckets_buf_appendf(b, "<PartNumberMarker>%ld</PartNumberMarker>", marker);
  buckets_buf_appendf(b, "<NextPartNumberMarker>%d</NextPartNumberMarker>", truncated && n ? parts[n - 1].number : 0);
  buckets_buf_appendf(b, "<MaxParts>%ld</MaxParts>", max);
  buckets_xml_elem(b, "IsTruncated", truncated ? "true" : "false");
  buckets_xml_elem(b, "ChecksumAlgorithm", ck_alg);
  buckets_xml_elem(b, "ChecksumType", ck_type);
  for (size_t i = 0; i < n; i++) {
    char lm[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(parts[i].mod_time_ns, lm);
    buckets_xml_open(b, "Part");
    buckets_buf_appendf(b, "<PartNumber>%d</PartNumber>", parts[i].number);
    buckets_xml_elem(b, "LastModified", lm);
    if (upload_enc) { /* SSE-S3 parts show their plaintext MD5, others the tail of the sealed one */
      char shown[128];
      sse_part_etag(have_key ? key : NULL, sse_s3, parts[i].etag, shown);
      snprintf(parts[i].etag, sizeof(parts[i].etag), "%s", shown);
    }
    if (upload_enc || upload_comp) parts[i].size = parts[i].actual_size;
    buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", parts[i].etag);
    buckets_buf_appendf(b, "<Size>%lld</Size>", (long long)parts[i].size);
    if (parts[i].cksum.type) {
      char enc[64], tag[32];
      buckets_checksum_encode(&parts[i].cksum, enc);
      snprintf(tag, sizeof(tag), "Checksum%s", buckets_cksum_type_name(parts[i].cksum.type));
      buckets_xml_elem(b, tag, enc);
    }
    buckets_xml_close(b, "Part");
  }
  buckets_xml_close(b, "ListPartsResult");
  if (have_key) OPENSSL_cleanse(key, sizeof(key));
  free(parts);
  buckets_s3_write_xml(c, 200);
}

static void mpu_abort(s3_ctx *c, const char *upload_id) {
  buckets_obj_err err = buckets_obj_mpu_abort(c->s->layer, c->bucket, c->object, upload_id);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  c->resp->status = 204;
}

/* CompleteMultipartUpload of an encrypted upload: client ETags are matched
 * against the unsealed (SSE-S3) or truncated part ETags, and the final
 * checksum is sealed with the object key. */
typedef struct {
  uint8_t key[32];
  bool have_key, sse_s3;
} mpu_sse;

static buckets_s3_error mpu_sse_open(s3_ctx *c, const buckets_object_info *ui, bool checksum, mpu_sse *cs) {
  buckets_sse_kind kind = buckets_s3_sse_kind_of(ui);
  cs->sse_s3 = kind == BUCKETS_SSE_S3;
  bool ssec_given = buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Algorithm").p != NULL;
  if (kind == BUCKETS_SSE_C && !ssec_given) return checksum ? BUCKETS_ERR_MISSING_SSE_CUSTOMER_KEY : BUCKETS_ERR_NONE;
  buckets_s3_error e = buckets_s3_sse_object_key(c, ui, c->bucket, c->object, false, cs->key);
  cs->have_key = !e;
  return e;
}

static void mpu_client_etag(void *ud, const char *stored, char out[128]) {
  mpu_sse *cs = ud;
  sse_part_etag(cs->have_key ? cs->key : NULL, cs->sse_s3, stored, out);
}



typedef struct {
  mpu_sse *cs; /* encrypted uploads */
  int64_t mtime_ns;
} mpu_commit;

static buckets_obj_err mpu_pre_commit(void *ud, buckets_xl_object *o) {
  mpu_commit *mc = ud;
  if (mc->cs && mc->cs->have_key) seal_checksum_meta(mc->cs->key, o);
  const buckets_xl_kv *v = buckets_xl_kv_get(o->meta_sys, o->nmeta_sys, MPU_VID_META);
  if (v) {
    uint8_t id[16];
    if (buckets_xl_version_id_parse((const char *)v->value, id)) memcpy(o->version_id, id, 16);
    remove_kv(o->meta_sys, &o->nmeta_sys, MPU_VID_META);
  }
  if (mc->mtime_ns) o->mod_time = mc->mtime_ns;
  return BUCKETS_OBJ_OK;
}

static void mpu_complete(s3_ctx *c, const char *upload_id) {
  buckets_s3_error serr = buckets_s3_read_doc(c);
  if (serr) {
    buckets_s3_write_error(c, serr);
    return;
  }
  buckets_xml_doc doc;
  if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc) ||
      !buckets_str_eq_c(doc.nodes[0].name, "CompleteMultipartUpload")) {
    if (doc.nodes) buckets_xml_doc_free(&doc);
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }
  if (put_preconditions(c, c->object)) {
    buckets_xml_doc_free(&doc);
    return;
  }
  size_t cap = 0, n = 0;
  buckets_complete_part *parts = NULL;
  char **etags = NULL, **cksums = NULL;
  bool bad = false;
  for (size_t i = doc.nodes[0].first_child; i && !bad; i = doc.nodes[i].next_sibling) {
    if (!buckets_str_eq_c(doc.nodes[i].name, "Part")) continue;
    size_t pn = buckets_xml_child(&doc, i, "PartNumber"), en = buckets_xml_child(&doc, i, "ETag");
    if (!pn || !en || n >= BUCKETS_MAX_PARTS) {
      bad = true;
      break;
    }
    char *num = buckets_str_dup(buckets_str_trim(doc.nodes[pn].text));
    char *end;
    long v = strtol(num, &end, 10);
    bad = !*num || *end || v < 1 || v > BUCKETS_MAX_PARTS;
    free(num);
    buckets_buf etag = BUCKETS_BUF_INIT;
    if (!bad && !buckets_xml_unescape(doc.nodes[en].text, &etag)) bad = true;
    char *cks = NULL;
    static const char *const ck_tags[] = {"ChecksumCRC32", "ChecksumCRC32C", "ChecksumSHA1", "ChecksumSHA256",
                                          "ChecksumCRC64NVME"};
    for (size_t t = 0; !bad && !cks && t < BUCKETS_ARRAY_LEN(ck_tags); t++) {
      size_t cn = buckets_xml_child(&doc, i, ck_tags[t]);
      if (cn) cks = buckets_str_dup(buckets_str_trim(doc.nodes[cn].text));
    }
    if (!bad) {
      if (n == cap) {
        cap = cap ? cap * 2 : 16;
        parts = buckets_xrealloc(parts, cap * sizeof(*parts));
        etags = buckets_xrealloc(etags, cap * sizeof(*etags));
        cksums = buckets_xrealloc(cksums, cap * sizeof(*cksums));
      }
      etags[n] = etag.data ? etag.data : buckets_xstrdup("");
      cksums[n] = cks;
      parts[n] = (buckets_complete_part){(int)v, etags[n], cks};
      n++;
    } else {
      buckets_buf_free(&etag);
      free(cks);
    }
  }
  buckets_xml_doc_free(&doc);
  buckets_checksum want;
  buckets_s3_error cerr = bad || n == 0 ? BUCKETS_ERR_MALFORMED_XML : buckets_checksum_from_request(c->req, &want);
  if (cerr) {
    for (size_t i = 0; i < n; i++) {
      free(etags[i]);
      free(cksums[i]);
    }
    free(etags);
    free(cksums);
    free(parts);
    buckets_s3_write_error(c, cerr);
    return;
  }
  buckets_s3_repl_in ri;
  if (!buckets_s3_repl_in_parse(c, c->object, false, &ri)) {
    for (size_t i = 0; i < n; i++) {
      free(etags[i]);
      free(cksums[i]);
    }
    free(etags), free(cksums), free(parts);
    return;
  }
  buckets_object_info oi;
  bool versioned, suspended;
  buckets_s3_versioning(c, c->object, &versioned, &suspended);
  mpu_sse cs = {0};
  mpu_commit mc = {.mtime_ns = ri.mtime_ns};
  buckets_complete_opts co = {.versioned = versioned, .pre_commit = mpu_pre_commit, .ud = &mc};
  buckets_object_info ui;
  c->tags.paused = true; /* a lookup of our own: MinIO's handler tags only the completion */
  buckets_obj_err ui_err = buckets_obj_mpu_stat(c->s->layer, c->bucket, c->object, upload_id, &ui);
  c->tags.paused = false;
  if (ui_err == BUCKETS_OBJ_OK) {
    if (buckets_s3_sse_encrypted(&ui)) {
      buckets_s3_error ke = mpu_sse_open(c, &ui, want.type != 0, &cs);
      if (ke) {
        buckets_object_info_free(&ui);
        for (size_t i = 0; i < n; i++) {
          free(etags[i]);
          free(cksums[i]);
        }
        free(etags), free(cksums), free(parts);
        buckets_s3_sse_write_error(c, ke);
        return;
      }
      co.client_etag = mpu_client_etag;
      mc.cs = &cs;
    }
    buckets_object_info_free(&ui);
  }
  buckets_obj_err err = buckets_obj_mpu_complete(c->s->layer, c->bucket, c->object, upload_id, parts, n,
                                                 want.type ? &want : NULL, &co, &oi);
  OPENSSL_cleanse(&cs, sizeof(cs));
  for (size_t i = 0; i < n; i++) {
    free(etags[i]);
    free(cksums[i]);
  }
  free(etags);
  free(cksums);
  free(parts);
  if (err) {
    buckets_s3_write_error(c, err == BUCKETS_OBJ_ERR_PART_TOO_SMALL      ? BUCKETS_ERR_ENTITY_TOO_SMALL
                              : err == BUCKETS_OBJ_ERR_INVALID_PART       ? BUCKETS_ERR_INVALID_PART
                              : err == BUCKETS_OBJ_ERR_INVALID_PART_ORDER ? BUCKETS_ERR_INVALID_PART_ORDER
                                                                          : buckets_s3_obj_error(err));
    return;
  }
  buckets_s3_version_header(c, oi.version_id);
  oi.is_latest = true; /* the version just written */
  buckets_s3_expiration_header(c, &oi);
  etag_header(c->resp, oi.etag); /* setPutObjHeaders */
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "CompleteMultipartUploadResult", BUCKETS_S3_XMLNS);
  buckets_buf loc = BUCKETS_BUF_INIT;
  buckets_str host = buckets_http_header_get(c->req, "Host");
  buckets_buf_appendf(&loc, "%s://" BUCKETS_STR_FMT "/%s/%s", c->req->secure ? "https" : "http", BUCKETS_STR_ARG(host), c->bucket, c->object);
  buckets_xml_elem(b, "Location", loc.data);
  buckets_buf_free(&loc);
  buckets_xml_elem(b, "Bucket", c->bucket);
  buckets_xml_elem(b, "Key", c->object);
  buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", oi.etag);
  if (oi.checksum) {
    /* Reuse the header writer to decode the stored checksum, then mirror it into XML. */
    buckets_http_response tmp = {.content_length = -1};
    buckets_checksum_write_headers(oi.checksum, oi.checksum_len, 0, &tmp);
    buckets_str rest = buckets_buf_str(&tmp.headers), line;
    while (rest.n) {
      buckets_str_cut(rest, '\n', &line, &rest);
      buckets_str name, value;
      if (!buckets_str_cut(buckets_str_trim(line), ':', &name, &value)) continue;
      value = buckets_str_trim(value);
      if (value.n && value.p[value.n - 1] == '\r') value.n--;
      if (buckets_str_ieq_c(name, "X-Amz-Checksum-Type")) {
        buckets_xml_elem_str(b, "ChecksumType", value);
      } else {
        char tag[40];
        snprintf(tag, sizeof(tag), "Checksum%s", buckets_str_ieq_c(name, "X-Amz-Checksum-Crc64nvme") ? "CRC64NVME"
                 : buckets_str_ieq_c(name, "X-Amz-Checksum-Crc32c") ? "CRC32C"
                 : buckets_str_ieq_c(name, "X-Amz-Checksum-Crc32") ? "CRC32"
                 : buckets_str_ieq_c(name, "X-Amz-Checksum-Sha1") ? "SHA1" : "SHA256");
        buckets_xml_elem_str(b, tag, value);
      }
    }
    buckets_buf_free(&tmp.headers);
  }
  buckets_xml_close(b, "CompleteMultipartUploadResult");
  buckets_s3_write_xml(c, 200);
  buckets_s3_send_event(c, BUCKETS_EV_OBJECT_CREATED_COMPLETE_MULTIPART_UPLOAD, c->bucket, c->object, &oi, NULL);
  if (!ri.request) {
    buckets_repl_dsc dsc;
    buckets_repl_must(c->s, c->bucket, c->object, oi.meta, oi.nmeta, oi.meta_sys, oi.nmeta_sys, NULL,
                      BUCKETS_REPL_OBJECT, false, &dsc);
    buckets_repl_schedule(c->s, c->bucket, &oi, &dsc, BUCKETS_REPL_OBJECT, "replicate:incoming");
    buckets_repl_dsc_free(&dsc);
  }
  buckets_object_info_free(&oi);
}

static void xml_key(buckets_buf *b, const char *tag, const char *value, bool url);

static int upload_cmp(const void *x, const void *y) {
  const buckets_upload_info *a = x, *b = y;
  return a->initiated_ns < b->initiated_ns ? -1 : a->initiated_ns > b->initiated_ns;
}

/* ListMultipartUploads, as MinIO's handler + erasureObjects.ListMultipartUploads:
 * uploads of the one object named by prefix, oldest first, paged by upload-id-marker. */
void buckets_s3_list_uploads(s3_ctx *c) {
  const char *prefix = buckets_query_get(&c->q, "prefix");
  const char *key_marker = buckets_query_get(&c->q, "key-marker");
  const char *id_marker = buckets_query_get(&c->q, "upload-id-marker");
  const char *delimiter = buckets_query_get(&c->q, "delimiter");
  const char *encoding = buckets_query_get(&c->q, "encoding-type");
  const char *mu = buckets_query_get(&c->q, "max-uploads");
  long max = 10000; /* maxUploadsList */
  if (mu && *mu) {
    char *end;
    max = strtol(mu, &end, 10);
    if (*end || max < 0 || max > 2147483647L) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_UPLOADS);
      return;
    }
  }
  if (!prefix) prefix = "";
  if (key_marker && *key_marker && strncmp(key_marker, prefix, strlen(prefix)) != 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED); /* marker not common with prefix */
    return;
  }
  if (id_marker && *id_marker) {
    size_t kl = key_marker ? strlen(key_marker) : 0;
    if (kl && key_marker[kl - 1] == '/') {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    size_t il = strlen(id_marker);
    uint8_t *dec = buckets_xmalloc(il + 3);
    long dn = buckets_base64url_raw_decode(id_marker, il, dec);
    free(dec);
    if (dn < 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_UPLOAD);
      return;
    }
  }
  buckets_upload_info *ups;
  size_t n;
  buckets_obj_err err = buckets_obj_mpu_list_uploads(c->s->layer, c->bucket, prefix, &ups, &n);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  /* Without a prefix, MinIO answers from its upload cache: every upload,
   * oldest first, markers and max-uploads aside. */
  bool from_cache = !*prefix;
  if (n && !from_cache) qsort(ups, n, sizeof(*ups), upload_cmp);
  size_t start = 0;
  if (!from_cache && id_marker && *id_marker) {
    while (start < n && strcmp(ups[start].upload_id, id_marker) != 0) start++;
    if (start < n) start++;
  }
  size_t end = start;
  while (end < n) {
    end++;
    if (!from_cache && (long)(end - start) == max) break;
  }
  bool truncated = end < n;
  bool url = encoding && strcasecmp(encoding, "url") == 0;

  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListMultipartUploadsResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Bucket", c->bucket);
  xml_key(b, "KeyMarker", key_marker ? key_marker : "", url);
  buckets_xml_elem(b, "UploadIdMarker", ""); /* MinIO never echoes it */
  buckets_xml_elem(b, "NextKeyMarker", "");
  buckets_xml_elem(b, "NextUploadIdMarker", truncated && end > start ? ups[end - 1].upload_id : "");
  if (delimiter && *delimiter) xml_key(b, "Delimiter", delimiter, url);
  xml_key(b, "Prefix", prefix, url);
  if (encoding && *encoding) buckets_xml_elem(b, "EncodingType", encoding);
  buckets_buf_appendf(b, "<MaxUploads>%ld</MaxUploads>", max);
  buckets_xml_elem(b, "IsTruncated", truncated ? "true" : "false");
  for (size_t i = start; i < end; i++) {
    char ts[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(ups[i].initiated_ns, ts);
    buckets_xml_open(b, "Upload");
    xml_key(b, "Key", ups[i].object, url);
    buckets_xml_elem(b, "UploadId", ups[i].upload_id);
    /* MinIO leaves these empty. */
    buckets_buf_append_c(b, "<Initiator><ID></ID><DisplayName></DisplayName></Initiator>"
                              "<Owner><ID></ID><DisplayName></DisplayName></Owner><StorageClass></StorageClass>");
    buckets_xml_elem(b, "Initiated", ts);
    buckets_xml_close(b, "Upload");
  }
  buckets_xml_close(b, "ListMultipartUploadsResult");
  buckets_upload_info_free(ups, n);
  buckets_s3_write_xml(c, 200);
}

/* ---- GetObjectAttributes / ACL -------------------------------------------- */

/* ReadCheckSums via the header writer: returns the value for one algorithm. */
static bool checksum_value(const buckets_object_info *oi, int part, const char *header, char *out, size_t cap,
                           char *type_out, size_t type_cap) {
  if (!oi->checksum) return false;
  buckets_http_response tmp = {.content_length = -1};
  buckets_checksum_write_headers(oi->checksum, oi->checksum_len, part, &tmp);
  bool found = false;
  buckets_str rest = buckets_buf_str(&tmp.headers), line;
  while (rest.n) {
    buckets_str_cut(rest, '\n', &line, &rest);
    buckets_str name, value;
    if (!buckets_str_cut(line, ':', &name, &value)) continue;
    value = buckets_str_trim(value);
    if (value.n && value.p[value.n - 1] == '\r') value.n--;
    if (buckets_str_ieq_c(name, header)) {
      snprintf(out, cap, BUCKETS_STR_FMT, BUCKETS_STR_ARG(value));
      char *dash = strchr(out, '-');
      if (dash) *dash = '\0'; /* attributes drop the "-N" suffix */
      found = true;
    } else if (type_out && buckets_str_ieq_c(name, "X-Amz-Checksum-Type")) {
      snprintf(type_out, type_cap, BUCKETS_STR_FMT, BUCKETS_STR_ARG(value));
    }
  }
  buckets_buf_free(&tmp.headers);
  return found;
}

static void get_object_attributes(s3_ctx *c) {
  static const char *const names[] = {"ETag", "Checksum", "ObjectParts", "StorageClass", "ObjectSize"};
  bool want[5] = {false};
  bool any = false;
  for (size_t h = 0; h < c->req->nheaders; h++) {
    if (!buckets_str_ieq_c(c->req->headers[h].name, "X-Amz-Object-Attributes")) continue;
    buckets_str rest = c->req->headers[h].value, item;
    while (rest.n) {
      buckets_str_cut(rest, ',', &item, &rest);
      item = buckets_str_trim(item);
      if (!item.n) continue;
      bool known = false;
      for (size_t i = 0; i < 5; i++) {
        if (buckets_str_eq_c(item, names[i])) want[i] = known = any = true;
      }
      if (!known) {
        buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ATTRIBUTE_NAME);
        return;
      }
    }
  }
  if (!any) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ATTRIBUTE_NAME);
    return;
  }
  long max_parts = 10000, marker = 0;
  buckets_str mp = buckets_http_header_get(c->req, "X-Amz-Max-Parts");
  buckets_str pm = buckets_http_header_get(c->req, "X-Amz-Part-Number-Marker");
  if (mp.p) {
    char *v = buckets_str_dup(mp), *end;
    max_parts = strtol(v, &end, 10);
    bool bad = !*v || *end;
    free(v);
    if (bad) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ARGUMENT);
      return;
    }
    if (max_parts == 0) max_parts = 10000;
  }
  if (pm.p) {
    char *v = buckets_str_dup(pm), *end;
    marker = strtol(v, &end, 10);
    bool bad = !*v || *end;
    free(v);
    if (bad) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ARGUMENT);
      return;
    }
  }
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, c->object, version, &oi);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  if (oi.delete_marker) {
    buckets_http_resp_header(c->resp, "x-amz-version-id", oi.version_id);
    buckets_http_resp_header(c->resp, "x-amz-delete-marker", "true");
    buckets_s3_write_error(c, version && *version ? BUCKETS_ERR_METHOD_NOT_ALLOWED : BUCKETS_ERR_NO_SUCH_KEY);
    buckets_object_info_free(&oi);
    return;
  }
  /* DecryptObjectInfo, then decryptPartsChecksums */
  buckets_s3_error serr = buckets_s3_sse_check_read(c, &oi, false);
  if (!serr && buckets_s3_sse_encrypted(&oi)) {
    uint8_t key[32];
    serr = buckets_s3_sse_object_key(c, &oi, c->bucket, c->object, false, key);
    if (!serr) {
      char etag[80];
      buckets_s3_sse_client_etag(c, &oi, key, etag);
      snprintf(oi.etag, sizeof(oi.etag), "%s", etag);
      buckets_s3_sse_unseal_checksum(key, &oi);
      OPENSSL_cleanse(key, sizeof(key));
    }
  }
  if (!serr && (buckets_s3_sse_encrypted(&oi) || buckets_s3_is_compressed(&oi))) oi.size = buckets_s3_actual_size(&oi);
  if (serr) {
    buckets_object_info_free(&oi);
    buckets_s3_sse_write_error(c, serr);
    return;
  }
  if (check_preconditions(c, &oi)) {
    buckets_object_info_free(&oi);
    return;
  }
  bool versioned, suspended;
  buckets_s3_versioning(c, c->object, &versioned, &suspended);
  if (versioned) buckets_http_resp_header(c->resp, "X-Amz-Version-Id", oi.version_id); /* Header().Set, canonical */
  char lm[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http((time_t)(oi.mod_time_ns / 1000000000LL), lm);
  buckets_http_resp_header(c->resp, "Last-Modified", lm);

  static const char *const ck_headers[] = {"X-Amz-Checksum-Crc32", "X-Amz-Checksum-Crc32c", "X-Amz-Checksum-Sha1",
                                           "X-Amz-Checksum-Sha256", "X-Amz-Checksum-Crc64nvme"};
  static const char *const ck_tags[] = {"ChecksumCRC32", "ChecksumCRC32C", "ChecksumSHA1", "ChecksumSHA256",
                                        "ChecksumCRC64NVME"};
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open(b, "getObjectAttributesResponse"); /* MinIO's (unexported Go type) element name */
  if (want[0]) buckets_xml_elem(b, "ETag", oi.etag);
  if (want[1] && oi.checksum) {
    buckets_buf ck = BUCKETS_BUF_INIT;
    char type[32] = "";
    for (size_t i = 0; i < 5; i++) {
      char v[64];
      if (checksum_value(&oi, 0, ck_headers[i], v, sizeof(v), type, sizeof(type))) buckets_xml_elem(&ck, ck_tags[i], v);
    }
    if (ck.len) {
      buckets_xml_open(b, "Checksum");
      buckets_buf_append(b, ck.data, ck.len);
      if (type[0]) buckets_xml_elem(b, "ChecksumType", type);
      buckets_xml_close(b, "Checksum");
    }
    buckets_buf_free(&ck);
  }
  if (want[2]) {
    buckets_buf parts = BUCKETS_BUF_INIT;
    int next = 0, listed = 0;
    for (size_t i = 0; i < oi.nparts; i++) {
      if (oi.parts[i].number <= marker) continue;
      if (listed == max_parts) break;
      next = oi.parts[i].number;
      listed++;
      buckets_xml_open(&parts, "Part");
      buckets_buf_appendf(&parts, "<PartNumber>%d</PartNumber><Size>%lld</Size>", oi.parts[i].number,
                          (long long)oi.parts[i].size);
      for (size_t k = 0; oi.nparts > 1 && k < 5; k++) {
        char v[64];
        if (checksum_value(&oi, oi.parts[i].number, ck_headers[k], v, sizeof(v), NULL, 0)) {
          buckets_xml_elem(&parts, ck_tags[k], v);
        }
      }
      buckets_xml_close(&parts, "Part");
    }
    buckets_xml_open(b, "ObjectParts");
    buckets_xml_elem(b, "IsTruncated", (size_t)next != oi.nparts ? "true" : "false");
    buckets_buf_appendf(b, "<MaxParts>%ld</MaxParts><NextPartNumberMarker>%d</NextPartNumberMarker>", max_parts, next);
    buckets_buf_appendf(b, "<PartNumberMarker>%ld</PartNumberMarker><PartsCount>%zu</PartsCount>", marker, oi.nparts);
    buckets_buf_append(b, parts.data, parts.len);
    buckets_xml_close(b, "ObjectParts");
    buckets_buf_free(&parts);
  }
  if (want[3]) {
    const char *sc = buckets_object_meta(&oi, "x-amz-storage-class");
    buckets_xml_elem(b, "StorageClass", sc ? sc : "STANDARD");
  }
  if (want[4] && oi.size) buckets_buf_appendf(b, "<ObjectSize>%lld</ObjectSize>", (long long)oi.size);
  buckets_xml_close(b, "getObjectAttributesResponse");
  buckets_s3_write_xml(c, 200);
  buckets_s3_send_event(c, BUCKETS_EV_OBJECT_ACCESSED_ATTRIBUTES, c->bucket, c->object, &oi, NULL);
  buckets_object_info_free(&oi);
}

/* MinIO supports only the canned private ACL (acl-handlers.go). */
void buckets_s3_write_private_acl(s3_ctx *c) {
  buckets_buf_append_c(&c->resp->body,
                       "<AccessControlPolicy><Owner><ID></ID><DisplayName></DisplayName></Owner><AccessControlList>"
                       "<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
                       "xsi:type=\"CanonicalUser\"><Type>CanonicalUser</Type></Grantee>"
                       "<Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>");
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "text/xml; charset=utf-8");
}

void buckets_s3_put_acl(s3_ctx *c) {
  buckets_str canned = buckets_http_header_get(c->req, "X-Amz-Acl");
  if (canned.p && canned.n) {
    if (!buckets_str_eq_c(canned, "private")) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    c->resp->status = 200;
    return;
  }
  buckets_s3_error err = buckets_s3_read_doc(c);
  if (err) {
    buckets_s3_write_error(c, err);
    return;
  }
  buckets_xml_doc doc;
  if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc)) {
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }
  size_t acl = buckets_xml_child(&doc, 0, "AccessControlList");
  size_t grant = acl ? buckets_xml_child(&doc, acl, "Grant") : 0;
  size_t perm = grant ? buckets_xml_child(&doc, grant, "Permission") : 0;
  bool ok = perm && buckets_str_eq_c(buckets_str_trim(doc.nodes[perm].text), "FULL_CONTROL");
  buckets_xml_doc_free(&doc);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
    return;
  }
  c->resp->status = 200;
}

/* ---- routing -------------------------------------------------------------- */

/* Server-side encryption arrives in Phase 5. Until then no request may leave
 * data unencrypted that the client asked to encrypt: SSE headers get MinIO's
 * answers for a server without a KMS, and SSE-C keys never travel in clear. */
static bool refuse_sse(s3_ctx *c) {
  /* MinIO's request validator: SSE-C needs TLS, on every request */
  bool ssec = buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Algorithm").p ||
              buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Key").p ||
              buckets_http_header_get(c->req, "X-Amz-Server-Side-Encryption-Customer-Key-Md5").p ||
              buckets_http_header_get(c->req, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Algorithm").p ||
              buckets_http_header_get(c->req, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key").p ||
              buckets_http_header_get(c->req, "X-Amz-Copy-Source-Server-Side-Encryption-Customer-Key-Md5").p;
  if (ssec && !c->req->secure) {
    buckets_s3_write_error(c, BUCKETS_ERR_INSECURE_SSE_CUSTOMER_REQUEST);
    return true;
  }
  return false;
}

/* The policy action of an object-level request (MinIO's router + handlers). */
static bool authorize_object_request(s3_ctx *c) {
  buckets_str m = c->req->method;
  const char *upload_id = buckets_query_get(&c->q, "uploadId");
  const char *vid = buckets_query_get(&c->q, "versionId");
  const char *action = NULL;
  if (buckets_str_eq_c(m, "POST") && buckets_query_has(&c->q, "uploads")) {
    action = "s3:PutObject";
  } else if (upload_id) {
    if (buckets_str_eq_c(m, "PUT") || buckets_str_eq_c(m, "POST")) action = "s3:PutObject";
    else if (buckets_str_eq_c(m, "GET")) action = "s3:ListMultipartUploadParts";
    else if (buckets_str_eq_c(m, "DELETE")) action = "s3:AbortMultipartUpload";
  } else if (buckets_query_has(&c->q, "attributes") && buckets_str_eq_c(m, "GET")) {
    bool versioned = vid && *vid;
    if (!buckets_s3_require(c, versioned ? "s3:GetObjectVersionAttributes" : "s3:GetObjectAttributes", c->bucket,
                            c->object, NULL)) {
      return false;
    }
    action = versioned ? "s3:GetObjectVersion" : "s3:GetObject";
  } else if (buckets_query_has(&c->q, "acl")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetBucketPolicy";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutBucketPolicy";
  } else if (buckets_query_has(&c->q, "retention")) {
    /* PUT is authorized by the handler, with the retention's condition values */
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetObjectRetention";
    else if (!buckets_str_eq_c(m, "PUT")) action = NULL;
  } else if (buckets_query_has(&c->q, "legal-hold")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetObjectLegalHold";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutObjectLegalHold";
  } else if (buckets_query_has(&c->q, "tagging")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetObjectTagging";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutObjectTagging";
    else if (buckets_str_eq_c(m, "DELETE")) action = "s3:DeleteObjectTagging";
  } else if (buckets_str_eq_c(m, "PUT")) {
    action = "s3:PutObject"; /* plus s3:GetObject on a copy source, checked by the handler */
  } else if (buckets_str_eq_c(m, "GET") || buckets_str_eq_c(m, "HEAD")) {
    action = "s3:GetObject";
  } else if (buckets_str_eq_c(m, "DELETE")) {
    action = "s3:DeleteObject";
  }
  return !action || buckets_s3_require(c, action, c->bucket, c->object, vid);
}

void buckets_s3_route_object(s3_ctx *c) {
  /* rejectedObjAPIs: matched before any object route, without authorization */
  buckets_str rm = c->req->method;
  if ((buckets_query_has(&c->q, "torrent") && !buckets_str_eq_c(rm, "HEAD") && !buckets_str_eq_c(rm, "POST")) ||
      (buckets_query_has(&c->q, "acl") && buckets_str_eq_c(rm, "DELETE"))) {
    buckets_s3_write_rejected(c);
    return;
  }
  if (!authorize_object_request(c)) return;
  if (refuse_sse(c)) return;
  /* getOpts: a versionId must be "null" or a UUID. */
  const char *vq = buckets_query_get(&c->q, "versionId");
  uint8_t vq_id[16];
  if (vq && *vq && !buckets_xl_version_id_parse(vq, vq_id)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_VERSION_ID);
    return;
  }
  buckets_str m = c->req->method;
  const char *upload_id = buckets_query_get(&c->q, "uploadId");
  if (buckets_str_eq_c(m, "POST") && buckets_query_has(&c->q, "uploads")) {
    mpu_create(c);
    return;
  }
  if (upload_id) {
    if (buckets_str_eq_c(m, "PUT")) mpu_put_part(c, upload_id);
    else if (buckets_str_eq_c(m, "GET")) mpu_list_parts(c, upload_id);
    else if (buckets_str_eq_c(m, "DELETE")) mpu_abort(c, upload_id);
    else if (buckets_str_eq_c(m, "POST")) mpu_complete(c, upload_id);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_query_has(&c->q, "attributes") && buckets_str_eq_c(m, "GET")) {
    get_object_attributes(c);
    return;
  }
  if (buckets_query_has(&c->q, "retention")) {
    if (buckets_str_eq_c(m, "PUT")) buckets_s3_put_object_retention(c);
    else if (buckets_str_eq_c(m, "GET")) buckets_s3_get_object_retention(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_query_has(&c->q, "tagging")) {
    if (buckets_str_eq_c(m, "PUT")) buckets_s3_put_object_tagging(c);
    else if (buckets_str_eq_c(m, "GET")) buckets_s3_get_object_tagging(c);
    else if (buckets_str_eq_c(m, "DELETE")) buckets_s3_delete_object_tagging(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_query_has(&c->q, "legal-hold")) {
    if (buckets_str_eq_c(m, "PUT")) buckets_s3_put_object_legal_hold(c);
    else if (buckets_str_eq_c(m, "GET")) buckets_s3_get_object_legal_hold(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_query_has(&c->q, "acl")) {
    buckets_object_info oi;
    buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, c->object, buckets_query_get(&c->q, "versionId"), &oi);
    if (err) {
      buckets_s3_write_error(c, buckets_s3_obj_error(err));
      return;
    }
    buckets_object_info_free(&oi);
    if (buckets_str_eq_c(m, "GET")) buckets_s3_write_private_acl(c);
    else if (buckets_str_eq_c(m, "PUT")) buckets_s3_put_acl(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  static const char *const unsupported[] = {"select", "restore", "torrent"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(unsupported); i++) {
    if (buckets_query_has(&c->q, unsupported[i])) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
  }
  if (buckets_str_eq_c(m, "PUT")) {
    put_object(c);
  } else if (buckets_str_eq_c(m, "GET")) {
    get_object(c, false);
  } else if (buckets_str_eq_c(m, "HEAD")) {
    get_object(c, true);
  } else if (buckets_str_eq_c(m, "DELETE")) {
    delete_object(c);
  } else if (buckets_str_eq_c(m, "POST")) {
    buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
  } else {
    buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
  }
}

/* ---- DeleteObjects (POST ?delete) ----------------------------------------- */

#define MAX_DELETE_LIST 1000

/* validateLengthAndChecksum: reads the body, which must come with Content-MD5
 * or an x-amz-checksum-* header, and verifies it. */
buckets_s3_error buckets_s3_read_checked_doc(s3_ctx *c) {
  buckets_str md5h = buckets_http_header_get(c->req, "Content-MD5");
  buckets_checksum want;
  bool has_cks = buckets_checksum_from_request(c->req, &want) == BUCKETS_ERR_NONE && want.type &&
                 !(want.type & BUCKETS_CKSUM_TRAILING);
  uint8_t md5_want[18];
  long md5_len = md5h.p && md5h.n ? buckets_base64_decode(md5h.p, md5h.n, md5_want) : -1;
  if (md5h.p && md5h.n ? md5_len != 16 : !has_cks) return BUCKETS_ERR_MISSING_CONTENT_MD5;
  buckets_s3_error err = buckets_s3_read_doc(c);
  if (err) return err;
  if (md5_len == 16) {
    uint8_t got[16];
    buckets_md5(c->doc.data ? c->doc.data : "", c->doc.len, got);
    if (memcmp(got, md5_want, 16) != 0) return BUCKETS_ERR_BAD_DIGEST;
    return BUCKETS_ERR_NONE;
  }
  buckets_cksum_hasher h;
  buckets_cksum_hasher_init(&h, want.type & BUCKETS_CKSUM_BASE_MASK);
  buckets_cksum_hasher_update(&h, c->doc.data ? c->doc.data : "", c->doc.len);
  uint8_t raw[64];
  size_t rl = buckets_cksum_hasher_final(&h, raw);
  return rl != want.raw_len || memcmp(raw, want.raw, rl) != 0 ? BUCKETS_ERR_BAD_DIGEST : BUCKETS_ERR_NONE;
}

typedef struct {
  char *key;
  char version[64];
  bool marker;
} deleted_ev;

static void flush_delete_events(s3_ctx *c, deleted_ev *evs, size_t n) {
  for (size_t i = 0; i < n; i++) {
    buckets_s3_send_event(c, evs[i].marker ? BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED : BUCKETS_EV_OBJECT_REMOVED_DELETE,
                          c->bucket, evs[i].key, NULL, evs[i].version);
    free(evs[i].key);
    evs[i].key = NULL;
  }
}

void buckets_s3_delete_objects(s3_ctx *c) {
  buckets_s3_error err = buckets_s3_read_checked_doc(c);
  if (err) {
    buckets_s3_write_error(c, err);
    return;
  }
  buckets_xml_doc doc;
  if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc) || !buckets_str_eq_c(doc.nodes[0].name, "Delete")) {
    if (doc.nodes) buckets_xml_doc_free(&doc);
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }
  bool quiet = false;
  size_t qn = buckets_xml_child(&doc, 0, "Quiet");
  if (qn) quiet = buckets_str_eq_c(buckets_str_trim(doc.nodes[qn].text), "true");
  size_t count = 0;
  for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
    if (buckets_str_eq_c(doc.nodes[i].name, "Object")) count++;
  }
  if (count == 0 || count > MAX_DELETE_LIST) {
    buckets_xml_doc_free(&doc);
    buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    return;
  }

  if (c->audited) { /* updateReqContext: every object asked for, leading slash trimmed */
    for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
      if (!buckets_str_eq_c(doc.nodes[i].name, "Object")) continue;
      size_t kn = buckets_xml_child(&doc, i, "Key"), vn = buckets_xml_child(&doc, i, "VersionId");
      buckets_buf key = BUCKETS_BUF_INIT, ver = BUCKETS_BUF_INIT;
      if (kn) buckets_xml_unescape(doc.nodes[kn].text, &key);
      if (vn) buckets_xml_unescape(doc.nodes[vn].text, &ver);
      const char *k = key.data ? key.data : "";
      while (*k == '/') k++;
      if (c->audit_objects.len) buckets_buf_append_char(&c->audit_objects, ',');
      buckets_buf_append_c(&c->audit_objects, "{\"objectName\":");
      buckets_json_go_string(&c->audit_objects, k, strlen(k));
      if (ver.len) {
        buckets_buf_append_c(&c->audit_objects, ",\"versionId\":");
        buckets_json_go_string(&c->audit_objects, ver.data, ver.len);
      }
      buckets_buf_append_char(&c->audit_objects, '}');
      buckets_buf_free(&key);
      buckets_buf_free(&ver);
    }
  }
  c->tags.delete_op = "DeleteObjects";
  bool replicates = bucket_replicates(c);
  deleted_ev *evs = buckets_xcalloc(count, sizeof(*evs));
  size_t nev = 0;
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "DeleteResult", BUCKETS_S3_XMLNS);
  for (size_t i = doc.nodes[0].first_child; i; i = doc.nodes[i].next_sibling) {
    if (!buckets_str_eq_c(doc.nodes[i].name, "Object")) continue;
    size_t kn = buckets_xml_child(&doc, i, "Key"), vn = buckets_xml_child(&doc, i, "VersionId");
    buckets_buf key = BUCKETS_BUF_INIT, ver = BUCKETS_BUF_INIT;
    bool ok = kn && buckets_xml_unescape(doc.nodes[kn].text, &key) && key.len > 0 &&
              (!vn || buckets_xml_unescape(doc.nodes[vn].text, &ver));
    buckets_s3_error e = BUCKETS_ERR_NONE;
    buckets_delete_result res = {0};
    uint8_t vid_bytes[16];
    char detail[160] = "";
    if (!ok) {
      e = BUCKETS_ERR_INVALID_OBJECT_NAME;
    } else if (ver.len && !buckets_xl_version_id_parse(ver.data, vid_bytes)) {
      e = BUCKETS_ERR_NO_SUCH_VERSION; /* with uuid.Parse's reason, as MinIO */
      if (ver.len != 36) snprintf(detail, sizeof(detail), " (invalid UUID length: %zu)", ver.len);
      else snprintf(detail, sizeof(detail), " (invalid UUID format)");
    } else if ((c->audited ? (free(c->err_object), c->err_object = buckets_xstrdup(key.data)) : NULL),
               (e = buckets_s3_authorize(c, "s3:DeleteObject", c->bucket, key.data, ver.len ? ver.data : NULL))) {
      /* reported for this key (the request info now names it, as MinIO's per-object check leaves it) */
    } else if ((e = buckets_s3_lock_check_delete(c, key.data, ver.len ? ver.data : NULL))) {
      /* locked */
    } else {
      buckets_delete_opts o = {.version_id = ver.len ? ver.data : NULL};
      buckets_s3_versioning(c, key.data, &o.versioned, &o.suspended);
      char *saved = c->object;
      c->object = key.data; /* delete_decide checks this key */
      del_decide dd = {c, o.version_id, o.versioned};
      if (replicates && o.versioned) {
        o.decide = delete_decide;
        o.decide_ud = &dd;
      }
      buckets_obj_err oe = buckets_obj_delete_ex(c->s->layer, c->bucket, key.data, &o, &res);
      c->object = saved;
      if (!oe && o.decide) buckets_repl_schedule_delete(c->s, c->bucket, key.data, &res, "replicate:incoming:delete");
      if (oe && oe != BUCKETS_OBJ_ERR_NO_SUCH_KEY && oe != BUCKETS_OBJ_ERR_NO_SUCH_VERSION) e = buckets_s3_obj_error(oe);
      if (oe == BUCKETS_OBJ_ERR_NO_SUCH_KEY && !ver.len && (o.versioned || o.suspended)) {
        /* MinIO's DeleteObjects reports the marker it would have made for a
         * key with no versions (a fresh ID when versioned), though none is stored. */
        res.delete_marker = true;
        if (o.versioned) buckets_uuid_v4(res.version_id);
        else snprintf(res.version_id, sizeof(res.version_id), "null");
      }
    }
    if (e) {
      /* DeleteError: Code, Message, Key, VersionId */
      const buckets_s3_error_info *info = buckets_s3_error_get(e);
      buckets_buf msg = BUCKETS_BUF_INIT;
      buckets_buf_appendf(&msg, "%s%s", info->message, detail);
      buckets_xml_open(b, "Error");
      buckets_xml_elem(b, "Code", info->code);
      buckets_xml_elem(b, "Message", msg.data);
      buckets_xml_elem(b, "Key", key.data ? key.data : "");
      if (ver.len) buckets_xml_elem(b, "VersionId", ver.data);
      buckets_xml_close(b, "Error");
      buckets_buf_free(&msg);
    } else {
      /* the event goes out once the response is written (extractRespElements) */
      deleted_ev *d = &evs[nev++];
      d->key = buckets_xstrdup(key.data);
      snprintf(d->version, sizeof(d->version), "%s",
               res.delete_marker ? (ver.len ? ver.data : res.version_id) : (ver.len ? ver.data : ""));
      d->marker = res.delete_marker;
    }
    if (!e && !quiet) {
      /* DeletedObject: DeleteMarker, DeleteMarkerVersionId, Key, VersionId (omitempty) */
      buckets_xml_open(b, "Deleted");
      if (res.delete_marker) {
        buckets_xml_elem(b, "DeleteMarker", "true");
        const char *dmv = ver.len ? ver.data : res.version_id;
        if (strcmp(dmv, "null") != 0) buckets_xml_elem(b, "DeleteMarkerVersionId", dmv);
      }
      buckets_xml_elem(b, "Key", key.data);
      if (ver.len) buckets_xml_elem(b, "VersionId", ver.data);
      buckets_xml_close(b, "Deleted");
    }
    buckets_buf_free(&key);
    buckets_buf_free(&ver);
  }
  buckets_xml_close(b, "DeleteResult");
  buckets_xml_doc_free(&doc);
  buckets_s3_write_xml(c, 200);
  flush_delete_events(c, evs, nev);
  free(evs);
  c->tags.delete_op = NULL;
}

/* ---- ListObjects v1 / v2 -------------------------------------------------- */

/* s3URLEncode: like url.QueryEscape but '/' kept and space as %20. */
/* MinIO's s3URLEncode: query escaping, but '/' and '*' kept and '~' escaped. */
static void url_encode_key(buckets_buf *out, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '*' || *p == '/') {
      buckets_buf_append_char(out, (char)*p);
    } else if (*p == ' ') {
      buckets_buf_append_char(out, '+');
    } else {
      char e[3] = {'%', hex[*p >> 4], hex[*p & 15]};
      buckets_buf_append(out, e, 3);
    }
  }
}

static void xml_key(buckets_buf *b, const char *tag, const char *value, bool url) {
  if (!url) {
    buckets_xml_elem(b, tag, value);
    return;
  }
  buckets_buf enc = BUCKETS_BUF_INIT;
  url_encode_key(&enc, value ? value : "");
  buckets_xml_elem(b, tag, enc.data ? enc.data : "");
  buckets_buf_free(&enc);
}

/* DecryptETags: listed encrypted objects show their plaintext size and the
 * ETag clients see. */
static void sse_list_view(s3_ctx *c, buckets_obj_listing *l) {
  for (size_t i = 0; i < l->nobjects; i++) {
    buckets_object_info *o = &l->objects[i];
    if (o->delete_marker) continue;
    bool enc = buckets_s3_sse_encrypted(o);
    if (!enc && !buckets_s3_is_compressed(o)) continue;
    if (enc) {
      char etag[80];
      buckets_s3_sse_client_etag(c, o, NULL, etag);
      snprintf(o->etag, sizeof(o->etag), "%s", etag);
    }
    int64_t size = buckets_s3_actual_size(o);
    if (size >= 0) o->size = size;
  }
}

/* The encryption entry MinIO puts first in a metadata listing's UserMetadata. */
static const char *sse_list_meta(const buckets_object_info *o, const char **value) {
  switch (buckets_s3_sse_kind_of(o)) {
  case BUCKETS_SSE_S3: *value = "AES256"; return "X-Amz-Server-Side-Encryption";
  case BUCKETS_SSE_KMS: *value = "aws:kms"; return "X-Amz-Server-Side-Encryption";
  case BUCKETS_SSE_C: *value = "AES256"; return "X-Amz-Server-Side-Encryption-Customer-Algorithm";
  default: return NULL;
  }
}

void buckets_s3_list_objects(s3_ctx *c, bool v2) {
  const char *max_keys_s = buckets_query_get(&c->q, "max-keys");
  long long max_keys = BUCKETS_MAX_LIST_KEYS;
  if (max_keys_s) {
    char *end = NULL;
    max_keys = strtoll(max_keys_s, &end, 10);
    if (!*max_keys_s || *end || max_keys < 0 || max_keys > 2147483647LL) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_KEYS);
      return;
    }
  }
  const char *encoding = buckets_query_get(&c->q, "encoding-type");
  if (encoding && *encoding && strcasecmp(encoding, "url") != 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ENCODING_METHOD);
    return;
  }
  bool url = encoding && *encoding;
  const char *prefix = buckets_query_get(&c->q, "prefix");
  const char *delimiter = buckets_query_get(&c->q, "delimiter");
  const char *start_after = v2 ? buckets_query_get(&c->q, "start-after") : NULL;
  const char *token = v2 ? buckets_query_get(&c->q, "continuation-token") : NULL;
  bool fetch_owner = v2 && buckets_query_get(&c->q, "fetch-owner") &&
                     strcmp(buckets_query_get(&c->q, "fetch-owner"), "true") == 0;
  /* MinIO extension (ListObjectsV2M): user metadata inline in the listing. */
  bool with_meta = v2 && buckets_query_get(&c->q, "metadata") && strcmp(buckets_query_get(&c->q, "metadata"), "true") == 0;

  /* v2 continuation tokens are the base64 of the next marker (as MinIO does). */
  char *marker = NULL;
  if (v2 && token) {
    size_t tl = strlen(token);
    uint8_t *dec = buckets_xmalloc(tl + 3);
    long n = tl ? buckets_base64_decode(token, tl, dec) : -1;
    if (n <= 0) {
      free(dec);
      buckets_s3_write_error(c, BUCKETS_ERR_INCORRECT_CONTINUATION_TOKEN);
      return;
    }
    marker = buckets_xstrndup((char *)dec, (size_t)n);
    free(dec);
  } else if (v2) {
    marker = start_after ? buckets_xstrdup(start_after) : NULL;
  } else {
    const char *m = buckets_query_get(&c->q, "marker");
    marker = m ? buckets_xstrdup(m) : NULL;
  }

  buckets_obj_listing l;
  buckets_obj_err err = buckets_obj_list(c->s->layer, c->bucket, prefix ? prefix : "", marker, delimiter,
                                         (int)BUCKETS_MIN(max_keys, BUCKETS_MAX_LIST_KEYS), &l);
  if (err) {
    free(marker);
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  sse_list_view(c, &l);


  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListBucketResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Name", c->bucket);
  xml_key(b, "Prefix", prefix, url);
  if (v2) {
    if (start_after) xml_key(b, "StartAfter", start_after, url);
    if (token) buckets_xml_elem(b, "ContinuationToken", token);
    buckets_buf_appendf(b, "<KeyCount>%zu</KeyCount>", l.nobjects + l.nprefixes);
  } else {
    xml_key(b, "Marker", buckets_query_get(&c->q, "marker"), url);
  }
  buckets_buf_appendf(b, "<MaxKeys>%lld</MaxKeys>", max_keys);
  if (delimiter && *delimiter) xml_key(b, "Delimiter", delimiter, url);
  if (url) buckets_xml_elem(b, "EncodingType", "url");
  buckets_xml_elem(b, "IsTruncated", l.truncated ? "true" : "false");
  if (l.truncated && l.next_marker) {
    if (v2) {
      size_t nl = strlen(l.next_marker);
      char *tok = buckets_xmalloc(4 * ((nl + 2) / 3) + 1);
      buckets_base64_encode((const uint8_t *)l.next_marker, nl, tok);
      buckets_xml_elem(b, "NextContinuationToken", tok);
      free(tok);
    } else if (delimiter && *delimiter) {
      xml_key(b, "NextMarker", l.next_marker, url);
    }
  }
  for (size_t i = 0; i < l.nobjects; i++) {
    const buckets_object_info *o = &l.objects[i];
    char lm[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(o->mod_time_ns, lm);
    buckets_xml_open(b, "Contents");
    xml_key(b, "Key", o->name, url);
    buckets_xml_elem(b, "LastModified", lm);
    buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", o->etag);
    buckets_buf_appendf(b, "<Size>%lld</Size>", (long long)o->size);
    if (!v2 || fetch_owner) {
      buckets_xml_open(b, "Owner");
      buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
      buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_NAME);
      buckets_xml_close(b, "Owner");
    }
    const char *sc = buckets_object_meta(o, "x-amz-storage-class");
    buckets_xml_elem(b, "StorageClass", sc ? sc : "STANDARD");
    if (with_meta) {
      bool any = false;
      const char *sv, *sk = sse_list_meta(o, &sv);
      if (sk) {
        buckets_xml_open(b, "UserMetadata");
        any = true;
        buckets_xml_elem(b, sk, sv);
      }
      for (size_t k = 0; k < o->nmeta; k++) {
        if (has_prefix_fold(o->meta[k].key, BUCKETS_XL_RESERVED_PREFIX) || strcasecmp(o->meta[k].key, "X-Amz-Tagging") == 0)
          continue;
        if (!any) buckets_xml_open(b, "UserMetadata");
        any = true;
        buckets_xml_elem(b, o->meta[k].key, (const char *)o->meta[k].value);
      }
      if (any) buckets_xml_close(b, "UserMetadata");
      const char *ut = buckets_object_meta(o, "X-Amz-Tagging");
      if (ut && *ut && buckets_s3_authorize(c, "s3:GetObjectTagging", c->bucket, o->name, NULL) == BUCKETS_ERR_NONE)
        buckets_xml_elem(b, "UserTags", ut);
      buckets_xml_open(b, "Internal");
      buckets_buf_appendf(b, "<K>%d</K><M>%d</M>", o->data_blocks, o->parity_blocks);
      buckets_xml_close(b, "Internal");
    }
    buckets_xml_close(b, "Contents");
  }
  for (size_t i = 0; i < l.nprefixes; i++) {
    buckets_xml_open(b, "CommonPrefixes");
    xml_key(b, "Prefix", l.prefixes[i], url);
    buckets_xml_close(b, "CommonPrefixes");
  }
  buckets_xml_close(b, "ListBucketResult");
  buckets_obj_list_free(&l);
  free(marker);
  buckets_s3_write_xml(c, 200);
}

/* ---- ListObjectVersions --------------------------------------------------- */

void buckets_s3_list_object_versions(s3_ctx *c) {
  const char *max_keys_s = buckets_query_get(&c->q, "max-keys");
  long long max_keys = BUCKETS_MAX_LIST_KEYS;
  if (max_keys_s && *max_keys_s) {
    char *end = NULL;
    max_keys = strtoll(max_keys_s, &end, 10);
    if (*end || max_keys < 0 || max_keys > 2147483647LL) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_MAX_KEYS);
      return;
    }
  }
  const char *encoding = buckets_query_get(&c->q, "encoding-type");
  if (encoding && *encoding && strcasecmp(encoding, "url") != 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_ENCODING_METHOD);
    return;
  }
  bool url = encoding && *encoding;
  const char *prefix = buckets_query_get(&c->q, "prefix");
  const char *delimiter = buckets_query_get(&c->q, "delimiter");
  const char *key_marker = buckets_query_get(&c->q, "key-marker");
  const char *vid_marker = buckets_query_get(&c->q, "version-id-marker");
  bool with_meta = buckets_query_get(&c->q, "metadata") && strcmp(buckets_query_get(&c->q, "metadata"), "true") == 0;
  if (vid_marker && *vid_marker && strcmp(vid_marker, "null") != 0) {
    uint8_t id[16];
    if (!buckets_xl_version_id_parse(vid_marker, id)) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_VERSION_ID);
      return;
    }
  }
  buckets_obj_listing l;
  buckets_obj_err err = buckets_obj_list_versions(c->s->layer, c->bucket, prefix ? prefix : "", key_marker, vid_marker,
                                                  delimiter, (int)BUCKETS_MIN(max_keys, BUCKETS_MAX_LIST_KEYS), &l);
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  sse_list_view(c, &l);

  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListVersionsResult", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Name", c->bucket);
  xml_key(b, "Prefix", prefix ? prefix : "", url);
  xml_key(b, "KeyMarker", key_marker ? key_marker : "", url);
  if (l.truncated && l.next_marker) xml_key(b, "NextKeyMarker", l.next_marker, url);
  buckets_xml_elem(b, "NextVersionIdMarker", l.truncated && l.next_version_marker ? l.next_version_marker : "");
  buckets_xml_elem(b, "VersionIdMarker", vid_marker ? vid_marker : "");
  buckets_buf_appendf(b, "<MaxKeys>%lld</MaxKeys>", max_keys);
  if (delimiter && *delimiter) xml_key(b, "Delimiter", delimiter, url);
  buckets_xml_elem(b, "IsTruncated", l.truncated ? "true" : "false");
  for (size_t i = 0; i < l.nprefixes; i++) {
    buckets_xml_open(b, "CommonPrefixes");
    xml_key(b, "Prefix", l.prefixes[i], url);
    buckets_xml_close(b, "CommonPrefixes");
  }
  for (size_t i = 0; i < l.nobjects; i++) {
    const buckets_object_info *o = &l.objects[i];
    const char *tag = o->delete_marker ? "DeleteMarker" : "Version";
    char lm[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(o->mod_time_ns, lm);
    buckets_xml_open(b, tag);
    xml_key(b, "Key", o->name, url);
    buckets_xml_elem(b, "LastModified", lm);
    if (o->etag[0]) buckets_buf_appendf(b, "<ETag>&#34;%s&#34;</ETag>", o->etag);
    else buckets_xml_elem(b, "ETag", "");
    buckets_buf_appendf(b, "<Size>%lld</Size>", (long long)o->size);
    buckets_xml_open(b, "Owner");
    buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
    buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_NAME);
    buckets_xml_close(b, "Owner");
    const char *sc = buckets_object_meta(o, "x-amz-storage-class");
    buckets_xml_elem(b, "StorageClass", sc ? sc : "STANDARD");
    if (with_meta && !o->delete_marker) {
      bool any = false;
      const char *sv, *sk = sse_list_meta(o, &sv);
      if (sk) {
        buckets_xml_open(b, "UserMetadata");
        any = true;
        buckets_xml_elem(b, sk, sv);
      }
      for (size_t k = 0; k < o->nmeta; k++) {
        if (has_prefix_fold(o->meta[k].key, BUCKETS_XL_RESERVED_PREFIX) || strcasecmp(o->meta[k].key, "X-Amz-Tagging") == 0)
          continue;
        if (!any) buckets_xml_open(b, "UserMetadata");
        any = true;
        buckets_xml_elem(b, o->meta[k].key, (const char *)o->meta[k].value);
      }
      if (any) buckets_xml_close(b, "UserMetadata");
      const char *ut = buckets_object_meta(o, "X-Amz-Tagging");
      if (ut && *ut && buckets_s3_authorize(c, "s3:GetObjectTagging", c->bucket, o->name, NULL) == BUCKETS_ERR_NONE)
        buckets_xml_elem(b, "UserTags", ut);
    }
    buckets_xml_elem(b, "IsLatest", o->is_latest ? "true" : "false");
    buckets_xml_elem(b, "VersionId", o->version_id);
    buckets_xml_close(b, tag);
  }
  if (url) buckets_xml_elem(b, "EncodingType", "url");
  buckets_xml_close(b, "ListVersionsResult");
  buckets_obj_list_free(&l);
  buckets_s3_write_xml(c, 200);
}
