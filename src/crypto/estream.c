/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/estream.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "crypto/aead.h"
#include "crypto/base64.h"
#include "crypto/xxhash.h"

#define SIO_BUF 16384 /* sio.BufSize */

/* ---- sio-go STREAM -------------------------------------------------------------------------------- */

static void sio_nonce(uint8_t out[12], const uint8_t nonce[8], uint32_t seq) {
  memcpy(out, nonce, 8);
  out[8] = (uint8_t)seq, out[9] = (uint8_t)(seq >> 8), out[10] = (uint8_t)(seq >> 16), out[11] = (uint8_t)(seq >> 24);
}

typedef void (*fragment_fn)(void *ud, const uint8_t *ct, size_t n);

/* Seals data fragment by fragment: the associated data is a flag byte
 * (0x80 on the final fragment) and the tag of an empty seal under sequence
 * number 0; fragments use 1, 2, ... */
static void sio_seal(const uint8_t key[32], const uint8_t nonce[8], const uint8_t *data, size_t n, fragment_fn fn,
                     void *ud) {
  buckets_aead *a = buckets_aead_new(BUCKETS_AEAD_AES_256_GCM, key);
  uint8_t ad[1 + BUCKETS_AEAD_TAG], nb[12];
  sio_nonce(nb, nonce, 0);
  ad[0] = 0x00;
  buckets_aead_seal(a, nb, NULL, 0, NULL, 0, ad + 1);
  uint8_t *ct = buckets_xmalloc(SIO_BUF + BUCKETS_AEAD_TAG);
  uint32_t seq = 1;
  /* every full fragment but the last is sealed as it comes; the final one
   * (which may be full) carries the flag */
  while (n > SIO_BUF) {
    sio_nonce(nb, nonce, seq++);
    buckets_aead_seal(a, nb, ad, sizeof(ad), data, SIO_BUF, ct);
    fn(ud, ct, SIO_BUF + BUCKETS_AEAD_TAG);
    data += SIO_BUF, n -= SIO_BUF;
  }
  ad[0] = 0x80;
  sio_nonce(nb, nonce, seq);
  buckets_aead_seal(a, nb, ad, sizeof(ad), data, n, ct);
  fn(ud, ct, n + BUCKETS_AEAD_TAG);
  free(ct);
  buckets_aead_free(a);
}

static void append_fragment(void *ud, const uint8_t *ct, size_t n) { buckets_buf_append(ud, ct, n); }

void buckets_sio_stream_seal(const uint8_t key[32], const uint8_t nonce[8], const void *data, size_t n,
                             buckets_buf *out) {
  sio_seal(key, nonce, data, n, append_fragment, out);
}

/* ---- RSA ----------------------------------------------------------------------------------------- */

static EVP_PKEY *rsa_from_der(const uint8_t *der, size_t n) {
  const unsigned char *p = der;
  EVP_PKEY *k = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, (long)n);
  if (k && p != der + n) { /* trailing data */
    EVP_PKEY_free(k);
    return NULL;
  }
  return k;
}

bool buckets_rsa_public_key_der(const void *in, size_t n, buckets_buf *der) {
  const char *s = in;
  buckets_buf raw = BUCKETS_BUF_INIT;
  /* pem.Decode: the base64 between the BEGIN and END lines */
  const char *begin = n > 11 ? strstr(s, "-----BEGIN ") : NULL;
  if (begin && (size_t)(begin - s) < n) {
    const char *body = strstr(begin, "-----\n");
    const char *end = body ? strstr(body + 6, "-----END ") : NULL;
    if (body && end) {
      buckets_buf b64 = BUCKETS_BUF_INIT;
      for (const char *c = body + 6; c < end; c++)
        if (*c != '\n' && *c != '\r' && *c != ' ') buckets_buf_append_char(&b64, *c);
      buckets_buf_reserve(&raw, b64.len);
      long dn = buckets_base64_decode(b64.data ? b64.data : "", b64.len, (uint8_t *)raw.data);
      buckets_buf_free(&b64);
      if (dn < 0) return false;
      raw.len = (size_t)dn;
    }
  }
  if (!raw.len) buckets_buf_append(&raw, in, n);
  EVP_PKEY *k = rsa_from_der((const uint8_t *)raw.data, raw.len);
  if (k) {
    unsigned char *out = NULL;
    int len = i2d_PublicKey(k, &out);
    if (len > 0) buckets_buf_append(der, out, (size_t)len);
    OPENSSL_free(out);
    EVP_PKEY_free(k);
  }
  buckets_buf_free(&raw);
  return der->len > 0;
}

/* ---- messagepack ----------------------------------------------------------------------------------- */

static void mp_uint(buckets_buf *b, uint64_t v) {
  uint8_t x[9];
  if (v < 128) {
    x[0] = (uint8_t)v;
    buckets_buf_append(b, x, 1);
  } else if (v <= 0xff) {
    x[0] = 0xcc, x[1] = (uint8_t)v;
    buckets_buf_append(b, x, 2);
  } else if (v <= 0xffff) {
    x[0] = 0xcd, x[1] = (uint8_t)(v >> 8), x[2] = (uint8_t)v;
    buckets_buf_append(b, x, 3);
  } else if (v <= 0xffffffffu) {
    x[0] = 0xce;
    for (int i = 0; i < 4; i++) x[1 + i] = (uint8_t)(v >> (24 - 8 * i));
    buckets_buf_append(b, x, 5);
  } else {
    x[0] = 0xcf;
    for (int i = 0; i < 8; i++) x[1 + i] = (uint8_t)(v >> (56 - 8 * i));
    buckets_buf_append(b, x, 9);
  }
}

static void mp_bin(buckets_buf *b, const void *data, size_t n) {
  uint8_t x[5];
  if (n <= 0xff) {
    x[0] = 0xc4, x[1] = (uint8_t)n;
    buckets_buf_append(b, x, 2);
  } else if (n <= 0xffff) {
    x[0] = 0xc5, x[1] = (uint8_t)(n >> 8), x[2] = (uint8_t)n;
    buckets_buf_append(b, x, 3);
  } else {
    x[0] = 0xc6;
    for (int i = 0; i < 4; i++) x[1 + i] = (uint8_t)(n >> (24 - 8 * i));
    buckets_buf_append(b, x, 5);
  }
  buckets_buf_append(b, data, n);
}

static void mp_str(buckets_buf *b, const char *s) {
  size_t n = strlen(s);
  uint8_t x[5];
  if (n < 32) {
    x[0] = (uint8_t)(0xa0 | n);
    buckets_buf_append(b, x, 1);
  } else if (n <= 0xff) {
    x[0] = 0xd9, x[1] = (uint8_t)n;
    buckets_buf_append(b, x, 2);
  } else if (n <= 0xffff) {
    x[0] = 0xda, x[1] = (uint8_t)(n >> 8), x[2] = (uint8_t)n;
    buckets_buf_append(b, x, 3);
  } else {
    x[0] = 0xdb;
    for (int i = 0; i < 4; i++) x[1 + i] = (uint8_t)(n >> (24 - 8 * i));
    buckets_buf_append(b, x, 5);
  }
  buckets_buf_append(b, s, n);
}

/* ---- the stream ------------------------------------------------------------------------------------- */

enum { B_PLAIN_KEY = 1, B_ENC_KEY, B_ENC_STREAM, B_PLAIN_STREAM, B_DATA, B_EOS, B_EOF, B_ERROR };

struct buckets_estream {
  buckets_buf *out;
  buckets_buf block;
  uint8_t key[32];
  bool have_key;
  uint64_t nonce;
};

/* A block: its id (a positive fixint), its length, its content. */
static void send_block(buckets_estream *e, int id) {
  uint8_t idb = (uint8_t)id;
  buckets_buf_append(e->out, &idb, 1);
  mp_uint(e->out, (uint32_t)e->block.len);
  buckets_buf_append(e->out, e->block.data ? e->block.data : "", e->block.len);
  buckets_buf_reset(&e->block);
}

buckets_estream *buckets_estream_new(buckets_buf *out) {
  buckets_estream *e = buckets_xcalloc(1, sizeof(*e));
  e->out = out;
  const uint8_t ver[2] = {2, 1};
  buckets_buf_append(out, ver, 2);
  return e;
}

bool buckets_estream_add_key_encrypted(buckets_estream *e, const void *der, size_t n) {
  EVP_PKEY *k = rsa_from_der(der, n);
  if (!k) return false;
  buckets_random(e->key, sizeof(e->key));
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(k, NULL);
  bool ok = ctx && EVP_PKEY_encrypt_init(ctx) > 0 && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) > 0 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha512()) > 0 && EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha512()) > 0;
  size_t clen = 0;
  uint8_t *cipher = NULL;
  if (ok) ok = EVP_PKEY_encrypt(ctx, NULL, &clen, e->key, sizeof(e->key)) > 0;
  if (ok) {
    cipher = buckets_xmalloc(clen);
    ok = EVP_PKEY_encrypt(ctx, cipher, &clen, e->key, sizeof(e->key)) > 0;
  }
  if (ok) {
    unsigned char *pub = NULL;
    int plen = i2d_PublicKey(k, &pub);
    mp_bin(&e->block, pub, plen > 0 ? (size_t)plen : 0);
    OPENSSL_free(pub);
    mp_bin(&e->block, cipher, clen);
    send_block(e, B_ENC_KEY);
    e->have_key = true;
  }
  free(cipher);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(k);
  return ok;
}

typedef struct {
  buckets_estream *e;
  buckets_buf all; /* the encrypted bytes, for the checksum */
} stream_ctx;

static void data_block(void *ud, const uint8_t *ct, size_t n) {
  stream_ctx *s = ud;
  mp_bin(&s->e->block, ct, n);
  send_block(s->e, B_DATA);
  buckets_buf_append(&s->all, ct, n);
}

void buckets_estream_add_encrypted(buckets_estream *e, const char *name, const void *data, size_t n) {
  uint8_t nonce[8];
  for (int i = 0; i < 8; i++) nonce[i] = (uint8_t)(e->nonce >> (8 * i));
  e->nonce++;
  mp_str(&e->block, name);
  mp_bin(&e->block, NULL, 0);
  mp_uint(&e->block, 1); /* checksumTypeXxhash */
  mp_bin(&e->block, nonce, 8);
  send_block(e, B_ENC_STREAM);
  stream_ctx s = {e, BUCKETS_BUF_INIT};
  sio_seal(e->key, nonce, data, n, data_block, &s);
  uint64_t h = buckets_xxh64(s.all.data ? s.all.data : "", s.all.len);
  uint8_t sum[8];
  for (int i = 0; i < 8; i++) sum[i] = (uint8_t)(h >> (56 - 8 * i));
  mp_bin(&e->block, sum, 8);
  send_block(e, B_EOS);
  buckets_buf_free(&s.all);
}

void buckets_estream_add_error(buckets_estream *e, const char *msg) {
  mp_str(&e->block, msg);
  send_block(e, B_ERROR);
}

void buckets_estream_close(buckets_estream *e) {
  send_block(e, B_EOF);
  buckets_buf_free(&e->block);
  free(e);
}
