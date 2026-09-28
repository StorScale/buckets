/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "crypto/dare.h"

#include <openssl/crypto.h>
#include <string.h>

static void le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16), p[3] = (uint8_t)(v >> 24);
}
static uint32_t get_le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void package_nonce(const uint8_t header[16], uint32_t seq, uint8_t nonce[12]) {
  memcpy(nonce, header + 4, 12);
  le32(nonce + 8, get_le32(nonce + 8) ^ seq);
}

void buckets_dare_enc_init(buckets_dare_enc *e, const uint8_t key[32], const uint8_t *nonce, uint32_t seq) {
  memset(e, 0, sizeof(*e));
  e->cipher = BUCKETS_AEAD_AES_256_GCM;
  e->aead = buckets_aead_new(BUCKETS_AEAD_AES_256_GCM, key);
  if (nonce) memcpy(e->rand, nonce, 12);
  else buckets_random(e->rand, 12);
  e->seq = seq;
}

void buckets_dare_enc_free(buckets_dare_enc *e) {
  buckets_aead_free(e->aead);
  memset(e, 0, sizeof(*e));
}

size_t buckets_dare_seal(buckets_dare_enc *e, const void *in, size_t n, bool final, uint8_t *out) {
  uint8_t *h = out;
  h[0] = BUCKETS_DARE_VERSION20;
  h[1] = e->cipher;
  h[2] = (uint8_t)((n - 1) & 0xff);
  h[3] = (uint8_t)((n - 1) >> 8);
  memcpy(h + 4, e->rand, 12);
  if (final) h[4] |= 0x80;
  else h[4] &= 0x7f;
  uint8_t nonce[12];
  package_nonce(h, e->seq, nonce);
  buckets_aead_seal(e->aead, nonce, h, 4, in, n, out + BUCKETS_DARE_HEADER);
  e->seq++;
  e->finalized = final;
  return n + BUCKETS_DARE_OVERHEAD;
}

void buckets_dare_dec_init(buckets_dare_dec *d, const uint8_t key[32], uint32_t seq) {
  memset(d, 0, sizeof(*d));
  memcpy(d->key, key, 32);
  d->seq = seq;
}

void buckets_dare_dec_free(buckets_dare_dec *d) {
  buckets_aead_free(d->aead[0]);
  buckets_aead_free(d->aead[1]);
  OPENSSL_cleanse(d, sizeof(*d));
}

size_t buckets_dare_package_size(const uint8_t header[BUCKETS_DARE_HEADER]) {
  return ((size_t)header[2] | (size_t)header[3] << 8) + 1 + BUCKETS_DARE_OVERHEAD;
}

bool buckets_dare_finalized(const buckets_dare_dec *d) { return d->finalized; }

long buckets_dare_open(buckets_dare_dec *d, const uint8_t *pkg, size_t n, uint8_t *out) {
  if (d->finalized) return BUCKETS_DARE_ERR_UNEXPECTED_DATA;
  if (n <= BUCKETS_DARE_OVERHEAD) return BUCKETS_DARE_ERR_SIZE;
  if (!d->have_ref) {
    memcpy(d->ref, pkg, BUCKETS_DARE_HEADER);
    d->have_ref = true;
  }
  if (pkg[0] != BUCKETS_DARE_VERSION20) return BUCKETS_DARE_ERR_VERSION;
  uint8_t c = pkg[1];
  if (c > BUCKETS_AEAD_CHACHA20_POLY1305 || c != d->ref[1]) return BUCKETS_DARE_ERR_CIPHER;
  size_t len = ((size_t)pkg[2] | (size_t)pkg[3] << 8) + 1;
  if (len + BUCKETS_DARE_OVERHEAD != n) return BUCKETS_DARE_ERR_SIZE;
  bool final = (pkg[4] & 0x80) != 0;
  if (!final && len != BUCKETS_DARE_PAYLOAD) return BUCKETS_DARE_ERR_SIZE;
  uint8_t ref[12];
  memcpy(ref, d->ref + 4, 12);
  if (final) ref[0] |= 0x80;
  if (CRYPTO_memcmp(pkg + 4, ref, 12) != 0) return BUCKETS_DARE_ERR_NONCE;
  if (!d->aead[c]) d->aead[c] = buckets_aead_new((buckets_aead_alg)c, d->key);
  uint8_t nonce[12];
  package_nonce(pkg, d->seq, nonce);
  if (!buckets_aead_open(d->aead[c], nonce, pkg, 4, pkg + BUCKETS_DARE_HEADER, len + BUCKETS_DARE_TAG, out))
    return BUCKETS_DARE_ERR_TAG;
  if (final) d->finalized = true;
  d->seq++;
  return (long)len;
}

uint64_t buckets_dare_encrypted_size(uint64_t n) {
  uint64_t size = (n / BUCKETS_DARE_PAYLOAD) * BUCKETS_DARE_PACKAGE;
  if (n % BUCKETS_DARE_PAYLOAD) size += n % BUCKETS_DARE_PAYLOAD + BUCKETS_DARE_OVERHEAD;
  return size;
}

bool buckets_dare_decrypted_size(uint64_t n, uint64_t *out) {
  uint64_t size = (n / BUCKETS_DARE_PACKAGE) * BUCKETS_DARE_PAYLOAD;
  uint64_t mod = n % BUCKETS_DARE_PACKAGE;
  if (mod) {
    if (mod <= BUCKETS_DARE_OVERHEAD) return false;
    size += mod - BUCKETS_DARE_OVERHEAD;
  }
  *out = size;
  return true;
}

size_t buckets_dare_encrypt_buffer(const uint8_t key[32], const void *in, size_t n, uint8_t *out) {
  buckets_dare_enc e;
  buckets_dare_enc_init(&e, key, NULL, 0);
  size_t w = 0;
  const uint8_t *p = in;
  /* like the writer: full packages while more than 64 KiB is left; the last
   * (up to 64 KiB inclusive) is final */
  while (n > BUCKETS_DARE_PAYLOAD) {
    w += buckets_dare_seal(&e, p, BUCKETS_DARE_PAYLOAD, false, out + w);
    p += BUCKETS_DARE_PAYLOAD;
    n -= BUCKETS_DARE_PAYLOAD;
  }
  if (n) w += buckets_dare_seal(&e, p, n, true, out + w);
  buckets_dare_enc_free(&e);
  return w;
}

long buckets_dare_decrypt_buffer(const uint8_t key[32], const void *in, size_t n, uint8_t *out) {
  buckets_dare_dec d;
  buckets_dare_dec_init(&d, key, 0);
  const uint8_t *p = in;
  size_t w = 0;
  while (n) {
    if (n < BUCKETS_DARE_HEADER) {
      buckets_dare_dec_free(&d);
      return -1;
    }
    size_t pl = buckets_dare_package_size(p);
    long r = pl <= n ? buckets_dare_open(&d, p, pl, out + w) : BUCKETS_DARE_ERR_SIZE;
    if (r < 0) {
      buckets_dare_dec_free(&d);
      return -1;
    }
    w += (size_t)r;
    p += pl;
    n -= pl;
  }
  /* a stream must end with its final package */
  bool ok = w == 0 || d.finalized;
  buckets_dare_dec_free(&d);
  return ok ? (long)w : -1;
}
