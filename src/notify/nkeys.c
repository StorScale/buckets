/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "notify/nkeys.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "core/common.h"

#define PREFIX_SEED (18 << 3) /* 'S' */

static const char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static uint16_t crc16(const uint8_t *p, size_t n) { /* CRC-16/XMODEM */
  uint16_t crc = 0;
  for (size_t i = 0; i < n; i++) {
    crc ^= (uint16_t)p[i] << 8;
    for (int b = 0; b < 8; b++) crc = (uint16_t)(crc & 0x8000 ? crc << 1 ^ 0x1021 : crc << 1);
  }
  return crc;
}

static size_t b32_decode(const char *s, uint8_t *out, size_t cap) {
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (; *s; s++) {
    const char *p = strchr(b32, *s);
    if (!p || !*s) return 0;
    acc = acc << 5 | (uint32_t)(p - b32);
    bits += 5;
    if (bits >= 8) {
      if (o == cap) return 0;
      out[o++] = (uint8_t)(acc >> (bits - 8));
      bits -= 8;
    }
  }
  return o;
}

static void b32_encode(const uint8_t *p, size_t n, char *out) {
  size_t o = 0;
  uint32_t acc = 0;
  int bits = 0;
  for (size_t i = 0; i < n; i++) {
    acc = acc << 8 | p[i];
    bits += 8;
    while (bits >= 5) {
      out[o++] = b32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out[o++] = b32[(acc << (5 - bits)) & 31];
  out[o] = '\0';
}

/* The seed's raw 32 bytes and its key type prefix byte. */
static bool decode_seed(const char *seed, uint8_t raw[32], uint8_t *type, char *err, size_t errlen) {
  uint8_t b[64];
  size_t n = b32_decode(seed, b, sizeof(b));
  if (n != 36 || crc16(b, 34) != (uint16_t)(b[34] | b[35] << 8)) {
    snprintf(err, errlen, "nkeys: invalid seed");
    return false;
  }
  if ((b[0] & 248) != PREFIX_SEED) {
    snprintf(err, errlen, "nkeys: invalid seed");
    return false;
  }
  *type = (uint8_t)((b[0] & 7) << 5 | (b[1] & 248) >> 3);
  memcpy(raw, b + 2, 32);
  return true;
}

bool buckets_nkey_from_seed(const char *seed, char *public_key, size_t pkcap, char *err, size_t errlen) {
  uint8_t raw[32], type;
  if (!decode_seed(seed, raw, &type, err, errlen)) return false;
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, 32);
  uint8_t pub[35];
  size_t pl = 32;
  bool ok = k && EVP_PKEY_get_raw_public_key(k, pub + 1, &pl) == 1 && pl == 32;
  EVP_PKEY_free(k);
  if (!ok || pkcap < 58) {
    snprintf(err, errlen, "nkeys: invalid seed");
    return false;
  }
  pub[0] = type;
  uint16_t c = crc16(pub, 33);
  pub[33] = (uint8_t)c, pub[34] = (uint8_t)(c >> 8);
  b32_encode(pub, 35, public_key);
  return true;
}

bool buckets_nkey_sign(const char *seed, const void *msg, size_t n, char *sig_b64url, size_t sigcap, char *err,
                       size_t errlen) {
  uint8_t raw[32], type, sig[64];
  if (!decode_seed(seed, raw, &type, err, errlen)) return false;
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, 32);
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  size_t sl = sizeof(sig);
  bool ok = k && md && EVP_DigestSignInit(md, NULL, NULL, NULL, k) == 1 &&
            EVP_DigestSign(md, sig, &sl, msg, n) == 1 && sl == 64;
  EVP_MD_CTX_free(md);
  EVP_PKEY_free(k);
  if (!ok || sigcap < 87) {
    snprintf(err, errlen, "error signing nonce");
    return false;
  }
  static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  size_t o = 0;
  for (size_t i = 0; i < 64; i += 3) {
    uint32_t v = (uint32_t)sig[i] << 16 | (i + 1 < 64 ? (uint32_t)sig[i + 1] << 8 : 0) | (i + 2 < 64 ? sig[i + 2] : 0);
    sig_b64url[o++] = a[v >> 18 & 63];
    sig_b64url[o++] = a[v >> 12 & 63];
    if (i + 1 < 64) sig_b64url[o++] = a[v >> 6 & 63];
    if (i + 2 < 64) sig_b64url[o++] = a[v & 63];
  }
  sig_b64url[o] = '\0';
  return true;
}

/* The first two blocks between "---...---" marker lines. */
static int decorated_blocks(FILE *f, char *found[2]) {
  char line[8192];
  bool inside = false;
  int nfound = 0;
  found[0] = found[1] = NULL;
  while (nfound < 2 && fgets(line, sizeof(line), f)) {
    size_t l = strcspn(line, "\r\n");
    line[l] = '\0';
    char *t = line;
    while (*t == ' ' || *t == '\t') t++;
    bool marker = strncmp(t, "---", 3) == 0 && l >= 6 && strcmp(line + l - 3, "---") == 0;
    if (marker) {
      inside = !inside;
      continue;
    }
    if (inside && *t && !found[nfound]) found[nfound++] = buckets_xstrdup(t);
  }
  return nfound;
}

bool buckets_nats_creds_read(const char *path, char **jwt, char **seed, char *err, size_t errlen) {
  *jwt = *seed = NULL;
  FILE *f = fopen(path, "r");
  if (!f) {
    snprintf(err, errlen, "open %s: no such file or directory", path);
    return false;
  }
  char *found[2];
  int nfound = decorated_blocks(f, found);
  fclose(f);
  if (nfound < 1) {
    snprintf(err, errlen, "nats: no user JWT found in %s", path);
    return false;
  }
  if (nfound < 2) {
    free(found[0]);
    snprintf(err, errlen, "nats: no nkey user seed found in %s", path);
    return false;
  }
  *jwt = found[0];
  *seed = found[1];
  return true;
}

bool buckets_nkey_seed_file(const char *path, char **seed, char *err, size_t errlen) {
  *seed = NULL;
  FILE *f = fopen(path, "r");
  if (!f) {
    snprintf(err, errlen, "nats: open %s: no such file or directory", path);
    return false;
  }
  char *found[2];
  int nfound = decorated_blocks(f, found);
  if (nfound > 1) {
    *seed = found[1];
    free(found[0]);
  } else {
    free(found[0]);
    rewind(f);
    char line[8192];
    while (!*seed && fgets(line, sizeof(line), f)) {
      line[strcspn(line, "\n")] = '\0';
      const char *t = line;
      while (*t == ' ' || *t == '\t' || *t == '\r') t++;
      if (!strncmp(t, "SO", 2) || !strncmp(t, "SA", 2) || !strncmp(t, "SU", 2)) *seed = buckets_xstrdup(line);
    }
  }
  fclose(f);
  if (!*seed) {
    snprintf(err, errlen, "nkeys: no nkey seed found");
    return false;
  }
  char pub[64] = "";
  bool ok = buckets_nkey_from_seed(*seed, pub, sizeof(pub), err, errlen);
  if (ok && pub[0] != 'U') {
    snprintf(err, errlen, "nats: Not a valid nkey user seed");
    ok = false;
  }
  if (!ok) {
    free(*seed);
    *seed = NULL;
    return false;
  }
  return true;
}
