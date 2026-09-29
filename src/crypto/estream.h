/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CRYPTO_ESTREAM_H
#define BUCKETS_CRYPTO_ESTREAM_H

/* madmin-go's estream (version 2.1): named streams, each encrypted with the
 * last key sent, keys encrypted to RSA public keys (RSA-OAEP with SHA-512),
 * messagepack-framed blocks. Streams are sealed with sio-go's STREAM
 * construction (AES-256-GCM, 16 KiB fragments); sio_stream_seal is that
 * construction on its own (MinIO's legacy inspect format uses it). */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* sio.AES_256_GCM.Stream(key).EncryptWriter(nonce, nil) over all of data. */
void buckets_sio_stream_seal(const uint8_t key[32], const uint8_t nonce[8], const void *data, size_t n,
                             buckets_buf *out);

/* An RSA public key (PKCS #1 DER, or PEM around it) re-encoded as PKCS #1
 * DER; false when it is not one (x509.ParsePKCS1PublicKey). */
bool buckets_rsa_public_key_der(const void *in, size_t n, buckets_buf *der);

typedef struct buckets_estream buckets_estream;
buckets_estream *buckets_estream_new(buckets_buf *out);
/* A fresh key for the streams that follow, encrypted to the key (DER). */
bool buckets_estream_add_key_encrypted(buckets_estream *e, const void *pkcs1_der, size_t n);
/* A whole encrypted stream. */
void buckets_estream_add_encrypted(buckets_estream *e, const char *name, const void *data, size_t n);
void buckets_estream_add_error(buckets_estream *e, const char *msg);
/* The EOF block; frees e. */
void buckets_estream_close(buckets_estream *e);

#endif
