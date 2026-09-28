/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_TLS_H
#define BUCKETS_NET_TLS_H

#include <stddef.h>

#include "core/common.h"

/* Server-side TLS over OpenSSL, laid out like MinIO's certs directory:
 *
 *   <certs-dir>/public.crt, private.key     the default certificate
 *   <certs-dir>/<name>/public.crt, ...      more certificates, picked by SNI
 *   <certs-dir>/CAs/                        trusted CAs (for outbound TLS)
 *
 * Replaces MinIO's internal/config/certs.go + pkg/certs. Certificates are
 * re-read when their files change, without dropping connections. */

typedef struct buckets_tls buckets_tls;

/* NULL (err set) when the directory has no usable default certificate. The
 * private key may be encrypted: password from BUCKETS_CERT_PASSWD or
 * MINIO_CERT_PASSWD. */
buckets_tls *buckets_tls_server_new(const char *certs_dir, char *err, size_t errlen);
void buckets_tls_free(buckets_tls *t);
/* Reloads certificates whose files changed. Call from the thread that
 * accepts connections. Returns true if anything was reloaded. */
bool buckets_tls_reload(buckets_tls *t);
/* How many certificates are loaded (default + SNI). */
size_t buckets_tls_cert_count(const buckets_tls *t);

typedef struct buckets_tls_conn buckets_tls_conn;

enum {
  BUCKETS_TLS_ERROR = -1,      /* fatal: close the connection */
  BUCKETS_TLS_WANT_READ = -2,  /* retry once the socket is readable */
  BUCKETS_TLS_WANT_WRITE = -3, /* retry once the socket is writable */
};

/* Wraps an accepted, non-blocking socket; the handshake runs inside the
 * first reads and writes. */
buckets_tls_conn *buckets_tls_accept(buckets_tls *t, int fd);
/* >0 bytes, 0 at end of stream, or a BUCKETS_TLS_* code. */
long buckets_tls_recv(buckets_tls_conn *c, void *buf, size_t n);
long buckets_tls_send(buckets_tls_conn *c, const void *buf, size_t n);
/* Decrypted bytes already buffered, which the socket will not signal. */
bool buckets_tls_pending(const buckets_tls_conn *c);
/* ---- client side (internode) ---- */
typedef struct buckets_tls_client buckets_tls_client;
/* Trusts the system roots plus every PEM file in ca_dir (MinIO's certs/CAs);
 * ca_dir may be NULL. */
buckets_tls_client *buckets_tls_client_new(const char *ca_dir, char *err, size_t errlen);
void buckets_tls_client_free(buckets_tls_client *t);
/* Handshakes on a connected blocking socket, verifying host; NULL on failure. */
buckets_tls_conn *buckets_tls_connect(buckets_tls_client *t, int fd, const char *host);

/* Sends close_notify (best effort) and frees. Does not close the fd. */
void buckets_tls_conn_free(buckets_tls_conn *c);

#endif
