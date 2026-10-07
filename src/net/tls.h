/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_TLS_H
#define BUCKETS_NET_TLS_H

#include <stddef.h>
#include <time.h>

#include "core/buf.h"
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

/* Protocol floor, ciphers and groups for any TLS context of ours: TLS 1.2 or later with ECDHE and AEAD suites; in
 * FIPS mode (crypto/fips.h) only AES-GCM and the NIST curves. */
struct ssl_ctx_st;
void buckets_tls_ctx_setup(struct ssl_ctx_st *ctx);

/* NULL (err set) when the directory has no usable default certificate. The
 * private key may be encrypted: password from BUCKETS_CERT_PASSWD or
 * MINIO_CERT_PASSWD. */
buckets_tls *buckets_tls_server_new(const char *certs_dir, char *err, size_t errlen);
/* One certificate and its key, from these files (reloaded like a certs dir's). */
buckets_tls *buckets_tls_server_new_files(const char *cert_file, const char *key_file, char *err, size_t errlen);
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
/* identity_tls (AssumeRoleWithCertificate): ask clients for a certificate
 * during the handshake, without requiring or verifying it. */
void buckets_tls_request_client_certs(buckets_tls *t, bool on);
/* The client's certificates after the handshake, leaf first, appended to
 * out as (uint32 length, DER) records. Returns how many. */
size_t buckets_tls_peer_chain(buckets_tls_conn *c, buckets_buf *out);

typedef enum {
  BUCKETS_CERT_OK = 0,
  BUCKETS_CERT_NONE,         /* no leaf certificate */
  BUCKETS_CERT_MULTIPLE,     /* more than one leaf */
  BUCKETS_CERT_TOO_MANY_CAS, /* more than 10 intermediates */
  BUCKETS_CERT_INVALID,      /* does not verify for client authentication */
  BUCKETS_CERT_BAD_USAGE,    /* (skip_verify) no clientAuth extended key usage */
} buckets_cert_status;

typedef struct {
  char *cn;
  char **orgs;
  size_t norgs;
  char *issuer_cn;
  time_t not_after;
} buckets_client_cert;
void buckets_client_cert_free(buckets_client_cert *c);

/* The checks of AssumeRoleWithCertificate: exactly one leaf (CAs among the
 * certificates are intermediates), verified for client authentication
 * against the system roots and ca_path (a file or directory), unless
 * skip_verify, which still requires the clientAuth usage. */
buckets_cert_status buckets_tls_check_client_cert(const buckets_buf *chain, size_t n, const char *ca_path,
                                                  bool skip_verify, buckets_client_cert *out, char *err,
                                                  size_t errlen);

typedef struct buckets_tls_client buckets_tls_client;
/* Trusts the system roots plus every PEM file in ca_dir (MinIO's certs/CAs),
 * or the certificates in ca_dir when it names a file (a CA bundle such as a
 * Kubernetes service account's ca.crt); ca_dir may be NULL. */
buckets_tls_client *buckets_tls_client_new(const char *ca_dir, char *err, size_t errlen);
void buckets_tls_client_free(buckets_tls_client *t);
/* Accept any server certificate (identity_ldap tls_skip_verify=on). */
void buckets_tls_client_skip_verify(buckets_tls_client *t);
/* Presents a client certificate (PEM chain and key files). */
bool buckets_tls_client_use_cert(buckets_tls_client *t, const char *cert_file, const char *key_file, char *err,
                                 size_t errlen);
/* The same, the key file encrypted with password. */
bool buckets_tls_client_use_cert_password(buckets_tls_client *t, const char *cert_file, const char *key_file,
                                          const char *password, char *err, size_t errlen);
/* A self-signed client certificate for an Ed25519 key (KES API keys:
 * kes.GenerateCertificate), valid 90 days, CN cn. */
bool buckets_tls_client_use_ed25519(buckets_tls_client *t, const uint8_t seed[32], const char *cn, char *err,
                                    size_t errlen);
/* Also trusts the certificates in a PEM file; false if it held none. */
bool buckets_tls_client_add_ca_file(buckets_tls_client *t, const char *file);
/* Handshakes on a connected blocking socket, verifying host; NULL on failure. */
buckets_tls_conn *buckets_tls_connect(buckets_tls_client *t, int fd, const char *host);

/* Sends close_notify (best effort) and frees. Does not close the fd. */
void buckets_tls_conn_free(buckets_tls_conn *c);

#endif
