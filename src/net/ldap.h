/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_NET_LDAP_H
#define BUCKETS_NET_LDAP_H

#include "core/buf.h"
#include "net/tls.h"

/* A small LDAPv3 client (RFC 4511): simple bind, search, StartTLS, over
 * TCP or TLS. Enough for identity_ldap, with go-ldap's semantics for the
 * parts MinIO relies on (filters, DN normalization, filter escaping). */

typedef struct buckets_ldap buckets_ldap;

typedef enum { BUCKETS_LDAP_PLAIN, BUCKETS_LDAP_LDAPS, BUCKETS_LDAP_STARTTLS } buckets_ldap_mode;

/* tls may be NULL for PLAIN. timeout_ms bounds each socket operation. */
buckets_ldap *buckets_ldap_connect(const char *host, int port, buckets_ldap_mode mode, buckets_tls_client *tls,
                                   int timeout_ms, char *err, size_t errlen);
void buckets_ldap_close(buckets_ldap *l);

/* The last result code from the server (0 success, 32 noSuchObject,
 * 49 invalidCredentials, ...), or -1 for a local/transport failure. */
int buckets_ldap_result_code(const buckets_ldap *l);

/* Simple bind (password "" is an unauthenticated bind). */
bool buckets_ldap_bind(buckets_ldap *l, const char *dn, const char *password, char *err, size_t errlen);

typedef struct {
  char *name;
  char **values;
  size_t nvalues;
} buckets_ldap_attr;

typedef struct {
  char *dn;
  buckets_ldap_attr *attrs;
  size_t nattrs;
} buckets_ldap_entry;

typedef enum { BUCKETS_LDAP_SCOPE_BASE = 0, BUCKETS_LDAP_SCOPE_ONE = 1, BUCKETS_LDAP_SCOPE_SUB = 2 } buckets_ldap_scope;

/* Search; attrs NULL-terminated (NULL: "1.1", i.e. no attributes). */
bool buckets_ldap_search(buckets_ldap *l, const char *base, buckets_ldap_scope scope, const char *filter,
                         const char *const *attrs, buckets_ldap_entry **out, size_t *n, char *err, size_t errlen);
void buckets_ldap_entries_free(buckets_ldap_entry *e, size_t n);

/* ldap.EscapeFilter: ( ) * \ NUL and bytes >= 0x80 as \xx. Caller frees. */
char *buckets_ldap_escape_filter(const char *s);

/* ParseDN + DN.String (go-ldap): types lowercased, values re-escaped per
 * RFC 4514, multi-valued RDNs sorted. NULL when it does not parse. */
char *buckets_ldap_normalize_dn(const char *dn);
/* DN.AncestorOf on normalized DNs: descendant has more RDNs and ends with
 * ancestor's. Both are parsed. */
bool buckets_ldap_dn_ancestor_of(const char *ancestor, const char *descendant);
/* DecodeDN (minio/pkg): unescapes a DN string. Caller frees; NULL on error. */
char *buckets_ldap_decode_dn(const char *dn);

/* Compiles an RFC 4515 filter to its BER form (for tests). */
bool buckets_ldap_compile_filter(const char *filter, buckets_buf *out, char *err, size_t errlen);

#endif
