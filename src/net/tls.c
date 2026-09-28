/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "net/tls.h"

#include <dirent.h>
#include <errno.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "core/buf.h"
#include "core/log.h"

/* MinIO's secure cipher suites (internal/fips): ECDHE with AEAD only. TLS 1.3
 * suites are OpenSSL's defaults, which are all AEAD. */
#define CIPHERS                                                                                              \
  "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:"                 \
  "ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"

#define MAX_CERTS 64

typedef struct {
  char *dir; /* holds public.crt and private.key */
  SSL_CTX *ctx;
  X509 *leaf; /* for SNI matching */
  struct timespec crt_mtime, key_mtime;
} cert;

struct buckets_tls {
  char *dir;
  bool request_client_certs; /* identity_tls: ask for (never require) a client certificate */
  cert certs[MAX_CERTS]; /* [0] is the default */
  size_t ncerts;
};

struct buckets_tls_conn {
  SSL *ssl;
};

static void ssl_err(char *err, size_t errlen, const char *what, const char *path) {
  unsigned long e = ERR_get_error();
  char buf[256] = "";
  if (e) ERR_error_string_n(e, buf, sizeof(buf));
  snprintf(err, errlen, "%s %s: %s", what, path, *buf ? buf : strerror(errno));
  ERR_clear_error();
}

static int password_cb(char *buf, int size, int rwflag, void *ud) {
  (void)rwflag;
  (void)ud;
  const char *pw = getenv("BUCKETS_CERT_PASSWD");
  if (!pw || !*pw) pw = getenv("MINIO_CERT_PASSWD");
  if (!pw) return 0;
  int n = (int)strlen(pw);
  if (n > size) n = size;
  memcpy(buf, pw, (size_t)n);
  return n;
}

static bool mtime_of(const char *path, struct timespec *out) {
  struct stat st;
  if (stat(path, &st) != 0) return false;
#ifdef __APPLE__
  *out = st.st_mtimespec;
#else
  *out = st.st_mtim;
#endif
  return true;
}

static int sni_cb(SSL *ssl, int *alert, void *arg);
static int accept_any_cert(int ok, X509_STORE_CTX *ctx);

/* Builds a server context for dir/public.crt + dir/private.key. */
static bool load_cert(buckets_tls *t, const char *dir, cert *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_buf crt = BUCKETS_BUF_INIT, key = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&crt, "%s/public.crt", dir);
  buckets_buf_appendf(&key, "%s/private.key", dir);
  bool ok = false;
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    ssl_err(err, errlen, "create TLS context for", dir);
    goto done;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list(ctx, CIPHERS);
  SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE | SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_default_passwd_cb(ctx, password_cb);
  SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);
  SSL_CTX_set_tlsext_servername_arg(ctx, t);
  if (SSL_CTX_use_certificate_chain_file(ctx, crt.data) != 1) {
    ssl_err(err, errlen, "load certificate", crt.data);
    goto done;
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, key.data, SSL_FILETYPE_PEM) != 1) {
    ssl_err(err, errlen, "load private key", key.data);
    goto done;
  }
  if (SSL_CTX_check_private_key(ctx) != 1) {
    ssl_err(err, errlen, "private key does not match", crt.data);
    goto done;
  }
  /* Like Go (and so MinIO), refuse EC keys with explicit curve parameters:
   * TLS 1.3 clients reject them mid-handshake with opaque errors. */
  EVP_PKEY *pub = X509_get0_pubkey(SSL_CTX_get0_certificate(ctx));
  char enc[32] = "";
  if (pub && EVP_PKEY_is_a(pub, "EC") &&
      EVP_PKEY_get_utf8_string_param(pub, OSSL_PKEY_PARAM_EC_ENCODING, enc, sizeof(enc), NULL) &&
      strcmp(enc, OSSL_PKEY_EC_ENCODING_EXPLICIT) == 0) {
    snprintf(err, errlen, "%s uses explicit EC parameters; re-create it with a named curve "
                          "(openssl: -pkeyopt ec_param_enc:named_curve)", crt.data);
    ERR_clear_error();
    goto done;
  }
  out->leaf = SSL_CTX_get0_certificate(ctx);
  X509_up_ref(out->leaf);
  out->dir = buckets_xstrdup(dir);
  mtime_of(crt.data, &out->crt_mtime);
  mtime_of(key.data, &out->key_mtime);
  out->ctx = ctx;
  ctx = NULL;
  ok = true;
done:
  SSL_CTX_free(ctx);
  buckets_buf_free(&crt);
  buckets_buf_free(&key);
  return ok;
}

static void cert_free(cert *c) {
  SSL_CTX_free(c->ctx);
  X509_free(c->leaf);
  free(c->dir);
  memset(c, 0, sizeof(*c));
}

/* Picks the certificate whose names match the requested server name. */
static int sni_cb(SSL *ssl, int *alert, void *arg) {
  (void)alert;
  buckets_tls *t = arg;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!name || t->ncerts < 2) return SSL_TLSEXT_ERR_OK;
  for (size_t i = 1; i < t->ncerts; i++) {
    if (X509_check_host(t->certs[i].leaf, name, 0, 0, NULL) == 1) {
      SSL_set_SSL_CTX(ssl, t->certs[i].ctx);
      if (t->request_client_certs) SSL_set_verify(ssl, SSL_VERIFY_PEER, accept_any_cert);
      break;
    }
  }
  return SSL_TLSEXT_ERR_OK;
}

buckets_tls *buckets_tls_server_new(const char *certs_dir, char *err, size_t errlen) {
  buckets_tls *t = buckets_xcalloc(1, sizeof(*t));
  t->dir = buckets_xstrdup(certs_dir);
  if (!load_cert(t, certs_dir, &t->certs[0], err, errlen)) {
    buckets_tls_free(t);
    return NULL;
  }
  t->ncerts = 1;
  /* Every subdirectory with its own key pair serves the names in its cert. */
  DIR *d = opendir(certs_dir);
  for (struct dirent *e; d && (e = readdir(d)) != NULL && t->ncerts < MAX_CERTS;) {
    if (e->d_name[0] == '.' || strcmp(e->d_name, "CAs") == 0) continue;
    buckets_buf sub = BUCKETS_BUF_INIT, crt = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&sub, "%s/%s", certs_dir, e->d_name);
    buckets_buf_appendf(&crt, "%s/public.crt", sub.data);
    struct stat st;
    if (stat(crt.data, &st) == 0) {
      char e2[512];
      if (load_cert(t, sub.data, &t->certs[t->ncerts], e2, sizeof(e2))) t->ncerts++;
      else buckets_log_warn("skipping certificate in %s: %s", sub.data, e2);
    }
    buckets_buf_free(&sub);
    buckets_buf_free(&crt);
  }
  if (d) closedir(d);
  return t;
}

void buckets_tls_free(buckets_tls *t) {
  if (!t) return;
  for (size_t i = 0; i < t->ncerts; i++) cert_free(&t->certs[i]);
  free(t->dir);
  free(t);
}

size_t buckets_tls_cert_count(const buckets_tls *t) { return t->ncerts; }

static bool ts_eq(struct timespec a, struct timespec b) { return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec; }

bool buckets_tls_reload(buckets_tls *t) {
  bool any = false;
  for (size_t i = 0; i < t->ncerts; i++) {
    cert *c = &t->certs[i];
    buckets_buf crt = BUCKETS_BUF_INIT, key = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&crt, "%s/public.crt", c->dir);
    buckets_buf_appendf(&key, "%s/private.key", c->dir);
    struct timespec cm, km;
    bool changed = mtime_of(crt.data, &cm) && mtime_of(key.data, &km) &&
                   (!ts_eq(cm, c->crt_mtime) || !ts_eq(km, c->key_mtime));
    buckets_buf_free(&crt);
    buckets_buf_free(&key);
    if (!changed) continue;
    cert fresh;
    char err[512];
    char *dir = buckets_xstrdup(c->dir);
    if (load_cert(t, dir, &fresh, err, sizeof(err))) {
      /* Connections hold their own reference to the old context. */
      cert_free(c);
      *c = fresh;
      buckets_log_info("reloaded TLS certificate from %s", dir);
      any = true;
    } else {
      /* A half-written pair: keep serving the old one and retry later. */
      c->crt_mtime = cm;
      c->key_mtime = km;
      buckets_log_warn("TLS certificate in %s changed but cannot be loaded: %s", dir, err);
    }
    free(dir);
  }
  return any;
}

/* ---- connections ------------------------------------------------------------- */

/* tls.RequestClientCert: the certificate is checked later, by the handler. */
static int accept_any_cert(int ok, X509_STORE_CTX *ctx) {
  (void)ok;
  (void)ctx;
  return 1;
}

void buckets_tls_request_client_certs(buckets_tls *t, bool on) { t->request_client_certs = on; }

static void append_der(buckets_buf *out, size_t *n, X509 *x) {
  unsigned char *der = NULL;
  int len = i2d_X509(x, &der);
  if (len <= 0) return;
  uint32_t l = (uint32_t)len;
  buckets_buf_append(out, &l, sizeof(l));
  buckets_buf_append(out, der, (size_t)len);
  OPENSSL_free(der);
  (*n)++;
}

size_t buckets_tls_peer_chain(buckets_tls_conn *c, buckets_buf *out) {
  size_t n = 0;
  X509 *leaf = SSL_get1_peer_certificate(c->ssl);
  if (!leaf) return 0;
  append_der(out, &n, leaf);
  STACK_OF(X509) *chain = SSL_get_peer_cert_chain(c->ssl); /* server side: without the leaf */
  for (int i = 0; chain && i < sk_X509_num(chain); i++) {
    X509 *x = sk_X509_value(chain, i);
    if (X509_cmp(x, leaf) != 0) append_der(out, &n, x);
  }
  X509_free(leaf);
  return n;
}

static void add_cas(X509_STORE *store, const char *path) {
  struct stat st;
  if (!path || stat(path, &st) != 0) return;
  DIR *d = S_ISDIR(st.st_mode) ? opendir(path) : NULL;
  for (struct dirent *e = d ? readdir(d) : NULL; S_ISREG(st.st_mode) || e; e = d ? readdir(d) : NULL) {
    buckets_buf p = BUCKETS_BUF_INIT;
    if (d) {
      if (e->d_name[0] == '.') {
        buckets_buf_free(&p);
        continue;
      }
      buckets_buf_appendf(&p, "%s/%s", path, e->d_name);
    } else {
      buckets_buf_append_c(&p, path);
    }
    FILE *f = fopen(p.data, "r");
    for (X509 *x; f && (x = PEM_read_X509(f, NULL, NULL, NULL)) != NULL;) {
      X509_STORE_add_cert(store, x);
      X509_free(x);
    }
    if (f) fclose(f);
    ERR_clear_error();
    buckets_buf_free(&p);
    if (!d) break;
  }
  if (d) closedir(d);
}

static char *name_entry(const X509_NAME *nm, int nid, int *pos) {
  int i = X509_NAME_get_index_by_NID(nm, nid, *pos);
  if (i < 0) return NULL;
  *pos = i;
  unsigned char *utf8 = NULL;
  int len = ASN1_STRING_to_UTF8(&utf8, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(nm, i)));
  if (len < 0) return NULL;
  char *s = buckets_xstrndup((const char *)utf8, (size_t)len);
  OPENSSL_free(utf8);
  return s;
}

void buckets_client_cert_free(buckets_client_cert *c) {
  free(c->cn);
  free(c->issuer_cn);
  for (size_t i = 0; i < c->norgs; i++) free(c->orgs[i]);
  free(c->orgs);
  memset(c, 0, sizeof(*c));
}

buckets_cert_status buckets_tls_check_client_cert(const buckets_buf *chain, size_t n, const char *ca_path,
                                                  bool skip_verify, buckets_client_cert *out, char *err,
                                                  size_t errlen) {
  memset(out, 0, sizeof(*out));
  STACK_OF(X509) *inter = sk_X509_new_null();
  X509 *leaf = NULL;
  size_t nleaves = 0, ncas = 0;
  buckets_cert_status st = BUCKETS_CERT_OK;
  const unsigned char *p = (const unsigned char *)(chain ? chain->data : NULL);
  const unsigned char *end = p ? p + chain->len : NULL;
  for (size_t i = 0; i < n && p && p + 4 <= end; i++) {
    uint32_t l;
    memcpy(&l, p, 4);
    p += 4;
    const unsigned char *q = p;
    X509 *x = d2i_X509(NULL, &q, l);
    p += l;
    if (!x) continue;
    if (X509_check_ca(x)) {
      if (++ncas > 10) {
        X509_free(x);
        snprintf(err, errlen, "client certificate contains more than %d intermediate CAs", 10);
        st = BUCKETS_CERT_TOO_MANY_CAS;
        goto out;
      }
      sk_X509_push(inter, x);
    } else {
      nleaves++;
      if (!leaf) leaf = x;
      else X509_free(x);
    }
  }
  if (!nleaves) {
    snprintf(err, errlen, "No client certificate provided");
    st = BUCKETS_CERT_NONE;
    goto out;
  }
  if (nleaves > 1) {
    snprintf(err, errlen, "More than one client certificate provided");
    st = BUCKETS_CERT_MULTIPLE;
    goto out;
  }
  if (!skip_verify) {
    X509_STORE *store = X509_STORE_new();
    X509_STORE_set_default_paths(store);
    add_cas(store, ca_path);
    X509_STORE_CTX *vctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(vctx, store, leaf, inter);
    X509_STORE_CTX_set_purpose(vctx, X509_PURPOSE_SSL_CLIENT);
    int ok = X509_verify_cert(vctx);
    if (ok != 1) {
      snprintf(err, errlen, "x509: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(vctx)));
      st = BUCKETS_CERT_INVALID;
    }
    X509_STORE_CTX_free(vctx);
    X509_STORE_free(store);
    ERR_clear_error();
    if (st) goto out;
  } else {
    uint32_t xku = X509_get_extended_key_usage(leaf);
    if (xku == UINT32_MAX || !(xku & (XKU_SSL_CLIENT | XKU_ANYEKU))) {
      snprintf(err, errlen, "certificate is not valid for client authentication");
      st = BUCKETS_CERT_BAD_USAGE;
      goto out;
    }
  }
  int pos = -1;
  out->cn = name_entry(X509_get_subject_name(leaf), NID_commonName, &pos);
  pos = -1;
  for (char *o; (o = name_entry(X509_get_subject_name(leaf), NID_organizationName, &pos)) != NULL;) {
    out->orgs = buckets_xrealloc(out->orgs, (out->norgs + 1) * sizeof(char *));
    out->orgs[out->norgs++] = o;
  }
  pos = -1;
  out->issuer_cn = name_entry(X509_get_issuer_name(leaf), NID_commonName, &pos);
  struct tm tm;
  if (ASN1_TIME_to_tm(X509_get0_notAfter(leaf), &tm) == 1) out->not_after = timegm(&tm);
out:
  X509_free(leaf);
  sk_X509_pop_free(inter, X509_free);
  return st;
}

buckets_tls_conn *buckets_tls_accept(buckets_tls *t, int fd) {
  SSL *ssl = SSL_new(t->certs[0].ctx);
  if (!ssl) return NULL;
  if (SSL_set_fd(ssl, fd) != 1) {
    SSL_free(ssl);
    return NULL;
  }
  SSL_set_accept_state(ssl);
  if (t->request_client_certs) SSL_set_verify(ssl, SSL_VERIFY_PEER, accept_any_cert);
  buckets_tls_conn *c = buckets_xcalloc(1, sizeof(*c));
  c->ssl = ssl;
  return c;
}

static long result(buckets_tls_conn *c, int r) {
  if (r > 0) return r;
  int e = SSL_get_error(c->ssl, r);
  ERR_clear_error();
  switch (e) {
    case SSL_ERROR_WANT_READ: return BUCKETS_TLS_WANT_READ;
    case SSL_ERROR_WANT_WRITE: return BUCKETS_TLS_WANT_WRITE;
    case SSL_ERROR_ZERO_RETURN: return 0; /* close_notify */
    case SSL_ERROR_SYSCALL:
      if (errno == EAGAIN || errno == EWOULDBLOCK) return BUCKETS_TLS_WANT_READ;
      return r == 0 ? 0 : BUCKETS_TLS_ERROR; /* EOF without close_notify: treat as end */
    default: return BUCKETS_TLS_ERROR;
  }
}

long buckets_tls_recv(buckets_tls_conn *c, void *buf, size_t n) {
  size_t got = 0;
  int r = SSL_read_ex(c->ssl, buf, n, &got);
  return r == 1 ? (long)got : result(c, r);
}

long buckets_tls_send(buckets_tls_conn *c, const void *buf, size_t n) {
  size_t put = 0;
  int r = SSL_write_ex(c->ssl, buf, n, &put);
  return r == 1 ? (long)put : result(c, r);
}

/* ---- client ------------------------------------------------------------------ */

struct buckets_tls_client {
  SSL_CTX *ctx;
};

void buckets_tls_client_skip_verify(buckets_tls_client *t) { SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL); }

buckets_tls_client *buckets_tls_client_new(const char *ca_dir, char *err, size_t errlen) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    ssl_err(err, errlen, "create TLS client context", "");
    return NULL;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_cipher_list(ctx, CIPHERS);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_default_verify_paths(ctx);
  X509_STORE *store = SSL_CTX_get_cert_store(ctx);
  struct stat cst;
  if (ca_dir && stat(ca_dir, &cst) == 0 && S_ISREG(cst.st_mode)) { /* a single CA bundle file */
    FILE *f = fopen(ca_dir, "r");
    for (X509 *x; f && (x = PEM_read_X509(f, NULL, NULL, NULL)) != NULL;) {
      X509_STORE_add_cert(store, x);
      X509_free(x);
    }
    if (f) fclose(f);
    ERR_clear_error();
    ca_dir = NULL;
  }
  DIR *d = ca_dir ? opendir(ca_dir) : NULL;
  for (struct dirent *e; d && (e = readdir(d)) != NULL;) {
    if (e->d_name[0] == '.') continue;
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s/%s", ca_dir, e->d_name);
    FILE *f = fopen(p.data, "r");
    for (X509 *x; f && (x = PEM_read_X509(f, NULL, NULL, NULL)) != NULL;) {
      X509_STORE_add_cert(store, x);
      X509_free(x);
    }
    if (f) fclose(f);
    ERR_clear_error();
    buckets_buf_free(&p);
  }
  if (d) closedir(d);
  buckets_tls_client *t = buckets_xcalloc(1, sizeof(*t));
  t->ctx = ctx;
  return t;
}

void buckets_tls_client_free(buckets_tls_client *t) {
  if (!t) return;
  SSL_CTX_free(t->ctx);
  free(t);
}

buckets_tls_conn *buckets_tls_connect(buckets_tls_client *t, int fd, const char *host) {
  SSL *ssl = SSL_new(t->ctx);
  if (!ssl) return NULL;
  SSL_set_fd(ssl, fd);
  SSL_set_tlsext_host_name(ssl, host);
  /* IP literals verify against IP SANs, names against DNS SANs. */
  X509_VERIFY_PARAM *vp = SSL_get0_param(ssl);
  if (X509_VERIFY_PARAM_set1_ip_asc(vp, host) != 1) SSL_set1_host(ssl, host);
  ERR_clear_error();
  if (SSL_connect(ssl) != 1) {
    long vr = SSL_get_verify_result(ssl);
    buckets_log_warn("TLS handshake with %s failed%s%s", host, vr != X509_V_OK ? ": " : "",
                     vr != X509_V_OK ? X509_verify_cert_error_string(vr) : "");
    ERR_clear_error();
    SSL_free(ssl);
    return NULL;
  }
  buckets_tls_conn *c = buckets_xcalloc(1, sizeof(*c));
  c->ssl = ssl;
  return c;
}

bool buckets_tls_pending(const buckets_tls_conn *c) { return SSL_pending(c->ssl) > 0; }

void buckets_tls_conn_free(buckets_tls_conn *c) {
  if (!c) return;
  if (SSL_is_init_finished(c->ssl)) SSL_shutdown(c->ssl);
  ERR_clear_error();
  SSL_free(c->ssl);
  free(c);
}
