/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* buckets-kes: Buckets' key server, speaking MinIO KES's API and reading its
 * configuration file.
 *
 *   buckets-kes server --config FILE [--addr HOST:PORT]
 *   buckets-kes identity of CERT|KEY  the identity of a certificate or of a KES API key
 *                                     ("kes:v1:..."), as "kes identity of"
 *   buckets-kes check --config FILE --key NAME
 *                                     signs in to the configuration's key store and reads
 *                                     key NAME (exit 1 and why when it cannot): KES's own
 *                                     configuration works, so a MinIO tenant's KES can be
 *                                     checked before Buckets takes over its keys
 *   buckets-kes --version */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "crypto/fips.h"
#include "core/log.h"
#include "core/loop.h"
#include "core/pool.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "kes/key.h"
#include "kes/server.h"

#define SHUTDOWN_GRACE_SECONDS 10

static buckets_loop *g_loop;
static volatile sig_atomic_t g_signal;

typedef struct {
  buckets_http_server *http;
  buckets_tls *tls;
  bool draining;
  time_t deadline, reload_at;
} app_state;

static void on_signal(int sig) {
  g_signal = sig;
  if (g_loop) buckets_loop_wake(g_loop);
}

static void on_wake(buckets_loop *loop, void *ud) {
  app_state *app = ud;
  if (!g_signal || app->draining) return;
  app->draining = true;
  app->deadline = time(NULL) + SHUTDOWN_GRACE_SECONDS;
  buckets_http_server_shutdown(app->http);
  if (buckets_http_server_connections(app->http) == 0) buckets_loop_stop(loop);
}

static void on_tick(buckets_loop *loop, void *ud) {
  app_state *app = ud;
  if (app->draining && (buckets_http_server_connections(app->http) == 0 || time(NULL) >= app->deadline))
    buckets_loop_stop(loop);
  if (time(NULL) >= app->reload_at) { /* renewed certificates */
    buckets_tls_reload(app->tls);
    app->reload_at = time(NULL) + 30;
  }
}

/* KES prints why it cannot start as "Error: ...", and the operator reads it from there */
static int die(const char *msg) {
  fprintf(stderr, "Error: %s\n", msg);
  return 1;
}

static void print_identity(const uint8_t *spki, size_t n) {
  uint8_t h[32];
  char hex[65];
  buckets_sha256(spki, n, h);
  buckets_hex_encode(h, 32, hex);
  hex[64] = '\0';
  printf("%s\n", hex);
}

/* A KES API key: "kes:v1:" and base64 of 0 (Ed25519) and the 32-byte seed; its
 * identity is that of the Ed25519 certificate the client makes from it. */
static int api_key_identity(const char *key) {
  const char *b = key + 7;
  uint8_t raw[48];
  size_t bl = strlen(b);
  if (bl > 60 || buckets_base64_decode(b, bl, raw) != 33 || raw[0] != 0) return die("invalid API key");
  EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw + 1, 32);
  OPENSSL_cleanse(raw, sizeof(raw));
  uint8_t spki[44] = {0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00};
  size_t pn = 32;
  bool ok = k && EVP_PKEY_get_raw_public_key(k, spki + 12, &pn) == 1 && pn == 32;
  EVP_PKEY_free(k);
  if (!ok) return die("invalid API key");
  print_identity(spki, sizeof(spki));
  return 0;
}

static int identity_of(const char *path) {
  if (strncmp(path, "kes:v1:", 7) == 0) return api_key_identity(path);
  FILE *f = fopen(path, "r");
  X509 *x = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
  if (f) fclose(f);
  if (!x) return die("failed to read the certificate");
  unsigned char *der = NULL;
  int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(x), &der);
  X509_free(x);
  print_identity(der, (size_t)n);
  OPENSSL_free(der);
  return 0;
}

/* buckets-kes check: the key store and one key, nothing served */
static int check(int argc, char **argv) {
  const char *config = NULL, *key = NULL;
  for (int i = 2; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config = argv[++i];
    else if (strncmp(argv[i], "--config=", 9) == 0) config = argv[i] + 9;
    else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key = argv[++i];
    else if (strncmp(argv[i], "--key=", 6) == 0) key = argv[i] + 6;
  }
  if (!config || !key) {
    fprintf(stderr, "usage: buckets-kes check --config FILE --key NAME\n");
    return 2;
  }
  char err[1024];
  yyjson_doc *conf = buckets_kes_config_load(config, err, sizeof(err));
  if (!conf) return die(err);
  buckets_kes_store *st = buckets_kes_store_open(yyjson_obj_get(yyjson_doc_get_root(conf), "keystore"), err, sizeof(err));
  if (!st) {
    yyjson_doc_free(conf);
    return die(err);
  }
  buckets_buf v = BUCKETS_BUF_INIT;
  buckets_kes_status s = st->ops->get(st, key, &v, err, sizeof(err));
  int rc = 1;
  buckets_kes_key k;
  if (s == BUCKETS_KES_NOT_FOUND) {
    char m[400];
    snprintf(m, sizeof(m), "key '%s' is not in %s", key, st->desc);
    die(m);
  } else if (s != BUCKETS_KES_OK) {
    die(err);
  } else if (!buckets_kes_key_decode(v.data ? v.data : "", v.len, &k, err, sizeof(err))) {
    char m[1200];
    snprintf(m, sizeof(m), "key '%s' in %s cannot be read: %.300s", key, st->desc, err);
    die(m);
  } else {
    printf("ok: key '%s' (%s) read from %s\n", key, buckets_kes_cipher_name(k.cipher), st->desc);
    buckets_kes_key_wipe(&k);
    rc = 0;
  }
  if (v.data) memset(v.data, 0, v.len);
  buckets_buf_free(&v);
  buckets_kes_store_close(st);
  yyjson_doc_free(conf);
  return rc;
}

int main(int argc, char **argv) {
  if (argc > 1 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
    printf("buckets-kes %s\n", BUCKETS_VERSION);
    return 0;
  }
  {
    char cerr[512];
    if (!buckets_crypto_init(cerr, sizeof(cerr))) {
      buckets_log_error("fips: %s", cerr);
      return 1;
    }
    if (buckets_fips_mode()) buckets_log_info("fips: FIPS 140-3 mode, with %s", buckets_fips_module());
  }
  if (argc == 4 && strcmp(argv[1], "identity") == 0 && strcmp(argv[2], "of") == 0) return identity_of(argv[3]);
  if (argc > 1 && strcmp(argv[1], "check") == 0) return check(argc, argv);
  const char *config = NULL, *addr = NULL;
  for (int i = 2; argc > 1 && strcmp(argv[1], "server") == 0 && i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) config = argv[++i];
    else if (strncmp(argv[i], "--config=", 9) == 0) config = argv[i] + 9;
    else if (strcmp(argv[i], "--addr") == 0 && i + 1 < argc) addr = argv[++i];
    else if (strncmp(argv[i], "--addr=", 7) == 0) addr = argv[i] + 7;
  }
  if (argc < 2 || strcmp(argv[1], "server") != 0 || !config) {
    fprintf(stderr, "usage: buckets-kes server --config FILE [--addr HOST:PORT]\n"
                    "       buckets-kes identity of CERT|KES-API-KEY\n"
                    "       buckets-kes check --config FILE --key NAME\n");
    return 2;
  }
  char err[1024];
  yyjson_doc *conf = buckets_kes_config_load(config, err, sizeof(err));
  if (!conf) return die(err);
  buckets_kes_server *srv = buckets_kes_server_new(conf, err, sizeof(err));
  if (!srv) return die(err);
  if (!addr) addr = buckets_kes_server_address(srv);
  const char *cert, *key;
  buckets_kes_server_tls_files(srv, &cert, &key);
  buckets_tls *tls = buckets_tls_server_new_files(cert, key, err, sizeof(err));
  if (!tls) return die(err);
  buckets_tls_request_client_certs(tls, true); /* identities come from client certificates */

  char host[256] = "";
  const char *colon = strrchr(addr, ':');
  int port = colon ? atoi(colon + 1) : 7373;
  if (colon) snprintf(host, sizeof(host), "%.*s", (int)(colon - addr), addr);
  if (strcmp(host, "0.0.0.0") == 0 || strcmp(host, "[::]") == 0) host[0] = '\0';

  g_loop = buckets_loop_new();
  buckets_pool *workers = buckets_pool_new(16);
  buckets_http_config hcfg = {
      .host = host,
      .port = port,
      .max_body = 2 * 1024 * 1024,
      .mem_body_limit = 2 * 1024 * 1024,
      .spool_dir = "/tmp",
      .idle_timeout_sec = 90,
      .server_header = "buckets-kes",
      .workers = workers,
      .tls = tls,
  };
  app_state app = {.tls = tls, .reload_at = time(NULL) + 30};
  app.http = buckets_http_server_start(g_loop, &hcfg, buckets_kes_server_handle, srv);
  if (!app.http) return die("failed to listen");
  buckets_loop_set_wake(g_loop, on_wake, &app);
  buckets_loop_add_tick(g_loop, on_tick, &app);
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_signal;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);
  buckets_log_info("buckets-kes %s listening on https://%s:%d, keys in %s", BUCKETS_VERSION, *host ? host : "0.0.0.0",
                   buckets_http_server_port(app.http), buckets_kes_server_store_desc(srv));
  int rc = buckets_loop_run(g_loop);
  buckets_pool_free(workers);
  buckets_http_server_free(app.http);
  buckets_loop_free(g_loop);
  buckets_tls_free(tls);
  buckets_kes_server_free(srv);
  return rc;
}
