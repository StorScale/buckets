/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The MySQL target (MinIO internal/event/target/mysql.go over database/sql
 * and go-sql-driver/mysql). Namespace format upserts by key_name into a
 * table keyed on SHA2(key_name) (INSERT ... ON DUPLICATE KEY UPDATE, DELETE
 * for s3:ObjectRemoved:Delete); access format appends (event_time,
 * event_data). The table is created when SELECT 1 FROM it fails; statements
 * are prepared on the server once per connection; every delivery pings
 * (COM_PING) first.
 *
 * The client behaves as go-sql-driver does: its DSN
 * ([user[:password]@][net[(addr)]]/dbname[?params], unknown parameters set
 * as session variables), protocol 10 with its capability flags, collation
 * utf8mb4_general_ci and connection attributes, TLS per the tls parameter
 * (true, skip-verify, preferred), mysql_native_password,
 * caching_sha2_password (full authentication over TLS in clear, else with the
 * server's RSA key), sha256_password and (when allowed) cleartext, and
 * statement parameters sent as strings. */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "net/conn.h"
#include "notify/targets.h"

#define CLIENT_LONG_PASSWORD 0x1
#define CLIENT_FOUND_ROWS 0x2
#define CLIENT_LONG_FLAG 0x4
#define CLIENT_CONNECT_WITH_DB 0x8
#define CLIENT_LOCAL_FILES 0x80
#define CLIENT_PROTOCOL_41 0x200
#define CLIENT_SSL 0x800
#define CLIENT_TRANSACTIONS 0x2000
#define CLIENT_SECURE_CONN 0x8000
#define CLIENT_MULTI_STATEMENTS 0x10000
#define CLIENT_MULTI_RESULTS 0x20000
#define CLIENT_PLUGIN_AUTH 0x80000
#define CLIENT_CONNECT_ATTRS 0x100000
#define CLIENT_PLUGIN_AUTH_LENENC 0x200000

typedef struct {
  char *user, *pass, *net, *addr, *db;
  char *tls; /* "", "true", "skip-verify", "preferred" */
  bool allow_native, allow_cleartext, multi_statements, client_found_rows;
  int timeout_ms, read_timeout_ms, write_timeout_ms;
  char *collation;
  char **pk, **pv; /* session variables to SET */
  size_t np;
} dsn;

typedef struct {
  char *table, *ca_dir;
  dsn d;
  bool access;
  pthread_mutex_t mu;
  buckets_conn *conn;
  uint8_t seq;
  uint32_t stmt_main, stmt_del; /* this connection's statement IDs (0: none) */
  int nparams_main;
  bool initialized, first_ping, tls_on;
} my;

typedef enum { M_OK, M_CONN, M_ERR } mstatus;

/* ---- DSN ------------------------------------------------------------------------- */

static void dsn_free(dsn *d) {
  free(d->user), free(d->pass), free(d->net), free(d->addr), free(d->db), free(d->tls), free(d->collation);
  for (size_t i = 0; i < d->np; i++) free(d->pk[i]), free(d->pv[i]);
  free(d->pk), free(d->pv);
  memset(d, 0, sizeof(*d));
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static char *unescape(const char *s, size_t n, bool plus) {
  buckets_buf b = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n && hexv(s[i + 1]) >= 0 && hexv(s[i + 2]) >= 0) {
      char c = (char)(hexv(s[i + 1]) << 4 | hexv(s[i + 2]));
      buckets_buf_append(&b, &c, 1);
      i += 2;
    } else if (plus && s[i] == '+') {
      buckets_buf_append(&b, " ", 1);
    } else {
      buckets_buf_append(&b, s + i, 1);
    }
  }
  return b.data ? b.data : buckets_xstrdup("");
}

static bool read_bool(const char *v, bool *out) {
  if (!strcmp(v, "1") || !strcasecmp(v, "true")) return *out = true, true;
  if (!strcmp(v, "0") || !strcasecmp(v, "false")) return *out = false, true;
  return false;
}

static bool parse_duration_ms(const char *v, int *ms, char *err, size_t errlen);

/* ParseDSN */
static bool parse_dsn(const char *s, dsn *d, char *err, size_t errlen) {
  memset(d, 0, sizeof(*d));
  d->allow_native = true;
  size_t n = strlen(s);
  long slash = -1;
  for (long i = (long)n - 1; i >= 0; i--)
    if (s[i] == '/') {
      slash = i;
      break;
    }
  if (slash < 0 && n) {
    snprintf(err, errlen, "invalid DSN: missing the slash separating the database name");
    return false;
  }
  if (slash > 0) {
    long j, k;
    for (j = slash; j >= 0 && s[j] != '@'; j--) {
    }
    if (j >= 0) {
      for (k = 0; k < j && s[k] != ':'; k++) {
      }
      if (k < j) d->pass = buckets_xstrndup(s + k + 1, (size_t)(j - k - 1));
      d->user = buckets_xstrndup(s, (size_t)k);
    }
    for (k = j + 1; k < slash && s[k] != '('; k++) {
    }
    if (k < slash) {
      if (s[slash - 1] != ')') {
        snprintf(err, errlen, memchr(s + k + 1, ')', (size_t)(slash - k - 1))
                                  ? "invalid DSN: did you forget to escape a param value?"
                                  : "invalid DSN: network address not terminated (missing closing brace)");
        return false;
      }
      d->addr = buckets_xstrndup(s + k + 1, (size_t)(slash - 1 - k - 1));
    }
    d->net = buckets_xstrndup(s + j + 1, (size_t)(k - j - 1));
  }
  if (slash >= 0) {
    const char *db = s + slash + 1, *q = strchr(db, '?');
    d->db = unescape(db, q ? (size_t)(q - db) : strlen(db), false);
    for (const char *p = q ? q + 1 : NULL; p && *p;) {
      size_t l = strcspn(p, "&");
      const char *eq = memchr(p, '=', l);
      if (eq) {
        char *k = buckets_xstrndup(p, (size_t)(eq - p)), *v = unescape(eq + 1, (size_t)(p + l - eq - 1), true);
        bool b, known = true, ok = true;
        if (!strcmp(k, "tls")) {
          free(d->tls);
          bool tb;
          d->tls = read_bool(v, &tb) ? buckets_xstrdup(tb ? "true" : "false") : buckets_xstrdup(v);
        } else if (!strcmp(k, "allowNativePasswords") || !strcmp(k, "allowCleartextPasswords") ||
                   !strcmp(k, "multiStatements") || !strcmp(k, "clientFoundRows") || !strcmp(k, "checkConnLiveness") ||
                   !strcmp(k, "parseTime") || !strcmp(k, "columnsWithAlias") || !strcmp(k, "interpolateParams") ||
                   !strcmp(k, "allowOldPasswords") || !strcmp(k, "allowAllFiles") || !strcmp(k, "rejectReadOnly") ||
                   !strcmp(k, "allowFallbackToPlaintext") || !strcmp(k, "compress")) {
          if (!read_bool(v, &b)) {
            snprintf(err, errlen, "invalid bool value: %s", v);
            ok = false;
          } else if (!strcmp(k, "allowNativePasswords")) d->allow_native = b;
          else if (!strcmp(k, "allowCleartextPasswords")) d->allow_cleartext = b;
          else if (!strcmp(k, "multiStatements")) d->multi_statements = b;
          else if (!strcmp(k, "clientFoundRows")) d->client_found_rows = b;
        } else if (!strcmp(k, "timeout") || !strcmp(k, "readTimeout") || !strcmp(k, "writeTimeout")) {
          int ms = 0;
          if (!parse_duration_ms(v, &ms, err, errlen)) ok = false;
          else if (!strcmp(k, "timeout")) d->timeout_ms = ms;
          else if (!strcmp(k, "readTimeout")) d->read_timeout_ms = ms;
          else d->write_timeout_ms = ms;
        } else if (!strcmp(k, "collation")) {
          free(d->collation);
          d->collation = buckets_xstrdup(v);
        } else if (!strcmp(k, "loc") || !strcmp(k, "maxAllowedPacket") || !strcmp(k, "charset") ||
                   !strcmp(k, "serverPubKey") || !strcmp(k, "timeTruncate") || !strcmp(k, "connectionAttributes")) {
          /* accepted; charset would issue SET NAMES, the others do not change what we send */
          if (!strcmp(k, "charset")) known = false; /* SET NAMES <charset> */
          if (!strcmp(k, "serverPubKey")) {
            snprintf(err, errlen, "invalid value / unknown server pub key name: %s", v);
            ok = false;
          }
        } else {
          known = false;
        }
        if (ok && !known) {
          d->pk = buckets_xrealloc(d->pk, (d->np + 1) * sizeof(char *));
          d->pv = buckets_xrealloc(d->pv, (d->np + 1) * sizeof(char *));
          d->pk[d->np] = buckets_xstrdup(k);
          d->pv[d->np++] = buckets_xstrdup(v);
        }
        free(k);
        free(v);
        if (!ok) return false;
      }
      p += l + (p[l] == '&');
    }
  }
  /* normalize */
  if (!d->net || !*d->net) {
    free(d->net);
    d->net = buckets_xstrdup("tcp");
  }
  if (!d->addr || !*d->addr) {
    free(d->addr);
    if (!strcmp(d->net, "tcp")) d->addr = buckets_xstrdup("127.0.0.1:3306");
    else if (!strcmp(d->net, "unix")) d->addr = buckets_xstrdup("/tmp/mysql.sock");
    else {
      snprintf(err, errlen, "default addr for network '%s' unknown", d->net);
      return false;
    }
  } else if (!strcmp(d->net, "tcp") && !strrchr(d->addr, ':')) {
    size_t an = strlen(d->addr) + 6;
    char *a = buckets_xmalloc(an);
    snprintf(a, an, "%s:3306", d->addr);
    free(d->addr);
    d->addr = a;
  }
  if (!d->tls) d->tls = buckets_xstrdup("");
  if (strcmp(d->tls, "") && strcmp(d->tls, "false") && strcmp(d->tls, "true") && strcmp(d->tls, "skip-verify") &&
      strcmp(d->tls, "preferred")) {
    snprintf(err, errlen, "invalid value / unknown config name: %s", d->tls);
    return false;
  }
  if (!d->user) d->user = buckets_xstrdup("");
  if (!d->pass) d->pass = buckets_xstrdup("");
  if (!d->db) d->db = buckets_xstrdup("");
  return true;
}

static bool parse_duration_ms(const char *v, int *ms, char *err, size_t errlen) {
  int64_t ns;
  if (!buckets_go_duration_parse(v, &ns)) {
    buckets_go_duration_error(v, err, errlen);
    return false;
  }
  *ms = (int)(ns / 1000000);
  return true;
}

/* ---- settings --------------------------------------------------------------------- */

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_mysql", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *dsn_s = get(cfg, target, "dsn_string"), *table = get(cfg, target, "table"), *fmt = get(cfg, target, "format");
  char *qdir = get(cfg, target, "queue_dir"), *qlim = get(cfg, target, "queue_limit");
  char *maxo = get(cfg, target, "max_open_connections");
  bool ok = true;
  char *end;
  long max_open = 0;
  strtol(qlim, &end, 10);
  if (!*qlim || *end) {
    snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qlim);
    ok = false;
  }
  if (ok) {
    max_open = strtol(maxo, &end, 10);
    if (!*maxo || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", maxo);
      ok = false;
    }
  }
  dsn d = {0};
  if (ok) {
    if (*fmt && strcasecmp(fmt, "namespace") != 0 && strcasecmp(fmt, "access") != 0) {
      snprintf(err, errlen, "unrecognized format");
      ok = false;
    } else if (!*table) {
      snprintf(err, errlen, "table unspecified");
      ok = false;
    } else if (!*dsn_s) {
      snprintf(err, errlen, "unspecified port"); /* MinIO reads only the DSN string */
      ok = false;
    } else if (!parse_dsn(dsn_s, &d, err, errlen)) {
      ok = false;
    } else if (*qdir && *qdir != '/') {
      snprintf(err, errlen, "queueDir path should be absolute");
      ok = false;
    } else if (max_open < 0) {
      snprintf(err, errlen, "maxOpenConnections cannot be less than zero");
      ok = false;
    }
  }
  if (ok && impl) {
    my *m = buckets_xcalloc(1, sizeof(*m));
    m->table = table, table = NULL;
    m->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    m->d = d;
    memset(&d, 0, sizeof(d));
    m->access = strcmp(fmt, "access") == 0;
    pthread_mutex_init(&m->mu, NULL);
    *impl = m;
  }
  dsn_free(&d);
  free(dsn_s), free(table), free(fmt), free(qdir), free(qlim), free(maxo);
  return ok;
}

/* ---- packets ------------------------------------------------------------------------- */

static void drop(my *m) {
  buckets_conn_close(m->conn);
  m->conn = NULL;
  m->stmt_main = m->stmt_del = 0;
}

static bool write_packet(my *m, const void *data, size_t n) {
  uint8_t h[4] = {(uint8_t)n, (uint8_t)(n >> 8), (uint8_t)(n >> 16), m->seq++};
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append(&b, h, 4);
  buckets_buf_append(&b, data, n);
  bool ok = buckets_conn_write(m->conn, b.data, b.len);
  buckets_buf_free(&b);
  if (!ok) drop(m);
  return ok;
}

static bool read_packet(my *m, buckets_buf *out) {
  buckets_buf_reset(out);
  for (;;) {
    uint8_t h[4];
    if (!buckets_conn_read_full(m->conn, h, 4)) {
      drop(m);
      return false;
    }
    size_t n = (size_t)h[0] | (size_t)h[1] << 8 | (size_t)h[2] << 16;
    m->seq = (uint8_t)(h[3] + 1);
    size_t off = out->len;
    buckets_buf_reserve(out, off + n + 1);
    if (n && !buckets_conn_read_full(m->conn, out->data + off, n)) {
      drop(m);
      return false;
    }
    out->len = off + n;
    out->data[out->len] = '\0';
    if (n < 0xffffff) return true; /* a full-size packet continues in the next */
  }
}

static void lenenc(buckets_buf *b, uint64_t v) {
  uint8_t x[9];
  size_t n;
  if (v < 251) x[0] = (uint8_t)v, n = 1;
  else if (v < 1u << 16) x[0] = 0xfc, x[1] = (uint8_t)v, x[2] = (uint8_t)(v >> 8), n = 3;
  else if (v < 1u << 24) x[0] = 0xfd, x[1] = (uint8_t)v, x[2] = (uint8_t)(v >> 8), x[3] = (uint8_t)(v >> 16), n = 4;
  else {
    x[0] = 0xfe;
    for (int i = 0; i < 8; i++) x[1 + i] = (uint8_t)(v >> (8 * i));
    n = 9;
  }
  buckets_buf_append(b, x, n);
}

/* An ERR packet: MySQLError. */
static void mysql_error(const buckets_buf *p, char *err, size_t errlen) {
  const uint8_t *d = (const uint8_t *)p->data;
  int code = p->len >= 3 ? d[1] | d[2] << 8 : 0;
  if (p->len >= 9 && d[3] == '#') snprintf(err, errlen, "Error %d (%.5s): %.*s", code, p->data + 4, (int)(p->len - 9), p->data + 9);
  else snprintf(err, errlen, "Error %d: %.*s", code, (int)(p->len > 3 ? p->len - 3 : 0), p->data + 3);
}

/* ---- authentication --------------------------------------------------------------- */

static void sha1(const void *d, size_t n, uint8_t out[20]) {
  buckets_sha1_ctx c;
  buckets_sha1_init(&c);
  buckets_sha1_update(&c, d, n);
  buckets_sha1_final(&c, out);
}

static size_t scramble(const char *plugin, const uint8_t *seed, size_t seedlen, const char *pass, uint8_t *out) {
  size_t pl = strlen(pass);
  if (!strcmp(plugin, "mysql_native_password")) {
    if (!pl) return 0;
    uint8_t s1[20], s2[20], s3[20];
    sha1(pass, pl, s1);
    sha1(s1, 20, s2);
    buckets_sha1_ctx c;
    buckets_sha1_init(&c);
    buckets_sha1_update(&c, seed, BUCKETS_MIN(seedlen, 20));
    buckets_sha1_update(&c, s2, 20);
    buckets_sha1_final(&c, s3);
    for (int i = 0; i < 20; i++) out[i] = s3[i] ^ s1[i];
    return 20;
  }
  if (!strcmp(plugin, "caching_sha2_password")) {
    if (!pl) return 0;
    uint8_t m1[32], m1h[32], m2[32];
    buckets_sha256(pass, pl, m1);
    buckets_sha256(m1, 32, m1h);
    buckets_sha256_ctx c;
    buckets_sha256_init(&c);
    buckets_sha256_update(&c, m1h, 32);
    buckets_sha256_update(&c, seed, seedlen);
    buckets_sha256_final(&c, m2);
    for (int i = 0; i < 32; i++) out[i] = m1[i] ^ m2[i];
    return 32;
  }
  return 0;
}

/* RSA-OAEP(SHA1) of the password (NUL-terminated) XORed with the seed. */
static bool encrypt_password(const char *pass, const uint8_t *seed, size_t seedlen, const char *pem, size_t pemlen,
                             buckets_buf *out) {
  BIO *bio = BIO_new_mem_buf(pem, (int)pemlen);
  EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
  BIO_free(bio);
  if (!key) return false;
  size_t pl = strlen(pass) + 1;
  uint8_t *plain = buckets_xmalloc(pl);
  for (size_t i = 0; i < pl; i++) plain[i] = (uint8_t)(i < pl - 1 ? pass[i] : 0) ^ seed[i % seedlen];
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  size_t ol = 0;
  bool ok = ctx && EVP_PKEY_encrypt_init(ctx) == 1 && EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
            EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha1()) == 1 && EVP_PKEY_encrypt(ctx, NULL, &ol, plain, pl) == 1;
  if (ok) {
    buckets_buf_reserve(out, ol);
    ok = EVP_PKEY_encrypt(ctx, (uint8_t *)out->data, &ol, plain, pl) == 1;
    out->len = ol;
  }
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);
  free(plain);
  return ok;
}

/* The auth response for plugin; false with err set when it is not allowed. */
static bool auth_response(my *m, const char *plugin, const uint8_t *seed, size_t seedlen, buckets_buf *out, char *err,
                          size_t errlen) {
  buckets_buf_reset(out);
  uint8_t s[32];
  if (!strcmp(plugin, "caching_sha2_password")) {
    buckets_buf_append(out, s, scramble(plugin, seed, seedlen, m->d.pass, s));
  } else if (!strcmp(plugin, "mysql_native_password")) {
    if (!m->d.allow_native) {
      snprintf(err, errlen, "this user requires mysql native password authentication");
      return false;
    }
    buckets_buf_append(out, s, scramble(plugin, seed, seedlen, m->d.pass, s));
  } else if (!strcmp(plugin, "mysql_clear_password")) {
    if (!m->d.allow_cleartext) {
      snprintf(err, errlen, "this user requires clear text authentication. If you still want to use it, please add 'allowCleartextPasswords=1' to your DSN");
      return false;
    }
    buckets_buf_append(out, m->d.pass, strlen(m->d.pass) + 1);
  } else if (!strcmp(plugin, "sha256_password")) {
    if (!*m->d.pass) buckets_buf_append(out, "", 1);
    else if (m->tls_on) buckets_buf_append(out, m->d.pass, strlen(m->d.pass) + 1);
    else buckets_buf_append(out, "\1", 1); /* request the server's public key */
  } else {
    snprintf(err, errlen, "this authentication plugin is not supported");
    return false;
  }
  return true;
}

/* readAuthResult and handleAuthResult. */
static mstatus finish_auth(my *m, const char *plugin_in, uint8_t *seed, size_t seedlen, char *err, size_t errlen) {
  char plugin[64];
  snprintf(plugin, sizeof(plugin), "%s", plugin_in);
  buckets_buf p = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
  mstatus st = M_ERR;
  bool switched = false;
  for (;;) {
    if (!read_packet(m, &p)) {
      snprintf(err, errlen, "invalid connection");
      st = M_CONN;
      break;
    }
    uint8_t t = p.len ? (uint8_t)p.data[0] : 0xff;
    if (t == 0x00) { /* OK */
      st = M_OK;
      break;
    }
    if (t == 0xff) {
      mysql_error(&p, err, errlen);
      break;
    }
    if (t == 0xfe) { /* auth switch */
      if (switched) {
        snprintf(err, errlen, "commands out of sync. You can't run this command now");
        break;
      }
      switched = true;
      const char *np = p.data + 1;
      snprintf(plugin, sizeof(plugin), "%s", np);
      size_t nl = strlen(np) + 2;
      if (p.len > nl) {
        seedlen = BUCKETS_MIN(p.len - nl, (size_t)32);
        if (seedlen && p.data[nl + seedlen - 1] == 0) seedlen--;
        memcpy(seed, p.data + nl, seedlen);
      }
      if (!auth_response(m, plugin, seed, seedlen, &resp, err, errlen)) break;
      if (!write_packet(m, resp.data ? resp.data : "", resp.len)) {
        st = M_CONN;
        break;
      }
      continue;
    }
    if (t == 0x01) { /* more data */
      if (!strcmp(plugin, "caching_sha2_password") && p.len >= 2 && p.data[1] == 3) continue; /* fast auth OK, then OK */
      if (!strcmp(plugin, "caching_sha2_password") && p.len >= 2 && p.data[1] == 4) { /* full authentication */
        if (m->tls_on) {
          if (!write_packet(m, m->d.pass, strlen(m->d.pass) + 1)) {
            st = M_CONN;
            break;
          }
        } else if (!write_packet(m, "\2", 1)) { /* request the public key */
          st = M_CONN;
          break;
        }
        continue;
      }
      /* the server's public key (caching_sha2 after 0x02, or sha256_password) */
      buckets_buf enc = BUCKETS_BUF_INIT;
      if (!encrypt_password(m->d.pass, seed, seedlen, p.data + 1, p.len - 1, &enc)) {
        snprintf(err, errlen, "no pem data found");
        buckets_buf_free(&enc);
        break;
      }
      bool w = write_packet(m, enc.data, enc.len);
      buckets_buf_free(&enc);
      if (!w) {
        st = M_CONN;
        break;
      }
      continue;
    }
    snprintf(err, errlen, "malformed packet");
    break;
  }
  buckets_buf_free(&p);
  buckets_buf_free(&resp);
  return st;
}

static mstatus simple(my *m, const char *q, char *err, size_t errlen);

/* connector.Connect: handshake, TLS, authentication, session variables. */
static mstatus my_connect(my *m, char *err, size_t errlen) {
  if (strcmp(m->d.net, "tcp") != 0) {
    snprintf(err, errlen, "dial %s %s: not supported", m->d.net, m->d.addr);
    return M_CONN;
  }
  char host[300];
  const char *colon = strrchr(m->d.addr, ':');
  snprintf(host, sizeof(host), "%.*s", (int)(colon - m->d.addr), m->d.addr);
  if (host[0] == '[') { /* [v6] */
    memmove(host, host + 1, strlen(host));
    host[strlen(host) - 1] = '\0';
  }
  char derr[256];
  m->conn = buckets_conn_dial(host, atoi(colon + 1), NULL, m->d.timeout_ms ? m->d.timeout_ms : 30000, derr, sizeof(derr));
  if (!m->conn) {
    snprintf(err, errlen, "%s", derr);
    return M_CONN;
  }
  m->tls_on = false;
  m->seq = 0;
  buckets_buf p = BUCKETS_BUF_INIT, out = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
  mstatus st = M_ERR;
  if (!read_packet(m, &p)) {
    snprintf(err, errlen, "invalid connection");
    st = M_CONN;
    goto done;
  }
  const uint8_t *d = (const uint8_t *)p.data;
  if (d[0] == 0xff) {
    mysql_error(&p, err, errlen);
    goto done;
  }
  if (d[0] < 10) {
    snprintf(err, errlen, "unsupported protocol version %d. Version %d or higher is required", d[0], 10);
    goto done;
  }
  size_t pos = 1 + strlen(p.data + 1) + 1 + 4;
  uint8_t seed[33];
  size_t seedlen = 0;
  if (pos + 8 + 1 + 2 > p.len) {
    snprintf(err, errlen, "malformed packet");
    goto done;
  }
  memcpy(seed, d + pos, 8), seedlen = 8, pos += 9;
  uint32_t flags = (uint32_t)d[pos] | (uint32_t)d[pos + 1] << 8;
  pos += 2;
  char plugin[64] = "mysql_native_password";
  if (p.len > pos + 16) {
    pos += 3; /* charset, status */
    flags |= ((uint32_t)d[pos] | (uint32_t)d[pos + 1] << 8) << 16;
    pos += 2 + 1 + 10;
    size_t part2 = 12;
    if (pos + part2 <= p.len) memcpy(seed + 8, d + pos, part2), seedlen += part2;
    pos += 13;
    if (pos < p.len && d[pos]) snprintf(plugin, sizeof(plugin), "%s", p.data + pos);
  }
  if (!(flags & CLIENT_PROTOCOL_41)) {
    snprintf(err, errlen, "MySQL server does not support required protocol 41+");
    goto done;
  }
  bool want_tls = !strcmp(m->d.tls, "true") || !strcmp(m->d.tls, "skip-verify") || !strcmp(m->d.tls, "preferred");
  if (want_tls && !(flags & CLIENT_SSL)) {
    if (!strcmp(m->d.tls, "preferred")) want_tls = false;
    else {
      snprintf(err, errlen, "TLS requested but server does not support TLS");
      goto done;
    }
  }
  if (!auth_response(m, plugin, seed, seedlen, &resp, err, errlen)) goto done;
  uint32_t cflags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONN | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS |
                    CLIENT_LOCAL_FILES | CLIENT_PLUGIN_AUTH | CLIENT_MULTI_RESULTS | (flags & CLIENT_CONNECT_ATTRS) |
                    (flags & CLIENT_LONG_FLAG);
  if (m->d.client_found_rows) cflags |= CLIENT_FOUND_ROWS;
  if (want_tls) cflags |= CLIENT_SSL;
  if (m->d.multi_statements) cflags |= CLIENT_MULTI_STATEMENTS;
  if (resp.len > 250) cflags |= CLIENT_PLUGIN_AUTH_LENENC;
  if (*m->d.db) cflags |= CLIENT_CONNECT_WITH_DB;
  uint8_t head[32] = {0};
  for (int i = 0; i < 4; i++) head[i] = (uint8_t)(cflags >> (8 * i));
  head[8] = 45; /* utf8mb4_general_ci */
  if (m->d.collation && !strcmp(m->d.collation, "utf8mb4_bin")) head[8] = 46;
  if (want_tls) {
    if (!write_packet(m, head, 32)) {
      st = M_CONN;
      goto done;
    }
    buckets_tls_client *tc = buckets_tls_client_new(m->ca_dir, err, errlen);
    if (tc && strcmp(m->d.tls, "true") != 0) buckets_tls_client_skip_verify(tc);
    bool ok = tc && buckets_conn_start_tls(m->conn, tc, host);
    buckets_tls_client_free(tc);
    if (!ok) {
      snprintf(err, errlen, "tls: failed to verify certificate");
      goto done;
    }
    m->tls_on = true;
    if (!strcmp(plugin, "sha256_password")) auth_response(m, plugin, seed, seedlen, &resp, err, errlen);
  }
  buckets_buf_append(&out, head, 32);
  buckets_buf_append(&out, m->d.user, strlen(m->d.user) + 1);
  lenenc(&out, resp.len);
  if (resp.len) buckets_buf_append(&out, resp.data, resp.len);
  if (*m->d.db) buckets_buf_append(&out, m->d.db, strlen(m->d.db) + 1);
  buckets_buf_append(&out, plugin, strlen(plugin) + 1);
  if (flags & CLIENT_CONNECT_ATTRS) { /* encodeConnectionAttributes */
    buckets_buf a = BUCKETS_BUF_INIT;
    struct utsname u;
    uname(&u);
    char pid[24];
    snprintf(pid, sizeof(pid), "%d", (int)getpid());
    char os[64];
    snprintf(os, sizeof(os), "%s", u.sysname);
    for (char *c = os; *c; c++) *c = (char)(*c >= 'A' && *c <= 'Z' ? *c + 32 : *c);
    const char *kv[] = {"_client_name", "Buckets", "_os", os, "_platform", u.machine, "_pid", pid, "_server_host", host};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(kv); i++) {
      lenenc(&a, strlen(kv[i]));
      buckets_buf_append(&a, kv[i], strlen(kv[i]));
    }
    lenenc(&out, a.len);
    buckets_buf_append(&out, a.data, a.len);
    buckets_buf_free(&a);
  }
  if (!write_packet(m, out.data, out.len)) {
    st = M_CONN;
    goto done;
  }
  st = finish_auth(m, plugin, seed, seedlen, err, errlen);
  for (size_t i = 0; st == M_OK && i < m->d.np; i++) { /* handleParams */
    buckets_buf q = BUCKETS_BUF_INIT;
    if (!strcmp(m->d.pk[i], "charset")) buckets_buf_appendf(&q, "SET NAMES %s", m->d.pv[i]);
    else buckets_buf_appendf(&q, "SET %s=%s", m->d.pk[i], m->d.pv[i]);
    st = simple(m, q.data, err, errlen);
    buckets_buf_free(&q);
  }
done:
  buckets_buf_free(&p);
  buckets_buf_free(&out);
  buckets_buf_free(&resp);
  if (st != M_OK) drop(m);
  return st;
}

static mstatus my_conn(my *m, char *err, size_t errlen) {
  if (m->conn && buckets_conn_broken(m->conn)) drop(m); /* checkConnLiveness */
  return m->conn ? M_OK : my_connect(m, err, errlen);
}

/* Reads a command's result: OK, ERR, or a result set (read and dropped). */
static mstatus read_result(my *m, char *err, size_t errlen) {
  buckets_buf p = BUCKETS_BUF_INIT;
  mstatus st = M_OK;
  if (!read_packet(m, &p)) {
    snprintf(err, errlen, "invalid connection");
    buckets_buf_free(&p);
    return M_CONN;
  }
  uint8_t t = p.len ? (uint8_t)p.data[0] : 0;
  if (t == 0xff) {
    mysql_error(&p, err, errlen);
    st = M_ERR;
  } else if (t != 0x00) { /* a result set: columns, EOF, rows, EOF */
    int eofs = 0;
    while (eofs < 2) {
      if (!read_packet(m, &p)) {
        snprintf(err, errlen, "invalid connection");
        st = M_CONN;
        break;
      }
      uint8_t k = p.len ? (uint8_t)p.data[0] : 0;
      if (k == 0xfe && p.len < 9) eofs++;
      else if (k == 0xff) {
        mysql_error(&p, err, errlen);
        st = M_ERR;
        break;
      }
    }
  }
  buckets_buf_free(&p);
  return st;
}

/* COM_QUERY: db.Exec without arguments. */
static mstatus simple(my *m, const char *q, char *err, size_t errlen) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append(&b, "\x03", 1);
  buckets_buf_append_c(&b, q);
  m->seq = 0;
  bool ok = write_packet(m, b.data, b.len);
  buckets_buf_free(&b);
  if (!ok) {
    snprintf(err, errlen, "invalid connection");
    return M_CONN;
  }
  return read_result(m, err, errlen);
}

static mstatus query(my *m, const char *q, char *err, size_t errlen) {
  mstatus st = my_conn(m, err, errlen);
  return st == M_OK ? simple(m, q, err, errlen) : st;
}

/* db.Ping: COM_PING. */
static mstatus ping(my *m, char *err, size_t errlen) {
  mstatus st = my_conn(m, err, errlen);
  if (st != M_OK) return st;
  m->seq = 0;
  if (!write_packet(m, "\x0e", 1)) {
    snprintf(err, errlen, "invalid connection");
    return M_CONN;
  }
  return read_result(m, err, errlen);
}

/* COM_STMT_PREPARE: the statement ID. */
static mstatus prepare(my *m, const char *q, uint32_t *id, char *err, size_t errlen) {
  mstatus st = my_conn(m, err, errlen);
  if (st != M_OK) return st;
  buckets_buf b = BUCKETS_BUF_INIT, p = BUCKETS_BUF_INIT;
  buckets_buf_append(&b, "\x16", 1);
  buckets_buf_append_c(&b, q);
  m->seq = 0;
  bool ok = write_packet(m, b.data, b.len);
  buckets_buf_free(&b);
  if (!ok || !read_packet(m, &p)) {
    snprintf(err, errlen, "invalid connection");
    buckets_buf_free(&p);
    return M_CONN;
  }
  const uint8_t *d = (const uint8_t *)p.data;
  if (d[0] == 0xff) {
    mysql_error(&p, err, errlen);
    buckets_buf_free(&p);
    return M_ERR;
  }
  *id = (uint32_t)d[1] | (uint32_t)d[2] << 8 | (uint32_t)d[3] << 16 | (uint32_t)d[4] << 24;
  int ncols = d[5] | d[6] << 8, nparams = d[7] | d[8] << 8;
  for (int part = 0; part < 2; part++) { /* parameter and column definitions, each ended by EOF */
    int count = part == 0 ? nparams : ncols;
    if (!count) continue;
    for (int i = 0; i <= count; i++) {
      if (!read_packet(m, &p)) {
        snprintf(err, errlen, "invalid connection");
        buckets_buf_free(&p);
        return M_CONN;
      }
    }
  }
  buckets_buf_free(&p);
  return M_OK;
}

/* COM_STMT_EXECUTE with string parameters. */
static mstatus execute(my *m, uint32_t id, const char *const *vals, const size_t *lens, int n, char *err, size_t errlen) {
  buckets_buf b = BUCKETS_BUF_INIT;
  uint8_t h[10] = {0x17, (uint8_t)id, (uint8_t)(id >> 8), (uint8_t)(id >> 16), (uint8_t)(id >> 24), 0, 1, 0, 0, 0};
  buckets_buf_append(&b, h, 10);
  if (n) {
    uint8_t zero[8] = {0};
    buckets_buf_append(&b, zero, (size_t)(n + 7) / 8); /* no NULLs */
    buckets_buf_append(&b, "\x01", 1);             /* new params bound */
    for (int i = 0; i < n; i++) buckets_buf_append(&b, "\xfe\x00", 2); /* MYSQL_TYPE_STRING */
    for (int i = 0; i < n; i++) {
      lenenc(&b, lens[i]);
      buckets_buf_append(&b, vals[i], lens[i]);
    }
  }
  m->seq = 0;
  bool ok = write_packet(m, b.data, b.len);
  buckets_buf_free(&b);
  if (!ok) {
    snprintf(err, errlen, "invalid connection");
    return M_CONN;
  }
  return read_result(m, err, errlen);
}

/* ---- the target ------------------------------------------------------------------------ */

static void stmt_sql(my *m, bool del, buckets_buf *q) {
  if (m->access) buckets_buf_appendf(q, "INSERT INTO %s (event_time, event_data) VALUES (?, ?);", m->table);
  else if (del) buckets_buf_appendf(q, "DELETE FROM %s WHERE key_hash = SHA2(?, 256);", m->table);
  else buckets_buf_appendf(q, "INSERT INTO %s (key_name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value=VALUES(value);", m->table);
}

/* executeStmts */
static mstatus execute_stmts(my *m, char *err, size_t errlen) {
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&q, "SELECT 1 FROM %s;", m->table);
  char qerr[512];
  mstatus st = query(m, q.data, qerr, sizeof(qerr));
  if (st == M_ERR) {
    buckets_buf_reset(&q);
    if (m->access)
      buckets_buf_appendf(&q, "CREATE TABLE %s (event_time DATETIME NOT NULL, event_data JSON)\n                                    ROW_FORMAT = Dynamic;", m->table);
    else
      buckets_buf_appendf(&q,
                          "CREATE TABLE %s (\n             key_name VARCHAR(3072) NOT NULL,\n             key_hash CHAR(64) GENERATED ALWAYS AS (SHA2(key_name, 256)) STORED NOT NULL PRIMARY KEY,\n             value JSON)\n           CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;",
                          m->table);
    st = query(m, q.data, err, errlen);
  } else if (st == M_CONN) {
    snprintf(err, errlen, "%s", qerr);
  }
  if (st == M_OK) {
    buckets_buf_reset(&q);
    stmt_sql(m, false, &q);
    st = prepare(m, q.data, &m->stmt_main, err, errlen);
    if (st == M_OK && !m->access) {
      buckets_buf_reset(&q);
      stmt_sql(m, true, &q);
      st = prepare(m, q.data, &m->stmt_del, err, errlen);
    }
  }
  buckets_buf_free(&q);
  return st;
}

static mstatus ensure_prepared(my *m, bool del, char *err, size_t errlen) {
  if (del ? m->stmt_del : m->stmt_main) return M_OK;
  buckets_buf q = BUCKETS_BUF_INIT;
  stmt_sql(m, del, &q);
  mstatus st = prepare(m, q.data, del ? &m->stmt_del : &m->stmt_main, err, errlen);
  buckets_buf_free(&q);
  return st;
}

/* initMySQL: Ping, executeStmts, then isActive. */
static mstatus init_my(my *m, char *err, size_t errlen) {
  if (m->initialized) return M_OK;
  mstatus st = ping(m, err, errlen);
  if (st == M_OK) {
    st = execute_stmts(m, err, errlen);
    if (st == M_OK) m->first_ping = true;
  }
  if (st != M_OK) {
    drop(m);
    return st;
  }
  if ((st = ping(m, err, errlen)) == M_OK) m->initialized = true;
  return st;
}

static mstatus is_active_locked(my *m, char *err, size_t errlen) {
  mstatus st = ping(m, err, errlen);
  if (st == M_CONN) snprintf(err, errlen, "not connected to target server/service");
  return st;
}

static mstatus send_record(my *m, const char *record, size_t n, const char *event_name, const char *key, char *err,
                           size_t errlen) {
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&data, "{\"Records\":[");
  buckets_buf_append(&data, record, n);
  buckets_buf_append_c(&data, "]}");
  mstatus st;
  if (!m->access) {
    bool del = strcmp(event_name, "s3:ObjectRemoved:Delete") == 0;
    st = ensure_prepared(m, del, err, errlen);
    if (st == M_OK) {
      if (del) {
        const char *v[] = {key};
        size_t l[] = {strlen(key)};
        st = execute(m, m->stmt_del, v, l, 1, err, errlen);
      } else {
        const char *v[] = {key, data.data};
        size_t l[] = {strlen(key), data.len};
        st = execute(m, m->stmt_main, v, l, 2, err, errlen);
      }
    }
  } else {
    /* appendDateTime in UTC: fraction digits trimmed of trailing zeros */
    yyjson_doc *doc = yyjson_read(record, n, 0);
    const char *et = doc ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "eventTime")) : NULL;
    char ts[40] = "";
    if (et && strlen(et) >= 19) {
      snprintf(ts, sizeof(ts), "%.10s %.8s", et, et + 11);
      const char *frac = et[19] == '.' ? et + 20 : NULL;
      if (frac) {
        size_t fl = strcspn(frac, "Z+-");
        while (fl && frac[fl - 1] == '0') fl--;
        if (fl) snprintf(ts + 19, sizeof(ts) - 19, ".%.*s", (int)fl, frac);
      }
    }
    yyjson_doc_free(doc);
    st = ensure_prepared(m, false, err, errlen);
    if (st == M_OK) {
      const char *v[] = {ts, data.data};
      size_t l[] = {strlen(ts), data.len};
      st = execute(m, m->stmt_main, v, l, 2, err, errlen);
    }
  }
  buckets_buf_free(&data);
  if (st == M_CONN) snprintf(err, errlen, "not connected to target server/service");
  return st;
}

static buckets_send_result result(mstatus st) {
  return st == M_OK ? BUCKETS_SEND_OK : st == M_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  my *m = impl;
  pthread_mutex_lock(&m->mu);
  mstatus st = init_my(m, err, errlen);
  if (st == M_OK) st = is_active_locked(m, err, errlen);
  if (st == M_OK) st = send_record(m, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&m->mu);
  return result(st);
}

static buckets_send_result send_from_store(void *impl, const char *record, size_t n, const char *event_name,
                                           const char *key, char *err, size_t errlen) {
  my *m = impl;
  pthread_mutex_lock(&m->mu);
  mstatus st = init_my(m, err, errlen);
  if (st == M_OK) st = is_active_locked(m, err, errlen);
  if (st == M_OK && !m->first_ping) {
    st = execute_stmts(m, err, errlen);
    if (st == M_CONN) snprintf(err, errlen, "not connected to target server/service");
  }
  if (st == M_OK) st = send_record(m, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&m->mu);
  return result(st);
}

static bool is_active(void *impl, char *err, size_t errlen) {
  my *m = impl;
  pthread_mutex_lock(&m->mu);
  bool up = init_my(m, err, errlen) == M_OK && is_active_locked(m, err, errlen) == M_OK;
  pthread_mutex_unlock(&m->mu);
  return up;
}

static void my_free(void *impl) {
  my *m = impl;
  if (!m) return;
  if (m->conn) { /* statements closed, then COM_QUIT */
    uint32_t ids[2] = {m->stmt_main, m->stmt_del};
    for (int i = 0; i < 2; i++) {
      if (!ids[i] || !m->conn) continue;
      uint8_t c[5] = {0x19, (uint8_t)ids[i], (uint8_t)(ids[i] >> 8), (uint8_t)(ids[i] >> 16), (uint8_t)(ids[i] >> 24)};
      m->seq = 0;
      write_packet(m, c, 5);
    }
    if (m->conn) {
      m->seq = 0;
      write_packet(m, "\x01", 1);
    }
  }
  drop(m);
  pthread_mutex_destroy(&m->mu);
  dsn_free(&m->d);
  free(m->table), free(m->ca_dir);
  free(m);
}

static const buckets_target_ops k_ops = {
    .type = "mysql", .send = send_event, .free = my_free, .is_active = is_active, .send_from_store = send_from_store};
const buckets_target_kind buckets_target_mysql = {"notify_mysql", &k_ops, create};
