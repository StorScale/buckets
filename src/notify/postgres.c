/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The PostgreSQL target (MinIO internal/event/target/postgresql.go over
 * database/sql and lib/pq). Namespace format upserts one row per object
 * (INSERT ... ON CONFLICT (key) DO UPDATE, DELETE for
 * s3:ObjectRemoved:Delete) into (key VARCHAR PRIMARY KEY, value JSONB);
 * access format appends (event_time, event_data). The table is created when
 * SELECT 1 FROM it fails; statements are prepared once per connection; every
 * delivery pings first (the empty query ";").
 *
 * The client speaks the v3 protocol as lib/pq does: the connection string
 * (key=value with quoting, or a postgres:// URL, over lib/pq's defaults and
 * the PG* environment), an SSLRequest unless sslmode=disable (require, the
 * default, encrypts without verifying; verify-ca and verify-full verify —
 * verify-ca here checks the host name too), cleartext, md5 and
 * SCRAM-SHA-256 authentication, every setting that is not a driver setting
 * sent as a startup parameter, statements named "1", "2", ... per
 * connection, and parameters in text format. */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <yyjson.h>

#include "core/common.h"
#include "crypto/base64.h"
#include "crypto/fips.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "net/conn.h"
#include "notify/targets.h"

extern char **environ;

#define MAX_OPTS 48

typedef struct {
  char *k[MAX_OPTS], *v[MAX_OPTS];
  size_t n;
} opts;

typedef struct {
  char *table, *dsn, *ca_dir;
  bool access;
  int max_open;
  pthread_mutex_t mu;
  buckets_conn *conn;
  int stmt_seq;                   /* the connection's statement counter (lib/pq gname) */
  char stmt_main[16], stmt_del[16]; /* this connection's prepared statements ("" when not) */
  int ntypes_main;
  uint32_t types_main[2];
  bool initialized, first_ping, prepared_ever;
} pg;

typedef enum { P_OK, P_CONN, P_ERR } pstatus;

/* ---- options ------------------------------------------------------------------ */

static const char *opt_get(const opts *o, const char *k) {
  for (size_t i = 0; i < o->n; i++)
    if (strcmp(o->k[i], k) == 0) return o->v[i];
  return NULL;
}

static void opt_set(opts *o, const char *k, const char *v) {
  for (size_t i = 0; i < o->n; i++)
    if (strcmp(o->k[i], k) == 0) {
      free(o->v[i]);
      o->v[i] = buckets_xstrdup(v);
      return;
    }
  if (o->n == MAX_OPTS) return;
  o->k[o->n] = buckets_xstrdup(k);
  o->v[o->n++] = buckets_xstrdup(v);
}

static void opts_free(opts *o) {
  for (size_t i = 0; i < o->n; i++) free(o->k[i]), free(o->v[i]);
  o->n = 0;
}

/* parseOpts: key=value pairs, values optionally 'quoted' with \ escapes. */
static bool parse_opts(const char *s, opts *o, char *err, size_t errlen) {
  buckets_buf k = BUCKETS_BUF_INIT, v = BUCKETS_BUF_INIT;
  bool ok = true;
  for (;;) {
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    if (!*s) break;
    buckets_buf_reset(&k);
    buckets_buf_reset(&v);
    while (*s && *s != '=' && *s != ' ' && *s != '\t' && *s != '\n') buckets_buf_append(&k, s++, 1);
    while (*s == ' ' || *s == '\t') s++;
    if (*s != '=') {
      snprintf(err, errlen, "missing \"=\" after \"%s\" in connection info string\"", k.len ? k.data : "");
      ok = false;
      break;
    }
    s++;
    while (*s == ' ' || *s == '\t' || *s == '\n') s++;
    if (*s == '\'') {
      s++;
      for (;;) {
        if (!*s) {
          snprintf(err, errlen, "unterminated quoted string literal in connection string");
          ok = false;
          break;
        }
        if (*s == '\'') {
          s++;
          break;
        }
        if (*s == '\\' && s[1]) s++;
        buckets_buf_append(&v, s++, 1);
      }
      if (!ok) break;
    } else {
      while (*s && *s != ' ' && *s != '\t' && *s != '\n') {
        if (*s == '\\') {
          if (!s[1]) {
            snprintf(err, errlen, "missing character after backslash");
            ok = false;
            break;
          }
          s++;
        }
        buckets_buf_append(&v, s++, 1);
      }
      if (!ok) break;
    }
    opt_set(o, k.data ? k.data : "", v.data ? v.data : "");
  }
  buckets_buf_free(&k);
  buckets_buf_free(&v);
  return ok;
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

static char *unescape(const char *s, size_t n) {
  buckets_buf b = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%' && i + 2 < n && hexv(s[i + 1]) >= 0 && hexv(s[i + 2]) >= 0) {
      char c = (char)(hexv(s[i + 1]) << 4 | hexv(s[i + 2]));
      buckets_buf_append(&b, &c, 1);
      i += 2;
    } else {
      buckets_buf_append(&b, s + i, 1);
    }
  }
  return b.data ? b.data : buckets_xstrdup("");
}

/* ParseURL: postgres://user:pass@host:port/db?k=v into options. */
static bool parse_url(const char *s, opts *o, char *err, size_t errlen) {
  const char *p = strstr(s, "://") + 3;
  size_t al = strcspn(p, "/?");
  const char *at = memchr(p, '@', al);
  if (at) {
    const char *colon = memchr(p, ':', (size_t)(at - p));
    char *u = unescape(p, colon ? (size_t)(colon - p) : (size_t)(at - p));
    opt_set(o, "user", u);
    free(u);
    if (colon) {
      char *pw = unescape(colon + 1, (size_t)(at - colon - 1));
      opt_set(o, "password", pw);
      free(pw);
    }
  }
  const char *hp = at ? at + 1 : p;
  size_t hl = al - (size_t)(hp - p);
  char host[300] = "", port[32] = "";
  if (hl && *hp == '[') {
    const char *rb = memchr(hp, ']', hl);
    if (rb) {
      snprintf(host, sizeof(host), "%.*s", (int)(rb - hp - 1), hp + 1);
      if (rb[1] == ':') snprintf(port, sizeof(port), "%.*s", (int)(hp + hl - rb - 2), rb + 2);
    }
  } else {
    const char *colon = memchr(hp, ':', hl);
    snprintf(host, sizeof(host), "%.*s", colon ? (int)(colon - hp) : (int)hl, hp);
    if (colon) snprintf(port, sizeof(port), "%.*s", (int)(hp + hl - colon - 1), colon + 1);
  }
  if (*host) opt_set(o, "host", host);
  if (*port) opt_set(o, "port", port);
  const char *rest = p + al;
  if (*rest == '/') {
    size_t dl = strcspn(rest + 1, "?");
    if (dl) {
      char *db = unescape(rest + 1, dl);
      opt_set(o, "dbname", db);
      free(db);
    }
    rest += 1 + dl;
  }
  if (*rest == '?') {
    for (const char *q = rest + 1; *q;) {
      size_t l = strcspn(q, "&");
      const char *eq = memchr(q, '=', l);
      char *k = unescape(q, eq ? (size_t)(eq - q) : l), *v = eq ? unescape(eq + 1, (size_t)(q + l - eq - 1)) : buckets_xstrdup("");
      opt_set(o, k, v);
      free(k), free(v);
      q += l + (q[l] == '&');
    }
  }
  (void)err, (void)errlen;
  return true;
}

/* parseEnviron: the PG* variables lib/pq honors. */
static void parse_environ(opts *o) {
  static const struct {
    const char *env, *key;
  } m[] = {{"PGHOST", "host"},           {"PGPORT", "port"},           {"PGDATABASE", "dbname"},
           {"PGUSER", "user"},           {"PGPASSWORD", "password"},   {"PGSERVICE", "service"},
           {"PGSERVICEFILE", "servicefile"}, {"PGREALM", "krbsrvname"}, {"PGOPTIONS", "options"},
           {"PGAPPNAME", "application_name"}, {"PGSSLMODE", "sslmode"}, {"PGSSLCERT", "sslcert"},
           {"PGSSLKEY", "sslkey"},       {"PGSSLROOTCERT", "sslrootcert"}, {"PGSSLSNI", "sslsni"},
           {"PGCONNECT_TIMEOUT", "connect_timeout"}, {"PGCLIENTENCODING", "client_encoding"},
           {"PGDATESTYLE", "datestyle"}, {"PGTZ", "timezone"},   {"PGGEQO", "geqo"}};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(m); i++) {
    const char *v = getenv(m[i].env);
    if (v) opt_set(o, m[i].key, v);
  }
}

static bool is_driver_setting(const char *k) {
  static const char *const s[] = {"host", "port", "password", "sslmode", "sslcert", "sslkey", "sslrootcert", "sslinline",
                                  "sslsni", "fallback_application_name", "connect_timeout",
                                  "disable_prepared_binary_result", "binary_parameters", "krbsrvname", "krbspn"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(s); i++)
    if (strcmp(k, s[i]) == 0) return true;
  return false;
}

/* NewConnector: lib/pq's defaults, the environment, then the string. */
static bool build_opts(const char *dsn, opts *o, char *err, size_t errlen) {
  opt_set(o, "host", "localhost");
  opt_set(o, "port", "5432");
  opt_set(o, "extra_float_digits", "2");
  parse_environ(o);
  if ((!strncmp(dsn, "postgres://", 11) || !strncmp(dsn, "postgresql://", 13)) ? !parse_url(dsn, o, err, errlen)
                                                                               : !parse_opts(dsn, o, err, errlen))
    return false;
  const char *fb = opt_get(o, "fallback_application_name");
  if (fb && !opt_get(o, "application_name")) opt_set(o, "application_name", fb);
  const char *enc = opt_get(o, "client_encoding");
  if (enc && strcasecmp(enc, "UTF8") != 0 && strcasecmp(enc, "UTF-8") != 0) {
    snprintf(err, errlen, "client_encoding must be absent or 'UTF8'");
    return false;
  }
  opt_set(o, "client_encoding", "UTF8");
  const char *ds = opt_get(o, "datestyle");
  if (ds && strcmp(ds, "ISO, MDY") != 0) {
    snprintf(err, errlen, "setting datestyle must be absent or ISO, MDY; got %s", ds);
    return false;
  }
  opt_set(o, "datestyle", "ISO, MDY");
  if (!opt_get(o, "user")) {
    struct passwd *pw = getpwuid(getuid());
    opt_set(o, "user", pw ? pw->pw_name : "");
  }
  const char *host = opt_get(o, "host");
  if (host && host[0] == '/') opt_set(o, "sslmode", "disable"); /* no SSL over UNIX sockets */
  return true;
}

/* ---- the target's settings ---------------------------------------------------------- */

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_postgres", target, key);
  return v ? v : buckets_xstrdup("");
}

/* validatePsqlTableName */
static bool table_ok(const char *t) {
  size_t n = strlen(t);
  if (n >= 3 && t[0] == '"' && t[n - 1] == '"' && !memchr(t + 1, '"', n - 2)) return true;
  if (!n) return false;
  const unsigned char *u = (const unsigned char *)t;
  bool first = true;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = u[i];
    bool letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c >= 0x80; /* non-ASCII: letters */
    bool digit = c >= '0' && c <= '9';
    if (!letter && !digit && c != '_' && c != '$') return false;
    if (first && !letter && c != '_') return false;
    first = false;
  }
  return true;
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *qlim = get(cfg, target, "queue_limit"), *maxo = get(cfg, target, "max_open_connections");
  char *fmt = get(cfg, target, "format"), *dsn = get(cfg, target, "connection_string"), *table = get(cfg, target, "table");
  char *qdir = get(cfg, target, "queue_dir");
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
  const char *why = NULL;
  if (ok) {
    if (!*table) why = "empty table name";
    else if (!table_ok(table)) why = "invalid PostgreSQL table";
    else if (*fmt && strcasecmp(fmt, "namespace") != 0 && strcasecmp(fmt, "access") != 0) why = "unrecognized format value";
    else if (!*dsn) why = "unspecified port"; /* MinIO reads only the connection string */
    else if (*qdir && *qdir != '/') why = "queueDir path should be absolute";
    else if (max_open < 0) why = "maxOpenConnections cannot be less than zero";
    if (why) {
      snprintf(err, errlen, "%s", why);
      ok = false;
    }
  }
  if (ok && impl) {
    pg *p = buckets_xcalloc(1, sizeof(*p));
    p->table = table, p->dsn = dsn, table = dsn = NULL;
    p->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    p->access = strcmp(fmt, "access") == 0;
    p->max_open = (int)max_open;
    pthread_mutex_init(&p->mu, NULL);
    *impl = p;
  }
  free(qlim), free(maxo), free(fmt), free(dsn), free(table), free(qdir);
  return ok;
}

/* ---- protocol ---------------------------------------------------------------------------- */

static void put32(buckets_buf *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 4);
}
static void put16(buckets_buf *b, uint16_t v) {
  uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 2);
}
static void put_cstr(buckets_buf *b, const char *s) { buckets_buf_append(b, s, strlen(s) + 1); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static void msg_begin(buckets_buf *b, char type) {
  buckets_buf_reset(b);
  if (type) buckets_buf_append(b, &type, 1);
  put32(b, 0);
}

static void msg_end(buckets_buf *b, bool typed) {
  size_t off = typed ? 1 : 0;
  uint32_t len = (uint32_t)(b->len - off);
  uint8_t *p = (uint8_t *)b->data + off;
  p[0] = (uint8_t)(len >> 24), p[1] = (uint8_t)(len >> 16), p[2] = (uint8_t)(len >> 8), p[3] = (uint8_t)len;
}

static void drop(pg *p) {
  buckets_conn_close(p->conn);
  p->conn = NULL;
  p->stmt_main[0] = p->stmt_del[0] = '\0';
  p->stmt_seq = 0;
}

static bool pg_send(pg *p, buckets_buf *b) {
  if (buckets_conn_write(p->conn, b->data, b->len)) return true;
  drop(p);
  return false;
}

/* The next backend message. */
static bool pg_recv(pg *p, char *type, buckets_buf *body) {
  uint8_t h[5];
  if (!buckets_conn_read_full(p->conn, h, 5)) {
    drop(p);
    return false;
  }
  uint32_t len = get32(h + 1);
  if (len < 4 || len > (256u << 20)) {
    drop(p);
    return false;
  }
  buckets_buf_reset(body);
  buckets_buf_reserve(body, len - 4 + 1);
  if (len > 4 && !buckets_conn_read_full(p->conn, body->data, len - 4)) {
    drop(p);
    return false;
  }
  body->len = len - 4;
  body->data[body->len] = '\0';
  *type = (char)h[0];
  return true;
}

/* ErrorResponse: pq.Error's message, "pq: <M>". */
static void pq_error(const buckets_buf *body, char *err, size_t errlen) {
  const char *p = body->data, *end = body->data + body->len;
  const char *m = "";
  while (p < end && *p) {
    char f = *p++;
    if (f == 'M') m = p;
    p += strlen(p) + 1;
  }
  snprintf(err, errlen, "pq: %s", m);
}

/* Messages up to ReadyForQuery; an ErrorResponse on the way fails the
 * command (the connection stays usable). */
static pstatus until_ready(pg *p, char *err, size_t errlen) {
  buckets_buf body = BUCKETS_BUF_INIT;
  pstatus st = P_OK;
  for (;;) {
    char t;
    if (!pg_recv(p, &t, &body)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
      break;
    }
    if (t == 'E') {
      pq_error(&body, err, errlen);
      st = P_ERR;
    } else if (t == 'Z') {
      break;
    }
  }
  buckets_buf_free(&body);
  return st;
}

static void hex(const uint8_t *in, size_t n, char *out) {
  static const char d[] = "0123456789abcdef";
  for (size_t i = 0; i < n; i++) out[2 * i] = d[in[i] >> 4], out[2 * i + 1] = d[in[i] & 15];
  out[2 * n] = '\0';
}

/* SCRAM-SHA-256 (lib/pq's scram client). */
static pstatus scram(pg *p, const char *user, const char *password, char *err, size_t errlen) {
  uint8_t raw[16];
  RAND_bytes(raw, sizeof(raw));
  char nonce[32];
  buckets_base64_encode(raw, sizeof(raw), nonce);
  buckets_buf auth = BUCKETS_BUF_INIT, m = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&auth, "n=");
  for (const char *c = user; *c; c++) { /* escaper: = and , */
    if (*c == '=') buckets_buf_append_c(&auth, "=3D");
    else if (*c == ',') buckets_buf_append_c(&auth, "=2C");
    else buckets_buf_append(&auth, c, 1);
  }
  buckets_buf_appendf(&auth, ",r=%s", nonce);
  char first[512];
  int fl = snprintf(first, sizeof(first), "n,,%s", auth.data);
  msg_begin(&m, 'p');
  put_cstr(&m, "SCRAM-SHA-256");
  put32(&m, (uint32_t)fl);
  buckets_buf_append(&m, first, (size_t)fl);
  msg_end(&m, true);
  pstatus st = P_ERR;
  char t;
  if (!pg_send(p, &m) || !pg_recv(p, &t, &body)) {
    snprintf(err, errlen, "driver: bad connection");
    st = P_CONN;
    goto out;
  }
  if (t == 'E') {
    pq_error(&body, err, errlen);
    goto out;
  }
  if (t != 'R' || body.len < 4 || get32((uint8_t *)body.data) != 11) {
    snprintf(err, errlen, "pq: unexpected authentication response: %c", t);
    goto out;
  }
  {
    const char *server_first = body.data + 4;
    size_t sfl = body.len - 4;
    char sf[1024];
    snprintf(sf, sizeof(sf), "%.*s", (int)sfl, server_first);
    char *r = strstr(sf, "r="), *s = strstr(sf, ",s="), *i = strstr(sf, ",i=");
    if (!r || !s || !i || strncmp(r + 2, nonce, strlen(nonce)) != 0) {
      snprintf(err, errlen, "pq: SCRAM-SHA-256 error: server sent an invalid SCRAM-SHA-256 message");
      goto out;
    }
    char snonce[256], salt64[256];
    snprintf(snonce, sizeof(snonce), "%.*s", (int)(s - r - 2), r + 2);
    snprintf(salt64, sizeof(salt64), "%.*s", (int)(i - s - 3), s + 3);
    int iters = atoi(i + 3);
    uint8_t salt[192];
    long sl = buckets_base64_decode(salt64, strlen(salt64), salt);
    if (sl < 0 || iters <= 0) {
      snprintf(err, errlen, "pq: SCRAM-SHA-256 error: cannot decode SCRAM-SHA-256 salt sent by server");
      goto out;
    }
    uint8_t salted[32], ckey[32], skey[32], stored[32], csig[32], proof[32], ssig[32];
    PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)sl, iters, EVP_sha256(), 32, salted);
    buckets_hmac_sha256(salted, 32, "Client Key", 10, ckey);
    buckets_sha256(ckey, 32, stored);
    buckets_buf_appendf(&auth, ",%s,c=biws,r=%s", sf, snonce);
    buckets_hmac_sha256(stored, 32, auth.data, auth.len, csig);
    for (int k = 0; k < 32; k++) proof[k] = ckey[k] ^ csig[k];
    char proof64[64];
    buckets_base64_encode(proof, 32, proof64);
    char final[512];
    int fn = snprintf(final, sizeof(final), "c=biws,r=%s,p=%s", snonce, proof64);
    msg_begin(&m, 'p');
    buckets_buf_append(&m, final, (size_t)fn);
    msg_end(&m, true);
    if (!pg_send(p, &m) || !pg_recv(p, &t, &body)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
      goto out;
    }
    if (t == 'E') {
      pq_error(&body, err, errlen);
      goto out;
    }
    if (t != 'R' || body.len < 4 || get32((uint8_t *)body.data) != 12) {
      snprintf(err, errlen, "pq: unexpected authentication response: %c", t);
      goto out;
    }
    buckets_hmac_sha256(salted, 32, "Server Key", 10, skey);
    buckets_hmac_sha256(skey, 32, auth.data, auth.len, ssig);
    char ssig64[64], want[80];
    buckets_base64_encode(ssig, 32, ssig64);
    snprintf(want, sizeof(want), "v=%s", ssig64);
    if (body.len - 4 < strlen(want) || strncmp(body.data + 4, want, strlen(want)) != 0) {
      snprintf(err, errlen, "pq: SCRAM-SHA-256 error: server's SCRAM-SHA-256 signature is invalid");
      goto out;
    }
    st = P_OK;
  }
out:
  buckets_buf_free(&auth);
  buckets_buf_free(&m);
  buckets_buf_free(&body);
  return st;
}

static int cmp_opt(const void *a, const void *b) { return strcmp(**(char *const *const *)a, **(char *const *const *)b); }

/* Connector.open: dial, SSL, startup, authentication, ReadyForQuery. */
static pstatus pg_connect(pg *p, char *err, size_t errlen) {
  opts o = {0};
  pstatus st = P_OK;
  if (!build_opts(p->dsn, &o, err, errlen)) {
    opts_free(&o);
    return P_ERR;
  }
  const char *host = opt_get(&o, "host"), *port = opt_get(&o, "port"), *mode = opt_get(&o, "sslmode");
  const char *ct = opt_get(&o, "connect_timeout");
  int timeout_ms = ct && atoi(ct) > 0 ? atoi(ct) * 1000 : 30000;
  if (mode && *mode && strcmp(mode, "require") && strcmp(mode, "verify-ca") && strcmp(mode, "verify-full") &&
      strcmp(mode, "disable")) {
    snprintf(err, errlen, "pq: unsupported sslmode \"%s\"; only \"require\" (default), \"verify-full\", \"verify-ca\", and \"disable\" supported", mode);
    opts_free(&o);
    return P_ERR;
  }
  char derr[256];
  if (host && host[0] == '/') {
    snprintf(err, errlen, "dial unix %s/.s.PGSQL.%s: connect: not supported", host, port ? port : "5432");
    opts_free(&o);
    return P_CONN;
  }
  p->conn = buckets_conn_dial(host, atoi(port ? port : "5432"), NULL, timeout_ms, derr, sizeof(derr));
  if (!p->conn) {
    snprintf(err, errlen, "%s", derr);
    opts_free(&o);
    return P_CONN;
  }
  buckets_buf m = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  if (!mode || strcmp(mode, "disable") != 0) { /* SSLRequest */
    msg_begin(&m, 0);
    put32(&m, 80877103);
    msg_end(&m, false);
    uint8_t answer = 0;
    if (!pg_send(p, &m) || !buckets_conn_read_full(p->conn, &answer, 1)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
    } else if (answer != 'S') {
      snprintf(err, errlen, "pq: SSL is not enabled on the server");
      st = P_ERR;
    } else {
      buckets_tls_client *tc = buckets_tls_client_new(p->ca_dir, err, errlen);
      const char *root = opt_get(&o, "sslrootcert"), *cert = opt_get(&o, "sslcert"), *key = opt_get(&o, "sslkey");
      bool verify = mode && (!strcmp(mode, "verify-ca") || !strcmp(mode, "verify-full"));
      if (tc && root && *root) buckets_tls_client_add_ca_file(tc, root), verify = true; /* require + a root: verify-ca */
      if (tc && !verify) buckets_tls_client_skip_verify(tc);
      if (tc && cert && *cert && key && *key) buckets_tls_client_use_cert(tc, cert, key, err, errlen);
      if (!tc || !buckets_conn_start_tls(p->conn, tc, host)) {
        snprintf(err, errlen, "x509: certificate signed by unknown authority");
        st = P_ERR;
      }
      buckets_tls_client_free(tc);
    }
  }
  if (st == P_OK) { /* StartupMessage */
    msg_begin(&m, 0);
    put32(&m, 196608);
    char **idx[MAX_OPTS];
    size_t ni = 0;
    for (size_t i = 0; i < o.n; i++)
      if (!is_driver_setting(o.k[i])) idx[ni++] = &o.k[i];
    qsort(idx, ni, sizeof(idx[0]), cmp_opt);
    for (size_t i = 0; i < ni; i++) {
      size_t at = (size_t)(idx[i] - o.k);
      put_cstr(&m, strcmp(o.k[at], "dbname") == 0 ? "database" : o.k[at]);
      put_cstr(&m, o.v[at]);
    }
    put_cstr(&m, "");
    msg_end(&m, false);
    if (!pg_send(p, &m)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
    }
  }
  const char *user = opt_get(&o, "user"), *pass = opt_get(&o, "password");
  if (!pass) pass = "";
  while (st == P_OK) {
    char t;
    if (!p->conn || !pg_recv(p, &t, &body)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
      break;
    }
    if (t == 'E') {
      pq_error(&body, err, errlen);
      st = P_ERR;
      break;
    }
    if (t == 'Z') break;
    if (t != 'R' || body.len < 4) continue; /* ParameterStatus, BackendKeyData, notices */
    uint32_t code = get32((uint8_t *)body.data);
    if (code == 0) continue;
    if (code == 5 && buckets_fips_mode()) { /* MD5 protects the password here: not outside the module */
      snprintf(err, errlen, "pq: the server asks for md5 password authentication, which FIPS mode does not allow; "
                            "use scram-sha-256");
      st = P_ERR;
      break;
    }
    if (code == 3 || code == 5) {
      char pw[80];
      if (code == 3) snprintf(pw, sizeof(pw), "%s", pass);
      else { /* md5(md5(password + user) + salt) */
        buckets_buf a = BUCKETS_BUF_INIT;
        uint8_t d[16];
        char h1[33], h2[33];
        buckets_buf_appendf(&a, "%s%s", pass, user);
        buckets_md5(a.data, a.len, d);
        hex(d, 16, h1);
        buckets_buf_reset(&a);
        buckets_buf_append(&a, h1, 32);
        buckets_buf_append(&a, body.data + 4, 4);
        buckets_md5(a.data, a.len, d);
        hex(d, 16, h2);
        snprintf(pw, sizeof(pw), "md5%s", h2);
        buckets_buf_free(&a);
      }
      msg_begin(&m, 'p');
      put_cstr(&m, code == 3 && strlen(pass) >= sizeof(pw) ? pass : pw);
      msg_end(&m, true);
      if (!pg_send(p, &m)) {
        snprintf(err, errlen, "driver: bad connection");
        st = P_CONN;
      }
    } else if (code == 10) {
      st = scram(p, user ? user : "", pass, err, errlen);
    } else {
      snprintf(err, errlen, "pq: unknown authentication response: %u", code);
      st = P_ERR;
    }
  }
  buckets_buf_free(&m);
  buckets_buf_free(&body);
  opts_free(&o);
  if (st != P_OK) drop(p);
  return st;
}

/* Ensures a connection (database/sql hands out a new one when needed). */
static pstatus pg_conn(pg *p, char *err, size_t errlen) {
  if (p->conn && buckets_conn_broken(p->conn)) drop(p);
  return p->conn ? P_OK : pg_connect(p, err, errlen);
}

/* A simple query ('Q'): db.Exec without arguments, and Ping (";"). */
static pstatus simple_query(pg *p, const char *q, char *err, size_t errlen) {
  pstatus st = pg_conn(p, err, errlen);
  if (st != P_OK) return st;
  buckets_buf m = BUCKETS_BUF_INIT;
  msg_begin(&m, 'Q');
  put_cstr(&m, q);
  msg_end(&m, true);
  st = pg_send(p, &m) ? until_ready(p, err, errlen) : P_CONN;
  if (st == P_CONN) snprintf(err, errlen, "driver: bad connection");
  buckets_buf_free(&m);
  return st;
}

/* Prepare: Parse (named), Describe, Sync; the parameter types. */
static pstatus prepare(pg *p, const char *q, char name[16], uint32_t *types, int *ntypes, char *err, size_t errlen) {
  pstatus st = pg_conn(p, err, errlen);
  if (st != P_OK) return st;
  snprintf(name, 16, "%d", ++p->stmt_seq);
  buckets_buf m = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  msg_begin(&m, 'P');
  put_cstr(&m, name);
  put_cstr(&m, q);
  put16(&m, 0);
  msg_end(&m, true);
  size_t off = m.len;
  buckets_buf_append(&m, "D", 1);
  put32(&m, 0);
  buckets_buf_append(&m, "S", 1);
  put_cstr(&m, name);
  uint32_t dl = (uint32_t)(m.len - off - 1);
  uint8_t *dp = (uint8_t *)m.data + off + 1;
  dp[0] = (uint8_t)(dl >> 24), dp[1] = (uint8_t)(dl >> 16), dp[2] = (uint8_t)(dl >> 8), dp[3] = (uint8_t)dl;
  buckets_buf_append(&m, "S\0\0\0\4", 5);
  if (!pg_send(p, &m)) {
    snprintf(err, errlen, "driver: bad connection");
    buckets_buf_free(&m);
    return P_CONN;
  }
  *ntypes = 0;
  for (;;) {
    char t;
    if (!pg_recv(p, &t, &body)) {
      snprintf(err, errlen, "driver: bad connection");
      st = P_CONN;
      break;
    }
    if (t == 'E') {
      pq_error(&body, err, errlen);
      st = P_ERR;
    } else if (t == 't' && body.len >= 2) {
      int n = (uint8_t)body.data[0] << 8 | (uint8_t)body.data[1];
      for (int i = 0; i < n && i < 2 && (size_t)(2 + 4 * i + 4) <= body.len; i++) types[i] = get32((uint8_t *)body.data + 2 + 4 * i);
      *ntypes = n;
    } else if (t == 'Z') {
      break;
    }
  }
  if (st != P_OK) name[0] = '\0';
  buckets_buf_free(&m);
  buckets_buf_free(&body);
  return st;
}

/* stmt.Exec: Bind (text parameters), Execute, Sync. */
static pstatus exec_stmt(pg *p, const char *name, const char *const *vals, const size_t *lens, int n, char *err,
                         size_t errlen) {
  buckets_buf m = BUCKETS_BUF_INIT;
  msg_begin(&m, 'B');
  put_cstr(&m, "");
  put_cstr(&m, name);
  put16(&m, 0);
  put16(&m, (uint16_t)n);
  for (int i = 0; i < n; i++) {
    put32(&m, (uint32_t)lens[i]);
    buckets_buf_append(&m, vals[i], lens[i]);
  }
  put16(&m, 0); /* colFmtData: no result columns */
  msg_end(&m, true);
  buckets_buf_append(&m, "E\0\0\0\t\0\0\0\0\0", 10);
  buckets_buf_append(&m, "S\0\0\0\4", 5);
  pstatus st = pg_send(p, &m) ? until_ready(p, err, errlen) : P_CONN;
  if (st == P_CONN) snprintf(err, errlen, "driver: bad connection");
  buckets_buf_free(&m);
  return st;
}

/* executeStmts: the table (created when SELECT 1 fails), then the statements. */
static pstatus execute_stmts(pg *p, char *err, size_t errlen) {
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&q, "SELECT 1 FROM %s;", p->table);
  char qerr[512];
  pstatus st = simple_query(p, q.data, qerr, sizeof(qerr));
  if (st == P_ERR) {
    buckets_buf_reset(&q);
    if (p->access)
      buckets_buf_appendf(&q, "CREATE TABLE %s (event_time TIMESTAMP WITH TIME ZONE NOT NULL, event_data JSONB);", p->table);
    else buckets_buf_appendf(&q, "CREATE TABLE %s (key VARCHAR PRIMARY KEY, value JSONB);", p->table);
    st = simple_query(p, q.data, err, errlen);
  } else if (st == P_CONN) {
    snprintf(err, errlen, "%s", qerr);
  }
  uint32_t types[2];
  int nt;
  if (st == P_OK) {
    buckets_buf_reset(&q);
    if (p->access) {
      buckets_buf_appendf(&q, "INSERT INTO %s (event_time, event_data) VALUES ($1, $2);", p->table);
      st = prepare(p, q.data, p->stmt_main, types, &nt, err, errlen);
    } else {
      buckets_buf_appendf(&q, "INSERT INTO %s (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;",
                          p->table);
      st = prepare(p, q.data, p->stmt_main, types, &nt, err, errlen);
      if (st == P_OK) {
        buckets_buf_reset(&q);
        buckets_buf_appendf(&q, "DELETE FROM %s WHERE key = $1;", p->table);
        uint32_t t2[2];
        int n2;
        st = prepare(p, q.data, p->stmt_del, t2, &n2, err, errlen);
      }
    }
    if (st == P_OK) p->prepared_ever = true;
  }
  buckets_buf_free(&q);
  return st;
}

/* Re-prepares on a new connection (database/sql prepares a statement on
 * each connection it runs on). */
static pstatus ensure_prepared(pg *p, bool del, char *err, size_t errlen) {
  if (del ? p->stmt_del[0] : p->stmt_main[0]) return P_OK;
  buckets_buf q = BUCKETS_BUF_INIT;
  uint32_t types[2];
  int nt;
  if (p->access) buckets_buf_appendf(&q, "INSERT INTO %s (event_time, event_data) VALUES ($1, $2);", p->table);
  else if (del) buckets_buf_appendf(&q, "DELETE FROM %s WHERE key = $1;", p->table);
  else buckets_buf_appendf(&q, "INSERT INTO %s (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;", p->table);
  pstatus st = prepare(p, q.data, del ? p->stmt_del : p->stmt_main, types, &nt, err, errlen);
  buckets_buf_free(&q);
  return st;
}

/* initPostgreSQL: Ping, executeStmts, then isActive. */
static pstatus init_pg(pg *p, char *err, size_t errlen) {
  if (p->initialized) return P_OK;
  pstatus st = simple_query(p, ";", err, errlen);
  if (st == P_OK) {
    st = execute_stmts(p, err, errlen);
    if (st == P_OK) p->first_ping = true;
  }
  if (st != P_OK) {
    drop(p); /* db.Close */
    return st;
  }
  if ((st = simple_query(p, ";", err, errlen)) == P_OK) p->initialized = true;
  return st;
}

/* isActive: db.Ping; connection errors are ErrNotConnected. */
static pstatus is_active_locked(pg *p, char *err, size_t errlen) {
  pstatus st = simple_query(p, ";", err, errlen);
  if (st == P_CONN) snprintf(err, errlen, "not connected to target server/service");
  return st;
}

static pstatus send_record(pg *p, const char *record, size_t n, const char *event_name, const char *key, char *err,
                           size_t errlen) {
  buckets_buf data = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&data, "{\"Records\":[");
  buckets_buf_append(&data, record, n);
  buckets_buf_append_c(&data, "]}");
  pstatus st;
  if (!p->access) {
    bool del = strcmp(event_name, "s3:ObjectRemoved:Delete") == 0;
    st = ensure_prepared(p, del, err, errlen);
    if (st == P_OK) {
      if (del) {
        const char *v[] = {key};
        size_t l[] = {strlen(key)};
        st = exec_stmt(p, p->stmt_del, v, l, 1, err, errlen);
      } else {
        const char *v[] = {key, data.data};
        size_t l[] = {strlen(key), data.len};
        st = exec_stmt(p, p->stmt_main, v, l, 2, err, errlen);
      }
    }
  } else {
    /* the event time as lib/pq formats a time.Time: 2006-01-02 15:04:05.999999999Z07:00 */
    yyjson_doc *doc = yyjson_read(record, n, 0);
    const char *et = doc ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "eventTime")) : NULL;
    char ts[64] = "";
    if (et && strlen(et) >= 19) {
      snprintf(ts, sizeof(ts), "%.10s %s", et, et + 11);
      size_t tl = strlen(ts);
      if (tl && ts[tl - 1] == 'Z') { /* trim trailing zeros of the fraction, as Go's .999 does */
        char *dot = strchr(ts, '.');
        if (dot) {
          size_t e = tl - 1;
          while (e > (size_t)(dot - ts) + 1 && ts[e - 1] == '0') e--;
          if (e == (size_t)(dot - ts) + 1) e--;
          ts[e] = 'Z', ts[e + 1] = '\0';
        }
      }
    }
    yyjson_doc_free(doc);
    if (!*ts) {
      snprintf(err, errlen, "parsing time \"%s\": cannot parse", et ? et : "");
      st = P_ERR;
    } else {
      st = ensure_prepared(p, false, err, errlen);
      if (st == P_OK) {
        const char *v[] = {ts, data.data};
        size_t l[] = {strlen(ts), data.len};
        st = exec_stmt(p, p->stmt_main, v, l, 2, err, errlen);
      }
    }
  }
  buckets_buf_free(&data);
  if (st == P_CONN) snprintf(err, errlen, "not connected to target server/service");
  return st;
}

static buckets_send_result result(pstatus st) {
  return st == P_OK ? BUCKETS_SEND_OK : st == P_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* Save: init, isActive, send. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  pg *p = impl;
  pthread_mutex_lock(&p->mu);
  pstatus st = init_pg(p, err, errlen);
  if (st == P_OK) st = is_active_locked(p, err, errlen);
  if (st == P_OK) st = send_record(p, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&p->mu);
  return result(st);
}

/* SendFromStore: init, isActive, executeStmts until the first success, send. */
static buckets_send_result send_from_store(void *impl, const char *record, size_t n, const char *event_name,
                                           const char *key, char *err, size_t errlen) {
  pg *p = impl;
  pthread_mutex_lock(&p->mu);
  pstatus st = init_pg(p, err, errlen);
  if (st == P_OK) st = is_active_locked(p, err, errlen);
  if (st == P_OK && !p->first_ping) {
    st = execute_stmts(p, err, errlen);
    if (st == P_CONN) snprintf(err, errlen, "not connected to target server/service");
  }
  if (st == P_OK) st = send_record(p, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&p->mu);
  return result(st);
}

static bool is_active(void *impl, char *err, size_t errlen) {
  pg *p = impl;
  pthread_mutex_lock(&p->mu);
  bool up = init_pg(p, err, errlen) == P_OK && is_active_locked(p, err, errlen) == P_OK;
  pthread_mutex_unlock(&p->mu);
  return up;
}

static void pg_free(void *impl) {
  pg *p = impl;
  if (!p) return;
  if (p->conn) { /* Terminate */
    buckets_buf m = BUCKETS_BUF_INIT;
    msg_begin(&m, 'X');
    msg_end(&m, true);
    buckets_conn_write(p->conn, m.data, m.len);
    buckets_buf_free(&m);
  }
  drop(p);
  pthread_mutex_destroy(&p->mu);
  free(p->table), free(p->dsn), free(p->ca_dir);
  free(p);
}

static const buckets_target_ops k_ops = {
    .type = "postgresql", .send = send_event, .free = pg_free, .is_active = is_active, .send_from_store = send_from_store};
const buckets_target_kind buckets_target_postgres = {"notify_postgres", &k_ops, create};
