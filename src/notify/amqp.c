/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The AMQP 0-9-1 target (MinIO internal/event/target/amqp.go over
 * amqp091-go): for each event a channel is opened (with publisher confirms
 * when asked for), the exchange declared, the event.Log JSON published with
 * the minio-bucket and minio-event headers, the confirmation awaited, and the
 * channel closed. The connection opens as amqp091-go's does (protocol
 * header, Start/StartOk with PLAIN or AMQPLAIN, Tune taking the smaller or
 * the non-zero of each value with a 10s heartbeat, Open of the vhost),
 * heartbeats are sent while idle, and channel numbers come from its rotating
 * allocator. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "net/conn.h"
#include "notify/event.h"
#include "notify/targets.h"

#define FRAME_METHOD 1
#define FRAME_HEADER 2
#define FRAME_BODY 3
#define FRAME_HEARTBEAT 8
#define FRAME_END 0xce

typedef struct {
  char *host, *user, *pass, *vhost, *ca_dir;
  int port;
  bool tls;
  int heartbeat_s; /* the client's (10 unless the URI says) */
  char *exchange, *routing_key, *exchange_type;
  int delivery_mode;
  bool mandatory, immediate, durable, internal, no_wait, auto_deleted, confirms;
  pthread_mutex_t mu;
  buckets_conn *conn;
  bool initialized;
  uint16_t channel_max, follow;
  uint32_t frame_max;
  int heartbeat; /* negotiated */
  time_t last_sent;
} amqp;

typedef enum { A_OK, A_CONN, A_ERR } astatus;

/* ---- settings ------------------------------------------------------------------------- */

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_amqp", target, key);
  return v ? v : buckets_xstrdup("");
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

/* amqp091.ParseURI */
static bool parse_uri(const char *s, amqp *a, char *err, size_t errlen) {
  a->host = buckets_xstrdup("localhost"), a->user = buckets_xstrdup("guest"), a->pass = buckets_xstrdup("guest");
  a->vhost = buckets_xstrdup("/");
  a->port = 5672;
  a->heartbeat_s = 10;
  if (strchr(s, ' ')) {
    snprintf(err, errlen, "URI must not contain whitespace");
    return false;
  }
  const char *colon = strstr(s, ":");
  size_t sl = colon ? (size_t)(colon - s) : 0;
  if (sl == 4 && !strncmp(s, "amqp", 4)) a->tls = false;
  else if (sl == 5 && !strncmp(s, "amqps", 5)) a->tls = true, a->port = 5671;
  else {
    snprintf(err, errlen, "AMQP scheme must be either 'amqp://' or 'amqps://'");
    return false;
  }
  const char *rest = colon + 1, *path = rest;
  bool has_host = false;
  if (!strncmp(rest, "//", 2)) {
    const char *auth = rest + 2;
    size_t al = strcspn(auth, "/?#");
    const char *at = memchr(auth, '@', al);
    if (at) {
      const char *pc = memchr(auth, ':', (size_t)(at - auth));
      free(a->user);
      a->user = unescape(auth, pc ? (size_t)(pc - auth) : (size_t)(at - auth));
      if (pc) {
        free(a->pass);
        a->pass = unescape(pc + 1, (size_t)(at - pc - 1));
      }
    }
    const char *hp = at ? at + 1 : auth;
    size_t hl = al - (size_t)(hp - auth);
    has_host = hl > 0;
    const char *pc = NULL;
    if (hl && *hp == '[') {
      const char *rb = memchr(hp, ']', hl);
      if (rb) {
        free(a->host);
        a->host = buckets_xstrndup(hp + 1, (size_t)(rb - hp - 1));
        if (rb + 1 < hp + hl && rb[1] == ':') pc = rb + 1;
      }
    } else {
      pc = memchr(hp, ':', hl);
      if (pc ? pc > hp : hl) {
        free(a->host);
        a->host = buckets_xstrndup(hp, pc ? (size_t)(pc - hp) : hl);
      }
    }
    if (pc && pc + 1 < hp + hl) {
      char port[16];
      snprintf(port, sizeof(port), "%.*s", (int)(hp + hl - pc - 1), pc + 1);
      char *end;
      long v = strtol(port, &end, 10);
      if (*end || v > 2147483647L) {
        snprintf(err, errlen, "strconv.ParseInt: parsing \"%s\": invalid syntax", port);
        return false;
      }
      a->port = (int)v;
    }
    path = auth + al;
  }
  size_t pl = strcspn(path, "?#");
  if (pl) {
    free(a->vhost);
    if (path[0] == '/') {
      if (!has_host && pl >= 3 && !strncmp(path, "///", 3)) a->vhost = pl > 3 ? unescape(path + 3, pl - 3) : buckets_xstrdup("/");
      else a->vhost = pl > 1 ? unescape(path + 1, pl - 1) : buckets_xstrdup("/");
    } else {
      a->vhost = unescape(path, pl);
    }
  }
  const char *q = path[pl] == '?' ? path + pl + 1 : NULL;
  for (; q && *q;) {
    size_t l = strcspn(q, "&#");
    if (!strncmp(q, "heartbeat=", 10)) {
      char v[32];
      snprintf(v, sizeof(v), "%.*s", (int)(l - 10), q + 10);
      char *end;
      long h = strtol(v, &end, 10);
      if (!*v || *end) {
        snprintf(err, errlen, "heartbeat is not an integer: strconv.Atoi: parsing \"%s\": invalid syntax", v);
        return false;
      }
      a->heartbeat_s = (int)h;
    }
    if (q[l] != '&') break;
    q += l + 1;
  }
  return true;
}

static void settings_free(amqp *a) {
  free(a->host), free(a->user), free(a->pass), free(a->vhost), free(a->ca_dir);
  free(a->exchange), free(a->routing_key), free(a->exchange_type);
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *url = get(cfg, target, "url"), *dm = get(cfg, target, "delivery_mode"), *qlim = get(cfg, target, "queue_limit");
  char *qdir = get(cfg, target, "queue_dir");
  amqp *a = buckets_xcalloc(1, sizeof(*a));
  bool ok = parse_uri(url, a, err, errlen);
  char *end;
  if (ok) {
    a->delivery_mode = (int)strtol(dm, &end, 10);
    if (!*dm || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", dm);
      ok = false;
    }
  }
  if (ok) {
    strtoull(qlim, &end, 10);
    if (!*qlim || *end || *qlim == '-') {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", qlim);
      ok = false;
    }
  }
  if (ok && *qdir && *qdir != '/') {
    snprintf(err, errlen, "queueDir path should be absolute");
    ok = false;
  }
  if (ok && impl) {
    a->exchange = get(cfg, target, "exchange");
    a->routing_key = get(cfg, target, "routing_key");
    a->exchange_type = get(cfg, target, "exchange_type");
    static const char *const flags[] = {"mandatory", "immediate", "durable", "internal", "no_wait", "auto_deleted"};
    bool *dst[] = {&a->mandatory, &a->immediate, &a->durable, &a->internal, &a->no_wait, &a->auto_deleted};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(flags); i++) {
      char *v = get(cfg, target, flags[i]);
      *dst[i] = strcmp(v, "on") == 0;
      free(v);
    }
    /* MinIO reads publisher_confirms from MINIO_NOTIFY_AMQP_PUBLISHING_CONFIRMS */
    char *pc = buckets_config_getenv_only("notify_amqp", target, "publishing_confirms");
    if (!*pc) {
      free(pc);
      pc = buckets_config_get_stored(cfg, "notify_amqp", target, "publisher_confirms");
    }
    a->confirms = strcmp(pc, "on") == 0;
    free(pc);
    a->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    a->follow = 1;
    pthread_mutex_init(&a->mu, NULL);
    *impl = a;
  } else {
    settings_free(a);
    free(a);
  }
  free(url), free(dm), free(qlim), free(qdir);
  return ok;
}

/* ---- frames --------------------------------------------------------------------------- */

static void u8(buckets_buf *b, uint8_t v) { buckets_buf_append(b, &v, 1); }
static void u16(buckets_buf *b, uint16_t v) {
  uint8_t x[2] = {(uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 2);
}
static void u32(buckets_buf *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 4);
}
static void u64(buckets_buf *b, uint64_t v) {
  u32(b, (uint32_t)(v >> 32));
  u32(b, (uint32_t)v);
}
static void shortstr(buckets_buf *b, const char *s) {
  size_t n = strlen(s);
  u8(b, (uint8_t)(n > 255 ? 255 : n));
  buckets_buf_append(b, s, n > 255 ? 255 : n);
}
static void longstr(buckets_buf *b, const void *s, size_t n) {
  u32(b, (uint32_t)n);
  buckets_buf_append(b, s, n);
}
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static void drop(amqp *a) {
  buckets_conn_close(a->conn);
  a->conn = NULL;
}

static bool send_frame(amqp *a, uint8_t type, uint16_t channel, const void *payload, size_t n) {
  buckets_buf f = BUCKETS_BUF_INIT;
  u8(&f, type);
  u16(&f, channel);
  u32(&f, (uint32_t)n);
  buckets_buf_append(&f, payload, n);
  u8(&f, FRAME_END);
  bool ok = a->conn && buckets_conn_write(a->conn, f.data, f.len);
  buckets_buf_free(&f);
  if (!ok) drop(a);
  else a->last_sent = time(NULL);
  return ok;
}

static bool send_method(amqp *a, uint16_t channel, uint16_t cls, uint16_t method, const buckets_buf *args) {
  buckets_buf p = BUCKETS_BUF_INIT;
  u16(&p, cls);
  u16(&p, method);
  if (args && args->len) buckets_buf_append(&p, args->data, args->len);
  bool ok = send_frame(a, FRAME_METHOD, channel, p.data, p.len);
  buckets_buf_free(&p);
  return ok;
}

typedef struct {
  uint8_t type;
  uint16_t channel;
  buckets_buf payload;
} frame;

static bool read_frame(amqp *a, frame *f) {
  uint8_t h[7];
  if (!a->conn || !buckets_conn_read_full(a->conn, h, 7)) {
    drop(a);
    return false;
  }
  f->type = h[0];
  f->channel = g16(h + 1);
  uint32_t n = g32(h + 3);
  buckets_buf_reset(&f->payload);
  buckets_buf_reserve(&f->payload, n + 1);
  uint8_t end;
  if ((n && !buckets_conn_read_full(a->conn, f->payload.data, n)) || !buckets_conn_read_full(a->conn, &end, 1) ||
      end != FRAME_END) {
    drop(a);
    return false;
  }
  f->payload.len = n;
  return true;
}

/* A server Close (connection or channel): amqp091's Error, "Exception (<code>)
 * Reason: \"<text>\"". */
static void close_error(const frame *f, char *err, size_t errlen) {
  const uint8_t *p = (const uint8_t *)f->payload.data + 4;
  int code = f->payload.len >= 6 ? g16(p) : 0;
  int tl = f->payload.len >= 7 ? p[2] : 0;
  snprintf(err, errlen, "Exception (%d) Reason: \"%.*s\"", code, tl, (const char *)p + 3);
}

/* Waits for the method cls.method on channel, handling heartbeats, flow
 * control and server closes on the way. */
static astatus expect(amqp *a, uint16_t channel, uint16_t cls, uint16_t method, frame *f, char *err, size_t errlen) {
  for (;;) {
    if (!read_frame(a, f)) {
      snprintf(err, errlen, "Exception (504) Reason: \"channel/connection is not open\"");
      return A_CONN;
    }
    if (f->type == FRAME_HEARTBEAT || f->type != FRAME_METHOD || f->payload.len < 4) continue;
    uint16_t c = g16((uint8_t *)f->payload.data), m = g16((uint8_t *)f->payload.data + 2);
    if (c == 10 && m == 50) { /* connection.close: answer CloseOk, then the connection is gone */
      close_error(f, err, errlen);
      send_method(a, 0, 10, 51, NULL);
      drop(a);
      return A_ERR;
    }
    if (f->channel == channel && c == 20 && m == 40) { /* channel.close */
      close_error(f, err, errlen);
      send_method(a, channel, 20, 41, NULL);
      return A_ERR;
    }
    if (c == 20 && m == 20) { /* channel.flow: acknowledge */
      buckets_buf b = BUCKETS_BUF_INIT;
      u8(&b, f->payload.len > 4 ? (uint8_t)f->payload.data[4] : 1);
      send_method(a, f->channel, 20, 21, &b);
      buckets_buf_free(&b);
      continue;
    }
    if (f->channel == channel && c == cls && m == method) return A_OK;
  }
}

static uint16_t pick16(uint16_t client, uint16_t server) {
  if (!client || !server) return client > server ? client : server;
  return client < server ? client : server;
}
static uint32_t pick32(uint32_t client, uint32_t server) {
  if (!client || !server) return client > server ? client : server;
  return client < server ? client : server;
}

/* amqp091.Dial: header, Start/StartOk, Tune/TuneOk, Open. */
static astatus connect_amqp(amqp *a, char *err, size_t errlen) {
  char derr[256];
  a->conn = buckets_conn_dial(a->host, a->port, NULL, 30000, derr, sizeof(derr));
  if (!a->conn) {
    snprintf(err, errlen, "%s", derr);
    return A_CONN;
  }
  if (a->tls) {
    buckets_tls_client *tc = buckets_tls_client_new(a->ca_dir, err, errlen);
    bool ok = tc && buckets_conn_start_tls(a->conn, tc, a->host);
    buckets_tls_client_free(tc);
    if (!ok) {
      snprintf(err, errlen, "tls: failed to verify certificate");
      drop(a);
      return A_CONN;
    }
  }
  frame f = {0};
  astatus st = A_ERR;
  if (!buckets_conn_write(a->conn, "AMQP\0\0\x09\x01", 8)) {
    snprintf(err, errlen, "write: broken pipe");
    st = A_CONN;
    goto out;
  }
  if ((st = expect(a, 0, 10, 10, &f, err, errlen)) != A_OK) goto out; /* connection.start */
  {
    /* the server's mechanisms, after version (2), properties (table), then longstr */
    const uint8_t *p = (const uint8_t *)f.payload.data + 6;
    size_t left = f.payload.len - 6;
    uint32_t tl = left >= 4 ? g32(p) : 0;
    p += 4 + tl, left -= 4 + tl;
    uint32_t ml = left >= 4 ? g32(p) : 0;
    char mechs[256];
    snprintf(mechs, sizeof(mechs), " %.*s ", (int)BUCKETS_MIN(ml, 250u), (const char *)p + 4);
    bool plain = strstr(mechs, " PLAIN ") != NULL, amqplain = strstr(mechs, " AMQPLAIN ") != NULL;
    if (!plain && !amqplain) {
      snprintf(err, errlen, "Exception (403) Reason: \"SASL could not negotiate a shared mechanism\"");
      st = A_ERR;
      goto out;
    }
    buckets_buf b = BUCKETS_BUF_INIT, props = BUCKETS_BUF_INIT, caps = BUCKETS_BUF_INIT, resp = BUCKETS_BUF_INIT;
    static const char *const cap_keys[] = {"connection.blocked", "consumer_cancel_notify", "basic.nack", "publisher_confirms"};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(cap_keys); i++) {
      shortstr(&caps, cap_keys[i]);
      u8(&caps, 't');
      u8(&caps, 1);
    }
    char version[32];
    snprintf(version, sizeof(version), "%s", BUCKETS_VERSION);
    const char *kv[][2] = {{"product", "Buckets"}, {"version", version}, {"platform", "C"}};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(kv); i++) {
      shortstr(&props, kv[i][0]);
      u8(&props, 'S');
      longstr(&props, kv[i][1], strlen(kv[i][1]));
    }
    shortstr(&props, "capabilities");
    u8(&props, 'F');
    longstr(&props, caps.data, caps.len);
    longstr(&b, props.data, props.len);
    if (plain) { /* PlainAuth: "\0user\0password" */
      shortstr(&b, "PLAIN");
      u8(&resp, 0);
      buckets_buf_append_c(&resp, a->user);
      u8(&resp, 0);
      buckets_buf_append_c(&resp, a->pass);
    } else { /* AMQPlainAuth: a table without its length */
      shortstr(&b, "AMQPLAIN");
      shortstr(&resp, "LOGIN");
      u8(&resp, 'S');
      longstr(&resp, a->user, strlen(a->user));
      shortstr(&resp, "PASSWORD");
      u8(&resp, 'S');
      longstr(&resp, a->pass, strlen(a->pass));
    }
    longstr(&b, resp.data, resp.len);
    shortstr(&b, "en_US");
    bool sent = send_method(a, 0, 10, 11, &b);
    buckets_buf_free(&b), buckets_buf_free(&props), buckets_buf_free(&caps), buckets_buf_free(&resp);
    if (!sent) {
      st = A_CONN;
      goto out;
    }
  }
  if ((st = expect(a, 0, 10, 30, &f, err, errlen)) != A_OK) { /* connection.tune */
    snprintf(err, errlen, "Exception (403) Reason: \"username or password not allowed\"");
    goto out;
  }
  {
    const uint8_t *p = (const uint8_t *)f.payload.data + 4;
    a->channel_max = pick16(0, g16(p));
    if (!a->channel_max) a->channel_max = 2047;
    a->frame_max = pick32(0, g32(p + 2));
    a->heartbeat = pick16((uint16_t)a->heartbeat_s, g16(p + 6));
    buckets_buf b = BUCKETS_BUF_INIT;
    u16(&b, a->channel_max);
    u32(&b, a->frame_max);
    u16(&b, (uint16_t)a->heartbeat);
    bool sent = send_method(a, 0, 10, 31, &b);
    buckets_buf_reset(&b);
    shortstr(&b, a->vhost); /* connection.open */
    shortstr(&b, "");
    u8(&b, 0);
    sent = sent && send_method(a, 0, 10, 40, &b);
    buckets_buf_free(&b);
    if (!sent) {
      st = A_CONN;
      goto out;
    }
  }
  if ((st = expect(a, 0, 10, 41, &f, err, errlen)) != A_OK) {
    if (st == A_ERR || st == A_CONN) snprintf(err, errlen, "Exception (403) Reason: \"no access to this vhost\"");
    goto out;
  }
  a->follow = 1;
out:
  buckets_buf_free(&f.payload);
  if (st != A_OK) drop(a);
  return st;
}

/* The allocator's next channel number (follow, wrapping to 1). */
static uint16_t next_channel(amqp *a) {
  uint16_t ch = a->follow;
  a->follow = a->follow >= a->channel_max ? 1 : (uint16_t)(a->follow + 1);
  return ch;
}

static astatus channel_close(amqp *a, uint16_t ch) {
  buckets_buf b = BUCKETS_BUF_INIT;
  u16(&b, 200);
  shortstr(&b, "");
  u16(&b, 0);
  u16(&b, 0);
  bool sent = send_method(a, ch, 20, 40, &b);
  buckets_buf_free(&b);
  if (!sent) return A_CONN;
  frame f = {0};
  char e[128];
  astatus st = expect(a, ch, 20, 41, &f, e, sizeof(e));
  buckets_buf_free(&f.payload);
  return st;
}

/* target.channel(): a channel on the connection (redialed once closed),
 * with confirms selected when asked for. */
static astatus channel_open(amqp *a, uint16_t *ch, char *err, size_t errlen) {
  if (a->conn && buckets_conn_broken(a->conn)) drop(a);
  if (!a->conn) {
    astatus st = connect_amqp(a, err, errlen);
    if (st != A_OK) {
      if (st == A_CONN && strstr(err, "connection refused")) snprintf(err, errlen, "not connected to target server/service");
      return st;
    }
  }
  *ch = next_channel(a);
  buckets_buf b = BUCKETS_BUF_INIT;
  shortstr(&b, "");
  frame f = {0};
  astatus st = send_method(a, *ch, 20, 10, &b) ? expect(a, *ch, 20, 11, &f, err, errlen) : A_CONN;
  if (st == A_OK && a->confirms) {
    buckets_buf_reset(&b);
    u8(&b, 0); /* nowait false */
    st = send_method(a, *ch, 85, 10, &b) ? expect(a, *ch, 85, 11, &f, err, errlen) : A_CONN;
    if (st == A_ERR) channel_close(a, *ch);
  }
  buckets_buf_free(&b);
  buckets_buf_free(&f.payload);
  return st;
}

static astatus publish(amqp *a, uint16_t ch, const char *bucket, const char *event_name, const char *body, size_t n,
                       char *err, size_t errlen) {
  buckets_buf b = BUCKETS_BUF_INIT;
  frame f = {0};
  astatus st;
  /* exchange.declare */
  u16(&b, 0);
  shortstr(&b, a->exchange);
  shortstr(&b, a->exchange_type);
  u8(&b, (uint8_t)((a->durable ? 2 : 0) | (a->auto_deleted ? 4 : 0) | (a->internal ? 8 : 0) | (a->no_wait ? 16 : 0)));
  u32(&b, 0); /* no arguments */
  if (!send_method(a, ch, 40, 10, &b)) st = A_CONN;
  else st = a->no_wait ? A_OK : expect(a, ch, 40, 11, &f, err, errlen);
  if (st == A_OK) { /* basic.publish, content header, body frames */
    buckets_buf_reset(&b);
    u16(&b, 0);
    shortstr(&b, a->exchange);
    shortstr(&b, a->routing_key);
    u8(&b, (uint8_t)((a->mandatory ? 1 : 0) | (a->immediate ? 2 : 0)));
    bool sent = send_method(a, ch, 60, 40, &b);
    buckets_buf h = BUCKETS_BUF_INIT, headers = BUCKETS_BUF_INIT;
    u16(&h, 60);
    u16(&h, 0);
    u64(&h, n);
    u16(&h, (uint16_t)(0x8000 | 0x2000 | (a->delivery_mode > 0 ? 0x1000 : 0)));
    shortstr(&h, "application/json");
    shortstr(&headers, "minio-bucket");
    u8(&headers, 'S');
    longstr(&headers, bucket, strlen(bucket));
    shortstr(&headers, "minio-event");
    u8(&headers, 'S');
    longstr(&headers, event_name, strlen(event_name));
    longstr(&h, headers.data, headers.len);
    if (a->delivery_mode > 0) u8(&h, (uint8_t)a->delivery_mode);
    sent = sent && send_frame(a, FRAME_HEADER, ch, h.data, h.len);
    size_t chunk = a->frame_max > 8 ? a->frame_max - 8 : n;
    for (size_t off = 0; sent && off < n; off += chunk) sent = send_frame(a, FRAME_BODY, ch, body + off, BUCKETS_MIN(chunk, n - off));
    buckets_buf_free(&h);
    buckets_buf_free(&headers);
    st = sent ? A_OK : A_CONN;
  }
  if (st == A_OK && a->confirms) { /* basic.ack or basic.nack */
    for (;;) {
      if (!read_frame(a, &f)) {
        st = A_CONN;
        break;
      }
      if (f.type != FRAME_METHOD || f.payload.len < 4) continue;
      uint16_t c = g16((uint8_t *)f.payload.data), m = g16((uint8_t *)f.payload.data + 2);
      if (c == 60 && (m == 80 || m == 120) && f.channel == ch) {
        if (m == 120) {
          uint64_t tag = (uint64_t)g32((uint8_t *)f.payload.data + 4) << 32 | g32((uint8_t *)f.payload.data + 8);
          snprintf(err, errlen, "failed delivery of delivery tag: %llu", (unsigned long long)tag);
          st = A_ERR;
        }
        break;
      }
      if (c == 20 && m == 40 && f.channel == ch) {
        close_error(&f, err, errlen);
        send_method(a, ch, 20, 41, NULL);
        st = A_ERR;
        break;
      }
    }
  }
  buckets_buf_free(&b);
  buckets_buf_free(&f.payload);
  if (st == A_CONN) snprintf(err, errlen, "Exception (504) Reason: \"channel/connection is not open\"");
  return st;
}

static buckets_send_result result(astatus st) {
  return st == A_OK ? BUCKETS_SEND_OK : st == A_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

static astatus init_amqp(amqp *a, char *err, size_t errlen) {
  if (a->initialized) return A_OK;
  astatus st = a->conn ? A_OK : connect_amqp(a, err, errlen);
  if (st == A_OK) a->initialized = true;
  return st;
}

/* Save and SendFromStore alike: init, channel, send, close the channel. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  amqp *a = impl;
  pthread_mutex_lock(&a->mu);
  astatus st = init_amqp(a, err, errlen);
  uint16_t ch = 0;
  if (st == A_OK) st = channel_open(a, &ch, err, errlen);
  if (st == A_OK) {
    const char *slash = strchr(key, '/');
    char *bucket = buckets_xstrndup(key, slash ? (size_t)(slash - key) : strlen(key));
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&b, "{\"EventName\":");
    buckets_json_go_string(&b, event_name, strlen(event_name));
    buckets_buf_append_c(&b, ",\"Key\":");
    buckets_json_go_string(&b, key, strlen(key));
    buckets_buf_append_c(&b, ",\"Records\":[");
    buckets_buf_append(&b, record, n);
    buckets_buf_append_c(&b, "]}");
    st = publish(a, ch, bucket, event_name, b.data, b.len, err, errlen);
    /* defer ch.Close(): the channel is closed unless the server already closed it */
    if (a->conn && (st == A_OK || (st == A_ERR && !strncmp(err, "failed delivery", 15)))) channel_close(a, ch);
    buckets_buf_free(&b);
    free(bucket);
  }
  pthread_mutex_unlock(&a->mu);
  return result(st);
}

/* IsActive: init, then a channel opened and closed. */
static bool is_active(void *impl, char *err, size_t errlen) {
  amqp *a = impl;
  pthread_mutex_lock(&a->mu);
  uint16_t ch;
  bool up = init_amqp(a, err, errlen) == A_OK && channel_open(a, &ch, err, errlen) == A_OK;
  if (up) channel_close(a, ch);
  pthread_mutex_unlock(&a->mu);
  return up;
}

/* The heartbeater: a heartbeat frame when nothing was sent for a while;
 * incoming frames (the server's heartbeats) are read and dropped. */
static void tick(void *impl) {
  amqp *a = impl;
  pthread_mutex_lock(&a->mu);
  while (a->conn && buckets_conn_readable(a->conn, 0) > 0) {
    frame f = {0};
    if (read_frame(a, &f) && f.type == FRAME_METHOD && f.payload.len >= 4 && g16((uint8_t *)f.payload.data) == 10 &&
        g16((uint8_t *)f.payload.data + 2) == 50) {
      send_method(a, 0, 10, 51, NULL);
      drop(a);
    }
    buckets_buf_free(&f.payload);
  }
  int interval = a->heartbeat / 2;
  if (a->conn && interval > 0 && time(NULL) - a->last_sent > interval - 1) send_frame(a, FRAME_HEARTBEAT, 0, NULL, 0);
  pthread_mutex_unlock(&a->mu);
}

static void amqp_free(void *impl) {
  amqp *a = impl;
  if (!a) return;
  if (a->conn) { /* connection.close */
    buckets_buf b = BUCKETS_BUF_INIT;
    u16(&b, 200);
    shortstr(&b, "");
    u16(&b, 0);
    u16(&b, 0);
    if (send_method(a, 0, 10, 50, &b)) {
      frame f = {0};
      char e[128];
      expect(a, 0, 10, 51, &f, e, sizeof(e));
      buckets_buf_free(&f.payload);
    }
    buckets_buf_free(&b);
  }
  drop(a);
  pthread_mutex_destroy(&a->mu);
  settings_free(a);
  free(a);
}

static const buckets_target_ops k_ops = {
    .type = "amqp", .send = send_event, .free = amqp_free, .is_active = is_active, .tick = tick};
const buckets_target_kind buckets_target_amqp = {"notify_amqp", &k_ops, create};
