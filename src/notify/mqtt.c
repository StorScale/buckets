/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The MQTT target (MinIO internal/event/target/mqtt.go over
 * paho.mqtt.golang): PUBLISH of the event.Log JSON at the configured QoS
 * (PUBACK for 1, PUBREC/PUBREL/PUBCOMP for 2), MQTT 3.1.1 falling back to
 * 3.1 when the broker refuses the version, a clean session, PINGREQ when
 * the keep-alive passes without traffic, and reconnects with a doubling
 * backoff up to reconnect_interval. Brokers are tcp://, ssl://, tls://,
 * tcps://, ws:// or wss:// (MQTT over WebSocket, subprotocol "mqtt"). */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "net/conn.h"
#include "notify/event.h"
#include "notify/targets.h"
#include "notify/xnet.h"

#define WAIT_MS 5000      /* the target's reconnectInterval: how long a token is waited for */
#define PING_TIMEOUT_S 10 /* paho's PingTimeout */

typedef struct {
  char *topic, *user, *pass, *ca_dir, *path;
  char scheme[8];
  buckets_xnet_host host;
  int qos;
  int64_t keepalive_s, max_reconnect_s;
  pthread_mutex_t mu;
  buckets_conn *conn;
  bool ws, tls, initialized, ever_connected;
  int version; /* 4 (3.1.1) or 3 (3.1), locked in after the first connection */
  uint16_t last_id;
  time_t last_sent, last_recv, ping_sent, next_retry;
  int64_t backoff_s;
  size_t ws_left; /* WebSocket: the unread rest of the current frame */
} mqtt;

typedef enum { M_OK, M_CONN, M_ERR } mstatus;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_mqtt", target, key);
  return v ? v : buckets_xstrdup("");
}

/* xnet.ParseURL (url.Parse, then the host checked as net.ParseHost does):
 * the scheme, host and path. */
static bool parse_url(const char *s, char *scheme, size_t scap, buckets_xnet_host *h, char **path, char *err,
                      size_t errlen) {
  memset(h, 0, sizeof(*h));
  *scheme = '\0';
  *path = NULL;
  const char *rest = s;
  size_t i = 0;
  while (s[i] && s[i] != ':' && s[i] != '/' && s[i] != '?' && s[i] != '#') i++;
  if (s[i] == ':' && i > 0) {
    bool valid = (s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z');
    for (size_t k = 1; k < i && valid; k++) valid = strchr("+-.", s[k]) || (s[k] >= '0' && s[k] <= '9') ||
                                                    (s[k] >= 'a' && s[k] <= 'z') || (s[k] >= 'A' && s[k] <= 'Z');
    if (!valid) {
      snprintf(err, errlen, "parse \"%s\": first path segment in URL cannot contain colon", s);
      return false;
    }
    snprintf(scheme, scap, "%.*s", (int)i, s);
    for (char *p = scheme; *p; p++) *p = (char)(*p >= 'A' && *p <= 'Z' ? *p + 32 : *p);
    rest = s + i + 1;
  } else if (s[i] == ':' && i == 0) {
    snprintf(err, errlen, "parse \"%s\": missing protocol scheme", s);
    return false;
  }
  char hostname[300] = "", port[64] = "";
  if (strncmp(rest, "//", 2) == 0) {
    const char *a = rest + 2;
    size_t al = strcspn(a, "/?#");
    const char *at = memchr(a, '@', al);
    const char *hp = at ? at + 1 : a;
    size_t hl = al - (size_t)(hp - a);
    if (hl && hp[0] == '[') {
      const char *rb = memchr(hp, ']', hl);
      if (!rb) {
        snprintf(err, errlen, "parse \"%s\": missing ']' in host", s);
        return false;
      }
      snprintf(hostname, sizeof(hostname), "%.*s", (int)(rb - hp - 1), hp + 1);
      if (rb + 1 < hp + hl && rb[1] == ':') snprintf(port, sizeof(port), "%.*s", (int)(hp + hl - rb - 2), rb + 2);
    } else {
      const char *colon = memchr(hp, ':', hl);
      snprintf(hostname, sizeof(hostname), "%.*s", colon ? (int)(colon - hp) : (int)hl, hp);
      if (colon) snprintf(port, sizeof(port), "%.*s", (int)(hp + hl - colon - 1), colon + 1);
    }
    rest = a + al;
  }
  if (!*hostname) {
    if (*scheme) {
      snprintf(err, errlen, "scheme appears with empty host");
      return false;
    }
  } else {
    if (!*port && strcmp(scheme, "http") == 0) snprintf(port, sizeof(port), "80");
    if (!*port && strcmp(scheme, "https") == 0) snprintf(port, sizeof(port), "443");
    char join[400];
    snprintf(join, sizeof(join), strchr(hostname, ':') ? "[%s]:%s" : "%s:%s", hostname, port);
    if (!buckets_xnet_parse_host(join, h, err, errlen)) return false;
  }
  size_t pl = strcspn(rest, "?#");
  *path = buckets_xstrndup(rest, pl);
  return true;
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *broker = get(cfg, target, "broker"), *topic = get(cfg, target, "topic"), *qos = get(cfg, target, "qos");
  char *user = get(cfg, target, "username"), *pass = get(cfg, target, "password");
  char *rint = get(cfg, target, "reconnect_interval"), *kint = get(cfg, target, "keep_alive_interval");
  char *qdir = get(cfg, target, "queue_dir"), *qlim = get(cfg, target, "queue_limit");
  char scheme[32];
  buckets_xnet_host h;
  char *path = NULL;
  int64_t reconnect_ns = 0, keepalive_ns = 0;
  unsigned long q = 0;
  bool ok = parse_url(broker, scheme, sizeof(scheme), &h, &path, err, errlen);
  if (ok && !buckets_go_duration_parse(rint, &reconnect_ns)) {
    buckets_go_duration_error(rint, err, errlen);
    ok = false;
  }
  if (ok && !buckets_go_duration_parse(kint, &keepalive_ns)) {
    buckets_go_duration_error(kint, err, errlen);
    ok = false;
  }
  if (ok) {
    char *end;
    strtoull(qlim, &end, 10);
    if (!*qlim || *end || *qlim == '-') {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", qlim);
      ok = false;
    }
  }
  if (ok) {
    char *end;
    q = strtoul(qos, &end, 10);
    if (!*qos || *end || *qos == '-') {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", qos);
      ok = false;
    } else if (q > 255) {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": value out of range", qos);
      ok = false;
    }
  }
  if (ok) { /* Validate */
    static const char *const schemes[] = {"ws", "wss", "tcp", "ssl", "tls", "tcps"};
    bool known = false;
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(schemes); i++) known |= strcmp(scheme, schemes[i]) == 0;
    if (!known) {
      snprintf(err, errlen, "unknown protocol in broker address");
      ok = false;
    } else if (*qdir && *qdir != '/') {
      snprintf(err, errlen, "queueDir path should be absolute");
      ok = false;
    } else if (*qdir && q == 0) {
      snprintf(err, errlen, "qos should be set to 1 or 2 if queueDir is set");
      ok = false;
    }
  }
  if (ok && impl) {
    mqtt *m = buckets_xcalloc(1, sizeof(*m));
    m->topic = topic, m->user = user, m->pass = pass, m->path = path, topic = user = pass = NULL, path = NULL;
    m->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    snprintf(m->scheme, sizeof(m->scheme), "%s", scheme);
    m->host = h;
    m->qos = (int)q;
    m->ws = strcmp(scheme, "ws") == 0 || strcmp(scheme, "wss") == 0;
    m->tls = strcmp(scheme, "ssl") == 0 || strcmp(scheme, "tls") == 0 || strcmp(scheme, "tcps") == 0 ||
             strcmp(scheme, "wss") == 0;
    m->max_reconnect_s = reconnect_ns ? reconnect_ns / 1000000000LL : 600; /* 10 minutes when unset */
    if (m->max_reconnect_s < 1) m->max_reconnect_s = 1;
    m->keepalive_s = keepalive_ns ? keepalive_ns / 1000000000LL : 10;
    m->version = 4;
    m->backoff_s = 1;
    pthread_mutex_init(&m->mu, NULL);
    *impl = m;
  }
  free(broker), free(topic), free(qos), free(user), free(pass), free(rint), free(kint), free(qdir), free(qlim), free(path);
  return ok;
}

/* ---- transport: raw stream, or WebSocket binary frames ---- */

static void drop(mqtt *m) {
  buckets_conn_close(m->conn);
  m->conn = NULL;
}

static bool tx(mqtt *m, const uint8_t *p, size_t n) {
  bool ok;
  if (!m->ws) {
    ok = buckets_conn_write(m->conn, p, n);
  } else { /* one masked binary frame per packet, as gorilla's writer sends */
    buckets_buf f = BUCKETS_BUF_INIT;
    uint8_t h[14], mask[4];
    size_t hl = 0;
    h[hl++] = 0x82;
    if (n < 126) h[hl++] = (uint8_t)(0x80 | n);
    else if (n < 65536) h[hl++] = 0x80 | 126, h[hl++] = (uint8_t)(n >> 8), h[hl++] = (uint8_t)n;
    else {
      h[hl++] = 0x80 | 127;
      for (int i = 7; i >= 0; i--) h[hl++] = (uint8_t)((uint64_t)n >> (8 * i));
    }
    RAND_bytes(mask, 4);
    buckets_buf_append(&f, h, hl);
    buckets_buf_append(&f, mask, 4);
    size_t off = f.len;
    buckets_buf_append(&f, p, n);
    for (size_t i = 0; i < n; i++) f.data[off + i] = (char)(f.data[off + i] ^ mask[i & 3]);
    ok = buckets_conn_write(m->conn, f.data, f.len);
    buckets_buf_free(&f);
  }
  if (ok) m->last_sent = time(NULL);
  return ok;
}

static bool rx(mqtt *m, uint8_t *out, size_t n) {
  if (!m->ws) return buckets_conn_read_full(m->conn, out, n);
  while (n) {
    while (!m->ws_left) { /* the next data frame's payload (control frames are dropped) */
      uint8_t h[2];
      if (!buckets_conn_read_full(m->conn, h, 2)) return false;
      uint64_t len = h[1] & 0x7f;
      uint8_t ext[8];
      if (len == 126) {
        if (!buckets_conn_read_full(m->conn, ext, 2)) return false;
        len = (uint64_t)ext[0] << 8 | ext[1];
      } else if (len == 127) {
        if (!buckets_conn_read_full(m->conn, ext, 8)) return false;
        len = 0;
        for (int i = 0; i < 8; i++) len = len << 8 | ext[i];
      }
      int op = h[0] & 0x0f;
      if (op == 0x8) return false; /* close */
      if (op == 0x0 || op == 0x1 || op == 0x2) {
        m->ws_left = (size_t)len;
        continue;
      }
      uint8_t skip[125];
      if (len > sizeof(skip) || !buckets_conn_read_full(m->conn, skip, (size_t)len)) return false;
      if (op == 0x9) { /* ping: pong with the same payload */
        uint8_t pong[2 + 4 + 125] = {0x8a, (uint8_t)(0x80 | len)}, mask[4] = {0};
        memcpy(pong + 2, mask, 4);
        memcpy(pong + 6, skip, (size_t)len);
        if (!buckets_conn_write(m->conn, pong, 6 + (size_t)len)) return false;
      }
    }
    size_t k = BUCKETS_MIN(n, m->ws_left);
    if (!buckets_conn_read_full(m->conn, out, k)) return false;
    out += k, n -= k, m->ws_left -= k;
  }
  return true;
}

static bool ws_handshake(mqtt *m, char *err, size_t errlen) {
  uint8_t key[16];
  RAND_bytes(key, sizeof(key));
  char k64[32];
  buckets_base64_encode(key, sizeof(key), k64);
  buckets_buf req = BUCKETS_BUF_INIT;
  char hostport[300];
  buckets_xnet_host_string(&m->host, hostport, sizeof(hostport));
  buckets_buf_appendf(&req,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Protocol: mqtt\r\nSec-WebSocket-Version: 13\r\n"
                      "Upgrade: websocket\r\n\r\n",
                      *m->path ? m->path : "/", hostport, k64);
  bool ok = buckets_conn_write(m->conn, req.data, req.len);
  buckets_buf_free(&req);
  buckets_buf line = BUCKETS_BUF_INIT;
  if (ok) ok = buckets_conn_read_line(m->conn, &line) && strncmp(line.data, "HTTP/1.1 101", 12) == 0;
  if (!ok) snprintf(err, errlen, "websocket: bad handshake");
  while (ok && buckets_conn_read_line(m->conn, &line) && line.len) {
  }
  buckets_buf_free(&line);
  m->ws_left = 0;
  return ok;
}

/* ---- packets ---- */

static void put_len(buckets_buf *b, size_t n) {
  do {
    uint8_t d = (uint8_t)(n % 128);
    n /= 128;
    if (n) d |= 0x80;
    buckets_buf_append(b, &d, 1);
  } while (n);
}

static void put_str(buckets_buf *b, const char *s, size_t n) {
  uint8_t l[2] = {(uint8_t)(n >> 8), (uint8_t)n};
  buckets_buf_append(b, l, 2);
  buckets_buf_append(b, s, n);
}

static bool send_packet(mqtt *m, uint8_t type, const buckets_buf *body) {
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_append(&p, &type, 1);
  put_len(&p, body ? body->len : 0);
  if (body && body->len) buckets_buf_append(&p, body->data, body->len);
  bool ok = tx(m, (const uint8_t *)p.data, p.len);
  buckets_buf_free(&p);
  return ok;
}

/* The next packet: its first byte and body. */
static bool read_packet(mqtt *m, uint8_t *type, buckets_buf *body) {
  uint8_t t, b;
  if (!rx(m, &t, 1)) return false;
  size_t len = 0, mult = 1;
  do {
    if (!rx(m, &b, 1) || mult > 128 * 128 * 128) return false;
    len += (size_t)(b & 127) * mult;
    mult *= 128;
  } while (b & 128);
  buckets_buf_reset(body);
  buckets_buf_reserve(body, len + 1);
  if (len && !rx(m, (uint8_t *)body->data, len)) return false;
  body->len = len;
  *type = t;
  m->last_recv = time(NULL);
  return true;
}

static const char *const k_connerr[] = {NULL, "unacceptable protocol version", "identifier rejected",
                                        "server Unavailable", "bad user name or password", "not Authorized"};

/* openConnection and the CONNECT handshake (3.1.1, then 3.1 once when the
 * broker refuses the version). */
static mstatus connect_mqtt(mqtt *m, char *err, size_t errlen) {
  for (int attempt = 0; attempt < 2; attempt++) {
    char derr[256];
    m->conn = buckets_conn_dial(m->host.name, m->host.port, NULL, 30000, derr, sizeof(derr));
    if (!m->conn) {
      snprintf(err, errlen, "network Error : %s", derr);
      return M_CONN;
    }
    buckets_conn_set_timeout(m->conn, 30000); /* ConnectTimeout */
    if (m->tls) {
      buckets_tls_client *tc = buckets_tls_client_new(m->ca_dir, err, errlen);
      bool ok = tc && buckets_conn_start_tls(m->conn, tc, m->host.name);
      buckets_tls_client_free(tc);
      if (!ok) {
        snprintf(err, errlen, "network Error : tls: failed to verify certificate");
        drop(m);
        return M_CONN;
      }
    }
    if (m->ws && !ws_handshake(m, derr, sizeof(derr))) {
      snprintf(err, errlen, "network Error : %s", derr);
      drop(m);
      return M_CONN;
    }
    char cid[40];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(cid, sizeof(cid), "%llx", (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec);
    buckets_buf body = BUCKETS_BUF_INIT;
    if (m->version == 4) put_str(&body, "MQTT", 4);
    else put_str(&body, "MQIsdp", 6);
    uint8_t flags = 0x02 | (*m->user ? 0x80 : 0) | (*m->pass ? 0x40 : 0);
    uint8_t vh[3] = {(uint8_t)m->version, flags, (uint8_t)(m->keepalive_s >> 8)};
    uint8_t ka = (uint8_t)m->keepalive_s;
    buckets_buf_append(&body, vh, 3);
    buckets_buf_append(&body, &ka, 1);
    put_str(&body, cid, strlen(cid));
    if (*m->user) put_str(&body, m->user, strlen(m->user));
    if (*m->pass) put_str(&body, m->pass, strlen(m->pass));
    bool sent = send_packet(m, 0x10, &body);
    uint8_t type = 0;
    int rc = -1;
    if (sent && read_packet(m, &type, &body) && (type & 0xf0) == 0x20 && body.len >= 2) rc = (uint8_t)body.data[1];
    buckets_buf_free(&body);
    if (rc == 0) {
      buckets_conn_set_timeout(m->conn, WAIT_MS);
      m->ever_connected = true;
      m->ping_sent = 0;
      m->backoff_s = 1;
      return M_OK;
    }
    drop(m);
    if (rc == 1 && m->version == 4 && !m->ever_connected) {
      m->version = 3;
      continue;
    }
    if (rc < 0) snprintf(err, errlen, "network Error : EOF");
    else snprintf(err, errlen, "%s", rc > 0 && rc < 6 ? k_connerr[rc] : "protocol Violation");
    return rc < 0 ? M_CONN : M_ERR;
  }
  return M_ERR;
}

/* isActive: IsConnectionOpen. */
static mstatus is_open(mqtt *m, char *err, size_t errlen) {
  if (m->conn && buckets_conn_broken(m->conn)) drop(m);
  if (m->conn) return M_OK;
  snprintf(err, errlen, "not connected to target server/service");
  return M_CONN;
}

static mstatus init_mqtt(mqtt *m, char *err, size_t errlen) {
  if (m->initialized) return M_OK;
  mstatus st = m->conn ? M_OK : connect_mqtt(m, err, errlen);
  if (st == M_OK) st = is_open(m, err, errlen);
  if (st == M_OK) m->initialized = true;
  return st;
}

/* Waits for the acknowledgement of id (type PUBACK/PUBREC/PUBCOMP),
 * answering what else arrives. */
static mstatus wait_ack(mqtt *m, uint8_t want, uint16_t id, char *err, size_t errlen) {
  buckets_buf body = BUCKETS_BUF_INIT;
  mstatus st = M_CONN;
  for (;;) {
    uint8_t type;
    if (!read_packet(m, &type, &body)) {
      snprintf(err, errlen, "not connected to target server/service"); /* the token timed out, or the connection was lost */
      drop(m);
      break;
    }
    uint8_t t = type & 0xf0;
    uint16_t pid = body.len >= 2 ? (uint16_t)((uint8_t)body.data[0] << 8 | (uint8_t)body.data[1]) : 0;
    if (t == want && pid == id) {
      st = M_OK;
      break;
    }
    if (t == 0xd0) m->ping_sent = 0; /* PINGRESP */
  }
  buckets_buf_free(&body);
  return st;
}

static mstatus publish(mqtt *m, const char *data, size_t n, char *err, size_t errlen) {
  buckets_buf body = BUCKETS_BUF_INIT;
  put_str(&body, m->topic, strlen(m->topic));
  uint16_t id = 0;
  if (m->qos > 0) {
    id = ++m->last_id ? m->last_id : ++m->last_id; /* 1, 2, ... skipping 0 */
    uint8_t pid[2] = {(uint8_t)(id >> 8), (uint8_t)id};
    buckets_buf_append(&body, pid, 2);
  }
  buckets_buf_append(&body, data, n);
  bool sent = send_packet(m, (uint8_t)(0x30 | (m->qos & 3) << 1), &body);
  buckets_buf_free(&body);
  if (!sent) {
    drop(m);
    snprintf(err, errlen, "not connected to target server/service");
    return M_CONN;
  }
  if (m->qos == 1) return wait_ack(m, 0x40, id, err, errlen);
  if (m->qos == 2) {
    mstatus st = wait_ack(m, 0x50, id, err, errlen);
    if (st != M_OK) return st;
    buckets_buf rel = BUCKETS_BUF_INIT;
    uint8_t pid[2] = {(uint8_t)(id >> 8), (uint8_t)id};
    buckets_buf_append(&rel, pid, 2);
    sent = send_packet(m, 0x62, &rel);
    buckets_buf_free(&rel);
    if (!sent) {
      drop(m);
      snprintf(err, errlen, "not connected to target server/service");
      return M_CONN;
    }
    return wait_ack(m, 0x70, id, err, errlen);
  }
  return M_OK;
}

static buckets_send_result result(mstatus st) {
  return st == M_OK ? BUCKETS_SEND_OK : st == M_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* Save and SendFromStore alike: init, isActive, send. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  mqtt *m = impl;
  pthread_mutex_lock(&m->mu);
  mstatus st = init_mqtt(m, err, errlen);
  if (st == M_OK) st = is_open(m, err, errlen);
  if (st == M_OK) {
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&b, "{\"EventName\":");
    buckets_json_go_string(&b, event_name, strlen(event_name));
    buckets_buf_append_c(&b, ",\"Key\":");
    buckets_json_go_string(&b, key, strlen(key));
    buckets_buf_append_c(&b, ",\"Records\":[");
    buckets_buf_append(&b, record, n);
    buckets_buf_append_c(&b, "]}");
    st = publish(m, b.data, b.len, err, errlen);
    buckets_buf_free(&b);
  }
  pthread_mutex_unlock(&m->mu);
  return result(st);
}

/* paho's keepalive and reconnect loops while idle. */
static void tick(void *impl) {
  mqtt *m = impl;
  char err[256];
  pthread_mutex_lock(&m->mu);
  time_t now = time(NULL);
  if (!m->conn && m->ever_connected && now >= m->next_retry) {
    if (connect_mqtt(m, err, sizeof(err)) != M_OK) {
      m->next_retry = now + m->backoff_s;
      m->backoff_s = BUCKETS_MIN(m->backoff_s * 2, m->max_reconnect_s);
    }
  }
  while (m->conn && buckets_conn_readable(m->conn, 0) > 0) {
    buckets_buf body = BUCKETS_BUF_INIT;
    uint8_t type;
    if (!read_packet(m, &type, &body)) drop(m);
    else if ((type & 0xf0) == 0xd0) m->ping_sent = 0;
    buckets_buf_free(&body);
  }
  if (m->conn) {
    if (m->ping_sent && now - m->ping_sent >= PING_TIMEOUT_S) {
      drop(m); /* pingresp not received: connection lost */
    } else if (!m->ping_sent && (now - m->last_sent >= m->keepalive_s || now - m->last_recv >= m->keepalive_s)) {
      if (send_packet(m, 0xc0, NULL)) m->ping_sent = now;
      else drop(m);
    }
  }
  pthread_mutex_unlock(&m->mu);
}

/* IsActive: init, isActive. */
static bool is_active(void *impl, char *err, size_t errlen) {
  mqtt *m = impl;
  pthread_mutex_lock(&m->mu);
  bool up = init_mqtt(m, err, errlen) == M_OK && is_open(m, err, errlen) == M_OK;
  pthread_mutex_unlock(&m->mu);
  return up;
}

static void mqtt_free(void *impl) {
  mqtt *m = impl;
  if (!m) return;
  if (m->conn) send_packet(m, 0xe0, NULL); /* Disconnect */
  drop(m);
  pthread_mutex_destroy(&m->mu);
  free(m->topic), free(m->user), free(m->pass), free(m->ca_dir), free(m->path);
  free(m);
}

static const buckets_target_ops k_ops = {
    .type = "mqtt", .send = send_event, .free = mqtt_free, .is_active = is_active, .tick = tick};
const buckets_target_kind buckets_target_mqtt = {"notify_mqtt", &k_ops, create};
