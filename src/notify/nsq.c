/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The NSQ target (MinIO internal/event/target/nsq.go over go-nsq's
 * Producer): PUB <topic> with the event.Log JSON {"EventName","Key",
 * "Records":[event]}. The connection opens as go-nsq's does (the "  V2"
 * magic, IDENTIFY with feature negotiation, a TLS upgrade when nsqd agrees
 * to one), a Ping is a NOP, and server heartbeats are answered with NOPs
 * while idle. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/common.h"
#include "net/conn.h"
#include "notify/event.h"
#include "notify/targets.h"
#include "notify/xnet.h"

#define DIAL_TIMEOUT_MS 1000    /* go-nsq dial_timeout */
#define READ_TIMEOUT_MS 60000   /* read_timeout */
#define FRAME_RESPONSE 0
#define FRAME_ERROR 1

typedef struct {
  buckets_xnet_host addr;
  char *topic, *ca_file;
  bool tls, skip_verify;
  pthread_mutex_t mu;
  buckets_conn *conn;
  bool initialized;
} nsq;

typedef enum { N_OK, N_CONN, N_ERR } nstatus;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_nsq", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  char *addr = get(cfg, target, "nsqd_address"), *qlim = get(cfg, target, "queue_limit");
  char *topic = get(cfg, target, "topic"), *qdir = get(cfg, target, "queue_dir");
  char *tls = get(cfg, target, "tls"), *skip = get(cfg, target, "tls_skip_verify");
  buckets_xnet_host h;
  bool ok = buckets_xnet_parse_host(addr, &h, err, errlen);
  if (ok) {
    char *end;
    strtol(qlim, &end, 10);
    if (!*qlim || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qlim);
      ok = false;
    }
  }
  if (ok && !*h.name) {
    snprintf(err, errlen, "empty nsqdAddress");
    ok = false;
  } else if (ok && !*topic) {
    snprintf(err, errlen, "empty topic");
    ok = false;
  } else if (ok && *qdir && *qdir != '/') {
    snprintf(err, errlen, "queueDir path should be absolute");
    ok = false;
  }
  if (ok && impl) {
    nsq *q = buckets_xcalloc(1, sizeof(*q));
    q->addr = h;
    q->topic = topic, topic = NULL;
    q->ca_file = ca_file ? buckets_xstrdup(ca_file) : NULL;
    q->tls = strcmp(tls, "on") == 0;
    q->skip_verify = strcmp(skip, "on") == 0;
    pthread_mutex_init(&q->mu, NULL);
    *impl = q;
  }
  free(addr), free(qlim), free(topic), free(qdir), free(tls), free(skip);
  return ok;
}

static void put32(buckets_buf *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
  buckets_buf_append(b, x, 4);
}

static void drop(nsq *q) {
  buckets_conn_close(q->conn);
  q->conn = NULL;
}

/* One frame: [size][type][data]. */
static bool read_frame(buckets_conn *c, int *type, buckets_buf *data) {
  uint8_t h[8];
  if (!buckets_conn_read_full(c, h, 4)) return false;
  uint32_t size = (uint32_t)h[0] << 24 | (uint32_t)h[1] << 16 | (uint32_t)h[2] << 8 | h[3];
  if (size < 4 || size > (64u << 20) || !buckets_conn_read_full(c, h + 4, 4)) return false;
  *type = (int)((uint32_t)h[4] << 24 | (uint32_t)h[5] << 16 | (uint32_t)h[6] << 8 | h[7]);
  buckets_buf_reset(data);
  buckets_buf_reserve(data, size - 4 + 1);
  if (!buckets_conn_read_full(c, data->data, size - 4)) return false;
  data->len = size - 4;
  data->data[data->len] = '\0';
  return true;
}

/* A response to a command, answering heartbeats that come first. */
static nstatus read_response(nsq *q, char *err, size_t errlen) {
  buckets_buf d = BUCKETS_BUF_INIT;
  nstatus st;
  for (;;) {
    int type;
    if (!read_frame(q->conn, &type, &d)) {
      snprintf(err, errlen, "EOF");
      st = N_CONN;
      break;
    }
    if (type == FRAME_RESPONSE && strcmp(d.data, "_heartbeat_") == 0) {
      if (!buckets_conn_write(q->conn, "NOP\n", 4)) {
        snprintf(err, errlen, "write: broken pipe");
        st = N_CONN;
        break;
      }
      continue;
    }
    if (type == FRAME_ERROR) {
      snprintf(err, errlen, "%s", d.data); /* ErrProtocol */
      st = N_ERR;
    } else {
      st = N_OK;
    }
    break;
  }
  if (st == N_CONN) drop(q);
  buckets_buf_free(&d);
  return st;
}

/* Conn.Connect: the magic, then IDENTIFY (a Go map: keys in order). */
static nstatus connect_nsq(nsq *q, char *err, size_t errlen) {
  q->conn = buckets_conn_dial(q->addr.name, q->addr.port, NULL, DIAL_TIMEOUT_MS, err, errlen);
  if (!q->conn) return N_CONN;
  buckets_conn_set_timeout(q->conn, READ_TIMEOUT_MS);
  char host[256] = "";
  gethostname(host, sizeof(host) - 1);
  char client[256];
  snprintf(client, sizeof(client), "%.*s", (int)strcspn(host, "."), host);
  buckets_buf id = BUCKETS_BUF_INIT, cmd = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&id, "{\"client_id\":");
  buckets_json_go_string(&id, client, strlen(client));
  buckets_buf_append_c(&id, ",\"deflate\":false,\"deflate_level\":6,\"feature_negotiation\":true,\"heartbeat_interval\":30000,\"hostname\":");
  buckets_json_go_string(&id, host, strlen(host));
  buckets_buf_append_c(&id, ",\"long_id\":");
  buckets_json_go_string(&id, host, strlen(host));
  buckets_buf_append_c(&id, ",\"msg_timeout\":0,\"output_buffer_size\":16384,\"output_buffer_timeout\":250,\"sample_rate\":0,\"short_id\":");
  buckets_json_go_string(&id, client, strlen(client));
  buckets_buf_appendf(&id, ",\"snappy\":false,\"tls_v1\":%s,\"user_agent\":\"buckets/%s\"}", q->tls ? "true" : "false",
                      BUCKETS_VERSION);
  buckets_buf_append_c(&cmd, "  V2IDENTIFY\n");
  put32(&cmd, (uint32_t)id.len);
  buckets_buf_append(&cmd, id.data, id.len);
  bool sent = buckets_conn_write(q->conn, cmd.data, cmd.len);
  buckets_buf_free(&cmd);
  buckets_buf_free(&id);
  if (!sent) {
    snprintf(err, errlen, "[%s:%d] failed to write magic", q->addr.name, q->addr.port);
    drop(q);
    return N_CONN;
  }
  buckets_buf d = BUCKETS_BUF_INIT;
  int type;
  nstatus st = N_OK;
  if (!read_frame(q->conn, &type, &d)) {
    snprintf(err, errlen, "failed to IDENTIFY - EOF");
    st = N_CONN;
  } else if (type == FRAME_ERROR) {
    snprintf(err, errlen, "failed to IDENTIFY - %s", d.data);
    st = N_ERR;
  } else if (d.len && d.data[0] == '{') {
    if (strstr(d.data, "\"tls_v1\":true")) { /* upgradeTLS, then an OK frame */
      buckets_tls_client *tc = buckets_tls_client_new(q->ca_file, err, errlen);
      if (tc && q->skip_verify) buckets_tls_client_skip_verify(tc);
      if (!tc || !buckets_conn_start_tls(q->conn, tc, q->addr.name) || !read_frame(q->conn, &type, &d) ||
          type != FRAME_RESPONSE || strcmp(d.data, "OK") != 0) {
        snprintf(err, errlen, "failed to IDENTIFY - invalid response from TLS upgrade");
        st = N_CONN;
      }
      /* the connection keeps its own reference to the TLS session */
      if (tc) buckets_tls_client_free(tc);
    }
    if (st == N_OK && strstr(d.data, "\"auth_required\":true")) {
      snprintf(err, errlen, "Auth Required");
      st = N_ERR;
    }
  }
  buckets_buf_free(&d);
  if (st != N_OK) drop(q);
  return st;
}

/* Producer.Ping: connect when not connected, then a NOP. */
static nstatus ping(nsq *q, char *err, size_t errlen) {
  if (q->conn && buckets_conn_broken(q->conn)) drop(q);
  if (!q->conn) {
    nstatus st = connect_nsq(q, err, errlen);
    if (st != N_OK) return st;
  }
  if (!buckets_conn_write(q->conn, "NOP\n", 4)) {
    snprintf(err, errlen, "write: broken pipe");
    drop(q);
    return N_CONN;
  }
  return N_OK;
}

static nstatus init_nsq(nsq *q, char *err, size_t errlen) {
  if (q->initialized) return N_OK;
  nstatus st = ping(q, err, errlen); /* initNSQ: Ping, then isActive */
  if (st != N_OK) {
    drop(q); /* producer.Stop */
    return st;
  }
  if ((st = ping(q, err, errlen)) == N_OK) q->initialized = true;
  return st;
}

static buckets_send_result result(nstatus st) {
  return st == N_OK ? BUCKETS_SEND_OK : st == N_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* Save and SendFromStore alike: init, isActive, Publish. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  nsq *q = impl;
  pthread_mutex_lock(&q->mu);
  nstatus st = init_nsq(q, err, errlen);
  if (st == N_OK) st = ping(q, err, errlen);
  if (st == N_OK) {
    buckets_buf body = BUCKETS_BUF_INIT, cmd = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&body, "{\"EventName\":");
    buckets_json_go_string(&body, event_name, strlen(event_name));
    buckets_buf_append_c(&body, ",\"Key\":");
    buckets_json_go_string(&body, key, strlen(key));
    buckets_buf_append_c(&body, ",\"Records\":[");
    buckets_buf_append(&body, record, n);
    buckets_buf_append_c(&body, "]}");
    buckets_buf_appendf(&cmd, "PUB %s\n", q->topic);
    put32(&cmd, (uint32_t)body.len);
    buckets_buf_append(&cmd, body.data, body.len);
    if (!buckets_conn_write(q->conn, cmd.data, cmd.len)) {
      snprintf(err, errlen, "write: broken pipe");
      drop(q);
      st = N_CONN;
    } else {
      st = read_response(q, err, errlen);
    }
    buckets_buf_free(&body);
    buckets_buf_free(&cmd);
  }
  pthread_mutex_unlock(&q->mu);
  return result(st);
}

/* go-nsq's read loop while idle: heartbeats get NOPs. */
static void tick(void *impl) {
  nsq *q = impl;
  pthread_mutex_lock(&q->mu);
  while (q->conn) {
    int r = buckets_conn_readable(q->conn, 0);
    if (r == 0) break;
    buckets_buf d = BUCKETS_BUF_INIT;
    int type;
    if (r < 0 || !read_frame(q->conn, &type, &d)) {
      drop(q);
    } else if (type == FRAME_RESPONSE && strcmp(d.data, "_heartbeat_") == 0 && !buckets_conn_write(q->conn, "NOP\n", 4)) {
      drop(q);
    }
    buckets_buf_free(&d);
  }
  pthread_mutex_unlock(&q->mu);
}

/* IsActive: init, isActive. */
static bool is_active(void *impl, char *err, size_t errlen) {
  nsq *q = impl;
  pthread_mutex_lock(&q->mu);
  bool up = init_nsq(q, err, errlen) == N_OK && ping(q, err, errlen) == N_OK;
  pthread_mutex_unlock(&q->mu);
  return up;
}

static void nsq_free(void *impl) {
  nsq *q = impl;
  if (!q) return;
  drop(q);
  pthread_mutex_destroy(&q->mu);
  free(q->topic);
  free(q->ca_file);
  free(q);
}

static const buckets_target_ops k_ops = {
    .type = "nsq", .send = send_event, .free = nsq_free, .is_active = is_active, .tick = tick};
const buckets_target_kind buckets_target_nsq = {"notify_nsq", &k_ops, create};
