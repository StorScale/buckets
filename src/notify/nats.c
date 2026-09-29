/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The NATS target (MinIO internal/event/target/nats.go over nats.go):
 * PUB <subject> with the event.Log JSON, or with jetstream=on a JetStream
 * publish (a request on the connection's _INBOX, answered by a PubAck). The
 * connection opens as nats.go's does: INFO, a TLS upgrade when asked for or
 * required (or TLS first with tls_handshake_first), CONNECT with the
 * credentials (user/password, token, an NKey seed or a .creds file signing
 * the server's nonce), then PING/PONG. Server PINGs get PONGs; the client
 * pings every 2 minutes and reconnects every 2 seconds while disconnected.
 * NATS Streaming (deprecated upstream) is not supported. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/uuid.h"
#include "net/conn.h"
#include "notify/event.h"
#include "notify/nkeys.h"
#include "notify/targets.h"
#include "notify/xnet.h"

#define DIAL_TIMEOUT_MS 2000       /* nats.DefaultTimeout */
#define PING_INTERVAL_S 120        /* nats.DefaultPingInterval */
#define MAX_PINGS_OUT 2            /* nats.DefaultMaxPingOut */
#define RECONNECT_WAIT_S 2         /* nats.DefaultReconnectWait */
#define JS_TIMEOUT_MS 5000         /* the JetStream API timeout */
#define JS_RETRY_WAIT_MS 250       /* DefaultPubRetryWait */
#define JS_RETRY_ATTEMPTS 2        /* DefaultPubRetryAttempts */

typedef struct {
  buckets_xnet_host addr;
  char *subject, *user, *pass, *token, *seed, *creds, *ca, *cert, *key, *ca_dir;
  bool tls, handshake_first, jetstream, streaming;
  pthread_mutex_t mu;
  buckets_conn *conn;
  bool initialized, ever_connected;
  bool headers; /* the server takes headers (and so no-responders statuses) */
  long long max_payload;
  time_t last_ping, last_attempt;
  int pings_out;
  char inbox[64]; /* _INBOX.<nuid>. once a request was made */
  unsigned long long rnd;
} nats;

typedef enum { S_OK, S_CONN, S_ERR } nstatus;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_nats", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool go_parse_int(const char *fn, const char *s, bool is_unsigned, char *err, size_t errlen) {
  char *end;
  if (*s == '-' && is_unsigned) end = (char *)s;
  else strtoll(s, &end, 10);
  if (*s && !*end) return true;
  snprintf(err, errlen, "strconv.%s: parsing \"%s\": invalid syntax", fn, s);
  return false;
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  static const char *const keys[] = {"address", "ping_interval", "queue_limit", "subject", "username", "user_credentials",
                                     "password", "cert_authority", "client_cert", "client_key", "token", "nkey_seed",
                                     "tls", "tls_skip_verify", "tls_handshake_first", "queue_dir", "jetstream",
                                     "streaming", "streaming_max_pub_acks_in_flight", "streaming_cluster_id"};
  /* read from the environment only, as MinIO's config does not know them */
  static const char *const env_only[] = {"user_credentials", "nkey_seed", "tls_handshake_first"};
  enum { ADDR, PING, QLIM, SUBJ, USER, CREDS, PASS, CA, CERT, KEY, TOKEN, SEED, TLS, SKIP, HSFIRST, QDIR, JS, STREAM,
         MAXACKS, CLUSTER, NKEYS };
  char *v[NKEYS];
  for (int i = 0; i < NKEYS; i++) {
    bool eo = false;
    for (size_t j = 0; j < BUCKETS_ARRAY_LEN(env_only); j++) eo |= strcmp(keys[i], env_only[j]) == 0;
    v[i] = eo ? buckets_config_getenv_only("notify_nats", target, keys[i]) : get(cfg, target, keys[i]);
  }
  buckets_xnet_host h;
  bool ok = buckets_xnet_parse_host(v[ADDR], &h, err, errlen) && go_parse_int("ParseInt", v[PING], false, err, errlen) &&
            go_parse_int("ParseUint", v[QLIM], true, err, errlen);
  bool streaming = strcmp(v[STREAM], "on") == 0;
  if (ok && streaming) ok = go_parse_int("Atoi", v[MAXACKS], false, err, errlen);
  const char *why = NULL;
  if (ok) {
    if (!*h.name) why = "empty address";
    else if (!*v[SUBJ]) why = "empty subject";
    else if (!*v[CERT] != !*v[KEY]) why = "cert and key must be specified as a pair";
    else if (!*v[USER] != !*v[PASS]) why = "username and password must be specified as a pair";
    else if (streaming && !*v[CLUSTER]) why = "empty cluster id";
    else if (*v[QDIR] && *v[QDIR] != '/') why = "queueDir path should be absolute";
    if (why) {
      snprintf(err, errlen, "%s", why);
      ok = false;
    }
  }
  if (ok && impl) {
    nats *n = buckets_xcalloc(1, sizeof(*n));
    n->addr = h;
    if (!n->addr.port_set) n->addr.port = 4222; /* nats.DefaultPort */
    n->subject = v[SUBJ], n->user = v[USER], n->pass = v[PASS], n->token = v[TOKEN], n->seed = v[SEED];
    n->creds = v[CREDS], n->ca = v[CA], n->cert = v[CERT], n->key = v[KEY];
    v[SUBJ] = v[USER] = v[PASS] = v[TOKEN] = v[SEED] = v[CREDS] = v[CA] = v[CERT] = v[KEY] = NULL;
    n->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    /* Secure || TLS && TLSSkipVerify: nats.Secure(nil), which still verifies */
    n->tls = strcmp(v[TLS], "on") == 0;
    n->handshake_first = strcmp(v[HSFIRST], "on") == 0;
    n->jetstream = strcmp(v[JS], "on") == 0;
    n->streaming = streaming;
    n->rnd = (unsigned long long)time(NULL) ^ (unsigned long long)(uintptr_t)n;
    pthread_mutex_init(&n->mu, NULL);
    *impl = n;
  }
  for (int i = 0; i < NKEYS; i++) free(v[i]);
  return ok;
}

static void drop(nats *n) {
  buckets_conn_close(n->conn);
  n->conn = NULL;
}

static bool write_str(nats *n, const char *s, size_t len) {
  if (n->conn && buckets_conn_write(n->conn, s, len)) return true;
  drop(n);
  return false;
}

static bool tls_upgrade(nats *n, char *err, size_t errlen) {
  buckets_tls_client *tc = buckets_tls_client_new(n->ca_dir, err, errlen);
  if (!tc) return false;
  bool ok = true;
  if (*n->ca && !buckets_tls_client_add_ca_file(tc, n->ca)) {
    snprintf(err, errlen, "nats: error parsing root certificates");
    ok = false;
  }
  if (ok && *n->cert && !buckets_tls_client_use_cert(tc, n->cert, n->key, err, errlen)) ok = false;
  if (ok && !buckets_conn_start_tls(n->conn, tc, n->addr.name)) {
    snprintf(err, errlen, "tls: failed to verify certificate");
    ok = false;
  }
  buckets_tls_client_free(tc);
  return ok;
}

/* A new-style inbox token: 8 base62 digits. */
static void resp_token(nats *n, char out[9]) {
  static const char d[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  n->rnd = n->rnd * 6364136223846793005ULL + 1442695040888963407ULL;
  unsigned long long r = n->rnd >> 1;
  for (int i = 0; i < 8; i++, r /= 62) out[i] = d[r % 62];
  out[8] = '\0';
}

/* nc.connect: INFO, TLS, CONNECT, PING, then PONG. */
static nstatus connect_nats(nats *n, char *err, size_t errlen) {
  char derr[256];
  n->conn = buckets_conn_dial(n->addr.name, n->addr.port, NULL, DIAL_TIMEOUT_MS, derr, sizeof(derr));
  if (!n->conn) {
    snprintf(err, errlen, "nats: no servers available for connection");
    return S_CONN;
  }
  if (n->handshake_first && !tls_upgrade(n, err, errlen)) {
    drop(n);
    return S_ERR;
  }
  buckets_buf line = BUCKETS_BUF_INIT;
  nstatus st = S_OK;
  if (!buckets_conn_read_line(n->conn, &line) || strncmp(line.data, "INFO ", 5) != 0) {
    snprintf(err, errlen, "nats: no servers available for connection");
    st = S_CONN;
  }
  yyjson_doc *info = st == S_OK ? yyjson_read(line.data + 5, line.len - 5, 0) : NULL;
  yyjson_val *root = info ? yyjson_doc_get_root(info) : NULL;
  bool tls_required = yyjson_get_bool(yyjson_obj_get(root, "tls_required"));
  bool tls_available = yyjson_get_bool(yyjson_obj_get(root, "tls_available"));
  n->headers = yyjson_get_bool(yyjson_obj_get(root, "headers"));
  yyjson_val *mp = yyjson_obj_get(root, "max_payload");
  n->max_payload = yyjson_is_num(mp) ? (long long)yyjson_get_num(mp) : 0;
  const char *nonce = yyjson_get_str(yyjson_obj_get(root, "nonce"));
  bool secure = n->tls;
  if (st == S_OK && secure && !tls_required && !tls_available) { /* checkForSecure */
    snprintf(err, errlen, "nats: secure connection not available");
    st = S_ERR;
  }
  if (st == S_OK && tls_required) secure = true;
  if (st == S_OK && secure && !n->handshake_first && !tls_upgrade(n, err, errlen)) st = S_ERR;
  /* credentials: JWT and seed from a .creds file, else an NKey seed */
  char *jwt = NULL, *seed = NULL, nkey[64] = "", sig[100] = "";
  if (st == S_OK && *n->creds && !buckets_nats_creds_read(n->creds, &jwt, &seed, err, errlen)) st = S_ERR;
  if (st == S_OK && !seed && *n->seed) { /* NkeyOptionFromSeed: a seed file */
    if (!buckets_nkey_seed_file(n->seed, &seed, err, errlen) || !buckets_nkey_from_seed(seed, nkey, sizeof(nkey), err, errlen))
      st = S_ERR;
  }
  if (st == S_OK && seed && !buckets_nkey_sign(seed, nonce ? nonce : "", nonce ? strlen(nonce) : 0, sig, sizeof(sig), err, errlen))
    st = S_ERR;
  if (st == S_OK) {
    buckets_buf c = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&c, "CONNECT {\"verbose\":false,\"pedantic\":false");
    struct {
      const char *k, *v;
    } opt[] = {{"jwt", jwt}, {"nkey", nkey}, {"sig", sig}, {"user", n->user}, {"pass", n->pass}, {"auth_token", n->token}};
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(opt); i++) {
      if (!opt[i].v || !*opt[i].v) continue;
      buckets_buf_appendf(&c, ",\"%s\":", opt[i].k);
      buckets_json_go_string(&c, opt[i].v, strlen(opt[i].v));
    }
    buckets_buf_appendf(&c,
                        ",\"tls_required\":%s,\"name\":\"Buckets Notification\",\"lang\":\"C\",\"version\":\"%s\","
                        "\"protocol\":1,\"echo\":true,\"headers\":%s,\"no_responders\":%s}\r\nPING\r\n",
                        secure ? "true" : "false", BUCKETS_VERSION, n->headers ? "true" : "false",
                        n->headers ? "true" : "false");
    if (!buckets_conn_write(n->conn, c.data, c.len)) {
      snprintf(err, errlen, "nats: no servers available for connection");
      st = S_CONN;
    } else if (!buckets_conn_read_line(n->conn, &line)) {
      snprintf(err, errlen, "nats: no servers available for connection");
      st = S_CONN;
    } else if (strcmp(line.data, "PONG") != 0) {
      if (strncmp(line.data, "-ERR", 4) == 0) { /* normalizeErr */
        const char *d = line.data + 4;
        while (*d == ' ') d++;
        size_t dl = strlen(d);
        while (dl && d[dl - 1] == '\'') dl--;
        while (*d == '\'') d++, dl--;
        snprintf(err, errlen, "nats: %.*s", (int)dl, d);
      } else {
        snprintf(err, errlen, "nats: expected 'PONG', got '%s'", line.data);
      }
      st = S_ERR;
    }
    buckets_buf_free(&c);
  }
  free(jwt);
  free(seed);
  yyjson_doc_free(info);
  buckets_buf_free(&line);
  if (st != S_OK) {
    drop(n);
    return st;
  }
  n->ever_connected = true;
  n->last_ping = time(NULL);
  n->pings_out = 0;
  if (*n->inbox) { /* resubscribe the response inbox after a reconnect */
    char sub[128];
    int k = snprintf(sub, sizeof(sub), "SUB %s*  1\r\n", n->inbox);
    if (!write_str(n, sub, (size_t)k)) return S_CONN;
  }
  return S_OK;
}

/* One protocol line from the server, handling PING/+OK/INFO on the way;
 * message payloads (MSG/HMSG) are read into payload with their header
 * status (503: no responders). Returns 1 for a message, 0 for none within
 * timeout_ms, -1 when the connection failed. */
static int read_proto(nats *n, int timeout_ms, int *status, buckets_buf *payload, char *err, size_t errlen) {
  buckets_buf line = BUCKETS_BUF_INIT;
  int rc = 0;
  for (;;) {
    int r = buckets_conn_readable(n->conn, timeout_ms);
    if (r == 0) break;
    if (r < 0 || !buckets_conn_read_line(n->conn, &line)) {
      rc = -1;
      break;
    }
    if (strcmp(line.data, "PING") == 0) {
      if (!write_str(n, "PONG\r\n", 6)) {
        rc = -1;
        break;
      }
    } else if (strcmp(line.data, "PONG") == 0) {
      n->pings_out = 0;
    } else if (strncmp(line.data, "-ERR", 4) == 0) {
      snprintf(err, errlen, "nats: %s", line.data + 5);
    } else if (strncmp(line.data, "MSG ", 4) == 0 || strncmp(line.data, "HMSG ", 5) == 0) {
      bool hdr = line.data[0] == 'H';
      char *f[6];
      int nf = 0;
      for (char *tok = strtok(line.data, " "); tok && nf < 6; tok = strtok(NULL, " ")) f[nf++] = tok;
      long total = nf >= 4 ? strtol(f[nf - 1], NULL, 10) : -1;
      long hlen = hdr && nf >= 5 ? strtol(f[nf - 2], NULL, 10) : 0;
      if (total < 0 || hlen > total) {
        rc = -1;
        break;
      }
      char *data = buckets_xmalloc((size_t)total + 2);
      if (!buckets_conn_read_full(n->conn, data, (size_t)total + 2)) {
        free(data);
        rc = -1;
        break;
      }
      *status = 0;
      if (hdr && hlen >= 12 && strncmp(data, "NATS/1.0 ", 9) == 0) *status = atoi(data + 9);
      buckets_buf_reset(payload);
      buckets_buf_append(payload, data + hlen, (size_t)(total - hlen));
      free(data);
      rc = 1;
      break;
    }
    timeout_ms = 0; /* keep draining what is already here */
  }
  buckets_buf_free(&line);
  if (rc < 0) drop(n);
  return rc;
}

/* isActive: connected (or the first connection made); while disconnected,
 * ErrNotConnected. */
static nstatus is_active_locked(nats *n, char *err, size_t errlen) {
  if (n->conn && buckets_conn_broken(n->conn)) drop(n);
  if (n->conn) return S_OK;
  if (!n->ever_connected) return connect_nats(n, err, errlen);
  snprintf(err, errlen, "not connected");
  return S_CONN;
}

static nstatus init_nats(nats *n, char *err, size_t errlen) {
  if (n->initialized) return S_OK;
  if (n->streaming) {
    snprintf(err, errlen, "NATS Streaming is not supported, please migrate to JetStream");
    return S_ERR;
  }
  nstatus st = n->conn ? S_OK : connect_nats(n, err, errlen);
  if (st == S_OK) st = is_active_locked(n, err, errlen);
  if (st == S_OK) n->initialized = true;
  return st;
}

static nstatus publish(nats *n, const char *reply, const char *data, size_t len, char *err, size_t errlen) {
  if (n->max_payload > 0 && (long long)len > n->max_payload) {
    snprintf(err, errlen, "nats: maximum payload exceeded");
    return S_ERR;
  }
  buckets_buf cmd = BUCKETS_BUF_INIT;
  if (reply) buckets_buf_appendf(&cmd, "PUB %s %s %zu\r\n", n->subject, reply, len);
  else buckets_buf_appendf(&cmd, "PUB %s %zu\r\n", n->subject, len);
  buckets_buf_append(&cmd, data, len);
  buckets_buf_append_c(&cmd, "\r\n");
  bool ok = write_str(n, cmd.data, cmd.len);
  buckets_buf_free(&cmd);
  if (!ok) snprintf(err, errlen, "nats: connection closed");
  return ok ? S_OK : S_CONN;
}

/* js.Publish: a request, retried on no-responders, then the PubAck. */
static nstatus js_publish(nats *n, const char *data, size_t len, char *err, size_t errlen) {
  if (!*n->inbox) {
    char nuid[40];
    buckets_uuid_v4(nuid); /* stands in for a NUID: unique per connection */
    size_t k = 0;
    for (const char *p = nuid; *p && k < 22; p++)
      if (*p != '-') nuid[k++] = *p;
    nuid[k] = '\0';
    snprintf(n->inbox, sizeof(n->inbox), "_INBOX.%s.", nuid);
    char sub[128];
    int sl = snprintf(sub, sizeof(sub), "SUB %s*  1\r\n", n->inbox);
    if (!write_str(n, sub, (size_t)sl)) return S_CONN;
  }
  buckets_buf resp = BUCKETS_BUF_INIT;
  nstatus st = S_ERR;
  for (int attempt = 0; attempt <= JS_RETRY_ATTEMPTS; attempt++) {
    if (attempt) {
      struct timespec w = {0, JS_RETRY_WAIT_MS * 1000000L};
      nanosleep(&w, NULL);
    }
    char token[9], reply[80];
    resp_token(n, token);
    snprintf(reply, sizeof(reply), "%s%s", n->inbox, token);
    if ((st = publish(n, reply, data, len, err, errlen)) != S_OK) break;
    int status = 0, r = n->conn ? read_proto(n, JS_TIMEOUT_MS, &status, &resp, err, errlen) : -1;
    if (r < 0) {
      snprintf(err, errlen, "nats: connection closed");
      st = S_CONN;
      break;
    }
    if (r == 0) {
      snprintf(err, errlen, "nats: timeout");
      st = S_ERR;
      break;
    }
    if (status == 503) { /* no responders: retried */
      snprintf(err, errlen, "nats: no response from stream");
      st = S_ERR;
      continue;
    }
    yyjson_doc *doc = yyjson_read(resp.data ? resp.data : "", resp.len, 0);
    yyjson_val *e = doc ? yyjson_obj_get(yyjson_doc_get_root(doc), "error") : NULL;
    if (!doc) {
      snprintf(err, errlen, "nats: invalid jetstream publish response");
      st = S_ERR;
    } else if (e) {
      snprintf(err, errlen, "nats: %s", yyjson_get_str(yyjson_obj_get(e, "description")) ? yyjson_get_str(yyjson_obj_get(e, "description")) : "");
      st = S_ERR;
    } else {
      st = S_OK;
    }
    yyjson_doc_free(doc);
    break;
  }
  buckets_buf_free(&resp);
  return st;
}

static buckets_send_result result(nstatus st) {
  return st == S_OK ? BUCKETS_SEND_OK : st == S_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* Save and SendFromStore alike: init, isActive, send. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  nats *t = impl;
  pthread_mutex_lock(&t->mu);
  nstatus st = init_nats(t, err, errlen);
  if (st == S_OK) st = is_active_locked(t, err, errlen);
  if (st == S_OK) {
    buckets_buf body = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&body, "{\"EventName\":");
    buckets_json_go_string(&body, event_name, strlen(event_name));
    buckets_buf_append_c(&body, ",\"Key\":");
    buckets_json_go_string(&body, key, strlen(key));
    buckets_buf_append_c(&body, ",\"Records\":[");
    buckets_buf_append(&body, record, n);
    buckets_buf_append_c(&body, "]}");
    st = t->jetstream ? js_publish(t, body.data, body.len, err, errlen) : publish(t, NULL, body.data, body.len, err, errlen);
    buckets_buf_free(&body);
  }
  pthread_mutex_unlock(&t->mu);
  return result(st);
}

/* The read loop, pinger and reconnector while idle. */
static void tick(void *impl) {
  nats *n = impl;
  char err[256];
  pthread_mutex_lock(&n->mu);
  time_t now = time(NULL);
  if (!n->conn && n->ever_connected && now - n->last_attempt >= RECONNECT_WAIT_S) {
    n->last_attempt = now;
    connect_nats(n, err, sizeof(err));
  }
  if (n->conn) {
    int status;
    buckets_buf ignored = BUCKETS_BUF_INIT;
    while (n->conn && read_proto(n, 0, &status, &ignored, err, sizeof(err)) > 0) {
    }
    buckets_buf_free(&ignored);
  }
  if (n->conn && now - n->last_ping >= PING_INTERVAL_S) { /* processPingTimer */
    n->last_ping = now;
    if (++n->pings_out > MAX_PINGS_OUT) drop(n); /* stale connection */
    else write_str(n, "PING\r\n", 6);
  }
  pthread_mutex_unlock(&n->mu);
}

/* IsActive: init, isActive. */
static bool is_active(void *impl, char *err, size_t errlen) {
  nats *n = impl;
  pthread_mutex_lock(&n->mu);
  bool up = init_nats(n, err, errlen) == S_OK && is_active_locked(n, err, errlen) == S_OK;
  pthread_mutex_unlock(&n->mu);
  return up;
}

static void nats_free(void *impl) {
  nats *n = impl;
  if (!n) return;
  drop(n);
  pthread_mutex_destroy(&n->mu);
  free(n->subject), free(n->user), free(n->pass), free(n->token), free(n->seed), free(n->creds);
  free(n->ca), free(n->cert), free(n->key), free(n->ca_dir);
  free(n);
}

static const buckets_target_ops k_ops = {
    .type = "nats", .send = send_event, .free = nats_free, .is_active = is_active, .tick = tick};
const buckets_target_kind buckets_target_nats = {"notify_nats", &k_ops, create};
