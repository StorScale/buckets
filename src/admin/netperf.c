/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The network speedtests, as MinIO runs them:
 *  - mc support perf client: the client streams an endless body to
 *    /speedtest/client/devnull; the server reads (and drops) it and later
 *    tells how long it waited for the test's lock (/devnull/extratime);
 *  - mc support perf net (NetperfHandler, distributed only): every node
 *    streams to every other node's devnull for a duration; each reports what
 *    it sent (TX) and received (RX) per second;
 *  - mc support perf site-replication (SitePerfHandler): the same between
 *    sites, through /site-replication/devnull and /netperf, which MinIO calls
 *    without signing (so they answer unsigned requests while site
 *    replication is on), the latter answering with a gob-encoded
 *    madmin.SiteNetPerfNodeResult.
 * Replaces ClientDevNull, ClientDevNullExtraTime, NetperfHandler,
 * SiteReplicationDevNull, SiteReplicationNetPerf, SitePerfHandler and
 * netperf/siteNetperf (cmd/perf-tests.go). */
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <yyjson.h>

#include "admin/admin.h"
#include "admin/info.h"
#include "admin/jobstream.h"
#include "core/timefmt.h"
#include "core/yaml.h"
#include "crypto/aead.h"
#include "dist/internode.h"
#include "dist/peer.h"
#include "net/client.h"
#include "notify/event.h"
#include "object/nslock.h"
#include "s3/replicate.h"
#include "siterepl/internal.h"
#include "siterepl/siterepl.h"

#define NETPERF_MIN_NS 10000000000LL           /* globalNetPerfMinDuration */
#define CLIENT_PERF_MAX_NS 30000000000LL       /* madmin.MaxClientPerfTimeout */
#define DEVNULL_MAX_BYTES (100ULL << 30)       /* 100 GiB */
#define LOCK_TIMEOUT_MS 10000

static int64_t mono_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void sleep_ns(int64_t ns) {
  struct timespec ts = {ns / 1000000000LL, ns % 1000000000LL};
  nanosleep(&ts, NULL);
}

/* ---- netPerfRX: bytes received between the last peer connecting and the
 * first disconnecting ------------------------------------------------------------------------------------ */

typedef struct {
  pthread_mutex_t mu;
  _Atomic uint64_t rx;
  int64_t last_connect, first_disconnect; /* mono ns, 0 unset */
  uint64_t rx_sample;
  uint64_t active;
} rx_stats;

static rx_stats g_node_rx = {.mu = PTHREAD_MUTEX_INITIALIZER}, g_site_rx = {.mu = PTHREAD_MUTEX_INITIALIZER};

static void rx_connect(rx_stats *r) {
  pthread_mutex_lock(&r->mu);
  r->active++;
  atomic_store(&r->rx, 0);
  r->last_connect = mono_ns();
  pthread_mutex_unlock(&r->mu);
}

static void rx_disconnect(rx_stats *r) {
  pthread_mutex_lock(&r->mu);
  r->active--;
  if (!r->first_disconnect) {
    r->rx_sample = atomic_load(&r->rx);
    r->first_disconnect = mono_ns();
  }
  pthread_mutex_unlock(&r->mu);
}

static uint64_t rx_active(rx_stats *r) {
  pthread_mutex_lock(&r->mu);
  uint64_t a = r->active;
  pthread_mutex_unlock(&r->mu);
  return a;
}

static void rx_reset(rx_stats *r) {
  pthread_mutex_lock(&r->mu);
  atomic_store(&r->rx, 0);
  r->rx_sample = 0;
  r->last_connect = r->first_disconnect = 0;
  pthread_mutex_unlock(&r->mu);
}

/* Reads (and drops) a request body; bytes go to rx when given. Returns the
 * bytes read; *eof tells whether it ended cleanly. */
static uint64_t drain(const buckets_http_request *req, rx_stats *rx, int64_t deadline, uint64_t max, bool *eof) {
  buckets_http_body_cursor cur = {req, 0};
  char *buf = buckets_xmalloc(128 << 10);
  uint64_t total = 0;
  *eof = false;
  for (;;) {
    long n = buckets_http_body_read(&cur, buf, 128 << 10);
    if (n == 0) {
      *eof = true;
      break;
    }
    if (n < 0) break;
    total += (uint64_t)n;
    if (rx) atomic_fetch_add(&rx->rx, (uint64_t)n);
    if ((deadline && mono_ns() > deadline) || total > max) break;
  }
  free(buf);
  return total;
}

/* ---- mc support perf client ---------------------------------------------------------------------------- */

static _Atomic int64_t g_client_extra_ns; /* globalLastClientPerfExtraTime */

void buckets_admin_client_devnull(s3_ctx *c) {
  int64_t t0 = mono_ns();
  if (!buckets_admin_authorize(c, "admin:BandwidthMonitor")) return;
  buckets_nslock_entry *lk = buckets_nslock_lock(c->s->layer->locks, BUCKETS_META_BUCKET, "client-perf", true,
                                                 LOCK_TIMEOUT_MS);
  if (!lk) {
    buckets_admin_error(c, BUCKETS_ERR_REQUEST_TIMEDOUT);
    return;
  }
  atomic_store(&g_client_extra_ns, mono_ns() - t0);
  bool eof;
  drain(c->req, NULL, mono_ns() + CLIENT_PERF_MAX_NS, DEVNULL_MAX_BYTES, &eof);
  buckets_nslock_unlock(lk);
  c->resp->status = 200;
}

void buckets_admin_client_devnull_extratime(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:BandwidthMonitor")) return;
  int64_t t = atomic_load(&g_client_extra_ns);
  buckets_buf_reset(&c->resp->body);
  if (t) buckets_buf_appendf(&c->resp->body, "{\"dur\":%lld}\n", (long long)t);
  else buckets_buf_append_c(&c->resp->body, "{}\n");
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
}

/* ---- mc support perf net --------------------------------------------------------------------------------- */

typedef struct {
  _Atomic uint64_t sent;
  _Atomic bool eof;
  uint8_t *buf; /* 128 KiB of random data, sent over and over */
} tx_src;

static long tx_read(void *ud, void *out, size_t n) {
  tx_src *t = ud;
  if (atomic_load(&t->eof)) return 0;
  size_t k = n < (128 << 10) ? n : (128 << 10);
  memcpy(out, t->buf, k);
  atomic_fetch_add(&t->sent, k);
  return (long)k;
}

typedef struct {
  buckets_http_client *client;
  tx_src *src;
  char err[256];
  const char *peer;
} tx_conn;

static void *tx_conn_run(void *arg) {
  tx_conn *t = arg;
  char auth[96];
  const char *target = BUCKETS_INTERNODE_PREFIX "perf/devnull";
  buckets_internode_sign("POST", target, auth);
  buckets_http_kv h[] = {{BUCKETS_INTERNODE_AUTH, auth}};
  int status = 0;
  buckets_buf hdrs = BUCKETS_BUF_INIT;
  /* a body "as long as" MinIO's limit, cut short when the test ends */
  buckets_http_stream *st = buckets_http_client_open(t->client, "POST", target, h, 1, tx_read, t->src,
                                                     (int64_t)DEVNULL_MAX_BYTES, &status, &hdrs);
  if (st) buckets_http_stream_free(st);
  else if (!atomic_load(&t->src->eof))
    snprintf(t->err, sizeof(t->err), "error with %s: %s", t->peer, buckets_http_client_dial_error(t->client));
  buckets_buf_free(&hdrs);
  return NULL;
}

/* netperf: this node's TX to every peer and RX from them, per second */
static void node_netperf(buckets_s3_server *s, int64_t dur_ns, uint64_t *tx, uint64_t *rx, char *err, size_t errcap) {
  tx_src src = {0};
  src.buf = buckets_xmalloc(128 << 10);
  buckets_random(src.buf, 128 << 10);
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  int per_peer = np > 16 ? 1 : 16;
  size_t nconn = np * (size_t)per_peer;
  tx_conn *conns = buckets_xcalloc(nconn ? nconn : 1, sizeof(*conns));
  pthread_t *th = buckets_xcalloc(nconn ? nconn : 1, sizeof(*th));
  char (*names)[300] = buckets_xcalloc(np ? np : 1, sizeof(*names));
  for (size_t i = 0; i < np; i++) {
    snprintf(names[i], sizeof(names[i]), "%s:%d", buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]));
    for (int k = 0; k < per_peer; k++) {
      tx_conn *t = &conns[i * (size_t)per_peer + (size_t)k];
      /* a connection of its own (the peer's pooled client carries RPC) */
      t->client = buckets_http_client_new(buckets_http_client_host(pcs[i]), buckets_http_client_port(pcs[i]),
                                          s->internode_tls, 10000);
      t->src = &src;
      t->peer = names[i];
      pthread_create(&th[i * (size_t)per_peer + (size_t)k], NULL, tx_conn_run, t);
    }
  }
  sleep_ns(dur_ns);
  atomic_store(&src.eof, true);
  for (size_t i = 0; i < nconn; i++) {
    pthread_join(th[i], NULL);
    if (*conns[i].err && !*err) snprintf(err, errcap, "%s", conns[i].err);
    buckets_http_client_free(conns[i].client);
  }
  for (int i = 0; i < 60 && rx_active(&g_node_rx); i++) sleep_ns(1000000000LL);
  pthread_mutex_lock(&g_node_rx.mu);
  double sample = (double)g_node_rx.rx_sample;
  int64_t delta = g_node_rx.first_disconnect - g_node_rx.last_connect;
  pthread_mutex_unlock(&g_node_rx.mu);
  if (delta < 0 || (!g_node_rx.first_disconnect && np)) {
    sample = 0;
    snprintf(err, errcap, "%s", "network disconnection issues detected");
  }
  rx_reset(&g_node_rx);
  uint64_t secs = (uint64_t)(dur_ns / 1000000000LL);
  *tx = atomic_load(&src.sent) / (secs ? secs : 1);
  *rx = delta > 0 ? (uint64_t)(sample / ((double)delta / 1e9)) : 0;
  free(conns);
  free(th);
  free(names);
  free(src.buf);
}

static const char *scheme_of(const buckets_s3_server *s) { return s->cluster && s->cluster->secure ? "https" : "http"; }

static void node_result_json(buckets_buf *b, const char *endpoint, uint64_t tx, uint64_t rx, const char *err) {
  buckets_buf_append_c(b, "{\"endpoint\":");
  buckets_json_go_string(b, endpoint, strlen(endpoint));
  buckets_buf_appendf(b, ",\"tx\":%llu,\"rx\":%llu", (unsigned long long)tx, (unsigned long long)rx);
  if (err && *err) {
    buckets_buf_append_c(b, ",\"error\":");
    buckets_json_go_string(b, err, strlen(err));
  }
  buckets_buf_append_char(b, '}');
}

typedef struct {
  buckets_s3_server *s;
  char node[300];
  int64_t dur_ns;
  buckets_buf out; /* its NetperfNodeResult JSON */
} netperf_peer;

static void *netperf_peer_run(void *arg) {
  netperf_peer *p = arg;
  char target[256];
  snprintf(target, sizeof(target), BUCKETS_INTERNODE_PREFIX "peer/admin?op=netperf&duration=%lld", (long long)p->dur_ns);
  int status = 0;
  buckets_buf body = BUCKETS_BUF_INIT;
  bool ok = buckets_peer_call(p->s->peers, p->node, target, &status, &body) && status == 200;
  const char *j = body.data ? body.data : "";
  size_t n = body.len;
  while (n && (*j == ' ' || *j == '\n')) j++, n--;
  yyjson_doc *d = ok ? yyjson_read(j, n, 0) : NULL;
  yyjson_val *o = yyjson_doc_get_root(d);
  char ep[320];
  snprintf(ep, sizeof(ep), "%s://%s", scheme_of(p->s), p->node);
  if (yyjson_is_obj(o)) {
    const char *e = yyjson_get_str(yyjson_obj_get(o, "error"));
    node_result_json(&p->out, ep, yyjson_get_uint(yyjson_obj_get(o, "tx")), yyjson_get_uint(yyjson_obj_get(o, "rx")), e);
  } else {
    node_result_json(&p->out, ep, 0, 0, "peer not reachable");
  }
  yyjson_doc_free(d);
  buckets_buf_free(&body);
  return NULL;
}

void buckets_admin_netperf(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:OBDInfo")) return;
  buckets_s3_server *s = c->s;
  if (!s->cluster || !s->cluster->distributed) {
    buckets_admin_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
    return;
  }
  buckets_nslock_entry *lk = buckets_nslock_lock(s->layer->locks, BUCKETS_META_BUCKET, "netperf", true, LOCK_TIMEOUT_MS);
  if (!lk) {
    buckets_admin_error(c, BUCKETS_ERR_REQUEST_TIMEDOUT);
    return;
  }
  buckets_s3_service(s, "freeze", true);
  int64_t dur = 0;
  const char *ds = buckets_query_get(&c->q, "duration");
  if (!ds || !buckets_go_duration_parse(ds, &dur) || dur < NETPERF_MIN_NS) dur = NETPERF_MIN_NS;
  dur = (dur + 500000000LL) / 1000000000LL * 1000000000LL; /* Round(time.Second) */
  /* NotificationSys.Netperf: every peer and this node at once */
  size_t np = 0;
  buckets_http_client *const *pcs = buckets_peer_clients(s->peers, &np);
  netperf_peer *peers = buckets_xcalloc(np ? np : 1, sizeof(*peers));
  pthread_t *th = buckets_xcalloc(np ? np : 1, sizeof(*th));
  for (size_t i = 0; i < np; i++) {
    peers[i].s = s;
    peers[i].dur_ns = dur;
    snprintf(peers[i].node, sizeof(peers[i].node), "%s:%d", buckets_http_client_host(pcs[i]),
             buckets_http_client_port(pcs[i]));
    pthread_create(&th[i], NULL, netperf_peer_run, &peers[i]);
  }
  uint64_t tx = 0, rx = 0;
  char err[512] = "";
  node_netperf(s, dur, &tx, &rx, err, sizeof(err));
  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  buckets_buf_append_c(b, "{\"nodeResults\":[");
  for (size_t i = 0; i < np; i++) {
    pthread_join(th[i], NULL);
    buckets_buf_append(b, peers[i].out.data, peers[i].out.len);
    buckets_buf_append_char(b, ',');
    buckets_buf_free(&peers[i].out);
  }
  char ep[320];
  snprintf(ep, sizeof(ep), "%s://%s", scheme_of(s), s->cluster->self);
  node_result_json(b, ep, tx, rx, err);
  buckets_buf_append_c(b, "]}\n");
  free(peers);
  free(th);
  buckets_s3_service(s, "unfreeze", true);
  buckets_nslock_unlock(lk);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
}

/* ---- the peer side --------------------------------------------------------------------------------------- */

typedef struct {
  buckets_s3_server *s;
  int64_t dur_ns;
} np_job;

static void np_job_run(buckets_jobstream *j, void *ud) {
  np_job *n = ud;
  uint64_t tx = 0, rx = 0;
  char err[512] = "";
  node_netperf(n->s, n->dur_ns, &tx, &rx, err, sizeof(err));
  buckets_buf b = BUCKETS_BUF_INIT;
  node_result_json(&b, "", tx, rx, err);
  buckets_jobstream_emit(j, b.data, b.len);
  buckets_buf_free(&b);
}

/* A peer's netperf stream (its own route and workers: each holds one for
 * the whole test). */
void buckets_admin_internode_devnull(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  (void)ud;
  if (!buckets_internode_verify(req)) {
    resp->status = 403;
    return;
  }
  rx_connect(&g_node_rx);
  bool eof;
  drain(req, &g_node_rx, 0, DEVNULL_MAX_BYTES, &eof);
  rx_disconnect(&g_node_rx);
  resp->status = 200;
}

bool buckets_admin_netperf_peer(buckets_s3_server *s, const char *op, const buckets_http_request *req,
                                const buckets_query *q, buckets_http_response *resp) {
  (void)req;
  if (strcmp(op, "netperf") == 0) {
    np_job *n = buckets_xcalloc(1, sizeof(*n));
    n->s = s;
    const char *d = buckets_query_get(q, "duration");
    n->dur_ns = d ? strtoll(d, NULL, 10) : NETPERF_MIN_NS;
    if (n->dur_ns < 1000000000LL) n->dur_ns = NETPERF_MIN_NS;
    buckets_jobstream_start(resp, np_job_run, n, free, 1000, " ");
    return true;
  }
  return false;
}

/* ---- site replication ------------------------------------------------------------------------------------ */

/* gob: madmin.SiteNetPerfNodeResult (the type's definition, then the value) */
static const uint8_t k_gob_type[] = {
    0x7d, 0x7f, 0x03, 0x01, 0x01, 0x15, 'S', 'i', 't', 'e', 'N', 'e', 't', 'P', 'e', 'r', 'f', 'N', 'o', 'd', 'e', 'R',
    'e', 's', 'u', 'l', 't', 0x01, 0xff, 0x80, 0x00, 0x01, 0x07, 0x01, 0x08, 'E', 'n', 'd', 'p', 'o', 'i', 'n', 't',
    0x01, 0x0c, 0x00, 0x01, 0x02, 'T', 'X', 0x01, 0x06, 0x00, 0x01, 0x0f, 'T', 'X', 'T', 'o', 't', 'a', 'l', 'D', 'u',
    'r', 'a', 't', 'i', 'o', 'n', 0x01, 0x04, 0x00, 0x01, 0x02, 'R', 'X', 0x01, 0x06, 0x00, 0x01, 0x0f, 'R', 'X', 'T',
    'o', 't', 'a', 'l', 'D', 'u', 'r', 'a', 't', 'i', 'o', 'n', 0x01, 0x04, 0x00, 0x01, 0x09, 'T', 'o', 't', 'a', 'l',
    'C', 'o', 'n', 'n', 0x01, 0x06, 0x00, 0x01, 0x05, 'E', 'r', 'r', 'o', 'r', 0x01, 0x0c, 0x00, 0x00, 0x00};

typedef struct {
  char endpoint[512];
  uint64_t tx, rx, conns;
  int64_t tx_dur, rx_dur;
  char error[512];
} site_result;

static void gob_uint(buckets_buf *b, uint64_t v) {
  if (v < 128) {
    buckets_buf_append_char(b, (char)v);
    return;
  }
  uint8_t tmp[8];
  int n = 0;
  while (v) tmp[n++] = (uint8_t)v, v >>= 8;
  buckets_buf_append_char(b, (char)(uint8_t)(256 - n));
  for (int i = n - 1; i >= 0; i--) buckets_buf_append_char(b, (char)tmp[i]);
}

static void gob_int(buckets_buf *b, int64_t v) {
  uint64_t u = v < 0 ? ~((uint64_t)v << 1) : (uint64_t)v << 1;
  gob_uint(b, u);
}

static void gob_encode(const site_result *r, buckets_buf *out) {
  buckets_buf m = BUCKETS_BUF_INIT;
  gob_int(&m, 64); /* the type's id */
  int last = -1;
  struct {
    int field;
    int kind; /* 0 string, 1 uint, 2 int */
    const char *s;
    uint64_t u;
    int64_t i;
  } f[] = {{0, 0, r->endpoint, 0, 0}, {1, 1, NULL, r->tx, 0},    {2, 2, NULL, 0, r->tx_dur}, {3, 1, NULL, r->rx, 0},
           {4, 2, NULL, 0, r->rx_dur}, {5, 1, NULL, r->conns, 0}, {6, 0, r->error, 0, 0}};
  for (size_t k = 0; k < BUCKETS_ARRAY_LEN(f); k++) {
    bool zero = f[k].kind == 0 ? !*f[k].s : f[k].kind == 1 ? !f[k].u : !f[k].i; /* zero values are left out */
    if (zero) continue;
    gob_uint(&m, (uint64_t)(f[k].field - last));
    last = f[k].field;
    if (f[k].kind == 0) {
      gob_uint(&m, strlen(f[k].s));
      buckets_buf_append_c(&m, f[k].s);
    } else if (f[k].kind == 1) {
      gob_uint(&m, f[k].u);
    } else {
      gob_int(&m, f[k].i);
    }
  }
  buckets_buf_append_char(&m, 0);
  buckets_buf_append(out, k_gob_type, sizeof(k_gob_type));
  gob_uint(out, m.len);
  buckets_buf_append(out, m.data, m.len);
  buckets_buf_free(&m);
}

static bool gob_read_uint(const uint8_t **p, const uint8_t *end, uint64_t *v) {
  if (*p >= end) return false;
  uint8_t c = *(*p)++;
  if (c < 128) {
    *v = c;
    return true;
  }
  int n = 256 - c;
  if (n > 8 || end - *p < n) return false;
  *v = 0;
  for (int i = 0; i < n; i++) *v = *v << 8 | *(*p)++;
  return true;
}

static bool gob_read_int(const uint8_t **p, const uint8_t *end, int64_t *v) {
  uint64_t u;
  if (!gob_read_uint(p, end, &u)) return false;
  *v = u & 1 ? (int64_t)~(u >> 1) : (int64_t)(u >> 1);
  return true;
}

/* gob.Decoder.Decode into the result: type definitions are skipped, the
 * value's fields read by number. err gets Go's words on failure. */
static bool gob_decode(const uint8_t *data, size_t n, site_result *r, char *err, size_t errcap) {
  const uint8_t *p = data, *end = data + n;
  if (!n) {
    snprintf(err, errcap, "%s", "EOF");
    return false;
  }
  while (p < end) {
    uint64_t len;
    if (!gob_read_uint(&p, end, &len) || (uint64_t)(end - p) < len) {
      snprintf(err, errcap, "%s", "unexpected EOF");
      return false;
    }
    const uint8_t *m = p, *mend = p + len;
    p = mend;
    int64_t id;
    if (!gob_read_int(&m, mend, &id)) break;
    if (id < 0) continue; /* a type definition */
    int64_t field = -1;
    for (;;) {
      uint64_t delta;
      if (!gob_read_uint(&m, mend, &delta) || !delta) break;
      field += (int64_t)delta;
      uint64_t u;
      int64_t i;
      switch (field) {
      case 0:
      case 6: {
        if (!gob_read_uint(&m, mend, &u) || (uint64_t)(mend - m) < u) return false;
        char *dst = field == 0 ? r->endpoint : r->error;
        size_t cap = field == 0 ? sizeof(r->endpoint) : sizeof(r->error);
        snprintf(dst, cap, "%.*s", (int)u, (const char *)m);
        m += u;
        break;
      }
      case 1: if (!gob_read_uint(&m, mend, &r->tx)) return false; break;
      case 2: if (!gob_read_int(&m, mend, &r->tx_dur)) return false; break;
      case 3: if (!gob_read_uint(&m, mend, &r->rx)) return false; break;
      case 4: if (!gob_read_int(&m, mend, &r->rx_dur)) return false; break;
      case 5: if (!gob_read_uint(&m, mend, &r->conns)) return false; break;
      default: (void)i; return false;
      }
    }
    return true;
  }
  snprintf(err, errcap, "%s", "EOF");
  return false;
}

static void site_result_json(buckets_buf *b, const site_result *r) {
  buckets_buf_append_c(b, "{\"endpoint\":");
  buckets_json_go_string(b, r->endpoint, strlen(r->endpoint));
  buckets_buf_appendf(b, ",\"tx\":%llu,\"txTotalDuration\":%lld,\"rx\":%llu,\"rxTotalDuration\":%lld,\"totalConn\":%llu",
                      (unsigned long long)r->tx, (long long)r->tx_dur, (unsigned long long)r->rx, (long long)r->rx_dur,
                      (unsigned long long)r->conns);
  if (*r->error) {
    buckets_buf_append_c(b, ",\"error\":");
    buckets_json_go_string(b, r->error, strlen(r->error));
  }
  buckets_buf_append_char(b, '}');
}

/* A site's endpoint as host, port and scheme. */
static bool site_addr(const char *ep, char *host, size_t cap, int *port, bool *secure) {
  const char *p = ep;
  *secure = strncmp(p, "https://", 8) == 0;
  if (*secure) p += 8;
  else if (strncmp(p, "http://", 7) == 0) p += 7;
  else return false;
  size_t n = strcspn(p, "/");
  if (!n || n >= cap) return false;
  memcpy(host, p, n);
  host[n] = '\0';
  char *colon = strrchr(host, ':');
  *port = *secure ? 443 : 80;
  if (colon && !strchr(colon, ']')) {
    *port = atoi(colon + 1);
    *colon = '\0';
  }
  return true;
}

typedef struct {
  buckets_s3_server *s;
  char endpoint[512];
  const char *path;
  tx_src *src; /* NULL: no body (the netperf call) */
  int64_t timeout_ns;
  site_result res;
} site_call;

/* perfNetRequest: an unsigned POST to the site; its answer gob-decoded */
static void *site_call_run(void *arg) {
  site_call *sc = arg;
  char host[300];
  int port;
  bool secure;
  snprintf(sc->res.endpoint, sizeof(sc->res.endpoint), "%s", sc->endpoint);
  if (!site_addr(sc->endpoint, host, sizeof(host), &port, &secure)) {
    snprintf(sc->res.error, sizeof(sc->res.error), "invalid endpoint %s", sc->endpoint);
    return NULL;
  }
  buckets_http_client *cl = buckets_http_client_new(host, port, secure && sc->s->repl ? buckets_repl_tls(sc->s->repl) : NULL,
                                                    (int)(sc->timeout_ns / 1000000));
  int status = 0;
  buckets_buf hdrs = BUCKETS_BUF_INIT, body = BUCKETS_BUF_INIT;
  buckets_http_stream *st = buckets_http_client_open(cl, "POST", sc->path, NULL, 0, sc->src ? tx_read : NULL, sc->src,
                                                     sc->src ? (int64_t)DEVNULL_MAX_BYTES : 0, &status, &hdrs);
  if (st) {
    char buf[4096];
    long n;
    while ((n = buckets_http_stream_read(st, buf, sizeof(buf))) > 0) buckets_buf_append(&body, buf, (size_t)n);
    buckets_http_stream_free(st);
    char err[128];
    if (!gob_decode((const uint8_t *)(body.data ? body.data : ""), body.len, &sc->res, err, sizeof(err)))
      snprintf(sc->res.error, sizeof(sc->res.error), "%s", err);
  } else if (!sc->src || !atomic_load(&sc->src->eof)) {
    snprintf(sc->res.error, sizeof(sc->res.error), "%s", buckets_http_client_dial_error(cl));
  } else {
    snprintf(sc->res.error, sizeof(sc->res.error), "%s", "EOF");
  }
  snprintf(sc->res.endpoint, sizeof(sc->res.endpoint), "%s", sc->endpoint); /* overwritten, as MinIO does */
  buckets_buf_free(&hdrs);
  buckets_buf_free(&body);
  buckets_http_client_free(cl);
  return NULL;
}

/* siteNetperf: this site streams to every other site's devnull */
static void site_netperf(buckets_s3_server *s, int64_t dur_ns, site_result *out) {
  memset(out, 0, sizeof(*out));
  sr_snapshot snap;
  sr_snapshot_take(s->sr, &snap);
  if (!snap.enabled || !snap.npeers) {
    sr_snapshot_free(&snap);
    return;
  }
  tx_src src = {0};
  src.buf = buckets_xmalloc(128 << 10);
  buckets_random(src.buf, 128 << 10);
  size_t per = 3 + (29 + snap.npeers - 1) / snap.npeers;
  const char *self = s->layer ? s->layer->deployment_id_str : "";
  size_t ncalls = 0;
  site_call *calls = buckets_xcalloc(snap.npeers * per + 1, sizeof(*calls));
  pthread_t *th = buckets_xcalloc(snap.npeers * per + 1, sizeof(*th));
  for (size_t i = 0; i < snap.npeers; i++) {
    if (strcmp(snap.peers[i].deployment_id, self) == 0) continue;
    for (size_t k = 0; k < per; k++) {
      site_call *sc = &calls[ncalls];
      sc->s = s;
      snprintf(sc->endpoint, sizeof(sc->endpoint), "%s", snap.peers[i].endpoint);
      sc->path = "/minio/admin/v3/site-replication/devnull";
      sc->src = &src;
      sc->timeout_ns = dur_ns + 10000000000LL;
      pthread_create(&th[ncalls], NULL, site_call_run, sc);
      ncalls++;
    }
  }
  sleep_ns(dur_ns);
  atomic_store(&src.eof, true);
  for (size_t i = 0; i < ncalls; i++) pthread_join(th[i], NULL);
  for (int i = 0; i < 60 && rx_active(&g_site_rx); i++) sleep_ns(1000000000LL);
  pthread_mutex_lock(&g_site_rx.mu);
  double rx = (double)g_site_rx.rx_sample;
  int64_t delta = g_site_rx.first_disconnect - g_site_rx.last_connect;
  pthread_mutex_unlock(&g_site_rx.mu);
  if (delta <= 0) {
    rx = 0;
    snprintf(out->error, sizeof(out->error), "%s", "detected network disconnections, possibly an unstable network");
  }
  rx_reset(&g_site_rx);
  out->tx = atomic_load(&src.sent);
  out->tx_dur = dur_ns;
  out->rx = (uint64_t)rx;
  out->rx_dur = delta;
  out->conns = per;
  free(calls);
  free(th);
  free(src.buf);
  sr_snapshot_free(&snap);
}

/* Unsigned site-replication requests are served only while site
 * replication is on (MinIO serves them always). */
bool buckets_admin_site_perf_unsigned(buckets_s3_server *s, buckets_str path) {
  return buckets_sr_enabled(s->sr) && (buckets_str_eq_c(path, "/minio/admin/v3/site-replication/devnull") ||
                                       buckets_str_eq_c(path, "/minio/admin/v3/site-replication/netperf"));
}

void buckets_admin_sr_devnull(s3_ctx *c) {
  rx_connect(&g_site_rx);
  bool eof;
  drain(c->req, &g_site_rx, 0, UINT64_MAX, &eof);
  rx_disconnect(&g_site_rx);
  c->resp->status = eof ? 204 : 400;
}

void buckets_admin_sr_netperf(s3_ctx *c) {
  int64_t dur = 0;
  const char *ds = buckets_query_get(&c->q, "duration");
  if (!ds || !buckets_go_duration_parse(ds, &dur) || dur < NETPERF_MIN_NS) dur = NETPERF_MIN_NS;
  site_result r;
  site_netperf(c->s, dur, &r);
  buckets_buf_reset(&c->resp->body);
  gob_encode(&r, &c->resp->body);
  c->resp->status = 200;
}

void buckets_admin_site_perf(s3_ctx *c) {
  if (!buckets_admin_authorize(c, "admin:OBDInfo")) return;
  buckets_s3_server *s = c->s;
  if (!buckets_sr_enabled(s->sr)) {
    buckets_admin_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
    return;
  }
  buckets_nslock_entry *lk = buckets_nslock_lock(s->layer->locks, BUCKETS_META_BUCKET, "site-net-perf", true,
                                                 LOCK_TIMEOUT_MS);
  if (!lk) {
    buckets_admin_error(c, BUCKETS_ERR_REQUEST_TIMEDOUT);
    return;
  }
  int64_t dur = 0;
  const char *ds = buckets_query_get(&c->q, "duration");
  if (!ds || !buckets_go_duration_parse(ds, &dur) || dur < NETPERF_MIN_NS) dur = NETPERF_MIN_NS;
  dur = (dur + 500000000LL) / 1000000000LL * 1000000000LL;
  /* SiteReplicationSys.Netperf: this site's own test, and every other
   * site's through its /site-replication/netperf */
  sr_snapshot snap;
  sr_snapshot_take(s->sr, &snap);
  const char *self = s->layer ? s->layer->deployment_id_str : "";
  site_call *calls = buckets_xcalloc(snap.npeers + 1, sizeof(*calls));
  pthread_t *th = buckets_xcalloc(snap.npeers + 1, sizeof(*th));
  size_t ncalls = 0;
  char self_ep[512] = "";
  for (size_t i = 0; i < snap.npeers; i++) {
    if (strcmp(snap.peers[i].deployment_id, self) == 0) {
      snprintf(self_ep, sizeof(self_ep), "%s", snap.peers[i].endpoint);
      continue;
    }
    site_call *sc = &calls[ncalls];
    sc->s = s;
    snprintf(sc->endpoint, sizeof(sc->endpoint), "%s", snap.peers[i].endpoint);
    sc->path = "/minio/admin/v3/site-replication/netperf";
    sc->timeout_ns = dur + 10000000000LL;
    pthread_create(&th[ncalls], NULL, site_call_run, sc);
    ncalls++;
  }
  site_result mine;
  site_netperf(s, dur, &mine);
  snprintf(mine.endpoint, sizeof(mine.endpoint), "%s", self_ep);
  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  buckets_buf_append_c(b, "{\"nodeResults\":[");
  site_result_json(b, &mine);
  for (size_t i = 0; i < ncalls; i++) {
    pthread_join(th[i], NULL);
    buckets_buf_append_char(b, ',');
    site_result_json(b, &calls[i].res);
  }
  buckets_buf_append_c(b, "]}\n");
  free(calls);
  free(th);
  sr_snapshot_free(&snap);
  buckets_nslock_unlock(lk);
  c->resp->status = 200;
  buckets_http_resp_header(c->resp, "Content-Type", "text/plain; charset=utf-8");
}
