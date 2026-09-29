/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Redis target (MinIO internal/event/target/redis.go): in namespace
 * format HSET <key> <bucket/object> {"Records":[event]} (HDEL for
 * s3:ObjectRemoved:Delete), in access format RPUSH <key>
 * [{"Event":[event],"EventTime":...}]. The key's type is checked once (a
 * hash for namespace, a list for access). Connections come from a pool that
 * behaves as MinIO's redigo pool does, so the commands on the wire are the
 * same: most recently used first, a PING before an idle connection is
 * reused (TestOnBorrow), at most 3 idle, none idle for 2 minutes; new ones
 * AUTH and then name themselves. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/common.h"
#include "core/log.h"
#include "net/conn.h"
#include "notify/targets.h"
#include "notify/xnet.h"

#define IDLE_TIMEOUT_S 120 /* redis.Pool IdleTimeout */
#define MAX_IDLE 3        /* redis.Pool MaxIdle */

typedef struct {
  buckets_conn *c;
  time_t t; /* when it was returned */
} idle_conn;
#define DIAL_TIMEOUT_MS 10000

typedef struct {
  char *key, *password, *user;
  bool access; /* format access (else namespace) */
  buckets_xnet_host addr;
  pthread_mutex_t mu;
  idle_conn idle[MAX_IDLE]; /* redis.Pool's idle list, most recently returned first */
  size_t nidle;
  bool initialized; /* initRedis succeeded */
  bool first_ping;  /* the key's type was checked (SendFromStore) */
} redis;

typedef enum { R_OK, R_CONN, R_REPLY_ERR } rstatus;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_redis", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  (void)ca_file;
  char *addr = get(cfg, target, "address"), *qlim = get(cfg, target, "queue_limit"), *fmt = get(cfg, target, "format");
  char *key = get(cfg, target, "key"), *qdir = get(cfg, target, "queue_dir");
  char *pass = get(cfg, target, "password"), *user = get(cfg, target, "user");
  buckets_xnet_host h;
  bool ok = buckets_xnet_parse_host(addr, &h, err, errlen);
  char *end;
  if (ok) {
    strtol(qlim, &end, 10);
    if (!*qlim || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qlim);
      ok = false;
    }
  }
  if (ok && *fmt && strcasecmp(fmt, "namespace") != 0 && strcasecmp(fmt, "access") != 0) {
    snprintf(err, errlen, "unrecognized format");
    ok = false;
  } else if (ok && !*key) {
    snprintf(err, errlen, "empty key");
    ok = false;
  } else if (ok && *qdir && *qdir != '/') {
    snprintf(err, errlen, "queueDir path should be absolute");
    ok = false;
  }
  if (ok && impl) {
    redis *r = buckets_xcalloc(1, sizeof(*r));
    r->key = key, r->password = pass, r->user = user, key = pass = user = NULL;
    r->access = strcmp(fmt, "access") == 0; /* RedisArgs.Format as given: "ACCESS" is neither */
    r->addr = h;
    pthread_mutex_init(&r->mu, NULL);
    *impl = r;
  }
  free(addr), free(qlim), free(fmt), free(key), free(qdir), free(pass), free(user);
  return ok;
}

/* ---- RESP ---- */

static void command(buckets_buf *b, size_t argc, const char *const *argv, const size_t *lens) {
  buckets_buf_appendf(b, "*%zu\r\n", argc);
  for (size_t i = 0; i < argc; i++) {
    size_t n = lens ? lens[i] : strlen(argv[i]);
    buckets_buf_appendf(b, "$%zu\r\n", n);
    buckets_buf_append(b, argv[i], n);
    buckets_buf_append_c(b, "\r\n");
  }
}

/* Reads one reply; simple strings and bulk strings land in out (when not
 * NULL), errors in err. Nested arrays are read and dropped. */
static rstatus read_reply(buckets_conn *c, buckets_buf *out, char *err, size_t errlen) {
  buckets_buf line = BUCKETS_BUF_INIT;
  rstatus st = R_OK;
  if (!buckets_conn_read_line(c, &line) || !line.len) {
    snprintf(err, errlen, "EOF");
    buckets_buf_free(&line);
    return R_CONN;
  }
  char t = line.data[0];
  const char *rest = line.data + 1;
  if (t == '+') {
    if (out) buckets_buf_append_c(out, rest);
  } else if (t == '-') {
    snprintf(err, errlen, "%s", rest);
    st = R_REPLY_ERR;
  } else if (t == ':') {
    if (out) buckets_buf_append_c(out, rest);
  } else if (t == '$') {
    long n = strtol(rest, NULL, 10);
    if (n >= 0) {
      char *data = buckets_xmalloc((size_t)n + 2);
      if (!buckets_conn_read_full(c, data, (size_t)n + 2)) st = R_CONN;
      else if (out) buckets_buf_append(out, data, (size_t)n);
      free(data);
    }
  } else if (t == '*') {
    long n = strtol(rest, NULL, 10);
    for (long i = 0; i < n && st != R_CONN; i++) {
      rstatus s = read_reply(c, NULL, err, errlen);
      if (s != R_OK) st = s;
    }
  } else {
    snprintf(err, errlen, "redigo: unexpected response line (possible server error or unsupported concurrent read by application)");
    st = R_CONN;
  }
  buckets_buf_free(&line);
  return st;
}

static rstatus roundtrip(buckets_conn *c, size_t argc, const char *const *argv, const size_t *lens, buckets_buf *out,
                         char *err, size_t errlen) {
  buckets_buf b = BUCKETS_BUF_INIT;
  command(&b, argc, argv, lens);
  bool sent = buckets_conn_write(c, b.data, b.len);
  buckets_buf_free(&b);
  if (!sent) {
    snprintf(err, errlen, "write: broken pipe");
    return R_CONN;
  }
  return read_reply(c, out, err, errlen);
}

static buckets_conn *dial(redis *r, char *err, size_t errlen) {
  buckets_conn *c = buckets_conn_dial(r->addr.name, r->addr.port, NULL, DIAL_TIMEOUT_MS, err, errlen);
  if (!c) return NULL;
  rstatus st = R_OK;
  if (*r->password) {
    const char *a3[] = {"AUTH", r->user, r->password}, *a2[] = {"AUTH", r->password};
    st = *r->user ? roundtrip(c, 3, a3, NULL, NULL, err, errlen) : roundtrip(c, 2, a2, NULL, NULL, err, errlen);
  }
  if (st == R_OK) { /* after AUTH */
    const char *a[] = {"CLIENT", "SETNAME", "Buckets"};
    st = roundtrip(c, 3, a, NULL, NULL, err, errlen);
  }
  if (st != R_OK) {
    buckets_conn_close(c);
    return NULL;
  }
  return c;
}

/* redis.Pool.Get: stale idle connections are pruned from the back; the
 * front one is taken if it answers a PING (TestOnBorrow), else a new one is
 * dialed (AUTH, then CLIENT SETNAME). */
static buckets_conn *pool_get(redis *r, char *err, size_t errlen) {
  time_t now = time(NULL);
  while (r->nidle && now - r->idle[r->nidle - 1].t >= IDLE_TIMEOUT_S) buckets_conn_close(r->idle[--r->nidle].c);
  while (r->nidle) {
    buckets_conn *c = r->idle[0].c;
    memmove(r->idle, r->idle + 1, --r->nidle * sizeof(idle_conn));
    const char *a[] = {"PING"};
    char perr[256];
    if (roundtrip(c, 1, a, NULL, NULL, perr, sizeof(perr)) == R_OK) return c;
    buckets_conn_close(c);
  }
  return dial(r, err, errlen);
}

/* Conn.Close on a pooled connection: back to the front of the idle list
 * (the oldest beyond MaxIdle is closed), or closed when it failed. */
static void pool_put(redis *r, buckets_conn *c, bool broken) {
  if (!c) return;
  if (broken) {
    buckets_conn_close(c);
    return;
  }
  if (r->nidle == MAX_IDLE) buckets_conn_close(r->idle[--r->nidle].c);
  memmove(r->idle + 1, r->idle, r->nidle * sizeof(idle_conn));
  r->idle[0] = (idle_conn){c, time(NULL)};
  r->nidle++;
}

/* One command on a pooled connection: Get, Do, Close. */
static rstatus pooled(redis *r, size_t argc, const char *const *argv, const size_t *lens, buckets_buf *out, char *err,
                      size_t errlen) {
  buckets_conn *c = pool_get(r, err, errlen);
  if (!c) return R_CONN;
  rstatus st = roundtrip(c, argc, argv, lens, out, err, errlen);
  pool_put(r, c, st == R_CONN);
  return st;
}

/* isActive: PING on a pooled connection. */
static rstatus ping(redis *r, char *err, size_t errlen) {
  const char *a[] = {"PING"};
  return pooled(r, 1, a, NULL, NULL, err, errlen);
}

/* validateFormat on c: the key is absent, or of the format's type. */
static rstatus validate_format(redis *r, buckets_conn *c, char *err, size_t errlen) {
  const char *a[] = {"TYPE", r->key};
  buckets_buf t = BUCKETS_BUF_INIT;
  rstatus st = roundtrip(c, 2, a, NULL, &t, err, errlen);
  if (st == R_OK && t.len && strcmp(t.data, "none") != 0) {
    const char *want = r->access ? "list" : "hash";
    if (strcmp(t.data, want) != 0) {
      snprintf(err, errlen, "expected type %s does not match with available type %s", want, t.data);
      st = R_REPLY_ERR;
    }
  }
  buckets_buf_free(&t);
  return st;
}

/* init (initRedis, until it succeeds): PING and validateFormat on one
 * connection, then isActive on another while the first is held. */
static rstatus init_redis(redis *r, char *err, size_t errlen) {
  if (r->initialized) return R_OK;
  buckets_conn *c = pool_get(r, err, errlen);
  if (!c) return R_CONN;
  const char *a[] = {"PING"};
  rstatus st = roundtrip(c, 1, a, NULL, NULL, err, errlen);
  if (st == R_OK) st = validate_format(r, c, err, errlen);
  if (st == R_OK) {
    r->first_ping = true;
    st = ping(r, err, errlen);
  }
  pool_put(r, c, st == R_CONN);
  if (st == R_OK) r->initialized = true;
  return st;
}

static buckets_send_result result(rstatus st) {
  return st == R_OK ? BUCKETS_SEND_OK : st == R_CONN ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
}

/* send: HSET/HDEL or RPUSH on a pooled connection. */
static rstatus send_record(redis *r, const char *record, size_t n, const char *event_name, const char *key, char *err,
                           size_t errlen) {
  buckets_buf v = BUCKETS_BUF_INIT;
  rstatus st;
  if (!r->access) {
    if (strcmp(event_name, "s3:ObjectRemoved:Delete") == 0) {
      const char *a[] = {"HDEL", r->key, key};
      st = pooled(r, 3, a, NULL, NULL, err, errlen);
    } else {
      buckets_buf_append_c(&v, "{\"Records\":[");
      buckets_buf_append(&v, record, n);
      buckets_buf_append_c(&v, "]}");
      const char *a[] = {"HSET", r->key, key, v.data};
      size_t l[] = {4, strlen(r->key), strlen(key), v.len};
      st = pooled(r, 4, a, l, NULL, err, errlen);
    }
  } else {
    /* []RedisAccessEvent{{Event: []event.Event{e}, EventTime: e.EventTime}} */
    yyjson_doc *doc = yyjson_read(record, n, 0);
    const char *when = doc ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "eventTime")) : NULL;
    buckets_buf_append_c(&v, "[{\"Event\":[");
    buckets_buf_append(&v, record, n);
    buckets_buf_append_c(&v, "],\"EventTime\":\"");
    buckets_buf_append_c(&v, when ? when : "");
    buckets_buf_append_c(&v, "\"}]");
    yyjson_doc_free(doc);
    const char *a[] = {"RPUSH", r->key, v.data};
    size_t l[] = {5, strlen(r->key), v.len};
    st = pooled(r, 3, a, l, NULL, err, errlen);
  }
  buckets_buf_free(&v);
  return st;
}

/* Save (no store): init, isActive, send. */
static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  redis *r = impl;
  pthread_mutex_lock(&r->mu);
  rstatus st = init_redis(r, err, errlen);
  if (st == R_OK) st = ping(r, err, errlen);
  if (st == R_OK) st = send_record(r, record, n, event_name, key, err, errlen);
  pthread_mutex_unlock(&r->mu);
  return result(st);
}

/* SendFromStore: init, then PING (and validateFormat until done) on a
 * connection held while the event is sent on another. */
static buckets_send_result send_from_store(void *impl, const char *record, size_t n, const char *event_name,
                                           const char *key, char *err, size_t errlen) {
  redis *r = impl;
  pthread_mutex_lock(&r->mu);
  rstatus st = init_redis(r, err, errlen);
  buckets_conn *c = NULL;
  if (st == R_OK) {
    c = pool_get(r, err, errlen);
    if (!c) st = R_CONN;
  }
  if (st == R_OK) {
    const char *a[] = {"PING"};
    st = roundtrip(c, 1, a, NULL, NULL, err, errlen);
  }
  if (st == R_OK && !r->first_ping) {
    st = validate_format(r, c, err, errlen);
    if (st == R_OK) r->first_ping = true;
  }
  if (st == R_OK) st = send_record(r, record, n, event_name, key, err, errlen);
  pool_put(r, c, st == R_CONN && c);
  pthread_mutex_unlock(&r->mu);
  return result(st);
}

/* IsActive: init, isActive. */
static bool is_active(void *impl, char *err, size_t errlen) {
  redis *r = impl;
  pthread_mutex_lock(&r->mu);
  bool up = init_redis(r, err, errlen) == R_OK && ping(r, err, errlen) == R_OK;
  pthread_mutex_unlock(&r->mu);
  return up;
}

static void redis_free(void *impl) {
  redis *r = impl;
  if (!r) return;
  for (size_t i = 0; i < r->nidle; i++) buckets_conn_close(r->idle[i].c);
  pthread_mutex_destroy(&r->mu);
  free(r->key), free(r->password), free(r->user);
  free(r);
}

static const buckets_target_ops k_ops = {
    .type = "redis", .send = send_event, .free = redis_free, .is_active = is_active, .send_from_store = send_from_store};
const buckets_target_kind buckets_target_redis = {"notify_redis", &k_ops, create};
