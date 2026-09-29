/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Kafka target (MinIO internal/event/target/kafka.go over sarama's
 * SyncProducer): each event as a message keyed by "bucket/object" with the
 * event.Log JSON as its value. The client (net/kafka.c) connects when the
 * target is first used; the target is active while it knows a broker. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "net/kafka.h"
#include "notify/event.h"
#include "notify/targets.h"
#include "notify/xnet.h"

typedef struct {
  char *topic;
  buckets_kafka_cfg cfg;
  char **brokers;
  size_t nbrokers;
  char *version, *ca_dir, *cert, *key, *user, *pass, *mech, *codec;
  pthread_mutex_t mu;
  buckets_kafka *client;
  size_t batch_size;
  int64_t batch_commit_ns;
} kafka;

static char *get(const buckets_config *cfg, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, "notify_kafka", target, key);
  return v ? v : buckets_xstrdup("");
}

static bool create(const buckets_config *cfg, const char *target, const char *ca_file, void **impl, char *err, size_t errlen) {
  static const char *const keys[] = {"brokers", "topic", "queue_dir", "queue_limit", "version", "batch_size",
                                     "batch_commit_timeout", "tls", "tls_skip_verify", "tls_client_auth",
                                     "client_tls_cert", "client_tls_key", "sasl", "sasl_username", "sasl_password",
                                     "sasl_mechanism", "compression_codec", "compression_level"};
  enum { BROKERS, TOPIC, QDIR, QLIM, VERSION, BATCH, BATCHTO, TLS, SKIP, CLIENTAUTH, CERT, KEY, SASL, USER, PASS, MECH,
         CODEC, LEVEL, NKEYS };
  char *v[NKEYS];
  for (int i = 0; i < NKEYS; i++) v[i] = get(cfg, target, keys[i]);
  bool ok = true;
  char **brokers = NULL;
  size_t nb = 0;
  if (!*v[BROKERS]) {
    snprintf(err, errlen, "kafka 'brokers' cannot be empty");
    ok = false;
  }
  for (char *p = v[BROKERS]; ok && *p;) {
    size_t l = strcspn(p, ",");
    char one[512];
    snprintf(one, sizeof(one), "%.*s", (int)l, p);
    buckets_xnet_host h;
    if (!buckets_xnet_parse_host(one, &h, err, errlen)) ok = false;
    else {
      char s[300];
      buckets_xnet_host_string(&h, s, sizeof(s));
      brokers = buckets_xrealloc(brokers, (nb + 1) * sizeof(char *));
      brokers[nb++] = buckets_xstrdup(s);
    }
    p += l + (p[l] == ',');
  }
  char *end;
  unsigned long long batch = 0;
  int64_t batch_to = 0;
  if (ok) {
    strtoull(v[QLIM], &end, 10);
    if (!*v[QLIM] || *end || *v[QLIM] == '-') {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", v[QLIM]);
      ok = false;
    }
  }
  if (ok) {
    strtol(v[CLIENTAUTH], &end, 10);
    if (!*v[CLIENTAUTH] || *end) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", v[CLIENTAUTH]);
      ok = false;
    }
  }
  if (ok) {
    batch = strtoull(v[BATCH], &end, 10);
    if (!*v[BATCH] || *end || *v[BATCH] == '-') {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", v[BATCH]);
      ok = false;
    } else if (batch > 0xffffffffULL) {
      snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": value out of range", v[BATCH]);
      ok = false;
    }
  }
  if (ok && !buckets_go_duration_parse(v[BATCHTO], &batch_to)) {
    buckets_go_duration_error(v[BATCHTO], err, errlen);
    ok = false;
  }
  if (ok) { /* Validate */
    int ver[4];
    if (*v[QDIR] && *v[QDIR] != '/') {
      snprintf(err, errlen, "queueDir path should be absolute");
      ok = false;
    } else if (*v[VERSION] && !buckets_kafka_parse_version(v[VERSION], ver, err, errlen)) {
      ok = false;
    } else if (*v[VERSION] && ver[0] == 0 && ver[1] < 11) { /* record batches start at 0.11 */
      snprintf(err, errlen, "Kafka versions older than 0.11 are not supported");
      ok = false;
    } else if (batch > 1 && !*v[QDIR]) {
      snprintf(err, errlen, "batch should be enabled only if queue dir is enabled");
      ok = false;
    } else if (batch_to > 0 && (!*v[QDIR] || batch <= 1)) {
      snprintf(err, errlen, "batch commit timeout should be set only if queue dir is enabled and batch size > 1");
      ok = false;
    }
  }
  if (ok && impl) {
    kafka *k = buckets_xcalloc(1, sizeof(*k));
    k->topic = v[TOPIC], k->version = v[VERSION], k->cert = v[CERT], k->key = v[KEY];
    k->user = v[USER], k->pass = v[PASS], k->mech = v[MECH], k->codec = v[CODEC];
    v[TOPIC] = v[VERSION] = v[CERT] = v[KEY] = v[USER] = v[PASS] = v[MECH] = v[CODEC] = NULL;
    k->ca_dir = ca_file ? buckets_xstrdup(ca_file) : NULL;
    k->brokers = brokers, k->nbrokers = nb, brokers = NULL, nb = 0;
    k->batch_size = *v[QDIR] ? (size_t)batch : 0;
    k->batch_commit_ns = batch_to;
    k->cfg = (buckets_kafka_cfg){.brokers = (const char *const *)k->brokers,
                                 .nbrokers = k->nbrokers,
                                 .version = k->version,
                                 .tls = strcmp(v[TLS], "on") == 0,
                                 .tls_skip_verify = strcmp(v[SKIP], "on") == 0,
                                 .ca_dir = k->ca_dir,
                                 .client_cert = k->cert,
                                 .client_key = k->key,
                                 .sasl = strcmp(v[SASL], "on") == 0,
                                 .sasl_user = k->user,
                                 .sasl_pass = k->pass,
                                 .sasl_mechanism = k->mech,
                                 .compression = k->codec,
                                 .compression_level = atoi(v[LEVEL])}; /* strconv.Atoi's error ignored: 0 */
    pthread_mutex_init(&k->mu, NULL);
    *impl = k;
  }
  for (size_t i = 0; i < nb; i++) free(brokers[i]);
  free(brokers);
  for (int i = 0; i < NKEYS; i++) free(v[i]);
  return ok;
}

/* init (initKafka): the client, connected to the seed brokers. */
static bool init_kafka(kafka *k, char *err, size_t errlen) {
  if (k->client) return true;
  buckets_kafka *c = buckets_kafka_new(&k->cfg);
  if (!buckets_kafka_connect(c, err, errlen)) {
    buckets_kafka_free(c);
    return false;
  }
  k->client = c;
  return true;
}

static buckets_send_result send_event(void *impl, const char *record, size_t n, const char *event_name, const char *key,
                                      char *err, size_t errlen) {
  kafka *k = impl;
  pthread_mutex_lock(&k->mu);
  buckets_send_result r;
  if (!init_kafka(k, err, errlen)) {
    r = BUCKETS_SEND_NOT_CONNECTED;
  } else {
    buckets_buf v = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&v, "{\"EventName\":");
    buckets_json_go_string(&v, event_name, strlen(event_name));
    buckets_buf_append_c(&v, ",\"Key\":");
    buckets_json_go_string(&v, key, strlen(key));
    buckets_buf_append_c(&v, ",\"Records\":[");
    buckets_buf_append(&v, record, n);
    buckets_buf_append_c(&v, "]}");
    buckets_kafka_msg m = {key, strlen(key), v.data, v.len};
    int rc = buckets_kafka_send(k->client, k->topic, &m, 1, err, errlen);
    r = rc == 0 ? BUCKETS_SEND_OK : rc == 1 ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
    buckets_buf_free(&v);
  }
  pthread_mutex_unlock(&k->mu);
  return r;
}

/* sendMultiple: a stored batch in one request. */
static buckets_send_result send_batch(void *impl, const char *const *records, const size_t *lens,
                                      const char *const *names, const char *const *keys, size_t n, char *err,
                                      size_t errlen) {
  kafka *k = impl;
  pthread_mutex_lock(&k->mu);
  buckets_send_result r;
  if (!init_kafka(k, err, errlen)) {
    r = BUCKETS_SEND_NOT_CONNECTED;
  } else {
    buckets_buf *vals = buckets_xcalloc(n, sizeof(buckets_buf));
    buckets_kafka_msg *msgs = buckets_xcalloc(n, sizeof(*msgs));
    for (size_t i = 0; i < n; i++) {
      buckets_buf_append_c(&vals[i], "{\"EventName\":");
      buckets_json_go_string(&vals[i], names[i], strlen(names[i]));
      buckets_buf_append_c(&vals[i], ",\"Key\":");
      buckets_json_go_string(&vals[i], keys[i], strlen(keys[i]));
      buckets_buf_append_c(&vals[i], ",\"Records\":[");
      buckets_buf_append(&vals[i], records[i], lens[i]);
      buckets_buf_append_c(&vals[i], "]}");
      msgs[i] = (buckets_kafka_msg){keys[i], strlen(keys[i]), vals[i].data, vals[i].len};
    }
    int rc = buckets_kafka_send(k->client, k->topic, msgs, n, err, errlen);
    r = rc == 0 ? BUCKETS_SEND_OK : rc == 1 ? BUCKETS_SEND_NOT_CONNECTED : BUCKETS_SEND_ERROR;
    for (size_t i = 0; i < n; i++) buckets_buf_free(&vals[i]);
    free(vals);
    free(msgs);
  }
  pthread_mutex_unlock(&k->mu);
  return r;
}

static void batch_limits(void *impl, size_t *limit, int64_t *commit_ns) {
  kafka *k = impl;
  *limit = k->batch_size;
  *commit_ns = k->batch_commit_ns;
}

static bool is_active(void *impl, char *err, size_t errlen) {
  kafka *k = impl;
  pthread_mutex_lock(&k->mu);
  bool up = init_kafka(k, err, errlen);
  if (up && !buckets_kafka_has_brokers(k->client)) {
    snprintf(err, errlen, "not connected to target server/service");
    up = false;
  }
  pthread_mutex_unlock(&k->mu);
  return up;
}

static void tick(void *impl) {
  kafka *k = impl;
  pthread_mutex_lock(&k->mu);
  if (k->client) buckets_kafka_tick(k->client);
  pthread_mutex_unlock(&k->mu);
}

static void kafka_free(void *impl) {
  kafka *k = impl;
  if (!k) return;
  buckets_kafka_free(k->client);
  pthread_mutex_destroy(&k->mu);
  for (size_t i = 0; i < k->nbrokers; i++) free(k->brokers[i]);
  free(k->brokers);
  free(k->topic), free(k->version), free(k->ca_dir), free(k->cert), free(k->key), free(k->user), free(k->pass);
  free(k->mech), free(k->codec);
  free(k);
}

static const buckets_target_ops k_ops = {
    .type = "kafka", .send = send_event, .free = kafka_free, .is_active = is_active, .tick = tick,
    .send_batch = send_batch, .batch_limits = batch_limits};
const buckets_target_kind buckets_target_kafka = {"notify_kafka", &k_ops, create};
