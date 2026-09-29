/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Site replication (MinIO's cmd/site-replication.go): the state, joining
 * and leaving a group, the peer operations, and the hooks that push local
 * changes of buckets, bucket metadata and IAM to the other sites. */
#include "siterepl/internal.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bucket/metasys.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/base64.h"
#include "crypto/madmin.h"
#include "dist/peer.h"
#include "iam/iam.h"
#include "iam/ldapidp.h"
#include "iam/openid.h"
#include "iam/policy.h"
#include "net/s3client.h"
#include "object/sysconfig.h"
#include "s3/replicate.h"
#include "s3/server.h"

#define STATE_PATH "config/site-replication/state.json"
#define ADD_SUCCESS "Requested sites were configured for replication successfully."
#define ADD_PARTIAL "Some sites could not be configured for replication."
#define REMOVE_SUCCESS "Requested site(s) were removed from cluster replication successfully."
#define REMOVE_PARTIAL "Some site(s) could not be removed from cluster replication configuration."
#define VERSIONING_ENABLED_XML \
  "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>"
#define OBJECT_LOCK_ENABLED_XML \
  "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>"

/* ---- time ------------------------------------------------------------------------------ */

#define GO_ZERO BUCKETS_GO_ZERO_SEC

buckets_sr_time sr_zero_time(void) { return (buckets_sr_time){GO_ZERO, 0}; }
bool sr_time_is_zero(buckets_sr_time t) { return (t.sec == GO_ZERO || t.sec == 0) && t.nsec == 0; }

buckets_sr_time sr_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (buckets_sr_time){ts.tv_sec, ts.tv_nsec};
}

bool sr_time_after(buckets_sr_time a, buckets_sr_time b) {
  if (sr_time_is_zero(a)) return false;
  if (sr_time_is_zero(b)) return true;
  return a.sec > b.sec || (a.sec == b.sec && a.nsec > b.nsec);
}

void sr_time_str(buckets_sr_time t, char *out) {
  if (t.sec == GO_ZERO && t.nsec == 0) {
    strcpy(out, "0001-01-01T00:00:00Z");
    return;
  }
  buckets_time_rfc3339_nano(t.sec, t.nsec, out);
}

bool sr_time_parse(const char *s, buckets_sr_time *out) {
  if (!s) return false;
  if (strncmp(s, "0001-01-01T00:00:00", 19) == 0) {
    *out = sr_zero_time();
    return true;
  }
  long long sec;
  long nsec;
  if (!buckets_time_parse_rfc3339(s, &sec, &nsec)) return false;
  *out = (buckets_sr_time){sec, nsec};
  return true;
}

void sr_add_time(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, buckets_sr_time t) {
  char ts[64];
  sr_time_str(t, ts);
  yyjson_mut_obj_add_strcpy(d, o, key, ts);
}

buckets_sr_time sr_get_time(yyjson_val *o, const char *key) {
  buckets_sr_time t = sr_zero_time();
  sr_time_parse(yyjson_get_str(yyjson_obj_get(o, key)), &t);
  return t;
}

static buckets_sr_time iam_t(buckets_iam_time t) { return (buckets_sr_time){t.sec, t.nsec}; }
static buckets_sr_time go_t(buckets_gotime t) { return (buckets_sr_time){t.sec, t.nsec}; }

/* ---- errors ---------------------------------------------------------------------------- */

void sr_err(buckets_sr_err *e, buckets_s3_error code, const char *fmt, ...) {
  if (!e) return;
  e->code = code;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(e->message, sizeof(e->message), fmt, ap);
  va_end(ap);
}

static const char *jstr(yyjson_val *o, const char *key) {
  const char *s = yyjson_get_str(yyjson_obj_get(o, key));
  return s ? s : "";
}

static bool jbool(yyjson_val *o, const char *key) { return yyjson_get_bool(yyjson_obj_get(o, key)); }

static char *mut_json(yyjson_mut_doc *d, size_t *len) {
  size_t n;
  char *s = yyjson_mut_write(d, 0, &n);
  if (len) *len = n;
  return s;
}

/* ---- peers and the state ---------------------------------------------------------------- */

static void peer_free(buckets_sr_peer *p) {
  free(p->endpoint);
  free(p->name);
  free(p->deployment_id);
  memset(p, 0, sizeof(*p));
}

static void peer_copy(buckets_sr_peer *dst, const buckets_sr_peer *src) {
  *dst = *src;
  dst->endpoint = buckets_xstrdup(src->endpoint);
  dst->name = buckets_xstrdup(src->name);
  dst->deployment_id = buckets_xstrdup(src->deployment_id);
}

static void peers_free(buckets_sr_peer *p, size_t n) {
  for (size_t i = 0; i < n; i++) peer_free(&p[i]);
  free(p);
}

static void peer_parse(yyjson_val *v, const char *dep_key, buckets_sr_peer *p) {
  memset(p, 0, sizeof(*p));
  p->endpoint = buckets_xstrdup(jstr(v, "endpoint"));
  p->name = buckets_xstrdup(jstr(v, "name"));
  const char *d = jstr(v, "deploymentID");
  p->deployment_id = buckets_xstrdup(*d || !dep_key ? d : dep_key);
  snprintf(p->sync, sizeof(p->sync), "%s", jstr(v, "sync"));
  yyjson_val *bw = yyjson_obj_get(v, "defaultbandwidth");
  p->bw_limit = yyjson_get_uint(yyjson_obj_get(bw, "bandwidthLimitPerBucket"));
  p->bw_set = jbool(bw, "set");
  p->bw_updated = sr_get_time(bw, "updatedAt");
  p->replicate_ilm_expiry = jbool(v, "replicate-ilm-expiry");
}

static yyjson_mut_val *peer_json(yyjson_mut_doc *d, const buckets_sr_peer *p) {
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, o, "endpoint", p->endpoint);
  yyjson_mut_obj_add_strcpy(d, o, "name", p->name);
  yyjson_mut_obj_add_strcpy(d, o, "deploymentID", p->deployment_id);
  yyjson_mut_obj_add_strcpy(d, o, "sync", p->sync);
  yyjson_mut_val *bw = yyjson_mut_obj_add_obj(d, o, "defaultbandwidth");
  yyjson_mut_obj_add_uint(d, bw, "bandwidthLimitPerBucket", p->bw_limit);
  yyjson_mut_obj_add_bool(d, bw, "set", p->bw_set);
  sr_add_time(d, bw, "updatedAt", p->bw_updated);
  yyjson_mut_obj_add_bool(d, o, "replicate-ilm-expiry", p->replicate_ilm_expiry);
  return o;
}

static int peer_cmp(const void *a, const void *b) {
  return strcmp(((const buckets_sr_peer *)a)->name, ((const buckets_sr_peer *)b)->name);
}

/* {"<dep>": PeerInfo, ...} */
static void peers_parse(yyjson_val *m, buckets_sr_peer **out, size_t *n) {
  *out = NULL;
  *n = 0;
  if (!yyjson_is_obj(m)) return;
  *out = buckets_xcalloc(yyjson_obj_size(m) + 1, sizeof(**out));
  size_t idx, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(m, idx, max, k, v) peer_parse(v, yyjson_get_str(k), &(*out)[(*n)++]);
  qsort(*out, *n, sizeof(**out), peer_cmp);
}

static yyjson_mut_val *peers_json(yyjson_mut_doc *d, const buckets_sr_peer *p, size_t n) {
  yyjson_mut_val *m = yyjson_mut_obj(d);
  for (size_t i = 0; i < n; i++) yyjson_mut_obj_add(m, yyjson_mut_strcpy(d, p[i].deployment_id), peer_json(d, &p[i]));
  return m;
}

const char *sr_self_id(buckets_sr *sr) {
  buckets_objlayer *L = sr->s->layer;
  return L ? L->deployment_id_str : "";
}

void sr_snapshot_take(buckets_sr *sr, sr_snapshot *out) {
  memset(out, 0, sizeof(*out));
  pthread_rwlock_rdlock(&sr->lock);
  out->enabled = sr->enabled;
  out->name = buckets_xstrdup(sr->name ? sr->name : "");
  out->svc_ak = buckets_xstrdup(sr->svc_ak ? sr->svc_ak : "");
  out->updated = sr->updated;
  out->peers = buckets_xcalloc(sr->npeers + 1, sizeof(*out->peers));
  for (size_t i = 0; i < sr->npeers; i++) peer_copy(&out->peers[i], &sr->peers[i]);
  out->npeers = sr->npeers;
  pthread_rwlock_unlock(&sr->lock);
}

void sr_snapshot_free(sr_snapshot *s) {
  free(s->name);
  free(s->svc_ak);
  peers_free(s->peers, s->npeers);
  memset(s, 0, sizeof(*s));
}

const buckets_sr_peer *sr_snapshot_peer(const sr_snapshot *s, const char *dep_id) {
  for (size_t i = 0; i < s->npeers; i++)
    if (strcmp(s->peers[i].deployment_id, dep_id) == 0) return &s->peers[i];
  return NULL;
}

/* Publishes a new state (takes ownership of peers); with svc_ak NULL clears it. */
static void state_set(buckets_sr *sr, const char *name, buckets_sr_peer *peers, size_t n, const char *svc_ak,
                      buckets_sr_time updated) {
  pthread_rwlock_wrlock(&sr->lock);
  free(sr->name);
  free(sr->svc_ak);
  peers_free(sr->peers, sr->npeers);
  sr->name = name ? buckets_xstrdup(name) : NULL;
  sr->svc_ak = svc_ak ? buckets_xstrdup(svc_ak) : NULL;
  sr->peers = peers;
  sr->npeers = n;
  sr->updated = updated;
  sr->enabled = n != 0;
  pthread_rwlock_unlock(&sr->lock);
}

/* The service account's secret signs STS tokens while enabled. */
static void refresh_token_key(buckets_sr *sr) {
  char key[128] = "";
  buckets_sr_token_key(sr, key, sizeof(key));
  buckets_iam_set_token_key(key);
}

static bool state_load(buckets_sr *sr) {
  buckets_objlayer *L = sr->s->layer;
  if (!L) return false;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_obj_err e = buckets_sysconfig_read(L, STATE_PATH, &b, NULL);
  if (e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) {
    buckets_buf_free(&b);
    state_set(sr, NULL, NULL, 0, NULL, sr_zero_time());
    refresh_token_key(sr);
    return true;
  }
  if (e) {
    buckets_buf_free(&b);
    return false;
  }
  yyjson_doc *doc = yyjson_read(b.data, b.len, 0);
  buckets_buf_free(&b);
  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!doc || yyjson_get_int(yyjson_obj_get(root, "version")) != 1) {
    buckets_log_warn("site replication: unexpected state version in %s", STATE_PATH);
    yyjson_doc_free(doc);
    return false;
  }
  yyjson_val *st = yyjson_obj_get(root, "srState");
  buckets_sr_peer *peers;
  size_t n;
  peers_parse(yyjson_obj_get(st, "peers"), &peers, &n);
  state_set(sr, jstr(st, "name"), peers, n, jstr(st, "serviceAccountAccessKey"), sr_get_time(st, "updatedAt"));
  yyjson_doc_free(doc);
  refresh_token_key(sr);
  return true;
}

/* saveToDisk (n == 0 removes the state, removeFromDisk). */
static bool state_save(buckets_sr *sr, const char *name, buckets_sr_peer *peers, size_t n, const char *svc_ak,
                       buckets_sr_time updated) {
  buckets_objlayer *L = sr->s->layer;
  if (!L) {
    peers_free(peers, n);
    return false;
  }
  bool ok;
  if (n == 0) {
    buckets_obj_err e = buckets_sysconfig_delete(L, STATE_PATH);
    ok = e == BUCKETS_OBJ_OK || e == BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  } else {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_int(d, root, "version", 1);
    yyjson_mut_val *st = yyjson_mut_obj_add_obj(d, root, "srState");
    yyjson_mut_obj_add_strcpy(d, st, "name", name ? name : "");
    yyjson_mut_obj_add(st, yyjson_mut_str(d, "peers"), peers_json(d, peers, n));
    yyjson_mut_obj_add_strcpy(d, st, "serviceAccountAccessKey", svc_ak ? svc_ak : "");
    sr_add_time(d, st, "updatedAt", updated);
    size_t len;
    char *json = mut_json(d, &len);
    yyjson_mut_doc_free(d);
    ok = buckets_sysconfig_write(L, STATE_PATH, json, len) == BUCKETS_OBJ_OK;
    free(json);
  }
  if (!ok) {
    peers_free(peers, n);
    return false;
  }
  if (n == 0) state_set(sr, NULL, NULL, 0, NULL, sr_zero_time());
  else state_set(sr, name, peers, n, svc_ak, updated);
  refresh_token_key(sr);
  if (sr->s->peers) buckets_peer_notify_iam(sr->s->peers, "site-replication", "");
  return true;
}

/* ---- lifecycle -------------------------------------------------------------------------- */

buckets_sr *buckets_sr_new(buckets_s3_server *s) {
  buckets_sr *sr = buckets_xcalloc(1, sizeof(*sr));
  sr->s = s;
  pthread_rwlock_init(&sr->lock, NULL);
  pthread_mutex_init(&sr->mu, NULL);
  pthread_cond_init(&sr->cv, NULL);
  sr->updated = sr_zero_time();
  return sr;
}

void buckets_sr_free(buckets_sr *sr) {
  if (!sr) return;
  buckets_sr_stop(sr);
  state_set(sr, NULL, NULL, 0, NULL, sr_zero_time());
  pthread_rwlock_destroy(&sr->lock);
  pthread_mutex_destroy(&sr->mu);
  pthread_cond_destroy(&sr->cv);
  free(sr);
}

static int heal_interval_sec(void) {
  const char *e = getenv("BUCKETS_SITE_REPLICATION_HEAL_INTERVAL");
  int v = e ? atoi(e) : 0;
  return v > 0 ? v : 30; /* siteHealTimeInterval */
}

static void *heal_main(void *arg) {
  buckets_sr *sr = arg;
  bool loaded = false;
  for (;;) {
    int wait = loaded ? heal_interval_sec() : 1;
    pthread_mutex_lock(&sr->mu);
    struct timespec until;
    clock_gettime(CLOCK_REALTIME, &until);
    until.tv_sec += wait;
    while (!sr->stop && pthread_cond_timedwait(&sr->cv, &sr->mu, &until) == 0) {
    }
    bool stop = sr->stop;
    pthread_mutex_unlock(&sr->mu);
    if (stop) break;
    if (!loaded) { /* Init: retry until the state reads */
      loaded = sr->s->layer && buckets_iam_ready(sr->s->iam) && state_load(sr);
      if (loaded && buckets_sr_enabled(sr)) buckets_log_info("Cluster replication initialized");
      continue;
    }
    buckets_objlayer *L = sr->s->layer;
    if (buckets_sr_enabled(sr) && L && buckets_objlayer_set_is_led_here(L, 0, 0)) sr_heal_once(sr);
  }
  return NULL;
}

void buckets_sr_start(buckets_sr *sr) {
  pthread_mutex_lock(&sr->mu);
  if (!sr->started) {
    sr->stop = false;
    sr->started = pthread_create(&sr->heal_thread, NULL, heal_main, sr) == 0;
  }
  pthread_mutex_unlock(&sr->mu);
}

void buckets_sr_stop(buckets_sr *sr) {
  pthread_mutex_lock(&sr->mu);
  bool started = sr->started;
  sr->stop = true;
  sr->started = false;
  pthread_cond_broadcast(&sr->cv);
  pthread_mutex_unlock(&sr->mu);
  if (started) pthread_join(sr->heal_thread, NULL);
}

void buckets_sr_reload(buckets_sr *sr) {
  if (sr && sr->s->layer) state_load(sr);
}

bool buckets_sr_enabled(buckets_sr *sr) {
  if (!sr) return false;
  pthread_rwlock_rdlock(&sr->lock);
  bool e = sr->enabled;
  pthread_rwlock_unlock(&sr->lock);
  return e;
}

bool buckets_sr_token_key(buckets_sr *sr, char *out, size_t cap) {
  *out = '\0';
  if (!buckets_sr_enabled(sr)) return false;
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, BUCKETS_SR_SVC_ACCOUNT);
  bool ok = id && id->secret_key && *id->secret_key;
  if (ok) snprintf(out, cap, "%s", id->secret_key);
  buckets_iam_ident_release(id);
  return ok;
}

/* ---- talking to peers ------------------------------------------------------------------- */

/* "http(s)://host[:port][/]" -> host[:port] */
static bool endpoint_host(const char *ep, char *host, size_t cap, bool *secure) {
  const char *p = ep;
  *secure = false;
  if (strncmp(p, "https://", 8) == 0) {
    *secure = true;
    p += 8;
  } else if (strncmp(p, "http://", 7) == 0) {
    p += 7;
  } else {
    return false;
  }
  size_t n = strcspn(p, "/");
  if (!n || n >= cap) return false;
  memcpy(host, p, n);
  host[n] = '\0';
  return true;
}

/* The message of an admin API error response (JSON), or of the transport failure. */
static void call_error(const buckets_s3c_result *r, char *err, size_t errlen) {
  yyjson_doc *doc = r->body.len ? yyjson_read(r->body.data, r->body.len, 0) : NULL;
  const char *m = doc ? yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(doc), "Message")) : NULL;
  if (m && *m) snprintf(err, errlen, "%s", m);
  else if (r->status && !*r->message) snprintf(err, errlen, "%d %s", r->status, r->code);
  else snprintf(err, errlen, "%s", buckets_s3c_error(r));
  yyjson_doc_free(doc);
}

bool sr_endpoint_call(buckets_sr *sr, const char *endpoint, const char *ak, const char *sk, const char *method, const char *path,
                      const char *query, const void *body, size_t n, buckets_buf *out, char *err, size_t errlen) {
  char host[512];
  bool secure;
  if (!endpoint_host(endpoint, host, sizeof(host), &secure)) {
    snprintf(err, errlen, "invalid endpoint %s", endpoint);
    return false;
  }
  buckets_tls_client *tls = secure ? buckets_repl_tls(sr->s->repl) : NULL;
  buckets_s3c_config cfg = {.endpoint = host,
                            .secure = secure,
                            .access_key = ak,
                            .secret_key = sk,
                            .tls = tls,
                            .timeout_ms = 60000};
  buckets_s3c *c = buckets_s3c_new(&cfg);
  char obj[1024];
  snprintf(obj, sizeof(obj), "admin/v3%s", path);
  buckets_buf q = BUCKETS_BUF_INIT;
  if (query && *query) {
    buckets_buf_append_c(&q, query);
    buckets_buf_append_c(&q, "&");
  }
  buckets_buf_append_c(&q, "api-version=1");
  buckets_s3c_result r;
  bool ok = buckets_s3c_do(c, method, "minio", obj, q.data, NULL, 0, body, n, &r);
  buckets_buf_free(&q);
  if (!ok) call_error(&r, err, errlen);
  else if (out) buckets_buf_append(out, r.body.data, r.body.len);
  buckets_s3c_result_free(&r);
  buckets_s3c_free(c);
  return ok;
}

static bool svc_creds(buckets_sr *sr, const char *svc_ak, char **ak, char **sk) {
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, svc_ak && *svc_ak ? svc_ak : BUCKETS_SR_SVC_ACCOUNT);
  if (!id) return false;
  *ak = buckets_xstrdup(id->access_key);
  *sk = buckets_xstrdup(id->secret_key);
  buckets_iam_ident_release(id);
  return true;
}

bool sr_peer_call(buckets_sr *sr, const char *dep_id, const char *method, const char *path, const char *query,
                  const void *body, size_t n, buckets_buf *out, char *err, size_t errlen) {
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  const buckets_sr_peer *p = sr_snapshot_peer(&s, dep_id);
  char *ak = NULL, *sk = NULL;
  bool ok = false;
  if (!p) snprintf(err, errlen, "peer not found");
  else if (!svc_creds(sr, s.svc_ak, &ak, &sk)) snprintf(err, errlen, "site replication service account not found");
  else ok = sr_endpoint_call(sr, p->endpoint, ak, sk, method, path, query, body, n, out, err, errlen);
  free(ak);
  free(sk);
  sr_snapshot_free(&s);
  return ok;
}

/* concDo: fn runs for every peer (and self_fn for this site) in parallel;
 * the error summarizes the failures as MinIO's does. */
typedef bool (*sr_peer_fn)(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen);

typedef struct {
  buckets_sr *sr;
  const buckets_sr_peer *p;
  sr_peer_fn fn;
  void *ud;
  bool ok;
  char err[1024];
} conc_job;

static void *conc_run(void *arg) {
  conc_job *j = arg;
  j->ok = j->fn(j->sr, j->p, j->ud, j->err, sizeof(j->err));
  return NULL;
}

static int job_cmp(const void *a, const void *b) {
  return strcmp(((const conc_job *)a)->p->deployment_id, ((const conc_job *)b)->p->deployment_id);
}

static bool conc_do(buckets_sr *sr, const sr_snapshot *s, sr_peer_fn self_fn, sr_peer_fn peer_fn, void *ud,
                    const char *action, char *err, size_t errlen) {
  size_t n = s->npeers;
  conc_job *jobs = buckets_xcalloc(n + 1, sizeof(*jobs));
  pthread_t *th = buckets_xcalloc(n + 1, sizeof(*th));
  bool *started = buckets_xcalloc(n + 1, sizeof(bool));
  const char *self = sr_self_id(sr);
  for (size_t i = 0; i < n; i++) {
    bool is_self = strcmp(s->peers[i].deployment_id, self) == 0;
    jobs[i] = (conc_job){sr, &s->peers[i], is_self ? self_fn : peer_fn, ud, true, ""};
    if (!jobs[i].fn) continue;
    started[i] = pthread_create(&th[i], NULL, conc_run, &jobs[i]) == 0;
    if (!started[i]) conc_run(&jobs[i]);
  }
  for (size_t i = 0; i < n; i++)
    if (started[i]) pthread_join(th[i], NULL);
  qsort(jobs, n, sizeof(*jobs), job_cmp);
  bool all = true;
  for (size_t i = 0; i < n; i++) all &= jobs[i].ok;
  if (!all && err) {
    buckets_buf m = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&m, "Site replication error(s): \n");
    for (size_t i = 0; i < n; i++) {
      if (i) buckets_buf_append_c(&m, "\n");
      char line[1400];
      if (jobs[i].ok)
        snprintf(line, sizeof(line), "'%s' on site %s (%s): succeeded", action, jobs[i].p->name,
                 jobs[i].p->deployment_id);
      else
        snprintf(line, sizeof(line), "'%s' on site %s (%s): failed(%s)", action, jobs[i].p->name,
                 jobs[i].p->deployment_id, jobs[i].err);
      buckets_buf_append_c(&m, line);
    }
    snprintf(err, errlen, "%s", m.data);
    buckets_buf_free(&m);
  }
  free(jobs);
  free(th);
  free(started);
  return all;
}

/* ---- IDP settings -------------------------------------------------------------------------- */

static void idp_settings(buckets_sr *sr, yyjson_mut_doc *d, yyjson_mut_val *root) {
  buckets_s3_server *s = sr->s;
  pthread_mutex_lock(&s->oidc_mu);
  buckets_ldapidp *ldap = s->ldap ? buckets_ldapidp_ref(s->ldap) : NULL;
  pthread_mutex_unlock(&s->oidc_mu);
  yyjson_mut_val *l = yyjson_mut_obj_add_obj(d, root, "LDAP");
  bool le = ldap && buckets_ldapidp_enabled(ldap);
  yyjson_mut_obj_add_bool(d, l, "IsLDAPEnabled", le);
  buckets_buf ub = BUCKETS_BUF_INIT, gb = BUCKETS_BUF_INIT;
  const char *uf = "", *gf = "";
  if (le) buckets_ldapidp_settings(ldap, &ub, &uf, &gb, &gf);
  yyjson_mut_obj_add_strcpy(d, l, "LDAPUserDNSearchBase", ub.data ? ub.data : "");
  yyjson_mut_obj_add_strcpy(d, l, "LDAPUserDNSearchFilter", uf);
  yyjson_mut_obj_add_strcpy(d, l, "LDAPGroupSearchBase", gb.data ? gb.data : "");
  yyjson_mut_obj_add_strcpy(d, l, "LDAPGroupSearchFilter", gf);
  buckets_buf_free(&ub);
  buckets_buf_free(&gb);
  if (ldap) buckets_ldapidp_release(ldap);

  buckets_openid *o = buckets_s3_openid(s);
  bool oe = o && buckets_openid_enabled(o);
  yyjson_mut_val *oi = yyjson_mut_obj_add_obj(d, root, "OpenID");
  yyjson_mut_obj_add_bool(d, oi, "Enabled", oe);
  yyjson_mut_obj_add_strcpy(d, oi, "Region", oe ? s->region : "");
  buckets_openid_setting *st = NULL;
  size_t n = oe ? buckets_openid_settings(o, &st) : 0;
  yyjson_mut_val *roles = NULL;
  yyjson_mut_val *cp = NULL;
  for (size_t i = 0; i < n; i++) {
    yyjson_mut_val *v = yyjson_mut_obj(d);
    yyjson_mut_obj_add_str(d, v, "ClaimName", "");
    yyjson_mut_obj_add_bool(d, v, "ClaimUserinfoEnabled", st[i].claim_userinfo);
    yyjson_mut_obj_add_strcpy(d, v, "RolePolicy", st[i].role_policy);
    yyjson_mut_obj_add_strcpy(d, v, "ClientID", st[i].client_id);
    yyjson_mut_obj_add_strcpy(d, v, "HashedClientSecret", st[i].hashed_secret);
    if (st[i].claim_provider) {
      cp = v;
    } else {
      if (!roles) roles = yyjson_mut_obj(d);
      yyjson_mut_obj_add(roles, yyjson_mut_strcpy(d, st[i].arn), v);
    }
  }
  free(st);
  if (o) buckets_openid_release(o);
  yyjson_mut_obj_add(oi, yyjson_mut_str(d, "Roles"), roles ? roles : yyjson_mut_null(d));
  if (!cp) {
    cp = yyjson_mut_obj(d);
    yyjson_mut_obj_add_str(d, cp, "ClaimName", "");
    yyjson_mut_obj_add_bool(d, cp, "ClaimUserinfoEnabled", false);
    yyjson_mut_obj_add_str(d, cp, "RolePolicy", "");
    yyjson_mut_obj_add_str(d, cp, "ClientID", "");
    yyjson_mut_obj_add_str(d, cp, "HashedClientSecret", "");
  }
  yyjson_mut_obj_add(oi, yyjson_mut_str(d, "ClaimProvider"), cp);
}

void buckets_sr_idp_settings_json(buckets_sr *sr, buckets_buf *out) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  idp_settings(sr, d, root);
  size_t n;
  char *j = mut_json(d, &n);
  buckets_buf_append(out, j, n);
  buckets_buf_append_c(out, "\n");
  free(j);
  yyjson_mut_doc_free(d);
}

/* reflect.DeepEqual of two decoded IDPSettings: equal JSON values, where a
 * missing Roles and an empty one differ as nil and empty maps do. */
static bool idp_equal(const char *a, size_t an, const char *b, size_t bn) {
  yyjson_doc *x = yyjson_read(a, an, 0), *y = yyjson_read(b, bn, 0);
  bool eq = x && y && yyjson_equals(yyjson_doc_get_root(x), yyjson_doc_get_root(y));
  yyjson_doc_free(x);
  yyjson_doc_free(y);
  return eq;
}

/* ---- joining ---------------------------------------------------------------------------- */

typedef struct {
  char *name, *endpoint, *ak, *sk;
  char *dep_id;
  bool self, empty;
} site_info;

static void sites_free(site_info *s, size_t n) {
  for (size_t i = 0; i < n; i++) {
    free(s[i].name);
    free(s[i].endpoint);
    free(s[i].ak);
    free(s[i].sk);
    free(s[i].dep_id);
  }
  free(s);
}

/* getSiteStatuses: the deployment of each site, and whether it has buckets. */
static bool site_statuses(buckets_sr *sr, site_info *s, size_t n, buckets_sr_err *e) {
  for (size_t i = 0; i < n; i++) {
    char err[1024];
    buckets_buf b = BUCKETS_BUF_INIT;
    if (!sr_endpoint_call(sr, s[i].endpoint, s[i].ak, s[i].sk, "GET", "/info", NULL, NULL, 0, &b, err, sizeof(err))) {
      buckets_buf_free(&b);
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "unable to fetch server info for %s: %s", s[i].name, err);
      return false;
    }
    yyjson_doc *doc = yyjson_read(b.data ? b.data : "", b.len, 0);
    s[i].dep_id = buckets_xstrdup(jstr(yyjson_doc_get_root(doc), "deploymentID"));
    yyjson_doc_free(doc);
    buckets_buf_free(&b);
    /* ListBuckets */
    char host[512];
    bool secure;
    if (!endpoint_host(s[i].endpoint, host, sizeof(host), &secure)) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "unable to create s3 client for %s: invalid endpoint",
             s[i].name);
      return false;
    }
    buckets_s3c_config cfg = {.endpoint = host,
                              .secure = secure,
                              .access_key = s[i].ak,
                              .secret_key = s[i].sk,
                              .tls = secure ? buckets_repl_tls(sr->s->repl) : NULL,
                              .timeout_ms = 60000};
    buckets_s3c *c = buckets_s3c_new(&cfg);
    buckets_s3c_result r;
    bool ok = buckets_s3c_do(c, "GET", NULL, NULL, NULL, NULL, 0, NULL, 0, &r);
    if (!ok) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "unable to list buckets for %s: %s", s[i].name,
             buckets_s3c_error(&r));
    } else {
      s[i].empty = !(r.body.data && strstr(r.body.data, "<Bucket>"));
    }
    buckets_s3c_result_free(&r);
    buckets_s3c_free(c);
    if (!ok) return false;
    s[i].self = strcmp(s[i].dep_id, sr_self_id(sr)) == 0;
  }
  return true;
}

static bool validate_idp(buckets_sr *sr, site_info *s, size_t n, buckets_sr_err *e) {
  buckets_buf *set = buckets_xcalloc(n, sizeof(buckets_buf));
  bool ok = true;
  for (size_t i = 0; i < n && ok; i++) {
    if (s[i].self) {
      buckets_sr_idp_settings_json(sr, &set[i]);
      continue;
    }
    char err[1024];
    if (!sr_endpoint_call(sr, s[i].endpoint, s[i].ak, s[i].sk, "GET", "/site-replication/peer/idp-settings", NULL,
                          NULL, 0, &set[i], err, sizeof(err))) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "unable to fetch IDP settings from %s: %s", s[i].name, err);
      ok = false;
    }
  }
  for (size_t i = 1; i < n && ok; i++) {
    if (!idp_equal(set[0].data ? set[0].data : "", set[0].len, set[i].data ? set[i].data : "", set[i].len)) {
      /* errSRIAMConfigMismatch */
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_IAM_CONFIG_MISMATCH,
             "IAM configuration mismatch between sites: %s and %s\nSite %s settings: %.*s\nSite %s settings: %.*s",
             s[0].name, s[i].name, s[0].name, (int)set[0].len, set[0].data ? set[0].data : "", s[i].name,
             (int)set[i].len, set[i].data ? set[i].data : "");
      ok = false;
    }
  }
  for (size_t i = 0; i < n; i++) buckets_buf_free(&set[i]);
  free(set);
  return ok;
}

/* The site replicator service account: the existing one, or a new one
 * with parent as its parent. */
static bool ensure_svc(buckets_sr *sr, const char *ak, const char *sk, const char *parent, char **secret,
                       char *err, size_t errlen) {
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, ak);
  if (id) {
    *secret = buckets_xstrdup(id->secret_key);
    buckets_iam_ident_release(id);
    return true;
  }
  buckets_iam_svc_opts o = {.parent = parent, .access_key = ak, .secret_key = sk};
  char perr[256] = "";
  buckets_iam_err e = buckets_iam_add_svc(sr->s->iam, &o, &id, perr, sizeof(perr));
  if (e) {
    snprintf(err, errlen, "%s", *perr ? perr : buckets_iam_strerror(e));
    return false;
  }
  *secret = buckets_xstrdup(id->secret_key);
  buckets_iam_ident_release(id);
  return true;
}

static void sync_to_all_peers(buckets_sr *sr, bool ilm_expiry, char *err, size_t errlen);

bool buckets_sr_add(buckets_sr *sr, const char *requester_ak, const char *sites_json, size_t len, bool ilm_expiry,
                    buckets_buf *out, buckets_sr_err *e) {
  (void)requester_ak;
  yyjson_doc *doc = yyjson_read(sites_json, len, 0);
  yyjson_val *arr = yyjson_doc_get_root(doc);
  if (!yyjson_is_arr(arr)) {
    yyjson_doc_free(doc);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "json: cannot unmarshal into []madmin.PeerSite");
    return false;
  }
  size_t n = yyjson_arr_size(arr);
  site_info *sites = buckets_xcalloc(n + 1, sizeof(*sites));
  size_t idx, max;
  yyjson_val *v;
  yyjson_arr_foreach(arr, idx, max, v) {
    sites[idx].name = buckets_xstrdup(jstr(v, "name"));
    sites[idx].endpoint = buckets_xstrdup(jstr(v, "endpoints"));
    sites[idx].ak = buckets_xstrdup(jstr(v, "accessKey"));
    sites[idx].sk = buckets_xstrdup(jstr(v, "secretKey"));
  }
  yyjson_doc_free(doc);
  bool ok = false;
  sr_snapshot cur;
  sr_snapshot_take(sr, &cur);
  if (!site_statuses(sr, sites, n, e)) goto out;

  /* validations */
  int self = -1;
  bool local_has_buckets = false;
  const char *nonlocal_with_buckets = NULL;
  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; j < i; j++) {
      if (strcmp(sites[i].dep_id, sites[j].dep_id) == 0) {
        sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "duplicate sites provided for site-replication");
        goto out;
      }
    }
    if (sites[i].self) {
      self = (int)i;
      local_has_buckets = !sites[i].empty;
      continue;
    }
    if (!sites[i].empty && !sr_snapshot_peer(&cur, sites[i].dep_id)) nonlocal_with_buckets = sites[i].name;
  }
  if (self < 0) {
    buckets_buf ids = BUCKETS_BUF_INIT;
    for (size_t i = 0; i < n; i++) {
      buckets_buf_append_c(&ids, i ? " " : "");
      buckets_buf_append_c(&ids, sites[i].dep_id);
    }
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "global deployment ID %s mismatch, expected one of [%s]",
           sr_self_id(sr), ids.data ? ids.data : "");
    buckets_buf_free(&ids);
    goto out;
  }
  if (cur.npeers) {
    size_t common = 0;
    for (size_t i = 0; i < n; i++) common += sr_snapshot_peer(&cur, sites[i].dep_id) != NULL;
    if (common == cur.npeers && n == cur.npeers) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "this site is already configured for site-replication");
      goto out;
    }
    if (common != cur.npeers) {
      buckets_buf miss = BUCKETS_BUF_INIT;
      for (size_t k = 0; k < cur.npeers; k++) {
        bool found = false;
        for (size_t i = 0; i < n && !found; i++) found = strcmp(sites[i].dep_id, cur.peers[k].deployment_id) == 0;
        if (found) continue;
        if (miss.len) buckets_buf_append_c(&miss, " ");
        buckets_buf_append_c(&miss, cur.peers[k].name);
      }
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST,
             "all existing replicated sites must be specified - missing %s", miss.data ? miss.data : "");
      buckets_buf_free(&miss);
      goto out;
    }
  }
  if (!validate_idp(sr, sites, n, e)) goto out;
  if (local_has_buckets && nonlocal_with_buckets) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "only one cluster may have data when configuring site replication");
    goto out;
  }
  if (!local_has_buckets && nonlocal_with_buckets) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST,
           "please send your request to the cluster containing data/buckets: %s", nonlocal_with_buckets);
    goto out;
  }

  /* the common service account */
  char gak[21], gsk[41];
  buckets_iam_generate_credentials(gak, gsk);
  char *secret = NULL, err[1024];
  if (!ensure_svc(sr, BUCKETS_SR_SVC_ACCOUNT, gsk, sites[self].ak, &secret, err, sizeof(err))) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_SERVICE_ACCOUNT_ERROR, "unable to create local service account: %s", err);
    goto out;
  }
  bool ilm_set = false;
  for (size_t k = 0; k < cur.npeers; k++) ilm_set |= cur.peers[k].replicate_ilm_expiry;
  buckets_sr_time now = sr_now();
  buckets_sr_peer *peers = buckets_xcalloc(n + 1, sizeof(*peers));
  for (size_t i = 0; i < n; i++) {
    peers[i].endpoint = buckets_xstrdup(sites[i].endpoint);
    peers[i].name = buckets_xstrdup(sites[i].name);
    peers[i].deployment_id = buckets_xstrdup(sites[i].dep_id);
    peers[i].bw_updated = sr_zero_time();
    peers[i].replicate_ilm_expiry = ilm_set ? true : ilm_expiry;
  }
  qsort(peers, n, sizeof(*peers), peer_cmp);

  /* SRPeerJoin to every other site */
  size_t added = 0;
  char peer_err[1400] = "";
  char *sak = NULL, *ssk = NULL;
  svc_creds(sr, BUCKETS_SR_SVC_ACCOUNT, &sak, &ssk);
  for (size_t i = 0; i < n; i++) {
    if (sites[i].self) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_str(d, root, "svcAcctAccessKey", BUCKETS_SR_SVC_ACCOUNT);
    yyjson_mut_obj_add_strcpy(d, root, "svcAcctSecretKey", secret);
    yyjson_mut_obj_add_strcpy(d, root, "svcAcctParent", sites[i].ak);
    yyjson_mut_obj_add(root, yyjson_mut_str(d, "peers"), peers_json(d, peers, n));
    sr_add_time(d, root, "updatedAt", now);
    size_t jl;
    char *j = mut_json(d, &jl);
    yyjson_mut_doc_free(d);
    /* an existing peer is reached with the service account, a new one with the given credentials */
    bool existing = sr_snapshot_peer(&cur, sites[i].dep_id) != NULL;
    const char *ak = existing ? sak : sites[i].ak, *sk = existing ? ssk : sites[i].sk;
    buckets_buf enc = BUCKETS_BUF_INIT;
    bool sent = buckets_madmin_encrypt(sk, j, jl, &enc) &&
                sr_endpoint_call(sr, sites[i].endpoint, ak, sk, "PUT", "/site-replication/peer/join", NULL, enc.data,
                                 enc.len, NULL, err, sizeof(err));
    buckets_buf_free(&enc);
    free(j);
    if (!sent) {
      snprintf(peer_err, sizeof(peer_err), "unable to link with peer %s: %s", sites[i].name, err);
      break;
    }
    added++;
  }
  free(sak);
  free(ssk);
  if (*peer_err) {
    peers_free(peers, n);
    free(secret);
    if (!added) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "%s", peer_err);
      goto out;
    }
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add_bool(d, root, "success", false);
    yyjson_mut_obj_add_str(d, root, "status", ADD_PARTIAL);
    yyjson_mut_obj_add_strcpy(d, root, "errorDetail", peer_err);
    size_t jl;
    char *j = mut_json(d, &jl);
    buckets_buf_append(out, j, jl);
    free(j);
    yyjson_mut_doc_free(d);
    ok = true;
    goto out;
  }
  free(secret);
  bool saved = state_save(sr, sites[self].name, peers, n, BUCKETS_SR_SVC_ACCOUNT, now);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  if (!saved) {
    yyjson_mut_obj_add_bool(d, root, "success", false);
    yyjson_mut_obj_add_str(d, root, "status", ADD_PARTIAL);
    yyjson_mut_obj_add_str(d, root, "errorDetail", "unable to save cluster-replication state on local");
  } else {
    yyjson_mut_obj_add_bool(d, root, "success", true);
    yyjson_mut_obj_add_str(d, root, "status", ADD_SUCCESS);
    char serr[4096] = "";
    sync_to_all_peers(sr, ilm_expiry, serr, sizeof(serr));
    if (*serr) yyjson_mut_obj_add_strcpy(d, root, "initialSyncErrorMessage", serr);
  }
  size_t jl;
  char *j = mut_json(d, &jl);
  buckets_buf_append(out, j, jl);
  free(j);
  yyjson_mut_doc_free(d);
  ok = true;
out:
  sr_snapshot_free(&cur);
  sites_free(sites, n);
  return ok;
}

bool buckets_sr_peer_join(buckets_sr *sr, const char *json, size_t len, buckets_sr_err *e) {
  yyjson_doc *doc = yyjson_read(json, len, 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(doc);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid join request");
    return false;
  }
  buckets_sr_peer *peers;
  size_t n;
  peers_parse(yyjson_obj_get(root, "peers"), &peers, &n);
  const char *our_name = NULL;
  for (size_t i = 0; i < n; i++)
    if (strcmp(peers[i].deployment_id, sr_self_id(sr)) == 0) our_name = peers[i].name;
  if (!our_name) {
    peers_free(peers, n);
    yyjson_doc_free(doc);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "none of the given sites correspond to the current one");
    return false;
  }
  char *secret = NULL, err[1024];
  if (!ensure_svc(sr, jstr(root, "svcAcctAccessKey"), jstr(root, "svcAcctSecretKey"), jstr(root, "svcAcctParent"),
                  &secret, err, sizeof(err))) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_SERVICE_ACCOUNT_ERROR, "unable to create service account on %s: %s",
           our_name, err);
    peers_free(peers, n);
    yyjson_doc_free(doc);
    return false;
  }
  free(secret);
  /* retain the ILM expiry flag of known peers */
  sr_snapshot cur;
  sr_snapshot_take(sr, &cur);
  for (size_t i = 0; i < n; i++) {
    const buckets_sr_peer *old = sr_snapshot_peer(&cur, peers[i].deployment_id);
    if (old && old->replicate_ilm_expiry) peers[i].replicate_ilm_expiry = true;
  }
  sr_snapshot_free(&cur);
  char name[256];
  snprintf(name, sizeof(name), "%s", our_name);
  bool ok = state_save(sr, name, peers, n, jstr(root, "svcAcctAccessKey"), sr_get_time(root, "updatedAt"));
  yyjson_doc_free(doc);
  if (!ok) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE,
           "unable to save cluster-replication state to drive on %s: storage error", name);
  }
  return ok;
}

void buckets_sr_info_json(buckets_sr *sr, buckets_buf *out) {
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_bool(d, root, "enabled", s.enabled);
  if (s.enabled) {
    if (*s.name) yyjson_mut_obj_add_strcpy(d, root, "name", s.name);
    yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, root, "sites");
    for (size_t i = 0; i < s.npeers; i++) yyjson_mut_arr_append(a, peer_json(d, &s.peers[i]));
    if (*s.svc_ak) yyjson_mut_obj_add_strcpy(d, root, "serviceAccountAccessKey", s.svc_ak);
  }
  size_t n;
  char *j = mut_json(d, &n);
  buckets_buf_append(out, j, n);
  buckets_buf_append_c(out, "\n");
  free(j);
  yyjson_mut_doc_free(d);
  sr_snapshot_free(&s);
}

/* ---- bucket operations of this site -------------------------------------------------------- */

bool sr_make_with_versioning(buckets_sr *sr, const char *bucket, bool lock_enabled, buckets_sr_time created,
                             char *err, size_t errlen) {
  buckets_s3_server *s = sr->s;
  buckets_obj_err oe = buckets_obj_make_bucket(s->layer, bucket);
  if (oe && oe != BUCKETS_OBJ_ERR_BUCKET_EXISTS) {
    snprintf(err, errlen, "%s: MakeBucketWithVersioning: %s", sr->name ? sr->name : "", buckets_obj_strerror(oe));
    return false;
  }
  buckets_sr_time now = sr_now();
  buckets_bucket_meta m;
  memset(&m, 0, sizeof(m));
  if (!buckets_bucket_meta_load(s->layer, bucket, &m)) {
    buckets_bucket_meta_free(&m);
    buckets_bucket_meta_init(&m, bucket, (int64_t)now.sec * 1000000000LL + now.nsec);
  }
  if (!sr_time_is_zero(created)) m.created = (buckets_gotime){created.sec, (int32_t)created.nsec};
  buckets_buf_reset(&m.config[BUCKETS_BCFG_VERSIONING]);
  buckets_buf_append_c(&m.config[BUCKETS_BCFG_VERSIONING], VERSIONING_ENABLED_XML);
  m.updated[BUCKETS_BCFG_VERSIONING] = (buckets_gotime){now.sec, (int32_t)now.nsec};
  if (lock_enabled) {
    buckets_buf_reset(&m.config[BUCKETS_BCFG_OBJECT_LOCK]);
    buckets_buf_append_c(&m.config[BUCKETS_BCFG_OBJECT_LOCK], OBJECT_LOCK_ENABLED_XML);
    m.updated[BUCKETS_BCFG_OBJECT_LOCK] = (buckets_gotime){now.sec, (int32_t)now.nsec};
  }
  bool ok = buckets_bucket_meta_save(s->layer, &m);
  buckets_bucket_meta_free(&m);
  buckets_metasys_changed(s->meta, bucket);
  if (!ok) snprintf(err, errlen, "unable to save the metadata of bucket %s", bucket);
  return ok;
}

bool sr_local_delete_bucket(buckets_sr *sr, const char *bucket, bool force, char *err, size_t errlen) {
  buckets_s3_server *s = sr->s;
  buckets_obj_err oe = force ? buckets_obj_delete_bucket_force(s->layer, bucket) : buckets_obj_delete_bucket(s->layer, bucket);
  if (oe == BUCKETS_OBJ_OK || oe == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET) buckets_obj_mark_bucket_deleted(s->layer, bucket);
  if (oe) {
    snprintf(err, errlen, "%s", oe == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET ? "The specified bucket does not exist"
                                : oe == BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY ? "The bucket you tried to delete is not empty"
                                                                         : buckets_obj_strerror(oe));
    return false;
  }
  buckets_bucket_meta_delete(s->layer, bucket);
  buckets_metasys_changed(s->meta, bucket);
  buckets_repl_stats_delete_bucket(bucket);
  return true;
}

void sr_purge_deleted_bucket(buckets_sr *sr, const char *bucket) { buckets_obj_purge_bucket_deleted(sr->s->layer, bucket); }

static char *target_url(const buckets_bucket_target *t) {
  size_t n = strlen(t->endpoint) + 16;
  char *u = buckets_xmalloc(n);
  snprintf(u, n, "%s://%s", t->secure ? "https" : "http", t->endpoint);
  return u;
}

/* The endpoint as url.Parse + URL.String() of a target would give it
 * (scheme://host, no trailing slash). */
static void norm_endpoint(const char *ep, char *out, size_t cap) {
  char host[512];
  bool secure;
  if (endpoint_host(ep, host, sizeof(host), &secure)) snprintf(out, cap, "%s://%s", secure ? "https" : "http", host);
  else snprintf(out, cap, "%s", ep);
}

/* One peer's part of PeerBucketConfigureReplHandler. */
static bool configure_peer(buckets_sr *sr, const char *bucket, const buckets_sr_peer *peer, const char *ak,
                           const char *sk, char *err, size_t errlen) {
  buckets_s3_server *s = sr->s;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  char rule_id[300];
  snprintf(rule_id, sizeof(rule_id), "site-repl-%s", peer->deployment_id);
  const char *rule_arn = NULL;
  long max_prio = 0;
  if (st->has_replication) {
    for (size_t i = 0; i < st->replication.n; i++) {
      const buckets_repl_rule *r = &st->replication.rules[i];
      if (r->priority > max_prio) max_prio = r->priority;
      if (r->id && strcmp(r->id, rule_id) == 0) rule_arn = r->dest_bucket;
    }
  }
  char host[512];
  bool secure;
  if (!endpoint_host(peer->endpoint, host, sizeof(host), &secure)) {
    buckets_bucket_state_release(st);
    snprintf(err, errlen, "invalid endpoint %s", peer->endpoint);
    return false;
  }
  char pep[600];
  norm_endpoint(peer->endpoint, pep, sizeof(pep));
  buckets_bucket_targets ts = {0};
  ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
  for (size_t i = 0; i < st->targets.n; i++) buckets_bucket_target_copy(&ts.t[ts.n++], &st->targets.t[i]);
  char target_arn[600] = "";
  bool targets_changed = false;
  for (size_t i = 0; i < ts.n && rule_arn; i++) {
    buckets_bucket_target *t = &ts.t[i];
    if (strcmp(t->arn, rule_arn) != 0) continue;
    snprintf(target_arn, sizeof(target_arn), "%s", rule_arn);
    bool update_bw = peer->bw_limit != 0 && t->bandwidth_limit == 0;
    char *u = target_url(t);
    bool update = strcmp(u, pep) != 0 || update_bw;
    free(u);
    if (update) { /* a stale target: the peer's endpoint and the service account */
      free(t->endpoint);
      t->endpoint = buckets_xstrdup(host);
      t->secure = secure;
      t->has_creds = true;
      free(t->access_key);
      free(t->secret_key);
      t->access_key = buckets_xstrdup(ak);
      t->secret_key = buckets_xstrdup(sk);
      if (*peer->sync) t->replication_sync = strcmp(peer->sync, "enable") == 0;
      if (update_bw) t->bandwidth_limit = (int64_t)peer->bw_limit;
      targets_changed = true;
    }
    break;
  }
  if (!*target_arn) {
    buckets_bucket_target t;
    buckets_bucket_target_init(&t);
    free(t.source_bucket);
    t.source_bucket = buckets_xstrdup(bucket);
    free(t.endpoint);
    t.endpoint = buckets_xstrdup(host);
    t.has_creds = true;
    free(t.access_key);
    free(t.secret_key);
    t.access_key = buckets_xstrdup(ak);
    t.secret_key = buckets_xstrdup(sk);
    free(t.target_bucket);
    t.target_bucket = buckets_xstrdup(bucket);
    t.secure = secure;
    free(t.api);
    t.api = buckets_xstrdup("s3v4");
    free(t.type);
    t.type = buckets_xstrdup("replication");
    t.replication_sync = strcmp(peer->sync, "enable") == 0;
    free(t.deployment_id);
    t.deployment_id = buckets_xstrdup(peer->deployment_id);
    t.bandwidth_limit = (int64_t)peer->bw_limit;
    /* getRemoteARN: an identical target's ARN, or one naming the peer's deployment */
    char *u = target_url(&t);
    for (size_t i = 0; i < ts.n && !*target_arn; i++) {
      char *tu = target_url(&ts.t[i]);
      if (strcmp(ts.t[i].type, t.type) == 0 && strcmp(ts.t[i].target_bucket, t.target_bucket) == 0 &&
          strcmp(tu, u) == 0 && strcmp(ts.t[i].access_key ? ts.t[i].access_key : "", ak) == 0)
        snprintf(target_arn, sizeof(target_arn), "%s", ts.t[i].arn);
      free(tu);
    }
    free(u);
    if (!*target_arn) {
      buckets_arn_generate("replication", "", peer->deployment_id, bucket, target_arn, sizeof(target_arn));
      free(t.arn);
      t.arn = buckets_xstrdup(target_arn);
      ts.t = buckets_xrealloc(ts.t, (ts.n + 1) * sizeof(*ts.t));
      ts.t[ts.n++] = t;
      targets_changed = true;
    } else {
      buckets_bucket_target_free(&t);
    }
  }
  bool ok = true;
  if (targets_changed) {
    buckets_buf j = BUCKETS_BUF_INIT;
    buckets_bucket_targets_json(&ts, &j);
    ok = buckets_metasys_update_targets(s->meta, bucket, j.data, j.len);
    buckets_buf_free(&j);
    if (!ok) snprintf(err, errlen, "%s->%s: Bucket target creation error: storage error", sr->name, peer->name);
  }
  buckets_bucket_targets_free(&ts);

  /* the rule: replicate everything, at a fresh priority */
  if (ok) {
    buckets_buf x = BUCKETS_BUF_INIT;
    if (st->has_replication) {
      buckets_replication c = st->replication;
      buckets_repl_rule *keep = buckets_xcalloc(c.n + 1, sizeof(*keep));
      size_t k = 0;
      for (size_t i = 0; i < c.n; i++)
        if (!c.rules[i].id || strcmp(c.rules[i].id, rule_id) != 0) keep[k++] = c.rules[i];
      buckets_replication tmp = {keep, k, c.role};
      buckets_replication_xml(&tmp, &x);
      free(keep);
    } else {
      buckets_buf_append_c(&x, "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></ReplicationConfiguration>");
    }
    char rule[2048];
    snprintf(rule, sizeof(rule),
             "<Rule><ID>%s</ID><Status>Enabled</Status><Priority>%ld</Priority>"
             "<DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>"
             "<DeleteReplication><Status>Enabled</Status></DeleteReplication>"
             "<Destination><Bucket>%s</Bucket></Destination><Filter></Filter>"
             "<SourceSelectionCriteria><ReplicaModifications><Status>Enabled</Status></ReplicaModifications></SourceSelectionCriteria>"
             "<ExistingObjectReplication><Status>Enabled</Status></ExistingObjectReplication></Rule>",
             rule_id, max_prio + 10, target_arn);
    char *end = x.data ? strstr(x.data, "</ReplicationConfiguration>") : NULL;
    buckets_buf doc = BUCKETS_BUF_INIT;
    if (end) {
      buckets_buf_append(&doc, x.data, (size_t)(end - x.data));
      buckets_buf_append_c(&doc, rule);
      buckets_buf_append_c(&doc, end);
    }
    buckets_buf_free(&x);
    buckets_replication cfg;
    char perr[512] = "";
    if (!end || !buckets_replication_parse(doc.data, doc.len, &cfg, perr, sizeof(perr))) {
      snprintf(err, errlen, "%s->%s: Error adding bucket replication rule: %s", sr->name, peer->name, perr);
      ok = false;
    } else {
      if (!buckets_replication_validate(&cfg, bucket, false, perr, sizeof(perr))) {
        snprintf(err, errlen, "%s", perr);
        ok = false;
      } else {
        buckets_buf out = BUCKETS_BUF_INIT;
        buckets_replication_xml(&cfg, &out);
        ok = buckets_metasys_update(s->meta, bucket, BUCKETS_BCFG_REPLICATION, out.data, out.len);
        buckets_buf_free(&out);
        if (!ok)
          snprintf(err, errlen, "%s->%s: Error updating replication configuration: storage error", sr->name,
                   peer->name);
      }
      buckets_replication_free(&cfg);
    }
    buckets_buf_free(&doc);
  }
  buckets_bucket_state_release(st);
  return ok;
}

bool sr_configure_repl(buckets_sr *sr, const char *bucket, char *err, size_t errlen) {
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  char *ak = NULL, *sk = NULL;
  if (!svc_creds(sr, s.svc_ak, &ak, &sk)) {
    sr_snapshot_free(&s);
    snprintf(err, errlen, "site replication service account not found");
    return false;
  }
  const char *self = sr_self_id(sr);
  bool all = true;
  buckets_buf msgs = BUCKETS_BUF_INIT;
  /* toErrorFromErrMap over the peers, sorted by deployment */
  size_t *order = buckets_xcalloc(s.npeers + 1, sizeof(size_t));
  for (size_t i = 0; i < s.npeers; i++) order[i] = i;
  for (size_t i = 1; i < s.npeers; i++)
    for (size_t j = i; j > 0 && strcmp(s.peers[order[j - 1]].deployment_id, s.peers[order[j]].deployment_id) > 0; j--) {
      size_t t = order[j];
      order[j] = order[j - 1];
      order[j - 1] = t;
    }
  for (size_t k = 0; k < s.npeers; k++) {
    const buckets_sr_peer *p = &s.peers[order[k]];
    if (strcmp(p->deployment_id, self) == 0) continue;
    char e[1024] = "";
    bool ok = configure_peer(sr, bucket, p, ak, sk, e, sizeof(e));
    all &= ok;
    char line[1400];
    if (ok) snprintf(line, sizeof(line), "'ConfigureReplication' on site %s (%s): succeeded", p->name, p->deployment_id);
    else snprintf(line, sizeof(line), "'ConfigureReplication' on site %s (%s): failed(%s)", p->name, p->deployment_id, e);
    buckets_buf_append_c(&msgs, msgs.len ? "\n" : "");
    buckets_buf_append_c(&msgs, line);
  }
  if (!all) snprintf(err, errlen, "Site replication error(s): \n%s", msgs.data);
  buckets_buf_free(&msgs);
  free(order);
  free(ak);
  free(sk);
  sr_snapshot_free(&s);
  return all;
}

bool sr_bucket_op_to_peer(buckets_sr *sr, const char *dep_id, const char *bucket, const char *op,
                          const char *extra_query, char *err, size_t errlen) {
  buckets_buf q = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&q, "bucket=");
  buckets_url_encode(&q, bucket, false);
  buckets_buf_append_c(&q, "&operation=");
  buckets_buf_append_c(&q, op);
  if (extra_query && *extra_query) {
    buckets_buf_append_c(&q, "&");
    buckets_buf_append_c(&q, extra_query);
  }
  bool ok = sr_peer_call(sr, dep_id, "PUT", "/site-replication/peer/bucket-ops", q.data, NULL, 0, NULL, err, errlen);
  buckets_buf_free(&q);
  return ok;
}

/* ---- hooks ------------------------------------------------------------------------------------ */

typedef struct {
  const char *bucket;
  bool lock_enabled;
  buckets_sr_time created;
  const char *query;
  const char *op;
} bucket_job;

static bool make_self(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen) {
  (void)p;
  bucket_job *j = ud;
  return sr_make_with_versioning(sr, j->bucket, j->lock_enabled, j->created, err, errlen);
}

static bool op_peer(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen) {
  bucket_job *j = ud;
  char e[1024];
  bool ok = sr_bucket_op_to_peer(sr, p->deployment_id, j->bucket, j->op, j->query, e, sizeof(e));
  if (!ok) {
    const char *action = strcmp(j->op, "make-with-versioning") == 0 ? "MakeBucketWithVersioning"
                         : strcmp(j->op, "configure-replication") == 0 ? "ConfigureReplication"
                                                                        : "DeleteBucket";
    snprintf(err, errlen, "%s->%s: %s: %s", sr->name ? sr->name : "", p->name, action, e);
  }
  return ok;
}

static bool configure_self(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen) {
  (void)p;
  bucket_job *j = ud;
  char e[3000];
  bool ok = sr_configure_repl(sr, j->bucket, e, sizeof(e));
  if (!ok) snprintf(err, errlen, "%s: ConfigureReplication: %s", sr->name ? sr->name : "", e);
  return ok;
}

bool buckets_sr_make_bucket_hook(buckets_sr *sr, const char *bucket, bool lock_enabled, bool force_create,
                                 char *err, size_t errlen) {
  if (!buckets_sr_enabled(sr)) return true;
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bucket);
  buckets_sr_time created = go_t(st->meta.created);
  buckets_bucket_state_release(st);
  char ts[64];
  sr_time_str(created, ts);
  buckets_buf q = BUCKETS_BUF_INIT;
  if (lock_enabled) buckets_buf_append_c(&q, "lockEnabled=true&versioningEnabled=true&");
  else buckets_buf_append_c(&q, "versioningEnabled=true&");
  if (force_create) buckets_buf_append_c(&q, "forceCreate=true&");
  buckets_buf_append_c(&q, "createdAt=");
  buckets_url_encode(&q, ts, false);
  bucket_job j = {bucket, lock_enabled, created, q.data, "make-with-versioning"};
  char e1[4096] = "", e2[4096] = "";
  bool ok1 = conc_do(sr, &s, make_self, op_peer, &j, "MakeBucketWithVersioning", e1, sizeof(e1));
  bucket_job j2 = {bucket, lock_enabled, created, NULL, "configure-replication"};
  bool ok2 = conc_do(sr, &s, configure_self, op_peer, &j2, "ConfigureReplication", e2, sizeof(e2));
  buckets_buf_free(&q);
  sr_snapshot_free(&s);
  if (!ok1) snprintf(err, errlen, "%s", e1);
  else if (!ok2) snprintf(err, errlen, "%s", e2);
  return ok1 && ok2;
}

bool buckets_sr_delete_bucket_hook(buckets_sr *sr, const char *bucket, bool force, char *err, size_t errlen) {
  if (!buckets_sr_enabled(sr)) return true;
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bucket_job j = {bucket, false, sr_zero_time(), NULL, force ? "force-delete-bucket" : "delete-bucket"};
  bool ok = conc_do(sr, &s, NULL, op_peer, &j, "DeleteBucket", err, errlen);
  sr_snapshot_free(&s);
  return ok;
}

typedef struct {
  const char *path;
  const char *json;
  size_t n;
  const char *action;
} send_job;

static bool send_peer(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen) {
  send_job *j = ud;
  char e[1024];
  bool ok = sr_peer_call(sr, p->deployment_id, "PUT", j->path, NULL, j->json, j->n, NULL, e, sizeof(e));
  if (!ok) snprintf(err, errlen, "%s->%s: %s: %s", sr->name ? sr->name : "", p->name, j->action, e);
  return ok;
}

static void broadcast(buckets_sr *sr, const char *path, const char *action, const char *json, size_t n) {
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  send_job j = {path, json, n, action};
  char err[4096] = "";
  if (!conc_do(sr, &s, NULL, send_peer, &j, action, err, sizeof(err))) buckets_log_warn("site replication: %s", err);
  sr_snapshot_free(&s);
}

void sr_send_bucket_meta(buckets_sr *sr, const char *dep_id, const char *json, size_t n) {
  char err[1024];
  if (!sr_peer_call(sr, dep_id, "PUT", "/site-replication/peer/bucket-meta", NULL, json, n, NULL, err, sizeof(err)))
    buckets_log_warn("site replication: SRPeerReplicateBucketMeta: %s", err);
}

void sr_send_iam_item(buckets_sr *sr, const char *dep_id, const char *json, size_t n) {
  char err[1024];
  if (!sr_peer_call(sr, dep_id, "PUT", "/site-replication/peer/iam-item", NULL, json, n, NULL, err, sizeof(err)))
    buckets_log_warn("site replication: SRPeerReplicateIAMItem: %s", err);
}

/* A madmin.SRBucketMeta of one configuration as it now is. */
static char *bucket_meta_item(buckets_sr *sr, const char *bucket, const char *type, size_t *len) {
  buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bucket);
  buckets_bucket_cfg cfg;
  const char *key;
  bool raw = false;
  if (strcmp(type, "policy") == 0) cfg = BUCKETS_BCFG_POLICY, key = "policy", raw = true;
  else if (strcmp(type, "tags") == 0) cfg = BUCKETS_BCFG_TAGGING, key = "tags";
  else if (strcmp(type, "version-config") == 0) cfg = BUCKETS_BCFG_VERSIONING, key = "versioningConfig";
  else if (strcmp(type, "object-lock-config") == 0) cfg = BUCKETS_BCFG_OBJECT_LOCK, key = "objectLockConfig";
  else if (strcmp(type, "sse-config") == 0) cfg = BUCKETS_BCFG_ENCRYPTION, key = "sseConfig";
  else if (strcmp(type, "quota-config") == 0) cfg = BUCKETS_BCFG_QUOTA, key = "quota", raw = true;
  else {
    buckets_bucket_state_release(st);
    return NULL;
  }
  const buckets_buf *v = &st->meta.config[cfg];
  bool present = v->len > 0;
  if (cfg == BUCKETS_BCFG_QUOTA && present && st->has_quota && st->quota.size == 0 && st->quota.quota == 0)
    present = false; /* a cleared quota replicates as none */
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "type", type);
  yyjson_mut_obj_add_strcpy(d, root, "bucket", bucket);
  if (present && raw) {
    yyjson_doc *pd = yyjson_read(v->data, v->len, 0);
    if (pd) yyjson_mut_obj_add(root, yyjson_mut_str(d, key), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    yyjson_doc_free(pd);
  } else if (present) {
    char *b64 = buckets_xmalloc(4 * ((v->len + 2) / 3) + 1);
    buckets_base64_encode((const uint8_t *)v->data, v->len, b64);
    yyjson_mut_obj_add_strcpy(d, root, key, b64);
    free(b64);
  }
  buckets_sr_time up = go_t(st->meta.updated[cfg]);
  if (sr_time_is_zero(up)) up = sr_now();
  sr_add_time(d, root, "updatedAt", up);
  sr_add_time(d, root, "expiryUpdatedAt", sr_zero_time());
  buckets_bucket_state_release(st);
  char *j = mut_json(d, len);
  yyjson_mut_doc_free(d);
  return j;
}

void buckets_sr_bucket_meta_hook(buckets_sr *sr, const char *bucket, const char *type) {
  if (!buckets_sr_enabled(sr)) return;
  size_t n;
  char *j = bucket_meta_item(sr, bucket, type, &n);
  if (!j) return;
  broadcast(sr, "/site-replication/peer/bucket-meta", "SRPeerReplicateBucketMeta", j, n);
  free(j);
}

void buckets_sr_iam_hook(buckets_sr *sr, const char *item_json, size_t len) {
  if (!buckets_sr_enabled(sr)) return;
  broadcast(sr, "/site-replication/peer/iam-item", "SRPeerReplicateIAMItem", item_json, len);
}

static yyjson_mut_val *iam_item(yyjson_mut_doc *d, const char *type) {
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "type", type);
  return root;
}

static void iam_send(buckets_sr *sr, yyjson_mut_doc *d, yyjson_mut_val *root, buckets_sr_time updated) {
  sr_add_time(d, root, "updatedAt", updated);
  size_t n;
  char *j = mut_json(d, &n);
  buckets_sr_iam_hook(sr, j, n);
  free(j);
  yyjson_mut_doc_free(d);
}

void buckets_sr_iam_policy(buckets_sr *sr, const char *name, const char *policy_json) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "policy");
  yyjson_mut_obj_add_strcpy(d, root, "name", name);
  buckets_sr_time up = sr_now();
  yyjson_doc *pd = policy_json ? yyjson_read(policy_json, strlen(policy_json), 0) : NULL;
  if (pd) {
    yyjson_mut_obj_add(root, yyjson_mut_str(d, "policy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    buckets_iam_policy_doc doc;
    if (buckets_iam_get_policy(sr->s->iam, name, &doc) == BUCKETS_IAM_OK) {
      up = iam_t(doc.updated);
      buckets_iam_policy_doc_free(&doc, 1);
    }
  } else {
    yyjson_mut_obj_add_null(d, root, "policy");
  }
  yyjson_doc_free(pd);
  iam_send(sr, d, root, up);
}

void buckets_sr_iam_user(buckets_sr *sr, const char *access_key, bool deleted, const char *secret_key,
                         const char *status) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "iam-user");
  yyjson_mut_val *u = yyjson_mut_obj_add_obj(d, root, "iamUser");
  yyjson_mut_obj_add_strcpy(d, u, "accessKey", access_key);
  yyjson_mut_obj_add_bool(d, u, "isDeleteReq", deleted);
  if (deleted) {
    yyjson_mut_obj_add_null(d, u, "userReq");
  } else {
    yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, u, "userReq");
    if (secret_key && *secret_key) yyjson_mut_obj_add_strcpy(d, r, "secretKey", secret_key);
    yyjson_mut_obj_add_strcpy(d, r, "status", status ? status : "");
  }
  buckets_sr_time up = sr_now();
  buckets_iam_ident *id = deleted ? NULL : buckets_iam_get_ident(sr->s->iam, access_key);
  if (id) up = iam_t(id->updated);
  buckets_iam_ident_release(id);
  iam_send(sr, d, root, up);
}

void buckets_sr_iam_group(buckets_sr *sr, const char *group, const char *const *members, size_t n,
                          const char *status, bool is_remove) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "group-info");
  yyjson_mut_val *g = yyjson_mut_obj_add_obj(d, root, "groupInfo");
  yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, g, "updateReq");
  yyjson_mut_obj_add_strcpy(d, r, "group", group);
  yyjson_mut_val *m = n ? yyjson_mut_obj_add_arr(d, r, "members") : NULL;
  if (!n) yyjson_mut_obj_add_null(d, r, "members");
  for (size_t i = 0; i < n; i++) yyjson_mut_arr_add_strcpy(d, m, members[i]);
  yyjson_mut_obj_add_strcpy(d, r, "groupStatus", status ? status : "");
  yyjson_mut_obj_add_bool(d, r, "isRemove", is_remove);
  buckets_sr_time up = sr_now();
  buckets_iam_group_desc gd;
  if (buckets_iam_group_describe(sr->s->iam, group, &gd) == BUCKETS_IAM_OK) {
    if (buckets_iam_time_is_set(gd.updated)) up = iam_t(gd.updated);
    buckets_iam_group_desc_free(&gd);
  }
  iam_send(sr, d, root, up);
}

void buckets_sr_iam_mapping(buckets_sr *sr, const char *name, int user_type, bool is_group, const char *policies) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "policy-mapping");
  yyjson_mut_val *m = yyjson_mut_obj_add_obj(d, root, "policyMapping");
  yyjson_mut_obj_add_strcpy(d, m, "userOrGroup", name);
  yyjson_mut_obj_add_int(d, m, "userType", user_type);
  yyjson_mut_obj_add_bool(d, m, "isGroup", is_group);
  yyjson_mut_obj_add_strcpy(d, m, "policy", policies ? policies : "");
  buckets_sr_time now = sr_now();
  sr_add_time(d, m, "createdAt", sr_zero_time());
  sr_add_time(d, m, "updatedAt", now);
  iam_send(sr, d, root, now);
}

/* SRSvcAccCreate of a stored service account. */
static yyjson_mut_val *svc_create_json(yyjson_mut_doc *d, const buckets_iam_ident *id) {
  yyjson_mut_val *c = yyjson_mut_obj(d);
  yyjson_mut_obj_add_strcpy(d, c, "parent", id->parent ? id->parent : "");
  yyjson_mut_obj_add_strcpy(d, c, "accessKey", id->access_key);
  yyjson_mut_obj_add_strcpy(d, c, "secretKey", id->secret_key);
  if (id->ngroups) {
    yyjson_mut_val *g = yyjson_mut_obj_add_arr(d, c, "groups");
    for (size_t i = 0; i < id->ngroups; i++) yyjson_mut_arr_add_strcpy(d, g, id->groups[i]);
  } else {
    yyjson_mut_obj_add_null(d, c, "groups");
  }
  /* claims: the token's, less what the account's own creation sets */
  yyjson_mut_val *cl = yyjson_mut_obj(d);
  if (id->claims) {
    size_t idx, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(yyjson_doc_get_root(id->claims), idx, max, k, v) {
      const char *n = yyjson_get_str(k);
      if (strcmp(n, "accessKey") == 0 || strcmp(n, "parent") == 0 || strcmp(n, "sessionPolicy") == 0 ||
          strcmp(n, "sa-policy") == 0 || strcmp(n, "exp") == 0)
        continue;
      yyjson_mut_obj_add(cl, yyjson_mut_strcpy(d, n), yyjson_val_mut_copy(d, v));
    }
  }
  yyjson_mut_obj_add(c, yyjson_mut_str(d, "claims"), cl);
  yyjson_doc *sp = id->has_session_policy && id->session_policy_json
                       ? yyjson_read(id->session_policy_json, strlen(id->session_policy_json), 0)
                       : NULL;
  if (sp) yyjson_mut_obj_add(c, yyjson_mut_str(d, "sessionPolicy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(sp)));
  else yyjson_mut_obj_add_null(d, c, "sessionPolicy");
  yyjson_doc_free(sp);
  yyjson_mut_obj_add_strcpy(d, c, "status", id->status);
  yyjson_mut_obj_add_strcpy(d, c, "name", id->name ? id->name : "");
  yyjson_mut_obj_add_strcpy(d, c, "description", id->description ? id->description : "");
  if (buckets_iam_time_is_set(id->expiration)) sr_add_time(d, c, "expiration", iam_t(id->expiration));
  return c;
}

void buckets_sr_iam_svc_create(buckets_sr *sr, const char *access_key) {
  if (!buckets_sr_enabled(sr)) return;
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, access_key);
  if (!id) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "service-account");
  yyjson_mut_val *ch = yyjson_mut_obj_add_obj(d, root, "serviceAccountChange");
  yyjson_mut_obj_add(ch, yyjson_mut_str(d, "crSvcAccCreate"), svc_create_json(d, id));
  yyjson_mut_obj_add_null(d, ch, "crSvcAccUpdate");
  yyjson_mut_obj_add_null(d, ch, "crSvcAccDelete");
  buckets_sr_time up = iam_t(id->updated);
  buckets_iam_ident_release(id);
  iam_send(sr, d, root, up);
}

void buckets_sr_iam_svc_update(buckets_sr *sr, const char *access_key, const char *secret_key, const char *status,
                               const char *name, const char *description, const char *session_policy,
                               bool has_expiration, long long exp_sec) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "service-account");
  yyjson_mut_val *ch = yyjson_mut_obj_add_obj(d, root, "serviceAccountChange");
  yyjson_mut_obj_add_null(d, ch, "crSvcAccCreate");
  yyjson_mut_val *u = yyjson_mut_obj_add_obj(d, ch, "crSvcAccUpdate");
  yyjson_mut_obj_add_strcpy(d, u, "accessKey", access_key);
  yyjson_mut_obj_add_strcpy(d, u, "secretKey", secret_key ? secret_key : "");
  yyjson_mut_obj_add_strcpy(d, u, "status", status ? status : "");
  yyjson_mut_obj_add_strcpy(d, u, "name", name ? name : "");
  yyjson_mut_obj_add_strcpy(d, u, "description", description ? description : "");
  yyjson_doc *sp = session_policy && *session_policy ? yyjson_read(session_policy, strlen(session_policy), 0) : NULL;
  if (sp) yyjson_mut_obj_add(u, yyjson_mut_str(d, "sessionPolicy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(sp)));
  else yyjson_mut_obj_add_null(d, u, "sessionPolicy");
  yyjson_doc_free(sp);
  if (has_expiration) sr_add_time(d, u, "expiration", (buckets_sr_time){exp_sec, 0});
  yyjson_mut_obj_add_null(d, ch, "crSvcAccDelete");
  buckets_sr_time up = sr_now();
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, access_key);
  if (id) up = iam_t(id->updated);
  buckets_iam_ident_release(id);
  iam_send(sr, d, root, up);
}

void buckets_sr_iam_svc_delete(buckets_sr *sr, const char *access_key) {
  if (!buckets_sr_enabled(sr)) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "service-account");
  yyjson_mut_val *ch = yyjson_mut_obj_add_obj(d, root, "serviceAccountChange");
  yyjson_mut_obj_add_null(d, ch, "crSvcAccCreate");
  yyjson_mut_obj_add_null(d, ch, "crSvcAccUpdate");
  yyjson_mut_val *x = yyjson_mut_obj_add_obj(d, ch, "crSvcAccDelete");
  yyjson_mut_obj_add_strcpy(d, x, "accessKey", access_key);
  iam_send(sr, d, root, sr_now());
}

void buckets_sr_iam_sts(buckets_sr *sr, const char *access_key, const char *parent_policy_mapping) {
  if (!buckets_sr_enabled(sr)) return;
  buckets_iam_ident *id = buckets_iam_get_ident(sr->s->iam, access_key);
  if (!id) return;
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = iam_item(d, "sts-account");
  yyjson_mut_val *c = yyjson_mut_obj_add_obj(d, root, "stsCredential");
  yyjson_mut_obj_add_strcpy(d, c, "accessKey", id->access_key);
  yyjson_mut_obj_add_strcpy(d, c, "secretKey", id->secret_key);
  yyjson_mut_obj_add_strcpy(d, c, "sessionToken", id->session_token ? id->session_token : "");
  yyjson_mut_obj_add_strcpy(d, c, "parentUser", id->parent ? id->parent : "");
  if (parent_policy_mapping && *parent_policy_mapping)
    yyjson_mut_obj_add_strcpy(d, c, "parentPolicyMapping", parent_policy_mapping);
  buckets_sr_time up = iam_t(id->updated);
  buckets_iam_ident_release(id);
  iam_send(sr, d, root, up);
}

/* ---- applying a peer's changes ---------------------------------------------------------------- */

static int iam_type_of(int minio_type) {
  switch (minio_type) {
    case 1:
      return BUCKETS_IAM_STS;
    case 2:
      return BUCKETS_IAM_SVC;
    default:
      return BUCKETS_IAM_REG;
  }
}

static bool mapping_updated(buckets_iam *iam, const char *name, bool is_group, buckets_sr_time *out) {
  for (int t = BUCKETS_IAM_REG; t <= BUCKETS_IAM_STS; t++) {
    buckets_iam_mapping *m;
    size_t n = buckets_iam_list_mappings(iam, (buckets_iam_utype)t, is_group, &m);
    bool found = false;
    for (size_t i = 0; i < n && !found; i++) {
      if (strcmp(m[i].name, name) == 0) {
        *out = iam_t(m[i].updated);
        found = true;
      }
    }
    buckets_iam_mappings_free(m, n);
    if (found || is_group) return found;
  }
  return false;
}

static char *raw_json(yyjson_val *v) {
  if (!v || yyjson_is_null(v)) return NULL;
  return yyjson_val_write(v, 0, NULL);
}

static bool iam_ok(buckets_iam_err e, char *err, size_t errlen) {
  if (e == BUCKETS_IAM_OK) return true;
  snprintf(err, errlen, "%s", buckets_iam_strerror(e));
  return false;
}

static bool apply_svc(buckets_sr *sr, yyjson_val *ch, buckets_sr_time up, char *err, size_t errlen) {
  buckets_iam *iam = sr->s->iam;
  yyjson_val *c = yyjson_obj_get(ch, "crSvcAccCreate");
  yyjson_val *u = yyjson_obj_get(ch, "crSvcAccUpdate");
  yyjson_val *x = yyjson_obj_get(ch, "crSvcAccDelete");
  const char *ak = yyjson_is_obj(c) ? jstr(c, "accessKey") : yyjson_is_obj(u) ? jstr(u, "accessKey") : jstr(x, "accessKey");
  buckets_iam_ident *cur = *ak ? buckets_iam_get_ident(iam, ak) : NULL;
  bool newer = cur && !sr_time_is_zero(up) && sr_time_after(iam_t(cur->updated), up);
  bool exists = cur != NULL;
  buckets_iam_ident_release(cur);
  if (newer) return true;
  if (yyjson_is_obj(c)) {
    char *sp = raw_json(yyjson_obj_get(c, "sessionPolicy"));
    char *claims = raw_json(yyjson_obj_get(c, "claims"));
    buckets_iam_time exp = {0, 0};
    buckets_sr_time et = sr_get_time(c, "expiration");
    if (!sr_time_is_zero(et)) exp = (buckets_iam_time){et.sec, et.nsec};
    char perr[512] = "";
    buckets_iam_err e;
    if (exists) { /* already here (a resync): bring it up to date */
      buckets_iam_svc_update upd = {.secret_key = jstr(c, "secretKey"),
                                    .status = jstr(c, "status"),
                                    .name = jstr(c, "name"),
                                    .description = jstr(c, "description"),
                                    .expiration = buckets_iam_time_is_set(exp) ? &exp : NULL,
                                    .set_policy = true,
                                    .session_policy = sp ? sp : ""};
      e = buckets_iam_update_svc(iam, ak, &upd, perr, sizeof(perr));
    } else {
      yyjson_val *ga = yyjson_obj_get(c, "groups");
      size_t ng = yyjson_arr_size(ga);
      const char **groups = buckets_xcalloc(ng + 1, sizeof(char *));
      size_t idx, max;
      yyjson_val *g;
      yyjson_arr_foreach(ga, idx, max, g) groups[idx] = yyjson_get_str(g) ? yyjson_get_str(g) : "";
      buckets_iam_svc_opts o = {.parent = jstr(c, "parent"),
                                .groups = groups,
                                .ngroups = ng,
                                .access_key = ak,
                                .secret_key = jstr(c, "secretKey"),
                                .session_policy = sp,
                                .name = jstr(c, "name"),
                                .description = jstr(c, "description"),
                                .expiration = buckets_iam_time_is_set(exp) ? &exp : NULL,
                                .claims_json = claims};
      buckets_iam_ident *id = NULL;
      e = buckets_iam_add_svc(iam, &o, &id, perr, sizeof(perr));
      buckets_iam_ident_release(id);
      free(groups);
      const char *st = jstr(c, "status");
      if (!e && (strcmp(st, "off") == 0 || strcmp(st, "disabled") == 0)) {
        buckets_iam_svc_update upd = {.status = "off"};
        buckets_iam_update_svc(iam, ak, &upd, perr, sizeof(perr));
      }
    }
    free(sp);
    free(claims);
    if (e && *perr) {
      snprintf(err, errlen, "%s", perr);
      return false;
    }
    return iam_ok(e, err, errlen);
  }
  if (yyjson_is_obj(u)) {
    yyjson_val *spv = yyjson_obj_get(u, "sessionPolicy");
    char *sp = raw_json(spv);
    buckets_iam_time exp = {0, 0};
    buckets_sr_time et = sr_get_time(u, "expiration");
    if (!sr_time_is_zero(et)) exp = (buckets_iam_time){et.sec, et.nsec};
    buckets_iam_svc_update upd = {.secret_key = jstr(u, "secretKey"),
                                  .status = jstr(u, "status"),
                                  .name = jstr(u, "name"),
                                  .description = jstr(u, "description"),
                                  .expiration = buckets_iam_time_is_set(exp) ? &exp : NULL,
                                  .set_policy = sp != NULL,
                                  .session_policy = sp};
    char perr[512] = "";
    buckets_iam_err e = buckets_iam_update_svc(iam, ak, &upd, perr, sizeof(perr));
    free(sp);
    if (e && *perr) {
      snprintf(err, errlen, "%s", perr);
      return false;
    }
    return iam_ok(e, err, errlen);
  }
  if (yyjson_is_obj(x)) {
    buckets_iam_err e = buckets_iam_delete_svc(iam, ak);
    return e == BUCKETS_IAM_ERR_NO_SUCH_SVC || iam_ok(e, err, errlen);
  }
  return true;
}

bool sr_apply_iam_item(buckets_sr *sr, yyjson_val *item, char *err, size_t errlen) {
  buckets_iam *iam = sr->s->iam;
  const char *type = jstr(item, "type");
  buckets_sr_time up = sr_get_time(item, "updatedAt");
  if (strcmp(type, "policy") == 0) {
    const char *name = jstr(item, "name");
    buckets_iam_policy_doc doc;
    if (!sr_time_is_zero(up) && buckets_iam_get_policy(iam, name, &doc) == BUCKETS_IAM_OK) {
      bool newer = sr_time_after(iam_t(doc.updated), up);
      buckets_iam_policy_doc_free(&doc, 1);
      if (newer) return true;
    }
    yyjson_val *pv = yyjson_obj_get(item, "policy");
    bool empty = !pv || yyjson_is_null(pv) || !yyjson_arr_size(yyjson_obj_get(pv, "Statement"));
    if (empty) {
      buckets_iam_err e = buckets_iam_delete_policy(iam, name);
      return e == BUCKETS_IAM_ERR_NO_SUCH_POLICY || iam_ok(e, err, errlen);
    }
    size_t n;
    char *j = yyjson_val_write(pv, 0, &n);
    char perr[512] = "";
    buckets_iam_err e = buckets_iam_set_policy(iam, name, j, n, perr, sizeof(perr));
    free(j);
    if (e && *perr) {
      snprintf(err, errlen, "%s", perr);
      return false;
    }
    return iam_ok(e, err, errlen);
  }
  if (strcmp(type, "iam-user") == 0) {
    yyjson_val *u = yyjson_obj_get(item, "iamUser");
    if (!yyjson_is_obj(u)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    const char *ak = jstr(u, "accessKey");
    buckets_iam_ident *cur = buckets_iam_get_ident(iam, ak);
    bool newer = cur && !sr_time_is_zero(up) && sr_time_after(iam_t(cur->updated), up);
    buckets_iam_ident_release(cur);
    if (newer) return true;
    if (jbool(u, "isDeleteReq")) {
      buckets_iam_err e = buckets_iam_delete_user(iam, ak);
      return e == BUCKETS_IAM_ERR_NO_SUCH_USER || iam_ok(e, err, errlen);
    }
    yyjson_val *r = yyjson_obj_get(u, "userReq");
    if (!yyjson_is_obj(r)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    const char *status = jstr(r, "status"), *sk = jstr(r, "secretKey");
    if (*status && !*sk) return iam_ok(buckets_iam_set_user_status(iam, ak, strcmp(status, "enabled") == 0), err, errlen);
    if (buckets_iam_ldap_mode(iam)) return iam_ok(BUCKETS_IAM_ERR_NOT_ALLOWED, err, errlen);
    return iam_ok(buckets_iam_add_user(iam, ak, sk, status), err, errlen);
  }
  if (strcmp(type, "group-info") == 0) {
    yyjson_val *r = yyjson_obj_get(yyjson_obj_get(item, "groupInfo"), "updateReq");
    if (!yyjson_is_obj(r)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    const char *group = jstr(r, "group"), *status = jstr(r, "groupStatus");
    buckets_iam_group_desc gd;
    if (!sr_time_is_zero(up) && buckets_iam_group_describe(iam, group, &gd) == BUCKETS_IAM_OK) {
      bool newer = sr_time_after(iam_t(gd.updated), up);
      buckets_iam_group_desc_free(&gd);
      if (newer) return true;
    }
    yyjson_val *ma = yyjson_obj_get(r, "members");
    size_t nm = yyjson_arr_size(ma);
    const char **members = buckets_xcalloc(nm + 1, sizeof(char *));
    size_t idx, max;
    yyjson_val *m;
    yyjson_arr_foreach(ma, idx, max, m) members[idx] = yyjson_get_str(m) ? yyjson_get_str(m) : "";
    buckets_iam_err e;
    if (jbool(r, "isRemove")) {
      e = buckets_iam_group_remove_members(iam, group, members, nm);
    } else if (*status && !nm) {
      e = buckets_iam_group_set_status(iam, group, strcmp(status, "enabled") == 0);
    } else {
      e = buckets_iam_ldap_mode(iam) ? BUCKETS_IAM_ERR_NOT_ALLOWED : buckets_iam_group_add_members(iam, group, members, nm);
      if (!e && *status) e = buckets_iam_group_set_status(iam, group, strcmp(status, "enabled") == 0);
    }
    free(members);
    return e == BUCKETS_IAM_ERR_NO_SUCH_GROUP || iam_ok(e, err, errlen);
  }
  if (strcmp(type, "service-account") == 0) {
    yyjson_val *ch = yyjson_obj_get(item, "serviceAccountChange");
    if (!yyjson_is_obj(ch)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    return apply_svc(sr, ch, up, err, errlen);
  }
  if (strcmp(type, "policy-mapping") == 0) {
    yyjson_val *m = yyjson_obj_get(item, "policyMapping");
    if (!yyjson_is_obj(m)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    const char *name = jstr(m, "userOrGroup");
    bool is_group = jbool(m, "isGroup");
    buckets_sr_time cur;
    if (!sr_time_is_zero(up) && mapping_updated(iam, name, is_group, &cur) && sr_time_after(cur, up)) return true;
    int ut = (int)yyjson_get_int(yyjson_obj_get(m, "userType"));
    buckets_iam_err e = buckets_iam_policy_set(iam, name, is_group, (buckets_iam_utype)iam_type_of(ut), jstr(m, "policy"));
    return iam_ok(e, err, errlen);
  }
  if (strcmp(type, "sts-account") == 0) {
    yyjson_val *c = yyjson_obj_get(item, "stsCredential");
    if (!yyjson_is_obj(c)) {
      snprintf(err, errlen, "Invalid arguments specified");
      return false;
    }
    const char *ak = jstr(c, "accessKey");
    buckets_iam_ident *cur = buckets_iam_get_ident(iam, ak);
    bool newer = cur && !sr_time_is_zero(up) && sr_time_after(iam_t(cur->updated), up);
    buckets_iam_ident_release(cur);
    if (newer) return true;
    buckets_iam_err e = buckets_iam_set_temp_user_token(iam, ak, jstr(c, "secretKey"), jstr(c, "sessionToken"),
                                                        jstr(c, "parentUser"), NULL, 0, jstr(c, "parentPolicyMapping"));
    if (e == BUCKETS_IAM_ERR_INVALID_ARGUMENT) {
      snprintf(err, errlen, "STS credential could not be verified");
      return false;
    }
    return iam_ok(e, err, errlen);
  }
  snprintf(err, errlen, "Invalid arguments specified");
  return false;
}

bool buckets_sr_peer_iam_item(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid character in the request body");
    return false;
  }
  char err[1024] = "";
  bool ok = sr_apply_iam_item(sr, yyjson_doc_get_root(doc), err, sizeof(err));
  yyjson_doc_free(doc);
  if (!ok) sr_err(e, BUCKETS_ERR_INTERNAL_ERROR, "%s", err);
  return ok;
}

/* The bucket's configuration was changed after t. */
static bool local_newer(buckets_sr *sr, const char *bucket, buckets_bucket_cfg cfg, buckets_sr_time t) {
  if (sr_time_is_zero(t)) return false;
  buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bucket);
  bool newer = st->exists && sr_time_after(go_t(st->meta.updated[cfg]), t);
  buckets_bucket_state_release(st);
  return newer;
}

static bool set_cfg(buckets_sr *sr, const char *bucket, buckets_bucket_cfg cfg, const void *data, size_t n, char *err,
                    size_t errlen) {
  if (buckets_obj_stat_bucket(sr->s->layer, bucket) != BUCKETS_OBJ_OK) {
    snprintf(err, errlen, "Bucket not found: %s", bucket);
    return false;
  }
  if (!buckets_metasys_update(sr->s->meta, bucket, cfg, data, n)) {
    snprintf(err, errlen, "unable to update the metadata of bucket %s", bucket);
    return false;
  }
  return true;
}

/* A base64 configuration (or none, deleting it unless keep_absent). */
static bool apply_b64(buckets_sr *sr, const char *bucket, buckets_bucket_cfg cfg, yyjson_val *v, bool delete_absent,
                      buckets_sr_time up, char *err, size_t errlen) {
  const char *b64 = yyjson_get_str(v);
  if (!b64 && !delete_absent) return true;
  if (local_newer(sr, bucket, cfg, up)) return true;
  if (!b64) return set_cfg(sr, bucket, cfg, NULL, 0, err, errlen);
  size_t n = strlen(b64);
  uint8_t *dec = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(b64, n, dec);
  bool ok = k >= 0;
  if (!ok) snprintf(err, errlen, "illegal base64 data");
  else ok = set_cfg(sr, bucket, cfg, dec, (size_t)k, err, errlen);
  free(dec);
  return ok;
}

/* A JSON configuration (policy, quota), or none (deleted). */
static bool apply_raw(buckets_sr *sr, const char *bucket, buckets_bucket_cfg cfg, yyjson_val *v, buckets_sr_time up,
                      char *err, size_t errlen) {
  if (local_newer(sr, bucket, cfg, up)) return true;
  if (!v || yyjson_is_null(v)) return set_cfg(sr, bucket, cfg, NULL, 0, err, errlen);
  if (cfg == BUCKETS_BCFG_POLICY && !yyjson_arr_size(yyjson_obj_get(v, "Statement")))
    return set_cfg(sr, bucket, cfg, NULL, 0, err, errlen);
  size_t n;
  char *j = yyjson_val_write(v, 0, &n);
  bool ok = true;
  if (cfg == BUCKETS_BCFG_POLICY) {
    buckets_policy *p;
    char perr[512];
    ok = buckets_bucket_policy_parse(j, n, bucket, &p, perr, sizeof(perr));
    if (ok) buckets_policy_free(p);
    else snprintf(err, errlen, "%s", perr);
  }
  if (ok) ok = set_cfg(sr, bucket, cfg, j, n, err, errlen);
  free(j);
  return ok;
}

bool sr_apply_bucket_meta(buckets_sr *sr, yyjson_val *item, char *err, size_t errlen) {
  const char *type = jstr(item, "type"), *bucket = jstr(item, "bucket");
  buckets_sr_time up = sr_get_time(item, "updatedAt");
  if (strcmp(type, "policy") == 0) return apply_raw(sr, bucket, BUCKETS_BCFG_POLICY, yyjson_obj_get(item, "policy"), up, err, errlen);
  if (strcmp(type, "quota-config") == 0) return apply_raw(sr, bucket, BUCKETS_BCFG_QUOTA, yyjson_obj_get(item, "quota"), up, err, errlen);
  if (strcmp(type, "version-config") == 0)
    return apply_b64(sr, bucket, BUCKETS_BCFG_VERSIONING, yyjson_obj_get(item, "versioningConfig"), false, up, err, errlen);
  if (strcmp(type, "tags") == 0) return apply_b64(sr, bucket, BUCKETS_BCFG_TAGGING, yyjson_obj_get(item, "tags"), true, up, err, errlen);
  if (strcmp(type, "object-lock-config") == 0)
    return apply_b64(sr, bucket, BUCKETS_BCFG_OBJECT_LOCK, yyjson_obj_get(item, "objectLockConfig"), false, up, err, errlen);
  if (strcmp(type, "sse-config") == 0)
    return apply_b64(sr, bucket, BUCKETS_BCFG_ENCRYPTION, yyjson_obj_get(item, "sseConfig"), true, up, err, errlen);
  if (strcmp(type, "lc-config") == 0) {
    /* ILM expiry rules: taken as the bucket's lifecycle configuration */
    yyjson_val *v = yyjson_obj_get(item, "expLCConfig");
    return apply_b64(sr, bucket, BUCKETS_BCFG_LIFECYCLE, v, true, up, err, errlen);
  }
  /* PeerBucketMetadataUpdateHandler: every configuration present */
  if (!*bucket || sr_time_is_zero(up)) {
    snprintf(err, errlen, "Invalid arguments specified");
    return false;
  }
  buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bucket);
  bool skip = st->exists && sr_time_after(go_t(st->meta.created), up);
  buckets_bucket_state_release(st);
  if (skip) return true;
  bool ok = true;
  if (yyjson_obj_get(item, "policy")) ok &= apply_raw(sr, bucket, BUCKETS_BCFG_POLICY, yyjson_obj_get(item, "policy"), sr_zero_time(), err, errlen);
  if (yyjson_obj_get(item, "versioningConfig")) ok &= apply_b64(sr, bucket, BUCKETS_BCFG_VERSIONING, yyjson_obj_get(item, "versioningConfig"), false, sr_zero_time(), err, errlen);
  if (yyjson_obj_get(item, "tags")) ok &= apply_b64(sr, bucket, BUCKETS_BCFG_TAGGING, yyjson_obj_get(item, "tags"), false, sr_zero_time(), err, errlen);
  if (yyjson_obj_get(item, "objectLockConfig")) ok &= apply_b64(sr, bucket, BUCKETS_BCFG_OBJECT_LOCK, yyjson_obj_get(item, "objectLockConfig"), false, sr_zero_time(), err, errlen);
  if (yyjson_obj_get(item, "sseConfig")) ok &= apply_b64(sr, bucket, BUCKETS_BCFG_ENCRYPTION, yyjson_obj_get(item, "sseConfig"), false, sr_zero_time(), err, errlen);
  if (yyjson_obj_get(item, "quota")) ok &= apply_raw(sr, bucket, BUCKETS_BCFG_QUOTA, yyjson_obj_get(item, "quota"), sr_zero_time(), err, errlen);
  return ok;
}

bool buckets_sr_peer_bucket_meta(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!doc || !*jstr(root, "bucket")) {
    yyjson_doc_free(doc);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "Invalid arguments specified");
    return false;
  }
  char err[1024] = "";
  bool ok = sr_apply_bucket_meta(sr, root, err, sizeof(err));
  yyjson_doc_free(doc);
  if (!ok) sr_err(e, BUCKETS_ERR_INTERNAL_ERROR, "%s", err);
  return ok;
}

bool buckets_sr_peer_bucket_op(buckets_sr *sr, const char *bucket, const char *op, const char *created_at,
                               bool lock_enabled, bool versioning_enabled, bool force_create, buckets_sr_err *e) {
  (void)versioning_enabled;
  (void)force_create;
  char err[3000] = "";
  bool ok;
  if (strcmp(op, "make-with-versioning") == 0) {
    buckets_sr_time created = sr_zero_time();
    if (created_at && *created_at) sr_time_parse(created_at, &created);
    ok = sr_make_with_versioning(sr, bucket, lock_enabled, created, err, sizeof(err));
  } else if (strcmp(op, "configure-replication") == 0) {
    ok = sr_configure_repl(sr, bucket, err, sizeof(err));
  } else if (strcmp(op, "delete-bucket") == 0 || strcmp(op, "force-delete-bucket") == 0) {
    if (!buckets_sr_enabled(sr)) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "site replication is not enabled");
      return false;
    }
    ok = sr_local_delete_bucket(sr, bucket, strcmp(op, "force-delete-bucket") == 0, err, sizeof(err));
    if (!ok && strstr(err, "does not exist")) {
      sr_err(e, BUCKETS_ERR_NO_SUCH_BUCKET, "The specified bucket does not exist");
      return false;
    }
    if (!ok && strstr(err, "not empty")) {
      sr_err(e, BUCKETS_ERR_BUCKET_NOT_EMPTY, "The bucket you tried to delete is not empty");
      return false;
    }
  } else if (strcmp(op, "purge-deleted-bucket") == 0) {
    sr_purge_deleted_bucket(sr, bucket);
    ok = true;
  } else {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "Invalid arguments specified");
    return false;
  }
  if (!ok) sr_err(e, BUCKETS_ERR_INTERNAL_ERROR, "%s", err);
  return ok;
}

/* ---- the initial sync --------------------------------------------------------------------------- */

static void send_meta_all(buckets_sr *sr, const char *bucket, const char *type) {
  size_t n;
  char *j = bucket_meta_item(sr, bucket, type, &n);
  if (j && !strstr(j, "\"updatedAt\"")) {
    free(j);
    return;
  }
  if (j) broadcast(sr, "/site-replication/peer/bucket-meta", "SRPeerReplicateBucketMeta", j, n);
  free(j);
}

static void sync_to_all_peers(buckets_sr *sr, bool ilm_expiry, char *err, size_t errlen) {
  (void)ilm_expiry;
  buckets_s3_server *s = sr->s;
  buckets_bucket_info *bs;
  size_t nb;
  if (buckets_obj_list_buckets(s->layer, &bs, &nb) != BUCKETS_OBJ_OK) {
    snprintf(err, errlen, "unable to list buckets");
    return;
  }
  for (size_t i = 0; i < nb; i++) {
    const char *b = bs[i].name;
    buckets_bucket_state *st = buckets_metasys_get(s->meta, b);
    bool lock = st->lock_enabled;
    bool has[6] = {st->meta.config[BUCKETS_BCFG_POLICY].len > 0, st->meta.config[BUCKETS_BCFG_TAGGING].len > 0,
                   st->meta.config[BUCKETS_BCFG_OBJECT_LOCK].len > 0, st->meta.config[BUCKETS_BCFG_ENCRYPTION].len > 0,
                   st->meta.config[BUCKETS_BCFG_QUOTA].len > 0, false};
    buckets_bucket_state_release(st);
    char e[4096] = "";
    if (!buckets_sr_make_bucket_hook(sr, b, lock, false, e, sizeof(e))) {
      snprintf(err, errlen, "Error while configuring replication on a bucket: %s", e);
      buckets_bucket_info_free(bs, nb);
      return;
    }
    static const char *types[] = {"policy", "tags", "object-lock-config", "sse-config", "quota-config"};
    for (size_t t = 0; t < 5; t++)
      if (has[t]) send_meta_all(sr, b, types[t]);
  }
  buckets_bucket_info_free(bs, nb);

  buckets_iam *iam = s->iam;
  /* policies first */
  buckets_iam_policy_doc *docs;
  size_t np;
  buckets_iam_list_policies(iam, &docs, &np);
  for (size_t i = 0; i < np; i++) {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = iam_item(d, "policy");
    yyjson_mut_obj_add_strcpy(d, root, "name", docs[i].name);
    yyjson_doc *pd = yyjson_read(docs[i].json, strlen(docs[i].json), 0);
    if (pd) yyjson_mut_obj_add(root, yyjson_mut_str(d, "policy"), yyjson_val_mut_copy(d, yyjson_doc_get_root(pd)));
    yyjson_doc_free(pd);
    iam_send(sr, d, root, iam_t(docs[i].updated));
  }
  buckets_iam_policy_doc_free(docs, np);
  free(docs);
  /* local users */
  buckets_iam_user_info *users;
  size_t nu;
  buckets_iam_list_users(iam, &users, &nu);
  for (size_t i = 0; i < nu; i++) {
    buckets_iam_ident *id = buckets_iam_get_ident(iam, users[i].name);
    if (!id) continue;
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = iam_item(d, "iam-user");
    yyjson_mut_val *u = yyjson_mut_obj_add_obj(d, root, "iamUser");
    yyjson_mut_obj_add_strcpy(d, u, "accessKey", id->access_key);
    yyjson_mut_obj_add_bool(d, u, "isDeleteReq", false);
    yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, u, "userReq");
    yyjson_mut_obj_add_strcpy(d, r, "secretKey", id->secret_key);
    yyjson_mut_obj_add_strcpy(d, r, "status", strcmp(id->status, "off") == 0 ? "off" : "on");
    buckets_sr_time up = iam_t(id->updated);
    buckets_iam_ident_release(id);
    iam_send(sr, d, root, up);
  }
  buckets_iam_user_info_free(users, nu);
  free(users);
  /* groups */
  char **groups;
  size_t ng;
  buckets_iam_list_groups(iam, &groups, &ng);
  for (size_t i = 0; i < ng; i++) {
    buckets_iam_group_desc gd;
    if (buckets_iam_group_describe(iam, groups[i], &gd) == BUCKETS_IAM_OK) {
      yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *root = iam_item(d, "group-info");
      yyjson_mut_val *r = yyjson_mut_obj_add_obj(d, yyjson_mut_obj_add_obj(d, root, "groupInfo"), "updateReq");
      yyjson_mut_obj_add_strcpy(d, r, "group", groups[i]);
      yyjson_mut_val *m = yyjson_mut_obj_add_arr(d, r, "members");
      for (size_t k = 0; k < gd.nmembers; k++) yyjson_mut_arr_add_strcpy(d, m, gd.members[k]);
      yyjson_mut_obj_add_strcpy(d, r, "groupStatus", gd.status ? gd.status : "");
      yyjson_mut_obj_add_bool(d, r, "isRemove", false);
      iam_send(sr, d, root, iam_t(gd.updated));
      buckets_iam_group_desc_free(&gd);
    }
    free(groups[i]);
  }
  free(groups);
  /* group mappings, service accounts, user and STS mappings */
  static const struct {
    buckets_iam_utype t;
    bool group;
    int minio_type;
  } maps[] = {{BUCKETS_IAM_REG, true, -1}};
  for (size_t k = 0; k < 1; k++) {
    buckets_iam_mapping *m;
    size_t n = buckets_iam_list_mappings(iam, maps[k].t, maps[k].group, &m);
    for (size_t i = 0; i < n; i++) {
      yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *root = iam_item(d, "policy-mapping");
      yyjson_mut_val *pm = yyjson_mut_obj_add_obj(d, root, "policyMapping");
      yyjson_mut_obj_add_strcpy(d, pm, "userOrGroup", m[i].name);
      yyjson_mut_obj_add_int(d, pm, "userType", maps[k].minio_type);
      yyjson_mut_obj_add_bool(d, pm, "isGroup", true);
      yyjson_mut_obj_add_strcpy(d, pm, "policy", m[i].policies);
      iam_send(sr, d, root, iam_t(m[i].updated));
    }
    buckets_iam_mappings_free(m, n);
  }
  buckets_iam_ident **svcs;
  size_t nsv;
  buckets_iam_list_derived(iam, NULL, BUCKETS_IAM_SVC, &svcs, &nsv);
  for (size_t i = 0; i < nsv; i++) {
    if (strcmp(svcs[i]->access_key, BUCKETS_SR_SVC_ACCOUNT) != 0) {
      yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *root = iam_item(d, "service-account");
      yyjson_mut_val *ch = yyjson_mut_obj_add_obj(d, root, "serviceAccountChange");
      yyjson_mut_obj_add(ch, yyjson_mut_str(d, "crSvcAccCreate"), svc_create_json(d, svcs[i]));
      yyjson_mut_obj_add_null(d, ch, "crSvcAccUpdate");
      yyjson_mut_obj_add_null(d, ch, "crSvcAccDelete");
      iam_send(sr, d, root, iam_t(svcs[i]->updated));
    }
    buckets_iam_ident_release(svcs[i]);
  }
  free(svcs);
  static const struct {
    buckets_iam_utype t;
    int minio_type;
  } umaps[] = {{BUCKETS_IAM_REG, 0}, {BUCKETS_IAM_STS, 1}};
  for (size_t k = 0; k < 2; k++) {
    buckets_iam_mapping *m;
    size_t n = buckets_iam_list_mappings(iam, umaps[k].t, false, &m);
    for (size_t i = 0; i < n; i++) {
      yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
      yyjson_mut_val *root = iam_item(d, "policy-mapping");
      yyjson_mut_val *pm = yyjson_mut_obj_add_obj(d, root, "policyMapping");
      yyjson_mut_obj_add_strcpy(d, pm, "userOrGroup", m[i].name);
      yyjson_mut_obj_add_int(d, pm, "userType", umaps[k].minio_type);
      yyjson_mut_obj_add_bool(d, pm, "isGroup", false);
      yyjson_mut_obj_add_strcpy(d, pm, "policy", m[i].policies);
      iam_send(sr, d, root, iam_t(m[i].updated));
    }
    buckets_iam_mappings_free(m, n);
  }
}

/* ---- leaving ------------------------------------------------------------------------------------ */

/* RemoveRemoteTargetsForEndpoint: the replication targets (and rules) to
 * the given endpoints, or all of them with unlink_self. */
static bool remove_targets_for(buckets_sr *sr, char **endpoints, size_t ne, bool unlink_self, char *err,
                               size_t errlen) {
  buckets_s3_server *s = sr->s;
  buckets_bucket_info *bs;
  size_t nb;
  if (buckets_obj_list_buckets(s->layer, &bs, &nb) != BUCKETS_OBJ_OK) {
    snprintf(err, errlen, "unable to list buckets");
    return false;
  }
  bool ok = true;
  for (size_t i = 0; i < nb && ok; i++) {
    const char *b = bs[i].name;
    buckets_bucket_state *st = buckets_metasys_get(s->meta, b);
    /* the ARNs going away */
    char **arns = buckets_xcalloc(st->targets.n + 1, sizeof(char *));
    size_t na = 0;
    for (size_t t = 0; t < st->targets.n; t++) {
      const buckets_bucket_target *tg = &st->targets.t[t];
      if (strcmp(tg->type, "replication") != 0) continue;
      bool match = unlink_self;
      for (size_t k = 0; k < ne && !match; k++) {
        char host[512];
        bool secure;
        if (endpoint_host(endpoints[k], host, sizeof(host), &secure))
          match = strcmp(tg->endpoint, host) == 0 && tg->secure == secure;
      }
      if (match) arns[na++] = tg->arn;
    }
    if (st->has_replication) {
      buckets_repl_rule *keep = buckets_xcalloc(st->replication.n + 1, sizeof(*keep));
      size_t k = 0;
      for (size_t r = 0; r < st->replication.n; r++) {
        bool drop = false;
        for (size_t a = 0; a < na && !drop; a++) drop = strcmp(st->replication.rules[r].dest_bucket, arns[a]) == 0;
        if (!drop) keep[k++] = st->replication.rules[r];
      }
      if (k != st->replication.n) {
        if (k) {
          buckets_replication tmp = {keep, k, st->replication.role};
          buckets_buf x = BUCKETS_BUF_INIT;
          buckets_replication_xml(&tmp, &x);
          ok = buckets_metasys_update(s->meta, b, BUCKETS_BCFG_REPLICATION, x.data, x.len);
          buckets_buf_free(&x);
        } else {
          ok = buckets_metasys_update(s->meta, b, BUCKETS_BCFG_REPLICATION, NULL, 0);
        }
      }
      free(keep);
    }
    if (ok && na) {
      buckets_bucket_targets ts = {0};
      ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
      for (size_t t = 0; t < st->targets.n; t++) {
        bool drop = false;
        for (size_t a = 0; a < na && !drop; a++) drop = strcmp(st->targets.t[t].arn, arns[a]) == 0;
        if (!drop) buckets_bucket_target_copy(&ts.t[ts.n++], &st->targets.t[t]);
      }
      buckets_buf j = BUCKETS_BUF_INIT;
      buckets_bucket_targets_json(&ts, &j);
      ok = buckets_metasys_update_targets(s->meta, b, j.data, j.len);
      buckets_buf_free(&j);
      buckets_bucket_targets_free(&ts);
    }
    free(arns);
    buckets_bucket_state_release(st);
    if (!ok) snprintf(err, errlen, "unable to update the replication configuration of bucket %s", b);
  }
  buckets_bucket_info_free(bs, nb);
  return ok;
}

typedef struct {
  char **names;
  size_t n;
  bool all;
  char *requesting;
} remove_req;

static void remove_req_free(remove_req *r) {
  for (size_t i = 0; i < r->n; i++) free(r->names[i]);
  free(r->names);
  free(r->requesting);
}

static bool remove_req_parse(const char *json, size_t n, remove_req *r) {
  memset(r, 0, sizeof(*r));
  yyjson_doc *doc = yyjson_read(json, n, 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(doc);
    return false;
  }
  r->requesting = buckets_xstrdup(jstr(root, "requestingDepID"));
  r->all = jbool(root, "all");
  yyjson_val *a = yyjson_obj_get(root, "sites");
  r->names = buckets_xcalloc(yyjson_arr_size(a) + 1, sizeof(char *));
  size_t idx, max;
  yyjson_val *v;
  yyjson_arr_foreach(a, idx, max, v) r->names[r->n++] = buckets_xstrdup(yyjson_get_str(v) ? yyjson_get_str(v) : "");
  yyjson_doc_free(doc);
  return true;
}

static void remove_status(buckets_buf *out, const char *status, const char *detail) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "status", status);
  if (detail && *detail) yyjson_mut_obj_add_strcpy(d, root, "errorDetail", detail);
  size_t n;
  char *j = mut_json(d, &n);
  buckets_buf_append(out, j, n);
  free(j);
  yyjson_mut_doc_free(d);
}

typedef struct {
  const char *json;
  size_t n;
} remove_job;

static bool remove_peer(buckets_sr *sr, const buckets_sr_peer *p, void *ud, char *err, size_t errlen) {
  remove_job *j = ud;
  char e[1024];
  bool ok = sr_peer_call(sr, p->deployment_id, "PUT", "/site-replication/peer/remove", NULL, j->json, j->n, NULL, e,
                         sizeof(e));
  if (!ok && strstr(e, "unable to find site replication configuration")) ok = true; /* already removed */
  if (!ok) snprintf(err, errlen, "unable to update peer %s: %s", p->name, e);
  return ok;
}

bool buckets_sr_remove(buckets_sr *sr, const char *json, size_t n, buckets_buf *out, buckets_sr_err *e) {
  if (!buckets_sr_enabled(sr)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "site replication is not enabled");
    return false;
  }
  remove_req r;
  if (!remove_req_parse(json, n, &r)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid remove request");
    return false;
  }
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = false;
  bool *removed = buckets_xcalloc(s.npeers + 1, sizeof(bool));
  char **eps = buckets_xcalloc(s.npeers + r.n + 1, sizeof(char *));
  size_t ne = 0;
  for (size_t i = 0; i < s.npeers; i++) removed[i] = r.all;
  for (size_t k = 0; k < r.n; k++) {
    bool found = false;
    for (size_t i = 0; i < s.npeers; i++) {
      if (strcmp(s.peers[i].name, r.names[k]) == 0) {
        removed[i] = true;
        found = true;
      }
    }
    if (!found) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_CONFIG_MISSING, "unable to find site replication configuration");
      goto out;
    }
  }
  for (size_t i = 0; i < s.npeers; i++)
    if (removed[i]) eps[ne++] = s.peers[i].endpoint;
  /* tell the peers (with our deployment as the requester), and unlink here */
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_strcpy(d, root, "requestingDepID", sr_self_id(sr));
  yyjson_mut_val *a = yyjson_mut_obj_add_arr(d, root, "sites");
  for (size_t k = 0; k < r.n; k++) yyjson_mut_arr_add_strcpy(d, a, r.names[k]);
  yyjson_mut_obj_add_bool(d, root, "all", r.all);
  size_t jl;
  char *j = mut_json(d, &jl);
  yyjson_mut_doc_free(d);
  remove_job job = {j, jl};
  char perr[4096] = "";
  bool peers_ok = conc_do(sr, &s, NULL, remove_peer, &job, "SRPeerRemove", perr, sizeof(perr));
  free(j);
  char lerr[1024] = "";
  bool self_ok = remove_targets_for(sr, eps, ne, false, lerr, sizeof(lerr));
  if (!peers_ok && !r.all && !self_ok) {
    remove_status(out, REMOVE_PARTIAL, perr);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_PEER_RESP, "%s", perr);
    goto out;
  }
  const char *detail = !self_ok ? lerr : !peers_ok ? perr : "";
  if (r.all) {
    ok = state_save(sr, NULL, NULL, 0, NULL, sr_zero_time());
    if (!ok) remove_status(out, REMOVE_PARTIAL, "unable to remove cluster-replication state on local");
    else remove_status(out, *detail ? REMOVE_PARTIAL : REMOVE_SUCCESS, detail);
    ok = true;
    goto out;
  }
  size_t left = 0;
  for (size_t i = 0; i < s.npeers; i++) left += !removed[i];
  buckets_sr_peer *np = buckets_xcalloc(left + 1, sizeof(*np));
  size_t k = 0;
  for (size_t i = 0; i < s.npeers; i++)
    if (!removed[i]) peer_copy(&np[k++], &s.peers[i]);
  bool saved = left > 1 ? state_save(sr, s.name, np, k, s.svc_ak, s.updated)
                        : (peers_free(np, k), state_save(sr, NULL, NULL, 0, NULL, sr_zero_time()));
  if (!saved) {
    remove_status(out, REMOVE_PARTIAL, "unable to save cluster-replication state on local");
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "unable to save cluster-replication state on local");
    goto out;
  }
  remove_status(out, *detail ? REMOVE_PARTIAL : REMOVE_SUCCESS, detail);
  ok = true;
out:
  free(eps);
  free(removed);
  sr_snapshot_free(&s);
  remove_req_free(&r);
  return ok;
}

bool buckets_sr_peer_remove(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e) {
  if (!buckets_sr_enabled(sr)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "site replication is not enabled");
    return false;
  }
  remove_req r;
  if (!remove_req_parse(json, n, &r)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid remove request");
    return false;
  }
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = false;
  if (*r.requesting && !sr_snapshot_peer(&s, r.requesting)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "requesting site not found in site replication config");
    goto out;
  }
  const char *self = sr_self_id(sr);
  bool *removed = buckets_xcalloc(s.npeers + 1, sizeof(bool));
  char **eps = buckets_xcalloc(s.npeers + 1, sizeof(char *));
  size_t ne = 0;
  bool unlink_self = false;
  for (size_t i = 0; i < s.npeers; i++) {
    bool rm = r.all;
    for (size_t k = 0; k < r.n && !rm; k++) rm = strcmp(s.peers[i].name, r.names[k]) == 0;
    if (!rm) continue;
    if (strcmp(s.peers[i].deployment_id, self) == 0) {
      unlink_self = true;
      continue;
    }
    removed[i] = true;
    eps[ne++] = s.peers[i].endpoint;
  }
  for (size_t k = 0; k < r.n; k++) {
    bool found = false;
    for (size_t i = 0; i < s.npeers && !found; i++) found = strcmp(s.peers[i].name, r.names[k]) == 0;
    if (!found) {
      free(removed);
      free(eps);
      sr_err(e, BUCKETS_ERR_INTERNAL_ERROR, "unable to find site replication configuration");
      goto out;
    }
  }
  char err[1024] = "";
  if (!remove_targets_for(sr, eps, ne, unlink_self, err, sizeof(err))) {
    free(removed);
    free(eps);
    sr_err(e, BUCKETS_ERR_INTERNAL_ERROR, "%s", err);
    goto out;
  }
  if (unlink_self) {
    ok = state_save(sr, NULL, NULL, 0, NULL, sr_zero_time());
  } else {
    buckets_sr_peer *np = buckets_xcalloc(s.npeers + 1, sizeof(*np));
    size_t k = 0;
    for (size_t i = 0; i < s.npeers; i++)
      if (!removed[i]) peer_copy(&np[k++], &s.peers[i]);
    ok = state_save(sr, s.name, np, k, s.svc_ak, sr_zero_time());
  }
  free(removed);
  free(eps);
  if (!ok) sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "unable to save cluster-replication state to drive on %s", s.name);
out:
  sr_snapshot_free(&s);
  remove_req_free(&r);
  return ok;
}

/* ---- editing ------------------------------------------------------------------------------------- */

static void edit_status(buckets_buf *out, bool success, const char *status, const char *detail) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_bool(d, root, "success", success);
  yyjson_mut_obj_add_strcpy(d, root, "status", status);
  if (detail && *detail) yyjson_mut_obj_add_strcpy(d, root, "errorDetail", detail);
  size_t n;
  char *j = mut_json(d, &n);
  buckets_buf_append(out, j, n);
  free(j);
  yyjson_mut_doc_free(d);
}

/* Points the replication targets for a peer at its new endpoint, sync mode and bandwidth. */
static void update_targets_for_peer(buckets_sr *sr, const buckets_sr_peer *peer) {
  buckets_bucket_info *bs;
  size_t nb;
  if (buckets_obj_list_buckets(sr->s->layer, &bs, &nb) != BUCKETS_OBJ_OK) return;
  for (size_t i = 0; i < nb; i++) {
    char err[1024];
    sr_configure_repl(sr, bs[i].name, err, sizeof(err));
    buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bs[i].name);
    buckets_bucket_targets ts = {0};
    ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
    bool changed = false;
    for (size_t t = 0; t < st->targets.n; t++) {
      buckets_bucket_target_copy(&ts.t[ts.n], &st->targets.t[t]);
      buckets_bucket_target *tg = &ts.t[ts.n++];
      if (!tg->deployment_id || strcmp(tg->deployment_id, peer->deployment_id) != 0) continue;
      bool want_sync = strcmp(peer->sync, "enable") == 0;
      if (*peer->sync && tg->replication_sync != want_sync) {
        tg->replication_sync = want_sync;
        changed = true;
      }
      if (peer->bw_set && tg->bandwidth_limit != (int64_t)peer->bw_limit) {
        tg->bandwidth_limit = (int64_t)peer->bw_limit;
        changed = true;
      }
    }
    if (changed) {
      buckets_buf j = BUCKETS_BUF_INIT;
      buckets_bucket_targets_json(&ts, &j);
      buckets_metasys_update_targets(sr->s->meta, bs[i].name, j.data, j.len);
      buckets_buf_free(&j);
    }
    buckets_bucket_targets_free(&ts);
    buckets_bucket_state_release(st);
  }
  buckets_bucket_info_free(bs, nb);
}

/* Applies an edited PeerInfo to the state (merging what is set). */
static bool merge_peer(buckets_sr_peer *cur, const buckets_sr_peer *in) {
  bool changed = false;
  if (*in->endpoint && strcmp(in->endpoint, cur->endpoint) != 0) {
    free(cur->endpoint);
    cur->endpoint = buckets_xstrdup(in->endpoint);
    changed = true;
  }
  if (*in->sync && strcmp(in->sync, cur->sync) != 0) {
    snprintf(cur->sync, sizeof(cur->sync), "%s", in->sync);
    changed = true;
  }
  if (in->bw_set && (in->bw_limit != cur->bw_limit || !cur->bw_set)) {
    cur->bw_limit = in->bw_limit;
    cur->bw_set = true;
    cur->bw_updated = sr_time_is_zero(in->bw_updated) ? sr_now() : in->bw_updated;
    changed = true;
  }
  return changed;
}

bool buckets_sr_peer_edit(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid edit request");
    return false;
  }
  buckets_sr_peer in;
  peer_parse(yyjson_doc_get_root(doc), NULL, &in);
  yyjson_doc_free(doc);
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = false;
  buckets_sr_peer *np = buckets_xcalloc(s.npeers + 1, sizeof(*np));
  bool found = false, changed = false;
  for (size_t i = 0; i < s.npeers; i++) {
    peer_copy(&np[i], &s.peers[i]);
    if (strcmp(np[i].deployment_id, in.deployment_id) == 0) {
      found = true;
      changed = merge_peer(&np[i], &in);
    }
  }
  if (!found) {
    peers_free(np, s.npeers);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "peer not found");
    goto out;
  }
  if (!changed) {
    peers_free(np, s.npeers);
    ok = true;
    goto out;
  }
  buckets_sr_peer edited;
  for (size_t i = 0; i < s.npeers; i++)
    if (strcmp(np[i].deployment_id, in.deployment_id) == 0) peer_copy(&edited, &np[i]);
  ok = state_save(sr, s.name, np, s.npeers, s.svc_ak, sr_now());
  if (ok && strcmp(in.deployment_id, sr_self_id(sr)) != 0) update_targets_for_peer(sr, &edited);
  peer_free(&edited);
  if (!ok) sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "unable to save cluster-replication state");
out:
  peer_free(&in);
  sr_snapshot_free(&s);
  return ok;
}

bool buckets_sr_edit(buckets_sr *sr, const char *json, size_t n, bool disable_ilm, bool enable_ilm,
                     buckets_buf *out, buckets_sr_err *e) {
  if (!buckets_sr_enabled(sr)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "site replication is not enabled");
    return false;
  }
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid edit request");
    return false;
  }
  buckets_sr_peer in;
  peer_parse(yyjson_doc_get_root(doc), NULL, &in);
  yyjson_doc_free(doc);
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = false;
  if (disable_ilm || enable_ilm) {
    /* every peer's replicate-ilm-expiry flag, told to all sites by state edits */
    buckets_sr_peer *np = buckets_xcalloc(s.npeers + 1, sizeof(*np));
    for (size_t i = 0; i < s.npeers; i++) {
      peer_copy(&np[i], &s.peers[i]);
      np[i].replicate_ilm_expiry = enable_ilm;
    }
    buckets_sr_time now = sr_now();
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *root = yyjson_mut_obj(d);
    yyjson_mut_doc_set_root(d, root);
    yyjson_mut_obj_add(root, yyjson_mut_str(d, "peers"), peers_json(d, np, s.npeers));
    sr_add_time(d, root, "updatedAt", now);
    size_t jl;
    char *j = mut_json(d, &jl);
    yyjson_mut_doc_free(d);
    send_job job = {"/site-replication/state/edit", j, jl, "SiteReplicationEdit"};
    char err[4096] = "";
    bool peers_ok = conc_do(sr, &s, NULL, send_peer, &job, "SiteReplicationEdit", err, sizeof(err));
    free(j);
    ok = state_save(sr, s.name, np, s.npeers, s.svc_ak, now);
    edit_status(out, ok && peers_ok, ok && peers_ok ? "Cluster replication configuration updated successfully."
                                                     : "Unable to update cluster replication configuration.",
                peers_ok ? "" : err);
    ok = true;
    goto out;
  }
  const buckets_sr_peer *cur = sr_snapshot_peer(&s, in.deployment_id);
  if (!cur) {
    for (size_t i = 0; i < s.npeers && !cur; i++)
      if (strcmp(s.peers[i].name, in.name) == 0) cur = &s.peers[i];
  }
  if (!cur) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "unable to find site replication configuration");
    goto out;
  }
  free(in.deployment_id);
  in.deployment_id = buckets_xstrdup(cur->deployment_id);
  /* the new endpoint must be the same deployment */
  if (*in.endpoint && strcmp(in.endpoint, cur->endpoint) != 0) {
    char err[1024];
    buckets_buf b = BUCKETS_BUF_INIT;
    char *ak = NULL, *sk = NULL;
    bool same = svc_creds(sr, s.svc_ak, &ak, &sk) &&
                sr_endpoint_call(sr, in.endpoint, ak, sk, "GET", "/info", NULL, NULL, 0, &b, err, sizeof(err));
    if (same) {
      yyjson_doc *id = yyjson_read(b.data ? b.data : "", b.len, 0);
      same = strcmp(jstr(yyjson_doc_get_root(id), "deploymentID"), cur->deployment_id) == 0;
      yyjson_doc_free(id);
    }
    free(ak);
    free(sk);
    buckets_buf_free(&b);
    if (!same) {
      sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "unable to validate the endpoint %s for site %s",
             in.endpoint, cur->name);
      goto out;
    }
  }
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(d, peer_json(d, &in));
  size_t jl;
  char *j = mut_json(d, &jl);
  yyjson_mut_doc_free(d);
  send_job job = {"/site-replication/peer/edit", j, jl, "SiteReplicationEdit"};
  char err[4096] = "";
  bool peers_ok = conc_do(sr, &s, NULL, send_peer, &job, "SiteReplicationEdit", err, sizeof(err));
  buckets_sr_err le;
  bool self_ok = buckets_sr_peer_edit(sr, j, jl, &le);
  free(j);
  edit_status(out, peers_ok && self_ok,
              peers_ok && self_ok ? "Cluster replication configuration updated successfully."
                                  : "Unable to update cluster replication configuration.",
              !self_ok ? le.message : peers_ok ? "" : err);
  ok = true;
out:
  peer_free(&in);
  sr_snapshot_free(&s);
  return ok;
}

bool buckets_sr_state_edit(buckets_sr *sr, const char *json, size_t n, buckets_sr_err *e) {
  yyjson_doc *doc = yyjson_read(json, n, 0);
  yyjson_val *root = yyjson_doc_get_root(doc);
  if (!yyjson_is_obj(root)) {
    yyjson_doc_free(doc);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid state edit request");
    return false;
  }
  buckets_sr_time up = sr_get_time(root, "updatedAt");
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = true;
  if (!sr_time_after(s.updated, up)) { /* PeerStateEditReq: only a newer state */
    buckets_sr_peer *in;
    size_t nin;
    peers_parse(yyjson_obj_get(root, "peers"), &in, &nin);
    buckets_sr_peer *np = buckets_xcalloc(s.npeers + 1, sizeof(*np));
    for (size_t i = 0; i < s.npeers; i++) {
      peer_copy(&np[i], &s.peers[i]);
      for (size_t k = 0; k < nin; k++)
        if (strcmp(in[k].deployment_id, np[i].deployment_id) == 0) np[i].replicate_ilm_expiry = in[k].replicate_ilm_expiry;
    }
    peers_free(in, nin);
    ok = state_save(sr, s.name, np, s.npeers, s.svc_ak, up);
    if (!ok) sr_err(e, BUCKETS_ERR_SITE_REPLICATION_BACKEND_ISSUE, "unable to save cluster-replication state");
  }
  sr_snapshot_free(&s);
  yyjson_doc_free(doc);
  return ok;
}

/* ---- resync ---------------------------------------------------------------------------------------- */

bool buckets_sr_resync_op(buckets_sr *sr, const char *json, size_t n, const char *op, buckets_buf *out,
                          buckets_sr_err *e) {
  if (!buckets_sr_enabled(sr)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "site replication is not enabled");
    return false;
  }
  yyjson_doc *doc = yyjson_read(json, n, 0);
  if (!doc) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid resync request");
    return false;
  }
  buckets_sr_peer in;
  peer_parse(yyjson_doc_get_root(doc), NULL, &in);
  yyjson_doc_free(doc);
  bool start = strcmp(op, "start") == 0;
  if (!start && strcmp(op, "cancel") != 0) {
    peer_free(&in);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "Invalid arguments specified");
    return false;
  }
  if (strcmp(in.deployment_id, sr_self_id(sr)) == 0) {
    peer_free(&in);
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "invalid peer specified - cannot resync to self");
    return false;
  }
  sr_snapshot s;
  sr_snapshot_take(sr, &s);
  bool ok = false;
  if (!sr_snapshot_peer(&s, in.deployment_id)) {
    sr_err(e, BUCKETS_ERR_SITE_REPLICATION_INVALID_REQUEST, "peer not found");
    goto done;
  }
  char resync_id[40];
  buckets_uuid_v4(resync_id);
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, root);
  yyjson_mut_obj_add_str(d, root, "op", op);
  yyjson_mut_obj_add_strcpy(d, root, "id", resync_id);
  yyjson_mut_val *arr = yyjson_mut_obj_add_arr(d, root, "buckets");
  buckets_bucket_info *bs;
  size_t nb = 0;
  if (buckets_obj_list_buckets(sr->s->layer, &bs, &nb) != BUCKETS_OBJ_OK) nb = 0, bs = NULL;
  size_t failed = 0;
  for (size_t i = 0; i < nb; i++) {
    buckets_bucket_state *st = buckets_metasys_get(sr->s->meta, bs[i].name);
    const char *arn = NULL;
    for (size_t t = 0; t < st->targets.n && !arn; t++)
      if (st->targets.t[t].deployment_id && strcmp(st->targets.t[t].deployment_id, in.deployment_id) == 0)
        arn = st->targets.t[t].arn;
    yyjson_mut_val *b = yyjson_mut_arr_add_obj(d, arr);
    yyjson_mut_obj_add_strcpy(d, b, "bucket", bs[i].name);
    char err[512] = "";
    int rc = -1;
    if (!arn) snprintf(err, sizeof(err), "no valid remote target found for this peer %s (%s)", in.name, in.deployment_id);
    else if (start) rc = buckets_repl_resync_start(sr->s->repl, bs[i].name, arn, resync_id, 0, err, sizeof(err));
    else rc = 0; /* cancel: nothing queued survives a restart; report it canceled */
    if (rc == 0) {
      yyjson_mut_obj_add_str(d, b, "status", start ? "Ongoing" : "Canceled");
    } else {
      failed++;
      yyjson_mut_obj_add_str(d, b, "status", "Failed");
      yyjson_mut_obj_add_strcpy(d, b, "errorDetail", err);
    }
    buckets_bucket_state_release(st);
  }
  buckets_bucket_info_free(bs, nb);
  yyjson_mut_obj_add_str(d, root, "status", failed ? "Failed" : "Success");
  size_t jl;
  char *j = mut_json(d, &jl);
  buckets_buf_append(out, j, jl);
  free(j);
  yyjson_mut_doc_free(d);
  ok = true;
done:
  sr_snapshot_free(&s);
  peer_free(&in);
  return ok;
}
