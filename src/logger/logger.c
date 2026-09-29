/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "logger/logger.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/utsname.h>

#include "core/common.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "notify/event.h"
#include <time.h>

struct buckets_logger {
  pthread_rwlock_t lock;
  buckets_http_target **log, **audit;
  size_t nlog, naudit;
};

buckets_logger *buckets_logger_new(void) {
  buckets_logger *l = buckets_xcalloc(1, sizeof(*l));
  pthread_rwlock_init(&l->lock, NULL);
  return l;
}

static void free_targets(buckets_http_target **t, size_t n) {
  for (size_t i = 0; i < n; i++) buckets_http_target_free(t[i]);
  free(t);
}

void buckets_logger_free(buckets_logger *l) {
  if (!l) return;
  free_targets(l->log, l->nlog);
  free_targets(l->audit, l->naudit);
  pthread_rwlock_destroy(&l->lock);
  free(l);
}

static char *get(const buckets_config *cfg, const char *subsys, const char *target, const char *key) {
  char *v = buckets_config_get(cfg, subsys, target, key);
  return v ? v : buckets_xstrdup("");
}

/* getUserAgent: "Buckets (<os>; <arch>) Buckets/<version>" */
static void user_agent(char *out, size_t cap) {
  struct utsname u;
  const char *os = "unknown", *arch = "unknown";
  if (uname(&u) == 0) os = u.sysname, arch = u.machine;
  char low[64];
  size_t i = 0;
  for (; os[i] && i + 1 < sizeof(low); i++) low[i] = (char)(os[i] >= 'A' && os[i] <= 'Z' ? os[i] + 32 : os[i]);
  low[i] = '\0';
  snprintf(out, cap, "Buckets (%s; %s) Buckets/%s", low, arch, BUCKETS_VERSION);
}

/* lookupLoggerWebhookConfig / lookupAuditWebhookConfig: the enabled targets
 * of subsys, validated; built into *out when out is not NULL. */
static bool build(const buckets_config *cfg, const char *subsys, const char *prefix, const char *ca_file,
                  const char *deployment_id, buckets_http_target ***out, size_t *nout, char *err, size_t errlen) {
  if (!buckets_config_check_valid_keys(cfg, subsys, err, errlen)) return false;
  char **names;
  size_t nn = buckets_config_targets(cfg, subsys, &names);
  bool ok = true;
  char ua[160];
  user_agent(ua, sizeof(ua));
  for (size_t j = 0; j < nn && ok; j++) {
    const char *tg = names[j];
    char *en = get(cfg, subsys, tg, "enable");
    int on = buckets_config_parse_bool(en);
    free(en);
    if (on != 1) continue;
    char *endpoint = get(cfg, subsys, tg, "endpoint"), *token = get(cfg, subsys, tg, "auth_token");
    char *cert = get(cfg, subsys, tg, "client_cert"), *key = get(cfg, subsys, tg, "client_key");
    char *qsize = get(cfg, subsys, tg, "queue_size"), *bsize = get(cfg, subsys, tg, "batch_size");
    char *qdir = get(cfg, subsys, tg, "queue_dir"), *mretry = get(cfg, subsys, tg, "max_retry");
    char *rint = get(cfg, subsys, tg, "retry_interval"), *hto = get(cfg, subsys, tg, "http_timeout");
    char *end;
    long queue_size = strtol(qsize, &end, 10);
    bool qs_ok = *qsize && !*end;
    long batch_size = strtol(bsize, &end, 10);
    bool bs_ok = *bsize && !*end;
    long max_retry = strtol(mretry, &end, 10);
    bool mr_ok = *mretry && !*end;
    int64_t retry_ns = 3000000000LL, timeout_ns = 5000000000LL;
    if (strncasecmp(endpoint, "http://", 7) != 0 && strncasecmp(endpoint, "https://", 8) != 0) {
      snprintf(err, errlen, "unexpected scheme found %s", endpoint);
      ok = false;
    } else if (!*cert != !*key) {
      snprintf(err, errlen, "%s", *cert ? "client_key must be set when client_cert is set" : "client_cert must be set when client_key is set");
      ok = false;
    } else if (!qs_ok) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", qsize);
      ok = false;
    } else if (queue_size <= 0) {
      snprintf(err, errlen, "invalid queue_size value");
      ok = false;
    } else if (!bs_ok) {
      snprintf(err, errlen, "strconv.Atoi: parsing \"%s\": invalid syntax", bsize);
      ok = false;
    } else if (batch_size <= 0) {
      snprintf(err, errlen, "invalid batch_size value");
      ok = false;
    } else if (!mr_ok || max_retry < 0) {
      snprintf(err, errlen, "invalid %s max_retry", mretry);
      ok = false;
    } else if (*rint && !buckets_go_duration_parse(rint, &retry_ns)) {
      buckets_go_duration_error(rint, err, errlen);
      ok = false;
    } else if (retry_ns > 60000000000LL) {
      snprintf(err, errlen, "maximum allowed value for retry interval is '1m': %s", rint);
      ok = false;
    } else if (*hto && !buckets_go_duration_parse(hto, &timeout_ns)) {
      buckets_go_duration_error(hto, err, errlen);
      ok = false;
    } else if (timeout_ns < 1000000000LL) {
      snprintf(err, errlen, "minimum value allowed for http_timeout is '1s': %s", hto);
      ok = false;
    }
    if (ok && *cert) buckets_log_warn("%s: client certificates are not supported yet; connecting without one", subsys);
    if (ok && out) {
      char name[160];
      snprintf(name, sizeof(name), "%s%s", prefix, tg);
      buckets_http_target_cfg tc = {
          .name = name,
          .endpoint = endpoint,
          .auth_token = token,
          .ca_file = ca_file,
          .user_agent = ua,
          .deployment_id = deployment_id,
          .batch_size = (int)batch_size,
          .queue_size = (int)queue_size,
          .queue_dir = qdir,
          .max_retry = (int)max_retry,
          .retry_interval_ms = (int)(retry_ns / 1000000),
          .http_timeout_ms = (int)(timeout_ns / 1000000),
      };
      buckets_http_target *t = buckets_http_target_new(&tc, err, errlen);
      if (!t) ok = false;
      else {
        *out = buckets_xrealloc(*out, (*nout + 1) * sizeof(**out));
        (*out)[(*nout)++] = t;
      }
    }
    free(endpoint), free(token), free(cert), free(key), free(qsize), free(bsize);
    free(qdir), free(mretry), free(rint), free(hto);
  }
  for (size_t j = 0; j < nn; j++) free(names[j]);
  free(names);
  return ok;
}

bool buckets_logger_validate(const buckets_config *cfg, char *err, size_t errlen) {
  return build(cfg, "logger_webhook", "logger-", NULL, NULL, NULL, NULL, err, errlen) &&
         build(cfg, "audit_webhook", "audit-", NULL, NULL, NULL, NULL, err, errlen);
}

bool buckets_logger_configure(buckets_logger *l, const buckets_config *cfg, const char *subsys, const char *ca_file,
                              const char *deployment_id, char *err, size_t errlen) {
  bool do_log = !subsys || !*subsys || strcmp(subsys, "logger_webhook") == 0;
  bool do_audit = !subsys || !*subsys || strcmp(subsys, "audit_webhook") == 0;
  buckets_http_target **nl = NULL, **na = NULL;
  size_t nnl = 0, nna = 0;
  bool ok = true;
  if (do_log) ok = build(cfg, "logger_webhook", "logger-", ca_file, deployment_id, &nl, &nnl, err, errlen);
  if (ok && do_audit) ok = build(cfg, "audit_webhook", "audit-", ca_file, deployment_id, &na, &nna, err, errlen);
  if (!ok) {
    free_targets(nl, nnl);
    free_targets(na, nna);
    return false;
  }
  pthread_rwlock_wrlock(&l->lock);
  buckets_http_target **ol = NULL, **oa = NULL;
  size_t nol = 0, noa = 0;
  if (do_log) {
    ol = l->log, nol = l->nlog;
    l->log = nl, l->nlog = nnl;
  }
  if (do_audit) {
    oa = l->audit, noa = l->naudit;
    l->audit = na, l->naudit = nna;
  }
  pthread_rwlock_unlock(&l->lock);
  free_targets(ol, nol);
  free_targets(oa, noa);
  return true;
}

bool buckets_logger_audit_enabled(buckets_logger *l) {
  if (!l) return false;
  pthread_rwlock_rdlock(&l->lock);
  bool on = l->naudit > 0;
  pthread_rwlock_unlock(&l->lock);
  return on;
}

static void send_all(buckets_logger *l, bool audit, const char *json, size_t n) {
  if (!l) return;
  pthread_rwlock_rdlock(&l->lock);
  buckets_http_target **t = audit ? l->audit : l->log;
  size_t k = audit ? l->naudit : l->nlog;
  for (size_t i = 0; i < k; i++) buckets_http_target_send(t[i], json, n);
  pthread_rwlock_unlock(&l->lock);
}

void buckets_logger_audit(buckets_logger *l, const char *json, size_t n) { send_all(l, true, json, n); }
void buckets_logger_log(buckets_logger *l, const char *json, size_t n) { send_all(l, false, json, n); }

size_t buckets_logger_targets(buckets_logger *l, buckets_logger_target_info **out) {
  *out = NULL;
  if (!l) return 0;
  pthread_rwlock_rdlock(&l->lock);
  size_t n = l->nlog + l->naudit;
  buckets_logger_target_info *v = buckets_xcalloc(n ? n : 1, sizeof(*v));
  for (size_t i = 0; i < n; i++) {
    buckets_http_target *t = i < l->nlog ? l->log[i] : l->audit[i - l->nlog];
    snprintf(v[i].name, sizeof(v[i].name), "%s", buckets_http_target_name(t));
    snprintf(v[i].endpoint, sizeof(v[i].endpoint), "%s", buckets_http_target_endpoint(t));
    v[i].audit = i >= l->nlog;
    buckets_http_target_stats_get(t, &v[i].st);
  }
  pthread_rwlock_unlock(&l->lock);
  *out = v;
  return n;
}

void buckets_logger_entry_json(const char *deployment_id, buckets_log_level level, const char *msg, size_t n,
                               buckets_buf *b) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  char when[64];
  buckets_time_rfc3339_nano((long long)now.tv_sec, now.tv_nsec, when);
  /* buildLogEntry without a request: API "SYSTEM", a request ID from the time */
  buckets_buf_append_c(b, "{");
  if (deployment_id && *deployment_id) {
    buckets_buf_append_c(b, "\"deploymentid\":");
    buckets_json_go_string(b, deployment_id, strlen(deployment_id));
    buckets_buf_append_char(b, ',');
  }
  buckets_buf_appendf(b, "\"level\":\"%s\",\"time\":\"%s\",\"api\":{\"name\":\"SYSTEM\",\"args\":{}},\"requestID\":\"%llX\",\"message\":",
                      level >= BUCKETS_LOG_ERROR ? "ERROR" : "WARNING", when,
                      (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec);
  buckets_json_go_string(b, msg, n);
  buckets_buf_append_char(b, '}');
}
