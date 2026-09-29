/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/server.h"
#include "logger/console.h"
#include "logger/logger.h"
#include "notify/event.h"
#include "trace/trace.h"
#include "metrics/stats.h"
#include "s3/metrics.h"
#include "notify/notifier.h"

#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <time.h>

#include "core/auditctx.h"
#include "core/log.h"
#include "core/query.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/md5.h"
#include "crypto/sha256.h"
#include "admin/admin.h"
#include "admin/info.h"
#include "config/sys.h"
#include "iam/openid.h"
#include "iam/ldapidp.h"
#include "iam/plugins.h"
#include "bucket/metadata.h"
#include "bucket/metasys.h"
#include "kms/kms.h"
#include "bucket/objectlock.h"
#include "s3/compress.h"
#include "s3/sse.h"
#include "scanner/scanner.h"
#include "scanner/usage.h"
#include "dist/peer.h"
#include "s3/bucketname.h"
#include "s3/errors.h"
#include "s3/sigv4.h"
#include "s3/internal.h"
#include "s3/replicate.h"
#include "siterepl/siterepl.h"
#include "s3/tiering.h"
#include "s3/batch.h"
#include "s3/datamove.h"
#include "tier/tier.h"
#include "s3/sigv2.h"
#include "s3/xml.h"

#define DEFAULT_REGION "us-east-1"


static void notify_iam(void *ud, const char *kind, const char *name) {
  buckets_s3_server *s = ud;
  if (s->peers) buckets_peer_notify_iam(s->peers, kind, name);
}

static void notify_bucket(void *ud, const char *bucket) {
  buckets_s3_server *s = ud;
  if (s->peers) buckets_peer_notify_bucket(s->peers, bucket);
}

void buckets_s3_service(buckets_s3_server *s, const char *action, bool local) {
  if (local && s->peers) buckets_peer_notify_iam(s->peers, "service", action);
  if (strcmp(action, "freeze") == 0 || strcmp(action, "unfreeze") == 0) {
    pthread_mutex_lock(&s->freeze_mu);
    if (strcmp(action, "freeze") == 0) {
      s->freeze_cnt++;
    } else if (s->freeze_cnt > 0 && --s->freeze_cnt == 0) {
      pthread_cond_broadcast(&s->freeze_cv);
    }
    pthread_mutex_unlock(&s->freeze_mu);
    buckets_log_info("service: S3 API %s", strcmp(action, "freeze") == 0 ? "frozen" : "unfrozen");
  } else if (s->service) {
    s->service(s->service_ud, action);
  }
}

void buckets_s3_peer_iam(void *server, const char *kind, const char *name) {
  buckets_s3_server *s = server;
  if (strcmp(kind, "service") == 0) {
    buckets_s3_service(s, name, false);
    return;
  }
  if (strcmp(kind, "config") == 0) {
    if (s->config) buckets_config_sys_reload(s->config);
    return;
  }
  if (strcmp(kind, "tier") == 0) {
    if (s->tiers) buckets_tiers_reload(s->tiers);
    return;
  }
  if (strcmp(kind, "site-replication") == 0) {
    buckets_sr_reload(s->sr);
    return;
  }
  if (strcmp(kind, "pool-meta") == 0) {
    if (s->datamove) buckets_datamove_reload_pool_meta(s->datamove);
    return;
  }
  if (strcmp(kind, "rebalance-meta") == 0) {
    if (s->datamove) buckets_datamove_reload_rebalance(s->datamove, strcmp(name, "start") == 0);
    return;
  }
  if (strcmp(kind, "rebalance-stop") == 0) {
    if (s->datamove) buckets_datamove_stop_rebalance(s->datamove);
    return;
  }
  if (strcmp(kind, "batch-cancel") == 0) {
    if (s->batch) buckets_batch_cancel(s->batch, name, false);
    return;
  }
  buckets_iam_on_notify(s->iam, kind, name);
}

/* ---- OpenID providers ---- */

static const char *g_region = ""; /* for role ARNs built while validating a config */

buckets_openid *buckets_s3_openid(buckets_s3_server *s) {
  pthread_mutex_lock(&s->oidc_mu);
  buckets_openid *o = buckets_openid_ref(s->openid);
  pthread_mutex_unlock(&s->oidc_mu);
  return o;
}

buckets_plugins *buckets_s3_plugins(buckets_s3_server *s) {
  pthread_mutex_lock(&s->oidc_mu);
  buckets_plugins *p = buckets_plugins_ref(s->plugins);
  pthread_mutex_unlock(&s->oidc_mu);
  return p;
}

buckets_ldapidp *buckets_s3_ldap(buckets_s3_server *s) {
  pthread_mutex_lock(&s->oidc_mu);
  buckets_ldapidp *p = buckets_ldapidp_ref(s->ldap);
  pthread_mutex_unlock(&s->oidc_mu);
  return p;
}

static const char *g_ca_path;

/* mc admin config set identity_ldap: the directory must be usable. */
static bool validate_ldap(const buckets_config *cfg, char *err, size_t errlen) {
  buckets_ldapidp *p = buckets_ldapidp_build(cfg, g_ca_path, err, errlen);
  buckets_ldapidp_release(p);
  return p != NULL;
}

/* identity_ldap is read once, before IAM starts (it decides how users are
 * stored); like MinIO, keep trying until the directory can be used. */
static void init_ldap(buckets_s3_server *s) {
  int delay_ms = 250;
  for (;;) {
    buckets_config *cfg = buckets_config_sys_snapshot(s->config);
    char err[1024];
    buckets_ldapidp *p = buckets_ldapidp_build(cfg, s->ca_path, err, sizeof(err));
    buckets_config_free(cfg);
    if (p) {
      pthread_mutex_lock(&s->oidc_mu);
      s->ldap = p;
      pthread_mutex_unlock(&s->oidc_mu);
      if (buckets_ldapidp_enabled(p)) buckets_log_info("identity_ldap: LDAP configured; users are LDAP DNs");
      buckets_iam_set_ldap_mode(s->iam, buckets_ldapidp_enabled(p));
      return;
    }
    buckets_log_warn("identity_ldap: unable to load the LDAP configuration: %s; retrying", err);
    struct timespec ts = {delay_ms / 1000, (delay_ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    if (delay_ms < 3000) delay_ms *= 2;
  }
}

/* purgeExpiredCredentialsForLDAP + updateGroupMembershipsForLDAP: drop the
 * credentials of users no longer in the directory, and bring the groups of
 * the others' credentials up to date. */
static void ldap_sync(buckets_s3_server *s) {
  buckets_ldapidp *p = buckets_s3_ldap(s);
  if (!buckets_ldapidp_enabled(p)) {
    buckets_ldapidp_release(p);
    return;
  }
  buckets_iam_ident **creds = NULL;
  size_t ncreds = 0;
  for (int t = 0; t < 2; t++) {
    buckets_iam_ident **l;
    size_t n;
    buckets_iam_list_derived(s->iam, NULL, t ? BUCKETS_IAM_SVC : BUCKETS_IAM_STS, &l, &n);
    creds = buckets_xrealloc(creds, (ncreds + n + 1) * sizeof(*creds));
    memcpy(creds + ncreds, l, n * sizeof(*l));
    ncreds += n;
    free(l);
  }
  /* 1. users gone from the directory (asking with the actual DN) */
  char **dns = NULL;
  size_t ndns = 0;
  for (size_t i = 0; i < ncreds; i++) {
    const char *parent = creds[i]->parent;
    if (!parent || !buckets_ldapidp_is_user_dn(p, parent)) continue;
    const char *ask = buckets_iam_ident_claim(creds[i], "ldapActualUser");
    if (!ask) ask = parent;
    bool seen = false;
    for (size_t k = 0; k < ndns && !seen; k++) seen = strcmp(dns[k], ask) == 0;
    if (seen) continue;
    dns = buckets_xrealloc(dns, (ndns + 1) * sizeof(char *));
    dns[ndns++] = buckets_xstrdup(ask);
  }
  char err[1024];
  char **gone = NULL;
  size_t ngone = 0;
  if (ndns && !buckets_ldapidp_non_eligible(p, dns, ndns, &gone, &ngone, err, sizeof(err))) {
    buckets_log_warn("ldap sync: %s", err);
  } else if (ngone) {
    buckets_log_info("ldap sync: removing the credentials of %zu user%s no longer in the directory", ngone,
                     ngone == 1 ? "" : "s");
    buckets_iam_delete_users(s->iam, gone, ngone);
  }
  /* 2. group memberships of the remaining ones */
  for (size_t i = 0; i < ncreds; i++) {
    buckets_iam_ident *c = creds[i];
    const char *parent = c->parent;
    bool removed = false;
    for (size_t k = 0; parent && k < ngone && !removed; k++) removed = strcmp(gone[k], parent) == 0;
    if (!parent || removed || buckets_iam_ident_is_expired(c) || !buckets_ldapidp_is_user_dn(p, parent)) continue;
    const char *user = buckets_iam_ident_claim(c, "ldapUsername"), *actual = buckets_iam_ident_claim(c, "ldapActualUser");
    if (!user || !actual) continue;
    char **groups;
    size_t ng;
    if (!buckets_ldapidp_user_groups(p, user, actual, &groups, &ng, err, sizeof(err))) {
      buckets_log_warn("ldap sync: %s", err);
      break;
    }
    bool same = ng == c->ngroups;
    for (size_t k = 0; same && k < ng; k++) {
      bool found = false;
      for (size_t j = 0; j < c->ngroups && !found; j++) found = strcmp(groups[k], c->groups[j]) == 0;
      same = found;
    }
    if (!same && buckets_iam_set_groups(s->iam, c->access_key, groups, ng) == BUCKETS_IAM_OK)
      buckets_log_info("ldap sync: groups of %s updated", c->access_key);
    buckets_ldap_strv_free(groups, ng);
  }
  buckets_ldap_strv_free(gone, ngone);
  buckets_ldap_strv_free(dns, ndns);
  for (size_t i = 0; i < ncreds; i++) buckets_iam_ident_release(creds[i]);
  free(creds);
  buckets_ldapidp_release(p);
}

/* Sleeps up to ms; false when the server is stopping. */
static bool bg_sleep(buckets_s3_server *s, long ms) {
  struct timespec until;
  clock_gettime(CLOCK_REALTIME, &until);
  until.tv_sec += ms / 1000;
  until.tv_nsec += (ms % 1000) * 1000000L;
  if (until.tv_nsec >= 1000000000L) {
    until.tv_sec++;
    until.tv_nsec -= 1000000000L;
  }
  pthread_mutex_lock(&s->bg_mu);
  while (!s->bg_stop && pthread_cond_timedwait(&s->bg_cv, &s->bg_mu, &until) == 0) {
  }
  bool stop = s->bg_stop;
  pthread_mutex_unlock(&s->bg_mu);
  return !stop;
}

static void *ldap_sync_main(void *arg) {
  buckets_s3_server *s = arg;
  const char *env = getenv("BUCKETS_LDAP_SYNC_INTERVAL");
  int interval = env && atoi(env) > 0 ? atoi(env) : 3600; /* MinIO: once an hour */
  while (bg_sleep(s, interval * 1000L)) ldap_sync(s);
  return NULL;
}

static void rebuild_plugins(buckets_s3_server *s) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  buckets_plugins *p = buckets_plugins_build(cfg, s->region, false, err, sizeof(err));
  buckets_config_free(cfg);
  if (!p) {
    buckets_log_error("plugins: %s", err);
    return;
  }
  if (buckets_authz_plugin_enabled(p)) buckets_log_info("policy_plugin: authorization is delegated to the plugin");
  if (buckets_idp_plugin_enabled(p)) buckets_log_info("identity_plugin: AssumeRoleWithCustomToken enabled");
  pthread_mutex_lock(&s->oidc_mu);
  buckets_plugins *old = s->plugins;
  s->plugins = p;
  pthread_mutex_unlock(&s->oidc_mu);
  buckets_plugins_release(old);
}

static bool validate_plugins(const buckets_config *cfg, char *err, size_t errlen) {
  buckets_plugins *p = buckets_plugins_build(cfg, g_region, true, err, errlen);
  buckets_plugins_release(p);
  return p != NULL;
}

static bool authz_hook(void *ud, const buckets_iam_ident *id, bool owner, const buckets_policy_args *a, bool *allowed) {
  buckets_plugins *p = buckets_s3_plugins(ud);
  bool handled = buckets_authz_plugin_enabled(p);
  if (handled) {
    char *claims = id && id->claims ? yyjson_write(id->claims, 0, NULL) : NULL;
    *allowed = buckets_authz_plugin_allowed(p, id ? id->access_key : "", id ? id->groups : NULL,
                                            id ? id->ngroups : 0, owner, a, claims);
    free(claims);
  }
  buckets_plugins_release(p);
  return handled;
}

static void rebuild_openid(buckets_s3_server *s) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  buckets_openid *o = buckets_openid_build(cfg, s->region, err, sizeof(err));
  buckets_config_free(cfg);
  if (!o) {
    buckets_log_error("identity_openid: %s", err);
    return;
  }
  if (buckets_openid_enabled(o)) buckets_log_info("identity_openid: OpenID configured");
  pthread_mutex_lock(&s->oidc_mu);
  buckets_openid *old = s->openid;
  s->openid = o;
  pthread_mutex_unlock(&s->oidc_mu);
  buckets_openid_release(old);
}

/* mc admin config set identity_openid: the providers must be reachable. */
static bool validate_openid(const buckets_config *cfg, char *err, size_t errlen) {
  buckets_openid *o = buckets_openid_build(cfg, g_region, err, errlen);
  buckets_openid_release(o);
  return o != NULL;
}

static char *oidc_claim_name(void *ud) {
  buckets_openid *o = buckets_s3_openid(ud);
  char *n = buckets_xstrdup(buckets_openid_claim_name(o));
  buckets_openid_release(o);
  return n;
}

static char *oidc_role_policy(void *ud, const char *arn) {
  buckets_openid *o = buckets_s3_openid(ud);
  const char *p = o ? buckets_openid_role_policy(o, arn) : NULL;
  char *r = p ? buckets_xstrdup(p) : NULL;
  buckets_openid_release(o);
  if (!r) { /* the identity plugin's role */
    buckets_plugins *pl = buckets_s3_plugins(ud);
    const char *parn = buckets_idp_plugin_role_arn(pl);
    if (parn && strcmp(parn, arn) == 0) r = buckets_xstrdup(buckets_idp_plugin_role_policy(pl));
    buckets_plugins_release(pl);
  }
  return r;
}

/* Server messages: warnings and errors to the logger webhooks, and all of
 * them to the console log (mc admin logs) as log.Info records. */
static void log_sink(void *ud, buckets_log_level level, const char *msg, size_t n) {
  buckets_s3_server *s = ud;
  buckets_objlayer *L = s->layer;
  const char *node = s->cluster && s->cluster->self ? s->cluster->self : "";
  buckets_buf e = BUCKETS_BUF_INIT, info = BUCKETS_BUF_INIT;
  if (level >= BUCKETS_LOG_WARN) {
    buckets_logger_entry_json(L ? L->deployment_id_str : "", level, msg, n, &e);
    buckets_logger_log(s->logger, e.data, e.len);
    buckets_buf_append(&info, e.data, e.len - 1); /* the entry's fields, then Info's own */
    buckets_buf_append_c(&info, ",\"ConsoleMsg\":\"\",\"node\":");
  } else { /* a plain console message: the entry's fields empty */
    buckets_buf_append_c(&info, "{\"level\":\"\",\"time\":\"0001-01-01T00:00:00Z\",\"ConsoleMsg\":");
    buckets_json_go_string(&info, msg, n);
    buckets_buf_append_c(&info, ",\"node\":");
  }
  buckets_json_go_string(&info, node, strlen(node));
  buckets_buf_append_char(&info, '}');
  uint32_t mask = level >= BUCKETS_LOG_ERROR ? BUCKETS_LOGMASK_ERROR : level >= BUCKETS_LOG_WARN ? BUCKETS_LOGMASK_WARNING
                                                                                               : BUCKETS_LOGMASK_ALL;
  buckets_console_add(mask, level >= BUCKETS_LOG_WARN, node, info.data, info.len);
  buckets_buf_free(&e);
  buckets_buf_free(&info);
}

static void configure_logger(buckets_s3_server *s, const char *subsys) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  buckets_objlayer *L = s->layer;
  if (!buckets_logger_configure(s->logger, cfg, subsys, s->ca_path, L ? L->deployment_id_str : "", err, sizeof(err)))
    buckets_log_error("logger: %s", err);
  buckets_config_free(cfg);
}

static void configure_notify(buckets_s3_server *s) {
  buckets_config *cfg = buckets_config_sys_snapshot(s->config);
  char err[512];
  if (!buckets_notifier_configure(s->notifier, cfg, s->ca_path, err, sizeof(err)))
    buckets_log_error("notify: %s", err);
  buckets_config_free(cfg);
}

static void config_changed(void *ud, const char *subsys, bool local) {
  buckets_s3_server *s = ud;
  if (!*subsys || strcmp(subsys, "identity_openid") == 0) rebuild_openid(s);
  if (!*subsys || strcmp(subsys, "policy_plugin") == 0 || strcmp(subsys, "policy_opa") == 0 ||
      strcmp(subsys, "identity_plugin") == 0) {
    rebuild_plugins(s);
  }
  if (!*subsys || strncmp(subsys, "notify_", 7) == 0) configure_notify(s);
  if (!*subsys || strcmp(subsys, "logger_webhook") == 0 || strcmp(subsys, "audit_webhook") == 0 ||
      strcmp(subsys, "audit_kafka") == 0)
    configure_logger(s, subsys);
  if (local && s->peers) buckets_peer_notify_iam(s->peers, "config", *subsys ? subsys : "all");
}

void buckets_s3_peer_bucket(void *server, const char *bucket) {
  buckets_s3_server *s = server;
  if (s->meta) buckets_metasys_invalidate(s->meta, bucket);
}

char *buckets_s3_peer_server_info(void *server) { return buckets_admin_local_server_json(server); }

void buckets_s3_peer_admin(void *server, const buckets_http_request *req, const buckets_query *q,
                           buckets_http_response *resp) {
  buckets_admin_peer(server, req, q, resp);
}

void buckets_s3_peer_datamove(void *server, const buckets_query *q, int *status, buckets_buf *body) {
  buckets_s3_server *s = server;
  const char *op = buckets_query_get(q, "op");
  if (!s->datamove || !op) {
    *status = 503;
    return;
  }
  buckets_datamove_result r;
  buckets_datamove_op(s->datamove, op, q, true, &r);
  *status = r.status;
  if (r.status >= 300) {
    buckets_buf_append_c(body, "{\"Code\":");
    buckets_json_go_string(body, r.code, strlen(r.code));
    buckets_buf_append_c(body, ",\"Message\":");
    buckets_json_go_string(body, r.message, strlen(r.message));
    buckets_buf_append_c(body, "}");
  } else {
    buckets_buf_append(body, r.body.data, r.body.len);
  }
  buckets_buf_free(&r.body);
}

char *buckets_s3_peer_batch_metrics(void *server) {
  buckets_s3_server *s = server;
  buckets_buf b = BUCKETS_BUF_INIT;
  if (s->batch) buckets_batch_metrics_json(s->batch, NULL, &b);
  else buckets_buf_append_c(&b, "{}");
  return buckets_buf_detach(&b);
}

char *buckets_s3_peer_tier_stats(void *server) {
  buckets_s3_server *s = server;
  buckets_tier_day *d;
  size_t n = buckets_tiering_day_stats(s->tiering, &d);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_tier_days_json(d, n, &b);
  free(d);
  return buckets_buf_detach(&b);
}

void buckets_s3_server_init(buckets_s3_server *s, buckets_objlayer *layer, const char *root_user,
                            const char *root_password, const char *region) {
  memset(s, 0, sizeof(*s));
  s->root_user = root_user;
  s->root_password = root_password;
  s->region = region ? region : "";
  s->iam = buckets_iam_new(root_user, root_password);
  buckets_iam_set_notify(s->iam, notify_iam, s);
  s->config = buckets_config_sys_new(root_user, root_password);
  char kerr[256];
  s->kms = buckets_kms_from_env(kerr, sizeof(kerr));
  if (!s->kms && *kerr) buckets_fatal("%s", kerr);
  if (s->kms) buckets_log_info("kms: %s, default key %s", buckets_kms_type(s->kms), buckets_kms_default_key(s->kms));
  buckets_config_sys_set_hook(s->config, config_changed, s);
  pthread_mutex_init(&s->oidc_mu, NULL);
  pthread_mutex_init(&s->freeze_mu, NULL);
  pthread_cond_init(&s->freeze_cv, NULL);
  pthread_mutex_init(&s->bg_mu, NULL);
  pthread_cond_init(&s->bg_cv, NULL);
  g_region = s->region;
  buckets_config_register_validator("identity_openid", validate_openid);
  buckets_config_register_validator("identity_ldap", validate_ldap);
  buckets_config_register_validator("policy_plugin", validate_plugins);
  buckets_config_register_validator("identity_plugin", validate_plugins);
  s->notifier = buckets_notifier_new();
  s->logger = buckets_logger_new();
  buckets_log_set_sink(log_sink, s);
  buckets_audit_internal_set(buckets_s3_audit_internal, s);
  buckets_config_register_validator("logger_webhook", buckets_logger_validate);
  buckets_config_register_validator("audit_webhook", buckets_logger_validate);
  buckets_config_register_validator("audit_kafka", buckets_logger_validate_kafka);
  static const char *const notify_subsys[] = {"notify_webhook", "notify_kafka", "notify_amqp", "notify_mqtt",
                                              "notify_nats", "notify_nsq", "notify_redis", "notify_postgres",
                                              "notify_mysql", "notify_elasticsearch"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(notify_subsys); i++)
    buckets_config_register_validator(notify_subsys[i], buckets_notifier_validate);
  buckets_iam_set_authz(s->iam, authz_hook, s);
  buckets_iam_openid_hooks hooks = {oidc_claim_name, oidc_role_policy, s};
  buckets_iam_set_openid_hooks(s->iam, &hooks);
  if (layer) buckets_s3_server_set_layer(s, layer);
}

/* Loads IAM once the object layer is up, retrying while it lacks quorum
 * (other servers still starting); then refreshes it periodically. */
static void *iam_start_main(void *arg) {
  buckets_s3_server *s = arg;
  int delay_ms = 250;
  /* The configuration first: identity providers come from it. */
  char err[512];
  while (!buckets_config_sys_load(s->config, s->layer, err, sizeof(err))) {
    buckets_log_warn("config: %s; retrying", err);
    if (!bg_sleep(s, delay_ms)) return NULL;
    if (delay_ms < 5000) delay_ms *= 2;
  }
  rebuild_openid(s);
  rebuild_plugins(s);
  configure_notify(s);
  configure_logger(s, NULL);
  g_ca_path = s->ca_path;
  init_ldap(s);
  delay_ms = 250;
  while (!buckets_iam_start(s->iam, s->layer)) {
    buckets_log_warn("iam: unable to load IAM data yet, retrying");
    if (!bg_sleep(s, delay_ms)) return NULL;
    if (delay_ms < 5000) delay_ms *= 2;
  }
  pthread_mutex_lock(&s->bg_mu);
  bool stopping = s->bg_stop;
  pthread_mutex_unlock(&s->bg_mu);
  if (stopping) return NULL;
  const char *env = getenv("BUCKETS_IAM_REFRESH_INTERVAL");
  if (!env) env = getenv("MINIO_IAM_REFRESH_INTERVAL");
  int interval = env ? atoi(env) : 600;
  buckets_iam_start_refresh(s->iam, interval > 0 ? interval : 600);
  if (buckets_iam_ldap_mode(s->iam)) s->ldap_thread_started = pthread_create(&s->ldap_thread, NULL, ldap_sync_main, s) == 0;
  return NULL;
}

static uint64_t usage_of(void *ud, const char *bucket) {
  return buckets_usage_cache_bucket_size(ud, bucket);
}

/* `scanner speed` (MINIO_SCANNER_SPEED): the cycle of scanner.LookupConfig. */
static int scanner_cycle_seconds(void *ud) {
  buckets_s3_server *s = ud;
  char *speed = s->config ? buckets_config_sys_value(s->config, "scanner", "", "speed") : NULL;
  int secs = 60;
  if (speed && strcmp(speed, "fastest") == 0) secs = 1;
  else if (speed && strcmp(speed, "slowest") == 0) secs = 30 * 60;
  free(speed);
  return secs;
}

static int64_t scanner_actual_size(void *ud, const buckets_object_info *oi) {
  (void)ud;
  return buckets_s3_actual_size(oi);
}

static bool scanner_versioned(void *ud, const char *bucket, const char *object) {
  bool enabled, suspended;
  s3_ctx c = {.s = ud, .bucket = (char *)bucket};
  buckets_s3_versioning(&c, object, &enabled, &suspended);
  return enabled || suspended;
}

/* Evaluator.IsObjectLocked: a legal hold, or retention not yet over. */
static bool version_locked(const buckets_object_info *oi, int64_t now_ns) {
  const char *hold = buckets_object_meta(oi, BUCKETS_LOCK_HOLD_META);
  if (hold && strcmp(hold, "ON") == 0) return true;
  const char *mode = buckets_object_meta(oi, BUCKETS_LOCK_MODE_META);
  const char *until = buckets_object_meta(oi, BUCKETS_LOCK_UNTIL_META);
  long long sec;
  long nsec;
  if (mode && (strcmp(mode, "COMPLIANCE") == 0 || strcmp(mode, "GOVERNANCE") == 0) && until &&
      buckets_time_parse_rfc3339(until, &sec, &nsec))
    return sec * 1000000000LL + nsec > now_ns;
  return false;
}

static const char *const k_lc_action_names[] = {
    "NoneAction",           "DeleteAction",         "DeleteVersionAction",         "TransitionAction",
    "TransitionVersionAction", "DeleteRestoredAction", "DeleteRestoredVersionAction", "DeleteAllVersionsAction",
    "DelMarkerDeleteAllVersionsAction"};

/* What applyExpiryOnNonTransitionedObjects reports of one expiry: on
 * success an ILMExpiry audit entry (lcAuditEvent tags, the deleted version)
 * and an ilm:expiry trace (the same tags, the matched version); otherwise a
 * trace only, as MinIO's traceFn calls from their own source lines. */
static void ilm_report(buckets_s3_server *s, const char *bucket, const buckets_object_info *oi, const char *oi_vid,
                       const buckets_lc_event *e, int64_t start_ns, buckets_obj_err err, const char *deleted_vid) {
  bool found = err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION;
  const char *keys[6], *values[6];
  size_t n = 0;
  char due[BUCKETS_TIME_AMZ_LEN + 1];
  if (!err) {
    keys[n] = "ilm-src", values[n++] = "Scanner";
    keys[n] = "ilm-action", values[n++] = (size_t)e->action < BUCKETS_ARRAY_LEN(k_lc_action_names) ? k_lc_action_names[e->action] : "";
    keys[n] = "ilm-rule-id", values[n++] = e->rule_id ? e->rule_id : "";
    if (e->due_ns) {
      buckets_time_amz((time_t)(e->due_ns / 1000000000LL), due);
      keys[n] = "ilm-due", values[n++] = due;
    }
    if (e->storage_class && *e->storage_class) keys[n] = "ilm-tier", values[n++] = e->storage_class;
    keys[n] = "version-id", values[n++] = deleted_vid ? deleted_vid : "";
    buckets_audit_internal("ilm:expiry", "ILMExpiry", bucket, oi->name, deleted_vid, NULL, keys, values, n);
  }
  if (!buckets_trace_wanted(BUCKETS_TRACE_ILM)) return;
  /* ilmTrace: version-id is the matched version's */
  if (!err) values[n - 1] = oi_vid;
  else keys[0] = "version-id", values[0] = oi_vid, n = 1;
  size_t ord[6];
  for (size_t i = 0; i < n; i++) {
    size_t j = i;
    for (; j > 0 && strcmp(keys[ord[j - 1]], keys[i]) > 0; j--) ord[j] = ord[j - 1];
    ord[j] = i;
  }
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t dur = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec - start_ns;
  char when[64];
  buckets_time_rfc3339_nano((long long)(start_ns / 1000000000LL), (long)(start_ns % 1000000000LL), when);
  buckets_buf b = BUCKETS_BUF_INIT, path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "%s/%s", bucket, oi->name);
  buckets_buf_appendf(&b, "{\"type\":%u,\"nodename\":", (unsigned)BUCKETS_TRACE_ILM);
  const char *node = buckets_trace_node();
  buckets_json_go_string(&b, node, strlen(node));
  buckets_buf_appendf(&b, ",\"funcname\":\"ilm:expiry\",\"time\":\"%s\",\"path\":", when);
  buckets_json_go_string(&b, path.data, path.len);
  buckets_buf_appendf(&b, ",\"dur\":%lld", (long long)dur);
  int64_t sz = oi->delete_marker ? 0 : buckets_s3_actual_size(oi);
  if (sz > 0) buckets_buf_appendf(&b, ",\"bytes\":%lld", (long long)sz);
  if (err && found) {
    buckets_buf msg = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&msg, "DeleteObject(%s, %s): %s", bucket, oi->name, buckets_obj_strerror(err));
    buckets_buf_append_c(&b, ",\"error\":");
    buckets_json_go_string(&b, msg.data, msg.len);
    buckets_buf_free(&msg);
  }
  buckets_buf_appendf(&b, ",\"msg\":\"[data-scanner.go:%d:applyExpiryOnNonTransitionedObjects()]\",\"custom\":{",
                      !err ? 1283 : found ? 1272 : 1266);
  for (size_t i = 0; i < n; i++) {
    if (i) buckets_buf_append_char(&b, ',');
    buckets_json_go_string(&b, keys[ord[i]], strlen(keys[ord[i]]));
    buckets_buf_append_char(&b, ':');
    buckets_json_go_string(&b, values[ord[i]], strlen(values[ord[i]]));
  }
  buckets_buf_append_c(&b, "}}");
  buckets_trace_meta m = {.type = BUCKETS_TRACE_ILM, .dur_ns = dur};
  buckets_trace_publish(&m, b.data, b.len);
  buckets_buf_free(&b);
  buckets_buf_free(&path);
}

static int64_t wall_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

/* The expiry of one matched version (NULL version_id: the object's latest). */
static bool expire(buckets_s3_server *s, const char *bucket, const buckets_object_info *oi, const char *oi_vid,
                   const buckets_lc_event *e, const char *version_id, bool enabled, bool suspended,
                   buckets_delete_result *r) {
  int64_t start = wall_ns();
  buckets_delete_opts o = {.version_id = version_id, .versioned = enabled, .suspended = suspended};
  /* expireTransitionedObject: the remote copy first; once it is gone no free
   * version is needed (a version really removed, not hidden by a marker) */
  const char *remote, *rver, *tier = buckets_object_tier(oi, &remote, &rver);
  if (tier && (version_id || (!enabled && !suspended)) && buckets_tiering_remove_remote_now(s, tier, remote, rver))
    o.skip_free_version = true;
  buckets_obj_err err = buckets_obj_delete_ex(s->layer, bucket, oi->name, &o, r);
  if (err && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION)
    buckets_log_warn("lifecycle: expiring %s/%s: %s", bucket, oi->name, buckets_obj_strerror(err));
  /* ToObjectInfo: no version ID for the null version outside versioning */
  const char *dvid = !err ? (!enabled && !suspended && strcmp(r->version_id, "null") == 0 ? "" : r->version_id) : NULL;
  if (e) ilm_report(s, bucket, oi, oi_vid, e, start, err, dvid);
  return !err;
}

#define ILM_EXPIRY_UA "Internal: [ILM-Expiry]"

/* applyExpiryOnNonTransitionedObjects' event: named after the version the
 * rule matched (so an expired latest version in a versioned bucket reports
 * Delete, though a marker was made), about what the delete returned. */
static void expiry_event(buckets_s3_server *s, const char *bucket, const buckets_object_info *matched,
                         const buckets_delete_result *r) {
  int ev = matched->delete_marker ? BUCKETS_EV_OBJECT_REMOVED_DELETE_MARKER_CREATED : BUCKETS_EV_OBJECT_REMOVED_DELETE;
  buckets_s3_send_internal_event(s, ev, bucket, matched->name, NULL, r->version_id, ILM_EXPIRY_UA);
}

/* The scanner's lifecycle step (scannerItem.applyActions): evaluate every
 * version of one object and expire what is due. Transitions wait for tiers. */
static void scanner_lifecycle(buckets_s3_server *s, const char *bucket, const buckets_object_info *v, size_t n,
                              bool *removed);

static void scanner_object(void *ud, const char *bucket, const buckets_object_info *v, size_t n, bool *removed) {
  buckets_s3_server *s = ud;
  if (!s->meta || !n) return;
  scanner_lifecycle(s, bucket, v, n, removed);
  /* healReplication: every version still there */
  for (size_t i = 0; i < n; i++)
    if (!removed[i]) buckets_repl_heal(s, bucket, &v[i], 0);
}

/* evalActionFromLifecycle for data movement (decommission, rebalance):
 * which versions of one key (newest first) are due for deletion now. */
void buckets_s3_lifecycle_due(buckets_s3_server *s, const char *bucket, const buckets_object_info *v, size_t n,
                              bool *due) {
  memset(due, 0, n * sizeof(*due));
  if (!s->meta || !n || strcmp(bucket, BUCKETS_META_BUCKET) == 0) return;
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  if (!st->has_lifecycle) {
    buckets_bucket_state_release(st);
    return;
  }
  bool enabled = buckets_versioning_enabled_for(&st->versioning, v[0].name);
  bool suspended = buckets_versioning_suspended_for(&st->versioning, v[0].name);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  buckets_lc_obj *objs = buckets_xcalloc(n, sizeof(*objs));
  buckets_lc_event *ev = buckets_xcalloc(n, sizeof(*ev));
  for (size_t i = 0; i < n; i++) {
    objs[i].name = v[i].name;
    objs[i].user_tags = buckets_object_meta(&v[i], "X-Amz-Tagging");
    objs[i].mod_time_ns = v[i].mod_time_ns;
    objs[i].size = v[i].size;
    objs[i].version_id = strcmp(v[i].version_id, "null") == 0 && !enabled && !suspended ? "" : v[i].version_id;
    objs[i].is_latest = i == 0;
    objs[i].delete_marker = v[i].delete_marker;
    objs[i].num_versions = n;
    objs[i].successor_mod_time_ns = i ? v[i - 1].mod_time_ns : 0;
    objs[i].locked = version_locked(&v[i], now);
    objs[i].transitioned = buckets_object_tier(&v[i], NULL, NULL) != NULL;
  }
  buckets_lifecycle_eval_versions(&st->lifecycle, st->lock_enabled, objs, n, now, ev);
  for (size_t i = 0; i < n; i++)
    due[i] = ev[i].action == BUCKETS_LC_DELETE || ev[i].action == BUCKETS_LC_DELETE_VERSION ||
             ev[i].action == BUCKETS_LC_DELETE_ALL_VERSIONS || ev[i].action == BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS;
  free(objs);
  free(ev);
  buckets_bucket_state_release(st);
}

static void scanner_lifecycle(buckets_s3_server *s, const char *bucket, const buckets_object_info *v, size_t n,
                              bool *removed) {
  buckets_bucket_state *st = buckets_metasys_get(s->meta, bucket);
  if (!st->has_lifecycle) {
    buckets_bucket_state_release(st);
    return;
  }
  const char *name = v[0].name;
  bool enabled = buckets_versioning_enabled_for(&st->versioning, name);
  bool suspended = buckets_versioning_suspended_for(&st->versioning, name);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int64_t now = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
  buckets_lc_obj *objs = buckets_xcalloc(n, sizeof(*objs));
  buckets_lc_event *ev = buckets_xcalloc(n, sizeof(*ev));
  for (size_t i = 0; i < n; i++) {
    objs[i].name = v[i].name;
    objs[i].user_tags = buckets_object_meta(&v[i], "X-Amz-Tagging");
    objs[i].mod_time_ns = v[i].mod_time_ns;
    objs[i].size = v[i].size;
    /* ToObjectInfo: the null version of an unversioned object has no ID */
    objs[i].version_id = strcmp(v[i].version_id, "null") == 0 && !enabled && !suspended ? "" : v[i].version_id;
    objs[i].is_latest = i == 0;
    objs[i].delete_marker = v[i].delete_marker;
    objs[i].num_versions = n;
    objs[i].successor_mod_time_ns = i ? v[i - 1].mod_time_ns : 0;
    objs[i].locked = version_locked(&v[i], now);
    objs[i].transitioned = buckets_object_tier(&v[i], NULL, NULL) != NULL;
    int64_t rexp;
    buckets_object_restore_state(&v[i], &objs[i].restore_ongoing, &rexp);
    objs[i].restore_expires_ns = rexp * 1000000000LL;
  }
  buckets_lifecycle_eval_versions(&st->lifecycle, st->lock_enabled, objs, n, now, ev);
  for (size_t i = 0; i < n; i++)
    if ((size_t)ev[i].action < BUCKETS_ARRAY_LEN(s->ilm_actions)) atomic_fetch_add(&s->ilm_actions[ev[i].action], 1);
  for (size_t i = 0; i < n; i++) {
    switch (ev[i].action) {
    case BUCKETS_LC_DELETE_ALL_VERSIONS:
    case BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS: {
      buckets_delete_result r;
      bool any = false;
      for (size_t j = 0; j < n; j++) {
        any |= expire(s, bucket, &v[j], objs[j].version_id, j == i ? &ev[i] : NULL, v[j].version_id, false, false, &r);
        removed[j] = true;
      }
      /* one event, about the version the rule matched */
      if (any)
        buckets_s3_send_internal_event(s,
                                       ev[i].action == BUCKETS_LC_DELETE_ALL_VERSIONS
                                           ? BUCKETS_EV_OBJECT_REMOVED_DELETE_ALL_VERSIONS
                                           : BUCKETS_EV_ILM_DEL_MARKER_EXPIRATION_DELETE,
                                       bucket, name, &v[i], v[i].version_id, ILM_EXPIRY_UA);
      i = n;
      break;
    }
    case BUCKETS_LC_DELETE: {
      buckets_delete_result r;
      if (!enabled) removed[i] = true; /* a versioned bucket only gains a marker */
      if (expire(s, bucket, &v[i], objs[i].version_id, &ev[i], NULL, enabled, suspended, &r)) expiry_event(s, bucket, &v[i], &r);
      break;
    }
    case BUCKETS_LC_DELETE_VERSION: {
      buckets_delete_result r;
      if (expire(s, bucket, &v[i], objs[i].version_id, &ev[i], v[i].version_id, false, false, &r)) expiry_event(s, bucket, &v[i], &r);
      removed[i] = true;
      break;
    }
    case BUCKETS_LC_TRANSITION:
    case BUCKETS_LC_TRANSITION_VERSION: /* applyTransitionRule */
      buckets_tiering_queue(s->tiering, bucket, &v[i], ev[i].storage_class, ev[i].rule_id, ev[i].due_ns,
                            ev[i].action == BUCKETS_LC_TRANSITION_VERSION, false);
      break;
    case BUCKETS_LC_DELETE_RESTORED:
    case BUCKETS_LC_DELETE_RESTORED_VERSION: { /* the restored copy expires; the remote one stays */
      buckets_obj_err err = buckets_obj_expire_restored(s->layer, bucket, v[i].name, v[i].version_id);
      if (err && err != BUCKETS_OBJ_ERR_NO_SUCH_KEY && err != BUCKETS_OBJ_ERR_NO_SUCH_VERSION)
        buckets_log_warn("lifecycle: expiring the restored copy of %s/%s: %s", bucket, v[i].name, buckets_obj_strerror(err));
      break;
    }
    default: break;
    }
  }
  free(objs);
  free(ev);
  buckets_bucket_state_release(st);
}

/* The free-version task: the remote copy, then the free version itself. */
static void scanner_free_version(void *ud, const char *bucket, const buckets_object_info *fv) {
  buckets_s3_server *s = ud;
  const buckets_xl_kv *tier = buckets_object_sys(fv, BUCKETS_XL_META_TIER_NAME);
  const buckets_xl_kv *remote = buckets_object_sys(fv, BUCKETS_XL_META_TIER_OBJECT);
  const buckets_xl_kv *rv = buckets_object_sys(fv, BUCKETS_XL_META_TIER_VERSION);
  if (!tier || !remote) return;
  if (!buckets_tiering_remove_remote_now(s, (const char *)tier->value, (const char *)remote->value,
                                         rv ? (const char *)rv->value : ""))
    return;
  buckets_obj_err err = buckets_obj_delete_free_version(s->layer, bucket, fv->name, fv->version_id);
  if (!err) {
    const char *keys[1] = {"version-id"}, *values[1] = {fv->version_id};
    buckets_audit_internal("ilm:free-version-delete", "ILMFreeVersionDelete", bucket, fv->name, fv->version_id, NULL,
                           keys, values, 1);
  }
}

static size_t scanner_tier_names(void *ud, char ***names) {
  buckets_s3_server *s = ud;
  *names = NULL;
  return s->tiers ? buckets_tiers_names(s->tiers, names) : 0;
}

void buckets_s3_scanner_hooks(buckets_s3_server *s, void *hooks) {
  buckets_scanner_hooks *h = hooks;
  memset(h, 0, sizeof(*h));
  h->cycle_seconds = scanner_cycle_seconds;
  h->versioned = scanner_versioned;
  h->actual_size = scanner_actual_size;
  h->object = scanner_object;
  h->free_version = scanner_free_version;
  h->tier_names = scanner_tier_names;
  h->ud = s;
}

/* The resource metrics' sampler (startResourceMetricsCollection). */
static void *metrics_main(void *arg) {
  buckets_s3_server *s = arg;
  while (!s->cluster) /* a single node describes its drives after bootstrap */
    if (!bg_sleep(s, 100)) return NULL;
  do buckets_metrics_resource_collect(s);
  while (bg_sleep(s, 60000));
  return NULL;
}

void buckets_s3_server_set_layer(buckets_s3_server *s, buckets_objlayer *layer) {
  uint8_t h[32];
  buckets_sha256(layer->deployment_id_str, strlen(layer->deployment_id_str), h);
  buckets_hex_encode(h, 32, s->host_id);
  s->meta = buckets_metasys_new(layer, s->meta_ttl_ms);
  s->usage = buckets_xmalloc(sizeof(*s->usage));
  buckets_usage_cache_init(s->usage, layer, 10000); /* bucketStorageCache: 10s */
  s->bucket_usage = usage_of;
  s->bucket_usage_ud = s->usage;
  buckets_metasys_set_notify(s->meta, notify_bucket, s);
  buckets_metasys_set_kms(s->meta, s->kms);
  s->repl = buckets_repl_new(s);
  s->tiers = buckets_tiers_new(s);
  s->tiering = buckets_tiering_new(s, layer);
  s->layer = layer; /* atomic store, after host_id and meta */
  buckets_tiers_reload(s->tiers);
  buckets_repl_resync_resume(s->repl);
  s->sr = buckets_sr_new(s);
  buckets_sr_start(s->sr); /* loads its state once IAM is up */
  s->batch = buckets_batch_new(s);
  s->datamove = buckets_datamove_new(s);
  s->iam_thread_started = pthread_create(&s->iam_thread, NULL, iam_start_main, s) == 0;
  s->metrics_thread_started = pthread_create(&s->metrics_thread, NULL, metrics_main, s) == 0;
}

void buckets_s3_server_stop(buckets_s3_server *s) {
  buckets_log_set_sink(NULL, NULL); /* the server's log targets go away with it */
  buckets_audit_internal_set(NULL, NULL);
  pthread_mutex_lock(&s->bg_mu);
  s->bg_stop = true;
  pthread_cond_broadcast(&s->bg_cv);
  pthread_mutex_unlock(&s->bg_mu);
  if (s->iam_thread_started) pthread_join(s->iam_thread, NULL); /* it starts the others */
  s->iam_thread_started = false;
  if (s->ldap_thread_started) pthread_join(s->ldap_thread, NULL);
  s->ldap_thread_started = false;
  if (s->metrics_thread_started) pthread_join(s->metrics_thread, NULL);
  s->metrics_thread_started = false;
  buckets_sr_stop(s->sr);
  buckets_datamove_stop(s->datamove);
  buckets_batch_stop(s->batch);
  buckets_tiering_stop(s->tiering);
  buckets_repl_stop(s->repl);
  buckets_iam_stop_refresh(s->iam);
}

void buckets_s3_server_close_targets(buckets_s3_server *s) {
  buckets_notifier *n = s->notifier;
  buckets_logger *l = s->logger;
  s->notifier = NULL;
  s->logger = NULL;
  buckets_notifier_free(n);
  buckets_logger_free(l);
}

/* ---- response helpers ---------------------------------------------------- */

static void common_headers(s3_ctx *c) {
  buckets_http_response *r = c->resp;
  buckets_http_resp_header(r, "X-Amz-Request-Id", c->request_id);
  buckets_http_resp_header(r, "X-Amz-Id-2", c->s->host_id);
  buckets_http_resp_header(r, "Accept-Ranges", "bytes");
  buckets_http_resp_header(r, "Vary", "Origin"); /* two headers, as MinIO sends them */
  buckets_http_resp_header(r, "Vary", "Accept-Encoding");
  buckets_http_resp_header(r, "X-Content-Type-Options", "nosniff");
  buckets_http_resp_header(r, "X-Xss-Protection", "1; mode=block");
  buckets_http_resp_header(r, "Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

void buckets_s3_write_error_msg(s3_ctx *c, buckets_s3_error e, const char *message) {
  /* KMS failures carry MinIO's kms.Error codes, outside the table */
  if (e == BUCKETS_SSE_ERR_KMS_KEY_NOT_FOUND) {
    buckets_s3_write_custom_error(c, 404, "kms:KeyNotFound", "key with given key ID does not exist");
    return;
  }
  if (e == BUCKETS_SSE_ERR_KMS_DECRYPT) {
    buckets_s3_write_custom_error(c, 400, "kms:InvalidCiphertextException", "failed to decrypt ciphertext");
    return;
  }
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  c->resp->status = info->status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
  buckets_buf_reset(&c->resp->body);
  buckets_s3_error_xml_msg(&c->resp->body, e, message, c->path ? c->path : "/",
                           c->err_bucket ? c->err_bucket : c->bucket, c->err_object ? c->err_object : c->object,
                           c->request_id, c->s->host_id);
}

void buckets_s3_write_error(s3_ctx *c, buckets_s3_error e) { buckets_s3_write_error_msg(c, e, NULL); }

void buckets_s3_write_rejected(s3_ctx *c) {
  /* notImplementedHandler runs before any handler names the bucket or key */
  char *b = c->bucket, *o = c->object;
  c->bucket = c->object = NULL;
  buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
  c->bucket = b;
  c->object = o;
}

/* Real MinIO sub-resources not implemented yet: NotImplemented rather than
 * falling through to the catch-all bucket routes. */
static bool pending_subresource(const s3_ctx *c, bool put) {
  (void)c, (void)put;
  return false;
}

void buckets_s3_write_custom_error(s3_ctx *c, int status, const char *code, const char *message) {
  c->resp->status = status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  buckets_xml_header(b);
  buckets_xml_open(b, "Error");
  buckets_xml_elem(b, "Code", code);
  buckets_xml_elem(b, "Message", message);
  const char *eo = c->err_object ? c->err_object : c->object;
  const char *eb = c->err_bucket ? c->err_bucket : c->bucket;
  if (eo && *eo) buckets_xml_elem(b, "Key", eo);
  if (eb && *eb) buckets_xml_elem(b, "BucketName", eb);
  buckets_xml_elem(b, "Resource", c->path ? c->path : "/");
  buckets_xml_elem(b, "RequestId", c->request_id);
  buckets_xml_elem(b, "HostId", c->s->host_id);
  buckets_xml_close(b, "Error");
}

void buckets_s3_versioning(s3_ctx *c, const char *object, bool *enabled, bool *suspended) {
  *enabled = *suspended = false;
  if (!c->s->meta || !c->bucket) return;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  *enabled = buckets_versioning_enabled_for(&st->versioning, object ? object : "");
  *suspended = buckets_versioning_suspended_for(&st->versioning, object ? object : "");
  buckets_bucket_state_release(st);
}

void buckets_s3_version_header(s3_ctx *c, const char *version_id) {
  if (version_id && *version_id && strcmp(version_id, "null") != 0)
    buckets_http_resp_header(c->resp, "x-amz-version-id", version_id);
}

void buckets_s3_write_xml(s3_ctx *c, int status) {
  c->resp->status = status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
}

/* ---- request parsing ----------------------------------------------------- */

static bool has_bad_component(const char *path) {
  const char *p = path;
  while (*p) {
    while (*p == '/') p++;
    const char *seg = p;
    while (*p && *p != '/') p++;
    size_t n = (size_t)(p - seg);
    if ((n == 1 && seg[0] == '.') || (n == 2 && seg[0] == '.' && seg[1] == '.')) return true;
  }
  return false;
}

/* Splits "/bucket/obj/ect" into bucket and object (path-style addressing). */
static buckets_s3_error parse_path(s3_ctx *c) {
  buckets_str raw = c->req->path;
  char *decoded = buckets_xmalloc(raw.n + 1);
  long n = buckets_url_decode(raw, decoded, false);
  if (n < 0) {
    free(decoded);
    return BUCKETS_ERR_INVALID_RESOURCE_NAME;
  }
  decoded[n] = '\0';
  c->path = decoded;
  if (memchr(decoded, '\0', (size_t)n) || has_bad_component(decoded)) return BUCKETS_ERR_INVALID_RESOURCE_NAME;

  const char *p = decoded;
  while (*p == '/') p++;
  if (!*p) return BUCKETS_ERR_NONE;
  const char *slash = strchr(p, '/');
  if (!slash) {
    c->bucket = buckets_xstrdup(p);
  } else {
    c->bucket = buckets_xstrndup(p, (size_t)(slash - p));
    if (slash[1]) c->object = buckets_xstrdup(slash + 1);
  }
  return BUCKETS_ERR_NONE;
}

bool buckets_s3_lookup_secret(void *ud, buckets_str access_key, char secret[BUCKETS_SECRET_MAX]) {
  s3_ctx *c = ud;
  char *ak = buckets_xstrndup(access_key.p, access_key.n);
  buckets_iam_ident *id;
  c->key_status = buckets_iam_get_key(c->s->iam, ak, &id);
  free(ak);
  if (c->key_status != BUCKETS_IAM_KEY_OK) return false;
  snprintf(secret, BUCKETS_SECRET_MAX, "%s", id->secret_key);
  buckets_iam_ident_release(c->ident);
  c->ident = id;
  return true;
}

/* getSessionToken: the header, else the query parameter. */
static char *session_token(s3_ctx *c) {
  buckets_str h = buckets_http_header_get(c->req, "X-Amz-Security-Token");
  if (h.p && h.n) return buckets_xstrndup(h.p, h.n);
  const char *q = buckets_query_get(&c->q, "X-Amz-Security-Token");
  return q && *q ? buckets_xstrdup(q) : NULL;
}

buckets_s3_error buckets_s3_check_credential(s3_ctx *c, buckets_s3_error verify_err, const char *form_token) {
  if (verify_err == BUCKETS_ERR_INVALID_ACCESS_KEY_ID) {
    if (c->key_status == BUCKETS_IAM_KEY_DISABLED) return BUCKETS_ERR_ACCESS_KEY_DISABLED;
    if (c->key_status == BUCKETS_IAM_KEY_NOT_READY) return BUCKETS_ERR_IAM_NOT_INITIALIZED;
  }
  if (verify_err != BUCKETS_ERR_NONE) return verify_err;
  char *token = form_token ? buckets_xstrdup(form_token) : session_token(c);
  buckets_iam_token_status ts = buckets_iam_check_token(c->s->iam, c->ident, token, &c->owner);
  free(token);
  switch (ts) {
    case BUCKETS_IAM_TOKEN_OK: return BUCKETS_ERR_NONE;
    case BUCKETS_IAM_TOKEN_NO_ACCESS_KEY: return BUCKETS_ERR_NO_ACCESS_KEY;
    case BUCKETS_IAM_TOKEN_INVALID: return BUCKETS_ERR_INVALID_TOKEN;
    case BUCKETS_IAM_TOKEN_EXPIRED: return BUCKETS_ERR_INVALID_ACCESS_KEY_ID;
  }
  return BUCKETS_ERR_ACCESS_DENIED;
}

static bool is_hex64(const char *s) {
  if (strlen(s) != 64) return false;
  for (int i = 0; i < 64; i++) {
    if (!isxdigit((unsigned char)s[i])) return false;
  }
  return true;
}

buckets_s3_error buckets_s3_read_doc(s3_ctx *c) {
  const buckets_http_request *req = c->req;
  if (req->body_len > BUCKETS_S3_MAX_DOC_SIZE) return BUCKETS_ERR_ENTITY_TOO_LARGE;
  if (c->auth == BUCKETS_AUTH_SIGV4_STREAMING) return BUCKETS_ERR_NOT_IMPLEMENTED; /* aws-chunked documents */
  buckets_buf_reset(&c->doc);
  buckets_buf_reserve(&c->doc, (size_t)req->body_len);
  buckets_http_body_cursor cur = {req, 0};
  char tmp[65536];
  long n;
  while ((n = buckets_http_body_read(&cur, tmp, sizeof(tmp))) > 0) buckets_buf_append(&c->doc, tmp, (size_t)n);
  if (n < 0) return BUCKETS_ERR_INTERNAL_ERROR;

  buckets_str md5h = buckets_http_header_get(req, "Content-MD5");
  if (md5h.p) {
    uint8_t want[BUCKETS_MD5_LEN + 3], got[BUCKETS_MD5_LEN];
    if (md5h.n != 24 || buckets_base64_decode(md5h.p, md5h.n, want) != BUCKETS_MD5_LEN) {
      return BUCKETS_ERR_INVALID_DIGEST;
    }
    buckets_md5(c->doc.data, c->doc.len, got);
    if (memcmp(want, got, BUCKETS_MD5_LEN) != 0) return BUCKETS_ERR_BAD_DIGEST;
  }
  const char *payload_hash = c->sig.payload_hash;
  if (!*payload_hash || strcmp(payload_hash, BUCKETS_UNSIGNED_PAYLOAD) == 0) return BUCKETS_ERR_NONE;
  if (!is_hex64(payload_hash)) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
  uint8_t sum[32];
  char hex[65];
  buckets_sha256(c->doc.data, c->doc.len, sum);
  buckets_hex_encode(sum, 32, hex);
  for (int i = 0; i < 64; i++) {
    if (hex[i] != tolower((unsigned char)payload_hash[i])) return BUCKETS_ERR_CONTENT_SHA256_MISMATCH;
  }
  return BUCKETS_ERR_NONE;
}

static buckets_s3_error authenticate(s3_ctx *c) {
  buckets_sigv4_config cfg = {
      .region = c->s->region,
      .service = "s3",
      .now = time(NULL),
      .lookup = buckets_s3_lookup_secret,
      .lookup_ud = c,
  };
  buckets_sigv4_result *res = &c->sig;
  buckets_s3_error err;
  c->auth = buckets_auth_classify(c->req, &c->q);
  switch (c->auth) {
    case BUCKETS_AUTH_SIGV4_HEADER:
    case BUCKETS_AUTH_SIGV4_STREAMING: /* seed signature; chunks are verified while reading */
      err = buckets_sigv4_verify_header(&cfg, c->req, &c->q, res);
      break;
    case BUCKETS_AUTH_SIGV4_PRESIGNED:
      err = buckets_sigv4_verify_presigned(&cfg, c->req, &c->q, res);
      break;
    case BUCKETS_AUTH_ANONYMOUS: {
      /* Authorized per action against the bucket policy; a token needs a key. */
      char *token = session_token(c);
      bool has = token != NULL;
      free(token);
      return has ? BUCKETS_ERR_NO_ACCESS_KEY : BUCKETS_ERR_NONE;
    }
    case BUCKETS_AUTH_SIGV2:
      err = buckets_sigv2_verify_header(&cfg, c->req, res);
      break;
    case BUCKETS_AUTH_SIGV2_PRESIGNED:
      err = buckets_sigv2_verify_presigned(&cfg, c->req, res);
      break;
    case BUCKETS_AUTH_POST_POLICY:
      return BUCKETS_ERR_NONE; /* the signed policy inside the form is verified by the handler */
    case BUCKETS_AUTH_JWT:
      return BUCKETS_ERR_NOT_IMPLEMENTED;
    default:
      return BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED;
  }
  if ((err = buckets_s3_check_credential(c, err, NULL)) != BUCKETS_ERR_NONE) return err;
  snprintf(c->access_key, sizeof(c->access_key), "%s", res->access_key);
  return BUCKETS_ERR_NONE;
}

/* ---- service-level handlers ---------------------------------------------- */

static void list_buckets(s3_ctx *c) {
  /* ListAllMyBuckets, else only the buckets the caller may list or locate. */
  buckets_s3_error aerr = buckets_s3_authorize(c, "s3:ListAllMyBuckets", NULL, NULL, NULL);
  if (!c->ident) aerr = BUCKETS_ERR_ACCESS_DENIED;
  if (aerr != BUCKETS_ERR_NONE && (aerr != BUCKETS_ERR_ACCESS_DENIED || !c->ident)) {
    buckets_s3_write_error(c, aerr);
    return;
  }
  bool filter = aerr == BUCKETS_ERR_ACCESS_DENIED;
  if (filter) {
    buckets_s3_cond_override(c, "prefix", "");
    buckets_s3_cond_override(c, "delimiter", "/");
  }
  buckets_bucket_info *vols;
  size_t n;
  buckets_obj_err lerr = buckets_obj_list_buckets(c->s->layer, &vols, &n);
  if (lerr) {
    buckets_s3_write_error(c, buckets_s3_obj_error(lerr));
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ListAllMyBucketsResult", BUCKETS_S3_XMLNS);
  buckets_xml_open(b, "Owner");
  buckets_xml_elem(b, "ID", BUCKETS_S3_OWNER_ID);
  buckets_xml_elem(b, "DisplayName", BUCKETS_S3_OWNER_NAME);
  buckets_xml_close(b, "Owner");
  buckets_xml_open(b, "Buckets");
  for (size_t i = 0; i < n; i++) {
    if (buckets_bucket_name_reserved(vols[i].name) || !buckets_bucket_name_valid(vols[i].name)) continue;
    if (filter && !buckets_s3_allowed(c, "s3:ListBucket", vols[i].name, NULL, false) &&
        !buckets_s3_allowed(c, "s3:GetBucketLocation", vols[i].name, NULL, false)) {
      continue;
    }
    /* Creation time comes from bucket metadata (as in MinIO), else the directory. */
    int64_t created_ns = (int64_t)vols[i].created * 1000000000LL;
    buckets_bucket_meta bm;
    if (buckets_bucket_meta_load(c->s->layer, vols[i].name, &bm)) {
      int64_t ns = buckets_bucket_meta_created_ns(&bm);
      if (ns) created_ns = ns; /* milliseconds show, as MinIO's iso8601TimeFormat has them */
      buckets_bucket_meta_free(&bm);
    }
    char ts[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(created_ns, ts);
    buckets_xml_open(b, "Bucket");
    buckets_xml_elem(b, "Name", vols[i].name);
    buckets_xml_elem(b, "CreationDate", ts);
    buckets_xml_close(b, "Bucket");
  }
  buckets_xml_close(b, "Buckets");
  buckets_xml_close(b, "ListAllMyBucketsResult");
  buckets_bucket_info_free(vols, n);
  buckets_s3_write_xml(c, 200);
}

/* ---- bucket-level handlers ----------------------------------------------- */

static bool bucket_exists(s3_ctx *c) { return buckets_obj_stat_bucket(c->s->layer, c->bucket) == BUCKETS_OBJ_OK; }

static void create_bucket(s3_ctx *c) {
  if (!buckets_bucket_name_valid_strict(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_NAME);
    return;
  }
  buckets_str lock = buckets_http_header_get(c->req, "X-Amz-Bucket-Object-Lock-Enabled");
  bool lock_enabled = false;
  if (lock.p && lock.n) {
    if (buckets_str_ieq_c(lock, "true")) lock_enabled = true;
    else if (!buckets_str_ieq_c(lock, "false")) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_REQUEST);
      return;
    }
  }
  /* Creating a bucket with locking needs these permissions as well. */
  if (lock_enabled && (!buckets_s3_require(c, "s3:PutBucketObjectLockConfiguration", c->bucket, NULL, NULL) ||
                       !buckets_s3_require(c, "s3:PutBucketVersioning", c->bucket, NULL, NULL)))
    return;

  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr != BUCKETS_ERR_NONE) {
    buckets_s3_write_error(c, derr);
    return;
  }
  if (c->doc.len > 0) {
    buckets_xml_doc doc;
    if (!buckets_xml_parse(buckets_buf_str(&c->doc), &doc) || !buckets_str_eq_c(doc.nodes[0].name, "CreateBucketConfiguration")) {
      if (doc.nodes) buckets_xml_doc_free(&doc);
      buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
      return;
    }
    size_t lc = buckets_xml_child(&doc, 0, "LocationConstraint");
    buckets_buf loc = BUCKETS_BUF_INIT;
    bool ok = !lc || buckets_xml_unescape(doc.nodes[lc].text, &loc);
    buckets_xml_doc_free(&doc);
    if (!ok) {
      buckets_buf_free(&loc);
      buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
      return;
    }
    bool region_ok = loc.len == 0 || !*c->s->region || strcmp(loc.data, c->s->region) == 0;
    buckets_buf_free(&loc);
    if (!region_ok) {
      buckets_s3_write_error(c, BUCKETS_ERR_INVALID_REGION);
      return;
    }
  }

  switch (buckets_obj_make_bucket(c->s->layer, c->bucket)) {
    case BUCKETS_OBJ_OK: {
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      buckets_bucket_meta bm;
      buckets_bucket_meta_init(&bm, c->bucket, (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
      if (lock_enabled) { /* MinIO's enabledBucketVersioningConfig and enabledBucketObjectLockConfig */
        buckets_buf_append_c(&bm.config[BUCKETS_BCFG_VERSIONING],
                             "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status></VersioningConfiguration>");
        buckets_buf_append_c(&bm.config[BUCKETS_BCFG_OBJECT_LOCK],
                             "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>");
      }
      if (!buckets_bucket_meta_save(c->s->layer, &bm)) buckets_log_warn("could not save metadata for bucket %s", c->bucket);
      buckets_bucket_meta_free(&bm);
      buckets_metasys_changed(c->s->meta, c->bucket);
      if (buckets_sr_enabled(c->s->sr)) {
        char err[4096];
        if (!buckets_sr_make_bucket_hook(c->s->sr, c->bucket, lock_enabled, false, err, sizeof(err)))
          buckets_log_warn("site replication: %s", err);
      }
      buckets_http_resp_headerf(c->resp, "Location", "/%s", c->bucket);
      c->resp->status = 200;
      buckets_s3_send_event(c, BUCKETS_EV_BUCKET_CREATED, c->bucket, "", NULL, NULL);
      return;
    }
    case BUCKETS_OBJ_ERR_BUCKET_EXISTS:
      buckets_s3_write_error(c, BUCKETS_ERR_BUCKET_ALREADY_OWNED_BY_YOU);
      return;
    default:
      buckets_s3_write_error(c, BUCKETS_ERR_SLOW_DOWN_WRITE);
      return;
  }
}

static void delete_bucket(s3_ctx *c) {
  buckets_str fh = buckets_http_header_get(c->req, "X-Minio-Force-Delete");
  bool force = fh.p && buckets_str_ieq_c(fh, "true");
  bool sr = buckets_sr_enabled(c->s->sr);
  buckets_obj_err err = force ? buckets_obj_delete_bucket_force(c->s->layer, c->bucket)
                              : buckets_obj_delete_bucket(c->s->layer, c->bucket);
  /* site replication holds on to the deleted bucket's state until the sites sync */
  if (sr && (err == BUCKETS_OBJ_OK || err == BUCKETS_OBJ_ERR_NO_SUCH_BUCKET))
    buckets_obj_mark_bucket_deleted(c->s->layer, c->bucket);
  if (err == BUCKETS_OBJ_ERR_BUCKET_NOT_EMPTY) {
    bool enabled, suspended;
    buckets_s3_versioning(c, NULL, &enabled, &suspended);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_BUCKET_NOT_EMPTY,
                               enabled || suspended
                                   ? "The bucket you tried to delete is not empty. You must delete all versions in the bucket."
                                   : NULL);
    return;
  }
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_bucket_meta_delete(c->s->layer, c->bucket);
  buckets_metasys_changed(c->s->meta, c->bucket);
  if (sr) {
    char e[4096];
    if (!buckets_sr_delete_bucket_hook(c->s->sr, c->bucket, force, e, sizeof(e))) buckets_log_warn("site replication: %s", e);
  }
  c->resp->status = 204;
  buckets_s3_send_event(c, BUCKETS_EV_BUCKET_REMOVED, c->bucket, "", NULL, NULL);
}

static void get_bucket_location(s3_ctx *c) {
  const char *region = c->s->region;
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "LocationConstraint", BUCKETS_S3_XMLNS);
  if (*region && strcmp(region, DEFAULT_REGION) != 0) buckets_xml_text(b, region, strlen(region));
  buckets_xml_close(b, "LocationConstraint");
  buckets_s3_write_xml(c, 200);
}

static void get_bucket_versioning(s3_ctx *c) {
  /* An unversioned bucket has an empty configuration. */
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  buckets_buf *b = &c->resp->body;
  buckets_versioning_xml(&st->versioning, b); /* xml.Marshal, no declaration (writeSuccessResponseXML) */
  buckets_bucket_state_release(st);
  buckets_s3_write_xml(c, 200);
}

#define MAX_BUCKET_VERSIONING_SIZE (1 << 20)

static void put_bucket_versioning(s3_ctx *c) {
  if (c->req->body_len > MAX_BUCKET_VERSIONING_SIZE) {
    buckets_s3_write_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_versioning v;
  char err[256] = "";
  if (!buckets_versioning_parse(c->doc.data ? c->doc.data : "", c->doc.len, &v, err, sizeof(err))) {
    if (strcmp(err, "malformed XML") == 0) {
      buckets_s3_write_error(c, BUCKETS_ERR_MALFORMED_XML);
    } else {
      char msg[400];
      snprintf(msg, sizeof(msg), "Versioning configuration specified in the request is invalid. (%s)", err);
      buckets_s3_write_custom_error(c, 400, "IllegalVersioningConfigurationException", msg);
    }
    return;
  }
  if (buckets_sr_enabled(c->s->sr) && v.status != BUCKETS_VERSIONING_ENABLED) {
    buckets_versioning_free(&v);
    buckets_s3_write_custom_error(c, 400, "InvalidBucketState",
                                  "Cluster replication is enabled on this site, versioning cannot be suspended on bucket.");
    return;
  }
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool locked = st->lock_enabled;
  buckets_bucket_state_release(st);
  if (locked && (v.status == BUCKETS_VERSIONING_SUSPENDED || v.nexcluded || v.exclude_folders)) {
    buckets_versioning_free(&v);
    buckets_s3_write_custom_error(c, 400, "InvalidBucketState",
                                  "An Object Lock configuration is present on this bucket, versioning cannot be suspended.");
    return;
  }
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_versioning_xml(&v, &x);
  buckets_versioning_free(&v);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_VERSIONING, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
  buckets_sr_bucket_meta_hook(c->s->sr, c->bucket, "version-config");
}

/* ---- bucket policy (?policy) -------------------------------------------------- */

#define MAX_BUCKET_POLICY_SIZE (20 * 1024)

static void put_bucket_policy(s3_ctx *c) {
  if (c->req->body_len <= 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_MISSING_CONTENT_LENGTH);
    return;
  }
  if (c->req->body_len > MAX_BUCKET_POLICY_SIZE) {
    buckets_s3_write_error(c, BUCKETS_ERR_POLICY_TOO_LARGE);
    return;
  }
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_policy *p;
  char err[512];
  if (!buckets_bucket_policy_parse(c->doc.data, c->doc.len, c->bucket, &p, err, sizeof(err))) {
    buckets_s3_write_custom_error(c, 400, "MalformedPolicy", err);
    return;
  }
  bool no_version = !*buckets_policy_version(p);
  buckets_policy_free(p);
  if (no_version) {
    buckets_s3_write_error(c, BUCKETS_ERR_POLICY_INVALID_VERSION);
    return;
  }
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_POLICY, c->doc.data, c->doc.len)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
  buckets_sr_bucket_meta_hook(c->s->sr, c->bucket, "policy");
}

static void get_bucket_policy(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  const buckets_buf *pol = &st->meta.config[BUCKETS_BCFG_POLICY];
  if (!pol->len) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET_POLICY);
  } else {
    c->resp->status = 200;
    buckets_http_resp_header(c->resp, "Content-Type", "application/json");
    buckets_buf_append(&c->resp->body, pol->data, pol->len);
  }
  buckets_bucket_state_release(st);
}

static void delete_bucket_policy(s3_ctx *c) {
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_POLICY, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 204;
  buckets_sr_bucket_meta_hook(c->s->sr, c->bucket, "policy");
}

/* PutBucketEncryptionHandler / GetBucketEncryptionHandler */
static void put_bucket_encryption(s3_ctx *c) {
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_sse_config cfg;
  char err[256];
  if (!buckets_sse_config_parse(c->doc.data ? c->doc.data : "", c->doc.len, &cfg, err, sizeof(err))) {
    char msg[400];
    snprintf(msg, sizeof(msg), "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_MALFORMED_XML)->message, err);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, msg);
    return;
  }
  if (!c->s->kms) {
    buckets_s3_write_error(c, BUCKETS_ERR_KMS_NOT_CONFIGURED);
    return;
  }
  const char *key = buckets_sse_config_key(&cfg);
  if (*key) { /* a test key operation, as MinIO does */
    uint8_t plain[32];
    char id[256];
    buckets_buf ct = BUCKETS_BUF_INIT;
    buckets_kms_err ke = buckets_kms_generate(c->s->kms, key, "{\"MinIO admin API\":\"ServerInfoHandler\"}", plain, &ct, id, sizeof(id));
    buckets_buf_free(&ct);
    if (ke == BUCKETS_KMS_ERR_KEY_NOT_FOUND) {
      buckets_s3_write_custom_error(c, 404, "kms:KeyNotFound", "key with given key ID does not exist");
      return;
    }
    if (ke) {
      buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
      return;
    }
  }
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_sse_config_xml(&cfg, &x);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_ENCRYPTION, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
  buckets_sr_bucket_meta_hook(c->s->sr, c->bucket, "sse-config");
}

static void get_bucket_encryption(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (!st->has_sse) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET_SSE_CONFIG);
    return;
  }
  buckets_sse_config_xml(&st->sse, &c->resp->body);
  buckets_bucket_state_release(st);
  buckets_s3_write_xml(c, 200);
}

/* Query keys that select a bucket sub-resource (as opposed to list parameters). */
static bool has_unhandled_subresource(const buckets_query *q) {
  static const char *const list_params[] = {"prefix",     "delimiter",          "marker",      "max-keys",
                                            "encoding-type", "list-type",       "continuation-token",
                                            "fetch-owner", "start-after",   "metadata"};
  for (size_t i = 0; i < q->n; i++) {
    const char *k = q->items[i].key;
    if (strncasecmp(k, "x-amz-", 6) == 0) continue; /* presign parameters */
    bool known = false;
    for (size_t j = 0; j < BUCKETS_ARRAY_LEN(list_params); j++) {
      if (strcmp(k, list_params[j]) == 0) known = true;
    }
    if (!known) return true;
  }
  return false;
}

/* The policy action of a bucket-level request (MinIO's router + handlers). */
static bool authorize_bucket_request(s3_ctx *c) {
  buckets_str m = c->req->method;
  const char *action = NULL;
  if (buckets_query_has(&c->q, "acl") && (buckets_str_eq_c(m, "GET") || buckets_str_eq_c(m, "PUT"))) {
    action = buckets_str_eq_c(m, "GET") ? "s3:GetBucketPolicy" : "s3:PutBucketPolicy";
  } else if (buckets_query_has(&c->q, "policy") && !buckets_str_eq_c(m, "HEAD") && !buckets_str_eq_c(m, "POST")) {
    if (buckets_str_eq_c(m, "GET")) action = "s3:GetBucketPolicy";
    else if (buckets_str_eq_c(m, "PUT")) action = "s3:PutBucketPolicy";
    else if (buckets_str_eq_c(m, "DELETE")) action = "s3:DeleteBucketPolicy";
  } else if (buckets_str_eq_c(m, "PUT")) {
    if (buckets_query_has(&c->q, "versioning")) action = "s3:PutBucketVersioning";
    else if (buckets_query_has(&c->q, "object-lock")) action = "s3:PutBucketObjectLockConfiguration";
    else if (buckets_query_has(&c->q, "tagging")) action = "s3:PutBucketTagging";
    else if (buckets_query_has(&c->q, "lifecycle")) action = "s3:PutLifecycleConfiguration";
    else if (buckets_query_has(&c->q, "encryption")) action = "s3:PutEncryptionConfiguration";
    else if (buckets_query_has(&c->q, "notification")) action = NULL; /* the handler authorizes */
    else if (buckets_query_has(&c->q, "replication")) action = "s3:PutReplicationConfiguration";
    else if (buckets_query_has(&c->q, "replication-reset")) action = "s3:ResetBucketReplicationState";
    else if (!pending_subresource(c, true)) action = "s3:CreateBucket"; /* the catch-all PUT route */
  } else if (buckets_str_eq_c(m, "HEAD")) {
    if (buckets_s3_authorize(c, "s3:HeadBucket", c->bucket, NULL, NULL) == BUCKETS_ERR_NONE) return true;
    action = "s3:ListBucket";
  } else if (buckets_str_eq_c(m, "DELETE")) {
    buckets_str force = buckets_http_header_get(c->req, "X-Minio-Force-Delete");
    if (buckets_query_has(&c->q, "tagging")) action = "s3:PutBucketTagging"; /* as MinIO */
    else if (buckets_query_has(&c->q, "lifecycle")) action = "s3:PutLifecycleConfiguration"; /* as MinIO */
    else if (buckets_query_has(&c->q, "encryption")) action = "s3:PutEncryptionConfiguration"; /* as MinIO */
    else if (buckets_query_has(&c->q, "replication")) action = "s3:PutReplicationConfiguration"; /* as MinIO */
    else if (!pending_subresource(c, false))
      action = force.p && buckets_str_ieq_c(force, "true") ? "s3:ForceDeleteBucket" : "s3:DeleteBucket";
  } else if (buckets_str_eq_c(m, "GET")) {
    if (buckets_query_has(&c->q, "location")) action = "s3:GetBucketLocation";
    else if (buckets_query_has(&c->q, "versioning")) action = "s3:GetBucketVersioning";
    else if (buckets_query_has(&c->q, "versions")) action = "s3:ListBucketVersions";
    else if (buckets_query_has(&c->q, "object-lock")) action = "s3:GetBucketObjectLockConfiguration";
    else if (buckets_query_has(&c->q, "tagging")) action = "s3:GetBucketTagging";
    else if (buckets_query_has(&c->q, "lifecycle")) action = "s3:GetLifecycleConfiguration";
    else if (buckets_query_has(&c->q, "encryption")) action = "s3:GetEncryptionConfiguration";
    else if (buckets_query_has(&c->q, "uploads")) action = "s3:ListBucketMultipartUploads";
    else if (buckets_query_has(&c->q, "replication")) action = "s3:GetReplicationConfiguration";
    else if (buckets_query_has(&c->q, "replication-reset-status")) action = "s3:ResetBucketReplicationState";
    else if (buckets_query_has(&c->q, "replication-metrics")) action = "s3:GetReplicationConfiguration";
    else if (buckets_query_has(&c->q, "replication-check")) action = "s3:GetReplicationConfiguration";
    else if (buckets_query_has(&c->q, "events")) action = NULL; /* the handler authorizes */
    else if (!has_unhandled_subresource(&c->q)) action = "s3:ListBucket";
  }
  /* DeleteObjects and POST policy uploads are authorized per object. */
  return !action || buckets_s3_require(c, action, c->bucket, NULL, NULL);
}

/* Sub-resources MinIO answers with fixed responses (dummy-handlers.go) or
 * rejects outright (rejectedBucketAPIs, which skip authorization). Returns
 * true when the request was one of them. */
static bool route_dummy_bucket(s3_ctx *c) {
  /* rejectedBucketAPIs register after the catch-all PUT, DELETE and HEAD
   * bucket routes, so only their GETs are ever reached. */
  static const char *const rejected_get[] = {"inventory",         "metrics",             "publicAccessBlock",
                                             "ownershipControls", "intelligent-tiering", "analytics"};
  static const struct {
    const char *query, *body; /* body NULL: an error */
    buckets_s3_error err;
  } get_dummies[] = {
      {"website", NULL, BUCKETS_ERR_NO_SUCH_WEBSITE_CONFIGURATION},
      {"accelerate",
       "<?xml version=\"1.0\" encoding=\"UTF-8\"?><AccelerateConfiguration "
       "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>",
       BUCKETS_ERR_NONE},
      {"requestPayment",
       "<?xml version=\"1.0\" encoding=\"UTF-8\"?><RequestPaymentConfiguration "
       "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Payer>BucketOwner</Payer></RequestPaymentConfiguration>",
       BUCKETS_ERR_NONE},
      {"logging",
       "<?xml version=\"1.0\" encoding=\"UTF-8\"?><BucketLoggingStatus "
       "xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><!--<LoggingEnabled><TargetBucket>myLogsBucket</TargetBucket>"
       "<TargetPrefix>add/this/prefix/to/my/log/files/access_log-</TargetPrefix></LoggingEnabled>--></BucketLoggingStatus>",
       BUCKETS_ERR_NONE},
  };
  buckets_str m = c->req->method;
  char mc = m.n ? m.p[0] : 0;
  bool get = buckets_str_eq_c(m, "GET");

  if (buckets_query_has(&c->q, "cors") && (get || buckets_str_eq_c(m, "PUT") || buckets_str_eq_c(m, "DELETE"))) {
    const char *action = get ? "s3:GetBucketCors" : mc == 'P' ? "s3:PutBucketCors" : "s3:DeleteBucketCors";
    if (!buckets_s3_require(c, action, c->bucket, NULL, NULL)) return true;
    if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    else buckets_s3_write_error(c, get ? BUCKETS_ERR_NO_SUCH_CORS_CONFIGURATION : BUCKETS_ERR_NOT_IMPLEMENTED);
    return true;
  }
  if (get) {
    for (size_t i = 0; i < BUCKETS_ARRAY_LEN(get_dummies); i++) {
      if (!buckets_query_has(&c->q, get_dummies[i].query)) continue;
      if (!buckets_s3_require(c, "s3:GetBucketPolicy", c->bucket, NULL, NULL)) return true;
      if (!bucket_exists(c)) {
        buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      } else if (!get_dummies[i].body) {
        buckets_s3_write_error(c, get_dummies[i].err);
      } else {
        buckets_buf_append_c(&c->resp->body, get_dummies[i].body);
        buckets_s3_write_xml(c, 200);
      }
      return true;
    }
    if (buckets_query_has(&c->q, "policyStatus")) {
      if (buckets_s3_authorize(c, "s3:GetBucketPolicyStatus", c->bucket, NULL, NULL) != BUCKETS_ERR_NONE) {
        buckets_s3_require(c, "s3:GetBucketPolicyStatus", c->bucket, NULL, NULL);
        buckets_buf_reset(&c->resp->body); /* writeErrorResponseHeadersOnly */
        return true;
      }
      if (!bucket_exists(c)) {
        buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
        return true;
      }
      bool pub = buckets_s3_bucket_policy_allows(c, "s3:ListBucket", c->bucket, NULL) &&
                 buckets_s3_bucket_policy_allows(c, "s3:PutObject", c->bucket, NULL);
      buckets_buf *b = &c->resp->body;
      buckets_xml_header(b);
      buckets_xml_open_ns(b, "PolicyStatus", BUCKETS_S3_XMLNS);
      buckets_xml_elem(b, "IsPublic", pub ? "TRUE" : "FALSE");
      buckets_xml_close(b, "PolicyStatus");
      buckets_s3_write_xml(c, 200);
      return true;
    }
  }
  if (buckets_str_eq_c(m, "DELETE") && buckets_query_has(&c->q, "website")) {
    c->resp->status = 200; /* DeleteBucketWebsiteHandler: success, nothing else */
    return true;
  }
  for (size_t i = 0; get && i < BUCKETS_ARRAY_LEN(rejected_get); i++) {
    if (buckets_query_has(&c->q, rejected_get[i])) {
      buckets_s3_write_rejected(c);
      return true;
    }
  }
  return false;
}

static void route_bucket(s3_ctx *c) {
  if (buckets_bucket_name_reserved(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_ALL_ACCESS_DISABLED);
    return;
  }
  if (!buckets_bucket_name_valid(c->bucket)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_NAME);
    return;
  }
  buckets_str m = c->req->method;
  if (route_dummy_bucket(c)) return;
  if (!authorize_bucket_request(c)) return;
  if (buckets_query_has(&c->q, "acl") && (buckets_str_eq_c(m, "GET") || buckets_str_eq_c(m, "PUT"))) {
    if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    else if (buckets_str_eq_c(m, "GET")) buckets_s3_write_private_acl(c);
    else buckets_s3_put_acl(c);
    return;
  }
  if (buckets_query_has(&c->q, "policy") && !buckets_str_eq_c(m, "HEAD") && !buckets_str_eq_c(m, "POST")) {
    if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    else if (buckets_str_eq_c(m, "GET")) get_bucket_policy(c);
    else if (buckets_str_eq_c(m, "PUT")) put_bucket_policy(c);
    else if (buckets_str_eq_c(m, "DELETE")) delete_bucket_policy(c);
    else buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    return;
  }
  if (buckets_str_eq_c(m, "PUT")) {
    if (buckets_query_has(&c->q, "versioning")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else put_bucket_versioning(c);
      return;
    }
    if (buckets_query_has(&c->q, "object-lock")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else buckets_s3_put_bucket_object_lock(c);
      return;
    }
    if (buckets_query_has(&c->q, "tagging")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else buckets_s3_put_bucket_tagging(c);
      return;
    }
    if (buckets_query_has(&c->q, "lifecycle")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else buckets_s3_put_bucket_lifecycle(c);
      return;
    }
    if (buckets_query_has(&c->q, "encryption")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else put_bucket_encryption(c);
      return;
    }
    if (buckets_query_has(&c->q, "notification")) {
      buckets_s3_put_notification(c); /* authorizes, then checks the bucket */
      return;
    }
    if (buckets_query_has(&c->q, "replication")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else buckets_s3_put_bucket_replication(c);
      return;
    }
    if (buckets_query_has(&c->q, "replication-reset")) {
      if (!bucket_exists(c)) buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
      else buckets_s3_reset_bucket_replication_start(c);
      return;
    }
    if (pending_subresource(c, true)) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    create_bucket(c); /* PutBucketHandler takes any other query */
    return;
  }

  if (buckets_str_eq_c(m, "GET") && buckets_query_has(&c->q, "notification")) {
    buckets_s3_get_notification(c); /* authorizes, then checks the bucket */
    return;
  }
  if (buckets_str_eq_c(m, "GET") && buckets_query_has(&c->q, "events")) {
    buckets_s3_listen_notification(c);
    return;
  }
  if (buckets_str_eq_c(m, "GET") && buckets_query_has(&c->q, "tagging")) {
    buckets_s3_get_bucket_tagging(c); /* NoSuchTagSet even without the bucket, as MinIO */
    return;
  }
  bool exists = bucket_exists(c);
  if (!exists && buckets_str_eq_c(m, "DELETE") && buckets_query_has(&c->q, "tagging")) {
    c->resp->status = 204; /* MinIO does not check the bucket here */
    return;
  }
  if (!exists) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_BUCKET);
    return;
  }
  if (buckets_str_eq_c(m, "HEAD")) {
    c->resp->status = 200;
    return;
  }
  if (buckets_str_eq_c(m, "DELETE")) {
    if (buckets_query_has(&c->q, "tagging")) {
      buckets_s3_delete_bucket_tagging(c);
      return;
    }
    if (buckets_query_has(&c->q, "lifecycle")) {
      buckets_s3_delete_bucket_lifecycle(c);
      return;
    }
    if (buckets_query_has(&c->q, "encryption")) {
      if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_ENCRYPTION, NULL, 0)) {
        buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
      } else {
        c->resp->status = 204;
        buckets_sr_bucket_meta_hook(c->s->sr, c->bucket, "sse-config");
      }
      return;
    }
    if (buckets_query_has(&c->q, "replication")) {
      buckets_s3_delete_bucket_replication(c);
      return;
    }
    if (pending_subresource(c, false)) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
      return;
    }
    delete_bucket(c); /* DeleteBucketHandler takes any other query */
    return;
  }
  if (buckets_str_eq_c(m, "GET")) {
    if (buckets_query_has(&c->q, "location")) {
      get_bucket_location(c);
    } else if (buckets_query_has(&c->q, "versioning")) {
      get_bucket_versioning(c);
    } else if (buckets_query_has(&c->q, "versions")) {
      buckets_s3_list_object_versions(c);
    } else if (buckets_query_has(&c->q, "object-lock")) {
      buckets_s3_get_bucket_object_lock(c);
    } else if (buckets_query_has(&c->q, "tagging")) {
      buckets_s3_get_bucket_tagging(c);
    } else if (buckets_query_has(&c->q, "lifecycle")) {
      buckets_s3_get_bucket_lifecycle(c);
    } else if (buckets_query_has(&c->q, "encryption")) {
      get_bucket_encryption(c);
    } else if (buckets_query_has(&c->q, "uploads")) {
      buckets_s3_list_uploads(c);
    } else if (buckets_query_has(&c->q, "replication")) {
      buckets_s3_get_bucket_replication(c);
    } else if (buckets_query_has(&c->q, "replication-reset-status")) {
      buckets_s3_reset_bucket_replication_status(c);
    } else if (buckets_query_has(&c->q, "replication-check")) {
      buckets_s3_validate_replication_creds(c);
    } else if (buckets_query_has(&c->q, "replication-metrics")) {
      const char *v = buckets_query_get(&c->q, "replication-metrics");
      buckets_s3_get_bucket_replication_metrics(c, v && strcmp(v, "2") == 0);

    } else if (has_unhandled_subresource(&c->q)) {
      buckets_s3_write_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
    } else {
      const char *lt = buckets_query_get(&c->q, "list-type");
      buckets_s3_list_objects(c, lt && strcmp(lt, "2") == 0);
    }
    return;
  }
  if (buckets_str_eq_c(m, "POST")) {
    if (buckets_query_has(&c->q, "delete")) {
      buckets_s3_delete_objects(c);
    } else if (c->auth == BUCKETS_AUTH_POST_POLICY) {
      buckets_s3_post_policy(c);
    } else {
      buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
    }
    return;
  }
  buckets_s3_write_error(c, BUCKETS_ERR_METHOD_NOT_ALLOWED);
}

/* ---- entry point --------------------------------------------------------- */

static bool is_health_path(buckets_str path) {
  static const char *const paths[] = {
      "/minio/health/live", "/minio/health/ready", "/minio/health/cluster", "/minio/health/cluster/read",
      "/buckets/health/live", "/buckets/health/ready", "/buckets/health/cluster", "/buckets/health/cluster/read",
  };
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(paths); i++) {
    if (buckets_str_eq_c(path, paths[i])) return true;
  }
  return false;
}

/* ---- CORS (MinIO's corsHandler around github.com/rs/cors) ---------------- */

/* wildcard.MatchSimple: '*' matches any run, '?' one character. */
static bool wildcard_match(const char *pat, const char *s) {
  for (; *pat; pat++, s++) {
    if (*pat == '*') {
      if (!pat[1]) return true;
      for (; *s; s++)
        if (wildcard_match(pat + 1, s)) return true;
      return wildcard_match(pat + 1, s);
    }
    if (!*s || (*pat != '?' && *pat != *s)) return false;
  }
  return !*s;
}

/* An origin in `api cors_allow_origin` (comma separated, default "*"). */
static bool cors_origin_allowed(buckets_s3_server *s, const char *origin) {
  char *list = s->config ? buckets_config_sys_value(s->config, "api", "", "cors_allow_origin") : NULL;
  if (!list) list = buckets_xstrdup("*");
  bool ok = false;
  for (char *save = NULL, *o = strtok_r(list, ",", &save); o && !ok; o = strtok_r(NULL, ",", &save)) {
    while (*o == ' ') o++;
    ok = wildcard_match(o, origin);
  }
  free(list);
  return ok;
}

static bool cors_method_allowed(buckets_str m) {
  static const char *const methods[] = {"GET", "PUT", "HEAD", "POST", "DELETE", "OPTIONS", "PATCH"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(methods); i++)
    if (buckets_str_eq_c(m, methods[i])) return true;
  return false;
}

#define CORS_EXPOSE                                                                                                   \
  "Date, Etag, Server, Connection, Accept-Ranges, Content-Range, Content-Encoding, Content-Length, Content-Type, "   \
  "Content-Disposition, Last-Modified, Content-Language, Cache-Control, Retry-After, X-Amz-Bucket-Region, Expires, " \
  "X-Amz*, X-Amz*, *"

/* A preflight (OPTIONS with Access-Control-Request-Method): answered here,
 * 204, never reaching the API. Returns false for any other request. */
static bool cors_preflight(buckets_s3_server *s, const buckets_http_request *req, buckets_http_response *resp) {
  buckets_str rm = buckets_http_header_get(req, "Access-Control-Request-Method");
  if (!buckets_str_eq_c(req->method, "OPTIONS") || !rm.p || !rm.n) return false;
  resp->status = 204;
  buckets_http_resp_header(resp, "Vary", "Origin"); /* one header each, as rs/cors adds them */
  buckets_http_resp_header(resp, "Vary", "Access-Control-Request-Method");
  buckets_http_resp_header(resp, "Vary", "Access-Control-Request-Headers");
  buckets_str origin = buckets_http_header_get(req, "Origin");
  if (!origin.p || !origin.n || !cors_method_allowed(rm)) return true;
  char *o = buckets_str_dup(origin);
  bool allowed = cors_origin_allowed(s, o);
  if (allowed) {
    buckets_http_resp_header(resp, "Access-Control-Allow-Origin", o);
    char *m = buckets_str_dup(rm);
    buckets_http_resp_header(resp, "Access-Control-Allow-Methods", m);
    free(m);
    buckets_str rh = buckets_http_header_get(req, "Access-Control-Request-Headers");
    if (rh.p && rh.n) {
      char *h = buckets_str_dup(rh);
      buckets_http_resp_header(resp, "Access-Control-Allow-Headers", h);
      free(h);
    }
    buckets_http_resp_header(resp, "Access-Control-Allow-Credentials", "true");
  }
  free(o);
  return true;
}

/* handleActualRequest: CORS headers for an allowed Origin (Vary: Origin is
 * among the common headers). */
static void cors_actual(buckets_s3_server *s, const buckets_http_request *req, buckets_http_response *resp) {
  buckets_str origin = buckets_http_header_get(req, "Origin");
  if (!origin.p || !origin.n || !cors_method_allowed(req->method)) return;
  char *o = buckets_str_dup(origin);
  if (cors_origin_allowed(s, o)) {
    buckets_http_resp_header(resp, "Access-Control-Allow-Origin", o);
    buckets_http_resp_header(resp, "Access-Control-Expose-Headers", CORS_EXPOSE);
    buckets_http_resp_header(resp, "Access-Control-Allow-Credentials", "true");
  }
  free(o);
}

void buckets_s3_handle(const buckets_http_request *req, buckets_http_response *resp, void *ud) {
  buckets_s3_server *s = ud;
  if (cors_preflight(s, req, resp)) return;
  cors_actual(s, req, resp);

  buckets_objlayer *layer = s->layer;
  if (is_health_path(req->path) && (buckets_str_eq_c(req->method, "GET") || buckets_str_eq_c(req->method, "HEAD"))) {
    /* live: the process answers. ready: initialized. cluster: every erasure
     * set has write (cluster/read: read) quorum of online drives. */
    bool live = buckets_str_has_suffix(req->path, "/live");
    bool cluster = buckets_str_has_suffix(req->path, "/cluster") || buckets_str_has_suffix(req->path, "/cluster/read");
    bool ok = live || (layer && (!cluster || buckets_objlayer_has_quorum(layer, !buckets_str_has_suffix(req->path, "/read"))));
    resp->status = ok ? 200 : 503;
    return;
  }

  s3_ctx c = {.s = s, .req = req, .resp = resp};
  int api = -1;          /* the MinIO API route taken, for request statistics */
  char *stat_bucket = NULL; /* an existing bucket it names */
  struct timespec t0, w0;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  clock_gettime(CLOCK_REALTIME, &w0);
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  uint64_t nanos = (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec + (s->request_seq++ % 1000);
  snprintf(c.request_id, sizeof(c.request_id), "%016llX", (unsigned long long)nanos);
  common_headers(&c);

  buckets_s3_error err;
  if (!buckets_query_parse(req->query, &c.q)) {
    err = BUCKETS_ERR_INVALID_QUERY_PARAMS;
    goto fail;
  }
  if (!layer) {
    err = BUCKETS_ERR_SERVER_NOT_INITIALIZED;
    goto fail;
  }
  if ((err = parse_path(&c)) != BUCKETS_ERR_NONE) goto fail;
  /* setRequestValidityMiddleware: bad components in query values (a
   * delimiter may be "." or ".."), then the bucket name, before any auth */
  for (size_t i = 0; i < c.q.n; i++) {
    if (strcmp(c.q.items[i].key, "delimiter") != 0 && has_bad_component(c.q.items[i].value)) {
      err = BUCKETS_ERR_INVALID_RESOURCE_NAME;
      c.err_bucket = buckets_xstrdup("");
      c.err_object = buckets_xstrdup("");
      goto fail;
    }
  }
  if (c.bucket && !buckets_str_has_prefix(req->path, "/minio/")) {
    if (buckets_bucket_name_reserved(c.bucket)) {
      err = BUCKETS_ERR_ALL_ACCESS_DISABLED;
    } else if (!buckets_bucket_name_valid(c.bucket)) {
      err = BUCKETS_ERR_INVALID_BUCKET_NAME;
    }
    if (err) { /* reported before the handlers know the bucket or object */
      c.err_bucket = buckets_xstrdup("");
      c.err_object = buckets_xstrdup("");
      goto fail;
    }
  }
  if (!buckets_str_has_prefix(req->path, "/minio/") && !buckets_sts_matches(&c)) {
    api = buckets_s3_api_index(&c); /* collectAPIStats: after the validity filter, before auth */
    if (api >= 0 && buckets_logger_audit_enabled(s->logger)) {
      c.audited = true;
      buckets_audit_tags_set(&c.tags);
    }
    if (api >= 0 && c.bucket && s->meta) {
      buckets_bucket_state *bst = buckets_metasys_get(s->meta, c.bucket);
      if (bst->exists) stat_bucket = buckets_xstrdup(c.bucket);
      buckets_bucket_state_release(bst);
    }
    buckets_stats_begin(api, stat_bucket);
    /* maxClients: the request pool's size and free slots (ListenNotification is not throttled) */
    if (api >= 0 && s->requests_max > 0 && api != buckets_api_index("listennotification")) {
      int64_t busy = buckets_stats_inflight();
      buckets_http_resp_headerf(resp, "X-Ratelimit-Limit", "%d", s->requests_max);
      buckets_http_resp_headerf(resp, "X-Ratelimit-Remaining", "%lld", (long long)(s->requests_max - (busy - 1) > 0 ? s->requests_max - (busy - 1) : 0));
    }
  }
  if (!buckets_admin_is_admin_path(req->path) && s->freeze_cnt > 0) {
    /* frozen (mc admin service freeze): S3 calls wait for the unfreeze */
    pthread_mutex_lock(&s->freeze_mu);
    while (s->freeze_cnt > 0) pthread_cond_wait(&s->freeze_cv, &s->freeze_mu);
    pthread_mutex_unlock(&s->freeze_mu);
  }
  if (buckets_admin_is_admin_path(req->path)) {
    if (buckets_logger_audit_enabled(s->logger)) { /* adminMiddleware audits every admin call */
      c.audited = true;
      buckets_audit_tags_set(&c.tags);
    }
    buckets_str authz = buckets_http_header_get(req, "Authorization");
    if (!authz.p && !buckets_query_has(&c.q, "X-Amz-Signature") && buckets_admin_site_perf_unsigned(s, req->path))
      buckets_admin_handle(&c); /* MinIO's sites call these unsigned */
    else if ((err = authenticate(&c)) != BUCKETS_ERR_NONE) buckets_admin_error(&c, err);
    else buckets_admin_handle(&c);
    if (c.audited && c.op_name) {
      struct timespec t1;
      clock_gettime(CLOCK_MONOTONIC, &t1);
      double ttfb = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
      uint64_t tx = resp->content_length >= 0 ? (uint64_t)resp->content_length : (uint64_t)resp->body.len;
      buckets_s3_audit(&c, -1, (int64_t)(ttfb * 1e9), (int64_t)(ttfb * 1e9), tx);
    }
    goto done;
  }
  if (buckets_admin_is_kms_path(req->path)) {
    if ((err = authenticate(&c)) != BUCKETS_ERR_NONE) buckets_admin_error(&c, err);
    else buckets_admin_kms_handle(&c);
    goto done;
  }
  c.auth = buckets_auth_classify(req, &c.q);
  if (buckets_sts_matches(&c)) {
    buckets_sts_handle(&c);
    goto done;
  }
  if (buckets_s3_metrics_handle(&c)) goto done;
  if (buckets_str_has_prefix(req->path, "/minio/")) {
    err = BUCKETS_ERR_NOT_IMPLEMENTED; /* other MinIO APIs come later */
    goto fail;
  }
  if ((err = authenticate(&c)) != BUCKETS_ERR_NONE) goto fail;

  if (!c.bucket) {
    if (buckets_str_eq_c(req->method, "GET") && buckets_query_has(&c.q, "events")) {
      buckets_s3_listen_notification(&c); /* ListenNotification: every bucket */
    } else if (buckets_str_eq_c(req->method, "GET")) {
      list_buckets(&c);
    } else {
      buckets_s3_write_error(&c, buckets_str_eq_c(req->method, "POST") ? BUCKETS_ERR_NOT_IMPLEMENTED
                                                             : BUCKETS_ERR_METHOD_NOT_ALLOWED);
    }
  } else if (!c.object) {
    route_bucket(&c);
  } else {
    buckets_s3_route_object(&c);
  }
  goto done;

fail:
  /* setAuthMiddleware's rejections */
  if (err == BUCKETS_ERR_REQUEST_TIME_TOO_SKEWED || err == BUCKETS_ERR_MISSING_DATE_HEADER ||
      err == BUCKETS_ERR_MALFORMED_DATE)
    buckets_stats_reject(BUCKETS_REJECT_TIMESTAMP);
  else if (err == BUCKETS_ERR_SIGNATURE_VERSION_NOT_SUPPORTED)
    buckets_stats_reject(BUCKETS_REJECT_AUTH);
  buckets_s3_write_error(&c, err);
done:
  /* writeErrorResponseHeadersOnly: a HEAD error carries no body (nor its length). */
  if (resp->status >= 400 && buckets_str_eq_c(req->method, "HEAD") && !resp->stream) buckets_buf_reset(&resp->body);
  buckets_log_debug("%.*s %.*s -> %d", BUCKETS_STR_ARG(req->method), BUCKETS_STR_ARG(req->target), resp->status);
  if (api >= 0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ttfb = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    uint64_t tx = buckets_str_eq_c(req->method, "HEAD") ? 0
                  : resp->content_length >= 0          ? (uint64_t)resp->content_length
                                                       : (uint64_t)resp->body.len;
    buckets_stats_end(api, stat_bucket, resp->status, ttfb, req->body_len > 0 ? (uint64_t)req->body_len : 0, tx);
    if (c.audited) buckets_s3_audit(&c, api, (int64_t)(ttfb * 1e9), (int64_t)(ttfb * 1e9), tx);
    if (stat_bucket && api == buckets_api_index("deletebucket") && resp->status == 204)
      buckets_stats_forget_bucket(stat_bucket);
  }
  if (buckets_trace_wanted(BUCKETS_TRACE_S3 | BUCKETS_TRACE_INTERNAL)) {
    struct timespec t1, w1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    clock_gettime(CLOCK_REALTIME, &w1);
    int64_t start = (int64_t)w0.tv_sec * 1000000000LL + w0.tv_nsec;
    int64_t end = (int64_t)w1.tv_sec * 1000000000LL + w1.tv_nsec;
    int64_t ttfb = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000000LL + (t1.tv_nsec - t0.tv_nsec);
    uint64_t sent = buckets_str_eq_c(req->method, "HEAD") ? 0
                    : resp->content_length >= 0          ? (uint64_t)resp->content_length
                                                         : (uint64_t)resp->body.len;
    buckets_s3_trace_http(&c, api, start, end, ttfb, sent);
  }
  free(stat_bucket);
  if (c.audited) {
    buckets_audit_tags_set(NULL);
    buckets_audit_tags_free(&c.tags);
    buckets_buf_free(&c.audit_objects);
  }
  free(c.audit_tagging);
  buckets_query_free(&c.q);
  free(c.path);
  free(c.bucket);
  free(c.err_bucket);
  free(c.err_object);
  free(c.object);
  buckets_buf_free(&c.doc);
  buckets_iam_ident_release(c.ident);
  buckets_s3_conds_free(c.conds);
}
