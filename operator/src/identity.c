/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "identity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/buf.h"
#include "crypto/hex.h"
#include "core/log.h"
#include "crypto/sha256.h"
#include "iam.h"
#include "iam/idpsettings.h"
#include "kms.h"
#include "s3client.h"

static const char *str_at(yyjson_val *o, const char *k) { return yyjson_get_str(yyjson_obj_get(o, k)); }

/* ---- what else sets identity ---------------------------------------------------------- */

static bool identity_var(const char *n, bool console) {
  static const char *const server[] = {"MINIO_IDENTITY_OPENID", "MINIO_IDENTITY_LDAP", "BUCKETS_IDENTITY_OPENID",
                                       "BUCKETS_IDENTITY_LDAP", "BUCKETS_OPENID_SYNC_", "BUCKETS_OPENID_REMOVE_", NULL};
  /* consoled also reads MINIO_IDENTITY_OPENID_* when its own are unset */
  static const char *const cons[] = {"BUCKETS_CONSOLE_OIDC_", "CONSOLE_LDAP_ENABLED", "BUCKETS_CONSOLE_LDAP",
                                     "MINIO_IDENTITY_OPENID", NULL};
  for (const char *const *p = console ? cons : server; *p; p++)
    if (strncmp(n, *p, strlen(*p)) == 0) return true;
  return false;
}

static void add_conflict(buckets_buf *b, const char *where, const char *name, size_t len) {
  buckets_buf_appendf(b, "%s%s %.*s", b->len ? ", " : "", where, (int)len, name);
}

static void scan_env(buckets_buf *b, yyjson_val *env, const char *where, bool console) {
  size_t i, n;
  yyjson_val *e;
  yyjson_arr_foreach(env, i, n, e) {
    const char *name = str_at(e, "name");
    if (name && identity_var(name, console)) add_conflict(b, where, name, strlen(name));
  }
}

void op_identity_conflicts(const bc_spec *s, const char *config_env, char *out, size_t cap) {
  buckets_buf b = BUCKETS_BUF_INIT;
  scan_env(&b, s->env, "spec.env", false);
  scan_env(&b, s->console.env, "spec.console.env", true);
  for (const char *p = config_env; p && *p;) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    const char *q = p;
    while (q < p + len && (*q == ' ' || *q == '\t')) q++;
    if (strncmp(q, "export ", 7) == 0) q += 7;
    const char *eq = memchr(q, '=', (size_t)(p + len - q));
    if (eq && *q != '#') {
      char name[128];
      snprintf(name, sizeof(name), "%.*s", (int)(eq - q), q);
      if (identity_var(name, false)) add_conflict(&b, "config.env", name, strlen(name));
    }
    p = eol ? eol + 1 : p + len;
  }
  snprintf(out, cap, "%s", b.len ? b.data : "");
  buckets_buf_free(&b);
}

/* ---- applying ------------------------------------------------------------------------ */

static void hash16(const char *text, size_t n, char out[17]) {
  uint8_t h[32];
  buckets_sha256(text, n, h);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
}

/* The identity_ldap line, when LDAP is configured ("" when it is off). */
static void ldap_hash_of(const char *config, yyjson_val *settings, char out[17]) {
  out[0] = '\0';
  if (!yyjson_is_obj(yyjson_obj_get(settings, "ldap"))) return;
  const char *l = strstr(config, "identity_ldap ");
  if (!l) return;
  const char *eol = strchr(l, '\n');
  hash16(l, eol ? (size_t)(eol - l) : strlen(l), out);
}

/* The identity sync's settings, when removal is on: on the servers' pod template (s->identity), the client
 * secret in Secret <name>-identity-sync, written when it changes (prev: the last syncHash). The servers
 * follow the settings in force; a change restarts them, as LDAP's does. False and why when the Secret
 * cannot be written. */
static bool sync_settings(op_ctx *o, bc_spec *s, yyjson_val *settings, const char *prev, char *err, size_t errlen) {
  buckets_idp_removal rm;
  if (!buckets_idp_removal_of(settings, &rm)) return true;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "%s|%s|%s|%s|%s|%s|%s|%s|%ld|%ld|%ld", rm.provider, rm.tenant, rm.client_id,
                      rm.client_secret, rm.api_token, rm.url, rm.realm, rm.issuer, rm.delete_after_days,
                      rm.max_per_sync, rm.interval_minutes);
  char hash[17];
  hash16(b.data, b.len, hash);
  memset(b.data, 0, b.len);
  buckets_buf_free(&b);
  if (!prev || strcmp(prev, hash) != 0) {
    yyjson_mut_doc *sec = bc_identity_sync_secret(s, strcmp(rm.provider, "okta") == 0 ? NULL : rm.client_secret,
                                                  strcmp(rm.provider, "okta") == 0 ? rm.api_token : NULL);
    char name[160];
    bc_identity_sync_secret_name(s, name, sizeof(name));
    buckets_buf path = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&path, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
    yyjson_doc *resp = NULL;
    int st = kube_apply(o->k, path.data, sec, &resp);
    if (st / 100 != 2) snprintf(err, errlen, "Secret %s cannot be written (%d): %s", name, st, kube_error_message(resp));
    yyjson_doc_free(resp);
    yyjson_mut_doc_free(sec);
    buckets_buf_free(&path);
    if (st / 100 != 2) return false;
  }
  snprintf(s->identity.sync_hash, sizeof(s->identity.sync_hash), "%s", hash);
  snprintf(s->identity.sync_provider, sizeof(s->identity.sync_provider), "%s", rm.provider);
  snprintf(s->identity.sync_tenant, sizeof(s->identity.sync_tenant), "%s", rm.tenant);
  snprintf(s->identity.sync_url, sizeof(s->identity.sync_url), "%s", rm.url);
  snprintf(s->identity.sync_realm, sizeof(s->identity.sync_realm), "%s", rm.realm);
  snprintf(s->identity.sync_issuer, sizeof(s->identity.sync_issuer), "%s", rm.issuer);
  s->identity.sync_interval_s = rm.interval_minutes * 60;
  snprintf(s->identity.sync_client_id, sizeof(s->identity.sync_client_id), "%s", rm.client_id);
  s->identity.sync_days = rm.delete_after_days;
  s->identity.sync_max = rm.max_per_sync;
  return true;
}

static void status(yyjson_mut_doc *d, yyjson_mut_val *idn, const char *phase, const char *message, const char *desc,
                   const char *applied, const char *ldap) {
  yyjson_mut_obj_add_strcpy(d, idn, "phase", phase);
  if (message && *message) yyjson_mut_obj_add_strcpy(d, idn, "message", message);
  if (desc && *desc) yyjson_mut_obj_add_strcpy(d, idn, "description", desc);
  if (applied && *applied) yyjson_mut_obj_add_strcpy(d, idn, "appliedHash", applied);
  if (ldap && *ldap) yyjson_mut_obj_add_strcpy(d, idn, "ldapHash", ldap);
}

/* bucketsd's answer to a refused `config set`: its error message, or the status. */
static void refusal(int st, const buckets_buf *body, char *out, size_t cap) {
  yyjson_doc *j = body->len ? yyjson_read(body->data, body->len, 0) : NULL;
  const char *m = j ? str_at(yyjson_doc_get_root(j), "Message") : NULL;
  if (m && *m) snprintf(out, cap, "%s", m);
  else if (st == 0) snprintf(out, cap, "the servers cannot be reached");
  else snprintf(out, cap, "the servers answered %d", st);
  yyjson_doc_free(j);
}

/* Each line through `config set`; false and why when bucketsd refuses one. */
static bool apply_lines(op_ctx *o, yyjson_val *bc, const char *config, char *err, size_t errlen) {
  op_admin *a = op_cluster_admin(o, bc, err, errlen);
  if (!a) return false;
  bool ok = true;
  for (const char *p = config; ok && *p;) {
    const char *eol = strchr(p, '\n');
    size_t len = eol ? (size_t)(eol - p) : strlen(p);
    if (len) {
      buckets_buf body = BUCKETS_BUF_INIT;
      int st = s3c_admin(op_admin_client(a), "PUT", "set-config-kv", NULL, p, len, true, false, &body);
      if (st / 100 != 2) {
        char why[512];
        refusal(st, &body, why, sizeof(why));
        snprintf(err, errlen, "The servers refused the %s settings: %s",
                 strncmp(p, "identity_ldap", 13) == 0 ? "LDAP" : "OpenID", why);
        ok = false;
      }
      buckets_buf_free(&body);
    }
    p = eol ? eol + 1 : p + len;
  }
  op_cluster_admin_free(a);
  return ok;
}

static bool write_console(op_ctx *o, const bc_spec *s, yyjson_val *settings, char *err, size_t errlen) {
  yyjson_mut_doc *v = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(v, buckets_idp_console_view(v, settings));
  char *json = yyjson_mut_write(v, 0, NULL);
  yyjson_mut_doc_free(v);
  yyjson_mut_doc *sec = bc_identity_console_secret(s, json);
  memset(json, 0, strlen(json));
  free(json);
  char name[160];
  bc_identity_console_secret_name(s, name, sizeof(name));
  buckets_buf path = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&path, "/api/v1/namespaces/%s/secrets/%s", s->ns, name);
  yyjson_doc *resp = NULL;
  int st = kube_apply(o->k, path.data, sec, &resp);
  if (st / 100 != 2) snprintf(err, errlen, "Secret %s cannot be written (%d): %s", name, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  yyjson_mut_doc_free(sec);
  buckets_buf_free(&path);
  return st / 100 == 2;
}

void op_identity_reconcile(op_ctx *o, yyjson_val *bc, bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *idn) {
  yyjson_val *prev = yyjson_obj_get(yyjson_obj_get(bc, "status"), "identity");
  const char *prev_hash = str_at(prev, "appliedHash"), *prev_ldap = str_at(prev, "ldapHash");
  const char *prev_phase = str_at(prev, "phase");
  /* until applied anew, the servers keep restarting for the LDAP they have */
  snprintf(s->identity.ldap_hash, sizeof(s->identity.ldap_hash), "%s", prev_ldap ? prev_ldap : "");

  char name[160], err[1024] = "";
  bc_identity_secret_name(s, name, sizeof(name));
  bool ok = op_secret_ensure_empty(o, s, name, err, sizeof(err));
  char cand[160];
  bc_identity_candidate_secret_name(s, cand, sizeof(cand));
  ok = ok && op_secret_ensure_empty(o, s, cand, err, sizeof(err));
  if (!ok) {
    status(d, idn, "Error", err, NULL, prev_hash, prev_ldap);
    return;
  }
  char *raw = op_secret_text(o, s, name, "settings.json");
  yyjson_doc *sd = raw ? yyjson_read(raw, strlen(raw), 0) : NULL;
  yyjson_val *settings = sd ? yyjson_doc_get_root(sd) : NULL;
  if (!yyjson_is_obj(settings)) {
    status(d, idn, "NotManaged", "Sign-in is not set up from the console; the servers' own settings apply.", NULL, NULL,
           prev_ldap);
    goto done;
  }
  char desc[600];
  buckets_idp_settings_describe(settings, desc, sizeof(desc));
  char *config_env = s->config_secret ? op_secret_text(o, s, s->config_secret, "config.env") : NULL;
  char conflicts[1024];
  op_identity_conflicts(s, config_env, conflicts, sizeof(conflicts));
  if (config_env) memset(config_env, 0, strlen(config_env));
  free(config_env);
  if (*conflicts) {
    char msg[1400];
    snprintf(msg, sizeof(msg),
             "Sign-in is also set in %s, which would override these settings: remove those entries to manage sign-in "
             "from the console.",
             conflicts);
    status(d, idn, "Conflict", msg, desc, prev_hash, prev_ldap);
    goto done;
  }
  buckets_buf config = BUCKETS_BUF_INIT;
  if (!buckets_idp_server_config(settings, &config, err, sizeof(err))) {
    status(d, idn, "Error", err, desc, prev_hash, prev_ldap);
    buckets_buf_free(&config);
    goto done;
  }
  char hash[17], ldap[17];
  hash16(raw, strlen(raw), hash);
  ldap_hash_of(config.data, settings, ldap);
  if (!sync_settings(o, s, settings, str_at(prev, "syncHash"), err, sizeof(err))) {
    status(d, idn, "Error", err, desc, prev_hash, prev_ldap);
    buckets_buf_free(&config);
    goto done;
  }
  if (prev_hash && strcmp(prev_hash, hash) == 0 && prev_phase && strcmp(prev_phase, "Ready") == 0) {
    status(d, idn, "Ready", NULL, desc, hash, ldap);
    snprintf(s->identity.ldap_hash, sizeof(s->identity.ldap_hash), "%s", ldap);
  } else if (!apply_lines(o, bc, config.data, err, sizeof(err))) {
    buckets_log_warn("%s/%s: identity: %s", s->ns, s->name, err);
    status(d, idn, "Error", err, desc, prev_hash, prev_ldap);
  } else if (!write_console(o, s, settings, err, sizeof(err))) {
    status(d, idn, "Error", err, desc, prev_hash, prev_ldap);
  } else {
    bool restart = strcmp(ldap, prev_ldap ? prev_ldap : "") != 0;
    buckets_log_info("%s/%s: identity settings applied (%s)%s", s->ns, s->name, desc,
                     restart ? "; the servers restart for LDAP" : "");
    status(d, idn, "Ready", restart ? "Applied. The servers restart one at a time to load the LDAP settings." : NULL, desc,
           hash, ldap);
    snprintf(s->identity.ldap_hash, sizeof(s->identity.ldap_hash), "%s", ldap);
  }
  if (config.data) memset(config.data, 0, config.len);
  buckets_buf_free(&config);
  if (s->identity.sync_hash[0]) yyjson_mut_obj_add_strcpy(d, idn, "syncHash", s->identity.sync_hash);
done:
  yyjson_doc_free(sd);
  if (raw) memset(raw, 0, strlen(raw));
  free(raw);
}
