/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "console/idpconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>

#include "config/config.h"
#include "core/log.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "iam/idpsettings.h"
#include "iam/idsync.h"
#include "iam/ldapidp.h"
#include "iam/openid.h"
#include "k8s/kube.h"

#define GROUP_PATH "/apis/buckets.io/v1alpha1"
#define MAX_BODY (256 * 1024)

struct buckets_console_idp {
  kube *k;
  char *cluster, *ns;
};

buckets_console_idp *buckets_console_idp_new(void) {
  const char *cluster = getenv("BUCKETS_CONSOLE_CLUSTER"), *ns = getenv("BUCKETS_CONSOLE_NAMESPACE");
  if (!cluster || !*cluster || !ns || !*ns) return NULL;
  char err[256];
  kube *k = kube_from_env(err, sizeof(err));
  if (!k) {
    buckets_log_warn("console: identity settings unavailable: Kubernetes API: %s", err);
    return NULL;
  }
  kube_set_field_manager(k, "buckets-console");
  buckets_console_idp *m = buckets_xcalloc(1, sizeof(*m));
  m->k = k;
  m->cluster = buckets_xstrdup(cluster);
  m->ns = buckets_xstrdup(ns);
  return m;
}

void buckets_console_idp_free(buckets_console_idp *m) {
  if (!m) return;
  kube_free(m->k);
  free(m->cluster);
  free(m->ns);
  free(m);
}

/* ---- replies ------------------------------------------------------------------- */

static void reply(buckets_http_response *resp, int status, yyjson_mut_doc *d) {
  size_t n;
  char *js = yyjson_mut_write(d, 0, &n);
  yyjson_mut_doc_free(d);
  resp->status = status;
  buckets_http_resp_header_set(resp, "Content-Type", "application/json");
  buckets_buf_reset(&resp->body);
  buckets_buf_append(&resp->body, js, n);
  free(js);
}

static void fail(buckets_http_response *resp, int status, const char *code, const char *message) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "code", code);
  yyjson_mut_obj_add_strcpy(d, o, "message", message);
  reply(resp, status, d);
}

static yyjson_mut_doc *new_obj(yyjson_mut_val **o) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, *o);
  return d;
}

/* ---- the cluster and its Secrets ---------------------------------------------------- */

static void secret_path(const buckets_console_idp *m, const char *suffix, buckets_buf *p) {
  buckets_buf_appendf(p, "/api/v1/namespaces/%s/secrets/%s%s", m->ns, m->cluster, suffix);
}

static int get_secret(buckets_console_idp *m, const char *suffix, yyjson_doc **out) {
  buckets_buf p = BUCKETS_BUF_INIT;
  secret_path(m, suffix, &p);
  int st = kube_get(m->k, p.data, out);
  buckets_buf_free(&p);
  return st;
}

/* data[key] of a Secret, decoded; NULL if absent. */
static char *secret_text(yyjson_val *secret, const char *key) {
  const char *b64 = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(secret, "data"), key));
  if (!b64) return NULL;
  size_t n = strlen(b64);
  char *raw = buckets_xmalloc(n * 3 / 4 + 4);
  long k = buckets_base64_decode(b64, n, (uint8_t *)raw);
  if (k <= 0) {
    free(raw);
    return NULL;
  }
  raw[k] = '\0';
  return raw;
}

static void wipe(char *s) {
  if (s) OPENSSL_cleanse(s, strlen(s));
  free(s);
}

/* Replaces a Secret's contents with the given keys (NULL values left out). */
static int put_secret(buckets_console_idp *m, const char *suffix, yyjson_val *current, const char *k1, const char *v1,
                      const char *k2, const char *v2) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  yyjson_mut_obj_add_str(d, o, "apiVersion", "v1");
  yyjson_mut_obj_add_str(d, o, "kind", "Secret");
  yyjson_mut_obj_add_val(d, o, "metadata", yyjson_val_mut_copy(d, yyjson_obj_get(current, "metadata"))); /* no lost update */
  yyjson_mut_obj_add_str(d, o, "type", "Opaque");
  yyjson_mut_val *sd = yyjson_mut_obj_add_obj(d, o, "stringData");
  if (v1) yyjson_mut_obj_add_strcpy(d, sd, k1, v1);
  if (k2 && v2) yyjson_mut_obj_add_strcpy(d, sd, k2, v2);
  buckets_buf p = BUCKETS_BUF_INIT;
  secret_path(m, suffix, &p);
  yyjson_doc *resp = NULL;
  int st = kube_update(m->k, p.data, d, &resp);
  if (st / 100 != 2) buckets_log_warn("console: updating %s: %d %s", p.data, st, kube_error_message(resp));
  yyjson_doc_free(resp);
  buckets_buf_free(&p);
  yyjson_mut_doc_free(d);
  return st;
}

static void hash16(const char *text, char out[17]) {
  uint8_t h[32];
  buckets_sha256(text, strlen(text), h);
  buckets_hex_encode(h, 8, out);
  out[16] = '\0';
}

/* A Secret's settings.json: the raw text, its hash and the parsed document. */
typedef struct {
  yyjson_doc *secret, *settings, *test;
  char *raw;
  char hash[17];
  int status;
} saved;

static void saved_load(buckets_console_idp *m, const char *suffix, saved *s) {
  memset(s, 0, sizeof(*s));
  s->status = get_secret(m, suffix, &s->secret);
  yyjson_val *sec = yyjson_doc_get_root(s->secret);
  s->raw = s->status == 200 ? secret_text(sec, "settings.json") : NULL;
  if (s->raw) {
    s->settings = yyjson_read(s->raw, strlen(s->raw), 0);
    hash16(s->raw, s->hash);
  }
  char *t = s->status == 200 ? secret_text(sec, "test.json") : NULL;
  if (t) s->test = yyjson_read(t, strlen(t), 0);
  free(t);
}

static void saved_free(saved *s) {
  yyjson_doc_free(s->secret);
  yyjson_doc_free(s->settings);
  yyjson_doc_free(s->test);
  wipe(s->raw);
}

/* The candidate's recorded tests, when they are of this very candidate. */
static yyjson_val *tests_of(const saved *c) {
  yyjson_val *t = yyjson_doc_get_root(c->test);
  const char *h = yyjson_get_str(yyjson_obj_get(t, "hash"));
  return h && c->raw && strcmp(h, c->hash) == 0 ? t : NULL;
}

/* ---- the settings as the servers read them --------------------------------------------- */

static buckets_config *server_config(yyjson_val *settings, char *err, size_t errlen) {
  buckets_buf text = BUCKETS_BUF_INIT;
  if (!buckets_idp_server_config(settings, &text, err, errlen)) {
    buckets_buf_free(&text);
    return NULL;
  }
  buckets_config *cfg = buckets_config_new();
  for (char *line = text.data, *eol; line && *line; line = eol ? eol + 1 : NULL) {
    eol = strchr(line, '\n');
    if (eol) *eol = '\0';
    bool dyn;
    if (*line && !buckets_config_set_text(cfg, line, &dyn, err, errlen)) {
      buckets_config_free(cfg);
      cfg = NULL;
      break;
    }
  }
  OPENSSL_cleanse(text.data, text.len);
  buckets_buf_free(&text);
  return cfg;
}

/* The names in a claim: an array of strings, or one comma-separated string. */
static void claim_values(yyjson_mut_val *v, yyjson_mut_doc *d, yyjson_mut_val *out) {
  if (yyjson_mut_is_arr(v)) {
    size_t i, n;
    yyjson_mut_val *e;
    yyjson_mut_arr_foreach(v, i, n, e) if (yyjson_mut_is_str(e)) yyjson_mut_arr_add_strcpy(d, out, yyjson_mut_get_str(e));
  } else if (yyjson_mut_is_str(v)) {
    const char *s = yyjson_mut_get_str(v);
    while (*s) {
      size_t n = strcspn(s, ",");
      char one[256];
      snprintf(one, sizeof(one), "%.*s", (int)n, s);
      char *a = one;
      while (*a == ' ') a++;
      size_t l = strlen(a);
      while (l && a[l - 1] == ' ') a[--l] = '\0';
      if (*a) yyjson_mut_arr_add_strcpy(d, out, a);
      s += n + (s[n] == ',');
    }
  }
}

/* Which of names are policies that exist (list-canned-policies as the admin). */
static bool match_policies(const buckets_console_idp_session *sess, yyjson_mut_doc *d, yyjson_mut_val *names,
                           yyjson_mut_val *matched, yyjson_mut_val *unmatched) {
  buckets_buf body = BUCKETS_BUF_INIT;
  int st = sess->admin_get(sess->ud, "list-canned-policies", NULL, false, &body);
  yyjson_doc *pd = st == 200 ? yyjson_read(body.data ? body.data : "", body.len, 0) : NULL;
  buckets_buf_free(&body);
  yyjson_val *pol = yyjson_doc_get_root(pd);
  size_t i, n;
  yyjson_mut_val *e;
  yyjson_mut_arr_foreach(names, i, n, e) {
    const char *name = yyjson_mut_get_str(e);
    yyjson_mut_arr_add_strcpy(d, yyjson_obj_get(pol, name) ? matched : unmatched, name);
  }
  yyjson_doc_free(pd);
  return pol != NULL;
}

static const char *user_of(yyjson_mut_val *claims) {
  static const char *const keys[] = {"preferred_username", "email", "name", "sub"};
  for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
    const char *v = yyjson_mut_get_str(yyjson_mut_obj_get(claims, keys[i]));
    if (v && *v) return v;
  }
  return "";
}

yyjson_mut_doc *buckets_console_idp_check_token(yyjson_val *settings, const char *id_token, const char *access_token,
                                                const buckets_console_idp_session *sess) {
  yyjson_mut_val *o;
  yyjson_mut_doc *d = new_obj(&o);
  char err[1024] = "";
  buckets_config *cfg = server_config(settings, err, sizeof(err));
  buckets_openid *oid = cfg ? buckets_openid_build(cfg, sess->region, err, sizeof(err)) : NULL;
  buckets_config_free(cfg);
  yyjson_mut_doc *claims = NULL;
  if (!oid) {
    yyjson_mut_obj_add_bool(d, o, "passed", false);
    yyjson_mut_obj_add_strcpy(d, o, "error", *err ? err : "The OpenID settings cannot be used.");
    return d;
  }
  buckets_oidc_status vs = buckets_openid_validate(oid, NULL, id_token, access_token, NULL, &claims, err, sizeof(err));
  if (vs != BUCKETS_OIDC_OK) {
    char msg[1200];
    snprintf(msg, sizeof(msg), "The provider signed you in, but its ID token does not check out: %s", err);
    yyjson_mut_obj_add_bool(d, o, "passed", false);
    yyjson_mut_obj_add_strcpy(d, o, "error", msg);
    yyjson_mut_doc_free(claims);
    buckets_openid_release(oid);
    return d;
  }
  yyjson_mut_val *cl = yyjson_mut_doc_get_root(claims);
  yyjson_mut_obj_add_strcpy(d, o, "user", user_of(cl));
  const char *rp = yyjson_get_str(yyjson_obj_get(yyjson_obj_get(settings, "openid"), "rolePolicy"));
  yyjson_mut_val *roles = yyjson_mut_obj_add_arr(d, o, "roles");
  yyjson_mut_val *matched = yyjson_mut_obj_add_arr(d, o, "policies");
  yyjson_mut_val *unmatched = yyjson_mut_obj_add_arr(d, o, "unmatched");
  bool passed;
  if (rp && *rp) { /* everyone who signs in gets the role's policies */
    yyjson_mut_val *v = yyjson_mut_strcpy(d, rp);
    claim_values(v, d, roles);
    match_policies(sess, d, roles, matched, unmatched);
    passed = yyjson_mut_arr_size(unmatched) == 0;
    if (!passed) yyjson_mut_obj_add_str(d, o, "error", "Some of the role's policies do not exist yet: create them first.");
  } else {
    const char *cn = buckets_openid_claim_name(oid);
    yyjson_mut_obj_add_strcpy(d, o, "claimName", cn);
    claim_values(yyjson_mut_obj_get(cl, cn), d, roles);
    bool listed = match_policies(sess, d, roles, matched, unmatched);
    passed = yyjson_mut_arr_size(matched) > 0;
    if (!passed) {
      char msg[600];
      if (!yyjson_mut_arr_size(roles))
        snprintf(msg, sizeof(msg),
                 "Signed in, but the token has no \"%s\" claim: assign yourself a role in the provider, or check the claim name.",
                 cn);
      else if (!listed) snprintf(msg, sizeof(msg), "Signed in, but the policies could not be listed to match the roles.");
      else snprintf(msg, sizeof(msg), "Signed in, but none of the token's roles names a policy: create a policy named after a role.");
      yyjson_mut_obj_add_strcpy(d, o, "error", msg);
    }
  }
  yyjson_mut_obj_add_bool(d, o, "passed", passed);
  yyjson_mut_obj_add_val(d, o, "claims", yyjson_mut_val_mut_copy(d, cl));
  yyjson_mut_doc_free(claims);
  buckets_openid_release(oid);
  return d;
}

/* ---- tests -------------------------------------------------------------------------- */

void buckets_console_idp_record_test(buckets_console_idp *m, const char *hash, const char *part, yyjson_mut_doc *result) {
  saved c;
  saved_load(m, "-identity-candidate", &c);
  if (!c.raw || strcmp(c.hash, hash) != 0) { /* the candidate changed meanwhile: the test is of no use */
    saved_free(&c);
    return;
  }
  yyjson_mut_doc *t = yyjson_mut_doc_new(NULL);
  yyjson_val *prev = tests_of(&c);
  yyjson_mut_val *root = prev ? yyjson_val_mut_copy(t, prev) : yyjson_mut_obj(t);
  yyjson_mut_doc_set_root(t, root);
  yyjson_mut_obj_remove_key(root, "hash");
  yyjson_mut_obj_add_strcpy(t, root, "hash", hash);
  yyjson_mut_obj_remove_key(root, part);
  yyjson_mut_val *r = yyjson_mut_val_mut_copy(t, yyjson_mut_doc_get_root(result));
  yyjson_mut_obj_add_int(t, r, "at", (int64_t)time(NULL));
  yyjson_mut_obj_add_val(t, root, part, r);
  char *js = yyjson_mut_write(t, 0, NULL);
  put_secret(m, "-identity-candidate", yyjson_doc_get_root(c.secret), "settings.json", c.raw, "test.json", js);
  free(js);
  yyjson_mut_doc_free(t);
  saved_free(&c);
}

yyjson_doc *buckets_console_idp_candidate(buckets_console_idp *m, char hash[17]) {
  saved c;
  saved_load(m, "-identity-candidate", &c);
  yyjson_doc *s = c.settings;
  c.settings = NULL;
  snprintf(hash, 17, "%s", c.hash);
  saved_free(&c);
  return s;
}

static void handle_ldap_test(buckets_console_idp *m, yyjson_val *body, const buckets_console_idp_session *sess,
                             buckets_http_response *resp) {
  const char *user = yyjson_get_str(yyjson_obj_get(body, "username"));
  const char *pass = yyjson_get_str(yyjson_obj_get(body, "password"));
  if (!user || !*user) {
    fail(resp, 400, "InvalidRequest", "Enter a user name to look up.");
    return;
  }
  saved c;
  saved_load(m, "-identity-candidate", &c);
  yyjson_val *settings = yyjson_doc_get_root(c.settings);
  if (!yyjson_is_obj(yyjson_obj_get(settings, "ldap"))) {
    saved_free(&c);
    fail(resp, 409, "NoCandidate", "Save LDAP settings before testing them.");
    return;
  }
  yyjson_mut_val *o;
  yyjson_mut_doc *d = new_obj(&o);
  char err[1024] = "";
  buckets_config *cfg = server_config(settings, err, sizeof(err));
  buckets_ldapidp *p = cfg ? buckets_ldapidp_build(cfg, sess->ca_file, err, sizeof(err)) : NULL;
  buckets_config_free(cfg);
  bool passed = false;
  if (!p) {
    char msg[1200];
    snprintf(msg, sizeof(msg), "The directory cannot be used with these settings: %s", err);
    yyjson_mut_obj_add_strcpy(d, o, "error", msg);
  } else {
    buckets_ldap_dnres dn = {0};
    char **groups = NULL;
    size_t ng = 0;
    int found = pass && *pass ? (buckets_ldapidp_bind(p, user, pass, &dn, &groups, &ng, err, sizeof(err)) ? 1 : -1)
                              : buckets_ldapidp_lookup_user(p, user, &dn, &groups, &ng, err, sizeof(err));
    if (found == 1) {
      yyjson_mut_obj_add_strcpy(d, o, "dn", dn.actual_dn ? dn.actual_dn : dn.norm_dn);
      yyjson_mut_val *ga = yyjson_mut_obj_add_arr(d, o, "groups");
      for (size_t i = 0; i < ng; i++) yyjson_mut_arr_add_strcpy(d, ga, groups[i]);
      /* the policies attached to the user's DN or groups, as the admin sees them */
      buckets_buf q = BUCKETS_BUF_INIT, pb = BUCKETS_BUF_INIT;
      buckets_buf_append_c(&q, "user=");
      buckets_url_encode(&q, dn.norm_dn ? dn.norm_dn : "", false);
      for (size_t i = 0; i < ng; i++) {
        buckets_buf_append_c(&q, "&group=");
        buckets_url_encode(&q, groups[i], false);
      }
      int st = sess->admin_get(sess->ud, "idp/ldap/policy-entities", q.data, true, &pb);
      yyjson_doc *pd = st == 200 ? yyjson_read(pb.data ? pb.data : "", pb.len, 0) : NULL;
      yyjson_mut_val *pa = yyjson_mut_obj_add_arr(d, o, "policies");
      static const char *const lists[] = {"userMappings", "groupMappings"}; /* madmin.PolicyEntitiesResult */
      for (size_t l = 0; l < 2; l++) {
        size_t i, n, j, k;
        yyjson_val *e, *pn;
        yyjson_arr_foreach(yyjson_obj_get(yyjson_doc_get_root(pd), lists[l]), i, n, e) {
          yyjson_arr_foreach(yyjson_obj_get(e, "policies"), j, k, pn) {
            const char *name = yyjson_get_str(pn);
            bool dup = false;
            size_t x, xn;
            yyjson_mut_val *have;
            yyjson_mut_arr_foreach(pa, x, xn, have) dup = dup || strcmp(yyjson_mut_get_str(have), name) == 0;
            if (name && !dup) yyjson_mut_arr_add_strcpy(d, pa, name);
          }
        }
      }
      yyjson_doc_free(pd);
      buckets_buf_free(&q);
      buckets_buf_free(&pb);
      passed = true;
      if (!yyjson_mut_arr_size(pa))
        yyjson_mut_obj_add_str(d, o, "note",
                               "Found, but no policy is attached to this user or their groups yet: attach one "
                               "(mc admin idp ldap policy attach), or they can sign in but do nothing.");
    } else {
      char msg[1200];
      snprintf(msg, sizeof(msg), found == 0 ? "No such user under the user search base: %s"
                                            : pass && *pass ? "The user cannot sign in: %s"
                                                            : "The directory search failed: %s",
               err);
      yyjson_mut_obj_add_strcpy(d, o, "error", msg);
    }
    buckets_ldap_strv_free(groups, ng);
    buckets_ldap_dnres_free(&dn);
    buckets_ldapidp_release(p);
  }
  yyjson_mut_obj_add_bool(d, o, "passed", passed);
  /* Recorded unless a lookup of these settings passed already: a wrong user name or password is
   * about that person, and must not take back what the settings have shown. */
  yyjson_val *prev = tests_of(&c);
  bool had_pass = yyjson_get_bool(yyjson_obj_get(yyjson_obj_get(prev, "ldap"), "passed"));
  if (c.raw && (passed || !had_pass)) buckets_console_idp_record_test(m, c.hash, "ldap", d);
  saved_free(&c);
  reply(resp, 200, d);
}

/* Removing people who leave: one person looked up in Microsoft Graph with the saved settings, which shows the
 * app may read the directory (Graph's User.Read.All). Recorded as the "removal" test. */
static void handle_removal_test(buckets_console_idp *m, yyjson_val *body, const buckets_console_idp_session *sess,
                                buckets_http_response *resp) {
  const char *user = yyjson_get_str(yyjson_obj_get(body, "user"));
  if (!user || !*user) {
    fail(resp, 400, "InvalidRequest", "Enter a person's sign-in name or ID.");
    return;
  }
  saved c;
  saved_load(m, "-identity-candidate", &c);
  buckets_idp_removal rm;
  if (!buckets_idp_removal_of(yyjson_doc_get_root(c.settings), &rm)) {
    saved_free(&c);
    fail(resp, 409, "NoCandidate", "Turn on removing people who leave, and save, before testing it.");
    return;
  }
  buckets_idsync_settings st = {0};
  snprintf(st.provider, sizeof(st.provider), "%s", rm.provider);
  snprintf(st.tenant, sizeof(st.tenant), "%s", rm.tenant);
  snprintf(st.client_id, sizeof(st.client_id), "%s", rm.client_id);
  snprintf(st.client_secret, sizeof(st.client_secret), "%s", rm.client_secret);
  snprintf(st.api_token, sizeof(st.api_token), "%s", rm.api_token);
  snprintf(st.realm, sizeof(st.realm), "%s", rm.realm);
  snprintf(st.url, sizeof(st.url), "%s", rm.url);
  snprintf(st.issuer, sizeof(st.issuer), "%s", rm.issuer);
  st.roles = rm.roles; /* and their roles now, as the sync will keep them (docs/design/roles-current.md) */
  snprintf(st.roles_from, sizeof(st.roles_from), "%s", rm.roles_from);
  snprintf(st.app_id, sizeof(st.app_id), "%s", rm.client_id);
  /* Microsoft's endpoints, unless a test points them elsewhere (as the servers' sync allows) */
  const char *login = getenv("BUCKETS_OPENID_SYNC_LOGIN_URL"), *graph = getenv("BUCKETS_OPENID_SYNC_GRAPH_URL");
  snprintf(st.login_url, sizeof(st.login_url), "%s", login && *login ? login : "https://login.microsoftonline.com");
  snprintf(st.graph_url, sizeof(st.graph_url), "%s", graph && *graph ? graph : "https://graph.microsoft.com");
  const char *okta = getenv("BUCKETS_OPENID_SYNC_URL");
  if (strcmp(rm.provider, "okta") == 0 && okta && *okta) snprintf(st.url, sizeof(st.url), "%s", okta);
  buckets_idsync_client *client = buckets_idsync_client_new(&st);
  memset(st.client_secret, 0, sizeof(st.client_secret));
  memset(st.api_token, 0, sizeof(st.api_token));
  buckets_idsync_person who;
  char err[1024] = "";
  buckets_idsync_state state = buckets_idsync_client_lookup(client, user, &who, err, sizeof(err));
  char **values = NULL, rerr[1024] = "";
  size_t nvalues = 0;
  bool asked = rm.roles && (state == BUCKETS_IDSYNC_ACTIVE || state == BUCKETS_IDSYNC_DISABLED) &&
               buckets_idsync_client_values(client, who.id, &values, &nvalues, rerr, sizeof(rerr));
  buckets_idsync_client_free(client);
  const char *need = strcmp(rm.provider, "entra") == 0
                         ? "The app needs Microsoft Graph's User.Read.All application permission, with admin consent."
                     : strcmp(rm.provider, "keycloak") == 0
                         ? "The client needs Service accounts roles on, and realm-management's view-users role for its "
                           "service account."
                         : "The API token needs to belong to an administrator who may read users (Read-only "
                           "Administrator is enough).";
  yyjson_mut_val *o;
  yyjson_mut_doc *d = new_obj(&o);
  bool passed = state == BUCKETS_IDSYNC_ACTIVE || state == BUCKETS_IDSYNC_DISABLED;
  yyjson_mut_obj_add_strcpy(d, o, "user", user);
  if (passed) {
    yyjson_mut_obj_add_str(d, o, "state", buckets_idsync_state_name(state));
    yyjson_mut_obj_add_strcpy(d, o, "id", who.id);
    yyjson_mut_obj_add_strcpy(d, o, "displayName", who.display_name);
    yyjson_mut_obj_add_strcpy(d, o, "userPrincipalName", who.upn);
    if (asked) {
      yyjson_mut_val *roles = yyjson_mut_obj_add_arr(d, o, "roles");
      for (size_t i = 0; i < nvalues; i++) yyjson_mut_arr_add_strcpy(d, roles, values[i]);
      match_policies(sess, d, roles, yyjson_mut_obj_add_arr(d, o, "policies"), yyjson_mut_obj_add_arr(d, o, "unmatched"));
    } else if (rm.roles) {
      /* the person was found, so removal works; their roles cannot be read */
      char msg[1400];
      snprintf(msg, sizeof(msg), "%s. %s", rerr,
               strcmp(rm.provider, "entra") == 0 && strcmp(rm.roles_from, "app-roles") == 0
                   ? "App roles also need Microsoft Graph's Application.Read.All application permission, with admin "
                     "consent."
                   : "The roles need the same permission as above.");
      yyjson_mut_obj_add_strcpy(d, o, "rolesError", msg);
    }
  } else if (state == BUCKETS_IDSYNC_GONE) {
    yyjson_mut_obj_add_str(d, o, "error",
                           "No one by that name in the directory. The directory can be read: try someone who exists.");
  } else {
    char msg[1400];
    snprintf(msg, sizeof(msg), "%s. %s", err, need);
    yyjson_mut_obj_add_strcpy(d, o, "error", msg);
  }
  buckets_idsync_values_free(values, nvalues);
  yyjson_mut_obj_add_bool(d, o, "passed", passed);
  /* as the LDAP test: a person not found must not take back a passed test of these settings */
  yyjson_val *prev = tests_of(&c);
  bool had_pass = yyjson_get_bool(yyjson_obj_get(yyjson_obj_get(prev, "removal"), "passed"));
  if (c.raw && (passed || !had_pass)) buckets_console_idp_record_test(m, c.hash, "removal", d);
  saved_free(&c);
  reply(resp, 200, d);
}

/* ---- GET, save, apply ------------------------------------------------------------------- */

static void add_redacted(yyjson_mut_doc *d, yyjson_mut_val *o, const char *key, yyjson_val *settings) {
  if (settings) yyjson_mut_obj_add_val(d, o, key, buckets_idp_settings_redacted(d, settings));
  else yyjson_mut_obj_add_null(d, o, key);
}

static void handle_get(buckets_console_idp *m, const buckets_console_idp_session *sess, buckets_http_response *resp) {
  saved a, c;
  saved_load(m, "-identity", &a);
  saved_load(m, "-identity-candidate", &c);
  yyjson_mut_val *o;
  yyjson_mut_doc *d = new_obj(&o);
  yyjson_mut_obj_add_bool(d, o, "managed", true);
  yyjson_mut_obj_add_strcpy(d, o, "cluster", m->cluster);
  yyjson_mut_obj_add_strcpy(d, o, "namespace", m->ns);
  yyjson_mut_obj_add_strcpy(d, o, "redirectUri", sess->callback ? sess->callback : "");
  add_redacted(d, o, "settings", yyjson_doc_get_root(a.settings));
  if (a.raw) {
    char desc[600];
    buckets_idp_settings_describe(yyjson_doc_get_root(a.settings), desc, sizeof(desc));
    yyjson_mut_obj_add_strcpy(d, o, "description", desc);
  }
  add_redacted(d, o, "candidate", yyjson_doc_get_root(c.settings));
  yyjson_mut_obj_add_strcpy(d, o, "candidateHash", c.hash);
  yyjson_val *t = tests_of(&c);
  if (t) yyjson_mut_obj_add_val(d, o, "test", yyjson_val_mut_copy(d, t));
  else yyjson_mut_obj_add_obj(d, o, "test");
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&p, GROUP_PATH "/namespaces/%s/bucketsclusters/%s", m->ns, m->cluster);
  yyjson_doc *bc = NULL;
  kube_get(m->k, p.data, &bc);
  buckets_buf_free(&p);
  yyjson_val *st = yyjson_obj_get(yyjson_obj_get(yyjson_doc_get_root(bc), "status"), "identity");
  if (st) yyjson_mut_obj_add_val(d, o, "status", yyjson_val_mut_copy(d, st));
  else yyjson_mut_obj_add_obj(d, o, "status");
  yyjson_doc_free(bc);
  saved_free(&a);
  saved_free(&c);
  reply(resp, 200, d);
}

static void handle_candidate(buckets_console_idp *m, yyjson_val *body, buckets_http_response *resp) {
  yyjson_val *in = yyjson_obj_get(body, "settings");
  if (!yyjson_is_obj(in)) {
    fail(resp, 400, "InvalidRequest", "settings must be an object");
    return;
  }
  saved a, c;
  saved_load(m, "-identity", &a);
  saved_load(m, "-identity-candidate", &c);
  if (c.status != 200) {
    saved_free(&a);
    saved_free(&c);
    fail(resp, 503, "NotReady", "The operator has not created the identity Secrets yet; try again in a moment.");
    return;
  }
  yyjson_mut_doc *md = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *s = yyjson_val_mut_copy(md, in);
  yyjson_mut_doc_set_root(md, s);
  /* secrets left empty: the candidate's, else the applied settings' */
  if (c.settings) buckets_idp_settings_keep_secrets(md, s, yyjson_doc_get_root(c.settings));
  if (a.settings) buckets_idp_settings_keep_secrets(md, s, yyjson_doc_get_root(a.settings));
  char *js = yyjson_mut_write(md, 0, NULL);
  yyjson_doc *check = yyjson_read(js, strlen(js), 0);
  char err[512];
  if (!buckets_idp_check(yyjson_doc_get_root(check), err, sizeof(err))) {
    fail(resp, 400, "InvalidSettings", err);
  } else if (put_secret(m, "-identity-candidate", yyjson_doc_get_root(c.secret), "settings.json", js, NULL, NULL) / 100 != 2) {
    fail(resp, 502, "KubernetesError", "The settings could not be saved.");
  } else {
    yyjson_mut_val *o;
    yyjson_mut_doc *d = new_obj(&o);
    char hash[17];
    hash16(js, hash);
    add_redacted(d, o, "candidate", yyjson_doc_get_root(check));
    yyjson_mut_obj_add_strcpy(d, o, "candidateHash", hash);
    reply(resp, 200, d);
  }
  yyjson_doc_free(check);
  wipe(js);
  yyjson_mut_doc_free(md);
  saved_free(&a);
  saved_free(&c);
}

static bool part_passed(yyjson_val *tests, const char *part) {
  return yyjson_get_bool(yyjson_obj_get(yyjson_obj_get(tests, part), "passed"));
}

static void handle_apply(buckets_console_idp *m, yyjson_val *body, buckets_http_response *resp) {
  const char *want = yyjson_get_str(yyjson_obj_get(body, "candidateHash"));
  saved a, c;
  saved_load(m, "-identity", &a);
  saved_load(m, "-identity-candidate", &c);
  yyjson_val *settings = yyjson_doc_get_root(c.settings), *tests = tests_of(&c);
  bool has_oidc = yyjson_is_obj(yyjson_obj_get(settings, "openid")), has_ldap = yyjson_is_obj(yyjson_obj_get(settings, "ldap"));
  buckets_idp_removal rm;
  bool has_removal = buckets_idp_removal_of(settings, &rm);
  if (!c.raw || !want || strcmp(want, c.hash) != 0) {
    fail(resp, 409, "CandidateChanged", "The settings changed since they were tested: test them again.");
  } else if (has_removal && rm.api && !part_passed(tests, "removal")) { /* SCIM alone has nothing to ask */
    fail(resp, 409, "NotTested", "Look up a person with the removal settings (Test) before applying them.");
  } else if ((has_oidc && !part_passed(tests, "openid")) || (has_ldap && !part_passed(tests, "ldap"))) {
    fail(resp, 409, "NotTested",
         has_oidc && !part_passed(tests, "openid") ? "Sign in once with the OpenID settings (Test sign-in) before applying them."
                                                   : "Look up a user with the LDAP settings (Test) before applying them.");
  } else if (a.status != 200) {
    fail(resp, 503, "NotReady", "The operator has not created the identity Secrets yet; try again in a moment.");
  } else if (put_secret(m, "-identity", yyjson_doc_get_root(a.secret), "settings.json", c.raw, NULL, NULL) / 100 != 2) {
    fail(resp, 502, "KubernetesError", "The settings could not be applied.");
  } else {
    char desc[600];
    buckets_idp_settings_describe(settings, desc, sizeof(desc));
    buckets_log_info("console: identity settings applied: %s", desc);
    yyjson_mut_val *o;
    yyjson_mut_doc *d = new_obj(&o);
    yyjson_mut_obj_add_bool(d, o, "applied", true);
    yyjson_mut_obj_add_strcpy(d, o, "description", desc);
    reply(resp, 200, d);
  }
  saved_free(&a);
  saved_free(&c);
}

void buckets_console_idp_handle(buckets_console_idp *m, const buckets_http_request *req, const char *sub,
                                const buckets_console_idp_session *sess, buckets_http_response *resp) {
  bool get = buckets_str_eq_c(req->method, "GET");
  if (!m) {
    if (get && !*sub) {
      yyjson_mut_val *o;
      yyjson_mut_doc *d = new_obj(&o);
      yyjson_mut_obj_add_bool(d, o, "managed", false);
      reply(resp, 200, d);
    } else {
      fail(resp, 501, "NotManaged", "Sign-in is set up from the console only where buckets-operator runs the cluster.");
    }
    return;
  }
  if (get && !*sub) {
    handle_get(m, sess, resp);
    return;
  }
  if (req->body_len > MAX_BODY || req->body_fd >= 0 || req->pipe) {
    fail(resp, 400, "InvalidRequest", "request too large");
    return;
  }
  yyjson_doc *bd = yyjson_read(req->body.p ? req->body.p : "", req->body.n, 0);
  yyjson_val *body = yyjson_doc_get_root(bd);
  if (buckets_str_eq_c(req->method, "PUT") && strcmp(sub, "/candidate") == 0) handle_candidate(m, body, resp);
  else if (buckets_str_eq_c(req->method, "POST") && strcmp(sub, "/ldap-test") == 0) handle_ldap_test(m, body, sess, resp);
  else if (buckets_str_eq_c(req->method, "POST") && strcmp(sub, "/removal-test") == 0) handle_removal_test(m, body, sess, resp);
  else if (buckets_str_eq_c(req->method, "POST") && strcmp(sub, "/apply") == 0) handle_apply(m, body, resp);
  else fail(resp, 404, "NotFound", "unknown identity settings API");
  yyjson_doc_free(bd);
}
