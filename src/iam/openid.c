/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "iam/openid.h"

#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/log.h"
#include "crypto/base64.h"
#include "crypto/jwk.h"
#include "net/fetch.h"

#define DUMMY_ARN "arn:minio:iam:::role/dummy-internal"
#define MIN_EXPIRATION 900
#define MAX_EXPIRATION 31536000

typedef struct {
  char *name; /* the config target */
  char *arn;  /* role ARN, or DUMMY_ARN */
  char *client_id, *client_secret, *claim_name, *claim_prefix, *role_policy;
  bool claim_userinfo;
  char *jwks_uri, *userinfo_endpoint;
} provider;

struct buckets_openid {
  _Atomic int refs;
  provider *p;
  size_t n;
  char *claim_name; /* prefix + name of the dummy-ARN provider */
  pthread_mutex_t keys_mu;
  buckets_jwk_set *keys;
};

static void provider_free(provider *p) {
  free(p->name);
  free(p->arn);
  free(p->client_id);
  free(p->client_secret);
  free(p->claim_name);
  free(p->claim_prefix);
  free(p->role_policy);
  free(p->jwks_uri);
  free(p->userinfo_endpoint);
}

buckets_openid *buckets_openid_ref(buckets_openid *o) {
  if (o) atomic_fetch_add(&o->refs, 1);
  return o;
}

void buckets_openid_release(buckets_openid *o) {
  if (!o || atomic_fetch_sub(&o->refs, 1) != 1) return;
  for (size_t i = 0; i < o->n; i++) provider_free(&o->p[i]);
  free(o->p);
  free(o->claim_name);
  buckets_jwk_set_free(o->keys);
  pthread_mutex_destroy(&o->keys_mu);
  free(o);
}

bool buckets_openid_enabled(const buckets_openid *o) { return o && o->n > 0; }
const char *buckets_openid_claim_name(const buckets_openid *o) { return o && o->claim_name ? o->claim_name : ""; }

const char *buckets_openid_role_policy(const buckets_openid *o, const char *arn) {
  for (size_t i = 0; o && i < o->n; i++) {
    if (o->p[i].role_policy && *o->p[i].role_policy && strcmp(o->p[i].arn, arn) == 0) return o->p[i].role_policy;
  }
  return NULL;
}

/* config.ParseBool */
static int parse_bool(const char *s) {
  static const char *const on[] = {"1", "t", "T", "TRUE", "true", "True", "on", "ON", "On", "enabled"};
  static const char *const off[] = {"0", "f", "F", "FALSE", "false", "False", "off", "OFF", "Off", "disabled"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(on); i++) {
    if (strcmp(s, on[i]) == 0) return 1;
    if (strcmp(s, off[i]) == 0) return 0;
  }
  return -1;
}

static bool get_json(const char *url, const char *bearer, const char *method, yyjson_doc **out, char *err, size_t errlen) {
  buckets_http_result r;
  char auth[4200];
  buckets_http_kv h[2];
  size_t nh = 0;
  if (bearer) {
    snprintf(auth, sizeof(auth), "Bearer %s", bearer);
    h[nh++] = (buckets_http_kv){"Authorization", auth};
    h[nh++] = (buckets_http_kv){"Content-Type", "application/x-www-form-urlencoded"};
  }
  if (!buckets_fetch(method, url, NULL, h, nh, NULL, 0, 10000, &r, err, errlen)) return false;
  bool ok = r.status == 200;
  if (!ok) snprintf(err, errlen, "unexpected error returned by %s : status(%d)", url, r.status);
  *out = ok ? yyjson_read(r.body.data ? r.body.data : "", r.body.len, 0) : NULL;
  if (ok && !*out) {
    snprintf(err, errlen, "%s did not return JSON", url);
    ok = false;
  }
  buckets_http_result_free(&r);
  return ok;
}

/* PopulatePublicKey */
static bool populate_keys(buckets_openid *o, const provider *p, char *err, size_t errlen) {
  if (!p->jwks_uri) return true;
  yyjson_doc *d;
  if (!get_json(p->jwks_uri, NULL, "GET", &d, err, errlen)) return false;
  char *json = yyjson_write(d, 0, NULL);
  yyjson_doc_free(d);
  pthread_mutex_lock(&o->keys_mu);
  if (p->client_id && p->client_secret) buckets_jwk_set_add_secret(o->keys, p->client_id, p->client_secret);
  bool ok = buckets_jwk_set_add_json(o->keys, json, strlen(json), err, errlen);
  pthread_mutex_unlock(&o->keys_mu);
  free(json);
  return ok;
}

static char *dupnz(char *s) {
  if (s && !*s) {
    free(s);
    return NULL;
  }
  return s;
}

buckets_openid *buckets_openid_build(const buckets_config *cfg, const char *region, char *err, size_t errlen) {
  buckets_openid *o = buckets_xcalloc(1, sizeof(*o));
  atomic_init(&o->refs, 1);
  pthread_mutex_init(&o->keys_mu, NULL);
  o->keys = buckets_jwk_set_new();
  char **targets;
  size_t nt = buckets_config_targets(cfg, "identity_openid", &targets);
  bool ok = true;
  for (size_t t = 0; t < nt && ok; t++) {
    const char *name = targets[t];
#define GET(key) buckets_config_get(cfg, "identity_openid", name, key)
    char *enable = GET("enable");
    bool explicit = enable && *enable;
    int en = explicit ? parse_bool(enable) : 1;
    free(enable);
    if (en < 0) {
      snprintf(err, errlen, "identity_openid: invalid value for enable");
      ok = false;
      break;
    }
    if (!en) continue;
    provider p = {0};
    p.name = buckets_xstrdup(name);
    p.client_id = dupnz(GET("client_id"));
    p.client_secret = dupnz(GET("client_secret"));
    p.claim_name = GET("claim_name");
    p.claim_prefix = GET("claim_prefix");
    p.role_policy = dupnz(GET("role_policy"));
    char *userinfo = GET("claim_userinfo");
    p.claim_userinfo = userinfo && strcmp(userinfo, "on") == 0;
    free(userinfo);
    char *config_url = dupnz(GET("config_url"));
    char *scopes = GET("scopes");
    char *vendor = dupnz(GET("vendor"));
#undef GET
    if (!explicit && !p.client_id && !p.client_secret && !config_url) {
      provider_free(&p);
      free(config_url);
      free(scopes);
      free(vendor);
      continue;
    }
    for (size_t i = 0; i < o->n && ok; i++) {
      if (o->p[i].client_id && p.client_id && strcmp(o->p[i].client_id, p.client_id) == 0) {
        snprintf(err, errlen, "Client ID %s is present with multiple OpenID configurations", p.client_id);
        ok = false;
      }
    }
    yyjson_doc *disc = NULL;
    if (ok && (!config_url || (strncmp(config_url, "http://", 7) != 0 && strncmp(config_url, "https://", 8) != 0))) {
      snprintf(err, errlen, "unexpected scheme found %s", config_url ? config_url : "");
      ok = false;
    }
    if (ok) ok = get_json(config_url, NULL, "GET", &disc, err, errlen);
    if (ok && p.claim_userinfo && !config_url) {
      snprintf(err, errlen, "please specify config_url to enable fetching claims from UserInfo endpoint");
      ok = false;
    }
    if (ok && scopes && *scopes) {
      for (const char *s = scopes; ok && *s;) {
        const char *c = strchr(s, ',');
        size_t n = c ? (size_t)(c - s) : strlen(s);
        bool blank = true;
        for (size_t i = 0; i < n; i++) blank &= s[i] == ' ';
        if (blank) {
          snprintf(err, errlen, "empty scope value is not allowed '%s', please refer to our documentation", scopes);
          ok = false;
        }
        s = c ? c + 1 : s + n;
      }
    }
    if (ok && strcmp(p.claim_name ? p.claim_name : "", "policy") != 0 && p.role_policy) {
      snprintf(err, errlen, "Role Policy (=`%s`) and Claim Name (=`%s`) cannot both be set", p.role_policy, p.claim_name);
      ok = false;
    }
    if (ok) {
      yyjson_val *root = yyjson_doc_get_root(disc);
      const char *jwks = yyjson_get_str(yyjson_obj_get(root, "jwks_uri"));
      const char *ui = yyjson_get_str(yyjson_obj_get(root, "userinfo_endpoint"));
      if (!jwks || !*jwks) {
        snprintf(err, errlen, "no JWKS URI found in your provider's discovery doc (config_url=%s)", config_url);
        ok = false;
      } else {
        p.jwks_uri = buckets_xstrdup(jwks);
        if (ui) p.userinfo_endpoint = buckets_xstrdup(ui);
      }
    }
    if (ok && p.role_policy) {
      if (!p.client_id) {
        snprintf(err, errlen, "client ID must not be empty");
        ok = false;
      } else {
        unsigned char sum[SHA_DIGEST_LENGTH];
        SHA1((const unsigned char *)p.client_id, strlen(p.client_id), sum);
        char rid[32];
        buckets_base64url_raw_encode(sum, sizeof(sum), rid);
        char arn[256];
        snprintf(arn, sizeof(arn), "arn:minio:iam:%s::role/%s", region ? region : "", rid);
        p.arn = buckets_xstrdup(arn);
      }
    } else if (ok && (!p.claim_name || !*p.claim_name)) {
      snprintf(err, errlen, "A role policy or claim name must be specified");
      ok = false;
    }
    if (ok && vendor) {
      snprintf(err, errlen, "Unsupported vendor %s", vendor);
      ok = false;
    }
    if (ok && !p.role_policy) {
      for (size_t i = 0; i < o->n && ok; i++) {
        if (strcmp(o->p[i].arn, DUMMY_ARN) == 0) {
          snprintf(err, errlen, "Only one OpenID provider can be configured if not using role policy mapping");
          ok = false;
        }
      }
      p.arn = buckets_xstrdup(DUMMY_ARN);
    }
    if (ok) ok = populate_keys(o, &p, err, errlen);
    yyjson_doc_free(disc);
    free(config_url);
    free(scopes);
    free(vendor);
    if (!ok) {
      provider_free(&p);
      break;
    }
    if (strcmp(p.arn, DUMMY_ARN) == 0) {
      char cn[512];
      snprintf(cn, sizeof(cn), "%s%s", p.claim_prefix ? p.claim_prefix : "", p.claim_name ? p.claim_name : "");
      o->claim_name = buckets_xstrdup(cn);
    }
    o->p = buckets_xrealloc(o->p, (o->n + 1) * sizeof(provider));
    o->p[o->n++] = p;
  }
  for (size_t i = 0; i < nt; i++) free(targets[i]);
  free(targets);
  if (!ok) {
    buckets_openid_release(o);
    return NULL;
  }
  return o;
}

long long buckets_sts_expiry_seconds(const char *dsecs) {
  const char *env = buckets_config_getenv("MINIO_STS_DURATION");
  long long def = -1;
  if (env) {
    /* time.ParseDuration for h/m/s */
    long long total = 0;
    const char *s = env;
    bool okp = *s != '\0';
    while (okp && *s) {
      char *end;
      double v = strtod(s, &end);
      if (end == s) {
        okp = false;
        break;
      }
      long long mult = *end == 'h' ? 3600 : *end == 'm' ? 60 : *end == 's' ? 1 : -1;
      if (mult < 0) {
        okp = false;
        break;
      }
      total += (long long)(v * (double)mult);
      s = end + 1;
    }
    if (okp) def = total;
  }
  if (def < 0) def = 3600;
  if (!env && dsecs && *dsecs) {
    char *end;
    long long v = strtoll(dsecs, &end, 10);
    if (*end || v < MIN_EXPIRATION || v > MAX_EXPIRATION) return -1;
    def = v;
  } else if (!env) {
    return 3600;
  }
  if (def < MIN_EXPIRATION || def > MAX_EXPIRATION) return -1;
  return def;
}

/* policy.GetValuesFromClaims: a comma-separated string or an array of them. */
static bool claim_has_value(yyjson_val *v, const char *want, bool *present) {
  *present = v && (yyjson_is_str(v) || yyjson_is_arr(v));
  if (!*present) return false;
  yyjson_val *one = v;
  size_t i = 0, max = yyjson_is_arr(v) ? yyjson_arr_size(v) : 1;
  for (; i < max; i++) {
    if (yyjson_is_arr(v)) one = yyjson_arr_get(v, i);
    const char *s = yyjson_get_str(one);
    if (!s) continue;
    for (const char *p = s; *p;) {
      const char *c = strchr(p, ',');
      size_t n = c ? (size_t)(c - p) : strlen(p);
      while (n && *p == ' ') {
        p++;
        n--;
      }
      while (n && p[n - 1] == ' ') n--;
      if (n == strlen(want) && strncmp(p, want, n) == 0) return true;
      p = c ? c + 1 : p + strlen(p);
    }
  }
  return false;
}

buckets_oidc_status buckets_openid_validate(buckets_openid *o, const char *role_arn, const char *token,
                                            const char *access_token, const char *dsecs, yyjson_mut_doc **claims,
                                            char *err, size_t errlen) {
  *claims = NULL;
  const char *arn = role_arn ? role_arn : DUMMY_ARN;
  const provider *p = NULL;
  for (size_t i = 0; o && i < o->n; i++) {
    if (strcmp(o->p[i].arn, arn) == 0) p = &o->p[i];
  }
  if (!p) {
    snprintf(err, errlen, "Role %s does not exist", arn);
    return BUCKETS_OIDC_ERROR;
  }
  long long now = (long long)time(NULL);
  yyjson_doc *cd = NULL;
  pthread_mutex_lock(&o->keys_mu);
  buckets_jwt_status st = buckets_jwt_verify_jwks(token ? token : "", o->keys, now, &cd, err, errlen);
  pthread_mutex_unlock(&o->keys_mu);
  if (st != BUCKETS_JWT_OK) {
    /* Keys rotate: refetch the JWKS once and retry. */
    char ferr[256];
    if (!populate_keys(o, p, ferr, sizeof(ferr))) {
      snprintf(err, errlen, "%s", ferr);
      return BUCKETS_OIDC_ERROR;
    }
    pthread_mutex_lock(&o->keys_mu);
    st = buckets_jwt_verify_jwks(token ? token : "", o->keys, now, &cd, err, errlen);
    pthread_mutex_unlock(&o->keys_mu);
  }
  if (st == BUCKETS_JWT_EXPIRED) return BUCKETS_OIDC_EXPIRED;
  if (st != BUCKETS_JWT_OK) return BUCKETS_OIDC_ERROR;
  yyjson_mut_doc *m = yyjson_doc_mut_copy(cd, NULL);
  yyjson_doc_free(cd);
  yyjson_mut_val *root = yyjson_mut_doc_get_root(m);
  /* updateClaimsExpiry */
  if (dsecs && *dsecs) {
    yyjson_mut_val *exp = yyjson_mut_obj_get(root, "exp");
    bool exp_ok = exp && (yyjson_mut_is_num(exp) || yyjson_mut_is_str(exp) || yyjson_mut_is_null(exp));
    long long secs = buckets_sts_expiry_seconds(dsecs);
    if (!exp_ok || secs < 0) {
      yyjson_mut_doc_free(m);
      snprintf(err, errlen, "invalid token expiry");
      return BUCKETS_OIDC_INVALID_DURATION;
    }
    yyjson_mut_obj_remove_key(root, "exp");
    yyjson_mut_obj_add_int(m, root, "exp", now + secs);
  }
  if (p->claim_userinfo) {
    if (!access_token || !*access_token) {
      yyjson_mut_doc_free(m);
      snprintf(err, errlen, "access_token is mandatory if user_info claim is enabled");
      return BUCKETS_OIDC_ERROR;
    }
    yyjson_doc *ui;
    if (!p->userinfo_endpoint || !get_json(p->userinfo_endpoint, access_token, "POST", &ui, err, errlen)) {
      yyjson_mut_doc_free(m);
      return BUCKETS_OIDC_ERROR;
    }
    size_t i, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(yyjson_doc_get_root(ui), i, max, k, v) {
      if (!yyjson_mut_obj_get(root, yyjson_get_str(k))) {
        yyjson_mut_obj_add(root, yyjson_mut_strcpy(m, yyjson_get_str(k)), yyjson_val_mut_copy(m, v));
      }
    }
    yyjson_doc_free(ui);
  }
  /* aud (else azp) must name the client id. */
  yyjson_doc *ro = yyjson_mut_doc_imut_copy(m, NULL);
  yyjson_val *rr = yyjson_doc_get_root(ro);
  bool aud_present, azp_present;
  bool aud_ok = claim_has_value(yyjson_obj_get(rr, "aud"), p->client_id ? p->client_id : "", &aud_present);
  bool azp_ok = !aud_ok && claim_has_value(yyjson_obj_get(rr, "azp"), p->client_id ? p->client_id : "", &azp_present);
  yyjson_doc_free(ro);
  if (!aud_present) {
    yyjson_mut_doc_free(m);
    snprintf(err, errlen, "STS JWT Token has `aud` claim invalid, `aud` must match configured OpenID Client ID");
    return BUCKETS_OIDC_ERROR;
  }
  if (!aud_ok && !azp_ok) {
    yyjson_mut_doc_free(m);
    snprintf(err, errlen, "STS JWT Token has `azp` claim invalid, `azp` must match configured OpenID Client ID");
    return BUCKETS_OIDC_ERROR;
  }
  *claims = m;
  return BUCKETS_OIDC_OK;
}
