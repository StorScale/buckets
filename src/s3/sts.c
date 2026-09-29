/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* STS AssumeRole (MinIO cmd/sts-handlers.go): temporary credentials for an
 * IAM user, signed with SigV4 for the "sts" service. */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "config/sys.h"
#include "core/timefmt.h"
#include "iam/ldapidp.h"
#include "iam/openid.h"
#include "iam/plugins.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "crypto/base64.h"
#include "siterepl/siterepl.h"
#include "s3/internal.h"
#include "s3/sigv2.h"
#include "s3/xml.h"

#define STS_XMLNS "https://sts.amazonaws.com/doc/2011-06-15/"
#define STS_API_VERSION "2011-06-15"
#define MAX_STS_SESSION_POLICY 2048

typedef enum {
  STS_ACCESS_DENIED,
  STS_MISSING_PARAMETER,
  STS_INVALID_PARAMETER_VALUE,
  STS_NOT_INITIALIZED,
  STS_INTERNAL_ERROR,
  STS_EXPIRED_TOKEN_WEB,
  STS_UPSTREAM_ERROR,
  STS_INSECURE_CONNECTION,
  STS_INVALID_CLIENT_CERTIFICATE,
  STS_TOO_MANY_INTERMEDIATE_CAS,
} sts_err;

static const struct {
  const char *code, *message;
  int status;
} k_sts_errors[] = {
    [STS_ACCESS_DENIED] = {"AccessDenied", "Generating temporary credentials not allowed for this request.", 403},
    [STS_MISSING_PARAMETER] = {"MissingParameter", "A required parameter for the specified action is not supplied.",
                               400},
    [STS_INVALID_PARAMETER_VALUE] = {"InvalidParameterValue",
                                     "An invalid or out-of-range value was supplied for the input parameter.", 400},
    [STS_NOT_INITIALIZED] = {"STSNotInitialized", "STS API not initialized, please try again.", 503},
    [STS_INTERNAL_ERROR] = {"InternalError", "We encountered an internal error generating credentials, please try again.",
                            500},
    [STS_EXPIRED_TOKEN_WEB] = {"ExpiredToken",
                               "The web identity token that was passed is expired or is not valid. Get a new identity "
                               "token from the identity provider and then retry the request.",
                               400},
    [STS_UPSTREAM_ERROR] = {"InternalError", "An upstream service required for this operation failed - please try again "
                                             "or contact an administrator.",
                            500},
    [STS_INSECURE_CONNECTION] = {"InsecureConnection",
                                 "The request was made over a plain HTTP connection. A TLS connection is required.", 400},
    [STS_INVALID_CLIENT_CERTIFICATE] = {"InvalidClientCertificate",
                                        "The provided client certificate is invalid. Retry with a different certificate.",
                                        400},
    [STS_TOO_MANY_INTERMEDIATE_CAS] = {"TooManyIntermediateCAs",
                                       "The provided client certificate contains too many intermediate CA certificates",
                                       400},
};

static void sts_error(s3_ctx *c, sts_err e, const char *message) {
  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "ErrorResponse", STS_XMLNS);
  buckets_xml_open(b, "Error");
  buckets_xml_elem(b, "Type", "");
  buckets_xml_elem(b, "Code", k_sts_errors[e].code);
  buckets_xml_elem(b, "Message", message ? message : k_sts_errors[e].message);
  buckets_xml_close(b, "Error");
  buckets_xml_elem(b, "RequestId", c->request_id);
  buckets_xml_close(b, "ErrorResponse");
  c->resp->status = k_sts_errors[e].status;
  buckets_http_resp_header(c->resp, "Content-Type", "application/xml");
}

/* apiToSTSError */
static sts_err from_s3(buckets_s3_error e) {
  switch (e) {
    case BUCKETS_ERR_SERVER_NOT_INITIALIZED: return STS_NOT_INITIALIZED;
    case BUCKETS_ERR_INTERNAL_ERROR: return STS_INTERNAL_ERROR;
    default: return STS_ACCESS_DENIED;
  }
}

bool buckets_sts_matches(const s3_ctx *c) {
  const buckets_http_request *req = c->req;
  if (!buckets_str_eq_c(req->method, "POST") || c->bucket) return false;
  /* ClientGrants / WebIdentity / LDAPIdentity may come as query parameters. */
  const char *action = buckets_query_get(&c->q, "Action");
  if (action && strncmp(action, "AssumeRoleWith", 14) == 0) return true;
  if (req->query.n) return false;
  buckets_str ct = buckets_http_header_get(req, "Content-Type");
  return ct.p && ct.n >= 33 && strncasecmp(ct.p, "application/x-www-form-urlencoded", 33) == 0;
}

/* r.Form: the form body's values, then the URL query's. */
static const char *form_get(const buckets_query *body, const buckets_query *url, const char *key) {
  const char *v = buckets_query_get(body, key);
  return v ? v : buckets_query_get(url, key);
}

/* claims.populateSessionPolicy: a Policy parameter, validated and compacted. */
static bool session_policy(s3_ctx *c, const char *pol, yyjson_mut_doc *claims) {
  if (!pol || !*pol) return true;
  buckets_policy *p;
  char err[512];
  if (!buckets_policy_parse(pol, strlen(pol), &p, err, sizeof(err))) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
    return false;
  }
  bool no_version = !*buckets_policy_version(p);
  buckets_policy_free(p);
  if (no_version) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "Version cannot be empty expecting '2012-10-17'");
    return false;
  }
  yyjson_doc *pd = yyjson_read(pol, strlen(pol), 0);
  char *compact = pd ? yyjson_write(pd, 0, NULL) : NULL;
  yyjson_doc_free(pd);
  if (!compact || strlen(compact) > MAX_STS_SESSION_POLICY) {
    free(compact);
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "Session policy should not exceed 2048 characters");
    return false;
  }
  size_t n = strlen(compact);
  char *b64 = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
  buckets_base64_encode((const uint8_t *)compact, n, b64);
  yyjson_mut_val *root = yyjson_mut_doc_get_root(claims);
  yyjson_mut_obj_remove_key(root, "sessionPolicy");
  yyjson_mut_obj_add_strcpy(claims, root, "sessionPolicy", b64);
  free(b64);
  free(compact);
  return true;
}

/* The credentials block and response wrapper shared by every action. */
static void write_credentials(s3_ctx *c, const char *action, const buckets_iam_ident *cred, const char *subject_tag,
                              const char *subject) {
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(cred->expiration.sec, cred->expiration.nsec, ts);
  char resp[96], result[96];
  snprintf(resp, sizeof(resp), "%sResponse", action);
  snprintf(result, sizeof(result), "%sResult", action);
  buckets_buf *b = &c->resp->body;
  buckets_buf_reset(b);
  buckets_xml_header(b);
  buckets_xml_open_ns(b, resp, STS_XMLNS);
  buckets_xml_open(b, result);
  /* LDAPIdentityResult, and the custom token and certificate results, carry no AssumedRoleUser. */
  if (strcmp(action, "AssumeRoleWithLDAPIdentity") != 0 && strcmp(action, "AssumeRoleWithCustomToken") != 0 &&
      strcmp(action, "AssumeRoleWithCertificate") != 0) {
    buckets_xml_open(b, "AssumedRoleUser");
    buckets_xml_elem(b, "Arn", "");
    buckets_xml_elem(b, "AssumeRoleId", "");
    buckets_xml_close(b, "AssumedRoleUser");
  }
  buckets_xml_open(b, "Credentials");
  buckets_xml_elem(b, "AccessKeyId", cred->access_key);
  buckets_xml_elem(b, "SecretAccessKey", cred->secret_key);
  buckets_xml_elem(b, "SessionToken", cred->session_token);
  buckets_xml_elem(b, "Expiration", ts);
  buckets_xml_close(b, "Credentials");
  if (subject_tag && subject && *subject) buckets_xml_elem(b, subject_tag, subject);
  buckets_xml_close(b, result);
  buckets_xml_open(b, "ResponseMetadata");
  buckets_xml_elem(b, "RequestId", c->request_id);
  buckets_xml_close(b, "ResponseMetadata");
  buckets_xml_close(b, resp);
  buckets_s3_write_xml(c, 200);
}

/* Issues temporary credentials for claims (their "exp" is the expiry). */
static buckets_iam_ident *issue(s3_ctx *c, const char *parent, char *const *groups, size_t ngroups,
                                 yyjson_mut_doc *claims, const char *policy) {
  yyjson_mut_val *exp = yyjson_mut_obj_get(yyjson_mut_doc_get_root(claims), "exp");
  long long e = exp && yyjson_mut_is_num(exp) ? (long long)yyjson_mut_get_num(exp) : 0;
  if (exp && yyjson_mut_is_str(exp)) e = atoll(yyjson_mut_get_str(exp));
  char *claims_json = yyjson_mut_write(claims, 0, NULL);
  char ak[21], sk[41];
  buckets_iam_generate_credentials(ak, sk);
  buckets_iam_ident *cred = NULL;
  buckets_iam_err err = buckets_iam_set_temp_user(c->s->iam, ak, sk, parent, (const char *const *)groups, ngroups,
                                                  (buckets_iam_time){e, 0},
                                                  claims_json, policy, &cred);
  free(claims_json);
  if (err) {
    sts_error(c, err == BUCKETS_IAM_ERR_NOT_INITIALIZED ? STS_NOT_INITIALIZED : STS_INTERNAL_ERROR,
              err == BUCKETS_IAM_ERR_INVALID_ARGUMENT ? "token expired or has no expiry" : buckets_iam_strerror(err));
    return NULL;
  }
  /* site replication: other sites accept the credential too (not root's) */
  if (strcmp(parent, buckets_iam_root_access_key(c->s->iam)) != 0) buckets_sr_iam_sts(c->s->sr, cred->access_key, policy);
  return cred;
}

/* ---- AssumeRole (signed by an IAM user) ---- */

static void assume_role(s3_ctx *c, const buckets_query *form, const buckets_query *url, buckets_s3_error auth_err) {
  if (auth_err) {
    sts_error(c, from_s3(auth_err), buckets_s3_error_get(auth_err)->message);
    return;
  }
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_doc_set_root(claims, yyjson_mut_obj(claims));
  yyjson_mut_val *root = yyjson_mut_doc_get_root(claims);
  if (!session_policy(c, form_get(form, url, "Policy"), claims)) {
    yyjson_mut_doc_free(claims);
    return;
  }
  long long dur = buckets_sts_expiry_seconds(form_get(form, url, "DurationSeconds"));
  if (dur < 0) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "invalid token expiry");
    yyjson_mut_doc_free(claims);
    return;
  }
  yyjson_mut_obj_add_int(claims, root, "exp", (long long)time(NULL) + dur);
  yyjson_mut_obj_add_strcpy(claims, root, "parent", c->ident->access_key);
  const char *revoke = form_get(form, url, "TokenRevokeType");
  if (revoke && *revoke) yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  buckets_iam_ident *cred = issue(c, c->ident->access_key, NULL, 0, claims, NULL);
  yyjson_mut_doc_free(claims);
  if (!cred) return;
  write_credentials(c, "AssumeRole", cred, NULL, NULL);
  buckets_iam_ident_release(cred);
}

/* ---- AssumeRoleWithWebIdentity / ClientGrants (an OpenID token) ---- */

static void assume_role_sso(s3_ctx *c, const buckets_query *form, const buckets_query *url, const char *action) {
  bool grants = strcmp(action, "AssumeRoleWithClientGrants") == 0;
  const char *token = form_get(form, url, "Token");
  if (!token || !*token) token = form_get(form, url, "WebIdentityToken");
  const char *access_token = form_get(form, url, "WebIdentityAccessToken");
  const char *role_arn = form_get(form, url, "RoleArn");
  buckets_openid *o = buckets_s3_openid(c->s);
  yyjson_mut_doc *claims = NULL;
  buckets_iam_ident *cred = NULL;
  char *policy_name = NULL;
  char err[512];
  bool role = role_arn && *role_arn;
  if (role && !buckets_openid_role_policy(o, role_arn)) {
    if (!*buckets_openid_claim_name(o)) {
      snprintf(err, sizeof(err), "Error processing RoleArn parameter: role %s not found", role_arn);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      goto out;
    }
    role = false; /* fall back to the claim-based provider */
  }
  if (!buckets_iam_ready(c->s->iam)) {
    sts_error(c, STS_NOT_INITIALIZED, "IAM sub-system not initialized");
    goto out;
  }
  switch (buckets_openid_validate(o, role ? role_arn : NULL, token, access_token,
                                  form_get(form, url, "DurationSeconds"), &claims, err, sizeof(err))) {
    case BUCKETS_OIDC_OK: break;
    case BUCKETS_OIDC_EXPIRED:
      sts_error(c, STS_EXPIRED_TOKEN_WEB, grants ? "The client grants that was passed is expired or is not valid."
                                                 : "token expired");
      goto out;
    default:
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      goto out;
  }
  yyjson_mut_val *root = yyjson_mut_doc_get_root(claims);
  const char *claim_name = buckets_openid_claim_name(o);
  if (role) {
    yyjson_mut_obj_remove_key(root, "roleArn");
    yyjson_mut_obj_add_strcpy(claims, root, "roleArn", role_arn);
  } else {
    /* The policy claim: the names that exist. */
    yyjson_mut_val *pv = yyjson_mut_obj_get(root, claim_name);
    buckets_buf csv = BUCKETS_BUF_INIT;
    if (pv && yyjson_mut_is_str(pv)) buckets_buf_append_c(&csv, yyjson_mut_get_str(pv));
    if (pv && yyjson_mut_is_arr(pv)) {
      size_t i, max;
      yyjson_mut_val *e;
      yyjson_mut_arr_foreach(pv, i, max, e) {
        if (!yyjson_mut_is_str(e)) continue;
        if (csv.len) buckets_buf_append_c(&csv, ",");
        buckets_buf_append_c(&csv, yyjson_mut_get_str(e));
      }
    }
    bool present = pv && (yyjson_mut_is_str(pv) || yyjson_mut_is_arr(pv));
    policy_name = buckets_iam_existing_policies(c->s->iam, csv.data ? csv.data : "");
    buckets_plugins *pl = buckets_s3_plugins(c->s);
    bool authz = buckets_authz_plugin_enabled(pl);
    buckets_plugins_release(pl);
    if (authz) {
      /* The authorization plugin decides; no policy claim is needed. */
    } else if (!present) {
      snprintf(err, sizeof(err), "%s claim missing from the JWT token, credentials will not be generated", claim_name);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      buckets_buf_free(&csv);
      goto out;
    }
    else if (!*policy_name) {
      snprintf(err, sizeof(err), "None of the given policies (`%s`) are defined, credentials will not be generated",
               csv.data ? csv.data : "");
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      buckets_buf_free(&csv);
      goto out;
    }
    buckets_buf_free(&csv);
    yyjson_mut_obj_remove_key(root, claim_name);
    yyjson_mut_obj_add_strcpy(claims, root, claim_name, policy_name);
  }
  const char *revoke = form_get(form, url, "TokenRevokeType");
  if (revoke && *revoke) {
    yyjson_mut_obj_remove_key(root, "tokenRevokeType");
    yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  }
  if (!session_policy(c, form_get(form, url, "Policy"), claims)) goto out;
  const char *sub = yyjson_mut_get_str(yyjson_mut_obj_get(root, "sub"));
  const char *iss = yyjson_mut_get_str(yyjson_mut_obj_get(root, "iss"));
  if (!sub || !*sub) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "STS JWT Token has `sub` claim missing, `sub` claim is mandatory");
    goto out;
  }
  /* ParentUser: base64url(sha256("openid:" + sub + ":" + iss)). */
  buckets_buf pu = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&pu, "openid:%s:%s", sub, iss ? iss : "");
  uint8_t sum[32];
  buckets_sha256(pu.data, pu.len, sum);
  char parent[48];
  buckets_base64url_raw_encode(sum, 32, parent);
  buckets_buf_free(&pu);
  /* The policy may deny assuming the role. */
  const char *p = policy_name ? policy_name : buckets_openid_role_policy(o, role_arn);
  buckets_policy_args a = {.action = "sts:AssumeRoleWithWebIdentity", .bucket = "", .object = "", .deny_only = true};
  if (!buckets_iam_policies_allow(c->s->iam, p ? p : "", &a)) {
    sts_error(c, STS_ACCESS_DENIED, "this user does not have enough permission");
    goto out;
  }
  char *sub_copy = buckets_xstrdup(sub);
  cred = issue(c, parent, NULL, 0, claims, policy_name);
  if (cred) {
    write_credentials(c, action, cred, grants ? "SubjectFromToken" : "SubjectFromWebIdentityToken", sub_copy);
  }
  free(sub_copy);
out:
  buckets_iam_ident_release(cred);
  yyjson_mut_doc_free(claims);
  free(policy_name);
  buckets_openid_release(o);
}

/* ---- AssumeRoleWithCustomToken (the identity plugin) ---- */

static void assume_role_custom(s3_ctx *c, const buckets_query *form, const buckets_query *url) {
  buckets_plugins *pl = buckets_s3_plugins(c->s);
  yyjson_mut_doc *claims = NULL;
  buckets_iam_ident *cred = NULL;
  buckets_idp_result res = {0};
  char err[512];
  if (!buckets_iam_ready(c->s->iam)) {
    sts_error(c, STS_NOT_INITIALIZED, "IAM sub-system not initialized");
    goto out;
  }
  if (!buckets_idp_plugin_enabled(pl)) {
    sts_error(c, STS_NOT_INITIALIZED, "STS API 'AssumeRoleWithCustomToken' is disabled");
    goto out;
  }
  const char *token = form_get(form, url, "Token");
  if (!token || !*token) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "Invalid empty `Token` parameter provided");
    goto out;
  }
  const char *dparam = form_get(form, url, "DurationSeconds");
  long requested = 0;
  if (dparam && *dparam) {
    char *end;
    requested = strtol(dparam, &end, 10);
    if (*end) {
      snprintf(err, sizeof(err), "Invalid requested duration: %s", dparam);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      goto out;
    }
  }
  const char *role_arn = form_get(form, url, "RoleArn");
  const char *policy = role_arn && buckets_idp_plugin_role_arn(pl) && strcmp(role_arn, buckets_idp_plugin_role_arn(pl)) == 0
                           ? buckets_idp_plugin_role_policy(pl)
                           : NULL;
  if (!policy) {
    snprintf(err, sizeof(err), "Error processing parameter RoleArn: role %s not found", role_arn ? role_arn : "");
    sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
    goto out;
  }
  if (!buckets_authz_plugin_enabled(pl)) {
    char *have = buckets_iam_existing_policies(c->s->iam, policy);
    bool none = !*have;
    free(have);
    if (none) {
      snprintf(err, sizeof(err), "None of the given policies (`%s`) are defined, credentials will not be generated",
               policy);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      goto out;
    }
  }
  if (!buckets_idp_plugin_authenticate(pl, role_arn, token, &res, err, sizeof(err))) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
    goto out;
  }
  if (res.reason) {
    sts_error(c, STS_UPSTREAM_ERROR, res.reason);
    goto out;
  }
  if (!res.user || !*res.user) {
    sts_error(c, STS_UPSTREAM_ERROR, "A valid user was not returned by the authenticator.");
    goto out;
  }
  long expiry = res.max_validity;
  if (dparam && *dparam && requested < expiry) expiry = requested;
  char parent[512];
  snprintf(parent, sizeof(parent), "custom/%s", res.user);
  claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  yyjson_mut_obj_add_int(claims, root, "exp", (long long)time(NULL) + expiry);
  yyjson_mut_obj_add_strcpy(claims, root, "sub", parent);
  yyjson_mut_obj_add_strcpy(claims, root, "roleArn", role_arn);
  yyjson_mut_obj_add_strcpy(claims, root, "parent", parent);
  const char *revoke = form_get(form, url, "TokenRevokeType");
  if (revoke && *revoke) yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  if (res.claims) {
    size_t i, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(yyjson_doc_get_root(res.claims), i, max, k, v) {
      if (!yyjson_mut_obj_get(root, yyjson_get_str(k))) {
        yyjson_mut_obj_add(root, yyjson_mut_strcpy(claims, yyjson_get_str(k)), yyjson_val_mut_copy(claims, v));
      }
    }
  }
  cred = issue(c, parent, NULL, 0, claims, NULL);
  if (cred) write_credentials(c, "AssumeRoleWithCustomToken", cred, "AssumedUser", parent);
out:
  buckets_iam_ident_release(cred);
  yyjson_mut_doc_free(claims);
  buckets_idp_result_free(&res);
  buckets_plugins_release(pl);
}

/* ---- AssumeRoleWithCertificate (identity_tls) ---- */

static void assume_role_certificate(s3_ctx *c, const buckets_query *form, const buckets_query *url) {
  if (!buckets_iam_ready(c->s->iam)) {
    sts_error(c, STS_NOT_INITIALIZED, "IAM sub-system not initialized");
    return;
  }
  /* identity_tls is enabled from the environment only, as in MinIO. */
  if (buckets_config_parse_bool(buckets_config_getenv("MINIO_IDENTITY_TLS_ENABLE")) != 1) {
    sts_error(c, STS_NOT_INITIALIZED, "STS API 'AssumeRoleWithCertificate' is disabled");
    return;
  }
  if (!c->req->secure) {
    sts_error(c, STS_INSECURE_CONNECTION, "No TLS connection attempt");
    return;
  }
  const char *sv = buckets_config_getenv("MINIO_IDENTITY_TLS_SKIP_VERIFY");
  char *cfg_sv = NULL;
  if (!sv && c->s->config) sv = cfg_sv = buckets_config_sys_value(c->s->config, "identity_tls", NULL, "skip_verify");
  bool skip = buckets_config_parse_bool(sv) == 1;
  free(cfg_sv);
  buckets_client_cert cert;
  char err[512];
  switch (buckets_tls_check_client_cert(c->req->peer_certs, c->req->npeer_certs, c->s->ca_path, skip, &cert, err,
                                        sizeof(err))) {
    case BUCKETS_CERT_OK: break;
    case BUCKETS_CERT_TOO_MANY_CAS: sts_error(c, STS_TOO_MANY_INTERMEDIATE_CAS, err); return;
    case BUCKETS_CERT_MULTIPLE: sts_error(c, STS_INVALID_PARAMETER_VALUE, err); return;
    case BUCKETS_CERT_INVALID: sts_error(c, STS_INVALID_CLIENT_CERTIFICATE, err); return;
    default: sts_error(c, STS_MISSING_PARAMETER, err); return;
  }
  yyjson_mut_doc *claims = NULL;
  buckets_iam_ident *cred = NULL;
  if (!cert.cn || !*cert.cn) {
    sts_error(c, STS_MISSING_PARAMETER, "certificate subject CN cannot be empty");
    goto out;
  }
  const char *ds = form_get(form, url, "DurationSeconds");
  long long expiry = 3600;
  if (ds && *ds) {
    char *end;
    expiry = strtoll(ds, &end, 10);
    if (*end || expiry < 15 * 60 || expiry > 365LL * 24 * 3600) {
      sts_error(c, STS_MISSING_PARAMETER, "invalid token expiry");
      goto out;
    }
  }
  /* never outliving the certificate */
  long long now = (long long)time(NULL);
  if (cert.not_after && (long long)cert.not_after - now < expiry) expiry = (long long)cert.not_after - now;
  char parent[600];
  snprintf(parent, sizeof(parent), "tls/%s", cert.cn);
  claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  yyjson_mut_obj_add_int(claims, root, "exp", now + expiry);
  yyjson_mut_obj_add_strcpy(claims, root, "sub", cert.cn);
  if (cert.norgs) {
    yyjson_mut_val *aud = yyjson_mut_obj_add_arr(claims, root, "aud");
    for (size_t i = 0; i < cert.norgs; i++) yyjson_mut_arr_add_strcpy(claims, aud, cert.orgs[i]);
  } else {
    yyjson_mut_obj_add_null(claims, root, "aud");
  }
  yyjson_mut_obj_add_strcpy(claims, root, "iss", cert.issuer_cn ? cert.issuer_cn : "");
  yyjson_mut_obj_add_strcpy(claims, root, "parent", parent);
  const char *revoke = form_get(form, url, "TokenRevokeType");
  if (revoke && *revoke) yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  /* The certificate's CN names its policy. */
  cred = issue(c, parent, NULL, 0, claims, cert.cn);
  if (cred) write_credentials(c, "AssumeRoleWithCertificate", cred, NULL, NULL);
out:
  buckets_iam_ident_release(cred);
  yyjson_mut_doc_free(claims);
  buckets_client_cert_free(&cert);
}

/* ---- AssumeRoleWithLDAPIdentity ---- */

static void assume_role_ldap(s3_ctx *c, const buckets_query *form, const buckets_query *url) {
  const char *user = form_get(form, url, "LDAPUsername"), *pass = form_get(form, url, "LDAPPassword");
  if (!user || !*user || !pass || !*pass) {
    sts_error(c, STS_MISSING_PARAMETER, "LDAPUsername and LDAPPassword cannot be empty");
    return;
  }
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  buckets_ldapidp *ldap = NULL;
  buckets_ldap_dnres dn = {0};
  char **groups = NULL;
  size_t ngroups = 0;
  char *policies = NULL;
  buckets_iam_ident *cred = NULL;
  char err[1024], msg[1400];
  if (!session_policy(c, form_get(form, url, "Policy"), claims)) goto out;
  if (!buckets_iam_ready(c->s->iam)) {
    sts_error(c, STS_NOT_INITIALIZED, "IAM sub-system not initialized");
    goto out;
  }
  ldap = buckets_s3_ldap(c->s);
  if (!buckets_ldapidp_bind(ldap, user, pass, &dn, &groups, &ngroups, err, sizeof(err))) {
    snprintf(msg, sizeof(msg), "LDAP server error: %s", err);
    sts_error(c, STS_INVALID_PARAMETER_VALUE, msg);
    goto out;
  }
  policies = buckets_iam_policy_db_get(c->s->iam, dn.norm_dn, groups, ngroups);
  buckets_plugins *pl = buckets_s3_plugins(c->s);
  bool authz = buckets_authz_plugin_enabled(pl);
  buckets_plugins_release(pl);
  if (!*policies && !authz) {
    buckets_buf g = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&g, "");
    for (size_t i = 0; i < ngroups; i++) buckets_buf_appendf(&g, "%s%s", i ? "`,`" : "", groups[i]);
    snprintf(msg, sizeof(msg),
             "expecting a policy to be set for user `%s` or one of their groups: `%s` - rejecting this request",
             dn.actual_dn, g.data);
    buckets_buf_free(&g);
    sts_error(c, STS_INVALID_PARAMETER_VALUE, msg);
    goto out;
  }
  long long dur = buckets_ldapidp_expiry(ldap, form_get(form, url, "DurationSeconds"));
  if (dur < 0) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "invalid token expiry");
    goto out;
  }
  yyjson_mut_obj_add_int(claims, root, "exp", (long long)time(NULL) + dur);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUser", dn.norm_dn);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapActualUser", dn.actual_dn);
  yyjson_mut_obj_add_strcpy(claims, root, "ldapUsername", user);
  for (size_t a = 0; a < dn.nattrs; a++) {
    char key[256];
    snprintf(key, sizeof(key), "ldapAttrib_%s", dn.attrs[a].name);
    yyjson_mut_val *arr = yyjson_mut_arr(claims);
    for (size_t v = 0; v < dn.attrs[a].nvalues; v++) yyjson_mut_arr_add_strcpy(claims, arr, dn.attrs[a].values[v]);
    yyjson_mut_obj_add(root, yyjson_mut_strcpy(claims, key), arr);
  }
  const char *revoke = form_get(form, url, "TokenRevokeType");
  if (revoke && *revoke) yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  cred = issue(c, dn.norm_dn, groups, ngroups, claims, NULL);
  if (cred) write_credentials(c, "AssumeRoleWithLDAPIdentity", cred, NULL, NULL);
out:
  buckets_iam_ident_release(cred);
  free(policies);
  buckets_ldap_strv_free(groups, ngroups);
  buckets_ldap_dnres_free(&dn);
  buckets_ldapidp_release(ldap);
  yyjson_mut_doc_free(claims);
}

void buckets_sts_handle(s3_ctx *c) {
  /* The body is read first: AssumeRole's signature covers its hash. */
  buckets_s3_error re = BUCKETS_ERR_NONE;
  if (c->req->body_len > BUCKETS_S3_MAX_DOC_SIZE) {
    re = BUCKETS_ERR_ENTITY_TOO_LARGE;
  } else {
    buckets_http_body_cursor cur = {c->req, 0};
    char tmp[16384];
    long n;
    while ((n = buckets_http_body_read(&cur, tmp, sizeof(tmp))) > 0) buckets_buf_append(&c->doc, tmp, (size_t)n);
    if (n < 0) re = BUCKETS_ERR_INTERNAL_ERROR;
  }
  buckets_query form = {0};
  buckets_str ct = buckets_http_header_get(c->req, "Content-Type");
  bool is_form = ct.p && ct.n >= 33 && strncasecmp(ct.p, "application/x-www-form-urlencoded", 33) == 0;
  if (re || (is_form && !buckets_query_parse(buckets_buf_str(&c->doc), &form))) {
    buckets_query_free(&form);
    sts_error(c, STS_INVALID_PARAMETER_VALUE, re ? buckets_s3_error_get(re)->message : "invalid form data");
    return;
  }
  const char *version = form_get(&form, &c->q, "Version");
  const char *action = form_get(&form, &c->q, "Action");
  char msg[256];
  if (!version || strcmp(version, STS_API_VERSION) != 0) {
    snprintf(msg, sizeof(msg), "Invalid STS API version %s, expecting %s", version ? version : "", STS_API_VERSION);
    sts_error(c, STS_MISSING_PARAMETER, msg);
  } else if (action && strcmp(action, "AssumeRole") == 0) {
    /* checkAssumeRoleAuth: SigV4 for "sts", by a long-term credential, no token. */
    buckets_s3_error auth_err = BUCKETS_ERR_NONE;
    if (c->auth != BUCKETS_AUTH_SIGV4_HEADER) {
      auth_err = BUCKETS_ERR_ACCESS_DENIED;
    } else {
      uint8_t sum[32];
      char body_hash[65];
      buckets_sha256(c->doc.data ? c->doc.data : "", c->doc.len, sum);
      buckets_hex_encode(sum, 32, body_hash);
      buckets_sigv4_config cfg = {
          .region = c->s->region,
          .service = "sts",
          .now = time(NULL),
          .lookup = buckets_s3_lookup_secret,
          .lookup_ud = c,
          .payload_hash = body_hash,
      };
      auth_err = buckets_sigv4_verify_header(&cfg, c->req, &c->q, &c->sig);
      if (auth_err == BUCKETS_ERR_INVALID_ACCESS_KEY_ID && c->key_status == BUCKETS_IAM_KEY_DISABLED) {
        auth_err = BUCKETS_ERR_ACCESS_KEY_DISABLED;
      }
      if (!auth_err && (buckets_iam_ident_is_temp(c->ident) || buckets_iam_ident_is_svc(c->ident))) {
        auth_err = BUCKETS_ERR_ACCESS_DENIED;
      }
      if (!auth_err && buckets_http_header_get(c->req, "X-Amz-Security-Token").p) auth_err = BUCKETS_ERR_ACCESS_DENIED;
    }
    assume_role(c, &form, &c->q, auth_err);
  } else if (action && (strcmp(action, "AssumeRoleWithWebIdentity") == 0 ||
                        strcmp(action, "AssumeRoleWithClientGrants") == 0)) {
    assume_role_sso(c, &form, &c->q, action);
  } else if (action && strcmp(action, "AssumeRoleWithCustomToken") == 0) {
    assume_role_custom(c, &form, &c->q);
  } else if (action && strcmp(action, "AssumeRoleWithCertificate") == 0) {
    assume_role_certificate(c, &form, &c->q);
  } else if (action && strcmp(action, "AssumeRoleWithLDAPIdentity") == 0) {
    assume_role_ldap(c, &form, &c->q);
  } else {
    snprintf(msg, sizeof(msg), "Unsupported action %s", action ? action : "");
    sts_error(c, STS_INVALID_PARAMETER_VALUE, msg);
  }
  buckets_query_free(&form);
}
