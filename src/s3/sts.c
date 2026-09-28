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

#include "core/timefmt.h"
#include "iam/openid.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "crypto/base64.h"
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
  buckets_xml_open(b, "AssumedRoleUser");
  buckets_xml_elem(b, "Arn", "");
  buckets_xml_elem(b, "AssumeRoleId", "");
  buckets_xml_close(b, "AssumedRoleUser");
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
static buckets_iam_ident *issue(s3_ctx *c, const char *parent, yyjson_mut_doc *claims, const char *policy) {
  yyjson_mut_val *exp = yyjson_mut_obj_get(yyjson_mut_doc_get_root(claims), "exp");
  long long e = exp && yyjson_mut_is_num(exp) ? (long long)yyjson_mut_get_num(exp) : 0;
  if (exp && yyjson_mut_is_str(exp)) e = atoll(yyjson_mut_get_str(exp));
  char *claims_json = yyjson_mut_write(claims, 0, NULL);
  char ak[21], sk[41];
  buckets_iam_generate_credentials(ak, sk);
  buckets_iam_ident *cred = NULL;
  buckets_iam_err err = buckets_iam_set_temp_user(c->s->iam, ak, sk, parent, NULL, 0, (buckets_iam_time){e, 0},
                                                  claims_json, policy, &cred);
  free(claims_json);
  if (err) {
    sts_error(c, err == BUCKETS_IAM_ERR_NOT_INITIALIZED ? STS_NOT_INITIALIZED : STS_INTERNAL_ERROR,
              err == BUCKETS_IAM_ERR_INVALID_ARGUMENT ? "token expired or has no expiry" : buckets_iam_strerror(err));
    return NULL;
  }
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
  buckets_iam_ident *cred = issue(c, c->ident->access_key, claims, NULL);
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
    if (!present) {
      snprintf(err, sizeof(err), "%s claim missing from the JWT token, credentials will not be generated", claim_name);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      buckets_buf_free(&csv);
      goto out;
    }
    if (!*policy_name) {
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
  cred = issue(c, parent, claims, policy_name);
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
  } else {
    snprintf(msg, sizeof(msg), "Unsupported action %s", action ? action : "");
    sts_error(c, STS_INVALID_PARAMETER_VALUE, msg);
  }
  buckets_query_free(&form);
}
