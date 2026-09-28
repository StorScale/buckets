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
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "crypto/base64.h"
#include "s3/internal.h"
#include "s3/sigv2.h"
#include "s3/xml.h"

#define STS_XMLNS "https://sts.amazonaws.com/doc/2011-06-15/"
#define STS_API_VERSION "2011-06-15"
#define MAX_STS_SESSION_POLICY 2048
#define MIN_EXPIRATION 900
#define MAX_EXPIRATION 31536000

typedef enum {
  STS_ACCESS_DENIED,
  STS_MISSING_PARAMETER,
  STS_INVALID_PARAMETER_VALUE,
  STS_NOT_INITIALIZED,
  STS_INTERNAL_ERROR,
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
  if (!buckets_str_eq_c(req->method, "POST") || c->bucket || req->query.n) return false;
  buckets_str ct = buckets_http_header_get(req, "Content-Type");
  return ct.p && ct.n >= 33 && strncasecmp(ct.p, "application/x-www-form-urlencoded", 33) == 0;
}

/* time.ParseDuration for the forms MINIO_STS_DURATION takes ("1h", "90m",
 * "3600s", "1h30m"). Returns seconds, or -1. */
static long long parse_duration(const char *s) {
  long long total = 0;
  if (!*s) return -1;
  while (*s) {
    char *end;
    double v = strtod(s, &end);
    if (end == s) return -1;
    long long mult;
    if (strncmp(end, "ms", 2) == 0) {
      mult = 0;
      end += 2;
    } else if (*end == 'h') {
      mult = 3600;
      end++;
    } else if (*end == 'm') {
      mult = 60;
      end++;
    } else if (*end == 's') {
      mult = 1;
      end++;
    } else {
      return -1;
    }
    total += (long long)(v * (double)mult);
    s = end;
  }
  return total;
}

/* openid.GetDefaultExpiration */
static long long expiry_seconds(const char *dsecs, bool *ok) {
  *ok = true;
  const char *env = getenv("BUCKETS_STS_DURATION");
  if (!env) env = getenv("MINIO_STS_DURATION");
  long long def = env ? parse_duration(env) : -1;
  if (def < 0) def = 3600;
  if (!env && dsecs && *dsecs) {
    char *end;
    long long v = strtoll(dsecs, &end, 10);
    if (*end || v < MIN_EXPIRATION || v > MAX_EXPIRATION) {
      *ok = false;
      return 0;
    }
    def = v;
  } else if (!env) {
    return 3600;
  }
  if (def < MIN_EXPIRATION || def > MAX_EXPIRATION) *ok = false;
  return def;
}

void buckets_sts_handle(s3_ctx *c) {
  /* checkAssumeRoleAuth runs first; its error is reported after the form
   * is validated, as MinIO does. */
  /* The body is signed over directly (no X-Amz-Content-Sha256). */
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
  uint8_t sum[32];
  char body_hash[65];
  buckets_sha256(c->doc.data ? c->doc.data : "", c->doc.len, sum);
  buckets_hex_encode(sum, 32, body_hash);

  buckets_s3_error auth_err = BUCKETS_ERR_NONE;
  if (c->auth != BUCKETS_AUTH_SIGV4_HEADER) {
    auth_err = BUCKETS_ERR_ACCESS_DENIED;
  } else {
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
    if (!auth_err && (buckets_http_header_get(c->req, "X-Amz-Security-Token").p)) auth_err = BUCKETS_ERR_ACCESS_DENIED;
  }

  buckets_query form = {0};
  if (re || !buckets_query_parse(buckets_buf_str(&c->doc), &form)) {
    buckets_query_free(&form);
    sts_error(c, STS_INVALID_PARAMETER_VALUE, re ? buckets_s3_error_get(re)->message : "invalid form data");
    return;
  }
  const char *version = buckets_query_get(&form, "Version");
  const char *action = buckets_query_get(&form, "Action");
  char msg[256];
  if (!version || strcmp(version, STS_API_VERSION) != 0) {
    snprintf(msg, sizeof(msg), "Invalid STS API version %s, expecting %s", version ? version : "", STS_API_VERSION);
    sts_error(c, STS_MISSING_PARAMETER, msg);
    goto out;
  }
  if (!action || strcmp(action, "AssumeRole") != 0) {
    snprintf(msg, sizeof(msg), "Unsupported action %s", action ? action : "");
    sts_error(c, STS_INVALID_PARAMETER_VALUE, msg);
    goto out;
  }
  if (auth_err) {
    sts_error(c, from_s3(auth_err), buckets_s3_error_get(auth_err)->message);
    goto out;
  }

  /* claims.populateSessionPolicy */
  yyjson_mut_doc *claims = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *root = yyjson_mut_obj(claims);
  yyjson_mut_doc_set_root(claims, root);
  const char *pol = buckets_query_get(&form, "Policy");
  if (pol && *pol) {
    buckets_policy *p;
    char err[512];
    if (!buckets_policy_parse(pol, strlen(pol), &p, err, sizeof(err))) {
      sts_error(c, STS_INVALID_PARAMETER_VALUE, err);
      yyjson_mut_doc_free(claims);
      goto out;
    }
    bool no_version = !*buckets_policy_version(p);
    buckets_policy_free(p);
    if (no_version) {
      sts_error(c, STS_INVALID_PARAMETER_VALUE, "Version cannot be empty expecting '2012-10-17'");
      yyjson_mut_doc_free(claims);
      goto out;
    }
    yyjson_doc *pd = yyjson_read(pol, strlen(pol), 0);
    char *compact = pd ? yyjson_write(pd, 0, NULL) : NULL;
    yyjson_doc_free(pd);
    if (!compact || strlen(compact) > MAX_STS_SESSION_POLICY) {
      free(compact);
      sts_error(c, STS_INVALID_PARAMETER_VALUE, "Session policy should not exceed 2048 characters");
      yyjson_mut_doc_free(claims);
      goto out;
    }
    size_t n = strlen(compact);
    char *b64 = buckets_xmalloc(4 * ((n + 2) / 3) + 1);
    buckets_base64_encode((const uint8_t *)compact, n, b64);
    yyjson_mut_obj_add_strcpy(claims, root, "sessionPolicy", b64);
    free(b64);
    free(compact);
  }
  bool dur_ok;
  long long dur = expiry_seconds(buckets_query_get(&form, "DurationSeconds"), &dur_ok);
  if (!dur_ok) {
    sts_error(c, STS_INVALID_PARAMETER_VALUE, "invalid token expiry");
    yyjson_mut_doc_free(claims);
    goto out;
  }
  long long exp = (long long)time(NULL) + dur;
  yyjson_mut_obj_add_int(claims, root, "exp", exp);
  yyjson_mut_obj_add_strcpy(claims, root, "parent", c->ident->access_key);
  const char *revoke = buckets_query_get(&form, "TokenRevokeType");
  if (revoke && *revoke) yyjson_mut_obj_add_strcpy(claims, root, "tokenRevokeType", revoke);
  char *claims_json = yyjson_mut_write(claims, 0, NULL);
  yyjson_mut_doc_free(claims);

  char ak[21], sk[41];
  buckets_iam_generate_credentials(ak, sk);
  buckets_iam_ident *cred;
  buckets_iam_err e = buckets_iam_set_temp_user(c->s->iam, ak, sk, c->ident->access_key, NULL, 0,
                                                (buckets_iam_time){exp, 0}, claims_json, NULL, &cred);
  free(claims_json);
  if (e) {
    sts_error(c, e == BUCKETS_IAM_ERR_NOT_INITIALIZED ? STS_NOT_INITIALIZED : STS_INTERNAL_ERROR,
              buckets_iam_strerror(e));
    goto out;
  }
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(cred->expiration.sec, cred->expiration.nsec, ts);
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "AssumeRoleResponse", STS_XMLNS);
  buckets_xml_open(b, "AssumeRoleResult");
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
  buckets_xml_close(b, "AssumeRoleResult");
  buckets_xml_open(b, "ResponseMetadata");
  buckets_xml_elem(b, "RequestId", c->request_id);
  buckets_xml_close(b, "ResponseMetadata");
  buckets_xml_close(b, "AssumeRoleResponse");
  buckets_s3_write_xml(c, 200);
  buckets_iam_ident_release(cred);
out:
  buckets_query_free(&form);
}
