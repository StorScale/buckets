/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* AWS Secrets Manager, as MinIO KES uses it: a secret per key, named after
 * it, its value the stored key (SecretString), optionally encrypted with a
 * KMS key; deletes skip the recovery window. Requests are Secrets Manager's
 * JSON protocol, signed with SigV4. Credentials: the configuration's, else
 * the AWS SDKs' chain -- the environment, web identity (IRSA), container
 * credentials (EKS Pod Identity, ECS) and the EC2 instance metadata service. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/log.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "kes/store.h"
#include "net/fetch.h"
#include "s3/sign.h"

#define TIMEOUT_MS 15000

typedef struct {
  char ak[256], sk[256], token[4096];
  int64_t expires; /* unix; 0: does not */
} aws_creds;

typedef struct {
  buckets_kes_store base;
  char url[512];  /* https://secretsmanager.<region>.amazonaws.com */
  char host[300]; /* as signed */
  char *region, *kms_key;
  bool fixed; /* the configuration's credentials */
  pthread_mutex_t mu;
  aws_creds creds;
} aws;

/* ---- credentials ------------------------------------------------------------------- */

static const char *env(const char *n) {
  const char *v = getenv(n);
  return v && *v ? v : NULL;
}

static char *read_file(const char *path) {
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  char tmp[4096];
  size_t n;
  while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0) buckets_buf_append(&b, tmp, n);
  fclose(f);
  while (b.len && (b.data[b.len - 1] == '\n' || b.data[b.len - 1] == '\r')) b.data[--b.len] = '\0';
  return b.data ? b.data : buckets_xstrdup("");
}

static int64_t parse_time(const char *s) {
  long long sec;
  long nsec;
  return s && buckets_time_parse_rfc3339(s, &sec, &nsec) ? (int64_t)sec : 0;
}

/* <tag>text</tag> */
static bool xml_get(const char *doc, size_t n, const char *tag, char *out, size_t cap) {
  char open[64], close[64];
  snprintf(open, sizeof(open), "<%s>", tag);
  snprintf(close, sizeof(close), "</%s>", tag);
  const char *a = memmem(doc, n, open, strlen(open));
  if (!a) return false;
  a += strlen(open);
  const char *b = memmem(a, n - (size_t)(a - doc), close, strlen(close));
  if (!b || (size_t)(b - a) >= cap) return false;
  memcpy(out, a, (size_t)(b - a));
  out[b - a] = '\0';
  return true;
}

static void form(buckets_buf *b, const char *k, const char *v) {
  if (b->len) buckets_buf_append_char(b, '&');
  buckets_url_encode(b, k, false);
  buckets_buf_append_char(b, '=');
  buckets_url_encode(b, v, false);
}

/* AssumeRoleWithWebIdentity (unsigned): IRSA's token file and role */
static bool web_identity(aws *a, aws_creds *c, char *err, size_t errlen) {
  const char *file = env("AWS_WEB_IDENTITY_TOKEN_FILE"), *role = env("AWS_ROLE_ARN");
  if (!file || !role) return false;
  char *token = read_file(file);
  if (!token) return snprintf(err, errlen, "aws: cannot read the web identity token %s", file), false;
  buckets_buf body = BUCKETS_BUF_INIT, url = BUCKETS_BUF_INIT;
  form(&body, "Action", "AssumeRoleWithWebIdentity");
  form(&body, "Version", "2011-06-15");
  form(&body, "RoleArn", role);
  form(&body, "RoleSessionName", env("AWS_ROLE_SESSION_NAME") ? env("AWS_ROLE_SESSION_NAME") : "buckets-kes");
  form(&body, "WebIdentityToken", token);
  free(token);
  if (env("AWS_ENDPOINT_URL_STS")) buckets_buf_append_c(&url, env("AWS_ENDPOINT_URL_STS"));
  else buckets_buf_appendf(&url, "https://sts.%s.amazonaws.com/", a->region);
  buckets_http_kv h[] = {{"Content-Type", "application/x-www-form-urlencoded"}};
  buckets_http_result r;
  char e2[300];
  bool ok = false;
  if (buckets_fetch("POST", url.data, NULL, h, 1, body.data, body.len, TIMEOUT_MS, &r, e2, sizeof(e2))) {
    char exp[64] = "";
    ok = r.status == 200 && xml_get(r.body.data, r.body.len, "AccessKeyId", c->ak, sizeof(c->ak)) &&
         xml_get(r.body.data, r.body.len, "SecretAccessKey", c->sk, sizeof(c->sk)) &&
         xml_get(r.body.data, r.body.len, "SessionToken", c->token, sizeof(c->token));
    xml_get(r.body.data, r.body.len, "Expiration", exp, sizeof(exp));
    c->expires = parse_time(exp);
    if (!ok) {
      char m[300] = "";
      xml_get(r.body.data, r.body.len, "Message", m, sizeof(m));
      snprintf(err, errlen, "aws: AssumeRoleWithWebIdentity for %s failed (%d): %s", role, r.status, m);
    }
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "aws: %s", e2);
  }
  memset(body.data, 0, body.len);
  buckets_buf_free(&body);
  buckets_buf_free(&url);
  return ok;
}

static bool creds_json(const char *body, size_t n, aws_creds *c) {
  yyjson_doc *d = yyjson_read(body, n, 0);
  yyjson_val *o = yyjson_doc_get_root(d);
  const char *ak = yyjson_get_str(yyjson_obj_get(o, "AccessKeyId")), *sk = yyjson_get_str(yyjson_obj_get(o, "SecretAccessKey"));
  const char *tok = yyjson_get_str(yyjson_obj_get(o, "Token")), *exp = yyjson_get_str(yyjson_obj_get(o, "Expiration"));
  bool ok = ak && sk;
  if (ok) {
    snprintf(c->ak, sizeof(c->ak), "%s", ak);
    snprintf(c->sk, sizeof(c->sk), "%s", sk);
    snprintf(c->token, sizeof(c->token), "%s", tok ? tok : "");
    c->expires = parse_time(exp);
  }
  yyjson_doc_free(d);
  return ok;
}

/* container credentials: EKS Pod Identity and ECS */
static bool container(aws_creds *c, char *err, size_t errlen) {
  buckets_buf url = BUCKETS_BUF_INIT;
  if (env("AWS_CONTAINER_CREDENTIALS_FULL_URI")) buckets_buf_append_c(&url, env("AWS_CONTAINER_CREDENTIALS_FULL_URI"));
  else if (env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"))
    buckets_buf_appendf(&url, "http://169.254.170.2%s", env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"));
  else return false;
  char *tok = env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") ? read_file(env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"))
              : env("AWS_CONTAINER_AUTHORIZATION_TOKEN")    ? buckets_xstrdup(env("AWS_CONTAINER_AUTHORIZATION_TOKEN"))
                                                             : NULL;
  buckets_http_kv h[1];
  size_t nh = 0;
  if (tok) h[nh++] = (buckets_http_kv){"Authorization", tok};
  buckets_http_result r;
  char e2[300];
  bool ok = false;
  if (buckets_fetch("GET", url.data, NULL, h, nh, NULL, 0, 5000, &r, e2, sizeof(e2))) {
    ok = r.status == 200 && creds_json(r.body.data, r.body.len, c);
    if (!ok) snprintf(err, errlen, "aws: container credentials from %s failed (%d)", url.data, r.status);
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "aws: container credentials: %s", e2);
  }
  free(tok);
  buckets_buf_free(&url);
  return ok;
}

/* the EC2 instance metadata service, IMDSv2 */
static bool imds(aws_creds *c, char *err, size_t errlen) {
  if (env("AWS_EC2_METADATA_DISABLED") && strcasecmp(env("AWS_EC2_METADATA_DISABLED"), "true") == 0) return false;
  const char *base = env("AWS_EC2_METADATA_SERVICE_ENDPOINT") ? env("AWS_EC2_METADATA_SERVICE_ENDPOINT") : "http://169.254.169.254";
  char url[512];
  snprintf(url, sizeof(url), "%s/latest/api/token", base);
  buckets_http_kv th[] = {{"X-aws-ec2-metadata-token-ttl-seconds", "21600"}};
  buckets_http_result r;
  char e2[300], token[512] = "", role[256] = "";
  bool ok = false;
  if (!buckets_fetch("PUT", url, NULL, th, 1, NULL, 0, 2000, &r, e2, sizeof(e2))) return false;
  if (r.status == 200) snprintf(token, sizeof(token), "%.*s", (int)r.body.len, r.body.data);
  buckets_http_result_free(&r);
  if (!*token) return false;
  buckets_http_kv h[] = {{"X-aws-ec2-metadata-token", token}};
  snprintf(url, sizeof(url), "%s/latest/meta-data/iam/security-credentials/", base);
  if (buckets_fetch("GET", url, NULL, h, 1, NULL, 0, 2000, &r, e2, sizeof(e2))) {
    if (r.status == 200) snprintf(role, sizeof(role), "%.*s", (int)strcspn(r.body.data, "\n"), r.body.data);
    buckets_http_result_free(&r);
  }
  if (!*role) return snprintf(err, errlen, "aws: the instance has no IAM role"), false;
  snprintf(url, sizeof(url), "%s/latest/meta-data/iam/security-credentials/%s", base, role);
  if (buckets_fetch("GET", url, NULL, h, 1, NULL, 0, 2000, &r, e2, sizeof(e2))) {
    ok = r.status == 200 && creds_json(r.body.data, r.body.len, c);
    buckets_http_result_free(&r);
  }
  return ok;
}

/* The credentials to sign with, refreshed five minutes before they expire. */
static bool credentials(aws *a, aws_creds *out, char *err, size_t errlen) {
  pthread_mutex_lock(&a->mu);
  bool fresh = a->creds.ak[0] && (!a->creds.expires || a->creds.expires - (int64_t)time(NULL) > 300);
  if (fresh || a->fixed) {
    *out = a->creds;
    pthread_mutex_unlock(&a->mu);
    return true;
  }
  pthread_mutex_unlock(&a->mu);
  aws_creds c = {0};
  bool ok = false;
  *err = '\0';
  if (env("AWS_ACCESS_KEY_ID") && env("AWS_SECRET_ACCESS_KEY")) {
    snprintf(c.ak, sizeof(c.ak), "%s", env("AWS_ACCESS_KEY_ID"));
    snprintf(c.sk, sizeof(c.sk), "%s", env("AWS_SECRET_ACCESS_KEY"));
    snprintf(c.token, sizeof(c.token), "%s", env("AWS_SESSION_TOKEN") ? env("AWS_SESSION_TOKEN") : "");
    ok = true;
  }
  if (!ok) ok = web_identity(a, &c, err, errlen);
  if (!ok && !*err) ok = container(&c, err, errlen);
  if (!ok && !*err) ok = imds(&c, err, errlen);
  if (!ok) {
    if (!*err)
      snprintf(err, errlen, "aws: no credentials: none configured, and none in the environment, from web identity, "
                            "container credentials or the instance metadata service");
    return false;
  }
  pthread_mutex_lock(&a->mu);
  a->creds = c;
  pthread_mutex_unlock(&a->mu);
  *out = c;
  memset(&c, 0, sizeof(c));
  return true;
}

/* ---- requests ------------------------------------------------------------------------- */

/* One Secrets Manager call: 0 on transport failure; the error's type (its
 * "__type" without the namespace) into etype. */
static int call(aws *a, const char *op, const char *body, buckets_buf *out, char *etype, size_t ecap, char *err,
                size_t errlen) {
  *etype = '\0';
  aws_creds c;
  if (!credentials(a, &c, err, errlen)) return -1;
  char target[128];
  snprintf(target, sizeof(target), "secretsmanager.%s", op);
  buckets_http_kv hdrs[] = {{"Content-Type", "application/x-amz-json-1.1"}, {"X-Amz-Target", target}};
  uint8_t sum[32];
  char hash[65];
  buckets_sha256(body, strlen(body), sum);
  buckets_hex_encode(sum, 32, hash);
  buckets_sigv4_creds cr = {.access_key = c.ak, .secret_key = c.sk, .session_token = c.token[0] ? c.token : NULL,
                            .region = a->region, .service = "secretsmanager"};
  buckets_sigv4_signed sg;
  if (!buckets_sigv4_sign(&cr, "POST", "/", "", a->host, hdrs, 2, hash, time(NULL), &sg)) {
    memset(&c, 0, sizeof(c));
    return snprintf(err, errlen, "aws: signing failed"), -1;
  }
  /* the signed headers point into c: it is wiped once they are sent */
  buckets_http_result r;
  char e2[300];
  int status = 0;
  if (buckets_fetch("POST", a->url, NULL, sg.kv, sg.n, body, strlen(body), TIMEOUT_MS, &r, e2, sizeof(e2))) {
    status = r.status;
    if (status != 200) {
      yyjson_doc *d = yyjson_read(r.body.data, r.body.len, 0);
      const char *t = yyjson_get_str(yyjson_obj_get(yyjson_doc_get_root(d), "__type"));
      if (t) snprintf(etype, ecap, "%s", strchr(t, '#') ? strchr(t, '#') + 1 : t);
      char m[200];
      buckets_kes_error_text(r.body.data, r.body.len, m, sizeof(m));
      snprintf(err, errlen, "aws: %s: %.100s%s%s (%d)", op, etype, *m ? ": " : "", m, status);
      yyjson_doc_free(d);
    }
    if (out) buckets_buf_append(out, r.body.data, r.body.len);
    buckets_http_result_free(&r);
  } else {
    snprintf(err, errlen, "aws: %s: %s", op, e2);
  }
  memset(&c, 0, sizeof(c));
  return status;
}

static char *json1(const char *k1, const char *v1, const char *k2, const char *v2, const char *k3, const char *v3) {
  yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *o = yyjson_mut_obj(d);
  yyjson_mut_doc_set_root(d, o);
  if (k1) yyjson_mut_obj_add_str(d, o, k1, v1);
  if (k2) yyjson_mut_obj_add_str(d, o, k2, v2);
  if (k3) yyjson_mut_obj_add_str(d, o, k3, v3);
  char *s = yyjson_mut_write(d, 0, NULL);
  yyjson_mut_doc_free(d);
  return s;
}

static buckets_kes_status a_status(buckets_kes_store *s, int64_t *lat, char *err, size_t errlen) {
  aws *a = (aws *)s;
  struct timespec t0, t1;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  buckets_http_result r;
  char e2[300];
  bool ok = buckets_fetch("GET", a->url, NULL, NULL, 0, NULL, 0, TIMEOUT_MS, &r, e2, sizeof(e2));
  clock_gettime(CLOCK_MONOTONIC, &t1);
  *lat = (t1.tv_sec - t0.tv_sec) * 1000000 + (t1.tv_nsec - t0.tv_nsec) / 1000;
  if (!ok) return snprintf(err, errlen, "aws: %s", e2), BUCKETS_KES_UNREACHABLE;
  buckets_http_result_free(&r);
  return BUCKETS_KES_OK;
}

static buckets_kes_status a_create(buckets_kes_store *s, const char *name, const char *value, size_t n, char *err,
                                   size_t errlen) {
  aws *a = (aws *)s;
  char *v = buckets_xmalloc(n + 1);
  memcpy(v, value, n);
  v[n] = '\0';
  char *body = json1("Name", name, "SecretString", v, a->kms_key ? "KmsKeyId" : NULL, a->kms_key);
  memset(v, 0, n);
  free(v);
  char etype[128];
  int st = call(a, "CreateSecret", body, NULL, etype, sizeof(etype), err, errlen);
  memset(body, 0, strlen(body));
  free(body);
  if (st == 200) return BUCKETS_KES_OK;
  if (strcmp(etype, "ResourceExistsException") == 0) return BUCKETS_KES_EXISTS;
  return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
}

static buckets_kes_status a_get(buckets_kes_store *s, const char *name, buckets_buf *value, char *err, size_t errlen) {
  aws *a = (aws *)s;
  char *body = json1("SecretId", name, NULL, NULL, NULL, NULL);
  buckets_buf out = BUCKETS_BUF_INIT;
  char etype[128];
  int st = call(a, "GetSecretValue", body, &out, etype, sizeof(etype), err, errlen);
  free(body);
  buckets_kes_status ret = BUCKETS_KES_FAILED;
  if (st == 200) {
    yyjson_doc *d = yyjson_read(out.data, out.len, 0);
    yyjson_val *o = yyjson_doc_get_root(d);
    const char *str = yyjson_get_str(yyjson_obj_get(o, "SecretString"));
    const char *bin = yyjson_get_str(yyjson_obj_get(o, "SecretBinary")); /* base64 in the JSON protocol */
    if (str) {
      buckets_buf_append_c(value, str);
      ret = BUCKETS_KES_OK;
    } else if (bin) {
      size_t bl = strlen(bin);
      buckets_buf_reserve(value, bl);
      long dn = buckets_base64_decode(bin, bl, (uint8_t *)value->data + value->len);
      if (dn >= 0) value->len += (size_t)dn, ret = BUCKETS_KES_OK;
    }
    if (ret != BUCKETS_KES_OK) snprintf(err, errlen, "aws: failed to read '%s': the secret has no value", name);
    yyjson_doc_free(d);
  } else if (strcmp(etype, "ResourceNotFoundException") == 0) {
    ret = BUCKETS_KES_NOT_FOUND;
  } else if (st <= 0) {
    ret = BUCKETS_KES_UNREACHABLE;
  }
  if (out.data) memset(out.data, 0, out.len);
  buckets_buf_free(&out);
  return ret;
}

static buckets_kes_status a_del(buckets_kes_store *s, const char *name, char *err, size_t errlen) {
  aws *a = (aws *)s;
  char body[400];
  snprintf(body, sizeof(body), "{\"SecretId\":\"%s\",\"ForceDeleteWithoutRecovery\":true}", name); /* names are [A-Za-z0-9_-] */
  char etype[128];
  int st = call(a, "DeleteSecret", body, NULL, etype, sizeof(etype), err, errlen);
  if (st == 200) return BUCKETS_KES_OK;
  if (strcmp(etype, "ResourceNotFoundException") == 0) return BUCKETS_KES_NOT_FOUND;
  return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
}

static buckets_kes_status a_list(buckets_kes_store *s, char ***names, size_t *n, char *err, size_t errlen) {
  aws *a = (aws *)s;
  *names = NULL, *n = 0;
  size_t cap = 0;
  char *next = NULL;
  for (int page = 0; page < 1000; page++) {
    char *body = next ? json1("NextToken", next, NULL, NULL, NULL, NULL) : buckets_xstrdup("{\"MaxResults\":100}");
    free(next), next = NULL;
    buckets_buf out = BUCKETS_BUF_INIT;
    char etype[128];
    int st = call(a, "ListSecrets", body, &out, etype, sizeof(etype), err, errlen);
    free(body);
    if (st != 200) {
      buckets_buf_free(&out);
      return st <= 0 ? BUCKETS_KES_UNREACHABLE : BUCKETS_KES_FAILED;
    }
    yyjson_doc *d = yyjson_read(out.data, out.len, 0);
    yyjson_val *o = yyjson_doc_get_root(d);
    size_t i, max;
    yyjson_val *sec;
    yyjson_arr_foreach(yyjson_obj_get(o, "SecretList"), i, max, sec) {
      const char *nm = yyjson_get_str(yyjson_obj_get(sec, "Name"));
      if (!nm || !buckets_kes_valid_name(nm)) continue; /* other secrets in the account */
      if (*n == cap) *names = buckets_xrealloc(*names, (cap = cap ? 2 * cap : 32) * sizeof(char *));
      (*names)[(*n)++] = buckets_xstrdup(nm);
    }
    const char *nt = yyjson_get_str(yyjson_obj_get(o, "NextToken"));
    if (nt && *nt) next = buckets_xstrdup(nt);
    yyjson_doc_free(d);
    buckets_buf_free(&out);
    if (!next) break;
  }
  free(next);
  return BUCKETS_KES_OK;
}

static void a_close(buckets_kes_store *s) {
  aws *a = (aws *)s;
  memset(&a->creds, 0, sizeof(a->creds));
  pthread_mutex_destroy(&a->mu);
  free(a->region);
  free(a->kms_key);
  free(a);
}

static const buckets_kes_store_ops aws_ops = {a_status, a_create, a_get, a_del, a_list, a_close};

buckets_kes_store *buckets_kes_aws_open(yyjson_val *c, char *err, size_t errlen) {
  const char *region = buckets_kes_conf_str(c, "region"), *ep = buckets_kes_conf_str(c, "endpoint");
  if (!region || !*region) return snprintf(err, errlen, "kesconf: invalid AWS secretsmanager keystore: no region specified"), NULL;
  aws *a = buckets_xcalloc(1, sizeof(*a));
  a->base.ops = &aws_ops;
  a->region = buckets_xstrdup(region);
  const char *kms = buckets_kes_conf_str(c, "kmskey");
  a->kms_key = kms && *kms ? buckets_xstrdup(kms) : NULL;
  /* endpoint: a host (as KES's configs have it) or a URL */
  if (!ep || !*ep) snprintf(a->url, sizeof(a->url), "https://secretsmanager.%s.amazonaws.com/", region);
  else if (strstr(ep, "://")) snprintf(a->url, sizeof(a->url), "%s%s", ep, ep[strlen(ep) - 1] == '/' ? "" : "/");
  else snprintf(a->url, sizeof(a->url), "https://%s/", ep);
  const char *h = strstr(a->url, "://") + 3;
  snprintf(a->host, sizeof(a->host), "%.*s", (int)strcspn(h, "/"), h);
  /* the default port is not part of the signed Host */
  size_t hl = strlen(a->host);
  if (hl > 4 && strcmp(a->host + hl - 4, ":443") == 0 && strncmp(a->url, "https", 5) == 0) a->host[hl - 4] = '\0';
  snprintf(a->base.desc, sizeof(a->base.desc), "AWS SecretsManager: %.250s", a->host);
  pthread_mutex_init(&a->mu, NULL);
  const char *ak = buckets_kes_conf_str(c, "credentials.accesskey"), *sk = buckets_kes_conf_str(c, "credentials.secretkey");
  const char *tok = buckets_kes_conf_str(c, "credentials.token");
  if ((ak && *ak) || (sk && *sk)) {
    a->fixed = true;
    snprintf(a->creds.ak, sizeof(a->creds.ak), "%s", ak ? ak : "");
    snprintf(a->creds.sk, sizeof(a->creds.sk), "%s", sk ? sk : "");
    snprintf(a->creds.token, sizeof(a->creds.token), "%s", tok ? tok : "");
  }
  /* as KES: the endpoint must answer at startup */
  int64_t lat;
  if (a_status(&a->base, &lat, err, errlen) != BUCKETS_KES_OK) {
    a_close(&a->base);
    return NULL;
  }
  return &a->base;
}
