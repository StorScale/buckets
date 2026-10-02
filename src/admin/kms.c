/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The KMS APIs (MinIO's kms-handlers.go under /minio/kms/v1, and the admin
 * v3 /kms/... handlers mc admin kms uses). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "admin/admin.h"
#include "kms/kms.h"
#include "object/object.h"
#include "bucket/metasys.h"
#include "notify/event.h"

#define KMS_PREFIX "/minio/kms/v1"

bool buckets_admin_is_kms_path(buckets_str path) { return buckets_str_has_prefix(path, KMS_PREFIX "/"); }

static void json_reply(s3_ctx *c, const buckets_buf *b) {
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  buckets_buf_append(&c->resp->body, b->data ? b->data : "", b->len);
  c->resp->status = 200;
}

static const char *kms_err_text(buckets_kms_err e);

/* toAdminAPIErr does not know kms.Error: an internal error with its text */
static void kms_error(s3_ctx *c, buckets_kms_err e) {
  char msg[256];
  snprintf(msg, sizeof(msg), "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_INTERNAL_ERROR)->message, kms_err_text(e));
  buckets_admin_error_msg(c, BUCKETS_ERR_INTERNAL_ERROR, msg);
}

static const char *kms_err_text(buckets_kms_err e) {
  switch (e) {
  case BUCKETS_KMS_ERR_KEY_NOT_FOUND: return "key with given key ID does not exist";
  case BUCKETS_KMS_ERR_DECRYPT: return "failed to decrypt ciphertext";
  case BUCKETS_KMS_ERR_NOT_SUPPORTED: return "requested functionality is not supported";
  case BUCKETS_KMS_ERR_KEY_EXISTS: return "key with given key ID already exits";
  case BUCKETS_KMS_ERR_PERMISSION: return "insufficient permissions to perform KMS operation";
  case BUCKETS_KMS_ERR_FAILED: return "failed to create KMS key";
  default: return "kms is unavailable";
  }
}

static bool kms_ready(s3_ctx *c, const char *action) {
  if (!buckets_admin_authorize(c, action)) return false;
  if (!c->s->kms) {
    buckets_admin_error(c, BUCKETS_ERR_KMS_NOT_CONFIGURED);
    return false;
  }
  return true;
}

/* checkKMSActionAllowed: the key name stands in for the bucket */
static bool key_allowed(s3_ctx *c, const char *action, const char *key) {
  return buckets_s3_authorize(c, action, key, NULL, NULL) == BUCKETS_ERR_NONE;
}

static void status(s3_ctx *c, const char *action) {
  if (!kms_ready(c, action)) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "{\"name\":\"%s\",\"default-key-id\":\"%s\",\"endpoints\":", buckets_kms_type(c->s->kms),
                      buckets_kms_default_key(c->s->kms));
  buckets_kms_status_endpoints(c->s->kms, "127.0.0.1", &b);
  buckets_buf_append_char(&b, ',');
  buckets_buf_append_c(&b, "\"state\":{\"Version\":\"\",\"KeyStoreLatency\":0,\"KeyStoreReachable\":false,"
                           "\"KeystoreAvailable\":false,\"OS\":\"\",\"Arch\":\"\",\"UpTime\":0,\"CPUs\":0,\"UsableCPUs\":0,"
                           "\"HeapAlloc\":0,\"StackAlloc\":0}}");
  json_reply(c, &b);
  buckets_buf_free(&b);
}

static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void metrics(s3_ctx *c) {
  if (!kms_ready(c, "kms:Metrics")) return;
  buckets_kms_metrics m;
  buckets_kms_metrics_get(c->s->kms, &m);
  /* map[time.Duration]uint64: nanosecond keys, sorted as strings */
  char keys[BUCKETS_KMS_LATENCY_BUCKETS][24], *order[BUCKETS_KMS_LATENCY_BUCKETS];
  for (int i = 0; i < BUCKETS_KMS_LATENCY_BUCKETS; i++) {
    snprintf(keys[i], sizeof(keys[i]), "%lld", (long long)buckets_kms_latency_ms[i] * 1000000LL);
    order[i] = keys[i];
  }
  qsort(order, BUCKETS_KMS_LATENCY_BUCKETS, sizeof(char *), cmp_str);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "{\"kms_req_success\":%llu,\"kms_req_error\":%llu,\"kms_req_failure\":%llu,\"kms_resp_time\":{",
                      (unsigned long long)m.ok, (unsigned long long)m.err, (unsigned long long)m.fail);
  for (int i = 0; i < BUCKETS_KMS_LATENCY_BUCKETS; i++) {
    int idx = (int)((order[i] - keys[0]) / (int)sizeof(keys[0]));
    buckets_buf_appendf(&b, "%s\"%s\":%llu", i ? "," : "", order[i], (unsigned long long)m.latency[idx]);
  }
  buckets_buf_append_c(&b, "}}");
  json_reply(c, &b);
  buckets_buf_free(&b);
}

static void apis(s3_ctx *c) {
  if (!kms_ready(c, "kms:API")) return;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_kms_err e = buckets_kms_apis_json(c->s->kms, &b); /* the builtin KMS has none */
  if (e) kms_error(c, e);
  else json_reply(c, &b);
  buckets_buf_free(&b);
}

static void version(s3_ctx *c) {
  if (!kms_ready(c, "kms:Version")) return;
  char v[256];
  buckets_kms_err e = buckets_kms_version(c->s->kms, v, sizeof(v));
  if (e) {
    kms_error(c, e);
    return;
  }
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "{\"version\":");
  buckets_json_go_string(&b, v, strlen(v));
  buckets_buf_append_char(&b, '}');
  json_reply(c, &b);
  buckets_buf_free(&b);
}

static void create_key(s3_ctx *c, const char *action) {
  if (!kms_ready(c, action)) return;
  const char *key = buckets_query_get(&c->q, "key-id");
  if (!key) {
    buckets_admin_error(c, BUCKETS_ERR_NOT_IMPLEMENTED); /* the route requires key-id */
    return;
  }
  if (!key_allowed(c, action, key)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  buckets_kms_err e = buckets_kms_create_key(c->s->kms, key);
  if (e) kms_error(c, e);
  else c->resp->status = 200;
}

/* A Buckets extension (MinIO's KMS API has no delete): deleting a key loses
 * every object encrypted under it, so the KMS's default key and any key a
 * bucket encrypts with by default are refused, with the buckets named. */
static void delete_key(s3_ctx *c) {
  if (!kms_ready(c, "kms:DeleteKey")) return;
  const char *key = buckets_query_get(&c->q, "key-id");
  if (!key || !*key) {
    buckets_admin_error(c, BUCKETS_ERR_NOT_IMPLEMENTED); /* the route requires key-id */
    return;
  }
  if (!key_allowed(c, "kms:DeleteKey", key)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  if (strcmp(key, buckets_kms_default_key(c->s->kms)) == 0) {
    buckets_admin_custom_error(c, 409, "KMSKeyInUse", "the key is the KMS's default key");
    return;
  }
  buckets_bucket_info *bk = NULL;
  size_t nb = 0;
  if (buckets_obj_list_buckets(c->s->layer, &bk, &nb) != BUCKETS_OBJ_OK) {
    buckets_admin_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  buckets_buf users = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < nb; i++) {
    buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bk[i].name);
    if (st->has_sse && strcmp(st->sse.algorithm, "aws:kms") == 0 && strcmp(buckets_sse_config_key(&st->sse), key) == 0)
      buckets_buf_appendf(&users, "%s%s", users.len ? ", " : "", bk[i].name);
    buckets_bucket_state_release(st);
  }
  buckets_bucket_info_free(bk, nb);
  if (users.len) {
    char msg[1024];
    snprintf(msg, sizeof(msg), "the key encrypts these buckets by default: %s", users.data);
    buckets_admin_custom_error(c, 409, "KMSKeyInUse", msg);
  } else {
    buckets_kms_err e = buckets_kms_delete_key(c->s->kms, key);
    if (e) kms_error(c, e);
    else c->resp->status = 200;
  }
  buckets_buf_free(&users);
}

static void list_keys(s3_ctx *c) {
  if (!kms_ready(c, "kms:ListKeys")) return;
  const char *pattern = buckets_query_get(&c->q, "pattern");
  if (!pattern) pattern = "";
  /* a pattern is a name prefix, "*" ending it optional (KES's ListKeys) */
  char prefix[256];
  snprintf(prefix, sizeof(prefix), "%s", pattern);
  if (*prefix && prefix[strlen(prefix) - 1] == '*') prefix[strlen(prefix) - 1] = '\0';
  pattern = prefix;
  char **names;
  size_t n = buckets_kms_list_keys(c->s->kms, pattern, &names);
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_char(&b, '[');
  size_t shown = 0;
  for (size_t i = 0; i < n; i++) {
    if (key_allowed(c, "kms:ListKeys", names[i]))
      buckets_buf_appendf(&b, "%s{\"createdAt\":\"0001-01-01T00:00:00Z\",\"createdBy\":\"\",\"name\":\"%s\"}", shown++ ? "," : "",
                          names[i]);
    free(names[i]);
  }
  free(names);
  buckets_buf_append_char(&b, ']');
  json_reply(c, &b);
  buckets_buf_free(&b);
}

static void key_status(s3_ctx *c, const char *action) {
  if (!kms_ready(c, action)) return;
  const char *key = buckets_query_get(&c->q, "key-id");
  if (!key || !*key) key = buckets_kms_default_key(c->s->kms);
  if (!key_allowed(c, action, key)) {
    buckets_admin_error(c, BUCKETS_ERR_ACCESS_DENIED);
    return;
  }
  /* a test round trip: generate a data key, then decrypt it */
  const char *ctx = "{\"MinIO admin API\":\"KMSKeyStatusHandler\"}";
  uint8_t plain[32], back[32];
  char id[256];
  buckets_buf ct = BUCKETS_BUF_INIT, b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(&b, "{\"key-id\":\"%s\"", key);
  buckets_kms_err e = buckets_kms_generate(c->s->kms, key, ctx, plain, &ct, id, sizeof(id));
  if (e) {
    buckets_buf_appendf(&b, ",\"encryption-error\":\"%s\"", kms_err_text(e));
  } else if ((e = buckets_kms_decrypt(c->s->kms, id, (uint8_t *)ct.data, ct.len, ctx, back)) != BUCKETS_KMS_OK) {
    buckets_buf_appendf(&b, ",\"decryption-error\":\"%s\"", kms_err_text(e));
  } else if (memcmp(plain, back, 32) != 0) {
    buckets_buf_append_c(&b, ",\"decryption-error\":\"The generated and the decrypted data key do not match\"");
  }
  buckets_buf_append_char(&b, '}');
  json_reply(c, &b);
  buckets_buf_free(&b);
  buckets_buf_free(&ct);
}

void buckets_admin_kms_status_v3(s3_ctx *c) { status(c, "admin:KMSKeyStatus"); }
void buckets_admin_kms_key_status_v3(s3_ctx *c) { key_status(c, "admin:KMSKeyStatus"); }
void buckets_admin_kms_create_key_v3(s3_ctx *c) { create_key(c, "admin:KMSCreateKey"); }

void buckets_admin_kms_handle(s3_ctx *c) {
  buckets_str p = c->req->path;
  buckets_str rest = {p.p + strlen(KMS_PREFIX), p.n - strlen(KMS_PREFIX)};
  buckets_str m = c->req->method;
  bool get = buckets_str_eq_c(m, "GET"), post = buckets_str_eq_c(m, "POST");
  if (buckets_str_eq_c(rest, "/status") && get) status(c, "kms:Status");
  else if (buckets_str_eq_c(rest, "/metrics") && get) metrics(c);
  else if (buckets_str_eq_c(rest, "/apis") && get) apis(c);
  else if (buckets_str_eq_c(rest, "/version") && get) version(c);
  else if (buckets_str_eq_c(rest, "/key/create") && post) create_key(c, "kms:CreateKey");
  else if (buckets_str_eq_c(rest, "/key/delete") && post) delete_key(c);
  else if (buckets_str_eq_c(rest, "/key/list") && get && buckets_query_get(&c->q, "pattern")) list_keys(c);
  else if (buckets_str_eq_c(rest, "/key/status") && get) key_status(c, "kms:KeyStatus");
  else buckets_admin_error(c, BUCKETS_ERR_NOT_IMPLEMENTED);
}
