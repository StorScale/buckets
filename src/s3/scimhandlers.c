/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The SCIM 2.0 endpoint (docs/design/scim.md, iam/scim.h), at /minio/scim/v2/: Entra ID's and Okta's provisioning
 * push who is assigned, turned off and deleted. Every request carries the bearer token made in the console; the
 * servers know only its SHA-256 (BUCKETS_SCIM_TOKEN_SHA256, or _FILE; _PREVIOUS while a new one rolls out). A change
 * is written to the store under the cluster lock and bumps its revision; identity sync, on the server leading pool
 * 0, set 0, sees it within seconds and acts (s3/server.c). Nothing here removes anyone itself. */
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/auditctx.h"
#include "core/log.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "crypto/hex.h"
#include "crypto/sha256.h"
#include "iam/idsync.h"
#include "iam/scim.h"
#include "object/nslock.h"
#include "object/sysconfig.h"
#include "s3/internal.h"

#define MAX_BODY (64 * 1024)
#define MAX_PAGE 1000
#define LOCK_TIMEOUT_MS 10000

enum { OP_READ, OP_CREATE, OP_UPDATE, OP_DELETE, OP_LIST };
enum { RES_OK, RES_UNAUTHORIZED, RES_ERROR };
static const char *const k_ops[] = {"read", "create", "update", "delete", "list"};
static const char *const k_results[] = {"ok", "unauthorized", "error"};
const char *buckets_scim_op_name(int i) { return k_ops[i]; }
const char *buckets_scim_result_name(int i) { return k_results[i]; }

bool buckets_scim_enabled(void) {
  const char *v = getenv("BUCKETS_SCIM"), *p = getenv("BUCKETS_OPENID_SYNC_PROVIDER");
  return (v && (!strcmp(v, "on") || !strcmp(v, "true") || !strcmp(v, "1"))) || (p && !strcmp(p, "scim"));
}

/* The token's SHA-256 (hex) from name, or name_FILE. */
static bool token_hash(const char *name, char out[65]) {
  char fk[96];
  snprintf(fk, sizeof(fk), "%s_FILE", name);
  const char *v = getenv(name), *f = getenv(fk);
  char buf[128] = "";
  if (f && *f) {
    FILE *fp = fopen(f, "r");
    if (!fp) return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
    buf[n] = '\0';
    v = buf;
  }
  if (!v) return false;
  size_t k = 0;
  for (const char *p = v; *p && k < 64; p++)
    if (*p != '\n' && *p != '\r' && *p != ' ') out[k++] = (char)(*p >= 'A' && *p <= 'F' ? *p + 32 : *p);
  out[k] = '\0';
  return k == 64;
}

static bool authorized(s3_ctx *c) {
  buckets_str a = buckets_http_header_get(c->req, "Authorization");
  if (!a.p || a.n < 8 || strncasecmp(a.p, "Bearer ", 7) != 0) return false;
  uint8_t sum[32];
  char got[65], want[65];
  buckets_sha256(a.p + 7, a.n - 7, sum);
  buckets_hex_encode(sum, 32, got);
  bool ok = false;
  if (token_hash("BUCKETS_SCIM_TOKEN_SHA256", want)) ok |= CRYPTO_memcmp(got, want, 64) == 0;
  if (token_hash("BUCKETS_SCIM_TOKEN_SHA256_PREVIOUS", want)) ok |= CRYPTO_memcmp(got, want, 64) == 0;
  return ok;
}

static void reply(s3_ctx *c, int status, buckets_buf *body) {
  c->resp->status = status;
  buckets_buf_reset(&c->resp->body);
  if (body && body->len) buckets_buf_append(&c->resp->body, body->data, body->len);
  buckets_http_resp_header(c->resp, "Content-Type", "application/scim+json");
}

static void scim_error(s3_ctx *c, int status, const char *type, const char *detail) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_scim_error_json(status, type, detail, &b);
  reply(c, status, &b);
  buckets_buf_free(&b);
}

/* The endpoint's own URL, for meta.location: as the provider reached it. */
static void base_url(s3_ctx *c, char *out, size_t cap) {
  buckets_str host = buckets_http_header_get(c->req, "Host");
  buckets_str proto = buckets_http_header_get(c->req, "X-Forwarded-Proto");
  bool tls = !strncmp(c->s->endpoint, "https://", 8); /* this server's own URL */
  const char *scheme = proto.p ? (proto.n == 5 && !strncasecmp(proto.p, "https", 5) ? "https" : "http")
                       : tls   ? "https"
                               : "http";
  snprintf(out, cap, "%s://%.*s" BUCKETS_SCIM_PREFIX, scheme, (int)(host.p ? host.n : 0),
           host.p ? host.p : "");
}

static void nap_ms(long ms) {
  struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
  nanosleep(&ts, NULL);
}

/* The store. A read that fails (drives or peers still coming up) is tried again for a few seconds: a provider
 * would retry anyway, but later. */
static bool load(s3_ctx *c, buckets_scim_store *st) {
  for (int attempt = 0;; attempt++) {
    buckets_buf b = BUCKETS_BUF_INIT;
    buckets_obj_err e = buckets_sysconfig_read(c->s->layer, BUCKETS_SCIM_PATH, &b, NULL);
    bool ok = (!e || e == BUCKETS_OBJ_ERR_NO_SUCH_KEY) && buckets_scim_store_parse(b.data, b.len, st);
    buckets_buf_free(&b);
    if (ok || attempt >= 20) return ok;
    nap_ms(250);
  }
}

static long long remove_after_s(void) {
  buckets_idsync_settings s;
  char err[256];
  if (buckets_idsync_settings_from_env(&s, err, sizeof(err)) && *s.provider) return s.remove_after_s;
  return 30LL * 86400;
}

static bool save(s3_ctx *c, buckets_scim_store *st) {
  st->rev++;
  buckets_scim_store_prune(st, (long long)time(NULL), remove_after_s());
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_scim_store_json(st, &b);
  buckets_obj_err e = buckets_sysconfig_write(c->s->layer, BUCKETS_SCIM_PATH, b.data, b.len);
  buckets_buf_free(&b);
  if (e) buckets_log_warn("scim: saving the people: %s", buckets_obj_strerror(e));
  return !e;
}

static void user_reply(s3_ctx *c, int status, const buckets_scim_user *u) {
  char base[600];
  base_url(c, base, sizeof(base));
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_scim_user_json(u, base, &b);
  char loc[800];
  snprintf(loc, sizeof(loc), "%s/Users/%s", base, u->id);
  if (status == 201) buckets_http_resp_header(c->resp, "Location", loc);
  reply(c, status, &b);
  buckets_buf_free(&b);
}

static void audit_person(const buckets_scim_user *u) {
  buckets_audit_tag("scimId", u->id);
  if (u->external_id) buckets_audit_tag("externalId", u->external_id);
  if (u->user_name) buckets_audit_tag("userName", u->user_name);
  buckets_audit_tag("active", u->active ? "true" : "false");
}

static void list_users(s3_ctx *c) {
  buckets_scim_filter f;
  if (!buckets_scim_filter_parse(buckets_query_get(&c->q, "filter"), &f)) {
    scim_error(c, 400, "invalidFilter", "Filters are userName eq \"...\" or externalId eq \"...\"");
    return;
  }
  const char *si = buckets_query_get(&c->q, "startIndex"), *ct = buckets_query_get(&c->q, "count");
  long start = si && atol(si) > 0 ? atol(si) : 1, count = ct ? atol(ct) : 100;
  if (count < 0) count = 0;
  if (count > MAX_PAGE) count = MAX_PAGE;
  buckets_scim_store st;
  if (!load(c, &st)) {
    scim_error(c, 500, NULL, "The people could not be read");
    return;
  }
  char base[600];
  base_url(c, base, sizeof(base));
  size_t total = 0, shown = 0;
  buckets_buf res = BUCKETS_BUF_INIT;
  for (size_t i = 0; i < st.n; i++) {
    if (!buckets_scim_filter_match(&f, &st.u[i])) continue;
    total++;
    if ((long)total < start || (long)shown >= count) continue;
    if (shown++) buckets_buf_append_char(&res, ',');
    buckets_scim_user_json(&st.u[i], base, &res);
  }
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_appendf(
      &b,
      "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:ListResponse\"],\"totalResults\":%zu,"
      "\"startIndex\":%ld,\"itemsPerPage\":%zu,\"Resources\":[",
      total, start, shown);
  if (res.len) buckets_buf_append(&b, res.data, res.len);
  buckets_buf_append_c(&b, "]}");
  reply(c, 200, &b);
  buckets_buf_free(&b);
  buckets_buf_free(&res);
  buckets_scim_store_free(&st);
}

/* A body as JSON; false (and the error sent) when it isn't. */
static yyjson_doc *body_json(s3_ctx *c) {
  if (c->req->body_len > MAX_BODY) {
    scim_error(c, 413, NULL, "The body is larger than 64 KiB");
    return NULL;
  }
  if (buckets_s3_read_doc(c)) {
    scim_error(c, 400, "invalidSyntax", "The body could not be read");
    return NULL;
  }
  yyjson_doc *d = yyjson_read(c->doc.data ? c->doc.data : "", c->doc.len, 0);
  if (!d) scim_error(c, 400, "invalidSyntax", "The body is not JSON");
  return d;
}

/* Runs fn on the store under the cluster lock; fn sends the reply and says whether to save. */
typedef bool (*change_fn)(s3_ctx *c, buckets_scim_store *st, yyjson_val *body, const char *id);
static void change(s3_ctx *c, change_fn fn, yyjson_val *body, const char *id) {
  buckets_nslock_entry *lk = NULL; /* the cluster lock can be refused at once while peers come up: tried again */
  for (int attempt = 0; !lk && attempt < 20; attempt++) {
    if (attempt) nap_ms(250);
    lk = buckets_nslock_lock(c->s->layer->locks, BUCKETS_META_BUCKET, BUCKETS_SCIM_PATH ".lock", true, LOCK_TIMEOUT_MS);
  }
  if (!lk) {
    scim_error(c, 503, NULL, "The people are being changed elsewhere; try again");
    return;
  }
  buckets_scim_store st;
  if (!load(c, &st)) {
    scim_error(c, 500, NULL, "The people could not be read");
  } else {
    if (fn(c, &st, body, id) && !save(c, &st)) scim_error(c, 500, NULL, "The people could not be saved");
    buckets_scim_store_free(&st);
  }
  buckets_nslock_unlock(lk);
}

static bool do_create(s3_ctx *c, buckets_scim_store *st, yyjson_val *body, const char *id) {
  (void)id;
  buckets_scim_user u;
  int status;
  char err[200];
  if (!buckets_scim_user_from_json(body, &u, &status, err, sizeof(err))) {
    scim_error(c, status, "invalidValue", err);
    return false;
  }
  if (buckets_scim_find_user_name(st, u.user_name) ||
      (u.external_id && buckets_scim_find_external(st, u.external_id))) {
    buckets_scim_user_free(&u);
    scim_error(c, 409, "uniqueness", "A person with this userName or externalId exists");
    return false;
  }
  char uuid[BUCKETS_UUID_STR_LEN + 1];
  buckets_uuid_v4(uuid);
  snprintf(u.id, sizeof(u.id), "%s", uuid);
  u.created = u.modified = (long long)time(NULL);
  st->u = buckets_xrealloc(st->u, (st->n + 1) * sizeof(*st->u));
  st->u[st->n++] = u;
  audit_person(&u);
  buckets_log_info("scim: %s (%s) assigned%s", u.user_name, u.external_id ? u.external_id : "no externalId",
                   u.active ? "" : ", turned off");
  user_reply(c, 201, &st->u[st->n - 1]);
  return true;
}

static bool do_replace(s3_ctx *c, buckets_scim_store *st, yyjson_val *body, const char *id) {
  buckets_scim_user *cur = buckets_scim_find_id(st, id);
  if (!cur) {
    scim_error(c, 404, NULL, "No such person");
    return false;
  }
  buckets_scim_user u;
  int status;
  char err[200];
  if (!buckets_scim_user_from_json(body, &u, &status, err, sizeof(err))) {
    scim_error(c, status, "invalidValue", err);
    return false;
  }
  bool was = cur->active;
  snprintf(u.id, sizeof(u.id), "%s", cur->id);
  u.created = cur->created;
  u.modified = (long long)time(NULL);
  buckets_scim_user_free(cur);
  *cur = u;
  audit_person(cur);
  if (was != cur->active) buckets_log_info("scim: %s turned %s", cur->user_name, cur->active ? "on" : "off");
  user_reply(c, 200, cur);
  return true;
}

static bool do_patch(s3_ctx *c, buckets_scim_store *st, yyjson_val *body, const char *id) {
  buckets_scim_user *cur = buckets_scim_find_id(st, id);
  if (!cur) {
    scim_error(c, 404, NULL, "No such person");
    return false;
  }
  bool was = cur->active;
  int status;
  char err[200];
  if (!buckets_scim_patch(cur, body, &status, err, sizeof(err))) {
    scim_error(c, status, "invalidValue", err);
    return false; /* not saved: the copy in memory is thrown away */
  }
  cur->modified = (long long)time(NULL);
  audit_person(cur);
  if (was != cur->active) buckets_log_info("scim: %s turned %s", cur->user_name, cur->active ? "on" : "off");
  user_reply(c, 200, cur);
  return true;
}

static bool do_delete(s3_ctx *c, buckets_scim_store *st, yyjson_val *body, const char *id) {
  (void)body;
  buckets_scim_user *cur = buckets_scim_find_id(st, id);
  if (!cur) {
    scim_error(c, 404, NULL, "No such person");
    return false;
  }
  cur->deleted = true; /* kept for the grace period: their keys are deleted after it */
  cur->active = false;
  cur->modified = (long long)time(NULL);
  audit_person(cur);
  buckets_log_info("scim: %s deleted", cur->user_name ? cur->user_name : cur->id);
  reply(c, 204, NULL);
  return true;
}

void buckets_scim_handle(s3_ctx *c) {
  const buckets_http_request *req = c->req;
  buckets_s3_server *s = c->s;
  snprintf(c->access_key, sizeof(c->access_key), "scim");
  int op = OP_READ;
  if (!buckets_scim_enabled() || !s->layer) {
    scim_error(c, 404, NULL, "SCIM is not turned on");
    goto out;
  }
  if (!authorized(c)) {
    buckets_http_resp_header(c->resp, "WWW-Authenticate", "Bearer");
    scim_error(c, 401, NULL, "A valid bearer token is required");
    s->scim_requests[OP_READ][RES_UNAUTHORIZED]++;
    buckets_log_warn("scim: a request without a valid token, from %s",
                     req->remote_addr ? req->remote_addr : "?");
    c->op_name = "SCIMUnauthorized";
    return;
  }
  /* the path after the prefix, without a trailing slash */
  char sub[512];
  size_t pl = strlen(BUCKETS_SCIM_PREFIX);
  snprintf(sub, sizeof(sub), "%.*s", (int)(req->path.n > pl ? req->path.n - pl : 0), req->path.p + pl);
  for (size_t n = strlen(sub); n > 1 && sub[n - 1] == '/';) sub[--n] = '\0';
  buckets_str m = req->method;
  bool get = buckets_str_eq_c(m, "GET");
  char base[600];
  base_url(c, base, sizeof(base));
  buckets_buf b = BUCKETS_BUF_INIT;
  if (get && !strcasecmp(sub, "/ServiceProviderConfig")) {
    buckets_scim_service_provider_config(&b);
    reply(c, 200, &b);
  } else if (get && !strcasecmp(sub, "/ResourceTypes")) {
    buckets_scim_resource_types(base, &b);
    reply(c, 200, &b);
  } else if (get && !strcasecmp(sub, "/Schemas")) {
    buckets_scim_schemas(&b);
    reply(c, 200, &b);
  } else if (!strncasecmp(sub, "/Groups", 7)) {
    scim_error(c, 501, NULL, "Groups are not supported: assign people to the app");
  } else if (!strcasecmp(sub, "/Users")) {
    if (get) {
      op = OP_LIST;
      c->op_name = "SCIMListUsers";
      list_users(c);
    } else if (buckets_str_eq_c(m, "POST")) {
      op = OP_CREATE;
      c->op_name = "SCIMCreateUser";
      yyjson_doc *d = body_json(c);
      if (d) change(c, do_create, yyjson_doc_get_root(d), NULL);
      yyjson_doc_free(d);
    } else {
      scim_error(c, 405, NULL, "Method not allowed");
    }
  } else if (!strncasecmp(sub, "/Users/", 7) && sub[7] && !strchr(sub + 7, '/')) {
    const char *id = sub + 7;
    if (get) {
      c->op_name = "SCIMGetUser";
      buckets_scim_store st;
      if (!load(c, &st)) {
        scim_error(c, 500, NULL, "The people could not be read");
      } else {
        buckets_scim_user *u = buckets_scim_find_id(&st, id);
        if (u)
          user_reply(c, 200, u);
        else
          scim_error(c, 404, NULL, "No such person");
        buckets_scim_store_free(&st);
      }
    } else if (buckets_str_eq_c(m, "DELETE")) {
      op = OP_DELETE;
      c->op_name = "SCIMDeleteUser";
      change(c, do_delete, NULL, id);
    } else if (buckets_str_eq_c(m, "PUT") || buckets_str_eq_c(m, "PATCH")) {
      op = OP_UPDATE;
      c->op_name = "SCIMUpdateUser";
      yyjson_doc *d = body_json(c);
      if (d) change(c, buckets_str_eq_c(m, "PUT") ? do_replace : do_patch, yyjson_doc_get_root(d), id);
      yyjson_doc_free(d);
    } else {
      scim_error(c, 405, NULL, "Method not allowed");
    }
  } else {
    scim_error(c, 404, NULL, "No such resource");
  }
  buckets_buf_free(&b);
out:
  s->scim_requests[op][c->resp->status < 400 ? RES_OK : RES_ERROR]++;
  if (!c->op_name) c->op_name = "SCIM";
}
