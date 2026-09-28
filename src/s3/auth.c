/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Request authorization: MinIO's authorizeRequest and getConditionValues
 * (cmd/auth-handler.go, cmd/bucket-policy.go). */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bucket/metasys.h"
#include "core/query.h"
#include "s3/internal.h"

typedef struct {
  char *key;
  char **values;
  size_t n;
} cond_entry;

struct s3_conds {
  cond_entry *e;
  size_t n, cap;
  buckets_cond_value *view; /* rebuilt by cond_view */
  const char ***vals;
};

static cond_entry *cond_find(s3_conds *cs, const char *key) {
  for (size_t i = 0; i < cs->n; i++) {
    if (strcmp(cs->e[i].key, key) == 0) return &cs->e[i];
  }
  return NULL;
}

/* args[key] = append(args[key], value) */
static void cond_add(s3_conds *cs, const char *key, const char *value, size_t vlen) {
  cond_entry *e = cond_find(cs, key);
  if (!e) {
    if (cs->n == cs->cap) {
      cs->cap = cs->cap ? cs->cap * 2 : 32;
      cs->e = buckets_xrealloc(cs->e, cs->cap * sizeof(*cs->e));
    }
    e = &cs->e[cs->n++];
    memset(e, 0, sizeof(*e));
    e->key = buckets_xstrdup(key);
  }
  e->values = buckets_xrealloc(e->values, (e->n + 1) * sizeof(char *));
  e->values[e->n++] = buckets_xstrndup(value, vlen);
}

static void cond_add_c(s3_conds *cs, const char *key, const char *value) {
  cond_add(cs, key, value ? value : "", value ? strlen(value) : 0);
}

/* args[key] = []string{value}: replaces. */
static void cond_set(s3_conds *cs, const char *key, const char *value) {
  cond_entry *e = cond_find(cs, key);
  if (e) {
    for (size_t i = 0; i < e->n; i++) free(e->values[i]);
    e->n = 0;
  }
  cond_add_c(cs, key, value);
}

void buckets_s3_conds_free(s3_conds *cs) {
  if (!cs) return;
  for (size_t i = 0; i < cs->n; i++) {
    free(cs->e[i].key);
    for (size_t j = 0; j < cs->e[i].n; j++) free(cs->e[i].values[j]);
    free(cs->e[i].values);
  }
  free(cs->e);
  free(cs->view);
  free(cs);
}

/* http.CanonicalMIMEHeaderKey: "x-amz-date" -> "X-Amz-Date"; keys with
 * characters outside the token set are left unchanged. */
static void canonical_key(buckets_str in, char *out, size_t cap) {
  size_t n = BUCKETS_MIN(in.n, cap - 1);
  bool valid = true;
  for (size_t i = 0; i < n; i++) {
    unsigned char ch = (unsigned char)in.p[i];
    if (ch <= ' ' || ch >= 0x7f || strchr("\"(),/:;<=>?@[\\]{}", ch)) valid = false;
  }
  bool upper = true;
  for (size_t i = 0; i < n; i++) {
    char ch = in.p[i];
    if (valid) {
      ch = upper ? (char)toupper((unsigned char)ch) : (char)tolower((unsigned char)ch);
      upper = ch == '-';
    }
    out[i] = ch;
  }
  out[n] = '\0';
}

/* GetSourceIPRaw: X-Forwarded-For (first address), X-Real-Ip, Forwarded
 * for=, else the peer address. */
static void source_ip(const buckets_http_request *req, char *out, size_t cap) {
  buckets_str h = buckets_http_header_get(req, "X-Forwarded-For");
  if (h.p && h.n) {
    size_t n = h.n;
    for (size_t i = 0; i + 1 < h.n; i++) {
      if (h.p[i] == ',' && h.p[i + 1] == ' ') {
        n = i;
        break;
      }
    }
    snprintf(out, cap, "%.*s", (int)n, h.p);
  } else if ((h = buckets_http_header_get(req, "X-Real-Ip")).p && h.n) {
    snprintf(out, cap, "%.*s", (int)h.n, h.p);
  } else if ((h = buckets_http_header_get(req, "Forwarded")).p && h.n) {
    const char *f = NULL;
    for (size_t i = 0; i + 4 <= h.n; i++) {
      if (strncasecmp(h.p + i, "for=", 4) == 0) {
        f = h.p + i + 4;
        break;
      }
    }
    size_t n = 0;
    if (f) {
      while (f + n < h.p + h.n && !strchr("(;|, ", f[n])) n++;
    }
    while (n && *f == '"') {
      f++;
      n--;
    }
    while (n && f[n - 1] == '"') n--;
    snprintf(out, cap, "%.*s", (int)n, f ? f : "");
  } else {
    snprintf(out, cap, "%s", req->remote_addr ? req->remote_addr : "");
    return;
  }
  /* net.SplitHostPort, when the header carried a port. */
  char *colon = strrchr(out, ':');
  if (out[0] == '[') {
    char *rb = strchr(out, ']');
    if (rb && rb[1] == ':') {
      memmove(out, out + 1, (size_t)(rb - out - 1));
      out[rb - out - 1] = '\0';
    }
  } else if (colon && strchr(out, ':') == colon) {
    *colon = '\0';
  }
}

static const char *auth_sig_version(buckets_auth_type t) {
  switch (t) {
    case BUCKETS_AUTH_SIGV2:
    case BUCKETS_AUTH_SIGV2_PRESIGNED: return "AWS";
    case BUCKETS_AUTH_SIGV4_HEADER:
    case BUCKETS_AUTH_SIGV4_PRESIGNED:
    case BUCKETS_AUTH_SIGV4_STREAMING:
    case BUCKETS_AUTH_POST_POLICY: return "AWS4-HMAC-SHA256";
    default: return "";
  }
}

static const char *auth_kind(buckets_auth_type t) {
  switch (t) {
    case BUCKETS_AUTH_SIGV2_PRESIGNED:
    case BUCKETS_AUTH_SIGV4_PRESIGNED: return "REST-QUERY-STRING";
    case BUCKETS_AUTH_SIGV2:
    case BUCKETS_AUTH_SIGV4_HEADER:
    case BUCKETS_AUTH_SIGV4_STREAMING: return "REST-HEADER";
    case BUCKETS_AUTH_POST_POLICY: return "POST";
    default: return "";
  }
}

static bool is_lock_header(const char *canon) {
  return strcmp(canon, "X-Amz-Object-Lock-Mode") == 0 || strcmp(canon, "X-Amz-Object-Lock-Legal-Hold") == 0 ||
         strcmp(canon, "X-Amz-Object-Lock-Retain-Until-Date") == 0;
}

/* getConditionValues(r, "", cred). */
static s3_conds *build_conds(s3_ctx *c) {
  s3_conds *cs = buckets_xcalloc(1, sizeof(*cs));
  const buckets_http_request *req = c->req;
  const buckets_iam_ident *id = c->ident;
  const char *username = id ? buckets_iam_condition_user(id) : "";
  const char *principal = "Anonymous";
  if (*username) {
    principal = id->claims ? "AssumedRole" : "User";
    if (strcmp(username, buckets_iam_root_access_key(c->s->iam)) == 0) principal = "Account";
  }
  time_t now = time(NULL);
  struct tm tm;
  gmtime_r(&now, &tm);
  char ts[32], epoch[24], ip[128];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
  snprintf(epoch, sizeof(epoch), "%lld", (long long)now);
  source_ip(req, ip, sizeof(ip));
  buckets_str ua = buckets_http_header_get(req, "User-Agent"), ref = buckets_http_header_get(req, "Referer");
  char *uas = buckets_xstrndup(ua.p ? ua.p : "", ua.n), *refs = buckets_xstrndup(ref.p ? ref.p : "", ref.n);

  const char *vid = buckets_query_get(&c->q, "versionId");
  char *copy_vid = NULL;
  if (!vid || !*vid) {
    /* url.Parse(X-Amz-Copy-Source).Query().Get("versionId") */
    buckets_str cs_h = buckets_http_header_get(req, "X-Amz-Copy-Source");
    const char *q = cs_h.p ? memchr(cs_h.p, '?', cs_h.n) : NULL;
    if (q) {
      buckets_query qq = {0};
      buckets_query_parse((buckets_str){q + 1, (size_t)(cs_h.p + cs_h.n - q - 1)}, &qq);
      const char *v = buckets_query_get(&qq, "versionId");
      if (v) copy_vid = buckets_xstrdup(v);
      buckets_query_free(&qq);
    }
    vid = copy_vid;
  }

  cond_add_c(cs, "CurrentTime", ts);
  cond_add_c(cs, "EpochTime", epoch);
  cond_add_c(cs, "SecureTransport", req->secure ? "true" : "false");
  cond_add_c(cs, "SourceIp", ip);
  cond_add_c(cs, "UserAgent", uas);
  cond_add_c(cs, "Referer", refs);
  cond_add_c(cs, "principaltype", principal);
  cond_add_c(cs, "userid", username);
  cond_add_c(cs, "username", username);
  cond_add_c(cs, "versionid", vid ? vid : "");
  cond_add_c(cs, "signatureversion", auth_sig_version(c->auth));
  cond_add_c(cs, "authType", auth_kind(c->auth));
  free(uas);
  free(refs);
  free(copy_vid);

  /* Object tags from X-Amz-Tagging. */
  buckets_str tagging = buckets_http_header_get(req, "X-Amz-Tagging");
  if (tagging.p && tagging.n) {
    buckets_query tags = {0};
    if (buckets_query_parse(tagging, &tags)) {
      for (size_t i = 0; i < tags.n; i++) {
        char key[512];
        snprintf(key, sizeof(key), "ExistingObjectTag/%s", tags.items[i].key);
        cond_set(cs, key, tags.items[i].value);
        snprintf(key, sizeof(key), "RequestObjectTag/%s", tags.items[i].key);
        cond_set(cs, key, tags.items[i].value);
      }
      cond_entry *e = cond_find(cs, "RequestObjectTagKeys");
      if (!e && tags.n) {
        for (size_t i = 0; i < tags.n; i++) cond_add_c(cs, "RequestObjectTagKeys", tags.items[i].key);
      }
    }
    buckets_query_free(&tags);
  }

  /* Headers (canonical names); object-lock headers lose their X-Amz- prefix. */
  for (size_t i = 0; i < req->nheaders; i++) {
    char key[256];
    canonical_key(req->headers[i].name, key, sizeof(key));
    if (strcmp(key, "X-Amz-Tagging") == 0) continue;
    if (strcmp(key, "X-Amz-Signature-Age") == 0) {
      char *v = buckets_xstrndup(req->headers[i].value.p, req->headers[i].value.n);
      cond_set(cs, "signatureAge", v);
      free(v);
      continue;
    }
    const char *k = is_lock_header(key) ? key + 6 : key;
    cond_add(cs, k, req->headers[i].value.p, req->headers[i].value.n);
  }
  /* Query parameters. */
  for (size_t i = 0; i < c->q.n; i++) {
    const char *k = c->q.items[i].key;
    if (is_lock_header(k)) k += 6;
    cond_add_c(cs, k, c->q.items[i].value);
  }

  /* JWT claims: every string claim (ldap prefix trimmed, lowercased), and
   * the groups list. */
  if (id && id->claims) {
    yyjson_val *root = yyjson_doc_get_root(id->claims);
    size_t idx, max;
    yyjson_val *k, *v;
    yyjson_obj_foreach(root, idx, max, k, v) {
      if (!yyjson_is_str(v)) continue;
      const char *name = yyjson_get_str(k);
      if (strncmp(name, "ldap", 4) == 0) name += 4;
      char lower[256];
      size_t n = BUCKETS_MIN(strlen(name), sizeof(lower) - 1);
      for (size_t j = 0; j < n; j++) lower[j] = (char)tolower((unsigned char)name[j]);
      lower[n] = '\0';
      cond_set(cs, lower, yyjson_get_str(v));
    }
    yyjson_val *groups = yyjson_obj_get(root, "groups");
    if (yyjson_is_arr(groups)) {
      bool any = false;
      yyjson_arr_foreach(groups, idx, max, v) {
        if (!yyjson_is_str(v)) continue;
        if (!any) {
          cond_entry *e = cond_find(cs, "groups");
          if (e) {
            for (size_t j = 0; j < e->n; j++) free(e->values[j]);
            e->n = 0;
          }
          any = true;
        }
        cond_add_c(cs, "groups", yyjson_get_str(v));
      }
    }
  }
  if (id && !cond_find(cs, "groups")) {
    for (size_t i = 0; i < id->ngroups; i++) cond_add_c(cs, "groups", id->groups[i]);
  }
  return cs;
}

static const buckets_cond_value *cond_view(s3_conds *cs) {
  free(cs->view);
  cs->view = buckets_xcalloc(cs->n ? cs->n : 1, sizeof(*cs->view));
  for (size_t i = 0; i < cs->n; i++) {
    cs->view[i] = (buckets_cond_value){cs->e[i].key, (const char *const *)cs->e[i].values, cs->e[i].n};
  }
  return cs->view;
}

void buckets_s3_cond_override(s3_ctx *c, const char *key, const char *value) {
  if (!c->conds) c->conds = build_conds(c);
  cond_set(c->conds, key, value);
}

/* PolicySys.IsAllowed: anonymous requests against the bucket's policy. */
static bool bucket_policy_allows(s3_ctx *c, const char *action, const char *bucket, const char *object) {
  if (!bucket || !*bucket || !c->s->meta) return false;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, bucket);
  bool ok = false;
  if (st->policy) {
    buckets_policy_args a = {
        .account = "",
        .action = action,
        .bucket = bucket,
        .object = object ? object : "",
        .conds = cond_view(c->conds),
        .nconds = c->conds->n,
    };
    ok = buckets_bucket_policy_allowed(st->policy, &a);
  }
  buckets_bucket_state_release(st);
  return ok;
}

bool buckets_s3_bucket_policy_allows(s3_ctx *c, const char *action, const char *bucket, const char *object) {
  if (!c->conds) c->conds = build_conds(c);
  return bucket_policy_allows(c, action, bucket, object);
}

bool buckets_s3_allowed(s3_ctx *c, const char *action, const char *bucket, const char *object, bool deny_only) {
  if (!c->conds) c->conds = build_conds(c);
  if (!c->ident) return bucket_policy_allows(c, action, bucket, object);
  buckets_policy_args a = {
      .action = action,
      .bucket = bucket ? bucket : "",
      .object = object ? object : "",
      .deny_only = deny_only,
      .conds = cond_view(c->conds),
      .nconds = c->conds->n,
  };
  return buckets_iam_is_allowed(c->s->iam, c->ident, c->owner, &a);
}

buckets_s3_error buckets_s3_authorize(s3_ctx *c, const char *action, const char *bucket, const char *object,
                                      const char *version_id) {
  if (!c->ident) {
    if (buckets_s3_allowed(c, action, bucket, object, false)) return BUCKETS_ERR_NONE;
    if (strcmp(action, "s3:ListBucketVersions") == 0 && buckets_s3_allowed(c, "s3:ListBucket", bucket, object, false)) {
      return BUCKETS_ERR_NONE;
    }
    return BUCKETS_ERR_ACCESS_DENIED;
  }
  if (strcmp(action, "s3:DeleteObject") == 0 && version_id && *version_id &&
      !buckets_s3_allowed(c, "s3:DeleteObjectVersion", bucket, object, true)) {
    return BUCKETS_ERR_ACCESS_DENIED;
  }
  if (buckets_s3_allowed(c, action, bucket, object, false)) return BUCKETS_ERR_NONE;
  if (strcmp(action, "s3:ListBucketVersions") == 0 && buckets_s3_allowed(c, "s3:ListBucket", bucket, object, false)) {
    return BUCKETS_ERR_NONE;
  }
  return BUCKETS_ERR_ACCESS_DENIED;
}

bool buckets_s3_require(s3_ctx *c, const char *action, const char *bucket, const char *object, const char *version_id) {
  buckets_s3_error e = buckets_s3_authorize(c, action, bucket, object, version_id);
  if (e == BUCKETS_ERR_NONE) return true;
  buckets_s3_write_error(c, e);
  return false;
}
