/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Replication in the request path: the bucket replication configuration
 * (MinIO's bucket-replication-handlers.go), what writes carry for incoming
 * replication (putOpts / delOpts with X-Minio-Source-*), and marking new
 * versions for replication (mustReplicate in the object handlers). */
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>

#include "bucket/metasys.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "admin/admin.h"
#include "notify/event.h"
#include "s3/internal.h"
#include "s3/replicate.h"
#include "s3/xml.h"

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void set_meta(buckets_xl_kv **kv, size_t *n, const char *k, const char *v) {
  buckets_xl_kv_set(kv, n, k, v, strlen(v));
}

static void set_now(buckets_xl_kv **kv, size_t *n, const char *k) {
  int64_t ns = now_ns();
  char ts[BUCKETS_TIME_RFC3339_NANO_LEN + 1];
  buckets_time_rfc3339_nano(ns / 1000000000LL, (long)(ns % 1000000000LL), ts);
  set_meta(kv, n, k, ts);
}

static char *header(s3_ctx *c, const char *name) {
  buckets_str h = buckets_http_header_get(c->req, name);
  return h.p ? buckets_str_dup(h) : NULL;
}

bool buckets_s3_repl_request(s3_ctx *c) {
  return buckets_http_header_get(c->req, BUCKETS_H_SRC_REPL_REQUEST).p != NULL;
}

bool buckets_s3_repl_replica(s3_ctx *c) {
  buckets_str h = buckets_http_header_get(c->req, BUCKETS_H_REPL_STATUS);
  return h.p && buckets_str_eq_c(h, BUCKETS_RS_REPLICA);
}

/* Go's strings.TrimSpace */
static char *trim(char *s) {
  while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r' || *s == '\v' || *s == '\f') s++;
  size_t n = strlen(s);
  while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == '\v' ||
               s[n - 1] == '\f'))
    s[--n] = '\0';
  return s;
}

bool buckets_s3_repl_in_parse(s3_ctx *c, const char *object, bool put, buckets_s3_repl_in *ri) {
  memset(ri, 0, sizeof(*ri));
  if (buckets_http_header_get(c->req, BUCKETS_H_SRC_REPL_CHECK).p) {
    /* requests that only validate replication settings may not write */
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_PERMISSION_CHECK_ERROR);
    return false;
  }
  ri->request = buckets_s3_repl_request(c);
  ri->replica = buckets_s3_repl_replica(c);
  if (ri->replica && !buckets_s3_require(c, put ? "s3:ReplicateObject" : "s3:ReplicateDelete", c->bucket, object, NULL))
    return false;
  const char *vid = buckets_query_get(&c->q, "versionId");
  bool enabled = false, suspended = false;
  buckets_s3_versioning(c, object, &enabled, &suspended);
  if (put && vid && *vid) {
    char *v = trim(buckets_xstrdup(vid)), *vv = v;
    if (*v && strcmp(v, "null") != 0) {
      uint8_t id[16];
      if (!buckets_xl_version_id_parse(v, id)) {
        free(vv);
        buckets_s3_write_error(c, BUCKETS_ERR_INVALID_VERSION_ID);
        return false;
      }
      if (!enabled) {
        char msg[400];
        snprintf(msg, sizeof(msg), "VersionID specified %s, but versioning not enabled on bucket=%s", "", c->bucket);
        free(vv);
        buckets_s3_write_custom_error(c, 400, "InvalidArgument", msg);
        return false;
      }
    }
    snprintf(ri->version_id, sizeof(ri->version_id), "%s", v);
    ri->has_vid = *v != '\0';
    free(vv);
  }
  char *mt = header(c, BUCKETS_H_SRC_MTIME);
  if (mt) {
    char *m = trim(mt);
    long long s;
    long ns;
    if (*m) {
      if (!buckets_time_parse_rfc3339(m, &s, &ns)) {
        char msg[400];
        snprintf(msg, sizeof(msg), "Unable to parse %s, failed with parsing time \"%s\" as \"2006-01-02T15:04:05.999999999Z07:00\": cannot parse \"%s\" as \"2006\"",
                 put ? "X-Minio-Source-Mtime" : "X-Minio-Source-Mtime", m, m);
        free(mt);
        buckets_s3_write_custom_error(c, 400, "InvalidArgument", msg);
        return false;
      }
      ri->mtime_ns = (int64_t)s * 1000000000LL + ns;
    }
    free(mt);
  }
  char *et = header(c, BUCKETS_H_SRC_ETAG);
  if (et) {
    snprintf(ri->etag, sizeof(ri->etag), "%s", trim(et));
    free(et);
  }
  buckets_str dm = buckets_http_header_get(c->req, "X-Minio-Source-Deletemarker");
  if (dm.p) {
    char *d = trim(buckets_str_dup(dm)), *dd = d;
    if (strcmp(d, "true") == 0) ri->delete_marker = true;
    else if (*d && strcmp(d, "false") != 0) {
      free(dd);
      buckets_s3_write_custom_error(c, 400, "InvalidArgument",
                                    "Unable to parse x-minio-source-deletemarker, value should be either 'true' or 'false'");
      return false;
    }
    free(dd);
  }
  return true;
}

void buckets_s3_repl_in_meta(s3_ctx *c, const buckets_s3_repl_in *ri, buckets_xl_kv **meta, size_t *n) {
  if (!ri->replica) return;
  set_meta(meta, n, BUCKETS_META_REPLICA_STATUS, BUCKETS_RS_REPLICA);
  set_now(meta, n, BUCKETS_META_REPLICA_TS);
  set_meta(meta, n, BUCKETS_H_REPL_STATUS, BUCKETS_RS_REPLICA);
  (void)c;
}

void buckets_s3_repl_out_meta(s3_ctx *c, const char *object, buckets_xl_kv **meta, size_t *n, bool request,
                              buckets_repl_dsc *dsc) {
  buckets_repl_must(c->s, c->bucket, object, *meta, *n, *meta, *n, NULL, BUCKETS_REPL_OBJECT, request, dsc);
  if (!buckets_repl_dsc_any(dsc)) return;
  set_now(meta, n, BUCKETS_META_REPL_TS);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_repl_dsc_pending(dsc, &p);
  buckets_buf_append_char(&p, '\0');
  set_meta(meta, n, BUCKETS_META_REPL_STATUS, p.data);
  buckets_buf_free(&p);
}

void buckets_s3_repl_meta_edit(s3_ctx *c, buckets_xl_kv **user, size_t *nuser, buckets_xl_kv **sys, size_t *nsys,
                               const char *tags, buckets_repl_dsc *dsc) {
  buckets_repl_dsc_free(dsc);
  buckets_repl_must(c->s, c->bucket, c->object, *user, *nuser, *sys, *nsys, tags, BUCKETS_REPL_METADATA, false, dsc);
  if (!buckets_repl_dsc_any(dsc)) return;
  set_now(sys, nsys, BUCKETS_META_REPL_TS);
  buckets_buf p = BUCKETS_BUF_INIT;
  buckets_repl_dsc_pending(dsc, &p);
  buckets_buf_append_char(&p, '\0');
  set_meta(sys, nsys, BUCKETS_META_REPL_STATUS, p.data);
  buckets_buf_free(&p);
}

/* ---- is the target this cluster? (isLocalHost) ---- */

static bool local_address(const struct sockaddr *sa) {
  struct ifaddrs *ifa = NULL;
  if (getifaddrs(&ifa) != 0) return false;
  bool found = false;
  for (struct ifaddrs *i = ifa; i && !found; i = i->ifa_next) {
    if (!i->ifa_addr || i->ifa_addr->sa_family != sa->sa_family) continue;
    if (sa->sa_family == AF_INET) {
      struct sockaddr_in a, b;
      memcpy(&a, sa, sizeof(a));
      memcpy(&b, i->ifa_addr, sizeof(b));
      found = a.sin_addr.s_addr == b.sin_addr.s_addr;
    } else if (sa->sa_family == AF_INET6) {
      struct sockaddr_in6 a, b;
      memcpy(&a, sa, sizeof(a));
      memcpy(&b, i->ifa_addr, sizeof(b));
      found = memcmp(&a.sin6_addr, &b.sin6_addr, 16) == 0;
    }
  }
  freeifaddrs(ifa);
  return found;
}

bool buckets_s3_is_local_endpoint(buckets_s3_server *s, const char *endpoint) {
  char host[256] = "", port[16] = "";
  const char *colon = strrchr(endpoint, ':');
  if (endpoint[0] == '[') {
    const char *rb = strchr(endpoint, ']');
    if (!rb) return false;
    snprintf(host, sizeof(host), "%.*s", (int)(rb - endpoint - 1), endpoint + 1);
    if (rb[1] == ':') snprintf(port, sizeof(port), "%s", rb + 2);
  } else if (colon) {
    snprintf(host, sizeof(host), "%.*s", (int)(colon - endpoint), endpoint);
    snprintf(port, sizeof(port), "%s", colon + 1);
  } else {
    snprintf(host, sizeof(host), "%s", endpoint);
  }
  /* our port, from our own endpoint URL */
  const char *mine = strrchr(s->endpoint, ':');
  const char *myport = mine && strchr(mine, '/') == NULL ? mine + 1 : "80";
  if (!*port) snprintf(port, sizeof(port), "%s", strncmp(s->endpoint, "https", 5) == 0 ? "443" : "80");
  if (strcmp(port, myport) != 0) return false;
  struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res = NULL;
  if (getaddrinfo(host, NULL, &hints, &res) != 0) return false;
  bool local = false;
  for (struct addrinfo *a = res; a && !local; a = a->ai_next) local = local_address(a->ai_addr);
  freeaddrinfo(res);
  return local;
}

/* ---- PutBucketReplicationConfig ---- */

static void write_with_err(s3_ctx *c, buckets_s3_error e, const char *err) {
  const buckets_s3_error_info *info = buckets_s3_error_get(e);
  char msg[1024];
  if (err && *err) snprintf(msg, sizeof(msg), "%s (%s)", info->message, err);
  else snprintf(msg, sizeof(msg), "%s", info->message);
  buckets_s3_write_error_msg(c, e, msg);
}

/* validateReplicationDestination with CheckRemoteBucket. */
static bool validate_destination(s3_ctx *c, const buckets_replication *cfg, bool *same_target) {
  *same_target = false;
  size_t n = cfg->n;
  const char **arns = buckets_xcalloc(n + 1, sizeof(*arns));
  size_t na = 0;
  if (*cfg->role) arns[na++] = cfg->role;
  else
    for (size_t i = 0; i < n; i++) arns[na++] = cfg->rules[i].dest_arn;
  bool ok = true;
  for (size_t i = 0; i < na && ok; i++) {
    buckets_arn a;
    if (!buckets_arn_parse(arns[i], &a)) {
      char e[512];
      snprintf(e, sizeof(e), "invalid ARN %s", arns[i]);
      write_with_err(c, BUCKETS_ERR_BUCKET_REMOTE_ARN_INVALID, e);
      ok = false;
      break;
    }
    if (strcmp(a.type, "replication") != 0) {
      char m[512];
      snprintf(m, sizeof(m), "%s", buckets_s3_error_get(BUCKETS_ERR_BUCKET_REMOTE_ARN_TYPE_INVALID)->message);
      buckets_s3_write_error_msg(c, BUCKETS_ERR_BUCKET_REMOTE_ARN_TYPE_INVALID, m);
      ok = false;
      break;
    }
    buckets_repl_target *t = buckets_repl_target_get(c->s->repl, c->bucket, arns[i]);
    if (!t) {
      buckets_s3_write_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
      ok = false;
      break;
    }
    buckets_s3c *cl = buckets_repl_target_client(t);
    buckets_s3c_result res;
    bool found = buckets_s3c_do(cl, "HEAD", a.bucket, NULL, NULL, NULL, 0, NULL, 0, &res);
    if (!found) {
      char e[700];
      if (res.status == 404) snprintf(e, sizeof(e), "Remote target not found: %s", a.bucket);
      else snprintf(e, sizeof(e), "%s", buckets_s3c_error(&res));
      write_with_err(c, BUCKETS_ERR_REMOTE_DESTINATION_NOT_FOUND_ERROR, e);
      ok = false;
    }
    buckets_s3c_result_free(&res);
    if (ok) {
      buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
      bool locked = st->lock_enabled;
      buckets_bucket_state_release(st);
      if (locked) {
        bool lok = buckets_s3c_do(cl, "GET", a.bucket, NULL, "object-lock=", NULL, 0, NULL, 0, &res);
        bool enabled = lok && res.body.data && strstr(res.body.data, "<ObjectLockEnabled>Enabled</ObjectLockEnabled>");
        if (!enabled) {
          write_with_err(c, BUCKETS_ERR_REPLICATION_DESTINATION_MISSING_LOCK, lok ? NULL : buckets_s3c_error(&res));
          ok = false;
        }
        buckets_s3c_result_free(&res);
      }
    }
    if (ok && buckets_s3_is_local_endpoint(c->s, buckets_s3c_endpoint(cl))) *same_target = true;
    buckets_repl_target_put(t);
  }
  if (ok && na == 0) {
    buckets_s3_write_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    ok = false;
  }
  free(arns);
  return ok;
}

void buckets_s3_put_bucket_replication(s3_ctx *c) {
  bool enabled, suspended;
  buckets_s3_versioning(c, "", &enabled, &suspended);
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool versioned = st->versioning.status == BUCKETS_VERSIONING_ENABLED;
  buckets_bucket_state_release(st);
  if (!versioned) {
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_NEEDS_VERSIONING_ERROR);
    return;
  }
  buckets_s3_error derr = buckets_s3_read_doc(c);
  if (derr) {
    buckets_s3_write_error(c, derr);
    return;
  }
  buckets_replication cfg;
  char err[512];
  if (!buckets_replication_parse(c->doc.data ? c->doc.data : "", c->doc.len, &cfg, err, sizeof(err))) {
    buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, err);
    return;
  }
  bool same = false;
  if (!validate_destination(c, &cfg, &same)) {
    buckets_replication_free(&cfg);
    return;
  }
  if (!buckets_replication_validate(&cfg, c->bucket, same, err, sizeof(err))) {
    buckets_replication_free(&cfg);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, err);
    return;
  }
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_replication_xml(&cfg, &x);
  buckets_replication_free(&cfg);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_REPLICATION, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

void buckets_s3_get_bucket_replication(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (!st->has_replication) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_CONFIGURATION_NOT_FOUND_ERROR);
    return;
  }
  buckets_replication_xml(&st->replication, &c->resp->body);
  buckets_bucket_state_release(st);
  buckets_s3_write_xml(c, 200);
}

void buckets_s3_delete_bucket_replication(s3_ctx *c) {
  if (!buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_REPLICATION, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  /* ListBucketTargets fails for a bucket that never had targets */
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool had = st->meta.config[BUCKETS_BCFG_TARGETS].len > 0;
  buckets_bucket_state_release(st);
  if (!had) {
    buckets_s3_write_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    return;
  }
  if (!buckets_metasys_update_targets(c->s->meta, c->bucket, NULL, 0)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  c->resp->status = 200;
}

/* ---- ResetBucketReplicationStart / Status ---- */

static void bad_request(s3_ctx *c, const char *detail) {
  char msg[1200];
  snprintf(msg, sizeof(msg), "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_BAD_REQUEST)->message, detail);
  /* writeErrorResponseJSON */
  buckets_admin_json_error(c, 400, buckets_s3_error_get(BUCKETS_ERR_BAD_REQUEST)->code, msg, NULL, NULL);
}

void buckets_s3_reset_bucket_replication_start(s3_ctx *c) {
  const char *dur = buckets_query_get(&c->q, "older-than");
  const char *arn = buckets_query_get(&c->q, "arn");
  const char *reset_id = buckets_query_get(&c->q, "reset-id");
  char rid[BUCKETS_UUID_STR_LEN + 1];
  if (!reset_id || !*reset_id) {
    buckets_uuid_v4(rid);
    reset_id = rid;
  }
  if (!arn) arn = "";
  int64_t days_ns = 0;
  if (dur && *dur && !buckets_go_duration_parse(dur, &days_ns)) {
    char e[300], msg[600];
    buckets_go_duration_error(dur, e, sizeof(e));
    snprintf(msg, sizeof(msg), "invalid query parameter older-than %s for %s : %s", dur, c->bucket, e);
    buckets_s3_write_custom_error(c, 400, "InvalidArgument", msg);
    return;
  }
  /* UTCNow().AddDate(0, 0, -days) */
  int64_t days = days_ns / (24LL * 3600 * 1000000000LL);
  int64_t before = now_ns() - days * 24LL * 3600 * 1000000000LL;
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (!st->has_replication) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_CONFIGURATION_NOT_FOUND_ERROR);
    return;
  }
  bool has_arn, enabled;
  buckets_replication_has_existing(&st->replication, arn, &has_arn, &enabled);
  if (!has_arn) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR);
    return;
  }
  if (!enabled) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_NO_EXISTING_OBJECTS);
    return;
  }
  buckets_repl_obj o = {.op = BUCKETS_REPL_RESYNC, .target_arn = arn};
  char **arns = NULL;
  size_t na = buckets_replication_target_arns(&st->replication, &o, &arns);
  if (na == 0 || (na > 1 && !*arn)) {
    buckets_replication_arns_free(arns, na);
    buckets_bucket_state_release(st);
    char d[600];
    if (na == 0) snprintf(d, sizeof(d), "Remote target ARN %s missing or ineligible for replication resync", arn);
    else snprintf(d, sizeof(d), "ARN should be specified for replication reset");
    bad_request(c, d);
    return;
  }
  /* the target gets its reset ID and date */
  buckets_bucket_targets ts = {0};
  ts.t = buckets_xcalloc(st->targets.n + 1, sizeof(*ts.t));
  bool found = false;
  for (size_t i = 0; i < st->targets.n; i++) {
    buckets_bucket_target_copy(&ts.t[ts.n], &st->targets.t[i]);
    if (strcmp(ts.t[ts.n].arn, arns[0]) == 0) {
      found = true;
      free(ts.t[ts.n].reset_id);
      ts.t[ts.n].reset_id = buckets_xstrdup(reset_id);
      ts.t[ts.n].reset_before_sec = before / 1000000000LL;
      ts.t[ts.n].reset_before_nsec = (int32_t)(before % 1000000000LL);
    }
    ts.n++;
  }
  buckets_bucket_state_release(st);
  char tarn[512];
  snprintf(tarn, sizeof(tarn), "%s", arns[0]);
  buckets_replication_arns_free(arns, na);
  if (!found) {
    buckets_bucket_targets_free(&ts);
    buckets_admin_json_error(c, 404, buckets_s3_error_get(BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR)->code,
                             buckets_s3_error_get(BUCKETS_ERR_REMOTE_TARGET_NOT_FOUND_ERROR)->message, NULL, NULL);
    return;
  }
  buckets_buf j = BUCKETS_BUF_INIT;
  buckets_bucket_targets_json(&ts, &j);
  buckets_bucket_targets_free(&ts);
  bool ok = buckets_metasys_update_targets(c->s->meta, c->bucket, j.data, j.len);
  buckets_buf_free(&j);
  if (!ok) {
    buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
    return;
  }
  char err[600];
  if (buckets_repl_resync_start(c->s->repl, c->bucket, tarn, reset_id, before, err, sizeof(err)) != 0) {
    bad_request(c, err);
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_buf_append_c(b, "{\"target\":[{\"arn\":");
  buckets_json_go_string(b, tarn, strlen(tarn));
  buckets_buf_append_c(b, ",\"resetid\":");
  buckets_json_go_string(b, reset_id, strlen(reset_id));
  buckets_buf_append_c(b, ",\"startTime\":\"0001-01-01T00:00:00Z\",\"endTime\":\"0001-01-01T00:00:00Z\","
                          "\"completedReplicationSize\":0,\"failedReplicationSize\":0,\"failedReplicationCount\":0,"
                          "\"replicationCount\":0}]}");
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

void buckets_s3_reset_bucket_replication_status(s3_ctx *c) {
  const char *arn = buckets_query_get(&c->q, "arn");
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool has = st->has_replication;
  buckets_bucket_state_release(st);
  if (!has) {
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_CONFIGURATION_NOT_FOUND_ERROR);
    return;
  }
  char err[300];
  if (!buckets_repl_resync_status(c->s->repl, c->bucket, arn, &c->resp->body, err, sizeof(err))) {
    char d[600];
    snprintf(d, sizeof(d), "replication resync status not available for %s (%s)", arn ? arn : "", err);
    char msg[800];
    snprintf(msg, sizeof(msg), "%s (%s)", buckets_s3_error_get(BUCKETS_ERR_BAD_REQUEST)->message, d);
    buckets_s3_write_error_msg(c, BUCKETS_ERR_BAD_REQUEST, msg);
    return;
  }
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}

/* ---- GetBucketReplicationMetrics / V2 ---- */

void buckets_s3_get_bucket_replication_metrics(s3_ctx *c, bool v2) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool has = st->has_replication;
  buckets_bucket_state_release(st);
  if (!has) {
    buckets_s3_write_error(c, BUCKETS_ERR_REPLICATION_CONFIGURATION_NOT_FOUND_ERROR);
    return;
  }
  /* the node's name: host:port of its endpoint */
  const char *ep = c->s->endpoint;
  const char *h = strstr(ep, "://");
  h = h ? h + 3 : ep;
  buckets_repl_stats_json(c->bucket, h, v2, &c->resp->body);
  buckets_http_resp_header(c->resp, "Content-Type", "application/json");
  c->resp->status = 200;
}
