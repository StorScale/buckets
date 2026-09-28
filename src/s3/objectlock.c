/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Object lock: bucket configuration, per-object retention and legal hold,
 * and their enforcement (MinIO's cmd/bucket-object-lock.go and the
 * retention / legal hold handlers of cmd/object-handlers.go). */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bucket/metasys.h"
#include "core/timefmt.h"
#include "s3/internal.h"
#include "s3/xml.h"

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static buckets_s3_error lock_api_error(buckets_lock_err e) {
  switch (e) {
    case BUCKETS_LOCK_OK: return BUCKETS_ERR_NONE;
    case BUCKETS_LOCK_INVALID_DATE: return BUCKETS_ERR_INVALID_RETENTION_DATE;
    case BUCKETS_LOCK_PAST_DATE: return BUCKETS_ERR_PAST_OBJECT_LOCK_RETAIN_DATE;
    case BUCKETS_LOCK_UNKNOWN_MODE: return BUCKETS_ERR_UNKNOWN_WORM_MODE_DIRECTIVE;
    case BUCKETS_LOCK_INVALID_HEADERS: return BUCKETS_ERR_OBJECT_LOCK_INVALID_HEADERS;
    default: return BUCKETS_ERR_MALFORMED_XML;
  }
}

/* The bucket's lock state: enabled, and its default retention. */
static bool bucket_lock(s3_ctx *c, buckets_lock_config *cfg) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool on = st->lock_enabled;
  *cfg = st->object_lock;
  buckets_bucket_state_release(st);
  return on;
}

static const char *header(s3_ctx *c, const char *name, char *buf, size_t cap) {
  buckets_str v = buckets_http_header_get(c->req, name);
  if (!v.p) return NULL;
  snprintf(buf, cap, "%.*s", (int)v.n, v.p);
  return buf;
}

static void iso8601(int64_t ns, char out[BUCKETS_TIME_ISO8601_LEN + 1]) { buckets_time_iso8601_ns(ns, out); }

buckets_s3_error buckets_s3_lock_put_meta(s3_ctx *c, const char *object, buckets_xl_kv **meta, size_t *nmeta) {
  char mode_b[64], date_b[128], hold_b[64];
  const char *mode_h = header(c, "X-Amz-Object-Lock-Mode", mode_b, sizeof(mode_b));
  const char *date_h = header(c, "X-Amz-Object-Lock-Retain-Until-Date", date_b, sizeof(date_b));
  const char *hold_h = header(c, "X-Amz-Object-Lock-Legal-Hold", hold_b, sizeof(hold_b));
  bool ret_req = mode_h || date_h, hold_req = hold_h != NULL;
  buckets_lock_config cfg;
  if (!bucket_lock(c, &cfg)) return ret_req || hold_req ? BUCKETS_ERR_INVALID_BUCKET_OBJECT_LOCK_CONFIGURATION : BUCKETS_ERR_NONE;
  buckets_s3_error ret_perm = buckets_s3_authorize(c, "s3:PutObjectRetention", c->bucket, object, NULL);
  buckets_s3_error hold_perm = buckets_s3_authorize(c, "s3:PutObjectLegalHold", c->bucket, object, NULL);
  const char *hold = NULL;
  if (hold_req) {
    if (strcasecmp(hold_h, "ON") == 0) hold = "ON";
    else if (strcasecmp(hold_h, "OFF") == 0) hold = "OFF";
    else return BUCKETS_ERR_UNKNOWN_WORM_MODE_DIRECTIVE;
    if (hold_perm) return hold_perm;
  }
  buckets_ret_mode mode = BUCKETS_RET_NONE;
  int64_t until = 0, now = now_ns();
  if (ret_req) {
    buckets_lock_err le = buckets_lock_parse_retention_headers(mode_h, date_h, now, &mode, &until);
    if (le) return lock_api_error(le);
    if (ret_perm) return ret_perm;
  } else {
    int64_t validity = buckets_lock_config_validity(&cfg, now / 1000000000LL);
    if (validity > 0) {
      if (ret_perm) return ret_perm;
      if (!hold_req) { /* inherit the bucket's default retention */
        mode = cfg.mode;
        until = now + validity * 1000000000LL;
      }
    }
  }
  if (mode != BUCKETS_RET_NONE) {
    const char *m = buckets_ret_mode_name(mode);
    char d[BUCKETS_TIME_ISO8601_LEN + 1];
    iso8601(until, d);
    buckets_xl_kv_set(meta, nmeta, BUCKETS_LOCK_MODE_META, m, strlen(m));
    buckets_xl_kv_set(meta, nmeta, BUCKETS_LOCK_UNTIL_META, d, strlen(d));
  }
  if (hold) buckets_xl_kv_set(meta, nmeta, BUCKETS_LOCK_HOLD_META, hold, strlen(hold));
  return BUCKETS_ERR_NONE;
}

/* GetObjectRetentionMeta */
static buckets_ret_mode meta_retention(const buckets_object_info *oi, int64_t *until_ns) {
  *until_ns = 0;
  const char *m = buckets_object_meta(oi, BUCKETS_LOCK_MODE_META);
  if (!m) m = buckets_object_meta(oi, "X-Amz-Object-Lock-Mode");
  buckets_ret_mode mode = buckets_ret_mode_parse(m);
  const char *u = buckets_object_meta(oi, BUCKETS_LOCK_UNTIL_META);
  if (!u) u = buckets_object_meta(oi, "X-Amz-Object-Lock-Retain-Until-Date");
  long long sec;
  long nsec;
  if (mode != BUCKETS_RET_NONE && u && buckets_time_parse_rfc3339(u, &sec, &nsec)) *until_ns = sec * 1000000000LL + nsec;
  return mode;
}

static bool meta_hold_on(const buckets_object_info *oi) {
  const char *h = buckets_object_meta(oi, BUCKETS_LOCK_HOLD_META);
  if (!h) h = buckets_object_meta(oi, "X-Amz-Object-Lock-Legal-Hold");
  return h && strcasecmp(h, "ON") == 0;
}

static bool bypass_requested(s3_ctx *c) {
  buckets_str b = buckets_http_header_get(c->req, "X-Amz-Bypass-Governance-Retention");
  return b.p && buckets_str_ieq_c(b, "true");
}

buckets_s3_error buckets_s3_lock_check_delete(s3_ctx *c, const char *object, const char *version_id) {
  if (!version_id || !*version_id) return BUCKETS_ERR_NONE;
  buckets_object_info oi;
  if (buckets_obj_stat(c->s->layer, c->bucket, object, version_id, &oi) != BUCKETS_OBJ_OK) return BUCKETS_ERR_NONE;
  buckets_s3_error e = BUCKETS_ERR_NONE;
  int64_t until;
  buckets_ret_mode mode = meta_retention(&oi, &until);
  if (oi.delete_marker) {
    e = BUCKETS_ERR_NONE;
  } else if (meta_hold_on(&oi)) {
    e = BUCKETS_ERR_OBJECT_LOCKED;
  } else if (mode == BUCKETS_RET_COMPLIANCE) {
    if (until >= now_ns()) e = BUCKETS_ERR_OBJECT_LOCKED;
  } else if (mode == BUCKETS_RET_GOVERNANCE) {
    if (!bypass_requested(c)) {
      if (until >= now_ns()) e = BUCKETS_ERR_OBJECT_LOCKED;
    } else if (buckets_s3_authorize(c, "s3:BypassGovernanceRetention", c->bucket, object, NULL)) {
      e = BUCKETS_ERR_ACCESS_DENIED;
    }
  }
  buckets_object_info_free(&oi);
  return e;
}

void buckets_s3_lock_filter_meta(s3_ctx *c, buckets_object_info *oi) {
  bool ret_ok = !buckets_s3_authorize(c, "s3:GetObjectRetention", c->bucket, c->object, NULL);
  bool hold_ok = !buckets_s3_authorize(c, "s3:GetObjectLegalHold", c->bucket, c->object, NULL);
  int64_t until;
  bool ret_valid = meta_retention(oi, &until) != BUCKETS_RET_NONE;
  const char *h = buckets_object_meta(oi, BUCKETS_LOCK_HOLD_META);
  bool hold_valid = h && (strcasecmp(h, "ON") == 0 || strcasecmp(h, "OFF") == 0);
  size_t w = 0;
  for (size_t i = 0; i < oi->nmeta; i++) {
    const char *k = oi->meta[i].key;
    bool drop = (strcasecmp(k, BUCKETS_LOCK_HOLD_META) == 0 && (!hold_valid || !hold_ok)) ||
                ((strcasecmp(k, BUCKETS_LOCK_MODE_META) == 0 || strcasecmp(k, BUCKETS_LOCK_UNTIL_META) == 0) &&
                 (!ret_valid || !ret_ok));
    if (drop) {
      free(oi->meta[i].key);
      free(oi->meta[i].value);
    } else {
      oi->meta[w++] = oi->meta[i];
    }
  }
  oi->nmeta = w;
}

/* ---- retention and legal hold ---------------------------------------------------- */

typedef struct {
  s3_ctx *c;
  buckets_ret_mode mode;
  int64_t until;
  bool hold, is_hold;
  buckets_s3_error err;
} lock_edit;

/* isPutRetentionAllowed */
static buckets_s3_error put_retention_allowed(s3_ctx *c, int64_t until, buckets_ret_mode mode, bool bypass) {
  int64_t now = now_ns();
  double hours = fabs((double)(until - now) / 3.6e12);
  int days = (int)ceil(hours / 24);
  char date[64] = "0001-01-01T00:00:00Z", dbuf[32];
  if (until) {
    time_t t = (time_t)(until / 1000000000LL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%SZ", &tm);
  }
  buckets_s3_cond_override(c, "object-lock-mode", buckets_ret_mode_name(mode));
  buckets_s3_cond_override(c, "object-lock-retain-until-date", date);
  if (days > 0) {
    snprintf(dbuf, sizeof(dbuf), "%d", days);
    buckets_s3_cond_override(c, "object-lock-remaining-retention-days", dbuf);
  }
  if (mode == BUCKETS_RET_GOVERNANCE && bypass)
    bypass = buckets_s3_allowed(c, "s3:BypassGovernanceRetention", c->bucket, c->object, false);
  bool ret = buckets_s3_allowed(c, "s3:PutObjectRetention", c->bucket, c->object, false);
  return bypass || ret ? BUCKETS_ERR_NONE : BUCKETS_ERR_ACCESS_DENIED;
}

/* enforceRetentionBypassForPut */
static buckets_s3_error enforce_put_retention(s3_ctx *c, const buckets_object_info *oi, buckets_ret_mode mode,
                                              int64_t until) {
  bool bypass = bypass_requested(c);
  int64_t cur_until;
  buckets_ret_mode cur = meta_retention(oi, &cur_until);
  if (cur != BUCKETS_RET_NONE) {
    if (cur_until < now_ns()) {
      return put_retention_allowed(c, until, mode, bypass) == BUCKETS_ERR_ACCESS_DENIED ? BUCKETS_ERR_ACCESS_DENIED
                                                                                       : BUCKETS_ERR_NONE;
    }
    if (cur == BUCKETS_RET_GOVERNANCE) {
      buckets_s3_error perm = put_retention_allowed(c, until, mode, bypass);
      if (!bypass && (mode != BUCKETS_RET_GOVERNANCE || until < cur_until)) return BUCKETS_ERR_OBJECT_LOCKED;
      return perm;
    }
    if (mode != BUCKETS_RET_COMPLIANCE || until < cur_until) return BUCKETS_ERR_OBJECT_LOCKED;
    return put_retention_allowed(c, until, mode, false);
  }
  return put_retention_allowed(c, until, mode, bypass);
}

static buckets_obj_err edit_lock(void *ud, const buckets_object_info *cur, buckets_xl_kv **user, size_t *nuser,
                                 buckets_xl_kv **sys, size_t *nsys) {
  lock_edit *e = ud;
  char ts[64];
  buckets_time_rfc3339_nano(now_ns() / 1000000000LL, (long)(now_ns() % 1000000000LL), ts);
  if (e->is_hold) {
    const char *v = e->hold ? "ON" : "OFF";
    buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_HOLD_META, v, strlen(v));
    buckets_xl_kv_set(sys, nsys, BUCKETS_LOCK_HOLD_TS_META, ts, strlen(ts));
    return BUCKETS_OBJ_OK;
  }
  if ((e->err = enforce_put_retention(e->c, cur, e->mode, e->until)) != BUCKETS_ERR_NONE) return BUCKETS_OBJ_ERR_READER;
  if (e->mode != BUCKETS_RET_NONE) {
    const char *m = buckets_ret_mode_name(e->mode);
    char d[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(e->until, d);
    buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_MODE_META, m, strlen(m));
    buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_UNTIL_META, d, strlen(d));
  } else {
    buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_MODE_META, "", 0);
    buckets_xl_kv_set(user, nuser, BUCKETS_LOCK_UNTIL_META, "", 0);
  }
  buckets_xl_kv_set(sys, nsys, BUCKETS_LOCK_RET_TS_META, ts, strlen(ts));
  return BUCKETS_OBJ_OK;
}

static void write_malformed(s3_ctx *c, const char *detail) {
  buckets_s3_write_error_msg(c, BUCKETS_ERR_MALFORMED_XML, detail);
}

static bool lock_request_prologue(s3_ctx *c) {
  buckets_s3_error e = buckets_s3_read_checked_doc(c);
  if (e) {
    buckets_s3_write_error(c, e);
    return false;
  }
  buckets_lock_config cfg;
  if (!bucket_lock(c, &cfg)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_OBJECT_LOCK_CONFIGURATION);
    return false;
  }
  return true;
}

static void apply_edit(s3_ctx *c, lock_edit *e) {
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_object_info oi;
  buckets_obj_err err = buckets_obj_update_meta(c->s->layer, c->bucket, c->object, version, edit_lock, e, &oi);
  if (err == BUCKETS_OBJ_ERR_READER && e->err) {
    buckets_s3_write_error(c, e->err);
    return;
  }
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return;
  }
  buckets_object_info_free(&oi);
  c->resp->status = 200;
}

void buckets_s3_put_object_retention(s3_ctx *c) {
  if (!lock_request_prologue(c)) return;
  lock_edit e = {.c = c};
  char err[256];
  if (buckets_lock_parse_retention(c->doc.data ? c->doc.data : "", c->doc.len, now_ns(), &e.mode, &e.until, err,
                                   sizeof(err))) {
    write_malformed(c, err);
    return;
  }
  apply_edit(c, &e);
}

void buckets_s3_put_object_legal_hold(s3_ctx *c) {
  if (!lock_request_prologue(c)) return;
  lock_edit e = {.c = c, .is_hold = true};
  char err[256];
  if (buckets_lock_parse_legal_hold(c->doc.data ? c->doc.data : "", c->doc.len, &e.hold, err, sizeof(err))) {
    write_malformed(c, err);
    return;
  }
  apply_edit(c, &e);
}

static bool get_lock_object(s3_ctx *c, buckets_object_info *oi) {
  buckets_lock_config cfg;
  if (!bucket_lock(c, &cfg)) {
    buckets_s3_write_error(c, BUCKETS_ERR_INVALID_BUCKET_OBJECT_LOCK_CONFIGURATION);
    return false;
  }
  const char *version = buckets_query_get(&c->q, "versionId");
  buckets_obj_err err = buckets_obj_stat(c->s->layer, c->bucket, c->object, version, oi);
  if (!err && oi->delete_marker) {
    buckets_object_info_free(oi);
    err = version && *version ? BUCKETS_OBJ_ERR_METHOD_NOT_ALLOWED : BUCKETS_OBJ_ERR_NO_SUCH_KEY;
  }
  if (err) {
    buckets_s3_write_error(c, buckets_s3_obj_error(err));
    return false;
  }
  return true;
}

void buckets_s3_get_object_retention(s3_ctx *c) {
  buckets_object_info oi;
  if (!get_lock_object(c, &oi)) return;
  int64_t until;
  buckets_ret_mode mode = meta_retention(&oi, &until);
  buckets_object_info_free(&oi);
  if (mode == BUCKETS_RET_NONE) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION);
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "Retention", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Mode", buckets_ret_mode_name(mode));
  if (until) {
    char d[BUCKETS_TIME_ISO8601_LEN + 1];
    buckets_time_iso8601_ns(until, d);
    buckets_xml_elem(b, "RetainUntilDate", d);
  }
  buckets_xml_close(b, "Retention");
  buckets_s3_write_xml(c, 200);
}

void buckets_s3_get_object_legal_hold(s3_ctx *c) {
  buckets_object_info oi;
  if (!get_lock_object(c, &oi)) return;
  const char *h = buckets_object_meta(&oi, BUCKETS_LOCK_HOLD_META);
  char status[8] = "";
  if (h && (strcasecmp(h, "ON") == 0 || strcasecmp(h, "OFF") == 0)) snprintf(status, sizeof(status), "%s", h);
  for (char *p = status; *p; p++) *p = (char)(*p >= 'a' && *p <= 'z' ? *p - 32 : *p);
  buckets_object_info_free(&oi);
  if (!*status) {
    buckets_s3_write_error(c, BUCKETS_ERR_NO_SUCH_OBJECT_LOCK_CONFIGURATION);
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_xml_open_ns(b, "LegalHold", BUCKETS_S3_XMLNS);
  buckets_xml_elem(b, "Status", status);
  buckets_xml_close(b, "LegalHold");
  buckets_s3_write_xml(c, 200);
}

/* ---- bucket configuration ---------------------------------------------------------- */

void buckets_s3_put_bucket_object_lock(s3_ctx *c) {
  if (c->req->body_len > 4096) {
    buckets_s3_write_error(c, BUCKETS_ERR_ENTITY_TOO_LARGE);
    return;
  }
  buckets_s3_error e = buckets_s3_read_doc(c);
  if (e) {
    buckets_s3_write_error(c, e);
    return;
  }
  buckets_lock_config cfg;
  char err[256];
  if (!buckets_lock_config_parse(c->doc.data ? c->doc.data : "", c->doc.len, &cfg, err, sizeof(err))) {
    buckets_s3_write_error_msg(c, BUCKETS_ERR_INVALID_ARGUMENT, err);
    return;
  }
  /* Only buckets created with object lock may change it. */
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  bool has = st->meta.config[BUCKETS_BCFG_OBJECT_LOCK].len > 0;
  buckets_bucket_state_release(st);
  if (!has) {
    buckets_s3_write_error(c, BUCKETS_ERR_OBJECT_LOCK_CONFIGURATION_NOT_ALLOWED);
    return;
  }
  buckets_buf x = BUCKETS_BUF_INIT;
  buckets_lock_config_xml(&cfg, &x);
  bool ok = buckets_metasys_update(c->s->meta, c->bucket, BUCKETS_BCFG_OBJECT_LOCK, x.data, x.len);
  buckets_buf_free(&x);
  if (!ok) buckets_s3_write_error(c, BUCKETS_ERR_INTERNAL_ERROR);
  else c->resp->status = 200;
}

void buckets_s3_get_bucket_object_lock(s3_ctx *c) {
  buckets_bucket_state *st = buckets_metasys_get(c->s->meta, c->bucket);
  if (!st->meta.config[BUCKETS_BCFG_OBJECT_LOCK].len) {
    buckets_bucket_state_release(st);
    buckets_s3_write_error(c, BUCKETS_ERR_OBJECT_LOCK_CONFIGURATION_NOT_FOUND);
    return;
  }
  buckets_buf *b = &c->resp->body;
  buckets_xml_header(b);
  buckets_lock_config_xml(&st->object_lock, b);
  buckets_bucket_state_release(st);
  buckets_s3_write_xml(c, 200);
}
