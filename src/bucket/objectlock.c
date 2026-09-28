/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/objectlock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "core/common.h"
#include "core/timefmt.h"
#include "s3/xml.h"

#define MAX_RETENTION_DAYS 36500
#define MAX_RETENTION_YEARS 100

const char *buckets_ret_mode_name(buckets_ret_mode m) {
  return m == BUCKETS_RET_GOVERNANCE ? "GOVERNANCE" : m == BUCKETS_RET_COMPLIANCE ? "COMPLIANCE" : "";
}

buckets_ret_mode buckets_ret_mode_parse(const char *s) {
  if (!s) return BUCKETS_RET_NONE;
  if (strcasecmp(s, "GOVERNANCE") == 0) return BUCKETS_RET_GOVERNANCE;
  if (strcasecmp(s, "COMPLIANCE") == 0) return BUCKETS_RET_COMPLIANCE;
  return BUCKETS_RET_NONE;
}

const char *buckets_lock_strerror(buckets_lock_err e) {
  switch (e) {
    case BUCKETS_LOCK_MALFORMED_XML:
      return "the XML you provided was not well-formed or did not validate against our published schema";
    case BUCKETS_LOCK_INVALID_DATE: return "date must be provided in ISO 8601 format";
    case BUCKETS_LOCK_PAST_DATE: return "the retain until date must be in the future";
    case BUCKETS_LOCK_UNKNOWN_MODE: return "unknown WORM mode directive";
    case BUCKETS_LOCK_INVALID_HEADERS:
      return "x-amz-object-lock-retain-until-date and x-amz-object-lock-mode must both be supplied";
    default: return "";
  }
}

static bool text_of(const buckets_xml_doc *d, size_t node, buckets_buf *out) {
  buckets_buf_reset(out);
  buckets_buf_append_c(out, "");
  return buckets_xml_unescape(d->nodes[node].text, out);
}

static bool parse_uint(const char *s, uint64_t *out) {
  if (!*s) return false;
  char *end;
  unsigned long long v = strtoull(s, &end, 10);
  if (*end || *s == '-' || *s == '+') return false;
  *out = v;
  return true;
}

bool buckets_lock_config_parse(const char *xml, size_t len, buckets_lock_config *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d) || !buckets_str_eq_c(d.nodes[0].name, "ObjectLockConfiguration")) {
    if (d.nodes) buckets_xml_doc_free(&d);
    snprintf(err, errlen, "%s", buckets_lock_strerror(BUCKETS_LOCK_MALFORMED_XML));
    return false;
  }
  buckets_xml_root_xmlns((buckets_str){xml, len}, out->xmlns, sizeof(out->xmlns));
  buckets_buf t = BUCKETS_BUF_INIT;
  bool ok = true;
  size_t en = buckets_xml_child(&d, 0, "ObjectLockEnabled");
  if (!en || !text_of(&d, en, &t) || strcmp(t.data, "Enabled") != 0) {
    snprintf(err, errlen, "only 'Enabled' value is allowed to ObjectLockEnabled element");
    ok = false;
  }
  out->enabled = ok;
  size_t rule = ok ? buckets_xml_child(&d, 0, "Rule") : 0;
  size_t dr = rule ? buckets_xml_child(&d, rule, "DefaultRetention") : 0;
  if (ok && dr) {
    size_t mn = buckets_xml_child(&d, dr, "Mode"), dn = buckets_xml_child(&d, dr, "Days"),
           yn = buckets_xml_child(&d, dr, "Years");
    char mode[32] = "";
    if (mn && text_of(&d, mn, &t)) snprintf(mode, sizeof(mode), "%s", t.data);
    if (strcmp(mode, "GOVERNANCE") == 0) out->mode = BUCKETS_RET_GOVERNANCE;
    else if (strcmp(mode, "COMPLIANCE") == 0) out->mode = BUCKETS_RET_COMPLIANCE;
    else {
      snprintf(err, errlen, "unknown retention mode %s", mode);
      ok = false;
    }
    if (ok && !dn && !yn) {
      snprintf(err, errlen, "either Days or Years must be specified");
      ok = false;
    } else if (ok && dn && yn) {
      snprintf(err, errlen, "either Days or Years must be specified, not both");
      ok = false;
    } else if (ok && dn) {
      if (!text_of(&d, dn, &t) || !parse_uint(t.data, &out->days)) {
        snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", t.data ? t.data : "");
        ok = false;
      } else if (out->days == 0) {
        snprintf(err, errlen, "Default retention period must be a positive integer value for 'Days'");
        ok = false;
      } else if (out->days > MAX_RETENTION_DAYS) {
        snprintf(err, errlen, "Default retention period too large for 'Days' %llu", (unsigned long long)out->days);
        ok = false;
      }
    } else if (ok) {
      if (!text_of(&d, yn, &t) || !parse_uint(t.data, &out->years)) {
        snprintf(err, errlen, "strconv.ParseUint: parsing \"%s\": invalid syntax", t.data ? t.data : "");
        ok = false;
      } else if (out->years == 0) {
        snprintf(err, errlen, "Default retention period must be a positive integer value for 'Years'");
        ok = false;
      } else if (out->years > MAX_RETENTION_YEARS) {
        snprintf(err, errlen, "Default retention period too large for 'Years' %llu", (unsigned long long)out->years);
        ok = false;
      }
    }
  }
  buckets_buf_free(&t);
  buckets_xml_doc_free(&d);
  return ok;
}

void buckets_lock_config_xml(const buckets_lock_config *c, buckets_buf *out) {
  if (*c->xmlns) buckets_xml_open_ns(out, "ObjectLockConfiguration", c->xmlns);
  else buckets_xml_open(out, "ObjectLockConfiguration");
  buckets_xml_elem(out, "ObjectLockEnabled", c->enabled ? "Enabled" : "");
  if (c->mode != BUCKETS_RET_NONE) {
    buckets_xml_open(out, "Rule");
    buckets_xml_open(out, "DefaultRetention");
    buckets_xml_elem(out, "Mode", buckets_ret_mode_name(c->mode));
    if (c->days) buckets_buf_appendf(out, "<Days>%llu</Days>", (unsigned long long)c->days);
    if (c->years) buckets_buf_appendf(out, "<Years>%llu</Years>", (unsigned long long)c->years);
    buckets_xml_close(out, "DefaultRetention");
    buckets_xml_close(out, "Rule");
  }
  buckets_xml_close(out, "ObjectLockConfiguration");
}

int64_t buckets_lock_config_validity(const buckets_lock_config *c, int64_t now_sec) {
  if (c->mode == BUCKETS_RET_NONE) return 0;
  if (c->days) return (int64_t)c->days * 86400;
  /* t.AddDate(years, 0, 0).Sub(t) */
  time_t t = (time_t)now_sec;
  struct tm tm;
  gmtime_r(&t, &tm);
  tm.tm_year += (int)c->years;
  return (int64_t)timegm(&tm) - now_sec;
}

/* amztime.ISO8601Parse: RFC 3339 (with or without fractions). */
static bool parse_iso8601(const char *s, int64_t *ns) {
  long long sec;
  long nsec;
  if (!buckets_time_parse_rfc3339(s, &sec, &nsec)) return false;
  *ns = sec * 1000000000LL + nsec;
  return true;
}

buckets_lock_err buckets_lock_parse_retention(const char *xml, size_t len, int64_t now_ns, buckets_ret_mode *mode,
                                              int64_t *until_ns, char *err, size_t errlen) {
  *mode = BUCKETS_RET_NONE;
  *until_ns = 0;
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d) || !buckets_str_eq_c(d.nodes[0].name, "Retention")) {
    if (d.nodes) buckets_xml_doc_free(&d);
    snprintf(err, errlen, "%s", buckets_lock_strerror(BUCKETS_LOCK_MALFORMED_XML));
    return BUCKETS_LOCK_MALFORMED_XML;
  }
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_lock_err e = BUCKETS_LOCK_OK;
  bool mode_set = false;
  size_t mn = buckets_xml_child(&d, 0, "Mode"), un = buckets_xml_child(&d, 0, "RetainUntilDate");
  if (mn && text_of(&d, mn, &t) && t.len) {
    mode_set = true;
    if (strcmp(t.data, "GOVERNANCE") == 0) *mode = BUCKETS_RET_GOVERNANCE;
    else if (strcmp(t.data, "COMPLIANCE") == 0) *mode = BUCKETS_RET_COMPLIANCE;
    else e = BUCKETS_LOCK_UNKNOWN_MODE;
  }
  if (!e && un && text_of(&d, un, &t) && !parse_iso8601(t.data, until_ns)) e = BUCKETS_LOCK_INVALID_DATE;
  if (!e && mode_set && !*until_ns) e = BUCKETS_LOCK_MALFORMED_XML;
  if (!e && !mode_set && *until_ns) e = BUCKETS_LOCK_MALFORMED_XML;
  if (!e && *until_ns && *until_ns < now_ns) e = BUCKETS_LOCK_PAST_DATE;
  buckets_buf_free(&t);
  buckets_xml_doc_free(&d);
  if (e) snprintf(err, errlen, "%s", buckets_lock_strerror(e));
  return e;
}

buckets_lock_err buckets_lock_parse_legal_hold(const char *xml, size_t len, bool *on, char *err, size_t errlen) {
  *on = false;
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d)) {
    if (d.nodes) buckets_xml_doc_free(&d);
    snprintf(err, errlen, "%s", buckets_lock_strerror(BUCKETS_LOCK_MALFORMED_XML));
    return BUCKETS_LOCK_MALFORMED_XML;
  }
  buckets_lock_err e = BUCKETS_LOCK_OK;
  if (!buckets_str_eq_c(d.nodes[0].name, "LegalHold") && !buckets_str_eq_c(d.nodes[0].name, "ObjectLockLegalHold")) {
    snprintf(err, errlen, "expected element type <LegalHold>/<ObjectLockLegalHold> but have <%.*s>",
             (int)d.nodes[0].name.n, d.nodes[0].name.p);
    e = BUCKETS_LOCK_MALFORMED_XML;
  }
  for (size_t c = d.nodes[0].first_child; !e && c; c = d.nodes[c].next_sibling) {
    if (!buckets_str_eq_c(d.nodes[c].name, "Status")) {
      snprintf(err, errlen, "expected element type <Status> but have <%.*s>", (int)d.nodes[c].name.n, d.nodes[c].name.p);
      e = BUCKETS_LOCK_MALFORMED_XML;
    }
  }
  if (!e) {
    size_t sn = buckets_xml_child(&d, 0, "Status");
    buckets_buf t = BUCKETS_BUF_INIT;
    if (sn && text_of(&d, sn, &t) && (strcmp(t.data, "ON") == 0 || strcmp(t.data, "OFF") == 0)) {
      *on = strcmp(t.data, "ON") == 0;
    } else {
      snprintf(err, errlen, "%s", buckets_lock_strerror(BUCKETS_LOCK_MALFORMED_XML));
      e = BUCKETS_LOCK_MALFORMED_XML;
    }
    buckets_buf_free(&t);
  }
  buckets_xml_doc_free(&d);
  return e;
}

buckets_lock_err buckets_lock_parse_retention_headers(const char *mode, const char *date, int64_t now_ns,
                                                      buckets_ret_mode *out_mode, int64_t *until_ns) {
  *out_mode = BUCKETS_RET_NONE;
  *until_ns = 0;
  if (!mode || !*mode || !date || !*date) return BUCKETS_LOCK_INVALID_HEADERS;
  *out_mode = buckets_ret_mode_parse(mode);
  if (*out_mode == BUCKETS_RET_NONE) return BUCKETS_LOCK_UNKNOWN_MODE;
  if (!parse_iso8601(date, until_ns)) return BUCKETS_LOCK_INVALID_DATE;
  if (*until_ns < now_ns) return BUCKETS_LOCK_PAST_DATE;
  return BUCKETS_LOCK_OK;
}
