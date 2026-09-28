/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/lifecycle.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bucket/tags.h"
#include "core/common.h"
#include "core/timefmt.h"
#include "core/uuid.h"
#include "s3/xml.h"

#define DAY_NS (86400LL * 1000000000LL)

/* ---- errors ------------------------------------------------------------------------- */

static bool fail(buckets_lc_error *e, buckets_lc_err code, const char *fmt, ...) BUCKETS_PRINTF(3, 4);
static bool fail(buckets_lc_error *e, buckets_lc_err code, const char *fmt, ...) {
  if (e->code) return false; /* the first error wins */
  e->code = code;
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
  va_end(ap);
  return false;
}

#define ERR_NOT_WELL_FORMED "The XML you provided was not well-formed or did not validate against our published schema"

/* ---- freeing ------------------------------------------------------------------------ */

static void tag_free(buckets_lc_tag *t) {
  free(t->key);
  free(t->value);
  t->key = t->value = NULL;
}

static void filter_free(buckets_lc_filter *f) {
  free(f->prefix);
  free(f->and_prefix);
  tag_free(&f->tag);
  for (size_t i = 0; i < f->nand_tags; i++) tag_free(&f->and_tags[i]);
  free(f->and_tags);
  memset(f, 0, sizeof(*f));
}

static void rule_free(buckets_lc_rule *r) {
  free(r->id);
  free(r->status);
  free(r->prefix);
  free(r->tr_class);
  free(r->nvt_class);
  filter_free(&r->filter);
  memset(r, 0, sizeof(*r));
}

void buckets_lifecycle_free(buckets_lifecycle *lc) {
  for (size_t i = 0; i < lc->n; i++) rule_free(&lc->rules[i]);
  free(lc->rules);
  memset(lc, 0, sizeof(*lc));
}

/* ---- Go decoding of leaf values ---------------------------------------------------- */

typedef struct {
  const buckets_xml_doc *d;
  buckets_lc_error *err;
} dec;

static char *text(dec *x, size_t node) {
  buckets_buf b = BUCKETS_BUF_INIT;
  if (!buckets_xml_unescape(x->d->nodes[node].text, &b)) {
    buckets_buf_free(&b);
    fail(x->err, BUCKETS_LC_ERR_MALFORMED, "invalid character entity");
    return NULL;
  }
  char *s = b.data ? b.data : buckets_xstrdup("");
  return s;
}

static void set_str(char **dst, char *s) {
  free(*dst);
  *dst = s;
}

/* encoding/xml into an int: empty text is 0, else strconv.ParseInt of the trimmed text. */
static bool dec_int(dec *x, size_t node, int64_t *out) {
  char *s = text(x, node);
  if (!s) return false;
  if (!*s) {
    free(s);
    *out = 0;
    return true;
  }
  char *p = s, *end;
  while (isspace((unsigned char)*p)) p++;
  size_t n = strlen(p);
  while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
  bool digits = n > 0;
  for (size_t i = (n && (p[0] == '+' || p[0] == '-')); i < n; i++) digits &= isdigit((unsigned char)p[i]) != 0;
  if (n == 1 && (p[0] == '+' || p[0] == '-')) digits = false;
  if (!digits) {
    fail(x->err, BUCKETS_LC_ERR_INTERNAL, "strconv.ParseInt: parsing \"%s\": invalid syntax", p);
    free(s);
    return false;
  }
  errno = 0;
  long long v = strtoll(p, &end, 10);
  if (errno == ERANGE) {
    fail(x->err, BUCKETS_LC_ERR_RANGE, "strconv.ParseInt: parsing \"%s\": value out of range", p);
    free(s);
    return false;
  }
  free(s);
  *out = v;
  return true;
}

/* strconv.ParseBool of the trimmed text (empty text is false). */
static bool dec_bool(dec *x, size_t node, bool *out) {
  char *s = text(x, node);
  if (!s) return false;
  char *p = s;
  while (isspace((unsigned char)*p)) p++;
  size_t n = strlen(p);
  while (n && isspace((unsigned char)p[n - 1])) p[--n] = '\0';
  static const char *const t[] = {"1", "t", "T", "TRUE", "true", "True"};
  static const char *const f[] = {"0", "f", "F", "FALSE", "false", "False"};
  bool ok = !*s;
  *out = false;
  for (size_t i = 0; i < 6 && !ok; i++) {
    if (strcmp(p, t[i]) == 0) ok = *out = true;
    else if (strcmp(p, f[i]) == 0) ok = true;
  }
  if (!ok) fail(x->err, BUCKETS_LC_ERR_INTERNAL, "strconv.ParseBool: parsing \"%s\": invalid syntax", p);
  free(s);
  return ok;
}

/* time.Parse(time.RFC3339): true with the instant and whether it is exactly
 * midnight in UTC ("Z"). */
static bool parse_rfc3339(const char *s, int64_t *unix_sec, bool *utc_midnight) {
  int Y, M, D, h, m, sec;
  if (strlen(s) < 20 || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d", &Y, &M, &D, &h, &m, &sec) != 6) return false;
  if (s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':') return false;
  const char *p = s + 19;
  long nsec = 0;
  if (*p == '.') {
    p++;
    int digits = 0;
    long scale = 100000000;
    while (isdigit((unsigned char)*p)) {
      if (digits < 9) nsec += (*p - '0') * scale;
      scale /= 10;
      digits++;
      p++;
    }
    if (!digits) return false;
  }
  int off = 0;
  bool z = false;
  if (*p == 'Z') {
    z = true;
    p++;
  } else if (*p == '+' || *p == '-') {
    int oh, om;
    if (sscanf(p + 1, "%2d:%2d", &oh, &om) != 2 || p[3] != ':') return false;
    off = (oh * 60 + om) * 60 * (*p == '-' ? -1 : 1);
    p += 6;
  } else {
    return false;
  }
  if (*p || M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || m > 59 || sec > 59) return false;
  struct tm tm = {.tm_year = Y - 1900, .tm_mon = M - 1, .tm_mday = D, .tm_hour = h, .tm_min = m, .tm_sec = sec};
  *unix_sec = (int64_t)timegm(&tm) - off;
  *utc_midnight = z && h == 0 && m == 0 && sec == 0 && nsec == 0;
  return true;
}

static bool dec_date(dec *x, size_t node, int64_t *out, const char *bad, const char *not_midnight) {
  char *s = text(x, node);
  if (!s) return false;
  int64_t t;
  bool midnight;
  bool ok = parse_rfc3339(s, &t, &midnight);
  free(s);
  if (!ok) return fail(x->err, BUCKETS_LC_ERR_INVALID, "%s", bad);
  if (!midnight) return fail(x->err, BUCKETS_LC_ERR_INVALID, "%s", not_midnight);
  *out = t;
  return true;
}

#define NAME_IS(d, n, s) buckets_str_eq_c((d)->nodes[n].name, s)

/* ---- elements ---------------------------------------------------------------------- */

static bool dec_tag(dec *x, size_t node, buckets_lc_tag *t) {
  bool have_key = false, have_value = false;
  tag_free(t);
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    char *s = text(x, c); /* DecodeElement(&s) comes first */
    if (!s) return false;
    if (NAME_IS(x->d, c, "Key")) {
      if (have_key) {
        free(s);
        return fail(x->err, BUCKETS_LC_ERR_INVALID, "duplicated XML Tag");
      }
      set_str(&t->key, s);
      have_key = true;
    } else if (NAME_IS(x->d, c, "Value")) {
      if (have_value) {
        free(s);
        return fail(x->err, BUCKETS_LC_ERR_INVALID, "duplicated XML Tag");
      }
      set_str(&t->value, s);
      have_value = true;
    } else {
      free(s);
      return fail(x->err, BUCKETS_LC_ERR_INVALID, "unknown XML Tag");
    }
  }
  if (!t->key) t->key = buckets_xstrdup("");
  if (!t->value) t->value = buckets_xstrdup("");
  return true;
}

static bool dec_and(dec *x, size_t node, buckets_lc_filter *f) {
  /* a fresh And (Filter.UnmarshalXML decodes into a new value) */
  free(f->and_prefix);
  f->and_prefix = NULL;
  f->and_prefix_set = false;
  f->and_size_gt = f->and_size_lt = 0;
  for (size_t i = 0; i < f->nand_tags; i++) tag_free(&f->and_tags[i]);
  free(f->and_tags);
  f->and_tags = NULL;
  f->nand_tags = 0;
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    if (NAME_IS(x->d, c, "Prefix")) {
      char *s = text(x, c);
      if (!s) return false;
      set_str(&f->and_prefix, s);
      f->and_prefix_set = true;
    } else if (NAME_IS(x->d, c, "ObjectSizeGreaterThan")) {
      if (!dec_int(x, c, &f->and_size_gt)) return false;
    } else if (NAME_IS(x->d, c, "ObjectSizeLessThan")) {
      if (!dec_int(x, c, &f->and_size_lt)) return false;
    } else if (NAME_IS(x->d, c, "Tag")) {
      f->and_tags = buckets_xrealloc(f->and_tags, (f->nand_tags + 1) * sizeof(*f->and_tags));
      memset(&f->and_tags[f->nand_tags], 0, sizeof(buckets_lc_tag));
      f->nand_tags++;
      if (!dec_tag(x, c, &f->and_tags[f->nand_tags - 1])) return false;
    }
  }
  return true;
}

static bool dec_filter(dec *x, size_t node, buckets_lc_filter *f) {
  f->set = true;
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    if (NAME_IS(x->d, c, "Prefix")) {
      char *s = text(x, c);
      if (!s) return false;
      set_str(&f->prefix, s);
      f->prefix_set = true;
    } else if (NAME_IS(x->d, c, "And")) {
      if (!dec_and(x, c, f)) return false;
    } else if (NAME_IS(x->d, c, "Tag")) {
      if (!dec_tag(x, c, &f->tag)) return false;
      f->tag_set = true;
    } else if (NAME_IS(x->d, c, "ObjectSizeLessThan")) {
      if (!dec_int(x, c, &f->size_lt)) return false;
    } else if (NAME_IS(x->d, c, "ObjectSizeGreaterThan")) {
      if (!dec_int(x, c, &f->size_gt)) return false;
    } else {
      return fail(x->err, BUCKETS_LC_ERR_INVALID, "unknown XML Tag");
    }
  }
  return true;
}

static bool dec_expiration(dec *x, size_t node, buckets_lc_rule *r) {
  /* the element replaces any earlier one */
  r->exp_days = r->exp_date = 0;
  r->exp_dm_set = r->exp_dm = r->exp_all_set = r->exp_all = false;
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    if (NAME_IS(x->d, c, "Days")) {
      if (!dec_int(x, c, &r->exp_days)) return false;
      if (r->exp_days <= 0) return fail(x->err, BUCKETS_LC_ERR_INVALID, "Days must be positive integer when used with Expiration");
    } else if (NAME_IS(x->d, c, "Date")) {
      if (!dec_date(x, c, &r->exp_date, "Date must be provided in ISO 8601 format", "'Date' must be at midnight GMT"))
        return false;
    } else if (NAME_IS(x->d, c, "ExpiredObjectDeleteMarker")) {
      if (!dec_bool(x, c, &r->exp_dm)) return false;
      r->exp_dm_set = true;
    } else if (NAME_IS(x->d, c, "ExpiredObjectAllVersions")) {
      if (!dec_bool(x, c, &r->exp_all)) return false;
      r->exp_all_set = true;
    }
  }
  r->exp_set = true;
  return true;
}

static bool dec_transition(dec *x, size_t node, buckets_lc_rule *r) {
  r->tr_days = r->tr_date = 0;
  free(r->tr_class);
  r->tr_class = NULL;
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    if (NAME_IS(x->d, c, "Days")) {
      if (!dec_int(x, c, &r->tr_days)) return false;
      if (r->tr_days < 0) return fail(x->err, BUCKETS_LC_ERR_INVALID, "Days must be 0 or greater when used with Transition");
    } else if (NAME_IS(x->d, c, "Date")) {
      if (!dec_date(x, c, &r->tr_date, "Date must be provided in ISO 8601 format", "'Date' must be at midnight GMT"))
        return false;
    } else if (NAME_IS(x->d, c, "StorageClass")) {
      char *s = text(x, c);
      if (!s) return false;
      set_str(&r->tr_class, s);
    }
  }
  r->tr_set = true;
  return true;
}

static bool dec_rule(dec *x, size_t node, buckets_lc_rule *r) {
  for (size_t c = x->d->nodes[node].first_child; c; c = x->d->nodes[c].next_sibling) {
    const buckets_xml_doc *d = x->d;
    if (NAME_IS(d, c, "ID") || NAME_IS(d, c, "Status")) {
      char *s = text(x, c);
      if (!s) return false;
      set_str(NAME_IS(d, c, "ID") ? &r->id : &r->status, s);
    } else if (NAME_IS(d, c, "Filter")) {
      if (!dec_filter(x, c, &r->filter)) return false;
    } else if (NAME_IS(d, c, "Prefix")) {
      char *s = text(x, c);
      if (!s) return false;
      set_str(&r->prefix, s);
      r->prefix_set = true;
    } else if (NAME_IS(d, c, "Expiration")) {
      if (!dec_expiration(x, c, r)) return false;
    } else if (NAME_IS(d, c, "Transition")) {
      if (!dec_transition(x, c, r)) return false;
    } else if (NAME_IS(d, c, "DelMarkerExpiration")) {
      int64_t days = 0;
      for (size_t k = d->nodes[c].first_child; k; k = d->nodes[k].next_sibling) {
        if (NAME_IS(d, k, "Days") && !dec_int(x, k, &days)) return false;
      }
      if (days <= 0) return fail(x->err, BUCKETS_LC_ERR_INVALID, "Days must be a positive integer with DelMarkerExpiration");
      r->dm_days = days;
    } else if (NAME_IS(d, c, "NoncurrentVersionExpiration")) {
      int64_t days = 0, newer = 0, max = 0;
      for (size_t k = d->nodes[c].first_child; k; k = d->nodes[k].next_sibling) {
        if (NAME_IS(d, k, "NoncurrentDays")) {
          if (!dec_int(x, k, &days)) return false;
          if (days <= 0) return fail(x->err, BUCKETS_LC_ERR_INVALID, "Days must be positive integer when used with Expiration");
        } else if (NAME_IS(d, k, "NewerNoncurrentVersions")) {
          if (!dec_int(x, k, &newer)) return false;
        } else if (NAME_IS(d, k, "MaxNoncurrentVersions")) {
          if (!dec_int(x, k, &max)) return false;
        }
      }
      if (max > 0) newer = max;
      r->nve_days = days;
      r->nve_newer = newer;
      r->nve_set = true;
    } else if (NAME_IS(d, c, "NoncurrentVersionTransition")) {
      int64_t days = 0;
      char *cls = NULL;
      for (size_t k = d->nodes[c].first_child; k; k = d->nodes[k].next_sibling) {
        if (NAME_IS(d, k, "NoncurrentDays")) {
          if (!dec_int(x, k, &days)) {
            free(cls);
            return false;
          }
          if (days < 0) {
            free(cls);
            return fail(x->err, BUCKETS_LC_ERR_INVALID, "Days must be 0 or greater when used with Transition");
          }
        } else if (NAME_IS(d, k, "StorageClass")) {
          char *s = text(x, k);
          if (!s) {
            free(cls);
            return false;
          }
          set_str(&cls, s);
        }
      }
      r->nvt_days = days;
      set_str(&r->nvt_class, cls);
      r->nvt_set = true;
    }
  }
  if (!r->status) r->status = buckets_xstrdup("");
  return true;
}

bool buckets_lifecycle_parse(const char *xml, size_t len, bool with_ids, buckets_lifecycle *out, buckets_lc_error *err) {
  memset(out, 0, sizeof(*out));
  memset(err, 0, sizeof(*err));
  buckets_xml_doc d = {0};
  if (!memchr(xml, '<', len)) {
    return fail(err, BUCKETS_LC_ERR_INTERNAL, "EOF"); /* io.EOF: no element at all */
  }
  if (!buckets_xml_parse((buckets_str){xml, len}, &d)) {
    if (d.nodes) buckets_xml_doc_free(&d);
    return fail(err, BUCKETS_LC_ERR_MALFORMED, "XML syntax error");
  }
  dec x = {&d, err};
  bool ok = true;
  if (!NAME_IS(&d, 0, "LifecycleConfiguration") && !NAME_IS(&d, 0, "BucketLifecycleConfiguration")) {
    ok = fail(err, BUCKETS_LC_ERR_INTERNAL,
              "expected element type <LifecycleConfiguration>/<BucketLifecycleConfiguration> but have <%.*s>",
              (int)BUCKETS_MIN(d.nodes[0].name.n, 64), d.nodes[0].name.p);
  }
  for (size_t c = d.nodes[0].first_child; ok && c; c = d.nodes[c].next_sibling) {
    if (NAME_IS(&d, c, "Rule")) {
      out->rules = buckets_xrealloc(out->rules, (out->n + 1) * sizeof(*out->rules));
      buckets_lc_rule *r = &out->rules[out->n++];
      memset(r, 0, sizeof(*r));
      ok = dec_rule(&x, c, r);
    } else if (NAME_IS(&d, c, "ExpiryUpdatedAt")) {
      char *s = text(&x, c);
      long long sec;
      long nsec;
      if (s && buckets_time_parse_rfc3339(s, &sec, &nsec)) out->expiry_updated_ns = sec * 1000000000LL + nsec;
      else if (s) ok = fail(err, BUCKETS_LC_ERR_INTERNAL, "parsing time \"%s\" as \"2006-01-02T15:04:05Z07:00\"", s);
      else ok = false;
      free(s);
    } else {
      ok = fail(err, BUCKETS_LC_ERR_INTERNAL, "expected element type <Rule> but have <%.*s>",
                (int)BUCKETS_MIN(d.nodes[c].name.n, 64), d.nodes[c].name.p);
    }
  }
  buckets_xml_doc_free(&d);
  if (!ok) {
    buckets_lifecycle_free(out);
    return false;
  }
  for (size_t i = 0; with_ids && i < out->n; i++) {
    if (!out->rules[i].id || !*out->rules[i].id) {
      char id[37];
      buckets_uuid_v4(id);
      set_str(&out->rules[i].id, buckets_xstrdup(id));
    }
  }
  for (size_t i = 0; i < out->n; i++) {
    if (!out->rules[i].id) out->rules[i].id = buckets_xstrdup("");
  }
  return true;
}

/* ---- validation ---------------------------------------------------------------------- */

static size_t runes(const char *s) {
  size_t n = 0;
  for (; *s; s++) n += ((unsigned char)*s & 0xC0) != 0x80;
  return n;
}

static bool tag_valid(const buckets_lc_tag *t, buckets_lc_error *e) {
  if (!*t->key || runes(t->key) > 128) return fail(e, BUCKETS_LC_ERR_INVALID, "The TagKey you have provided is invalid");
  if (runes(t->value) > 256) return fail(e, BUCKETS_LC_ERR_INVALID, "The TagValue you have provided is invalid");
  return true;
}

static bool and_empty(const buckets_lc_filter *f) {
  return !f->nand_tags && !f->and_prefix_set && !f->and_size_gt && !f->and_size_lt;
}

static bool tag_empty(const buckets_lc_filter *f) { return !f->tag.key || !*f->tag.key; }

static bool and_valid(const buckets_lc_filter *f, buckets_lc_error *e) {
  size_t preds = f->and_prefix_set + f->nand_tags + (f->and_size_gt > 0) + (f->and_size_lt > 0);
  if (preds < 2) return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  for (size_t i = 0; i < f->nand_tags; i++)
    for (size_t j = 0; j < i; j++)
      if (strcmp(f->and_tags[i].key, f->and_tags[j].key) == 0)
        return fail(e, BUCKETS_LC_ERR_INVALID, "Duplicate Tag Keys are not allowed");
  for (size_t i = 0; i < f->nand_tags; i++)
    if (!tag_valid(&f->and_tags[i], e)) return false;
  if (f->and_size_gt < 0 || f->and_size_lt < 0) return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  return true;
}

static bool filter_valid(const buckets_lc_filter *f, buckets_lc_error *e) {
  enum { NONE, PREFIX, AND, TAG, LT, GT } type = NONE;
  int count = 0;
  if (!and_empty(f)) type = AND, count++;
  if (f->prefix_set) type = PREFIX, count++;
  if (!tag_empty(f)) type = TAG, count++;
  if (f->size_gt) type = GT, count++;
  if (f->size_lt) type = LT, count++;
  if (count > 1) return fail(e, BUCKETS_LC_ERR_INVALID, "Filter must have exactly one of Prefix, Tag, or And specified");
  switch (type) {
  case AND: return and_valid(f, e);
  case TAG: return tag_valid(&f->tag, e);
  case LT: return f->size_lt >= 0 || fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  case GT: return f->size_gt >= 0 || fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  default: return true;
  }
}

static bool rule_valid(const buckets_lc_rule *r, buckets_lc_error *e) {
  if (strlen(r->id) > 255) return fail(e, BUCKETS_LC_ERR_INVALID, "ID length is limited to 255 characters");
  if (!*r->status) return fail(e, BUCKETS_LC_ERR_INVALID, "Status should not be empty");
  if (strcmp(r->status, "Enabled") != 0 && strcmp(r->status, "Disabled") != 0)
    return fail(e, BUCKETS_LC_ERR_INVALID, "Status must be set to either Enabled or Disabled");
  if (r->exp_set) {
    if ((r->exp_days || r->exp_date) && r->exp_dm_set)
      return fail(e, BUCKETS_LC_ERR_INVALID, "Delete marker cannot be specified with Days or Date in a Lifecycle Expiration Policy");
    if (!r->exp_dm_set && !r->exp_all_set && !r->exp_days && !r->exp_date)
      return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
    if (r->exp_days && r->exp_date)
      return fail(e, BUCKETS_LC_ERR_INVALID,
                  "Exactly one of Days (positive integer) or Date (positive ISO 8601 format) should be present inside Expiration.");
    if (r->exp_all_set && !r->exp_days)
      return fail(e, BUCKETS_LC_ERR_INVALID,
                  "Days (positive integer) should be present inside Expiration with ExpiredObjectAllVersions.");
  }
  if (r->nve_set && ((!r->nve_days && !r->nve_newer) || r->nve_days < 0 || r->nve_newer < 0))
    return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  if (r->prefix_set && r->filter.set && r->filter.prefix_set) return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  if (r->filter.set && !filter_valid(&r->filter, e)) return false;
  if (r->tr_set) {
    if (r->tr_date && r->tr_days > 0)
      return fail(e, BUCKETS_LC_ERR_INVALID,
                  "Exactly one of Days (0 or greater) or Date (positive ISO 8601 format) should be present in Transition.");
    if (!r->tr_class || !*r->tr_class) return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  }
  if (r->nvt_set && (!r->nvt_class || !*r->nvt_class)) return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  if ((!tag_empty(&r->filter) || r->filter.nand_tags) && r->dm_days)
    return fail(e, BUCKETS_LC_ERR_INVALID, "Rule with DelMarkerExpiration cannot have tags based filtering");
  if (!r->exp_set && !r->tr_set && !r->nve_set && !r->nvt_set && !r->dm_days)
    return fail(e, BUCKETS_LC_ERR_INVALID, ERR_NOT_WELL_FORMED);
  return true;
}

bool buckets_lifecycle_validate(const buckets_lifecycle *lc, bool lock_enabled, bool (*tier_valid)(void *ud, const char *tier),
                                void *ud, buckets_lc_error *e) {
  memset(e, 0, sizeof(*e));
  if (lc->n > 1000) return fail(e, BUCKETS_LC_ERR_INVALID, "Lifecycle configuration allows a maximum of 1000 rules");
  if (!lc->n) return fail(e, BUCKETS_LC_ERR_INVALID, "Lifecycle configuration should have at least one rule");
  for (size_t i = 0; i < lc->n; i++) {
    const buckets_lc_rule *r = &lc->rules[i];
    if (!rule_valid(r, e)) return false;
    if (lock_enabled && (r->exp_all || r->dm_days))
      return fail(e, BUCKETS_LC_ERR_INVALID,
                  "ExpiredObjectAllVersions element and DelMarkerExpiration action cannot be used on an object locked bucket");
  }
  for (size_t i = 0; i < lc->n; i++)
    for (size_t j = i + 1; j < lc->n; j++)
      if (strcmp(lc->rules[i].id, lc->rules[j].id) == 0)
        return fail(e, BUCKETS_LC_ERR_INVALID, "Rule ID must be unique. Found same ID for more than one rule");
  /* validateTransitionTier */
  for (size_t i = 0; i < lc->n; i++) {
    const buckets_lc_rule *r = &lc->rules[i];
    const char *cls[2] = {r->tr_class, r->nvt_class};
    for (int k = 0; k < 2; k++) {
      if (cls[k] && *cls[k] && !(tier_valid && tier_valid(ud, cls[k])))
        return fail(e, BUCKETS_LC_ERR_STORAGE_CLASS, "invalid storage class");
    }
  }
  return true;
}

bool buckets_lc_rule_has_expiry(const buckets_lc_rule *r) {
  return r->exp_days || r->exp_date || r->nve_days || r->nve_newer;
}

bool buckets_lifecycle_has_expiry(const buckets_lifecycle *lc) {
  for (size_t i = 0; i < lc->n; i++)
    if (buckets_lc_rule_has_expiry(&lc->rules[i])) return true;
  return false;
}

/* ---- marshalling --------------------------------------------------------------------- */

static void xml_i64(buckets_buf *out, const char *tag, int64_t v) { buckets_buf_appendf(out, "<%s>%lld</%s>", tag, (long long)v, tag); }

static void xml_date(buckets_buf *out, const char *tag, int64_t t) {
  time_t tt = (time_t)t;
  struct tm tm;
  gmtime_r(&tt, &tm);
  char s[32];
  strftime(s, sizeof(s), "%Y-%m-%dT%H:%M:%SZ", &tm);
  buckets_xml_elem(out, tag, s);
}

static void xml_tag(buckets_buf *out, const buckets_lc_tag *t) {
  buckets_xml_open(out, "Tag");
  if (t->key && *t->key) buckets_xml_elem(out, "Key", t->key);
  if (t->value && *t->value) buckets_xml_elem(out, "Value", t->value);
  buckets_xml_close(out, "Tag");
}

static void xml_filter(buckets_buf *out, const buckets_lc_filter *f) {
  if (!f->set) return;
  buckets_xml_open(out, "Filter");
  if (!and_empty(f)) {
    buckets_xml_open(out, "And");
    if (f->and_size_gt) xml_i64(out, "ObjectSizeGreaterThan", f->and_size_gt);
    if (f->and_size_lt) xml_i64(out, "ObjectSizeLessThan", f->and_size_lt);
    if (f->and_prefix_set) buckets_xml_elem(out, "Prefix", f->and_prefix);
    for (size_t i = 0; i < f->nand_tags; i++) xml_tag(out, &f->and_tags[i]);
    buckets_xml_close(out, "And");
  } else if (!tag_empty(f)) {
    xml_tag(out, &f->tag);
  } else {
    if (f->prefix_set) buckets_xml_elem(out, "Prefix", f->prefix);
    if (f->size_lt > 0) xml_i64(out, "ObjectSizeLessThan", f->size_lt);
    if (f->size_gt > 0) xml_i64(out, "ObjectSizeGreaterThan", f->size_gt);
  }
  buckets_xml_close(out, "Filter");
}

void buckets_lifecycle_xml(const buckets_lifecycle *lc, bool with_updated_at, buckets_buf *out) {
  buckets_xml_open(out, "LifecycleConfiguration");
  for (size_t i = 0; i < lc->n; i++) {
    const buckets_lc_rule *r = &lc->rules[i];
    buckets_xml_open(out, "Rule");
    if (*r->id) buckets_xml_elem(out, "ID", r->id);
    buckets_xml_elem(out, "Status", r->status);
    xml_filter(out, &r->filter);
    if (r->prefix_set) buckets_xml_elem(out, "Prefix", r->prefix);
    if (r->exp_set) {
      buckets_xml_open(out, "Expiration");
      if (r->exp_days) xml_i64(out, "Days", r->exp_days);
      if (r->exp_date) xml_date(out, "Date", r->exp_date);
      if (r->exp_dm_set) buckets_xml_elem(out, "ExpiredObjectDeleteMarker", r->exp_dm ? "true" : "false");
      if (r->exp_all_set) buckets_xml_elem(out, "ExpiredObjectAllVersions", r->exp_all ? "true" : "false");
      buckets_xml_close(out, "Expiration");
    }
    if (r->tr_set) {
      buckets_xml_open(out, "Transition");
      if (r->tr_days) xml_i64(out, "Days", r->tr_days);
      if (r->tr_date) xml_date(out, "Date", r->tr_date);
      if (r->tr_class && *r->tr_class) buckets_xml_elem(out, "StorageClass", r->tr_class);
      buckets_xml_close(out, "Transition");
    }
    if (r->dm_days) {
      buckets_xml_open(out, "DelMarkerExpiration");
      xml_i64(out, "Days", r->dm_days);
      buckets_xml_close(out, "DelMarkerExpiration");
    }
    if (r->nve_days || r->nve_newer) {
      buckets_xml_open(out, "NoncurrentVersionExpiration");
      if (r->nve_days) xml_i64(out, "NoncurrentDays", r->nve_days);
      if (r->nve_newer) xml_i64(out, "NewerNoncurrentVersions", r->nve_newer);
      buckets_xml_close(out, "NoncurrentVersionExpiration");
    }
    if (r->nvt_class && *r->nvt_class) {
      buckets_xml_open(out, "NoncurrentVersionTransition");
      xml_i64(out, "NoncurrentDays", r->nvt_days);
      buckets_xml_elem(out, "StorageClass", r->nvt_class);
      buckets_xml_close(out, "NoncurrentVersionTransition");
    }
    buckets_xml_close(out, "Rule");
  }
  if (with_updated_at && lc->expiry_updated_ns) {
    char ts[64];
    buckets_time_rfc3339_nano(lc->expiry_updated_ns / 1000000000LL, (long)(lc->expiry_updated_ns % 1000000000LL), ts);
    buckets_xml_elem(out, "ExpiryUpdatedAt", ts);
  }
  buckets_xml_close(out, "LifecycleConfiguration");
}

/* ---- evaluation ---------------------------------------------------------------------- */

int64_t buckets_lc_expected_expiry(int64_t mod_time_ns, int64_t days) {
  if (days == 0) return mod_time_ns;
  int64_t t = mod_time_ns + (days + 1) * DAY_NS;
  /* Truncate(24h) counts from Go's zero time, a UTC midnight, as the epoch is */
  int64_t r = t % DAY_NS;
  if (r < 0) r += DAY_NS;
  return t - r;
}

static const char *rule_prefix(const buckets_lc_rule *r) {
  if (r->prefix && *r->prefix) return r->prefix;
  if (r->filter.prefix && *r->filter.prefix) return r->filter.prefix;
  if (r->filter.and_prefix && *r->filter.and_prefix) return r->filter.and_prefix;
  return "";
}

/* Filter.TestTags */
static bool test_tags(const buckets_lc_filter *f, const char *user_tags) {
  size_t want = f->nand_tags + !tag_empty(f);
  if (!want) return true;
  buckets_tags t;
  buckets_tags_error te;
  if (!buckets_tags_parse_query(user_tags ? user_tags : "", true, &t, &te)) return false;
  bool ok = true;
  /* the filter's tags as a map: a later duplicate key wins */
  for (size_t i = 0; i <= f->nand_tags && ok; i++) {
    const buckets_lc_tag *ft = i < f->nand_tags ? &f->and_tags[i] : &f->tag;
    if (!ft->key || !*ft->key) continue;
    bool superseded = false;
    for (size_t j = i + 1; j <= f->nand_tags; j++) {
      const buckets_lc_tag *later = j < f->nand_tags ? &f->and_tags[j] : &f->tag;
      superseded |= later->key && strcmp(later->key, ft->key) == 0;
    }
    if (superseded) continue;
    const char *v = buckets_tags_get(&t, ft->key);
    ok = v && strcmp(v, ft->value) == 0;
  }
  size_t distinct = 0;
  for (size_t i = 0; i <= f->nand_tags; i++) {
    const buckets_lc_tag *ft = i < f->nand_tags ? &f->and_tags[i] : &f->tag;
    if (!ft->key || !*ft->key) continue;
    bool dup = false;
    for (size_t j = 0; j < i; j++) {
      const buckets_lc_tag *e = &f->and_tags[j];
      dup |= e->key && strcmp(e->key, ft->key) == 0;
    }
    distinct += !dup;
  }
  if (t.n < distinct) ok = false;
  buckets_tags_free(&t);
  return ok;
}

static bool by_size(const buckets_lc_filter *f, int64_t sz) {
  if (f->size_gt > 0 && sz <= f->size_gt) return false;
  if (f->size_lt > 0 && sz >= f->size_lt) return false;
  if (!and_empty(f)) {
    if (f->and_size_gt > 0 && sz <= f->and_size_gt) return false;
    if (f->and_size_lt > 0 && sz >= f->and_size_lt) return false;
  }
  return true;
}

static bool rule_applies(const buckets_lc_rule *r, const buckets_lc_obj *o) {
  if (strcmp(r->status, "Disabled") == 0) return false;
  const char *p = rule_prefix(r);
  if (strncmp(o->name, p, strlen(p)) != 0) return false;
  if (!test_tags(&r->filter, o->user_tags)) return false;
  if (!o->delete_marker && !by_size(&r->filter, o->size)) return false;
  return true;
}

static bool after(int64_t now, int64_t t) { return now == 0 || now > t; }

static bool is_delete(buckets_lc_action a) {
  return a == BUCKETS_LC_DELETE_ALL_VERSIONS || a == BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS || a == BUCKETS_LC_DELETE ||
         a == BUCKETS_LC_DELETE_VERSION;
}

/* The comparator MinIO sorts events with. */
static int event_cmp(const buckets_lc_event *a, const buckets_lc_event *b, int64_t now) {
  bool now_after_a = now != 0 && now > a->due_ns, now_after_b = now != 0 && now > b->due_ns;
  if ((now_after_a && now_after_b) || a->due_ns == b->due_ns) {
    if (is_delete(a->action)) return -1;
    if (is_delete(b->action)) return 1;
    return -1;
  }
  return a->due_ns < b->due_ns ? -1 : 1;
}

buckets_lc_event buckets_lifecycle_eval(const buckets_lifecycle *lc, const buckets_lc_obj *o, int64_t now,
                                        size_t remaining) {
  buckets_lc_event none = {0};
  if (!o->mod_time_ns || !o->name || !*o->name) return none;
  buckets_lc_event ev[64];
  size_t n = 0;
  for (size_t i = 0; i < lc->n && n + 4 < 64; i++) {
    const buckets_lc_rule *r = &lc->rules[i];
    if (!rule_applies(r, o)) continue;
    if (o->delete_marker && o->num_versions == 1) { /* ExpiredObjectDeleteMarker */
      if (r->exp_dm) {
        ev[n++] = (buckets_lc_event){BUCKETS_LC_DELETE_VERSION, r->id, now, NULL};
        break;
      }
      if (r->exp_days) {
        int64_t due = buckets_lc_expected_expiry(o->mod_time_ns, r->exp_days);
        if (after(now, due)) {
          ev[n++] = (buckets_lc_event){BUCKETS_LC_DELETE_VERSION, r->id, due, NULL};
          break;
        }
      }
    }
    if (o->is_latest && o->delete_marker && r->dm_days) {
      int64_t due = buckets_lc_expected_expiry(o->mod_time_ns, r->dm_days);
      if (after(now, due)) ev[n++] = (buckets_lc_event){BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS, r->id, due, NULL};
      continue;
    }
    if (!o->is_latest && r->nve_set) {
      bool retained = r->nve_newer == 0 || (int64_t)remaining >= r->nve_newer;
      int64_t due = buckets_lc_expected_expiry(o->successor_mod_time_ns, r->nve_days);
      if (retained && after(now, due)) ev[n++] = (buckets_lc_event){BUCKETS_LC_DELETE_VERSION, r->id, due, NULL};
    }
    if (!o->is_latest && r->nvt_class && *r->nvt_class && !o->delete_marker) {
      int64_t due = r->nvt_days ? buckets_lc_expected_expiry(o->successor_mod_time_ns, r->nvt_days) : o->successor_mod_time_ns;
      if (after(now, due)) ev[n++] = (buckets_lc_event){BUCKETS_LC_TRANSITION_VERSION, r->id, due, r->nvt_class};
    }
    if (o->is_latest && !o->delete_marker) {
      if (r->exp_date) {
        int64_t due = r->exp_date * 1000000000LL;
        if (after(now, due)) ev[n++] = (buckets_lc_event){BUCKETS_LC_DELETE, r->id, due, NULL};
      } else if (r->exp_days) {
        int64_t due = buckets_lc_expected_expiry(o->mod_time_ns, r->exp_days);
        if (after(now, due))
          ev[n++] = (buckets_lc_event){r->exp_all ? BUCKETS_LC_DELETE_ALL_VERSIONS : BUCKETS_LC_DELETE, r->id, due, NULL};
      }
      if (r->tr_class && *r->tr_class) {
        int64_t due = r->tr_date ? r->tr_date * 1000000000LL
                      : r->tr_days ? buckets_lc_expected_expiry(o->mod_time_ns, r->tr_days)
                                   : o->mod_time_ns;
        if (after(now, due)) ev[n++] = (buckets_lc_event){BUCKETS_LC_TRANSITION, r->id, due, r->tr_class};
      }
    }
  }
  if (!n) return none;
  /* slices.SortFunc on so few elements is pdqsort's insertion sort */
  for (size_t i = 1; i < n; i++) {
    for (size_t j = i; j > 0 && event_cmp(&ev[j], &ev[j - 1], now) < 0; j--) {
      buckets_lc_event t = ev[j];
      ev[j] = ev[j - 1];
      ev[j - 1] = t;
    }
  }
  return ev[0];
}

void buckets_lifecycle_eval_versions(const buckets_lifecycle *lc, bool lock_enabled, const buckets_lc_obj *objs, size_t n,
                                     int64_t now, buckets_lc_event *events) {
  memset(events, 0, n * sizeof(*events));
  size_t newer_noncurrent = 0;
  for (size_t i = 0; i < n; i++) {
    buckets_lc_event e = buckets_lifecycle_eval(lc, &objs[i], now, newer_noncurrent);
    switch (e.action) {
    case BUCKETS_LC_DELETE_ALL_VERSIONS:
    case BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS:
      if (!lock_enabled) {
        events[i] = e;
        return;
      }
      e = (buckets_lc_event){0};
      break;
    case BUCKETS_LC_DELETE_VERSION:
    case BUCKETS_LC_DELETE_RESTORED_VERSION:
      if (!*objs[i].version_id) e.action = BUCKETS_LC_NONE;
      if (lock_enabled && objs[i].locked && !objs[i].delete_marker) e = (buckets_lc_event){0};
      break;
    default: break;
    }
    if (!objs[i].is_latest && e.action != BUCKETS_LC_DELETE_VERSION) newer_noncurrent++;
    events[i] = e;
  }
}

const char *buckets_lifecycle_prediction(const buckets_lifecycle *lc, const buckets_lc_obj *obj, char *value, size_t cap) {
  buckets_lc_event e = buckets_lifecycle_eval(lc, obj, 0, 0);
  bool transition;
  switch (e.action) {
  case BUCKETS_LC_DELETE:
  case BUCKETS_LC_DELETE_VERSION:
  case BUCKETS_LC_DELETE_ALL_VERSIONS:
  case BUCKETS_LC_DELMARKER_DELETE_ALL_VERSIONS: transition = false; break;
  case BUCKETS_LC_TRANSITION:
  case BUCKETS_LC_TRANSITION_VERSION: transition = true; break;
  default: return NULL;
  }
  char date[BUCKETS_TIME_HTTP_LEN + 1];
  buckets_time_http((time_t)(e.due_ns / 1000000000LL), date);
  if (transition) snprintf(value, cap, "transition-date=\"%s\", rule-id=\"%s\"", date, e.rule_id);
  else snprintf(value, cap, "expiry-date=\"%s\", rule-id=\"%s\"", date, e.rule_id);
  const char *hdr = transition ? "X-Minio-Transition" : "x-amz-expiration";
  return hdr;
}
