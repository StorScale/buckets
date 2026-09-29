/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Bucket replication configuration (MinIO's internal/bucket/replication). */
#include "bucket/replication.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bucket/tags.h"
#include "core/common.h"
#include "s3/xml.h"

static char *dup0(const char *s) { return buckets_xstrdup(s ? s : ""); }

static void tag_free(buckets_repl_tag *t) {
  free(t->key);
  free(t->value);
  t->key = t->value = NULL;
}

static void rule_free(buckets_repl_rule *r) {
  free(r->id);
  free(r->status);
  free(r->dm_status);
  free(r->del_status);
  free(r->existing_status);
  free(r->replica_mod_status);
  free(r->dest_bucket);
  free(r->dest_arn);
  free(r->dest_sc);
  free(r->prefix);
  tag_free(&r->tag);
  free(r->and_prefix);
  for (size_t i = 0; i < r->nand_tags; i++) tag_free(&r->and_tags[i]);
  free(r->and_tags);
}

void buckets_replication_free(buckets_replication *c) {
  for (size_t i = 0; i < c->n; i++) rule_free(&c->rules[i]);
  free(c->rules);
  free(c->role);
  memset(c, 0, sizeof(*c));
}

/* ---- parsing ---- */

typedef struct {
  const buckets_xml_doc *d;
  char *err;
  size_t errlen;
} pctx;

static char *text_of(const buckets_xml_doc *d, size_t i) {
  buckets_buf t = BUCKETS_BUF_INIT;
  buckets_xml_unescape(d->nodes[i].text, &t);
  char *s = buckets_xstrndup(t.data ? t.data : "", t.len);
  buckets_buf_free(&t);
  return s;
}

static void set_text(char **dst, const buckets_xml_doc *d, size_t i) {
  free(*dst);
  *dst = text_of(d, i);
}

static bool is(const buckets_xml_doc *d, size_t i, const char *name) { return buckets_str_eq_c(d->nodes[i].name, name); }

/* <X><Status>..</Status></X>: the last Status wins, "" when none. */
static char *status_of(const buckets_xml_doc *d, size_t node) {
  char *s = NULL;
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (is(d, c, "Status")) set_text(&s, d, c);
  }
  return s ? s : dup0("");
}

static void parse_tag(const buckets_xml_doc *d, size_t node, buckets_repl_tag *t) {
  tag_free(t);
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (is(d, c, "Key")) set_text(&t->key, d, c);
    else if (is(d, c, "Value")) set_text(&t->value, d, c);
  }
  if (!t->key) t->key = dup0("");
  if (!t->value) t->value = dup0("");
}

static bool parse_destination(pctx *p, size_t node, buckets_repl_rule *r) {
  const buckets_xml_doc *d = p->d;
  char *bucket = NULL, *sc = NULL;
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (is(d, c, "Bucket")) set_text(&bucket, d, c);
    else if (is(d, c, "StorageClass")) set_text(&sc, d, c);
  }
  if (!bucket) bucket = dup0("");
  bool ok = false;
  static const char aws[] = "arn:aws:s3:::", mn[] = "arn:minio:replication:";
  if (strncmp(bucket, aws, sizeof(aws) - 1) != 0 && strncmp(bucket, mn, sizeof(mn) - 1) != 0) {
    snprintf(p->err, p->errlen, "invalid destination '%s'", bucket);
  } else if (sc && *sc && strcmp(sc, "STANDARD") != 0 && strcmp(sc, "REDUCED_REDUNDANCY") != 0) {
    snprintf(p->err, p->errlen, "unknown storage class %s", sc);
  } else {
    free(r->dest_bucket);
    free(r->dest_arn);
    free(r->dest_sc);
    r->dest_arn = dup0(bucket);
    r->dest_bucket = dup0(strncmp(bucket, aws, sizeof(aws) - 1) == 0 ? bucket + sizeof(aws) - 1 : bucket);
    r->dest_sc = dup0(sc);
    ok = true;
  }
  free(bucket);
  free(sc);
  return ok;
}

static void parse_filter(const buckets_xml_doc *d, size_t node, buckets_repl_rule *r) {
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (is(d, c, "Prefix")) {
      set_text(&r->prefix, d, c);
    } else if (is(d, c, "Tag")) {
      parse_tag(d, c, &r->tag);
    } else if (is(d, c, "And")) {
      for (size_t a = d->nodes[c].first_child; a; a = d->nodes[a].next_sibling) {
        if (is(d, a, "Prefix")) {
          set_text(&r->and_prefix, d, a);
        } else if (is(d, a, "Tag")) {
          r->and_tags = buckets_xrealloc(r->and_tags, (r->nand_tags + 1) * sizeof(*r->and_tags));
          memset(&r->and_tags[r->nand_tags], 0, sizeof(r->and_tags[0]));
          parse_tag(d, a, &r->and_tags[r->nand_tags++]);
        }
      }
    }
  }
}

static bool parse_int(pctx *p, const buckets_xml_doc *d, size_t node, long *out) {
  char *s = text_of(d, node);
  char *b = s, *e = s + strlen(s);
  while (*b == ' ' || *b == '\t' || *b == '\n' || *b == '\r') b++;
  while (e > b && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\n' || e[-1] == '\r')) e--;
  *e = '\0';
  bool ok = true;
  if (!*b) {
    *out = 0;
  } else {
    char *end = NULL;
    errno = 0;
    long long v = strtoll(b, &end, 10);
    bool digits = (*b == '+' || *b == '-') ? b[1] >= '0' && b[1] <= '9' : *b >= '0' && *b <= '9';
    if (!digits || *end) {
      snprintf(p->err, p->errlen, "strconv.ParseInt: parsing \"%s\": invalid syntax", b);
      ok = false;
    } else if (errno == ERANGE) {
      snprintf(p->err, p->errlen, "strconv.ParseInt: parsing \"%s\": value out of range", b);
      ok = false;
    } else {
      *out = (long)v;
    }
  }
  free(s);
  return ok;
}

static bool parse_rule(pctx *p, size_t node, buckets_repl_rule *r) {
  const buckets_xml_doc *d = p->d;
  for (size_t c = d->nodes[node].first_child; c; c = d->nodes[c].next_sibling) {
    if (is(d, c, "ID")) {
      set_text(&r->id, d, c);
    } else if (is(d, c, "Status")) {
      set_text(&r->status, d, c);
    } else if (is(d, c, "Priority")) {
      if (!parse_int(p, d, c, &r->priority)) return false;
    } else if (is(d, c, "DeleteMarkerReplication")) {
      free(r->dm_status);
      r->dm_status = status_of(d, c);
    } else if (is(d, c, "DeleteReplication")) {
      free(r->del_status);
      r->del_status = status_of(d, c);
      if (!*r->del_status) {
        free(r->del_status);
        r->del_status = dup0("Disabled");
      }
    } else if (is(d, c, "ExistingObjectReplication")) {
      free(r->existing_status);
      r->existing_status = status_of(d, c);
      if (!*r->existing_status) {
        free(r->existing_status);
        r->existing_status = dup0("Disabled");
      }
    } else if (is(d, c, "SourceSelectionCriteria")) {
      char *st = NULL;
      for (size_t s = d->nodes[c].first_child; s; s = d->nodes[s].next_sibling) {
        if (is(d, s, "ReplicaModifications")) {
          free(st);
          st = status_of(d, s);
        }
      }
      free(r->replica_mod_status);
      r->replica_mod_status = st && *st ? st : (free(st), dup0("Enabled"));
    } else if (is(d, c, "Destination")) {
      if (!parse_destination(p, c, r)) return false;
    } else if (is(d, c, "Filter")) {
      parse_filter(d, c, r);
    }
  }
  return true;
}

bool buckets_replication_parse(const char *xml, size_t len, buckets_replication *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d) || !d.count) {
    buckets_xml_doc_free(&d);
    snprintf(err, errlen, len ? "XML syntax error on line 1: unexpected EOF" : "EOF");
    return false;
  }
  if (!is(&d, 0, "ReplicationConfiguration")) {
    snprintf(err, errlen, "expected element type <ReplicationConfiguration> but have <%.*s>",
             (int)d.nodes[0].name.n, d.nodes[0].name.p);
    buckets_xml_doc_free(&d);
    return false;
  }
  pctx p = {&d, err, errlen};
  bool ok = true;
  for (size_t c = d.nodes[0].first_child; c && ok; c = d.nodes[c].next_sibling) {
    if (is(&d, c, "Rule")) {
      out->rules = buckets_xrealloc(out->rules, (out->n + 1) * sizeof(*out->rules));
      buckets_repl_rule *r = &out->rules[out->n++];
      memset(r, 0, sizeof(*r));
      ok = parse_rule(&p, c, r);
    } else if (is(&d, c, "Role")) {
      set_text(&out->role, &d, c);
    }
  }
  buckets_xml_doc_free(&d);
  if (!ok) {
    buckets_replication_free(out);
    return false;
  }
  if (!out->role) out->role = dup0("");
  /* ParseConfig's defaults, and the zero values of absent elements */
  for (size_t i = 0; i < out->n; i++) {
    buckets_repl_rule *r = &out->rules[i];
    if (!r->replica_mod_status || !*r->replica_mod_status) {
      free(r->replica_mod_status);
      r->replica_mod_status = dup0("Enabled");
    }
    if (!r->del_status || !*r->del_status) {
      free(r->del_status);
      r->del_status = dup0("Disabled");
    }
    char **s[] = {&r->id, &r->status, &r->dm_status, &r->existing_status, &r->dest_bucket, &r->dest_arn,
                  &r->dest_sc, &r->prefix, &r->and_prefix};
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(s); k++)
      if (!*s[k]) *s[k] = dup0("");
  }
  return true;
}

/* ---- validation ---- */

static size_t utf8_runes(const char *s) {
  size_t n = 0;
  for (; *s; s++) n += ((unsigned char)*s & 0xC0) != 0x80;
  return n;
}

static bool tag_empty(const buckets_repl_tag *t) { return !t->key || !*t->key; }

static bool tag_validate(const buckets_repl_tag *t, char *err, size_t errlen) {
  if (!t->key || !*t->key || utf8_runes(t->key) > 128) {
    snprintf(err, errlen, "The TagKey you have provided is invalid");
    return false;
  }
  if (utf8_runes(t->value ? t->value : "") > 256) {
    snprintf(err, errlen, "The TagValue you have provided is invalid");
    return false;
  }
  return true;
}

static bool and_empty(const buckets_repl_rule *r) { return r->nand_tags == 0 && !*r->and_prefix; }

static bool filter_validate(const buckets_repl_rule *r, char *err, size_t errlen) {
  static const char inv[] = "Filter must have exactly one of Prefix, Tag, or And specified";
  if (!and_empty(r)) {
    if (*r->prefix || !tag_empty(&r->tag)) {
      snprintf(err, errlen, inv);
      return false;
    }
    for (size_t i = 0; i < r->nand_tags; i++) {
      for (size_t j = 0; j < i; j++) {
        if (strcmp(r->and_tags[i].key, r->and_tags[j].key) == 0) {
          snprintf(err, errlen, "Duplicate Tag Keys are not allowed");
          return false;
        }
      }
    }
    for (size_t i = 0; i < r->nand_tags; i++)
      if (!tag_validate(&r->and_tags[i], err, errlen)) return false;
  }
  if (*r->prefix && !tag_empty(&r->tag)) {
    snprintf(err, errlen, inv);
    return false;
  }
  if (!tag_empty(&r->tag) && !tag_validate(&r->tag, err, errlen)) return false;
  return true;
}

static bool status_ok(const char *s) { return strcmp(s, "Enabled") == 0 || strcmp(s, "Disabled") == 0; }

static bool rule_validate(const buckets_repl_rule *r, const char *bucket, bool same_target, char *err, size_t errlen) {
  if (strlen(r->id) > 255) {
    snprintf(err, errlen, "ID must be less than 255 characters");
    return false;
  }
  if (!*r->status) {
    snprintf(err, errlen, "Status should not be empty");
    return false;
  }
  if (!status_ok(r->status)) {
    snprintf(err, errlen, "Status must be set to either Enabled or Disabled");
    return false;
  }
  if (!filter_validate(r, err, errlen)) return false;
  if (!*r->dm_status) {
    snprintf(err, errlen, "DeleteMarkerReplication must be specified");
    return false;
  }
  if (!status_ok(r->dm_status)) {
    snprintf(err, errlen, "Delete marker replication status is invalid");
    return false;
  }
  if (!status_ok(r->del_status)) {
    snprintf(err, errlen, "Delete replication is either enable|disable");
    return false;
  }
  if (*r->replica_mod_status && !status_ok(r->replica_mod_status)) {
    snprintf(err, errlen, "Invalid ReplicaModification status");
    return false;
  }
  if (r->priority < 0) {
    snprintf(err, errlen, "Priority must be specified");
    return false;
  }
  if (strcmp(r->dest_bucket, bucket) == 0 && same_target) {
    snprintf(err, errlen, "Destination bucket cannot be the same as the source bucket.");
    return false;
  }
  if (!tag_empty(&r->tag) && strcmp(r->dm_status, "Enabled") == 0) {
    snprintf(err, errlen, "Delete marker replication is not supported if any Tag filter is specified");
    return false;
  }
  if (*r->existing_status && !status_ok(r->existing_status)) {
    snprintf(err, errlen, "Existing object replication status is invalid");
    return false;
  }
  return true;
}

bool buckets_replication_validate(const buckets_replication *c, const char *bucket, bool same_target, char *err,
                                  size_t errlen) {
  if (c->n > 1000) {
    snprintf(err, errlen, "Replication configuration allows a maximum of 1000 rules");
    return false;
  }
  if (c->n == 0) {
    snprintf(err, errlen, "Replication configuration should have at least one rule");
    return false;
  }
  size_t ntargets = 0;
  bool legacy = false;
  for (size_t i = 0; i < c->n; i++) {
    const buckets_repl_rule *r = &c->rules[i];
    bool seen = false;
    for (size_t j = 0; j < i && !seen; j++) seen = strcmp(c->rules[j].dest_bucket, r->dest_bucket) == 0;
    if (!seen) ntargets++;
    if (!rule_validate(r, bucket, same_target, err, errlen)) return false;
    for (size_t j = 0; j < i; j++) {
      if (c->rules[j].priority == r->priority) {
        snprintf(err, errlen, "Replication configuration has duplicate priority");
        return false;
      }
    }
    if (strncmp(r->dest_arn, "arn:aws:s3:::", 13) == 0) legacy = true;
    if (!*c->role && strncmp(r->dest_arn, "arn:minio:replication:", 22) != 0) {
      snprintf(err, errlen, "Missing required parameter `Destination` in Replication rule");
      return false;
    }
  }
  if (*c->role && ntargets > 1) {
    snprintf(err, errlen, "`Role` should be empty in ReplicationConfiguration for multiple targets");
    return false;
  }
  if (!*c->role && legacy) {
    snprintf(err, errlen, "Missing required parameter `Role` in ReplicationConfiguration");
    return false;
  }
  return true;
}

/* ---- marshalling ---- */

static void status_elem(buckets_buf *b, const char *tag, const char *status) {
  buckets_xml_open(b, tag);
  buckets_xml_elem(b, "Status", status);
  buckets_xml_close(b, tag);
}

static void tag_xml(buckets_buf *b, const buckets_repl_tag *t) {
  buckets_xml_open(b, "Tag");
  if (t->key && *t->key) buckets_xml_elem(b, "Key", t->key);
  if (t->value && *t->value) buckets_xml_elem(b, "Value", t->value);
  buckets_xml_close(b, "Tag");
}

void buckets_replication_xml(const buckets_replication *c, buckets_buf *b) {
  buckets_xml_open(b, "ReplicationConfiguration");
  for (size_t i = 0; i < c->n; i++) {
    const buckets_repl_rule *r = &c->rules[i];
    buckets_xml_open(b, "Rule");
    if (*r->id) buckets_xml_elem(b, "ID", r->id);
    buckets_xml_elem(b, "Status", r->status);
    char pr[32];
    snprintf(pr, sizeof(pr), "%ld", r->priority);
    buckets_xml_elem(b, "Priority", pr);
    status_elem(b, "DeleteMarkerReplication", r->dm_status);
    status_elem(b, "DeleteReplication", r->del_status);
    buckets_xml_open(b, "Destination");
    buckets_xml_elem(b, "Bucket", r->dest_arn);
    if (*r->dest_sc) buckets_xml_elem(b, "StorageClass", r->dest_sc);
    buckets_xml_close(b, "Destination");
    buckets_xml_open(b, "SourceSelectionCriteria");
    if (status_ok(r->replica_mod_status)) status_elem(b, "ReplicaModifications", r->replica_mod_status);
    buckets_xml_close(b, "SourceSelectionCriteria");
    buckets_xml_open(b, "Filter");
    if (!and_empty(r)) {
      buckets_xml_open(b, "And");
      if (*r->and_prefix) buckets_xml_elem(b, "Prefix", r->and_prefix);
      for (size_t k = 0; k < r->nand_tags; k++) tag_xml(b, &r->and_tags[k]);
      buckets_xml_close(b, "And");
    } else if (!tag_empty(&r->tag)) {
      tag_xml(b, &r->tag);
    } else {
      buckets_xml_elem(b, "Prefix", r->prefix);
    }
    buckets_xml_close(b, "Filter");
    status_elem(b, "ExistingObjectReplication", r->existing_status);
    buckets_xml_close(b, "Rule");
  }
  buckets_xml_elem(b, "Role", c->role);
  buckets_xml_close(b, "ReplicationConfiguration");
}

/* ---- evaluation ---- */

static const char *rule_prefix(const buckets_repl_rule *r) { return *r->prefix ? r->prefix : r->and_prefix; }

/* Filter.TestTags */
static bool test_tags(const buckets_repl_rule *r, const char *user_tags) {
  size_t nwant = (tag_empty(&r->tag) ? 0 : 1);
  for (size_t i = 0; i < r->nand_tags; i++) nwant += !tag_empty(&r->and_tags[i]);
  if (nwant == 0) return true;
  buckets_tags t = {0};
  buckets_tags_error te;
  if (!buckets_tags_parse_query(user_tags ? user_tags : "", true, &t, &te)) return false;
  bool match = false;
  if (t.n > 0) {
    /* the cached map: And tags first, then Tag (a later key overwrites) */
    for (size_t i = 0; i <= r->nand_tags && !match; i++) {
      const buckets_repl_tag *w = i < r->nand_tags ? &r->and_tags[i] : &r->tag;
      if (tag_empty(w)) continue;
      bool overridden = false;
      for (size_t j = i + 1; j <= r->nand_tags && !overridden; j++) {
        const buckets_repl_tag *later = j < r->nand_tags ? &r->and_tags[j] : &r->tag;
        overridden = !tag_empty(later) && strcmp(later->key, w->key) == 0;
      }
      if (overridden) continue;
      const char *v = buckets_tags_get(&t, w->key);
      match = v && strcmp(v, w->value ? w->value : "") == 0;
    }
  }
  buckets_tags_free(&t);
  return match;
}

/* FilterActionableRules, as indexes into c->rules. */
static size_t actionable(const buckets_replication *c, const buckets_repl_obj *o, size_t *idx) {
  if ((!o->name || !*o->name) && o->op != BUCKETS_REPL_RESYNC && o->op != BUCKETS_REPL_ALL) return 0;
  size_t n = 0;
  for (size_t i = 0; i < c->n; i++) {
    const buckets_repl_rule *r = &c->rules[i];
    if (strcmp(r->status, "Disabled") == 0) continue;
    if (o->target_arn && *o->target_arn && strcmp(r->dest_arn, o->target_arn) != 0 && strcmp(c->role, o->target_arn) != 0)
      continue;
    if (o->op == BUCKETS_REPL_RESYNC || o->op == BUCKETS_REPL_ALL) {
      idx[n++] = i;
      continue;
    }
    if (o->existing && strcmp(r->existing_status, "Disabled") == 0) continue;
    const char *pfx = rule_prefix(r);
    if (strncmp(o->name, pfx, strlen(pfx)) != 0) continue;
    if (test_tags(r, o->user_tags)) idx[n++] = i;
  }
  /* sort.Slice with MinIO's comparator (insertion sort for small inputs) */
  for (size_t i = 1; i < n; i++) {
    for (size_t j = i; j > 0; j--) {
      const buckets_repl_rule *a = &c->rules[idx[j]], *b = &c->rules[idx[j - 1]];
      if (!(a->priority > b->priority && strcmp(a->dest_arn, b->dest_arn) == 0)) break;
      size_t t = idx[j];
      idx[j] = idx[j - 1];
      idx[j - 1] = t;
    }
  }
  return n;
}

size_t buckets_replication_target_arns(const buckets_replication *c, const buckets_repl_obj *o, char ***arns) {
  *arns = NULL;
  if (c->n == 0) return 0;
  size_t *idx = buckets_xcalloc(c->n, sizeof(*idx));
  size_t n = actionable(c, o, idx), k = 0;
  char **out = buckets_xcalloc(n + 1, sizeof(*out));
  for (size_t i = 0; i < n; i++) {
    const buckets_repl_rule *r = &c->rules[idx[i]];
    if (*c->role) {
      out[0] = dup0(c->role);
      k = 1;
      break;
    }
    bool seen = false;
    for (size_t j = 0; j < k && !seen; j++) seen = strcmp(out[j], r->dest_arn) == 0;
    if (!seen) out[k++] = dup0(r->dest_arn);
  }
  free(idx);
  if (!k) {
    free(out);
    out = NULL;
  }
  *arns = out;
  return k;
}

void buckets_replication_arns_free(char **arns, size_t n) {
  for (size_t i = 0; i < n; i++) free(arns[i]);
  free(arns);
}

bool buckets_replication_replicate(const buckets_replication *c, const buckets_repl_obj *o) {
  if (c->n == 0) return false;
  size_t *idx = buckets_xcalloc(c->n, sizeof(*idx));
  size_t n = actionable(c, o, idx);
  bool ret = false;
  for (size_t i = 0; i < n; i++) {
    const buckets_repl_rule *r = &c->rules[idx[i]];
    if (strcmp(r->status, "Disabled") == 0) continue;
    if (o->existing && strcmp(r->existing_status, "Disabled") == 0) break;
    if (o->op == BUCKETS_REPL_DELETE) {
      ret = o->version_id && *o->version_id ? strcmp(r->del_status, "Enabled") == 0
                                            : strcmp(r->dm_status, "Enabled") == 0;
      break;
    }
    ret = !o->replica || strcmp(r->replica_mod_status, "Enabled") == 0;
    break;
  }
  free(idx);
  return ret;
}

bool buckets_replication_has_active_rules(const buckets_replication *c, const char *prefix, bool recursive) {
  for (size_t i = 0; i < c->n; i++) {
    const buckets_repl_rule *r = &c->rules[i];
    if (strcmp(r->status, "Disabled") == 0) continue;
    if (prefix && *prefix && *r->prefix) {
      if (!recursive && strncmp(prefix, r->prefix, strlen(r->prefix)) != 0) continue;
      const char *rp = rule_prefix(r);
      if (recursive && strncmp(rp, prefix, strlen(prefix)) != 0 && strncmp(prefix, rp, strlen(rp)) != 0) continue;
    }
    return true;
  }
  return false;
}

void buckets_replication_has_existing(const buckets_replication *c, const char *arn, bool *has_arn, bool *enabled) {
  *has_arn = *enabled = false;
  for (size_t i = 0; i < c->n; i++) {
    const buckets_repl_rule *r = &c->rules[i];
    if (strcmp(r->dest_arn, arn) == 0 || strcmp(c->role, arn) == 0) {
      *has_arn = true;
      if (strcmp(r->existing_status, "Enabled") == 0) {
        *enabled = true;
        return;
      }
    }
  }
}

/* ---- status strings ----
 * Go's `([^=].*?)=([^,].*?);` over the string: each match starts at a
 * character other than '=', takes the shortest key up to '=', and the
 * shortest value (first char not ',') up to ';'. */

typedef struct {
  const char *k;
  size_t kn;
  const char *v;
  size_t vn;
} kvspan;

static const char *next_match(const char *s, kvspan *m) {
  for (; *s; s++) {
    if (*s == '=' || *s == '\n') continue;
    const char *eq = s + 1;
    while (*eq && *eq != '=' && *eq != '\n') eq++;
    if (*eq != '=') return NULL;
    const char *v = eq + 1;
    if (!*v || *v == ',' || *v == '\n') continue; /* [^,] must match one char */
    const char *semi = v + 1;
    while (*semi && *semi != ';' && *semi != '\n') semi++;
    if (*semi != ';') {
      if (!*semi) return NULL;
      continue;
    }
    m->k = s;
    m->kn = (size_t)(eq - s);
    m->v = v;
    m->vn = (size_t)(semi - v);
    return semi + 1;
  }
  return NULL;
}

void buckets_repl_target_status(const char *internal, const char *arn, char *out, size_t cap) {
  if (cap) out[0] = '\0';
  kvspan m;
  size_t al = strlen(arn);
  for (const char *p = internal ? internal : ""; (p = next_match(p, &m));) {
    if (m.kn == al && memcmp(m.k, arn, al) == 0) {
      snprintf(out, cap, "%.*s", (int)m.vn, m.v);
      return;
    }
  }
}

static const char *composite(const char *internal, const char *failed, const char *completed, const char *pending) {
  kvspan m;
  size_t n = 0, done = 0;
  bool fail = false;
  /* a map: the last status of a repeated key counts */
  for (const char *p = internal ? internal : ""; (p = next_match(p, &m));) {
    kvspan m2;
    bool later = false;
    for (const char *q = p; !later && (q = next_match(q, &m2));) later = m2.kn == m.kn && memcmp(m2.k, m.k, m.kn) == 0;
    if (later) continue;
    n++;
    if (m.vn == strlen(failed) && memcmp(m.v, failed, m.vn) == 0) fail = true;
    else if (m.vn == strlen(completed) && memcmp(m.v, completed, m.vn) == 0) done++;
  }
  if (n == 0) return "";
  if (fail) return failed;
  return done == n ? completed : pending;
}

const char *buckets_repl_composite_status(const char *internal) {
  if (internal && (strcmp(internal, BUCKETS_RS_PENDING) == 0 || strcmp(internal, BUCKETS_RS_COMPLETED) == 0 ||
                   strcmp(internal, BUCKETS_RS_FAILED) == 0 || strcmp(internal, BUCKETS_RS_REPLICA) == 0))
    return internal;
  return composite(internal, BUCKETS_RS_FAILED, BUCKETS_RS_COMPLETED, BUCKETS_RS_PENDING);
}

const char *buckets_repl_composite_purge(const char *internal) {
  if (internal && (strcmp(internal, BUCKETS_VPS_PENDING) == 0 || strcmp(internal, BUCKETS_VPS_COMPLETE) == 0 ||
                   strcmp(internal, BUCKETS_VPS_FAILED) == 0))
    return internal;
  return composite(internal, BUCKETS_VPS_FAILED, BUCKETS_VPS_COMPLETE, BUCKETS_VPS_PENDING);
}

void buckets_repl_status_set(buckets_buf *internal, const char *arn, const char *status) {
  buckets_buf out = BUCKETS_BUF_INIT;
  kvspan m;
  size_t al = strlen(arn);
  bool found = false;
  for (const char *p = internal->data ? internal->data : ""; (p = next_match(p, &m));) {
    if (m.kn == al && memcmp(m.k, arn, al) == 0) {
      if (found) continue;
      found = true;
      buckets_buf_appendf(&out, "%s=%s;", arn, status);
    } else {
      buckets_buf_append(&out, m.k, m.kn);
      buckets_buf_append_char(&out, '=');
      buckets_buf_append(&out, m.v, m.vn);
      buckets_buf_append_char(&out, ';');
    }
  }
  if (!found) buckets_buf_appendf(&out, "%s=%s;", arn, status);
  buckets_buf_append_char(&out, '\0');
  out.len--;
  buckets_buf_free(internal);
  *internal = out;
}
