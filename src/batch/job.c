/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "batch/job.h"

#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "core/common.h"
#include "core/msgpack.h"
#include "core/timefmt.h"
#include "core/yaml.h"
#include "iam/policy.h"

/* Go's zero time.Time: 0001-01-01T00:00:00Z */
#define GO_ZERO_SEC (-62135596800LL)

static char *dupz(const char *s) { return buckets_xstrdup(s ? s : ""); }

/* ---- freeing ------------------------------------------------------------------------------------- */

static void kvs_free(buckets_batch_kvs *k) {
  for (size_t i = 0; i < k->n; i++) {
    free(k->v[i].key);
    free(k->v[i].value);
  }
  free(k->v);
  memset(k, 0, sizeof(*k));
}

static void strs_free(buckets_batch_strs *s) {
  for (size_t i = 0; i < s->n; i++) free(s->v[i]);
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void flags_free(buckets_batch_flags *f) {
  kvs_free(&f->filter.tags);
  kvs_free(&f->filter.metadata);
  free(f->filter.kms_key_id);
  free(f->notify.endpoint);
  free(f->notify.token);
}

static void creds_free(buckets_batch_creds *c) {
  free(c->access_key);
  free(c->secret_key);
  free(c->session_token);
}

static void replicate_free(buckets_batch_replicate *r) {
  if (!r) return;
  free(r->api_version);
  flags_free(&r->flags);
  free(r->target.type);
  free(r->target.bucket);
  free(r->target.prefix);
  free(r->target.endpoint);
  free(r->target.path);
  creds_free(&r->target.creds);
  free(r->source.type);
  free(r->source.bucket);
  strs_free(&r->source.prefix);
  free(r->source.endpoint);
  free(r->source.path);
  creds_free(&r->source.creds);
  free(r->source.snowball.smaller_than);
  free(r);
}

static void keyrotate_free(buckets_batch_keyrotate *k) {
  if (!k) return;
  free(k->api_version);
  flags_free(&k->flags);
  free(k->bucket);
  free(k->prefix);
  free(k->enc_type);
  free(k->enc_key);
  free(k->enc_context);
  free(k);
}

static void expire_free(buckets_batch_expire *e) {
  if (!e) return;
  free(e->api_version);
  free(e->bucket);
  strs_free(&e->prefix);
  free(e->notify.endpoint);
  free(e->notify.token);
  for (size_t i = 0; i < e->nrules; i++) {
    kvs_free(&e->rules[i].tags);
    kvs_free(&e->rules[i].metadata);
    free(e->rules[i].type);
    free(e->rules[i].name);
  }
  free(e->rules);
  free(e);
}

void buckets_batch_job_free(buckets_batch_job *j) {
  free(j->id);
  free(j->user);
  replicate_free(j->replicate);
  keyrotate_free(j->keyrotate);
  expire_free(j->expire);
  memset(j, 0, sizeof(*j));
}

const char *buckets_batch_job_type(const buckets_batch_job *j) {
  if (j->replicate) return "replicate";
  if (j->keyrotate) return "keyrotate";
  if (j->expire) return "expire";
  return "unknown";
}

void buckets_batch_job_redact(buckets_batch_job *j) {
  if (j->replicate) {
    buckets_batch_creds *c = &j->replicate->target.creds;
    if (c->secret_key && *c->secret_key) {
      free(c->secret_key);
      c->secret_key = buckets_xstrdup(BUCKETS_BATCH_REDACTED);
    }
    if (c->session_token && *c->session_token) {
      free(c->session_token);
      c->session_token = buckets_xstrdup(BUCKETS_BATCH_REDACTED);
    }
  }
  if (j->expire && j->expire->notify.token && *j->expire->notify.token) {
    free(j->expire->notify.token);
    j->expire->notify.token = buckets_xstrdup(BUCKETS_BATCH_REDACTED);
  }
}

void buckets_batch_job_defaults(buckets_batch_job *j) {
  if (!j->replicate) return;
  buckets_batch_snowball *s = &j->replicate->source.snowball;
  if (s->disable < 0) s->disable = 0;
  if (!s->has_batch) s->has_batch = true, s->batch = 100;
  if (s->inmemory < 0) s->inmemory = 1;
  if (s->compress < 0) s->compress = 0;
  if (!s->smaller_than) s->smaller_than = buckets_xstrdup("5MiB");
  if (s->skip_errs < 0) s->skip_errs = 1;
}

/* ---- units ----------------------------------------------------------------------------------------- */

bool buckets_humanize_parse_bytes(const char *s, uint64_t *out, char *err, size_t errlen) {
  static const struct {
    const char *name;
    double mult;
  } table[] = {
      {"b", 1},          {"kib", 1024.0},        {"kb", 1e3},    {"mib", 1048576.0},      {"mb", 1e6},
      {"gib", 1073741824.0}, {"gb", 1e9},      {"tib", 1099511627776.0}, {"tb", 1e12}, {"pib", 1125899906842624.0},
      {"pb", 1e15},      {"eib", 1152921504606846976.0}, {"eb", 1e18}, {"", 1},        {"ki", 1024.0},
      {"k", 1e3},        {"mi", 1048576.0},       {"m", 1e6},     {"gi", 1073741824.0}, {"g", 1e9},
      {"ti", 1099511627776.0}, {"t", 1e12},     {"pi", 1125899906842624.0}, {"p", 1e15},
      {"ei", 1152921504606846976.0}, {"e", 1e18},
  };
  size_t last = 0;
  char num[64];
  size_t nn = 0;
  for (; s[last] && (isdigit((unsigned char)s[last]) || s[last] == '.' || s[last] == ','); last++)
    if (s[last] != ',' && nn + 1 < sizeof(num)) num[nn++] = s[last];
  num[nn] = 0;
  char *end;
  double f = nn ? strtod(num, &end) : 0;
  if (!nn || *end) {
    snprintf(err, errlen, "strconv.ParseFloat: parsing \"%s\": invalid syntax", num);
    return false;
  }
  char extra[32];
  const char *e = s + last;
  while (*e && isspace((unsigned char)*e)) e++;
  size_t en = strlen(e);
  while (en && isspace((unsigned char)e[en - 1])) en--;
  if (en >= sizeof(extra)) en = sizeof(extra) - 1;
  for (size_t i = 0; i < en; i++) extra[i] = (char)tolower((unsigned char)e[i]);
  extra[en] = 0;
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(table); i++) {
    if (strcmp(extra, table[i].name) != 0) continue;
    f *= table[i].mult;
    if (f >= 18446744073709551615.0) {
      snprintf(err, errlen, "too large: %s", s);
      return false;
    }
    *out = (uint64_t)f;
    return true;
  }
  snprintf(err, errlen, "unhandled size name: %s", extra);
  return false;
}

bool buckets_xtime_parse_duration(const char *orig, int64_t *ns, char *err, size_t errlen) {
  if (buckets_go_duration_parse(orig, ns)) return true;
  static const struct {
    const char *u;
    int64_t mult;
  } units[] = {{"ns", 1LL},
               {"us", 1000LL},
               {"\xC2\xB5s", 1000LL},
               {"\xCE\xBCs", 1000LL},
               {"ms", 1000000LL},
               {"s", 1000000000LL},
               {"m", 60000000000LL},
               {"h", 3600000000000LL},
               {"d", 86400000000000LL},
               {"w", 604800000000000LL}};
  const char *s = orig;
  bool neg = false;
  if (*s == '-' || *s == '+') neg = *s++ == '-';
  if (strcmp(s, "0") == 0) {
    *ns = 0;
    return true;
  }
  if (!*s) goto invalid;
  int64_t d = 0;
  while (*s) {
    if (*s != '.' && !isdigit((unsigned char)*s)) goto invalid;
    int64_t v = 0;
    bool pre = false, post = false;
    while (isdigit((unsigned char)*s)) {
      if (v > (INT64_MAX - 9) / 10) goto invalid;
      v = v * 10 + (*s++ - '0');
      pre = true;
    }
    int64_t f = 0;
    double scale = 1;
    if (*s == '.') {
      s++;
      while (isdigit((unsigned char)*s)) {
        if (f < INT64_MAX / 10) f = f * 10 + (*s - '0'), scale *= 10;
        s++;
        post = true;
      }
    }
    if (!pre && !post) goto invalid;
    size_t i = 0;
    while (s[i] && s[i] != '.' && !isdigit((unsigned char)s[i])) i++;
    if (!i) {
      snprintf(err, errlen, "missing unit in duration \"%s\"", orig);
      return false;
    }
    int64_t mult = 0;
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(units); k++)
      if (strlen(units[k].u) == i && strncmp(s, units[k].u, i) == 0) mult = units[k].mult;
    if (!mult) {
      snprintf(err, errlen, "unknown unit \"%.*s\" in duration \"%s\"", (int)i, s, orig);
      return false;
    }
    s += i;
    if (v > INT64_MAX / mult) goto invalid;
    v *= mult;
    if (f > 0) {
      v += (int64_t)((double)f * ((double)mult / scale));
      if (v < 0) goto invalid;
    }
    d += v;
    if (d < 0) goto invalid;
  }
  *ns = neg ? -d : d;
  return true;
invalid:
  snprintf(err, errlen, "invalid duration \"%s\"", orig);
  return false;
}

/* ---- YAML decoding (yaml.v3 into MinIO's structs) ----------------------------------------------------- */

typedef buckets_yaml_dec ydec;
typedef buckets_yaml_node ynode;

/* A struct's node: false (a type error when not null) unless a mapping. */
static bool as_map(ydec *d, const ynode *n, const char *gotype) {
  if (buckets_yaml_is_null(n) || d->fatal) return false;
  if (n->kind != BUCKETS_YAML_MAP) {
    buckets_yaml_terror(d, n, gotype);
    return false;
  }
  return true;
}

#define GET(n, k) buckets_yaml_get((n), (k))

static void dec_int_field(ydec *d, const ynode *n, int64_t *out) { buckets_yaml_dec_int(d, n, out, "int"); }

/* xtime.Duration.UnmarshalYAML */
static void dec_xduration(ydec *d, const ynode *n, int64_t *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  if (n->kind != BUCKETS_YAML_SCALAR) {
    char msg[64];
    snprintf(msg, sizeof(msg), "unable to unmarshal %s", n->tag);
    buckets_yaml_fail(d, msg);
    return;
  }
  char err[256];
  if (!buckets_xtime_parse_duration(n->value, out, err, sizeof(err))) buckets_yaml_fail(d, err);
}

/* BatchJobSize.UnmarshalYAML: a string humanize.ParseBytes takes */
static void dec_size(ydec *d, const ynode *n, int64_t *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  char *s = NULL;
  size_t before = d->terrors.len;
  buckets_yaml_dec_str(d, n, &s);
  if (d->terrors.len != before || !s) {
    free(s);
    return;
  }
  uint64_t v;
  char err[256];
  if (!buckets_humanize_parse_bytes(s, &v, err, sizeof(err))) buckets_yaml_fail(d, err);
  else *out = (int64_t)v;
  free(s);
}

static void dec_kvs(ydec *d, const ynode *n, buckets_batch_kvs *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  if (n->kind != BUCKETS_YAML_SEQ) {
    buckets_yaml_terror(d, n, "[]cmd.BatchJobKV");
    return;
  }
  kvs_free(out);
  out->v = buckets_xcalloc(n->n + 1, sizeof(*out->v));
  for (size_t i = 0; i < n->n; i++) {
    const ynode *it = n->items[i];
    buckets_batch_kv *kv = &out->v[out->n++];
    if (!as_map(d, it, "cmd.jobKV")) continue;
    buckets_yaml_dec_str(d, GET(it, "key"), &kv->key);
    buckets_yaml_dec_str(d, GET(it, "value"), &kv->value);
    kv->line = it->line;
    kv->col = it->col;
  }
}

static void dec_notify(ydec *d, const ynode *n, buckets_batch_notify *out) {
  if (!as_map(d, n, "cmd.notification")) return;
  buckets_yaml_dec_str(d, GET(n, "endpoint"), &out->endpoint);
  buckets_yaml_dec_str(d, GET(n, "token"), &out->token);
  out->line = n->line;
  out->col = n->col;
}

static void dec_retry(ydec *d, const ynode *n, buckets_batch_retry *out) {
  if (!as_map(d, n, "cmd.retry")) return;
  dec_int_field(d, GET(n, "attempts"), &out->attempts);
  buckets_yaml_dec_duration(d, GET(n, "delay"), &out->delay_ns);
  out->line = n->line;
  out->col = n->col;
}

static void dec_creds(ydec *d, const ynode *n, buckets_batch_creds *out) {
  if (!as_map(d, n, "cmd.BatchJobReplicateCredentials")) return;
  buckets_yaml_dec_str(d, GET(n, "accessKey"), &out->access_key);
  buckets_yaml_dec_str(d, GET(n, "secretKey"), &out->secret_key);
  buckets_yaml_dec_str(d, GET(n, "sessionToken"), &out->session_token);
}

/* BatchJobPrefix.UnmarshalYAML: a list of strings, or one string */
static void dec_prefix(ydec *d, const ynode *n, buckets_batch_strs *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  strs_free(out);
  if (n->kind == BUCKETS_YAML_SEQ) {
    bool ok = true;
    for (size_t i = 0; i < n->n; i++) ok &= n->items[i]->kind == BUCKETS_YAML_SCALAR;
    if (ok) {
      out->v = buckets_xcalloc(n->n + 1, sizeof(char *));
      for (size_t i = 0; i < n->n; i++)
        out->v[out->n++] = buckets_xstrdup(buckets_yaml_is_null(n->items[i]) ? "" : n->items[i]->value);
      return;
    }
  } else if (n->kind == BUCKETS_YAML_SCALAR) {
    out->v = buckets_xcalloc(2, sizeof(char *));
    out->v[out->n++] = buckets_xstrdup(n->value);
    return;
  }
  char msg[512];
  snprintf(msg, sizeof(msg), "unable to decode %s", n->kind == BUCKETS_YAML_SCALAR ? n->value : "");
  buckets_yaml_fail(d, msg);
}

static void dec_bool_ptr(ydec *d, const ynode *n, signed char *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  bool b = false;
  size_t before = d->terrors.len;
  buckets_yaml_dec_bool(d, n, &b);
  if (d->terrors.len == before) *out = b;
}

static void dec_snowball(ydec *d, const ynode *n, buckets_batch_snowball *out) {
  if (!as_map(d, n, "cmd.snowball")) return;
  dec_bool_ptr(d, GET(n, "disable"), &out->disable);
  const ynode *b = GET(n, "batch");
  if (!buckets_yaml_is_null(b)) {
    size_t before = d->terrors.len;
    int64_t v = 0;
    dec_int_field(d, b, &v);
    if (d->terrors.len == before) out->has_batch = true, out->batch = v;
  }
  dec_bool_ptr(d, GET(n, "inmemory"), &out->inmemory);
  dec_bool_ptr(d, GET(n, "compress"), &out->compress);
  buckets_yaml_dec_str(d, GET(n, "smallerThan"), &out->smaller_than);
  dec_bool_ptr(d, GET(n, "skipErrs"), &out->skip_errs);
  out->line = n->line;
  out->col = n->col;
}

static void dec_time(ydec *d, const ynode *n, buckets_batch_time *t) {
  buckets_yaml_dec_time(d, n, &t->sec, &t->nsec, &t->set);
}

static void dec_replicate(ydec *d, const ynode *n, buckets_batch_replicate *r) {
  if (!as_map(d, n, "cmd.BatchJobReplicateV1")) return;
  buckets_yaml_dec_str(d, GET(n, "apiVersion"), &r->api_version);
  const ynode *fl = GET(n, "flags");
  if (as_map(d, fl, "cmd.BatchJobReplicateFlags")) {
    const ynode *f = GET(fl, "filter");
    if (as_map(d, f, "cmd.BatchReplicateFilter")) {
      dec_xduration(d, GET(f, "newerThan"), &r->flags.filter.newer_than_ns);
      dec_xduration(d, GET(f, "olderThan"), &r->flags.filter.older_than_ns);
      dec_time(d, GET(f, "createdAfter"), &r->flags.filter.created_after);
      dec_time(d, GET(f, "createdBefore"), &r->flags.filter.created_before);
      dec_kvs(d, GET(f, "tags"), &r->flags.filter.tags);
      dec_kvs(d, GET(f, "metadata"), &r->flags.filter.metadata);
    }
    dec_notify(d, GET(fl, "notify"), &r->flags.notify);
    dec_retry(d, GET(fl, "retry"), &r->flags.retry);
  }
  const ynode *t = GET(n, "target");
  if (as_map(d, t, "cmd.BatchJobReplicateTarget")) {
    buckets_yaml_dec_str(d, GET(t, "type"), &r->target.type);
    buckets_yaml_dec_str(d, GET(t, "bucket"), &r->target.bucket);
    buckets_yaml_dec_str(d, GET(t, "prefix"), &r->target.prefix);
    buckets_yaml_dec_str(d, GET(t, "endpoint"), &r->target.endpoint);
    buckets_yaml_dec_str(d, GET(t, "path"), &r->target.path);
    dec_creds(d, GET(t, "credentials"), &r->target.creds);
  }
  const ynode *s = GET(n, "source");
  if (as_map(d, s, "cmd.BatchJobReplicateSource")) {
    buckets_yaml_dec_str(d, GET(s, "type"), &r->source.type);
    buckets_yaml_dec_str(d, GET(s, "bucket"), &r->source.bucket);
    dec_prefix(d, GET(s, "prefix"), &r->source.prefix);
    buckets_yaml_dec_str(d, GET(s, "endpoint"), &r->source.endpoint);
    buckets_yaml_dec_str(d, GET(s, "path"), &r->source.path);
    dec_creds(d, GET(s, "credentials"), &r->source.creds);
    dec_snowball(d, GET(s, "snowball"), &r->source.snowball);
  }
}

static void dec_keyrotate(ydec *d, const ynode *n, buckets_batch_keyrotate *k) {
  if (!as_map(d, n, "cmd.BatchJobKeyRotateV1")) return;
  buckets_yaml_dec_str(d, GET(n, "apiVersion"), &k->api_version);
  const ynode *fl = GET(n, "flags");
  if (as_map(d, fl, "cmd.BatchJobKeyRotateFlags")) {
    const ynode *f = GET(fl, "filter");
    if (as_map(d, f, "cmd.BatchKeyRotateFilter")) {
      buckets_yaml_dec_duration(d, GET(f, "newerThan"), &k->flags.filter.newer_than_ns);
      buckets_yaml_dec_duration(d, GET(f, "olderThan"), &k->flags.filter.older_than_ns);
      dec_time(d, GET(f, "createdAfter"), &k->flags.filter.created_after);
      dec_time(d, GET(f, "createdBefore"), &k->flags.filter.created_before);
      dec_kvs(d, GET(f, "tags"), &k->flags.filter.tags);
      dec_kvs(d, GET(f, "metadata"), &k->flags.filter.metadata);
      buckets_yaml_dec_str(d, GET(f, "kmskeyid"), &k->flags.filter.kms_key_id);
    }
    dec_notify(d, GET(fl, "notify"), &k->flags.notify);
    dec_retry(d, GET(fl, "retry"), &k->flags.retry);
  }
  buckets_yaml_dec_str(d, GET(n, "bucket"), &k->bucket);
  buckets_yaml_dec_str(d, GET(n, "prefix"), &k->prefix);
  const ynode *e = GET(n, "encryption");
  if (as_map(d, e, "cmd.BatchJobKeyRotateEncryption")) {
    buckets_yaml_dec_str(d, GET(e, "type"), &k->enc_type);
    buckets_yaml_dec_str(d, GET(e, "key"), &k->enc_key);
    buckets_yaml_dec_str(d, GET(e, "context"), &k->enc_context);
    buckets_yaml_dec_bool(d, GET(e, "includeUnencrypted"), &k->include_unencrypted);
    buckets_yaml_dec_bool(d, GET(e, "onlyUnencrypted"), &k->only_unencrypted);
  }
}

static void dec_rule(ydec *d, const ynode *n, buckets_batch_expire_rule *r) {
  if (!as_map(d, n, "cmd.expFilter")) return;
  r->line = n->line;
  r->col = n->col;
  dec_xduration(d, GET(n, "olderThan"), &r->older_than_ns);
  dec_time(d, GET(n, "createdBefore"), &r->created_before);
  dec_kvs(d, GET(n, "tags"), &r->tags);
  dec_kvs(d, GET(n, "metadata"), &r->metadata);
  const ynode *sz = GET(n, "size");
  if (as_map(d, sz, "cmd.sizeFilter")) {
    r->size_line = sz->line;
    r->size_col = sz->col;
    dec_size(d, GET(sz, "lessThan"), &r->size_lt);
    dec_size(d, GET(sz, "greaterThan"), &r->size_gt);
  }
  buckets_yaml_dec_str(d, GET(n, "type"), &r->type);
  buckets_yaml_dec_str(d, GET(n, "name"), &r->name);
  const ynode *p = GET(n, "purge");
  if (as_map(d, p, "cmd.purge")) {
    r->purge_line = p->line;
    r->purge_col = p->col;
    dec_int_field(d, GET(p, "retainVersions"), &r->retain_versions);
  }
}

static void dec_expire(ydec *d, const ynode *n, buckets_batch_expire *e) {
  if (!as_map(d, n, "cmd.expireJob")) return;
  e->line = n->line;
  e->col = n->col;
  buckets_yaml_dec_str(d, GET(n, "apiVersion"), &e->api_version);
  buckets_yaml_dec_str(d, GET(n, "bucket"), &e->bucket);
  dec_prefix(d, GET(n, "prefix"), &e->prefix);
  dec_notify(d, GET(n, "notify"), &e->notify);
  dec_retry(d, GET(n, "retry"), &e->retry);
  const ynode *rules = GET(n, "rules");
  if (!buckets_yaml_is_null(rules)) {
    if (rules->kind != BUCKETS_YAML_SEQ) {
      buckets_yaml_terror(d, rules, "[]cmd.BatchJobExpireFilter");
    } else {
      e->rules = buckets_xcalloc(rules->n + 1, sizeof(*e->rules));
      for (size_t i = 0; i < rules->n; i++) dec_rule(d, rules->items[i], &e->rules[e->nrules++]);
    }
  }
}

static void snowball_unset(buckets_batch_snowball *s) {
  s->disable = s->inmemory = s->compress = s->skip_errs = -1;
}

bool buckets_batch_job_parse(const char *yaml, size_t n, buckets_batch_job *out, char **err) {
  memset(out, 0, sizeof(*out));
  *err = NULL;
  char perr[512];
  buckets_yaml_node *root = buckets_yaml_parse(yaml, n, perr, sizeof(perr));
  if (!root) {
    *err = buckets_xstrdup(perr);
    return false;
  }
  ydec d = {0};
  if (as_map(&d, root, "cmd.BatchJobRequest")) {
    const ynode *r = GET(root, "replicate"), *k = GET(root, "keyrotate"), *e = GET(root, "expire");
    if (!buckets_yaml_is_null(r)) {
      out->replicate = buckets_xcalloc(1, sizeof(*out->replicate));
      snowball_unset(&out->replicate->source.snowball);
      dec_replicate(&d, r, out->replicate);
    }
    if (!buckets_yaml_is_null(k)) {
      out->keyrotate = buckets_xcalloc(1, sizeof(*out->keyrotate));
      dec_keyrotate(&d, k, out->keyrotate);
    }
    if (!buckets_yaml_is_null(e)) {
      out->expire = buckets_xcalloc(1, sizeof(*out->expire));
      dec_expire(&d, e, out->expire);
    }
  }
  buckets_yaml_free(root);
  *err = buckets_yaml_dec_error(&d);
  buckets_yaml_dec_free(&d);
  if (*err) {
    buckets_batch_job_free(out);
    return false;
  }
  return true;
}

/* ---- validation ------------------------------------------------------------------------------------------ */

static bool yaml_err(buckets_batch_err *e, int line, int col, const char *msg) {
  e->code = "InternalError";
  e->internal = true;
  e->status = 500;
  snprintf(e->desc, sizeof(e->desc), "%s\n Hint: error near line: %d, col: %d", msg, line, col);
  return false;
}

bool buckets_batch_kv_validate(const buckets_batch_kv *kv, buckets_batch_err *e) {
  if (!kv->key || !*kv->key) return yaml_err(e, kv->line, kv->col, "key can't be empty");
  return true;
}

bool buckets_batch_retry_validate(const buckets_batch_retry *r, buckets_batch_err *e) {
  if (r->attempts < 0 || r->delay_ns < 0) return yaml_err(e, r->line, r->col, "Invalid arguments specified");
  return true;
}

bool buckets_batch_snowball_validate(const buckets_batch_snowball *s, buckets_batch_err *e) {
  if (!s->has_batch || s->batch <= 0)
    return yaml_err(e, s->line, s->col, "batch number should be non positive zero");
  uint64_t v;
  char err[256];
  if (!buckets_humanize_parse_bytes(s->smaller_than ? s->smaller_than : "", &v, err, sizeof(err)))
    return yaml_err(e, s->line, s->col, err);
  return true;
}

bool buckets_batch_expire_rule_validate(const buckets_batch_expire_rule *r, int64_t now_sec, buckets_batch_err *e) {
  const char *t = r->type ? r->type : "";
  if (strcmp(t, "object") == 0) {
  } else if (strcmp(t, "deleted") == 0) {
    if (r->tags.n || r->metadata.n) return yaml_err(e, r->line, r->col, "delete type filter can't have tags or metadata");
  } else {
    return yaml_err(e, r->line, r->col, "invalid batch-expire type");
  }
  for (size_t i = 0; i < r->tags.n; i++)
    if (!buckets_batch_kv_validate(&r->tags.v[i], e)) return false;
  for (size_t i = 0; i < r->metadata.n; i++)
    if (!buckets_batch_kv_validate(&r->metadata.v[i], e)) return false;
  if (r->retain_versions < 0) return yaml_err(e, r->purge_line, r->purge_col, "retainVersions must be >= 0");
  if (r->size_gt > 0 && r->size_lt > 0 && r->size_gt >= r->size_lt)
    return yaml_err(e, r->size_line, r->size_col, "invalid batch-job size filter");
  if (r->created_before.set && r->created_before.sec >= now_sec)
    return yaml_err(e, r->line, r->col, "CreatedBefore is in the future");
  return true;
}

bool buckets_batch_kv_match(const buckets_batch_kv *kv, const char *key, const char *value) {
  const char *k = kv->key ? kv->key : "", *v = kv->value ? kv->value : "";
  if (!*k && !*v) return true;
  if (strcasecmp(k, key) == 0) return buckets_wildcard_match(v, value);
  return false;
}

/* ---- msgp (job.bin) ---------------------------------------------------------------------------------------- */

static void mp_str(buckets_buf *b, const char *s) { buckets_mp_cstr(b, s ? s : ""); }
static void mp_key(buckets_buf *b, const char *k) { buckets_mp_cstr(b, k); }

static void mp_time(buckets_buf *b, const buckets_batch_time *t) {
  if (t->set) buckets_mp_time_sec(b, t->sec, t->nsec);
  else buckets_mp_time_sec(b, GO_ZERO_SEC, 0);
}

static void mp_kvs(buckets_buf *b, const buckets_batch_kvs *k) {
  buckets_mp_array(b, (uint32_t)k->n);
  for (size_t i = 0; i < k->n; i++) {
    buckets_mp_map(b, 2);
    mp_key(b, "Key");
    mp_str(b, k->v[i].key);
    mp_key(b, "Value");
    mp_str(b, k->v[i].value);
  }
}

static void mp_notify(buckets_buf *b, const buckets_batch_notify *n) {
  buckets_mp_map(b, 2);
  mp_key(b, "Endpoint");
  mp_str(b, n->endpoint);
  mp_key(b, "Token");
  mp_str(b, n->token);
}

static void mp_retry(buckets_buf *b, const buckets_batch_retry *r) {
  buckets_mp_map(b, 2);
  mp_key(b, "Attempts");
  buckets_mp_int(b, r->attempts);
  mp_key(b, "Delay");
  buckets_mp_int(b, r->delay_ns);
}

static void mp_creds(buckets_buf *b, const buckets_batch_creds *c) {
  buckets_mp_map(b, 3);
  mp_key(b, "AccessKey");
  mp_str(b, c->access_key);
  mp_key(b, "SecretKey");
  mp_str(b, c->secret_key);
  mp_key(b, "SessionToken");
  mp_str(b, c->session_token);
}

static void mp_strs(buckets_buf *b, const buckets_batch_strs *s) {
  buckets_mp_array(b, (uint32_t)s->n);
  for (size_t i = 0; i < s->n; i++) mp_str(b, s->v[i]);
}

static void mp_optbool(buckets_buf *b, signed char v) {
  if (v < 0) buckets_mp_nil(b);
  else buckets_mp_bool(b, v != 0);
}

static void mp_filter(buckets_buf *b, const buckets_batch_filter *f, bool keyrotate) {
  buckets_mp_map(b, keyrotate ? 7 : 6);
  mp_key(b, "NewerThan");
  buckets_mp_int(b, f->newer_than_ns);
  mp_key(b, "OlderThan");
  buckets_mp_int(b, f->older_than_ns);
  mp_key(b, "CreatedAfter");
  mp_time(b, &f->created_after);
  mp_key(b, "CreatedBefore");
  mp_time(b, &f->created_before);
  mp_key(b, "Tags");
  mp_kvs(b, &f->tags);
  mp_key(b, "Metadata");
  mp_kvs(b, &f->metadata);
  if (keyrotate) {
    mp_key(b, "KMSKeyID");
    mp_str(b, f->kms_key_id);
  }
}

static void mp_flags(buckets_buf *b, const buckets_batch_flags *f, bool keyrotate) {
  buckets_mp_map(b, 3);
  mp_key(b, "Filter");
  mp_filter(b, &f->filter, keyrotate);
  mp_key(b, "Notify");
  mp_notify(b, &f->notify);
  mp_key(b, "Retry");
  mp_retry(b, &f->retry);
}

static void mp_replicate(buckets_buf *b, const buckets_batch_replicate *r) {
  buckets_mp_map(b, 4);
  mp_key(b, "APIVersion");
  mp_str(b, r->api_version);
  mp_key(b, "Flags");
  mp_flags(b, &r->flags, false);
  mp_key(b, "Target");
  buckets_mp_map(b, 6);
  mp_key(b, "Type");
  mp_str(b, r->target.type);
  mp_key(b, "Bucket");
  mp_str(b, r->target.bucket);
  mp_key(b, "Prefix");
  mp_str(b, r->target.prefix);
  mp_key(b, "Endpoint");
  mp_str(b, r->target.endpoint);
  mp_key(b, "Path");
  mp_str(b, r->target.path);
  mp_key(b, "Creds");
  mp_creds(b, &r->target.creds);
  mp_key(b, "Source");
  buckets_mp_map(b, 7);
  mp_key(b, "Type");
  mp_str(b, r->source.type);
  mp_key(b, "Bucket");
  mp_str(b, r->source.bucket);
  mp_key(b, "Prefix");
  mp_strs(b, &r->source.prefix);
  mp_key(b, "Endpoint");
  mp_str(b, r->source.endpoint);
  mp_key(b, "Path");
  mp_str(b, r->source.path);
  mp_key(b, "Creds");
  mp_creds(b, &r->source.creds);
  mp_key(b, "Snowball");
  const buckets_batch_snowball *s = &r->source.snowball;
  buckets_mp_map(b, 6);
  mp_key(b, "Disable");
  mp_optbool(b, s->disable);
  mp_key(b, "Batch");
  if (s->has_batch) buckets_mp_int(b, s->batch);
  else buckets_mp_nil(b);
  mp_key(b, "InMemory");
  mp_optbool(b, s->inmemory);
  mp_key(b, "Compress");
  mp_optbool(b, s->compress);
  mp_key(b, "SmallerThan");
  if (s->smaller_than) mp_str(b, s->smaller_than);
  else buckets_mp_nil(b);
  mp_key(b, "SkipErrs");
  mp_optbool(b, s->skip_errs);
}

static void mp_keyrotate(buckets_buf *b, const buckets_batch_keyrotate *k) {
  buckets_mp_map(b, 5);
  mp_key(b, "APIVersion");
  mp_str(b, k->api_version);
  mp_key(b, "Flags");
  mp_flags(b, &k->flags, true);
  mp_key(b, "Bucket");
  mp_str(b, k->bucket);
  mp_key(b, "Prefix");
  mp_str(b, k->prefix);
  mp_key(b, "Encryption");
  buckets_mp_map(b, 3 + k->include_unencrypted + k->only_unencrypted); /* as MinIO's, unless the extension is used */
  mp_key(b, "Type");
  mp_str(b, k->enc_type);
  mp_key(b, "Key");
  mp_str(b, k->enc_key);
  mp_key(b, "Context");
  mp_str(b, k->enc_context);
  if (k->include_unencrypted) {
    mp_key(b, "IncludeUnencrypted");
    buckets_mp_bool(b, true);
  }
  if (k->only_unencrypted) {
    mp_key(b, "OnlyUnencrypted");
    buckets_mp_bool(b, true);
  }
}

static void mp_expire(buckets_buf *b, const buckets_batch_expire *e) {
  buckets_mp_map(b, 6);
  mp_key(b, "APIVersion");
  mp_str(b, e->api_version);
  mp_key(b, "Bucket");
  mp_str(b, e->bucket);
  mp_key(b, "Prefix");
  mp_strs(b, &e->prefix);
  mp_key(b, "NotificationCfg");
  mp_notify(b, &e->notify);
  mp_key(b, "Retry");
  mp_retry(b, &e->retry);
  mp_key(b, "Rules");
  buckets_mp_array(b, (uint32_t)e->nrules);
  for (size_t i = 0; i < e->nrules; i++) {
    const buckets_batch_expire_rule *r = &e->rules[i];
    buckets_mp_map(b, 8);
    mp_key(b, "OlderThan");
    buckets_mp_int(b, r->older_than_ns);
    mp_key(b, "CreatedBefore");
    if (r->created_before.set) buckets_mp_time_sec(b, r->created_before.sec, r->created_before.nsec);
    else buckets_mp_nil(b);
    mp_key(b, "Tags");
    mp_kvs(b, &r->tags);
    mp_key(b, "Metadata");
    mp_kvs(b, &r->metadata);
    mp_key(b, "Size");
    buckets_mp_map(b, 2);
    mp_key(b, "UpperBound");
    buckets_mp_int(b, r->size_lt);
    mp_key(b, "LowerBound");
    buckets_mp_int(b, r->size_gt);
    mp_key(b, "Type");
    mp_str(b, r->type);
    mp_key(b, "Name");
    mp_str(b, r->name);
    mp_key(b, "Purge");
    buckets_mp_map(b, 1);
    mp_key(b, "RetainVersions");
    buckets_mp_int(b, r->retain_versions);
  }
}

void buckets_batch_job_msgp(const buckets_batch_job *j, buckets_buf *out) {
  buckets_mp_map(out, 6);
  mp_key(out, "ID");
  mp_str(out, j->id);
  mp_key(out, "User");
  mp_str(out, j->user);
  mp_key(out, "Started");
  mp_time(out, &j->started);
  mp_key(out, "Replicate");
  if (j->replicate) mp_replicate(out, j->replicate);
  else buckets_mp_nil(out);
  mp_key(out, "KeyRotate");
  if (j->keyrotate) mp_keyrotate(out, j->keyrotate);
  else buckets_mp_nil(out);
  mp_key(out, "Expire");
  if (j->expire) mp_expire(out, j->expire);
  else buckets_mp_nil(out);
}

/* ---- msgp decoding: maps read by key, unknown keys skipped ---------------------------------------------------- */

typedef buckets_mp_reader mpr;

static bool rd_str(mpr *r, char **out) {
  if (buckets_mp_read_nil(r)) return true;
  buckets_str s;
  if (!buckets_mp_read_str(r, &s)) return false;
  free(*out);
  *out = buckets_xstrndup(s.p, s.n);
  return true;
}

static bool rd_time(mpr *r, buckets_batch_time *t) {
  if (buckets_mp_read_nil(r)) return true;
  int64_t sec;
  int32_t nsec;
  if (!buckets_mp_read_time_sec(r, &sec, &nsec)) return false;
  t->sec = sec;
  t->nsec = nsec;
  t->set = !(sec == GO_ZERO_SEC && nsec == 0);
  return true;
}

static bool rd_int(mpr *r, int64_t *v) { return buckets_mp_read_nil(r) || buckets_mp_read_int(r, v); }

/* Iterates a map: key in *k; false at the end or on errors (*ok). */
#define MAP_EACH(r, ok, k, body)                                         \
  do {                                                                   \
    uint32_t n_##k;                                                      \
    if (buckets_mp_read_nil(r)) break;                                   \
    if (!buckets_mp_read_map(r, &n_##k)) {                               \
      ok = false;                                                        \
      break;                                                             \
    }                                                                    \
    for (uint32_t i_##k = 0; i_##k < n_##k && ok; i_##k++) {             \
      buckets_str k;                                                     \
      if (!buckets_mp_read_str(r, &k)) {                                 \
        ok = false;                                                      \
        break;                                                           \
      }                                                                  \
      body                                                               \
    }                                                                    \
  } while (0)

#define IS(k, lit) buckets_str_eq_c((k), (lit))

static bool rd_kvs(mpr *r, buckets_batch_kvs *out) {
  if (buckets_mp_read_nil(r)) return true;
  uint32_t n;
  if (!buckets_mp_read_array(r, &n) || n > buckets_mp_remaining(r)) return false;
  kvs_free(out);
  out->v = buckets_xcalloc(n + 1, sizeof(*out->v));
  bool ok = true;
  for (uint32_t i = 0; i < n && ok; i++) {
    buckets_batch_kv *kv = &out->v[out->n++];
    MAP_EACH(r, ok, k, {
      if (IS(k, "Key")) ok = rd_str(r, &kv->key);
      else if (IS(k, "Value")) ok = rd_str(r, &kv->value);
      else ok = buckets_mp_skip(r);
    });
  }
  return ok;
}

static bool rd_notify(mpr *r, buckets_batch_notify *n) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "Endpoint")) ok = rd_str(r, &n->endpoint);
    else if (IS(k, "Token")) ok = rd_str(r, &n->token);
    else ok = buckets_mp_skip(r);
  });
  return ok;
}

static bool rd_retry(mpr *r, buckets_batch_retry *t) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "Attempts")) ok = rd_int(r, &t->attempts);
    else if (IS(k, "Delay")) ok = rd_int(r, &t->delay_ns);
    else ok = buckets_mp_skip(r);
  });
  return ok;
}

static bool rd_creds(mpr *r, buckets_batch_creds *c) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "AccessKey")) ok = rd_str(r, &c->access_key);
    else if (IS(k, "SecretKey")) ok = rd_str(r, &c->secret_key);
    else if (IS(k, "SessionToken")) ok = rd_str(r, &c->session_token);
    else ok = buckets_mp_skip(r);
  });
  return ok;
}

static bool rd_strs(mpr *r, buckets_batch_strs *s) {
  if (buckets_mp_read_nil(r)) return true;
  uint32_t n;
  if (!buckets_mp_read_array(r, &n) || n > buckets_mp_remaining(r)) return false;
  strs_free(s);
  s->v = buckets_xcalloc(n + 1, sizeof(char *));
  for (uint32_t i = 0; i < n; i++) {
    s->v[s->n] = NULL;
    if (!rd_str(r, &s->v[s->n])) return false;
    if (!s->v[s->n]) s->v[s->n] = buckets_xstrdup("");
    s->n++;
  }
  return true;
}

static bool rd_optbool(mpr *r, signed char *v) {
  if (buckets_mp_read_nil(r)) {
    *v = -1;
    return true;
  }
  bool b;
  if (!buckets_mp_read_bool(r, &b)) return false;
  *v = b;
  return true;
}

static bool rd_filter(mpr *r, buckets_batch_filter *f) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "NewerThan")) ok = rd_int(r, &f->newer_than_ns);
    else if (IS(k, "OlderThan")) ok = rd_int(r, &f->older_than_ns);
    else if (IS(k, "CreatedAfter")) ok = rd_time(r, &f->created_after);
    else if (IS(k, "CreatedBefore")) ok = rd_time(r, &f->created_before);
    else if (IS(k, "Tags")) ok = rd_kvs(r, &f->tags);
    else if (IS(k, "Metadata")) ok = rd_kvs(r, &f->metadata);
    else if (IS(k, "KMSKeyID")) ok = rd_str(r, &f->kms_key_id);
    else ok = buckets_mp_skip(r);
  });
  return ok;
}

static bool rd_flags(mpr *r, buckets_batch_flags *f) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "Filter")) ok = rd_filter(r, &f->filter);
    else if (IS(k, "Notify")) ok = rd_notify(r, &f->notify);
    else if (IS(k, "Retry")) ok = rd_retry(r, &f->retry);
    else ok = buckets_mp_skip(r);
  });
  return ok;
}

static bool rd_replicate(mpr *r, buckets_batch_replicate *rp) {
  bool ok = true;
  snowball_unset(&rp->source.snowball);
  MAP_EACH(r, ok, k, {
    if (IS(k, "APIVersion")) {
      ok = rd_str(r, &rp->api_version);
    } else if (IS(k, "Flags")) {
      ok = rd_flags(r, &rp->flags);
    } else if (IS(k, "Target")) {
      buckets_batch_repl_target *t = &rp->target;
      MAP_EACH(r, ok, k2, {
        if (IS(k2, "Type")) ok = rd_str(r, &t->type);
        else if (IS(k2, "Bucket")) ok = rd_str(r, &t->bucket);
        else if (IS(k2, "Prefix")) ok = rd_str(r, &t->prefix);
        else if (IS(k2, "Endpoint")) ok = rd_str(r, &t->endpoint);
        else if (IS(k2, "Path")) ok = rd_str(r, &t->path);
        else if (IS(k2, "Creds")) ok = rd_creds(r, &t->creds);
        else ok = buckets_mp_skip(r);
      });
    } else if (IS(k, "Source")) {
      buckets_batch_repl_source *s = &rp->source;
      MAP_EACH(r, ok, k2, {
        if (IS(k2, "Type")) {
          ok = rd_str(r, &s->type);
        } else if (IS(k2, "Bucket")) {
          ok = rd_str(r, &s->bucket);
        } else if (IS(k2, "Prefix")) {
          ok = rd_strs(r, &s->prefix);
        } else if (IS(k2, "Endpoint")) {
          ok = rd_str(r, &s->endpoint);
        } else if (IS(k2, "Path")) {
          ok = rd_str(r, &s->path);
        } else if (IS(k2, "Creds")) {
          ok = rd_creds(r, &s->creds);
        } else if (IS(k2, "Snowball")) {
          buckets_batch_snowball *sb = &s->snowball;
          MAP_EACH(r, ok, k3, {
            if (IS(k3, "Disable")) {
              ok = rd_optbool(r, &sb->disable);
            } else if (IS(k3, "Batch")) {
              if (!buckets_mp_read_nil(r)) ok = sb->has_batch = buckets_mp_read_int(r, &sb->batch);
            } else if (IS(k3, "InMemory")) {
              ok = rd_optbool(r, &sb->inmemory);
            } else if (IS(k3, "Compress")) {
              ok = rd_optbool(r, &sb->compress);
            } else if (IS(k3, "SmallerThan")) {
              ok = rd_str(r, &sb->smaller_than);
            } else if (IS(k3, "SkipErrs")) {
              ok = rd_optbool(r, &sb->skip_errs);
            } else {
              ok = buckets_mp_skip(r);
            }
          });
        } else {
          ok = buckets_mp_skip(r);
        }
      });
    } else {
      ok = buckets_mp_skip(r);
    }
  });
  return ok;
}

static bool rd_keyrotate(mpr *r, buckets_batch_keyrotate *kr) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "APIVersion")) {
      ok = rd_str(r, &kr->api_version);
    } else if (IS(k, "Flags")) {
      ok = rd_flags(r, &kr->flags);
    } else if (IS(k, "Bucket")) {
      ok = rd_str(r, &kr->bucket);
    } else if (IS(k, "Prefix")) {
      ok = rd_str(r, &kr->prefix);
    } else if (IS(k, "Encryption")) {
      MAP_EACH(r, ok, k2, {
        if (IS(k2, "Type")) ok = rd_str(r, &kr->enc_type);
        else if (IS(k2, "Key")) ok = rd_str(r, &kr->enc_key);
        else if (IS(k2, "Context")) ok = rd_str(r, &kr->enc_context);
        else if (IS(k2, "IncludeUnencrypted")) ok = buckets_mp_read_nil(r) || buckets_mp_read_bool(r, &kr->include_unencrypted);
        else if (IS(k2, "OnlyUnencrypted")) ok = buckets_mp_read_nil(r) || buckets_mp_read_bool(r, &kr->only_unencrypted);
        else ok = buckets_mp_skip(r);
      });
    } else {
      ok = buckets_mp_skip(r);
    }
  });
  return ok;
}

static bool rd_rule(mpr *r, buckets_batch_expire_rule *ru) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "OlderThan")) {
      ok = rd_int(r, &ru->older_than_ns);
    } else if (IS(k, "CreatedBefore")) {
      ok = rd_time(r, &ru->created_before);
      if (ok && !ru->created_before.set && ru->created_before.sec == GO_ZERO_SEC) ru->created_before.set = true;
    } else if (IS(k, "Tags")) {
      ok = rd_kvs(r, &ru->tags);
    } else if (IS(k, "Metadata")) {
      ok = rd_kvs(r, &ru->metadata);
    } else if (IS(k, "Size")) {
      MAP_EACH(r, ok, k2, {
        if (IS(k2, "UpperBound")) ok = rd_int(r, &ru->size_lt);
        else if (IS(k2, "LowerBound")) ok = rd_int(r, &ru->size_gt);
        else ok = buckets_mp_skip(r);
      });
    } else if (IS(k, "Type")) {
      ok = rd_str(r, &ru->type);
    } else if (IS(k, "Name")) {
      ok = rd_str(r, &ru->name);
    } else if (IS(k, "Purge")) {
      MAP_EACH(r, ok, k2, {
        if (IS(k2, "RetainVersions")) ok = rd_int(r, &ru->retain_versions);
        else ok = buckets_mp_skip(r);
      });
    } else {
      ok = buckets_mp_skip(r);
    }
  });
  return ok;
}

static bool rd_expire(mpr *r, buckets_batch_expire *e) {
  bool ok = true;
  MAP_EACH(r, ok, k, {
    if (IS(k, "APIVersion")) {
      ok = rd_str(r, &e->api_version);
    } else if (IS(k, "Bucket")) {
      ok = rd_str(r, &e->bucket);
    } else if (IS(k, "Prefix")) {
      ok = rd_strs(r, &e->prefix);
    } else if (IS(k, "NotificationCfg")) {
      ok = rd_notify(r, &e->notify);
    } else if (IS(k, "Retry")) {
      ok = rd_retry(r, &e->retry);
    } else if (IS(k, "Rules")) {
      if (!buckets_mp_read_nil(r)) {
        uint32_t n;
        if (!buckets_mp_read_array(r, &n) || n > buckets_mp_remaining(r)) {
          ok = false;
        } else {
          e->rules = buckets_xcalloc(n + 1, sizeof(*e->rules));
          for (uint32_t i = 0; i < n && ok; i++) ok = rd_rule(r, &e->rules[e->nrules++]);
        }
      }
    } else {
      ok = buckets_mp_skip(r);
    }
  });
  return ok;
}

bool buckets_batch_job_from_msgp(const void *p, size_t n, buckets_batch_job *out) {
  memset(out, 0, sizeof(*out));
  mpr r = buckets_mp_reader_init(p, n);
  bool ok = true;
  MAP_EACH(&r, ok, k, {
    if (IS(k, "ID")) {
      ok = rd_str(&r, &out->id);
    } else if (IS(k, "User")) {
      ok = rd_str(&r, &out->user);
    } else if (IS(k, "Started")) {
      ok = rd_time(&r, &out->started);
    } else if (IS(k, "Replicate")) {
      if (!buckets_mp_read_nil(&r)) {
        out->replicate = buckets_xcalloc(1, sizeof(*out->replicate));
        ok = rd_replicate(&r, out->replicate);
      }
    } else if (IS(k, "KeyRotate")) {
      if (!buckets_mp_read_nil(&r)) {
        out->keyrotate = buckets_xcalloc(1, sizeof(*out->keyrotate));
        ok = rd_keyrotate(&r, out->keyrotate);
      }
    } else if (IS(k, "Expire")) {
      if (!buckets_mp_read_nil(&r)) {
        out->expire = buckets_xcalloc(1, sizeof(*out->expire));
        ok = rd_expire(&r, out->expire);
      }
    } else {
      ok = buckets_mp_skip(&r);
    }
  });
  if (!ok) buckets_batch_job_free(out);
  return ok;
}

/* ---- YAML (mc batch describe) ------------------------------------------------------------------------------------- */

typedef buckets_yaml_writer yw;

static void w_duration(yw *w, const char *key, int64_t ns, bool omitempty) {
  if (omitempty && !ns) return;
  char b[64];
  buckets_go_duration_string(ns, b, sizeof(b));
  buckets_yaml_w_raw(w, key, b);
}

static void w_time(yw *w, const char *key, const buckets_batch_time *t, bool omitempty) {
  if (omitempty && !t->set) return;
  char b[64];
  if (t->set) buckets_time_rfc3339_nano(t->sec, t->nsec, b);
  else snprintf(b, sizeof(b), "0001-01-01T00:00:00Z");
  buckets_yaml_w_raw(w, key, b);
}

static void w_kvs(yw *w, const char *key, const buckets_batch_kvs *k, bool omitempty) {
  if (omitempty && !k->n) return;
  buckets_yaml_w_seq(w, key, k->n);
  if (!k->n) return;
  for (size_t i = 0; i < k->n; i++) {
    buckets_yaml_w_item(w);
    buckets_yaml_w_str(w, "key", k->v[i].key);
    buckets_yaml_w_str(w, "value", k->v[i].value);
  }
  buckets_yaml_w_end(w);
}

static void w_strs(yw *w, const char *key, const buckets_batch_strs *s) {
  buckets_yaml_w_seq(w, key, s->n);
  if (!s->n) return;
  for (size_t i = 0; i < s->n; i++) buckets_yaml_w_seq_str(w, s->v[i]);
  buckets_yaml_w_end(w);
}

static void w_notify(yw *w, const buckets_batch_notify *n) {
  buckets_yaml_w_map(w, "notify");
  buckets_yaml_w_str(w, "endpoint", n->endpoint);
  buckets_yaml_w_str(w, "token", n->token);
  buckets_yaml_w_end(w);
}

static void w_retry(yw *w, const buckets_batch_retry *r) {
  buckets_yaml_w_map(w, "retry");
  buckets_yaml_w_int(w, "attempts", r->attempts);
  w_duration(w, "delay", r->delay_ns, false);
  buckets_yaml_w_end(w);
}

static void w_creds(yw *w, const buckets_batch_creds *c) {
  buckets_yaml_w_map(w, "credentials");
  buckets_yaml_w_str(w, "accessKey", c->access_key);
  buckets_yaml_w_str(w, "secretKey", c->secret_key);
  buckets_yaml_w_str(w, "sessionToken", c->session_token);
  buckets_yaml_w_end(w);
}

static void w_optbool(yw *w, const char *key, signed char v) {
  buckets_yaml_w_raw(w, key, v < 0 ? "null" : v ? "true" : "false");
}

/* filter: every field omitempty but keyrotate's kmskeyid; empty: "{}" */
static void w_filter(yw *w, const buckets_batch_filter *f, bool keyrotate) {
  bool empty = !f->newer_than_ns && !f->older_than_ns && !f->created_after.set && !f->created_before.set &&
               !f->tags.n && !f->metadata.n && !keyrotate;
  if (empty) {
    buckets_yaml_w_raw(w, "filter", "{}");
    return;
  }
  buckets_yaml_w_map(w, "filter");
  w_duration(w, "newerThan", f->newer_than_ns, true);
  w_duration(w, "olderThan", f->older_than_ns, true);
  w_time(w, "createdAfter", &f->created_after, true);
  w_time(w, "createdBefore", &f->created_before, true);
  w_kvs(w, "tags", &f->tags, true);
  w_kvs(w, "metadata", &f->metadata, true);
  if (keyrotate) buckets_yaml_w_str(w, "kmskeyid", f->kms_key_id);
  buckets_yaml_w_end(w);
}

static void w_flags(yw *w, const buckets_batch_flags *f, bool keyrotate) {
  buckets_yaml_w_map(w, "flags");
  w_filter(w, &f->filter, keyrotate);
  w_notify(w, &f->notify);
  w_retry(w, &f->retry);
  buckets_yaml_w_end(w);
}

void buckets_batch_job_yaml(const buckets_batch_job *j, buckets_buf *out) {
  yw w = {.out = out};
  if (!j->replicate) {
    buckets_yaml_w_raw(&w, "replicate", "null");
  } else {
    const buckets_batch_replicate *r = j->replicate;
    buckets_yaml_w_map(&w, "replicate");
    buckets_yaml_w_str(&w, "apiVersion", r->api_version);
    w_flags(&w, &r->flags, false);
    buckets_yaml_w_map(&w, "target");
    buckets_yaml_w_str(&w, "type", r->target.type);
    buckets_yaml_w_str(&w, "bucket", r->target.bucket);
    buckets_yaml_w_str(&w, "prefix", r->target.prefix);
    buckets_yaml_w_str(&w, "endpoint", r->target.endpoint);
    buckets_yaml_w_str(&w, "path", r->target.path);
    w_creds(&w, &r->target.creds);
    buckets_yaml_w_end(&w);
    buckets_yaml_w_map(&w, "source");
    buckets_yaml_w_str(&w, "type", r->source.type);
    buckets_yaml_w_str(&w, "bucket", r->source.bucket);
    w_strs(&w, "prefix", &r->source.prefix);
    buckets_yaml_w_str(&w, "endpoint", r->source.endpoint);
    buckets_yaml_w_str(&w, "path", r->source.path);
    w_creds(&w, &r->source.creds);
    const buckets_batch_snowball *s = &r->source.snowball;
    buckets_yaml_w_map(&w, "snowball");
    w_optbool(&w, "disable", s->disable);
    if (s->has_batch) buckets_yaml_w_int(&w, "batch", s->batch);
    else buckets_yaml_w_raw(&w, "batch", "null");
    w_optbool(&w, "inmemory", s->inmemory);
    w_optbool(&w, "compress", s->compress);
    if (s->smaller_than) buckets_yaml_w_str(&w, "smallerThan", s->smaller_than);
    else buckets_yaml_w_raw(&w, "smallerThan", "null");
    w_optbool(&w, "skipErrs", s->skip_errs);
    buckets_yaml_w_end(&w);
    buckets_yaml_w_end(&w);
    buckets_yaml_w_end(&w);
  }
  if (!j->keyrotate) {
    buckets_yaml_w_raw(&w, "keyrotate", "null");
  } else {
    const buckets_batch_keyrotate *k = j->keyrotate;
    buckets_yaml_w_map(&w, "keyrotate");
    buckets_yaml_w_str(&w, "apiVersion", k->api_version);
    w_flags(&w, &k->flags, true);
    buckets_yaml_w_str(&w, "bucket", k->bucket);
    buckets_yaml_w_str(&w, "prefix", k->prefix);
    buckets_yaml_w_map(&w, "encryption");
    buckets_yaml_w_str(&w, "type", k->enc_type);
    buckets_yaml_w_str(&w, "key", k->enc_key);
    buckets_yaml_w_str(&w, "context", k->enc_context);
    if (k->include_unencrypted) buckets_yaml_w_bool(&w, "includeUnencrypted", true);
    if (k->only_unencrypted) buckets_yaml_w_bool(&w, "onlyUnencrypted", true);
    buckets_yaml_w_end(&w);
    buckets_yaml_w_end(&w);
  }
  if (!j->expire) {
    buckets_yaml_w_raw(&w, "expire", "null");
  } else {
    const buckets_batch_expire *e = j->expire;
    buckets_yaml_w_map(&w, "expire");
    buckets_yaml_w_str(&w, "apiVersion", e->api_version);
    buckets_yaml_w_str(&w, "bucket", e->bucket);
    w_strs(&w, "prefix", &e->prefix);
    w_notify(&w, &e->notify);
    w_retry(&w, &e->retry);
    buckets_yaml_w_seq(&w, "rules", e->nrules);
    for (size_t i = 0; i < e->nrules; i++) {
      const buckets_batch_expire_rule *r = &e->rules[i];
      buckets_yaml_w_item(&w);
      w_duration(&w, "olderThan", r->older_than_ns, true);
      w_time(&w, "createdBefore", &r->created_before, true);
      w_kvs(&w, "tags", &r->tags, true);
      w_kvs(&w, "metadata", &r->metadata, true);
      buckets_yaml_w_map(&w, "size");
      buckets_yaml_w_int(&w, "lessThan", r->size_lt);
      buckets_yaml_w_int(&w, "greaterThan", r->size_gt);
      buckets_yaml_w_end(&w);
      buckets_yaml_w_str(&w, "type", r->type);
      buckets_yaml_w_str(&w, "name", r->name);
      buckets_yaml_w_map(&w, "purge");
      buckets_yaml_w_int(&w, "retainVersions", r->retain_versions);
      buckets_yaml_w_end(&w);
    }
    if (e->nrules) buckets_yaml_w_end(&w);
    buckets_yaml_w_end(&w);
  }
}

/* ---- reports ------------------------------------------------------------------------------------------------------ */

void buckets_batch_info_free(buckets_batch_info *ri) {
  free(ri->job_id);
  free(ri->job_type);
  free(ri->bucket);
  free(ri->object);
  memset(ri, 0, sizeof(*ri));
}

void buckets_batch_info_copy(buckets_batch_info *dst, const buckets_batch_info *src) {
  *dst = *src;
  dst->job_id = dupz(src->job_id);
  dst->job_type = dupz(src->job_type);
  dst->bucket = dupz(src->bucket);
  dst->object = dupz(src->object);
}

const char *buckets_batch_report_name(const char *job_type) {
  if (!job_type) return NULL;
  if (strcmp(job_type, "replicate") == 0) return "batch-replicate.bin";
  if (strcmp(job_type, "keyrotate") == 0) return "batch-rotate.bin";
  if (strcmp(job_type, "expire") == 0) return "batch-expire.bin";
  return NULL;
}

void buckets_batch_info_encode(const buckets_batch_info *ri, buckets_buf *out) {
  const uint8_t hdr[4] = {1, 0, 1, 0}; /* format 1, version 1, little endian */
  buckets_buf_append(out, hdr, sizeof(hdr));
  buckets_mp_map(out, 17);
  mp_key(out, "v");
  buckets_mp_int(out, ri->version);
  mp_key(out, "jid");
  mp_str(out, ri->job_id);
  mp_key(out, "jt");
  mp_str(out, ri->job_type);
  mp_key(out, "st");
  mp_time(out, &ri->start);
  mp_key(out, "lu");
  mp_time(out, &ri->last_update);
  mp_key(out, "ra");
  buckets_mp_int(out, ri->retry_attempts);
  mp_key(out, "at");
  buckets_mp_int(out, ri->attempts);
  mp_key(out, "cmp");
  buckets_mp_bool(out, ri->complete);
  mp_key(out, "fld");
  buckets_mp_bool(out, ri->failed);
  mp_key(out, "lbkt");
  mp_str(out, ri->bucket);
  mp_key(out, "lobj");
  mp_str(out, ri->object);
  mp_key(out, "ob");
  buckets_mp_int(out, ri->objects);
  mp_key(out, "dm");
  buckets_mp_int(out, ri->delete_markers);
  mp_key(out, "obf");
  buckets_mp_int(out, ri->objects_failed);
  mp_key(out, "dmf");
  buckets_mp_int(out, ri->delete_markers_failed);
  mp_key(out, "bt");
  buckets_mp_int(out, ri->bytes_transferred);
  mp_key(out, "bf");
  buckets_mp_int(out, ri->bytes_failed);
}

bool buckets_batch_info_decode(const char *file_name, const void *p, size_t n, buckets_batch_info *out, char *err,
                               size_t errlen) {
  memset(out, 0, sizeof(*out));
  const char *type = strcmp(file_name, "batch-replicate.bin") == 0 ? "replicate"
                     : strcmp(file_name, "batch-rotate.bin") == 0  ? "keyrotate"
                     : strcmp(file_name, "batch-expire.bin") == 0  ? "expire"
                                                                   : NULL;
  if (!type) {
    snprintf(err, errlen, "no supported batch job request specified");
    return false;
  }
  if (n == 0) return true;
  const uint8_t *b = p;
  if (n <= 4) {
    snprintf(err, errlen, "%s: no data", type);
    return false;
  }
  if ((b[0] | b[1] << 8) != 1) {
    snprintf(err, errlen, "%s: unknown format: %d", type, b[0] | b[1] << 8);
    return false;
  }
  if ((b[2] | b[3] << 8) != 1) {
    snprintf(err, errlen, "%s: unknown version: %d", type, b[2] | b[3] << 8);
    return false;
  }
  mpr r = buckets_mp_reader_init(b + 4, n - 4);
  bool ok = true;
  MAP_EACH(&r, ok, k, {
    if (IS(k, "v")) ok = rd_int(&r, &out->version);
    else if (IS(k, "jid")) ok = rd_str(&r, &out->job_id);
    else if (IS(k, "jt")) ok = rd_str(&r, &out->job_type);
    else if (IS(k, "st")) ok = rd_time(&r, &out->start);
    else if (IS(k, "lu")) ok = rd_time(&r, &out->last_update);
    else if (IS(k, "ra")) ok = rd_int(&r, &out->retry_attempts);
    else if (IS(k, "at")) ok = rd_int(&r, &out->attempts);
    else if (IS(k, "cmp")) ok = buckets_mp_read_bool(&r, &out->complete);
    else if (IS(k, "fld")) ok = buckets_mp_read_bool(&r, &out->failed);
    else if (IS(k, "lbkt")) ok = rd_str(&r, &out->bucket);
    else if (IS(k, "lobj")) ok = rd_str(&r, &out->object);
    else if (IS(k, "ob")) ok = rd_int(&r, &out->objects);
    else if (IS(k, "dm")) ok = rd_int(&r, &out->delete_markers);
    else if (IS(k, "obf")) ok = rd_int(&r, &out->objects_failed);
    else if (IS(k, "dmf")) ok = rd_int(&r, &out->delete_markers_failed);
    else if (IS(k, "bt")) ok = rd_int(&r, &out->bytes_transferred);
    else if (IS(k, "bf")) ok = rd_int(&r, &out->bytes_failed);
    else ok = buckets_mp_skip(&r);
  });
  if (!ok) {
    buckets_batch_info_free(out);
    snprintf(err, errlen, "%s: msgp decode error", type);
    return false;
  }
  if (out->version != 1) {
    snprintf(err, errlen, "unexpected batch %s meta version: %" PRId64, out->job_type ? out->job_type : "",
             out->version);
    buckets_batch_info_free(out);
    return false;
  }
  return true;
}

static void json_time(buckets_buf *b, const buckets_batch_time *t) {
  char s[64];
  if (t->set) buckets_time_rfc3339_nano(t->sec, t->nsec, s);
  else snprintf(s, sizeof(s), "0001-01-01T00:00:00Z");
  buckets_buf_appendf(b, "\"%s\"", s);
}

static void json_str(buckets_buf *b, const char *s) {
  buckets_buf_append_c(b, "\"");
  for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
    if (*p == '"' || *p == '\\') buckets_buf_appendf(b, "\\%c", *p);
    else if (*p < 0x20) buckets_buf_appendf(b, "\\u%04x", *p);
    else if (*p == '<' || *p == '>' || *p == '&') buckets_buf_appendf(b, "\\u%04x", *p);
    else buckets_buf_append(b, p, 1);
  }
  buckets_buf_append_c(b, "\"");
}

void buckets_batch_info_metric_json(const buckets_batch_info *ri, buckets_buf *b) {
  buckets_buf_append_c(b, "{\"jobID\":");
  json_str(b, ri->job_id);
  buckets_buf_append_c(b, ",\"jobType\":");
  json_str(b, ri->job_type);
  buckets_buf_append_c(b, ",\"startTime\":");
  json_time(b, &ri->start);
  buckets_buf_append_c(b, ",\"lastUpdate\":");
  json_time(b, &ri->last_update);
  buckets_buf_appendf(b, ",\"retryAttempts\":%" PRId64 ",\"complete\":%s,\"failed\":%s", ri->retry_attempts,
                      ri->complete ? "true" : "false", ri->failed ? "true" : "false");
  const char *t = ri->job_type ? ri->job_type : "";
  if (strcmp(t, "replicate") == 0 || strcmp(t, "keyrotate") == 0 || strcmp(t, "expire") == 0) {
    buckets_buf_appendf(b, ",\"%s\":{\"lastBucket\":",
                        t[0] == 'r' ? "replicate" : t[0] == 'k' ? "rotation" : "expired");
    json_str(b, ri->bucket);
    buckets_buf_append_c(b, ",\"lastObject\":");
    json_str(b, ri->object);
    buckets_buf_appendf(b, ",\"objects\":%" PRId64 ",\"objectsFailed\":%" PRId64, ri->objects, ri->objects_failed);
    if (t[0] != 'k')
      buckets_buf_appendf(b, ",\"deleteMarkers\":%" PRId64 ",\"deleteMarkersFailed\":%" PRId64, ri->delete_markers,
                          ri->delete_markers_failed);
    if (t[0] == 'r')
      buckets_buf_appendf(b, ",\"bytesTransferred\":%" PRId64 ",\"bytesFailed\":%" PRId64, ri->bytes_transferred,
                          ri->bytes_failed);
    buckets_buf_append_c(b, "}");
  }
  buckets_buf_append_c(b, "}");
}

void buckets_batch_info_count(buckets_batch_info *ri, int64_t size, bool dmarker, bool success, int attempt) {
  ri->attempts++;
  if (success) {
    if (dmarker) {
      ri->delete_markers++;
    } else {
      ri->objects++;
      ri->bytes_transferred += size;
    }
    if (attempt > 1) {
      if (dmarker) {
        ri->delete_markers_failed--;
      } else {
        ri->objects_failed--;
        ri->bytes_failed += size;
      }
    }
  } else {
    if (attempt > 1) return;
    if (dmarker) {
      ri->delete_markers_failed++;
    } else {
      ri->objects_failed++;
      ri->bytes_failed += size;
    }
  }
}
