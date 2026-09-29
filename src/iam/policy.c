/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Port of github.com/minio/pkg/v3/policy (and its condition package). */
#include "iam/policy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <yyjson.h>

#include "core/buf.h"
#include "core/timefmt.h"
#include "crypto/base64.h"
#include "notify/event.h"

#include "iam/policy_tables.inc"

#define DEFAULT_VERSION "2012-10-17"
#define ARN_S3 "arn:aws:s3:::"
#define ARN_KMS "arn:minio:kms:::"

/* ---- small string sets ------------------------------------------------------- */

typedef struct {
  char **v;
  size_t n;
} strset;

static bool set_has(const strset *s, const char *x) {
  for (size_t i = 0; i < s->n; i++) {
    if (strcmp(s->v[i], x) == 0) return true;
  }
  return false;
}

static void set_add(strset *s, const char *x) {
  if (set_has(s, x)) return;
  s->v = buckets_xrealloc(s->v, (s->n + 1) * sizeof(char *));
  s->v[s->n++] = buckets_xstrdup(x);
}

static void set_free(strset *s) {
  for (size_t i = 0; i < s->n; i++) free(s->v[i]);
  free(s->v);
  memset(s, 0, sizeof(*s));
}

static void set_copy(strset *dst, const strset *src) {
  memset(dst, 0, sizeof(*dst));
  for (size_t i = 0; i < src->n; i++) set_add(dst, src->v[i]);
}

/* ---- wildcard (minio/pkg/wildcard) -------------------------------------------- */

static bool deep_match(const char *str, size_t sn, const char *pat, size_t pn, bool simple) {
  while (pn > 0) {
    switch (*pat) {
      default:
        if (sn == 0 || *str != *pat) return false;
        break;
      case '?':
        if (sn == 0) return simple;
        break;
      case '*':
        return pn == 1 || deep_match(str, sn, pat + 1, pn - 1, simple) ||
               (sn > 0 && deep_match(str + 1, sn - 1, pat, pn, simple));
    }
    str++, sn--, pat++, pn--;
  }
  return sn == 0 && pn == 0;
}

bool buckets_wildcard_match(const char *pattern, const char *name) {
  if (!*pattern) return !*name;
  if (strcmp(pattern, "*") == 0) return true;
  return deep_match(name, strlen(name), pattern, strlen(pattern), false);
}

bool buckets_wildcard_match_simple(const char *pattern, const char *name) {
  if (!*pattern) return !*name;
  if (strcmp(pattern, "*") == 0) return true;
  return deep_match(name, strlen(name), pattern, strlen(pattern), true);
}

/* ---- Go's path.Clean ------------------------------------------------------------ */

static char *path_clean(const char *p) {
  size_t n = strlen(p);
  if (n == 0) return buckets_xstrdup(".");
  bool rooted = p[0] == '/';
  char *out = buckets_xmalloc(n + 2);
  size_t w = 0, r = 0, dotdot = 0;
  if (rooted) {
    out[w++] = '/';
    r = 1;
    dotdot = 1;
  }
  while (r < n) {
    if (p[r] == '/') {
      r++;
    } else if (p[r] == '.' && (r + 1 == n || p[r + 1] == '/')) {
      r++;
    } else if (p[r] == '.' && p[r + 1] == '.' && (r + 2 == n || p[r + 2] == '/')) {
      r += 2;
      if (w > dotdot) {
        w--;
        while (w > dotdot && out[w] != '/') w--;
      } else if (!rooted) {
        if (w > 0) out[w++] = '/';
        out[w++] = '.';
        out[w++] = '.';
        dotdot = w;
      }
    } else {
      if ((rooted && w != 1) || (!rooted && w != 0)) out[w++] = '/';
      while (r < n && p[r] != '/') out[w++] = p[r++];
    }
  }
  if (w == 0) out[w++] = '.';
  out[w] = '\0';
  return out;
}

/* ---- errors -------------------------------------------------------------------- */

static bool fail(char *err, size_t errlen, const char *fmt, ...) BUCKETS_PRINTF(3, 4);
static bool fail(char *err, size_t errlen, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(err, errlen, fmt, ap);
  va_end(ap);
  return false;
}

/* ---- condition keys -------------------------------------------------------------- */

static int key_index(const char *name) {
  for (int i = 0; i < K_COND_KEYS_N; i++) {
    if (strcmp(k_cond_keys[i], name) == 0) return i;
  }
  return -1;
}

/* KeyName.Name(): the part after aws:/jwt:/ldap:/sts:/svc:/s3:. */
static const char *key_short(const char *name) {
  const char *c = strchr(name, ':');
  if (!c) return name;
  size_t n = (size_t)(c - name);
  static const char *const trim[] = {"aws", "jwt", "ldap", "sts", "svc", "s3"};
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(trim); i++) {
    if (strlen(trim[i]) == n && strncmp(name, trim[i], n) == 0) return c + 1;
  }
  return name;
}

typedef struct {
  char *name;     /* e.g. "s3:prefix" */
  char *variable; /* after '/', e.g. an object tag name */
  int index;      /* into k_cond_keys */
} cond_key;

/* Key.Name(): short name plus "/variable". */
static char *key_lookup_name(const cond_key *k) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, key_short(k->name));
  if (k->variable && *k->variable) buckets_buf_appendf(&b, "/%s", k->variable);
  return b.data;
}

/* http.CanonicalHeaderKey. */
static char *canonical_header(const char *s) {
  char *c = buckets_xstrdup(s);
  for (const char *p = s; *p; p++) {
    unsigned char ch = (unsigned char)*p;
    bool token = isalnum(ch) || strchr("!#$%&'*+-.^_`|~", ch);
    if (!token) return c; /* Go leaves such keys alone */
  }
  bool upper = true;
  for (char *p = c; *p; p++) {
    *p = upper ? (char)toupper((unsigned char)*p) : (char)tolower((unsigned char)*p);
    upper = *p == '-';
  }
  return c;
}

static const buckets_cond_value *cond_find(const buckets_policy_args *a, const char *key) {
  for (size_t i = 0; i < a->nconds; i++) {
    if (strcmp(a->conds[i].key, key) == 0) return &a->conds[i];
  }
  return NULL;
}

/* getValuesByKey: the canonical header form first, then the plain name. */
static const buckets_cond_value *values_by_key(const buckets_policy_args *a, const cond_key *k) {
  char *name = key_lookup_name(k);
  char *canon = canonical_header(name);
  const buckets_cond_value *v = cond_find(a, canon);
  if (!v) v = cond_find(a, name);
  free(canon);
  free(name);
  return v;
}

/* ---- condition functions ------------------------------------------------------- */

typedef enum { F_STRING, F_STRING_LIKE, F_IP, F_NULL, F_BOOL, F_NUMERIC, F_DATE } func_kind;
typedef enum { C_EQ = 1, C_NE, C_GT, C_GE, C_LT, C_LE } cmp_op;

typedef struct {
  unsigned char addr[16];
  int bits; /* prefix length over a 4- or 16-byte address */
  int len;  /* 4 or 16 */
} ipnet;

typedef struct {
  func_kind kind;
  char *name; /* e.g. "ForAllValues:StringEquals" */
  bool for_all, negate, ignore_case, if_exists;
  cond_key key;
  strset values; /* string functions */
  ipnet *nets;
  size_t nnets;
  bool null_value;
  char *bool_value;
  long long num;
  cmp_op cmp;
  long long date_sec;
  long date_nsec;
} cond_func;

static void func_free(cond_func *f) {
  free(f->name);
  free(f->key.name);
  free(f->key.variable);
  set_free(&f->values);
  free(f->nets);
  free(f->bool_value);
}

/* Replaces ${key} for every common key the request has a value for. */
static char *substitute(const buckets_policy_args *a, const char *v) {
  char *cur = buckets_xstrdup(v);
  for (int i = 0; i < K_COND_KEYS_N; i++) {
    if (!k_cond_common[i]) continue;
    const buckets_cond_value *cv = cond_find(a, key_short(k_cond_keys[i]));
    if (!cv || !cv->n || !*cv->values[0]) continue;
    char var[96];
    snprintf(var, sizeof(var), "${%s}", k_cond_keys[i]);
    size_t vl = strlen(var);
    buckets_buf out = BUCKETS_BUF_INIT;
    for (const char *p = cur; *p;) {
      const char *hit = strstr(p, var);
      if (!hit) {
        buckets_buf_append_c(&out, p);
        break;
      }
      buckets_buf_append(&out, p, (size_t)(hit - p));
      buckets_buf_append_c(&out, cv->values[0]);
      p = hit + vl;
    }
    free(cur);
    cur = out.data ? out.data : buckets_xstrdup("");
  }
  return cur;
}

static void lower(char *s) {
  for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

static bool eval_string(const cond_func *f, const buckets_policy_args *a) {
  const buckets_cond_value *rv = values_by_key(a, &f->key);
  strset req = {0}, fv = {0};
  for (size_t i = 0; rv && i < rv->n; i++) {
    char *x = buckets_xstrdup(rv->values[i]);
    if (f->ignore_case) lower(x);
    set_add(&req, x);
    free(x);
  }
  for (size_t i = 0; i < f->values.n; i++) {
    char *x = substitute(a, f->values.v[i]);
    if (f->ignore_case) lower(x);
    set_add(&fv, x);
    free(x);
  }
  bool result;
  if (f->kind == F_STRING) {
    size_t inter = 0;
    for (size_t i = 0; i < req.n; i++) inter += set_has(&fv, req.v[i]);
    result = f->for_all ? (req.n == 0 || inter == req.n) : inter > 0;
  } else { /* StringLike: over the request's raw values, in order */
    result = f->for_all;
    for (size_t i = 0; rv && i < rv->n; i++) {
      bool matched = false;
      for (size_t j = 0; j < fv.n && !matched; j++) matched = buckets_wildcard_match(fv.v[j], rv->values[i]);
      if (f->for_all && !matched) {
        result = false;
        break;
      }
      if (!f->for_all && matched) {
        result = true;
        break;
      }
    }
  }
  set_free(&req);
  set_free(&fv);
  return result;
}

static bool parse_ip(const char *s, unsigned char out[16], int *len) {
  struct in_addr a4;
  struct in6_addr a6;
  if (strchr(s, ':')) {
    if (inet_pton(AF_INET6, s, &a6) != 1) return false;
    memcpy(out, &a6, 16);
    *len = 16;
    return true;
  }
  /* Go rejects leading zeros; inet_pton may not, so check shape first. */
  for (const char *p = s; *p; p++) {
    if (!isdigit((unsigned char)*p) && *p != '.') return false;
    if (*p == '0' && isdigit((unsigned char)p[1]) && (p == s || p[-1] == '.')) return false;
  }
  if (inet_pton(AF_INET, s, &a4) != 1) return false;
  memcpy(out, &a4, 4);
  *len = 4;
  return true;
}

/* net.IP.To4 for v4-mapped v6 addresses. */
static bool to4(const unsigned char *ip, int len, unsigned char out[4]) {
  if (len == 4) {
    memcpy(out, ip, 4);
    return true;
  }
  static const unsigned char prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  if (memcmp(ip, prefix, 12) != 0) return false;
  memcpy(out, ip + 12, 4);
  return true;
}

static bool net_contains(const ipnet *n, const unsigned char *ip, int len) {
  unsigned char v4[4];
  const unsigned char *x = ip;
  if (n->len == 4) {
    if (!to4(ip, len, v4)) return false;
    x = v4;
  } else if (len != 16) {
    return false; /* a v4 address against a v6 network */
  }
  int bits = n->bits;
  for (int i = 0; bits > 0; i++, bits -= 8) {
    unsigned char mask = bits >= 8 ? 0xff : (unsigned char)(0xff << (8 - bits));
    if ((x[i] & mask) != (n->addr[i] & mask)) return false;
  }
  return true;
}

static bool eval_ip(const cond_func *f, const buckets_policy_args *a) {
  const buckets_cond_value *rv = values_by_key(a, &f->key);
  bool result = false;
  unsigned char ips[16][16];
  int lens[16];
  size_t n = 0;
  for (size_t i = 0; rv && i < rv->n; i++) {
    if (n == 16) break;
    if (!parse_ip(rv->values[i], ips[n], &lens[n])) goto done; /* any unparsable address: no match */
    n++;
  }
  for (size_t i = 0; i < n && !result; i++) {
    for (size_t j = 0; j < f->nnets && !result; j++) result = net_contains(&f->nets[j], ips[i], lens[i]);
  }
done:
  return f->negate ? !result : result;
}

/* strconv.Atoi. */
static bool go_atoi(const char *s, long long *out) {
  if (!*s) return false;
  const char *p = s;
  if (*p == '+' || *p == '-') p++;
  if (!*p) return false;
  for (const char *q = p; *q; q++) {
    if (!isdigit((unsigned char)*q)) return false;
  }
  errno = 0;
  char *end;
  long long v = strtoll(s, &end, 10);
  if (errno || *end) return false;
  *out = v;
  return true;
}

static bool compare(cmp_op c, int order) {
  switch (c) {
    case C_EQ: return order == 0;
    case C_NE: return order != 0;
    case C_GT: return order > 0;
    case C_GE: return order >= 0;
    case C_LT: return order < 0;
    case C_LE: return order <= 0;
  }
  return false;
}

static bool func_eval(const cond_func *f, const buckets_policy_args *a) {
  const buckets_cond_value *rv;
  switch (f->kind) {
    case F_STRING:
    case F_STRING_LIKE: {
      bool r = eval_string(f, a);
      return f->negate ? !r : r;
    }
    case F_IP: return eval_ip(f, a);
    case F_NULL:
      rv = values_by_key(a, &f->key);
      return f->null_value ? (!rv || rv->n == 0) : (rv && rv->n != 0);
    case F_BOOL:
      rv = values_by_key(a, &f->key);
      return rv && rv->n && strcmp(f->bool_value, rv->values[0]) == 0;
    case F_NUMERIC: {
      rv = values_by_key(a, &f->key);
      if (!rv || !rv->n) return f->if_exists;
      long long v;
      if (!go_atoi(rv->values[0], &v)) return false;
      return compare(f->cmp, v < f->num ? -1 : v > f->num);
    }
    case F_DATE: {
      rv = values_by_key(a, &f->key);
      if (!rv || !rv->n) return false;
      long long s;
      long ns;
      if (!buckets_time_parse_rfc3339(rv->values[0], &s, &ns)) return false;
      int order = s != f->date_sec ? (s < f->date_sec ? -1 : 1) : ns != f->date_nsec ? (ns < f->date_nsec ? -1 : 1) : 0;
      return compare(f->cmp, order);
    }
  }
  return false;
}

/* ---- condition parsing (Functions.UnmarshalJSON) --------------------------------- */

typedef enum { V_BOOL, V_INT, V_STRING } vtype;
typedef struct {
  vtype t;
  bool b;
  long long i;
  const char *s;
} value;

/* Value.UnmarshalJSON: bool, then int, then string. */
static bool parse_value(yyjson_val *v, value *out) {
  if (yyjson_is_bool(v)) {
    *out = (value){V_BOOL, yyjson_get_bool(v), 0, NULL};
    return true;
  }
  if (yyjson_is_int(v)) {
    *out = (value){V_INT, false, yyjson_get_sint(v), NULL};
    if (yyjson_is_uint(v) && yyjson_get_uint(v) > (uint64_t)INT64_MAX) return false;
    return true;
  }
  if (yyjson_is_str(v)) {
    *out = (value){V_STRING, false, 0, yyjson_get_str(v)};
    return true;
  }
  return false;
}

static bool value_eq(const value *a, const value *b) {
  if (a->t != b->t) return false;
  switch (a->t) {
    case V_BOOL: return a->b == b->b;
    case V_INT: return a->i == b->i;
    case V_STRING: return strcmp(a->s, b->s) == 0;
  }
  return false;
}

/* ValueSet.UnmarshalJSON: one value, or a non-empty array of distinct values. */
static bool parse_value_set(yyjson_val *v, value **out, size_t *n, char *err, size_t errlen) {
  *out = NULL;
  *n = 0;
  value one;
  if (parse_value(v, &one)) {
    *out = buckets_xmalloc(sizeof(value));
    **out = one;
    *n = 1;
    return true;
  }
  if (!yyjson_is_arr(v)) return fail(err, errlen, "unknown json data");
  if (yyjson_arr_size(v) < 1) return fail(err, errlen, "invalid value");
  *out = buckets_xcalloc(yyjson_arr_size(v), sizeof(value));
  size_t i, max;
  yyjson_val *e;
  yyjson_arr_foreach(v, i, max, e) {
    value x;
    if (!parse_value(e, &x)) {
      free(*out);
      return fail(err, errlen, "unknown json data");
    }
    for (size_t j = 0; j < *n; j++) {
      if (value_eq(&(*out)[j], &x)) {
        free(*out);
        return fail(err, errlen, "duplicate value found");
      }
    }
    (*out)[(*n)++] = x;
  }
  return true;
}

static const char *const k_names[] = {
    "StringEquals",     "StringNotEquals",          "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
    "StringLike",       "StringNotLike",            "BinaryEquals",           "IpAddress",
    "NotIpAddress",     "Null",                     "Bool",                   "NumericEquals",
    "NumericNotEquals", "NumericLessThan",          "NumericLessThanEquals",  "NumericGreaterThan",
    "NumericGreaterThanIfExists", "NumericGreaterThanEquals", "DateEquals", "DateNotEquals",
    "DateLessThan",     "DateLessThanEquals",       "DateGreaterThan",        "DateGreaterThanEquals",
};

static bool parse_bool_str(const char *s, bool *out) {
  static const char *const t[] = {"1", "t", "T", "TRUE", "true", "True"};
  static const char *const f[] = {"0", "f", "F", "FALSE", "false", "False"};
  for (size_t i = 0; i < 6; i++) {
    if (strcmp(s, t[i]) == 0) return (*out = true);
    if (strcmp(s, f[i]) == 0) return !(*out = false);
  }
  return false;
}

/* The checks newStringFunc applies to particular keys (validateStringValues). */
static bool check_string_values(const char *n, const char *key, const strset *vals, char *err, size_t errlen) {
  bool like = strcmp(n, "StringLike") == 0 || strcmp(n, "StringNotLike") == 0;
  for (size_t i = 0; i < vals->n; i++) {
    const char *s = vals->v[i];
    if (strcmp(key, "s3:x-amz-copy-source") == 0) {
      const char *p = s[0] == '/' ? s + 1 : s;
      const char *slash = strchr(p, '/');
      if (!slash || !slash[1]) return fail(err, errlen, "invalid value '%s' for 's3:x-amz-copy-source' for %s condition", s, n);
      size_t bl = (size_t)(slash - p);
      if (bl < 3 || bl > 63) return fail(err, errlen, "Bucket name cannot be shorter than 3 characters");
    }
    if (like) continue;
    if (strcmp(key, "s3:x-amz-server-side-encryption-customer-algorithm") == 0 && strcmp(s, "AES256") != 0) {
      return fail(err, errlen, "invalid value '%s' for '%s' for %s condition", s, key, n);
    }
    if (strcmp(key, "s3:x-amz-server-side-encryption") == 0 && strcmp(s, "AES256") != 0 && strcmp(s, "aws:kms") != 0) {
      return fail(err, errlen, "invalid value '%s' for '%s' for %s condition", s, key, n);
    }
    if (strcmp(key, "s3:x-amz-metadata-directive") == 0 && strcmp(s, "COPY") != 0 && strcmp(s, "REPLACE") != 0) {
      return fail(err, errlen, "invalid value '%s' for '%s' for %s condition", s, key, n);
    }
    if (strcmp(key, "s3:x-amz-content-sha256") == 0 && !*s) {
      return fail(err, errlen, "invalid empty value for '%s' for %s condition", key, n);
    }
  }
  return true;
}

static bool parse_cidr(const char *in, ipnet *out) {
  char s[80];
  snprintf(s, sizeof(s), "%s%s", in, strchr(in, '/') ? "" : "/32");
  char *slash = strchr(s, '/');
  *slash = '\0';
  const char *bits = slash + 1;
  long long b;
  if (!go_atoi(bits, &b) || bits[0] == '+' || bits[0] == '-' || (bits[0] == '0' && bits[1])) return false;
  unsigned char ip[16];
  int len;
  if (!parse_ip(s, ip, &len)) return false;
  if (b > len * 8) return false;
  memset(out, 0, sizeof(*out));
  memcpy(out->addr, ip, (size_t)len);
  out->len = len;
  out->bits = (int)b;
  return true;
}

static bool make_func(const char *qual, const char *nm, yyjson_val *key_json, const char *key_str, yyjson_val *vals,
                      cond_func *f, char *err, size_t errlen) {
  (void)key_json;
  memset(f, 0, sizeof(*f));
  buckets_buf full = BUCKETS_BUF_INIT;
  if (qual) buckets_buf_appendf(&full, "%s:%s", qual, nm);
  else buckets_buf_append_c(&full, nm);
  f->name = full.data;
  /* parseKey */
  const char *sl = strchr(key_str, '/');
  f->key.name = sl ? buckets_xstrndup(key_str, (size_t)(sl - key_str)) : buckets_xstrdup(key_str);
  f->key.variable = sl ? buckets_xstrdup(sl + 1) : NULL;
  f->key.index = key_index(f->key.name);
  if (f->key.index < 0) return fail(err, errlen, "invalid condition key '%s'", key_str);
  f->for_all = qual && strcmp(qual, "ForAllValues") == 0;
  value *vs;
  size_t nv;
  if (!parse_value_set(vals, &vs, &nv, err, errlen)) return false;
  bool ok = true;
  bool is_string = strncmp(nm, "String", 6) == 0 || strcmp(nm, "BinaryEquals") == 0;
  if (is_string) {
    f->kind = strstr(nm, "Like") ? F_STRING_LIKE : F_STRING;
    f->negate = strstr(nm, "Not") != NULL;
    f->ignore_case = strstr(nm, "IgnoreCase") != NULL;
    for (size_t i = 0; i < nv && ok; i++) {
      if (vs[i].t != V_STRING) {
        ok = fail(err, errlen, "value must be a string for %s condition", nm);
        break;
      }
      if (strcmp(nm, "BinaryEquals") == 0) {
        size_t sl2 = strlen(vs[i].s);
        char *dec = buckets_xmalloc(sl2 + 1);
        long dn = buckets_base64_decode(vs[i].s, sl2, (uint8_t *)dec);
        if (dn < 0) {
          free(dec);
          ok = fail(err, errlen, "illegal base64 data");
          break;
        }
        dec[dn] = '\0';
        set_add(&f->values, dec);
        free(dec);
      } else {
        set_add(&f->values, vs[i].s);
      }
    }
    if (ok && strcmp(nm, "BinaryEquals") != 0) ok = check_string_values(nm, f->key.name, &f->values, err, errlen);
  } else if (strcmp(nm, "IpAddress") == 0 || strcmp(nm, "NotIpAddress") == 0) {
    f->kind = F_IP;
    f->negate = nm[0] == 'N';
    f->nets = buckets_xcalloc(nv, sizeof(ipnet));
    for (size_t i = 0; i < nv && ok; i++) {
      if (vs[i].t != V_STRING) ok = fail(err, errlen, "value must be string representation of CIDR for %s condition", nm);
      else if (!parse_cidr(vs[i].s, &f->nets[f->nnets++])) ok = fail(err, errlen, "value %s must be CIDR string for %s condition", vs[i].s, nm);
    }
    if (ok && strcmp(f->key.name, "aws:SourceIp") != 0) ok = fail(err, errlen, "only aws:SourceIp key is allowed for %s condition", nm);
  } else if (strcmp(nm, "Null") == 0) {
    f->kind = F_NULL;
    if (nv != 1) ok = fail(err, errlen, "only one value is allowed for Null condition");
    else if (vs[0].t == V_BOOL) f->null_value = vs[0].b;
    else if (vs[0].t != V_STRING || !parse_bool_str(vs[0].s, &f->null_value)) ok = fail(err, errlen, "value must be a boolean string for Null condition");
  } else if (strcmp(nm, "Bool") == 0) {
    f->kind = F_BOOL;
    bool b;
    if (strcmp(f->key.name, "aws:SecureTransport") != 0) ok = fail(err, errlen, "only aws:SecureTransport key is allowed for Bool condition");
    else if (nv != 1) ok = fail(err, errlen, "only one value is allowed for boolean condition");
    else if (vs[0].t == V_BOOL) f->bool_value = buckets_xstrdup(vs[0].b ? "true" : "false");
    else if (vs[0].t == V_STRING && parse_bool_str(vs[0].s, &b)) f->bool_value = buckets_xstrdup(vs[0].s);
    else ok = fail(err, errlen, "value must be a boolean string for boolean condition");
  } else if (strncmp(nm, "Numeric", 7) == 0) {
    f->kind = F_NUMERIC;
    const char *op = nm + 7;
    f->if_exists = strcmp(op, "GreaterThanIfExists") == 0;
    f->cmp = strcmp(op, "Equals") == 0 ? C_EQ : strcmp(op, "NotEquals") == 0 ? C_NE
           : strcmp(op, "LessThan") == 0 ? C_LT : strcmp(op, "LessThanEquals") == 0 ? C_LE
           : strcmp(op, "GreaterThanEquals") == 0 ? C_GE : C_GT;
    if (nv != 1) ok = fail(err, errlen, "only one value is allowed for %s condition", nm);
    else if (vs[0].t == V_INT) f->num = vs[0].i;
    else if (vs[0].t != V_STRING || !go_atoi(vs[0].s, &f->num)) ok = fail(err, errlen, "value must be a int for %s condition", nm);
  } else { /* Date* */
    f->kind = F_DATE;
    const char *op = nm + 4;
    f->cmp = strcmp(op, "Equals") == 0 ? C_EQ : strcmp(op, "NotEquals") == 0 ? C_NE
           : strcmp(op, "LessThan") == 0 ? C_LT : strcmp(op, "LessThanEquals") == 0 ? C_LE
           : strcmp(op, "GreaterThan") == 0 ? C_GT : C_GE;
    if (nv != 1) ok = fail(err, errlen, "only one value is allowed for %s condition", nm);
    else if (vs[0].t != V_STRING || !buckets_time_parse_rfc3339(vs[0].s, &f->date_sec, &f->date_nsec)) ok = fail(err, errlen, "value must be a time.Time string for %s condition", nm);
  }
  free(vs);
  return ok;
}

typedef struct {
  cond_func *f;
  size_t n;
} functions;

static void functions_free(functions *fs) {
  for (size_t i = 0; i < fs->n; i++) func_free(&fs->f[i]);
  free(fs->f);
  memset(fs, 0, sizeof(*fs));
}

static bool parse_conditions(yyjson_val *v, functions *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  if (yyjson_is_null(v)) return true;
  if (!yyjson_is_obj(v)) return fail(err, errlen, "cannot unmarshal Condition");
  if (yyjson_obj_size(v) == 0) return fail(err, errlen, "condition must not be empty");
  size_t i, max;
  yyjson_val *nk, *args;
  yyjson_obj_foreach(v, i, max, nk, args) {
    const char *s = yyjson_get_str(nk);
    /* parseName */
    const char *colon = strchr(s, ':');
    char qual[32] = "", nm[64];
    if (colon && strchr(colon + 1, ':')) return fail(err, errlen, "invalid condition name '%s'", s);
    if (colon) {
      snprintf(qual, sizeof(qual), "%.*s", (int)(colon - s), s);
      snprintf(nm, sizeof(nm), "%s", colon + 1);
    } else {
      snprintf(nm, sizeof(nm), "%s", s);
    }
    bool known = false;
    for (size_t k = 0; k < BUCKETS_ARRAY_LEN(k_names); k++) known |= strcmp(nm, k_names[k]) == 0;
    if (!known || (colon && strcmp(qual, "ForAllValues") != 0 && strcmp(qual, "ForAnyValue") != 0)) {
      return fail(err, errlen, "invalid condition name '%s'", s);
    }
    if (yyjson_is_null(args)) continue;
    if (!yyjson_is_obj(args)) return fail(err, errlen, "cannot unmarshal condition arguments");
    size_t j, jmax;
    yyjson_val *kk, *vals;
    yyjson_obj_foreach(args, j, jmax, kk, vals) {
      out->f = buckets_xrealloc(out->f, (out->n + 1) * sizeof(cond_func));
      if (!make_func(colon ? qual : NULL, nm, kk, yyjson_get_str(kk), vals, &out->f[out->n], err, errlen)) {
        func_free(&out->f[out->n]);
        functions_free(out);
        return false;
      }
      out->n++;
    }
  }
  return true;
}

/* ---- resources ------------------------------------------------------------------- */

typedef enum { ARN_UNKNOWN, ARN_TYPE_S3, ARN_TYPE_KMS, ARN_TYPE_ALL } arn_type;

typedef struct {
  char *pattern;
  arn_type type;
} resource;

static bool parse_resource(const char *s, resource *r, char *err, size_t errlen) {
  r->type = ARN_UNKNOWN;
  r->pattern = NULL;
  if (strcmp(s, "*") == 0 || strcmp(s, ARN_S3) == 0 || strcmp(s, ARN_KMS) == 0) {
    r->type = ARN_TYPE_ALL; /* an exact prefix string is an "all" resource with itself as pattern */
    r->pattern = buckets_xstrdup(s);
  } else if (strncmp(s, ARN_S3, strlen(ARN_S3)) == 0) {
    r->type = ARN_TYPE_S3;
    r->pattern = buckets_xstrdup(s + strlen(ARN_S3));
  } else if (strncmp(s, ARN_KMS, strlen(ARN_KMS)) == 0) {
    r->type = ARN_TYPE_KMS;
    r->pattern = buckets_xstrdup(s + strlen(ARN_KMS));
  } else if (s[0] == '*') {
    r->type = ARN_TYPE_ALL;
    r->pattern = buckets_xstrdup(s + 1);
  }
  if (r->type == ARN_UNKNOWN) return fail(err, errlen, "invalid resource '%s'", s);
  if (r->pattern[0] == '/') return fail(err, errlen, "invalid resource '%s' - starts with '/' will not match a bucket", s);
  return true;
}

static bool res_is_s3(const resource *r) { return r->type == ARN_TYPE_S3 || r->type == ARN_TYPE_ALL; }
static bool res_is_kms(const resource *r) { return r->type == ARN_TYPE_KMS || r->type == ARN_TYPE_ALL; }

static bool res_valid(const resource *r) {
  if (r->type == ARN_UNKNOWN) return false;
  if (res_is_s3(r) && r->pattern[0] == '/') return false;
  if (res_is_kms(r) && strpbrk(r->pattern, "/\\.")) return false;
  return r->pattern[0] != '\0';
}

static bool res_match(const resource *r, const char *res, const buckets_policy_args *a) {
  const char *dollar = strchr(r->pattern, '$');
  char *pattern;
  if (!dollar) {
    pattern = buckets_xstrdup(r->pattern);
  } else {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_append(&p, r->pattern, (size_t)(dollar - r->pattern));
    const char *rem = dollar;
    while (*rem) {
      size_t len = strlen(rem);
      const char *close = strchr(rem, '}');
      if (rem[0] != '$' || len < 3) {
        buckets_buf_append_char(&p, rem[0]);
        rem++;
        continue;
      }
      if (rem[1] != '{' || !close) {
        buckets_buf_append_char(&p, '$');
        rem++;
        continue;
      }
      char key[128];
      snprintf(key, sizeof(key), "%.*s", (int)(close - rem - 2), rem + 2);
      int ki = key_index(key);
      const buckets_cond_value *cv = cond_find(a, key_short(key));
      if (ki >= 0 && k_cond_common[ki] && cv && cv->n && *cv->values[0]) buckets_buf_append_c(&p, cv->values[0]);
      else buckets_buf_appendf(&p, "${%s}", key);
      rem = close + 1;
    }
    pattern = p.data ? p.data : buckets_xstrdup("");
  }
  char *cp = path_clean(res);
  bool m = (strcmp(cp, ".") != 0 && strcmp(cp, pattern) == 0) || buckets_wildcard_match(pattern, res);
  free(cp);
  free(pattern);
  return m;
}

/* ---- statements ------------------------------------------------------------------- */

typedef enum { EFFECT_NONE, EFFECT_ALLOW, EFFECT_DENY } effect;

typedef struct {
  char *sid;
  effect eff;
  char *eff_raw;
  strset actions, not_actions;
  resource *res, *not_res;
  size_t nres, nnot_res;
  functions conds;
  strset principals; /* bucket policies: Principal.AWS */
} statement;

static void statement_free(statement *s) {
  free(s->sid);
  free(s->eff_raw);
  set_free(&s->actions);
  set_free(&s->not_actions);
  for (size_t i = 0; i < s->nres; i++) free(s->res[i].pattern);
  for (size_t i = 0; i < s->nnot_res; i++) free(s->not_res[i].pattern);
  free(s->res);
  free(s->not_res);
  functions_free(&s->conds);
  set_free(&s->principals);
}

struct buckets_policy {
  char *version, *id;
  statement *st;
  size_t n;
};

static bool in_list(const char *const *list, size_t n, const char *x) {
  for (size_t i = 0; i < n; i++) {
    if (strcmp(list[i], x) == 0) return true;
  }
  return false;
}

static bool action_match(const strset *set, const char *action) {
  for (size_t i = 0; i < set->n; i++) {
    if (buckets_wildcard_match(set->v[i], action)) return true;
    if (strcmp(set->v[i], "s3:GetObjectVersion") == 0 && strcmp(action, "s3:GetObject") == 0) return true;
  }
  return false;
}

static bool any_in(const strset *acts, const char *const *list, size_t n) {
  for (size_t i = 0; i < acts->n; i++) {
    if (in_list(list, n, acts->v[i])) return true;
  }
  return false;
}

static bool st_is_admin(const statement *s) { return any_in(&s->actions, k_admin_actions, K_ADMIN_ACTIONS_N); }
static bool st_is_sts(const statement *s) { return any_in(&s->actions, k_sts_actions, K_STS_ACTIONS_N); }
static bool st_is_kms(const statement *s) { return any_in(&s->actions, k_kms_actions, K_KMS_ACTIONS_N); }

static bool statement_allowed(const statement *s, const buckets_policy_args *a) {
  bool matched = false;
  if ((!action_match(&s->actions, a->action) && s->actions.n != 0) || action_match(&s->not_actions, a->action)) {
    matched = false;
    goto out;
  }
  {
    buckets_buf res = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&res, a->bucket ? a->bucket : "");
    if (a->object && *a->object) {
      if (a->object[0] != '/') buckets_buf_append_char(&res, '/');
      buckets_buf_append_c(&res, a->object);
    } else {
      buckets_buf_append_char(&res, '/');
    }
    const char *rs = res.data;
    if (st_is_kms(s) && ((res.len == 1 && strcmp(rs, "/") == 0) || s->nres == 0)) {
      matched = true;
      for (size_t i = 0; i < s->conds.n && matched; i++) matched = func_eval(&s->conds.f[i], a);
      buckets_buf_free(&res);
      goto out;
    }
    bool ignore = st_is_admin(s) || st_is_sts(s);
    matched = true;
    if (!ignore && s->nres > 0) {
      bool any = false;
      for (size_t i = 0; i < s->nres && !any; i++) any = res_match(&s->res[i], rs, a);
      if (!any) matched = false;
    }
    if (matched && !ignore && s->nnot_res > 0) {
      bool any = false;
      for (size_t i = 0; i < s->nnot_res && !any; i++) any = res_match(&s->not_res[i], rs, a);
      if (any) matched = false;
    }
    for (size_t i = 0; i < s->conds.n && matched; i++) matched = func_eval(&s->conds.f[i], a);
    buckets_buf_free(&res);
  }
out:
  return s->eff == EFFECT_ALLOW ? matched : !matched;
}

bool buckets_policy_allowed(const buckets_policy *p, const buckets_policy_args *a) {
  for (size_t i = 0; i < p->n; i++) {
    if (p->st[i].eff == EFFECT_DENY && !statement_allowed(&p->st[i], a)) return false;
  }
  if (a->deny_only || a->owner) return true;
  for (size_t i = 0; i < p->n; i++) {
    if (p->st[i].eff == EFFECT_ALLOW && statement_allowed(&p->st[i], a)) return true;
  }
  return false;
}

/* ---- validation ---------------------------------------------------------------------- */

/* Condition keys a statement's actions accept (ActionConditionKeyMap.Lookup
 * and the admin/STS maps), from the generated tables. */
static bool key_allowed_for(const char *action, int key, bool admin, bool sts) {
  if (admin) {
    for (int i = 0; i < K_ADMIN_ACTIONS_N; i++) {
      if (strcmp(k_admin_actions[i], action) == 0) return k_admin_action_keys[i][key];
    }
    return false;
  }
  if (sts) {
    for (int i = 0; i < K_STS_ACTIONS_N; i++) {
      if (strcmp(k_sts_actions[i], action) == 0) return k_sts_action_keys[i][key];
    }
    return false;
  }
  if (k_cond_common[key]) return true;
  for (int i = 0; i < K_S3_ACTIONS_N; i++) {
    if (buckets_wildcard_match(action, k_s3_actions[i]) && k_s3_action_keys[i][key]) return true;
  }
  return false;
}

static bool s3_action_valid(const char *a) {
  for (int i = 0; i < K_S3_ACTIONS_N; i++) {
    if (buckets_wildcard_match(a, k_s3_actions[i])) return true;
  }
  return false;
}

static bool utf8_valid(const char *s) {
  const unsigned char *p = (const unsigned char *)s;
  while (*p) {
    int n = *p < 0x80 ? 0 : (*p & 0xe0) == 0xc0 ? 1 : (*p & 0xf0) == 0xe0 ? 2 : (*p & 0xf8) == 0xf0 ? 3 : -1;
    if (n < 0) return false;
    for (int i = 1; i <= n; i++) {
      if ((p[i] & 0xc0) != 0x80) return false;
    }
    p += n + 1;
  }
  return true;
}

static bool check_keys(const statement *s, bool admin, bool sts, char *err, size_t errlen) {
  for (size_t a = 0; a < s->actions.n; a++) {
    for (size_t f = 0; f < s->conds.n; f++) {
      if (!key_allowed_for(s->actions.v[a], s->conds.f[f].key.index, admin, sts)) {
        return fail(err, errlen, "unsupported condition keys '[%s]' used for action '%s'", s->conds.f[f].key.name,
                    s->actions.v[a]);
      }
    }
  }
  return true;
}

static bool statement_valid(const statement *s, char *err, size_t errlen) {
  if (s->eff == EFFECT_NONE) return fail(err, errlen, "invalid Effect %s", s->eff_raw ? s->eff_raw : "");
  if (s->actions.n == 0 && s->not_actions.n == 0) return fail(err, errlen, "Action must not be empty");
  if (s->actions.n > 0 && s->not_actions.n > 0) {
    return fail(err, errlen, "Action and NotAction cannot be specified in the same statement");
  }
  if (st_is_admin(s)) {
    for (size_t i = 0; i < s->actions.n; i++) {
      if (!in_list(k_admin_actions, K_ADMIN_ACTIONS_N, s->actions.v[i])) {
        return fail(err, errlen, "unsupported admin action '%s'", s->actions.v[i]);
      }
    }
    return check_keys(s, true, false, err, errlen);
  }
  if (st_is_sts(s)) {
    for (size_t i = 0; i < s->actions.n; i++) {
      if (!in_list(k_sts_actions, K_STS_ACTIONS_N, s->actions.v[i])) {
        return fail(err, errlen, "unsupported STS action '%s'", s->actions.v[i]);
      }
    }
    return check_keys(s, false, true, err, errlen);
  }
  if (st_is_kms(s)) {
    for (size_t i = 0; i < s->actions.n; i++) {
      if (!in_list(k_kms_actions, K_KMS_ACTIONS_N, s->actions.v[i])) {
        return fail(err, errlen, "unsupported KMS action '%s'", s->actions.v[i]);
      }
    }
    for (size_t i = 0; i < s->nres; i++) {
      if (!res_is_kms(&s->res[i]) || !res_valid(&s->res[i])) return fail(err, errlen, "resource type is not KMS");
    }
    for (size_t i = 0; i < s->nnot_res; i++) {
      if (!res_is_kms(&s->not_res[i]) || !res_valid(&s->not_res[i])) return fail(err, errlen, "resource type is not KMS");
    }
    return true;
  }
  if (s->sid && !utf8_valid(s->sid)) return fail(err, errlen, "invalid SID %s", s->sid);
  if (s->nres == 0 && s->nnot_res == 0) return fail(err, errlen, "Resource must not be empty");
  if (s->nres > 0 && s->nnot_res > 0) {
    return fail(err, errlen, "Resource and NotResource cannot be specified in the same statement");
  }
  for (size_t i = 0; i < s->nres; i++) {
    if (!res_is_s3(&s->res[i])) return fail(err, errlen, "resource '%s' type is not S3", s->res[i].pattern);
    if (!res_valid(&s->res[i])) return fail(err, errlen, "invalid resource");
  }
  for (size_t i = 0; i < s->nnot_res; i++) {
    if (!res_is_s3(&s->not_res[i])) return fail(err, errlen, "resource '%s' type is not S3", s->not_res[i].pattern);
    if (!res_valid(&s->not_res[i])) return fail(err, errlen, "invalid resource");
  }
  for (size_t i = 0; i < s->actions.n; i++) {
    if (!s3_action_valid(s->actions.v[i])) return fail(err, errlen, "unsupported action '%s'", s->actions.v[i]);
  }
  return check_keys(s, false, false, err, errlen);
}

/* ---- JSON decoding with encoding/json's field matching ------------------------------- */

/* Which of `fields` a JSON object key maps to: an exact match wins, else a
 * case-insensitive one (as encoding/json does); -1 for unknown keys. */
static int field_of(const char *key, const char *const *fields, size_t n) {
  for (size_t i = 0; i < n; i++) {
    if (strcmp(key, fields[i]) == 0) return (int)i;
  }
  for (size_t i = 0; i < n; i++) {
    if (strcasecmp(key, fields[i]) == 0) return (int)i;
  }
  return -1;
}

/* set.StringSet.UnmarshalJSON: a string or an array of strings. */
static bool parse_string_set(yyjson_val *v, strset *out, char *err, size_t errlen) {
  set_free(out);
  if (yyjson_is_null(v)) return true;
  if (yyjson_is_str(v)) {
    set_add(out, yyjson_get_str(v));
    return true;
  }
  if (!yyjson_is_arr(v)) return fail(err, errlen, "cannot unmarshal into set");
  size_t i, max;
  yyjson_val *e;
  yyjson_arr_foreach(v, i, max, e) {
    if (!yyjson_is_str(e)) {
      set_free(out);
      return fail(err, errlen, "cannot unmarshal into set");
    }
    set_add(out, yyjson_get_str(e));
  }
  return true;
}

static bool parse_resources(yyjson_val *v, resource **out, size_t *n, char *err, size_t errlen) {
  for (size_t i = 0; i < *n; i++) free((*out)[i].pattern);
  free(*out);
  *out = NULL;
  *n = 0;
  strset ss = {0};
  if (!parse_string_set(v, &ss, err, errlen)) return false;
  *out = buckets_xcalloc(ss.n ? ss.n : 1, sizeof(resource));
  for (size_t i = 0; i < ss.n; i++) {
    resource r;
    if (!parse_resource(ss.v[i], &r, err, errlen)) {
      free(r.pattern);
      set_free(&ss);
      return false;
    }
    (*out)[(*n)++] = r;
  }
  set_free(&ss);
  return true;
}

/* Principal.UnmarshalJSON: {"AWS": <string set>}, or the string "*". */
static bool parse_principal(yyjson_val *v, strset *out, char *err, size_t errlen) {
  set_free(out);
  if (yyjson_is_null(v)) return true;
  if (yyjson_is_str(v)) {
    if (strcmp(yyjson_get_str(v), "*") != 0) return fail(err, errlen, "invalid principal '%s'", yyjson_get_str(v));
    set_add(out, "*");
    return true;
  }
  if (!yyjson_is_obj(v)) return fail(err, errlen, "cannot unmarshal Principal");
  static const char *const fields[] = {"AWS"};
  size_t i, max;
  yyjson_val *k, *e;
  yyjson_obj_foreach(v, i, max, k, e) {
    if (field_of(yyjson_get_str(k), fields, 1) == 0 && !parse_string_set(e, out, err, errlen)) return false;
  }
  return true;
}

static bool parse_statement(yyjson_val *o, statement *s, char *err, size_t errlen) {
  memset(s, 0, sizeof(*s));
  if (!yyjson_is_obj(o)) return fail(err, errlen, "cannot unmarshal statement");
  static const char *const fields[] = {"Sid",         "Effect",    "Action",   "NotAction",
                                       "Resource",    "NotResource", "Condition", "Principal"};
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(o, i, max, k, v) {
    switch (field_of(yyjson_get_str(k), fields, BUCKETS_ARRAY_LEN(fields))) {
      case 0:
        if (!yyjson_is_str(v) && !yyjson_is_null(v)) return fail(err, errlen, "cannot unmarshal Sid");
        free(s->sid);
        s->sid = yyjson_is_str(v) ? buckets_xstrdup(yyjson_get_str(v)) : NULL;
        break;
      case 1:
        if (!yyjson_is_str(v) && !yyjson_is_null(v)) return fail(err, errlen, "cannot unmarshal Effect");
        if (yyjson_is_str(v)) {
          free(s->eff_raw);
          s->eff_raw = buckets_xstrdup(yyjson_get_str(v));
        }
        break;
      case 2:
      case 3: {
        strset *target = field_of(yyjson_get_str(k), fields, BUCKETS_ARRAY_LEN(fields)) == 2 ? &s->actions : &s->not_actions;
        if (!parse_string_set(v, target, err, errlen)) return false;
        if (target->n == 0) return fail(err, errlen, "empty actions not allowed");
        break;
      }
      case 4:
        if (!parse_resources(v, &s->res, &s->nres, err, errlen)) return false;
        break;
      case 5:
        if (!parse_resources(v, &s->not_res, &s->nnot_res, err, errlen)) return false;
        break;
      case 6:
        functions_free(&s->conds);
        if (!parse_conditions(v, &s->conds, err, errlen)) return false;
        break;
      case 7:
        if (!parse_principal(v, &s->principals, err, errlen)) return false;
        break;
      default:
        break; /* unknown fields are ignored (Policy.UnmarshalJSON re-decodes leniently) */
    }
  }
  s->eff = !s->eff_raw ? EFFECT_NONE : strcmp(s->eff_raw, "Allow") == 0 ? EFFECT_ALLOW
         : strcmp(s->eff_raw, "Deny") == 0 ? EFFECT_DENY : EFFECT_NONE;
  return true;
}

static bool conds_equal(const functions *a, const functions *b) {
  if (a->n != b->n) return false;
  for (size_t i = 0; i < a->n; i++) {
    bool found = false;
    for (size_t j = 0; j < b->n && !found; j++) {
      const cond_func *x = &a->f[i], *y = &b->f[j];
      if (strcmp(x->name, y->name) != 0 || strcmp(x->key.name, y->key.name) != 0) continue;
      if ((x->key.variable ? x->key.variable : "")[0] != (y->key.variable ? y->key.variable : "")[0]) continue;
      if (x->values.n != y->values.n || x->nnets != y->nnets || x->num != y->num || x->null_value != y->null_value) continue;
      bool same = true;
      for (size_t k = 0; k < x->values.n && same; k++) same = set_has(&y->values, x->values.v[k]);
      for (size_t k = 0; k < x->nnets && same; k++) same = memcmp(&x->nets[k], &y->nets[k], sizeof(ipnet)) == 0;
      if (same && x->bool_value && y->bool_value) same = strcmp(x->bool_value, y->bool_value) == 0;
      if (same && x->kind == F_DATE) same = x->date_sec == y->date_sec && x->date_nsec == y->date_nsec;
      found = same;
    }
    if (!found) return false;
  }
  return true;
}

static bool sets_equal(const strset *a, const strset *b) {
  if (a->n != b->n) return false;
  for (size_t i = 0; i < a->n; i++) {
    if (!set_has(b, a->v[i])) return false;
  }
  return true;
}

static bool res_equal(const resource *a, size_t an, const resource *b, size_t bn) {
  if (an != bn) return false;
  for (size_t i = 0; i < an; i++) {
    bool found = false;
    for (size_t j = 0; j < bn && !found; j++) found = a[i].type == b[j].type && strcmp(a[i].pattern, b[j].pattern) == 0;
    if (!found) return false;
  }
  return true;
}

static bool statements_equal(const statement *a, const statement *b) {
  return a->eff == b->eff && sets_equal(&a->principals, &b->principals) && sets_equal(&a->actions, &b->actions) && sets_equal(&a->not_actions, &b->not_actions) &&
         res_equal(a->res, a->nres, b->res, b->nres) && res_equal(a->not_res, a->nnot_res, b->not_res, b->nnot_res) &&
         conds_equal(&a->conds, &b->conds);
}

static bool bp_statement_valid(const statement *s, const char *bucket, char *err, size_t errlen);

/* Decodes a policy document; bucket (non-NULL) selects BucketPolicy rules. */
static bool parse_doc(const char *json, size_t len, const char *bucket, buckets_policy **out, char *err,
                      size_t errlen) {
  *out = NULL;
  yyjson_doc *doc = yyjson_read(json, len, 0);
  if (!doc) return fail(err, errlen, "invalid JSON");
  yyjson_val *root = yyjson_doc_get_root(doc);
  buckets_policy *p = buckets_xcalloc(1, sizeof(*p));
  bool ok = true;
  if (!yyjson_is_obj(root)) {
    ok = fail(err, errlen, "cannot unmarshal into policy");
    goto done;
  }
  static const char *const fields[] = {"ID", "Version", "Statement"};
  size_t i, max;
  yyjson_val *k, *v;
  yyjson_obj_foreach(root, i, max, k, v) {
    int f = field_of(yyjson_get_str(k), fields, 3);
    if (f == 0 || f == 1) {
      if (!yyjson_is_str(v) && !yyjson_is_null(v)) {
        ok = fail(err, errlen, "cannot unmarshal %s", fields[f]);
        goto done;
      }
      char **dst = f == 0 ? &p->id : &p->version;
      if (yyjson_is_str(v)) {
        free(*dst);
        *dst = buckets_xstrdup(yyjson_get_str(v));
      }
    } else if (f == 2) {
      for (size_t s = 0; s < p->n; s++) statement_free(&p->st[s]);
      free(p->st);
      p->st = NULL;
      p->n = 0;
      if (yyjson_is_null(v)) continue;
      if (!yyjson_is_arr(v)) {
        ok = fail(err, errlen, "cannot unmarshal object into Statement");
        goto done;
      }
      p->st = buckets_xcalloc(yyjson_arr_size(v) ? yyjson_arr_size(v) : 1, sizeof(statement));
      size_t j, jmax;
      yyjson_val *e;
      yyjson_arr_foreach(v, j, jmax, e) {
        if (!parse_statement(e, &p->st[p->n], err, errlen)) {
          statement_free(&p->st[p->n]);
          ok = false;
          goto done;
        }
        p->n++;
      }
    }
  }
  /* dropDuplicateStatements */
  for (size_t a = 0; a < p->n; a++) {
    for (size_t b = a + 1; b < p->n;) {
      if (statements_equal(&p->st[a], &p->st[b])) {
        statement_free(&p->st[b]);
        memmove(&p->st[b], &p->st[b + 1], (p->n - b - 1) * sizeof(statement));
        p->n--;
      } else {
        b++;
      }
    }
  }
  if (p->version && *p->version && strcmp(p->version, DEFAULT_VERSION) != 0) {
    ok = fail(err, errlen, "invalid version '%s'", p->version);
    goto done;
  }
  for (size_t s = 0; s < p->n && ok; s++) {
    ok = bucket ? bp_statement_valid(&p->st[s], bucket, err, errlen) : statement_valid(&p->st[s], err, errlen);
  }
done:
  yyjson_doc_free(doc);
  if (!ok) {
    buckets_policy_free(p);
    return false;
  }
  *out = p;
  return true;
}

bool buckets_policy_parse(const char *json, size_t len, buckets_policy **out, char *err, size_t errlen) {
  return parse_doc(json, len, NULL, out, err, errlen);
}

/* ---- bucket policies (policy.BucketPolicy) --------------------------------------------- */

static bool is_object_action(const char *action) {
  for (int i = 0; i < K_OBJECT_ACTIONS_N; i++) {
    if (buckets_wildcard_match(action, k_object_actions[i])) return true;
  }
  return false;
}

static bool any_pattern(const resource *r, size_t n, bool object) {
  for (size_t i = 0; i < n; i++) {
    const char *p = r[i].pattern;
    bool m = object ? (strchr(p, '/') || strchr(p, '*')) : (!strchr(p, '/') || strcmp(p, "*") == 0);
    if (m) return true;
  }
  return false;
}

/* wildcard.MatchAsPatternPrefix */
static bool match_as_pattern_prefix(const char *pattern, const char *text) {
  size_t pl = strlen(pattern), tl = strlen(text);
  for (size_t i = 0; i < tl && i < pl; i++) {
    if (pattern[i] == '*') return true;
    if (pattern[i] == '?') continue;
    if (pattern[i] != text[i]) return false;
  }
  return tl <= pl;
}

static bool res_validate_bucket(const resource *r, const char *bucket, char *err, size_t errlen) {
  if (!res_valid(r)) return fail(err, errlen, "invalid resource");
  size_t n = strlen(bucket);
  char *prefix = buckets_xmalloc(n + 2);
  memcpy(prefix, bucket, n);
  prefix[n] = '/';
  prefix[n + 1] = '\0';
  bool ok = buckets_wildcard_match(r->pattern, bucket) || match_as_pattern_prefix(r->pattern, prefix);
  free(prefix);
  return ok || fail(err, errlen, "bucket name does not match");
}

/* BPStatement.isValid + Validate(bucket). */
static bool bp_statement_valid(const statement *s, const char *bucket, char *err, size_t errlen) {
  if (s->eff == EFFECT_NONE) return fail(err, errlen, "invalid Effect %s", s->eff_raw ? s->eff_raw : "");
  if (s->principals.n == 0) return fail(err, errlen, "invalid Principal");
  if (s->actions.n == 0 && s->not_actions.n == 0) return fail(err, errlen, "Action must not be empty");
  if (s->actions.n > 0 && s->not_actions.n > 0) {
    return fail(err, errlen, "Action and NotAction cannot be specified in the same statement");
  }
  if (s->nres == 0 && s->nnot_res == 0) return fail(err, errlen, "Resource must not be empty");
  if (s->nres > 0 && s->nnot_res > 0) {
    return fail(err, errlen, "Resource and NotResource cannot be specified in the same statement");
  }
  for (size_t i = 0; i < s->actions.n; i++) {
    bool obj = is_object_action(s->actions.v[i]);
    if ((s->nres > 0 && !any_pattern(s->res, s->nres, obj)) ||
        (s->nnot_res > 0 && !any_pattern(s->not_res, s->nnot_res, obj))) {
      return fail(err, errlen, "unsupported Resource found for action %s", s->actions.v[i]);
    }
  }
  if (!check_keys(s, false, false, err, errlen)) return false;
  for (size_t i = 0; i < s->nres; i++) {
    if (!res_validate_bucket(&s->res[i], bucket, err, errlen)) return false;
  }
  for (size_t i = 0; i < s->nnot_res; i++) {
    if (!res_validate_bucket(&s->not_res[i], bucket, err, errlen)) return false;
  }
  return true;
}

bool buckets_bucket_policy_parse(const char *json, size_t len, const char *bucket, buckets_policy **out, char *err,
                                 size_t errlen) {
  return parse_doc(json, len, bucket, out, err, errlen);
}

static bool bp_statement_allowed(const statement *s, const buckets_policy_args *a) {
  bool matched = false;
  const char *account = a->account ? a->account : "";
  bool principal = false;
  for (size_t i = 0; i < s->principals.n && !principal; i++) {
    principal = buckets_wildcard_match_simple(s->principals.v[i], account);
  }
  if (!principal) goto out;
  if ((!action_match(&s->actions, a->action) && s->actions.n != 0) || action_match(&s->not_actions, a->action)) {
    goto out;
  }
  {
    buckets_buf res = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&res, a->bucket ? a->bucket : "");
    if (a->object && *a->object) {
      if (a->object[0] != '/') buckets_buf_append_char(&res, '/');
      buckets_buf_append_c(&res, a->object);
    }
    const char *rs = res.data ? res.data : "";
    matched = true;
    if (s->nres > 0) {
      bool any = false;
      for (size_t i = 0; i < s->nres && !any; i++) any = res_match(&s->res[i], rs, a);
      if (!any) matched = false;
    }
    if (matched && s->nnot_res > 0) {
      bool any = false;
      for (size_t i = 0; i < s->nnot_res && !any; i++) any = res_match(&s->not_res[i], rs, a);
      if (any) matched = false;
    }
    for (size_t i = 0; i < s->conds.n && matched; i++) matched = func_eval(&s->conds.f[i], a);
    buckets_buf_free(&res);
  }
out:
  return s->eff == EFFECT_ALLOW ? matched : !matched;
}

bool buckets_bucket_policy_allowed(const buckets_policy *p, const buckets_policy_args *a) {
  for (size_t i = 0; i < p->n; i++) {
    if (p->st[i].eff == EFFECT_DENY && !bp_statement_allowed(&p->st[i], a)) return false;
  }
  if (a->owner) return true;
  for (size_t i = 0; i < p->n; i++) {
    if (p->st[i].eff == EFFECT_ALLOW && bp_statement_allowed(&p->st[i], a)) return true;
  }
  return false;
}

void buckets_policy_free(buckets_policy *p) {
  if (!p) return;
  for (size_t i = 0; i < p->n; i++) statement_free(&p->st[i]);
  free(p->st);
  free(p->version);
  free(p->id);
  free(p);
}

bool buckets_policy_is_empty(const buckets_policy *p) { return !p || p->n == 0; }

const char *buckets_policy_version(const buckets_policy *p) { return p && p->version ? p->version : ""; }

bool buckets_policy_is_blank(const buckets_policy *p) {
  return !p || ((!p->version || !*p->version) && (!p->id || !*p->id) && p->n == 0);
}

bool buckets_policies_allowed(const buckets_policy *const *ps, size_t n, const buckets_policy_args *a) {
  for (size_t k = 0; k < n; k++) {
    for (size_t i = 0; ps[k] && i < ps[k]->n; i++) {
      if (ps[k]->st[i].eff == EFFECT_DENY && !statement_allowed(&ps[k]->st[i], a)) return false;
    }
  }
  if (a->deny_only || a->owner) return true;
  for (size_t k = 0; k < n; k++) {
    for (size_t i = 0; ps[k] && i < ps[k]->n; i++) {
      if (ps[k]->st[i].eff == EFFECT_ALLOW && statement_allowed(&ps[k]->st[i], a)) return true;
    }
  }
  return false;
}

static void statement_copy(statement *dst, const statement *src) {
  memset(dst, 0, sizeof(*dst));
  dst->sid = src->sid ? buckets_xstrdup(src->sid) : NULL;
  for (size_t i = 0; i < src->principals.n; i++) set_add(&dst->principals, src->principals.v[i]);
  dst->eff = src->eff;
  dst->eff_raw = src->eff_raw ? buckets_xstrdup(src->eff_raw) : NULL;
  set_copy(&dst->actions, &src->actions);
  set_copy(&dst->not_actions, &src->not_actions);
  dst->res = buckets_xcalloc(src->nres ? src->nres : 1, sizeof(resource));
  for (size_t i = 0; i < src->nres; i++) dst->res[i] = (resource){buckets_xstrdup(src->res[i].pattern), src->res[i].type};
  dst->nres = src->nres;
  dst->not_res = buckets_xcalloc(src->nnot_res ? src->nnot_res : 1, sizeof(resource));
  for (size_t i = 0; i < src->nnot_res; i++) {
    dst->not_res[i] = (resource){buckets_xstrdup(src->not_res[i].pattern), src->not_res[i].type};
  }
  dst->nnot_res = src->nnot_res;
  dst->conds.f = buckets_xcalloc(src->conds.n ? src->conds.n : 1, sizeof(cond_func));
  for (size_t i = 0; i < src->conds.n; i++) {
    const cond_func *f = &src->conds.f[i];
    cond_func *g = &dst->conds.f[i];
    *g = *f;
    g->name = buckets_xstrdup(f->name);
    g->key.name = buckets_xstrdup(f->key.name);
    g->key.variable = f->key.variable ? buckets_xstrdup(f->key.variable) : NULL;
    set_copy(&g->values, &f->values);
    g->nets = f->nnets ? buckets_xmalloc(f->nnets * sizeof(ipnet)) : NULL;
    if (f->nnets) memcpy(g->nets, f->nets, f->nnets * sizeof(ipnet));
    g->bool_value = f->bool_value ? buckets_xstrdup(f->bool_value) : NULL;
  }
  dst->conds.n = src->conds.n;
}

buckets_policy *buckets_policy_merge(const buckets_policy *const *ps, size_t n) {
  buckets_policy *m = buckets_xcalloc(1, sizeof(*m));
  m->version = buckets_xstrdup(DEFAULT_VERSION);
  size_t total = 0;
  for (size_t i = 0; i < n; i++) total += ps[i] ? ps[i]->n : 0;
  m->st = buckets_xcalloc(total ? total : 1, sizeof(statement));
  for (size_t i = 0; i < n; i++) {
    for (size_t j = 0; ps[i] && j < ps[i]->n; j++) {
      bool dup = false;
      for (size_t k = 0; k < m->n && !dup; k++) dup = statements_equal(&m->st[k], &ps[i]->st[j]);
      if (!dup) statement_copy(&m->st[m->n++], &ps[i]->st[j]);
    }
  }
  return m;
}

/* ---- canned policies ------------------------------------------------------------------ */

const char *buckets_policy_canned(const char *name) {
  static const struct {
    const char *name, *doc;
  } canned[] = {
      {"readwrite", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],"
                    "\"Resource\":[\"arn:aws:s3:::*\"]}]}"},
      {"readonly", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketLocation\","
                   "\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::*\"]}]}"},
      {"writeonly", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],"
                    "\"Resource\":[\"arn:aws:s3:::*\"]}]}"},
      {"diagnostics", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"admin:Profiling\","
                      "\"admin:ServerTrace\",\"admin:ConsoleLog\",\"admin:ServerInfo\",\"admin:TopLocksInfo\","
                      "\"admin:OBDInfo\",\"admin:BandwidthMonitor\",\"admin:Prometheus\"],"
                      "\"Resource\":[\"arn:aws:s3:::*\"]}]}"},
      {"consoleAdmin", "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"admin:*\"]},"
                       "{\"Effect\":\"Allow\",\"Action\":[\"kms:*\"]},{\"Effect\":\"Allow\",\"Action\":[\"s3:*\"],"
                       "\"Resource\":[\"arn:aws:s3:::*\"]}]}"},
  };
  for (size_t i = 0; i < BUCKETS_ARRAY_LEN(canned); i++) {
    if (strcmp(canned[i].name, name) == 0) return canned[i].doc;
  }
  return NULL;
}

/* ---- json.Marshal(policy.BucketPolicy) -------------------------------------------------------
 * As MinIO writes a bucket policy it parsed (the export of bucket metadata):
 * sets as arrays (Go writes actions and resources in map order; sorted
 * here), conditions by function name, then key. */

static int str_cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void json_str(buckets_buf *b, const char *s) { buckets_json_go_string(b, s, strlen(s)); }

static void json_sorted_set(buckets_buf *b, const strset *s) {
  char **v = buckets_xcalloc(s->n ? s->n : 1, sizeof(char *));
  memcpy(v, s->v, s->n * sizeof(char *));
  qsort(v, s->n, sizeof(char *), str_cmp);
  buckets_buf_append_char(b, '[');
  for (size_t i = 0; i < s->n; i++) {
    if (i) buckets_buf_append_char(b, ',');
    json_str(b, v[i]);
  }
  buckets_buf_append_char(b, ']');
  free(v);
}

static char *resource_string(const resource *r) {
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, r->type == ARN_TYPE_S3 ? ARN_S3 : r->type == ARN_TYPE_KMS ? ARN_KMS : "*");
  buckets_buf_append_c(&b, r->pattern);
  buckets_buf_append_char(&b, '\0');
  return b.data;
}

static void json_resources(buckets_buf *b, const resource *r, size_t n) {
  strset s = {0};
  for (size_t i = 0; i < n; i++) {
    char *x = resource_string(&r[i]);
    set_add(&s, x);
    free(x);
  }
  json_sorted_set(b, &s);
  set_free(&s);
}

static void json_cidr(buckets_buf *b, const ipnet *n) {
  char a[64];
  if (n->len == 4) snprintf(a, sizeof(a), "%u.%u.%u.%u/%d", n->addr[0], n->addr[1], n->addr[2], n->addr[3], n->bits);
  else {
    struct in6_addr in6;
    memcpy(&in6, n->addr, 16);
    char t[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &in6, t, sizeof(t));
    snprintf(a, sizeof(a), "%s/%d", t, n->bits);
  }
  json_str(b, a);
}

/* One function's values (its toMap). */
static void json_func_values(buckets_buf *b, const cond_func *f) {
  if (f->kind == F_STRING || f->kind == F_STRING_LIKE) {
    json_sorted_set(b, &f->values);
    return;
  }
  buckets_buf_append_char(b, '[');
  switch (f->kind) {
  case F_STRING:
  case F_STRING_LIKE: break;
  case F_IP:
    for (size_t i = 0; i < f->nnets; i++) {
      if (i) buckets_buf_append_char(b, ',');
      json_cidr(b, &f->nets[i]);
    }
    break;
  case F_NULL: buckets_buf_append_c(b, f->null_value ? "true" : "false"); break;
  case F_BOOL: json_str(b, f->bool_value ? f->bool_value : ""); break;
  case F_NUMERIC: buckets_buf_appendf(b, "%lld", f->num); break;
  case F_DATE: {
    char t[64];
    buckets_time_rfc3339_nano(f->date_sec, f->date_nsec, t);
    json_str(b, t);
    break;
  }
  }
  buckets_buf_append_char(b, ']');
}

static int func_cmp(const void *a, const void *b) {
  const cond_func *x = *(const cond_func *const *)a, *y = *(const cond_func *const *)b;
  int c = strcmp(x->name, y->name);
  if (c) return c;
  c = strcmp(x->key.name, y->key.name);
  if (c) return c;
  return strcmp(x->key.variable ? x->key.variable : "", y->key.variable ? y->key.variable : "");
}

static void json_conditions(buckets_buf *b, const functions *fs) {
  const cond_func **v = buckets_xcalloc(fs->n ? fs->n : 1, sizeof(*v));
  for (size_t i = 0; i < fs->n; i++) v[i] = &fs->f[i];
  qsort(v, fs->n, sizeof(*v), func_cmp);
  buckets_buf_append_char(b, '{');
  for (size_t i = 0; i < fs->n; i++) {
    bool first_of_name = i == 0 || strcmp(v[i - 1]->name, v[i]->name) != 0;
    if (first_of_name) {
      if (i) buckets_buf_append_c(b, "},");
      json_str(b, v[i]->name);
      buckets_buf_append_c(b, ":{");
    } else {
      buckets_buf_append_char(b, ',');
    }
    buckets_buf k = BUCKETS_BUF_INIT;
    buckets_buf_append_c(&k, v[i]->key.name);
    if (v[i]->key.variable && *v[i]->key.variable) buckets_buf_appendf(&k, "/%s", v[i]->key.variable);
    buckets_buf_append_char(&k, '\0');
    json_str(b, k.data);
    buckets_buf_free(&k);
    buckets_buf_append_char(b, ':');
    json_func_values(b, v[i]);
  }
  if (fs->n) buckets_buf_append_char(b, '}');
  buckets_buf_append_char(b, '}');
  free(v);
}

void buckets_bucket_policy_json(const buckets_policy *p, buckets_buf *out) {
  buckets_buf_append_char(out, '{');
  if (p->id && *p->id) {
    buckets_buf_append_c(out, "\"ID\":");
    json_str(out, p->id);
    buckets_buf_append_char(out, ',');
  }
  buckets_buf_append_c(out, "\"Version\":");
  json_str(out, p->version ? p->version : "");
  buckets_buf_append_c(out, ",\"Statement\":");
  if (!p->n) buckets_buf_append_c(out, "null");
  else buckets_buf_append_char(out, '[');
  for (size_t i = 0; i < p->n; i++) {
    const statement *s = &p->st[i];
    if (i) buckets_buf_append_char(out, ',');
    buckets_buf_append_char(out, '{');
    if (s->sid && *s->sid) {
      buckets_buf_append_c(out, "\"Sid\":");
      json_str(out, s->sid);
      buckets_buf_append_char(out, ',');
    }
    buckets_buf_append_c(out, "\"Effect\":");
    json_str(out, s->eff == EFFECT_ALLOW ? "Allow" : s->eff == EFFECT_DENY ? "Deny" : (s->eff_raw ? s->eff_raw : ""));
    buckets_buf_append_c(out, ",\"Principal\":{\"AWS\":");
    json_sorted_set(out, &s->principals);
    buckets_buf_append_c(out, "},\"Action\":");
    json_sorted_set(out, &s->actions);
    if (s->not_actions.n) {
      buckets_buf_append_c(out, ",\"NotAction\":");
      json_sorted_set(out, &s->not_actions);
    }
    buckets_buf_append_c(out, ",\"Resource\":");
    json_resources(out, s->res, s->nres);
    if (s->nnot_res) {
      buckets_buf_append_c(out, ",\"NotResource\":");
      json_resources(out, s->not_res, s->nnot_res);
    }
    if (s->conds.n) {
      buckets_buf_append_c(out, ",\"Condition\":");
      json_conditions(out, &s->conds);
    }
    buckets_buf_append_char(out, '}');
  }
  if (p->n) buckets_buf_append_char(out, ']');
  buckets_buf_append_char(out, '}');
}

/* Policy.MatchResource: a statement's resource matches the name (a bucket,
 * for the admin API's bucket filters). */
bool buckets_policy_match_resource(const buckets_policy *p, const char *name) {
  buckets_policy_args none;
  memset(&none, 0, sizeof(none));
  for (size_t i = 0; i < p->n; i++) {
    for (size_t k = 0; k < p->st[i].nres; k++) {
      const resource *r = &p->st[i].res[k];
      if (!strchr(r->pattern, '$')) {
        char *cp = path_clean(name);
        bool exact = strcmp(cp, ".") != 0 && strcmp(cp, r->pattern) == 0;
        free(cp);
        if (exact || buckets_wildcard_match(r->pattern, name)) return true;
      } else if (res_match(r, name, &none)) {
        return true;
      }
    }
  }
  return false;
}
