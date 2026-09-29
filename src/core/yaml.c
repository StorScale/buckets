/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "core/yaml.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include "core/common.h"
#include "core/timefmt.h"

/* ---- resolution (yaml.v3 resolve.go) ------------------------------------------------------- */

static bool str_in(const char *s, const char *const *set) {
  for (; *set; set++)
    if (strcmp(s, *set) == 0) return true;
  return false;
}

/* strconv.ParseInt(s, 0, 64): 0x, 0o, 0b and 0 prefixes, underscores
 * between digits. */
static bool go_parse_int(const char *s, int64_t *out) {
  const char *p = s;
  bool neg = false;
  if (*p == '+' || *p == '-') neg = *p++ == '-';
  int base = 10;
  bool after_digit = false; /* an underscore may follow a digit or a base prefix */
  if (p[0] == '0' && p[1]) {
    char c = (char)tolower((unsigned char)p[1]);
    if (c == 'x') base = 16, p += 2, after_digit = true;
    else if (c == 'o') base = 8, p += 2, after_digit = true;
    else if (c == 'b') base = 2, p += 2, after_digit = true;
    else base = 8, p += 1, after_digit = true;
  }
  if (!*p) return false;
  uint64_t v = 0;
  bool any = false, last_us = false;
  for (; *p; p++) {
    if (*p == '_') {
      if (!after_digit) return false;
      after_digit = false;
      last_us = true;
      continue;
    }
    int d;
    if (isdigit((unsigned char)*p)) d = *p - '0';
    else if (isalpha((unsigned char)*p)) d = tolower((unsigned char)*p) - 'a' + 10;
    else return false;
    if (d >= base) return false;
    if (v > (UINT64_MAX - (uint64_t)d) / (uint64_t)base) return false;
    v = v * (uint64_t)base + (uint64_t)d;
    any = after_digit = true;
    last_us = false;
  }
  if (!any || last_us) return false;
  if (neg ? v > (uint64_t)INT64_MAX + 1 : v > (uint64_t)INT64_MAX) return false;
  *out = neg ? (int64_t)(0 - v) : (int64_t)v;
  return true;
}

/* yamlStyleFloat: ^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$ */
static bool yaml_style_float(const char *s) {
  const char *p = s;
  if (*p == '+' || *p == '-') p++;
  if (*p == '.') {
    p++;
    if (!isdigit((unsigned char)*p)) return false;
    while (isdigit((unsigned char)*p)) p++;
  } else {
    if (!isdigit((unsigned char)*p)) return false;
    while (isdigit((unsigned char)*p)) p++;
    if (*p == '.') {
      p++;
      while (isdigit((unsigned char)*p)) p++;
    }
  }
  if (*p == 'e' || *p == 'E') {
    p++;
    if (*p == '+' || *p == '-') p++;
    if (!isdigit((unsigned char)*p)) return false;
    while (isdigit((unsigned char)*p)) p++;
  }
  return *p == 0;
}

static int digits(const char **p, int max) {
  int n = 0, v = 0;
  while (n < max && isdigit((unsigned char)**p)) v = v * 10 + (*(*p)++ - '0'), n++;
  return n ? v : -1;
}

bool buckets_yaml_parse_timestamp(const char *s, int64_t *sec, int32_t *nsec) {
  /* at least 4 digits and a '-' first (yaml.v3's quick check) */
  if (strlen(s) < 5 || !isdigit((unsigned char)s[0]) || !isdigit((unsigned char)s[1]) ||
      !isdigit((unsigned char)s[2]) || !isdigit((unsigned char)s[3]) || s[4] != '-')
    return false;
  const char *p = s;
  int y = digits(&p, 4);
  if (*p++ != '-') return false;
  int mo = digits(&p, 2);
  if (mo < 1 || mo > 12 || *p++ != '-') return false;
  int d = digits(&p, 2);
  if (d < 1 || d > 31) return false;
  int h = 0, mi = 0, se = 0;
  int32_t frac = 0;
  int64_t off = 0;
  if (*p) {
    if (*p != 'T' && *p != 't' && *p != ' ') return false;
    bool spaced = *p == ' ';
    p++;
    h = digits(&p, 2);
    if (h < 0 || h > 23 || *p++ != ':') return false;
    mi = digits(&p, 2);
    if (mi < 0 || mi > 59 || *p++ != ':') return false;
    se = digits(&p, 2);
    if (se < 0 || se > 60) return false;
    if (*p == '.') {
      p++;
      int n = 0;
      while (isdigit((unsigned char)*p)) {
        if (n < 9) frac = frac * 10 + (*p - '0'), n++;
        p++;
      }
      if (!n) return false;
      while (n++ < 9) frac *= 10;
    }
    if (*p == 'Z') {
      p++;
    } else if (*p == '+' || *p == '-') {
      if (spaced) return false;
      int sign = *p++ == '-' ? -1 : 1;
      int oh = digits(&p, 2);
      if (oh < 0 || *p++ != ':') return false;
      int om = digits(&p, 2);
      if (om < 0) return false;
      off = sign * (oh * 3600 + om * 60);
    } else if (!spaced) {
      return false;
    }
    if (*p) return false;
  }
  *sec = buckets_days_from_civil(y, mo, d) * 86400LL + h * 3600 + mi * 60 + se - off;
  *nsec = frac;
  return true;
}

/* The tag yaml.v3 gives a plain scalar. */
static const char *resolve_plain(const char *s) {
  static const char *const nulls[] = {"", "~", "null", "Null", "NULL", NULL};
  static const char *const bools[] = {"true", "True", "TRUE", "false", "False", "FALSE", NULL};
  static const char *const floats[] = {".inf", ".Inf", ".INF", "+.inf", "+.Inf", "+.INF", "-.inf", "-.Inf", "-.INF",
                                       ".nan", ".NaN", ".NAN", NULL};
  if (str_in(s, nulls)) return "!!null";
  if (str_in(s, bools)) return "!!bool";
  if (str_in(s, floats)) return "!!float";
  if (strcmp(s, "<<") == 0) return "!!merge";
  char c = s[0];
  if (isdigit((unsigned char)c) || c == '+' || c == '-' || c == '.') {
    int64_t sec;
    int32_t ns;
    if (buckets_yaml_parse_timestamp(s, &sec, &ns)) return "!!timestamp";
    int64_t i;
    if (go_parse_int(s, &i)) return "!!int";
    if (yaml_style_float(s)) return "!!float";
    /* big unsigned integers */
    const char *p = s + (c == '+');
    bool alldig = *p != 0;
    for (; *p; p++) alldig &= isdigit((unsigned char)*p) != 0;
    if (alldig) return "!!int";
  }
  return "!!str";
}

static const char *short_tag(const char *tag) {
  static const char prefix[] = "tag:yaml.org,2002:";
  static _Thread_local char buf[64];
  if (strncmp(tag, prefix, sizeof(prefix) - 1) == 0) {
    snprintf(buf, sizeof(buf), "!!%s", tag + sizeof(prefix) - 1);
    return buf;
  }
  return tag;
}

/* ---- the tree -------------------------------------------------------------------------------- */

static buckets_yaml_node *build(yaml_document_t *doc, yaml_node_t *yn, int depth) {
  buckets_yaml_node *n = buckets_xcalloc(1, sizeof(*n));
  n->line = (int)yn->start_mark.line + 1;
  n->col = (int)yn->start_mark.column + 1;
  const char *tag = (const char *)yn->tag;
  bool explicit = tag && strcmp(tag, "?") != 0 && strcmp(tag, "!") != 0;
  if (depth > 64) { /* keep recursion bounded */
    n->kind = BUCKETS_YAML_SCALAR;
    n->tag = buckets_xstrdup("!!null");
    n->value = buckets_xstrdup("");
    return n;
  }
  switch (yn->type) {
  case YAML_SCALAR_NODE:
    n->kind = BUCKETS_YAML_SCALAR;
    n->value = buckets_xstrndup((const char *)yn->data.scalar.value, yn->data.scalar.length);
    n->quoted = yn->data.scalar.style != YAML_PLAIN_SCALAR_STYLE && yn->data.scalar.style != YAML_ANY_SCALAR_STYLE;
    /* libyaml marks plain scalars with the default (str) tag: resolve them */
    if (!n->quoted && (!explicit || strcmp(tag, YAML_DEFAULT_SCALAR_TAG) == 0))
      n->tag = buckets_xstrdup(resolve_plain(n->value));
    else n->tag = buckets_xstrdup(explicit ? short_tag(tag) : "!!str");
    break;
  case YAML_SEQUENCE_NODE: {
    n->kind = BUCKETS_YAML_SEQ;
    n->tag = buckets_xstrdup("!!seq");
    size_t cnt = (size_t)(yn->data.sequence.items.top - yn->data.sequence.items.start);
    n->items = buckets_xcalloc(cnt + 1, sizeof(*n->items));
    for (yaml_node_item_t *it = yn->data.sequence.items.start; it < yn->data.sequence.items.top; it++)
      n->items[n->n++] = build(doc, yaml_document_get_node(doc, *it), depth + 1);
    break;
  }
  case YAML_MAPPING_NODE: {
    n->kind = BUCKETS_YAML_MAP;
    n->tag = buckets_xstrdup("!!map");
    size_t cnt = (size_t)(yn->data.mapping.pairs.top - yn->data.mapping.pairs.start);
    n->items = buckets_xcalloc(2 * cnt + 1, sizeof(*n->items));
    for (yaml_node_pair_t *pr = yn->data.mapping.pairs.start; pr < yn->data.mapping.pairs.top; pr++) {
      n->items[n->n++] = build(doc, yaml_document_get_node(doc, pr->key), depth + 1);
      n->items[n->n++] = build(doc, yaml_document_get_node(doc, pr->value), depth + 1);
    }
    break;
  }
  default:
    n->kind = BUCKETS_YAML_SCALAR;
    n->tag = buckets_xstrdup("!!null");
    n->value = buckets_xstrdup("");
  }
  return n;
}

/* yaml.v3's parser error: "yaml: line N: problem" (the line from the
 * context mark, else the problem mark; scanner errors count from 1). */
static void parse_error(const yaml_parser_t *p, char *err, size_t errlen) {
  size_t line = 0;
  if (p->context_mark.line != 0) {
    line = p->context_mark.line;
    if (p->error == YAML_SCANNER_ERROR) line++;
  } else if (p->problem_mark.line != 0) {
    line = p->problem_mark.line;
    if (p->error == YAML_SCANNER_ERROR) line++;
  }
  const char *problem = p->problem ? p->problem : "unknown problem parsing YAML content";
  if (line) snprintf(err, errlen, "yaml: line %zu: %s", line, problem);
  else snprintf(err, errlen, "yaml: %s", problem);
}

buckets_yaml_node *buckets_yaml_parse(const char *s, size_t n, char *err, size_t errlen) {
  yaml_parser_t p;
  yaml_document_t doc;
  if (!yaml_parser_initialize(&p)) {
    snprintf(err, errlen, "yaml: out of memory");
    return NULL;
  }
  yaml_parser_set_input_string(&p, (const unsigned char *)s, n);
  if (!yaml_parser_load(&p, &doc)) {
    parse_error(&p, err, errlen);
    yaml_parser_delete(&p);
    return NULL;
  }
  yaml_node_t *root = yaml_document_get_root_node(&doc);
  buckets_yaml_node *out;
  if (root) {
    out = build(&doc, root, 0);
  } else {
    out = buckets_xcalloc(1, sizeof(*out));
    out->kind = BUCKETS_YAML_SCALAR;
    out->tag = buckets_xstrdup("!!null");
    out->value = buckets_xstrdup("");
  }
  yaml_document_delete(&doc);
  yaml_parser_delete(&p);
  return out;
}

void buckets_yaml_free(buckets_yaml_node *n) {
  if (!n) return;
  for (size_t i = 0; i < n->n; i++) buckets_yaml_free(n->items[i]);
  free(n->items);
  free(n->tag);
  free(n->value);
  free(n);
}

bool buckets_yaml_is_null(const buckets_yaml_node *n) {
  return !n || (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!null") == 0);
}

const buckets_yaml_node *buckets_yaml_get(const buckets_yaml_node *map, const char *key) {
  if (!map || map->kind != BUCKETS_YAML_MAP) return NULL;
  const buckets_yaml_node *found = NULL;
  for (size_t i = 0; i + 1 < map->n; i += 2) {
    const buckets_yaml_node *k = map->items[i];
    if (k->kind == BUCKETS_YAML_SCALAR && strcmp(k->value, key) == 0) found = map->items[i + 1];
  }
  return found;
}

/* ---- decoding --------------------------------------------------------------------------------- */

void buckets_yaml_dec_free(buckets_yaml_dec *d) {
  buckets_buf_free(&d->terrors);
  free(d->fatal);
  memset(d, 0, sizeof(*d));
}

void buckets_yaml_terror(buckets_yaml_dec *d, const buckets_yaml_node *n, const char *gotype) {
  char value[32] = "";
  if (n->kind == BUCKETS_YAML_SCALAR) {
    if (strlen(n->value) > 10) snprintf(value, sizeof(value), " `%.7s...`", n->value);
    else snprintf(value, sizeof(value), " `%s`", n->value);
  }
  buckets_buf_appendf(&d->terrors, "\n  line %d: cannot unmarshal %s%s into %s", n->line, n->tag, value, gotype);
}

void buckets_yaml_fail(buckets_yaml_dec *d, const char *msg) {
  if (!d->fatal) d->fatal = buckets_xstrdup(msg);
}

char *buckets_yaml_dec_error(const buckets_yaml_dec *d) {
  if (d->fatal) return buckets_xstrdup(d->fatal);
  if (!d->terrors.len) return NULL;
  buckets_buf b = BUCKETS_BUF_INIT;
  buckets_buf_append_c(&b, "yaml: unmarshal errors:");
  buckets_buf_append(&b, d->terrors.data, d->terrors.len);
  return buckets_buf_detach(&b);
}

void buckets_yaml_dec_str(buckets_yaml_dec *d, const buckets_yaml_node *n, char **out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  if (n->kind != BUCKETS_YAML_SCALAR || strcmp(n->tag, "!!binary") == 0) {
    buckets_yaml_terror(d, n, "string");
    return;
  }
  free(*out);
  *out = buckets_xstrdup(n->value);
}

void buckets_yaml_dec_int(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *out, const char *gotype) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  int64_t v;
  if (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!int") == 0 && go_parse_int(n->value, &v)) {
    *out = v;
    return;
  }
  /* floats with an integral value decode into ints */
  if (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!float") == 0) {
    double f = strtod(n->value, NULL);
    if (f == (double)(int64_t)f) {
      *out = (int64_t)f;
      return;
    }
  }
  buckets_yaml_terror(d, n, gotype);
}

void buckets_yaml_dec_bool(buckets_yaml_dec *d, const buckets_yaml_node *n, bool *out) {
  static const char *const yes[] = {"y", "Y", "yes", "Yes", "YES", "on", "On", "ON", NULL};
  static const char *const no[] = {"n", "N", "no", "No", "NO", "off", "Off", "OFF", NULL};
  if (buckets_yaml_is_null(n) || d->fatal) return;
  if (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!bool") == 0) {
    *out = n->value[0] == 't' || n->value[0] == 'T';
    return;
  }
  /* YAML 1.1 booleans, for a bool target (yaml.v3 decode.go) */
  if (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!str") == 0 && !n->quoted) {
    if (str_in(n->value, yes)) {
      *out = true;
      return;
    }
    if (str_in(n->value, no)) {
      *out = false;
      return;
    }
  }
  buckets_yaml_terror(d, n, "bool");
}

void buckets_yaml_dec_duration(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *out) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  int64_t v;
  if (n->kind == BUCKETS_YAML_SCALAR && strcmp(n->tag, "!!str") == 0 && buckets_go_duration_parse(n->value, &v)) {
    *out = v;
    return;
  }
  buckets_yaml_terror(d, n, "time.Duration");
}

void buckets_yaml_dec_time(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *sec, int32_t *nsec, bool *set) {
  if (buckets_yaml_is_null(n) || d->fatal) return;
  if (n->kind == BUCKETS_YAML_SCALAR &&
      (strcmp(n->tag, "!!timestamp") == 0 || strcmp(n->tag, "!!str") == 0) &&
      buckets_yaml_parse_timestamp(n->value, sec, nsec)) {
    *set = true;
    return;
  }
  buckets_yaml_terror(d, n, "time.Time");
}

/* ---- writing ------------------------------------------------------------------------------------ */

/* libyaml's analysis: may s be written plain in block context, or single-quoted? */
static void analyze(const char *s, bool *plain, bool *single) {
  size_t n = strlen(s);
  *plain = *single = true;
  if (!n) {
    *plain = false;
    return;
  }
  if ((strncmp(s, "---", 3) == 0 || strncmp(s, "...", 3) == 0) &&
      (n == 3 || s[3] == ' ' || s[3] == '\t' || s[3] == '\n'))
    *plain = false;
  bool preceded_by_ws = true;
  for (size_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    bool followed_by_ws = i + 1 >= n || s[i + 1] == ' ' || s[i + 1] == '\t' || s[i + 1] == '\n' || s[i + 1] == '\r';
    if (i == 0) {
      if (strchr("#,[]{}&*!|>'\"%@`", c)) *plain = false;
      if ((c == '?' || c == ':') && followed_by_ws) *plain = false;
      if (c == '-' && followed_by_ws) *plain = false;
    } else {
      if (c == ':' && followed_by_ws) *plain = false;
      if (c == '#' && preceded_by_ws) *plain = false;
    }
    if (c == '\n' || c == '\r') *plain = *single = false; /* yaml.v3 writes a literal block; quoted here */
    if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f) *plain = *single = false;
    preceded_by_ws = c == ' ' || c == '\t' || c == '\n' || c == '\r';
  }
  if (s[0] == ' ' || s[0] == '\t' || s[n - 1] == ' ' || s[n - 1] == '\t') *plain = false;
  if (s[n - 1] == '\n') *plain = false;
}

static void double_quoted(buckets_buf *out, const char *s) {
  buckets_buf_append_c(out, "\"");
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    switch (*p) {
    case '"': buckets_buf_append_c(out, "\\\""); break;
    case '\\': buckets_buf_append_c(out, "\\\\"); break;
    case '\n': buckets_buf_append_c(out, "\\n"); break;
    case '\t': buckets_buf_append_c(out, "\\t"); break;
    case '\r': buckets_buf_append_c(out, "\\r"); break;
    case 0: buckets_buf_append_c(out, "\\0"); break;
    default:
      if (*p < 0x20 || *p == 0x7f) buckets_buf_appendf(out, "\\x%02X", *p);
      else buckets_buf_append(out, p, 1);
    }
  }
  buckets_buf_append_c(out, "\"");
}

void buckets_yaml_scalar(buckets_buf *out, const char *s) {
  static const char *const old_bools[] = {"y", "Y", "yes", "Yes", "YES", "on", "On", "ON",
                                          "n", "N", "no", "No", "NO", "off", "Off", "OFF", NULL};
  /* encode.go stringv: strings that would read back as another type are
   * double-quoted, and so are YAML 1.1 booleans and base 60 floats */
  bool can_plain = strcmp(resolve_plain(s), "!!str") == 0 && !str_in(s, old_bools);
  if (can_plain) {
    /* base 60 float: [-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)? */
    const char *p = s;
    if (*p == '+' || *p == '-') p++;
    if (isdigit((unsigned char)*p) && strchr(p, ':')) {
      bool ok = true;
      for (const char *q = p; *q && ok; q++) ok = isdigit((unsigned char)*q) || *q == '_' || *q == ':' || *q == '.';
      if (ok) can_plain = false;
    }
  }
  if (!can_plain) {
    double_quoted(out, s);
    return;
  }
  bool plain, single;
  analyze(s, &plain, &single);
  if (plain) {
    buckets_buf_append_c(out, s);
  } else if (single) {
    buckets_buf_append_c(out, "'");
    for (const char *q = s; *q; q++) {
      if (*q == '\'') buckets_buf_append_c(out, "''");
      else buckets_buf_append(out, q, 1);
    }
    buckets_buf_append_c(out, "'");
  } else {
    double_quoted(out, s);
  }
}

static void pad(buckets_buf *out, int n) {
  for (int i = 0; i < n; i++) buckets_buf_append_c(out, " ");
}

/* The writer keeps the column of the current mapping's keys; a sequence
 * item's first key follows its "- ". */
static void key_prefix(buckets_yaml_writer *w, const char *key) {
  if (w->in_seq_item) {
    pad(w->out, w->depth - 2);
    buckets_buf_append_c(w->out, "- ");
    w->in_seq_item = false;
  } else {
    pad(w->out, w->depth);
  }
  buckets_buf_appendf(w->out, "%s:", key);
}

/* yaml.v3's increase_indent: align to the next multiple of 4 */
static int align4(int indent) { return 4 * ((indent + 4) / 4); }

static void push(buckets_yaml_writer *w, bool seq, int seq_col) {
  if (w->sp >= (int)BUCKETS_ARRAY_LEN(w->frames)) return;
  w->frames[w->sp].indent = w->depth;
  w->frames[w->sp].seq_col = seq_col;
  w->frames[w->sp].seq = seq;
  w->sp++;
}

void buckets_yaml_w_str(buckets_yaml_writer *w, const char *key, const char *value) {
  key_prefix(w, key);
  buckets_buf_append_c(w->out, " ");
  buckets_yaml_scalar(w->out, value ? value : "");
  buckets_buf_append_c(w->out, "\n");
}

void buckets_yaml_w_raw(buckets_yaml_writer *w, const char *key, const char *value) {
  key_prefix(w, key);
  buckets_buf_appendf(w->out, " %s\n", value);
}

void buckets_yaml_w_int(buckets_yaml_writer *w, const char *key, int64_t v) {
  char b[32];
  snprintf(b, sizeof(b), "%" PRId64, v);
  buckets_yaml_w_raw(w, key, b);
}

void buckets_yaml_w_bool(buckets_yaml_writer *w, const char *key, bool v) {
  buckets_yaml_w_raw(w, key, v ? "true" : "false");
}

void buckets_yaml_w_map(buckets_yaml_writer *w, const char *key) {
  key_prefix(w, key);
  buckets_buf_append_c(w->out, "\n");
  push(w, false, 0);
  w->depth = align4(w->depth);
}

void buckets_yaml_w_seq(buckets_yaml_writer *w, const char *key, size_t n) {
  key_prefix(w, key);
  if (!n) {
    buckets_buf_append_c(w->out, " []\n");
    return;
  }
  buckets_buf_append_c(w->out, "\n");
  int col = align4(w->depth);
  push(w, true, col);
}

void buckets_yaml_w_item(buckets_yaml_writer *w) {
  if (!w->sp || !w->frames[w->sp - 1].seq) return;
  w->depth = w->frames[w->sp - 1].seq_col + 2;
  w->in_seq_item = true;
}

void buckets_yaml_w_seq_str(buckets_yaml_writer *w, const char *value) {
  if (!w->sp || !w->frames[w->sp - 1].seq) return;
  pad(w->out, w->frames[w->sp - 1].seq_col);
  buckets_buf_append_c(w->out, "- ");
  buckets_yaml_scalar(w->out, value);
  buckets_buf_append_c(w->out, "\n");
}

void buckets_yaml_w_end(buckets_yaml_writer *w) {
  if (!w->sp) return;
  w->depth = w->frames[--w->sp].indent;
  w->in_seq_item = false;
}

/* ---- Go durations -------------------------------------------------------------------------------- */

/* fmtFrac/fmtInt of time.Duration.String */
void buckets_go_duration_string(int64_t d, char *out, size_t cap) {
  char buf[32];
  int w = (int)sizeof(buf);
  uint64_t u = (uint64_t)d;
  bool neg = d < 0;
  if (neg) u = 0 - u;
  if (u < 1000000000ULL) {
    int prec = 0;
    w--;
    buf[w] = 's';
    w--;
    if (u == 0) {
      snprintf(out, cap, "0s");
      return;
    } else if (u < 1000ULL) {
      prec = 0;
      buf[w] = 'n';
    } else if (u < 1000000ULL) {
      prec = 3;
      /* U+00B5 'µ' micro sign, 0xC2 0xB5 */
      w--;
      memcpy(&buf[w], "\xC2\xB5", 2);
    } else {
      prec = 6;
      buf[w] = 'm';
    }
    /* fmtFrac */
    bool print = false;
    for (int i = 0; i < prec; i++) {
      int digit = (int)(u % 10);
      print = print || digit != 0;
      if (print) buf[--w] = (char)('0' + digit);
      u /= 10;
    }
    if (print) buf[--w] = '.';
    /* fmtInt */
    if (u == 0) buf[--w] = '0';
    while (u > 0) buf[--w] = (char)('0' + u % 10), u /= 10;
  } else {
    buf[--w] = 's';
    bool print = false;
    for (int i = 0; i < 9; i++) {
      int digit = (int)(u % 10);
      print = print || digit != 0;
      if (print) buf[--w] = (char)('0' + digit);
      u /= 10;
    }
    if (print) buf[--w] = '.';
    uint64_t secs = u % 60;
    if (secs == 0) buf[--w] = '0';
    while (secs > 0) buf[--w] = (char)('0' + secs % 10), secs /= 10;
    u /= 60;
    if (u > 0) {
      buf[--w] = 'm';
      uint64_t mins = u % 60;
      if (mins == 0) buf[--w] = '0';
      while (mins > 0) buf[--w] = (char)('0' + mins % 10), mins /= 10;
      u /= 60;
      if (u > 0) {
        buf[--w] = 'h';
        while (u > 0) buf[--w] = (char)('0' + u % 10), u /= 10;
      }
    }
  }
  if (neg) buf[--w] = '-';
  snprintf(out, cap, "%.*s", (int)sizeof(buf) - w, buf + w);
}
