/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/tags.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "s3/xml.h"

void buckets_tags_free(buckets_tags *t) {
  for (size_t i = 0; i < t->n; i++) {
    free(t->keys[i]);
    free(t->values[i]);
  }
  free(t->keys);
  free(t->values);
  memset(t, 0, sizeof(*t));
}

static long find(const buckets_tags *t, const char *key) {
  for (size_t i = 0; i < t->n; i++)
    if (strcmp(t->keys[i], key) == 0) return (long)i;
  return -1;
}

const char *buckets_tags_get(const buckets_tags *t, const char *key) {
  long i = find(t, key);
  return i < 0 ? NULL : t->values[i];
}

static size_t rune_count(const char *s) {
  size_t n = 0;
  for (; *s; s++) n += ((unsigned char)*s & 0xC0) != 0x80;
  return n;
}

/* ^[a-zA-Z0-9-+\-._:/@ =]+$ */
static bool valid_chars(const char *s) {
  if (!*s) return false;
  for (; *s; s++) {
    char c = *s;
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("-+._:/@ =", c);
    if (!ok) return false;
  }
  return true;
}

static buckets_tags_err check_key(const char *k) {
  if (!*k || rune_count(k) > 128 || !valid_chars(k)) return BUCKETS_TAGS_INVALID_KEY;
  return BUCKETS_TAGS_OK;
}

static buckets_tags_err check_value(const char *v) {
  if (*v && (rune_count(v) > 256 || !valid_chars(v))) return BUCKETS_TAGS_INVALID_VALUE;
  return BUCKETS_TAGS_OK;
}

static void append(buckets_tags *t, const char *k, const char *v) {
  t->keys = buckets_xrealloc(t->keys, (t->n + 1) * sizeof(char *));
  t->values = buckets_xrealloc(t->values, (t->n + 1) * sizeof(char *));
  t->keys[t->n] = buckets_xstrdup(k);
  t->values[t->n] = buckets_xstrdup(v);
  t->n++;
}

/* tagSet.set(key, value, failOnExist=true) */
static buckets_tags_err set(buckets_tags *t, const char *k, const char *v, bool is_object) {
  if (find(t, k) >= 0) return BUCKETS_TAGS_DUPLICATE_KEY;
  buckets_tags_err e = check_key(k);
  if (!e) e = check_value(v);
  if (e) return e;
  if (t->n == (is_object ? BUCKETS_TAGS_MAX_OBJECT : BUCKETS_TAGS_MAX_BUCKET))
    return is_object ? BUCKETS_TAGS_TOO_MANY_OBJECT : BUCKETS_TAGS_TOO_MANY;
  append(t, k, v);
  return BUCKETS_TAGS_OK;
}

static int unhex(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

/* url.QueryUnescape of s[0:n]; on error, detail gets Go's EscapeError text. */
static char *query_unescape(const char *s, size_t n, char *detail, size_t cap) {
  char *out = buckets_xmalloc(n + 1);
  size_t j = 0;
  for (size_t i = 0; i < n; i++) {
    if (s[i] == '%') {
      if (i + 2 >= n || unhex(s[i + 1]) < 0 || unhex(s[i + 2]) < 0) {
        size_t el = n - i < 3 ? n - i : 3;
        snprintf(detail, cap, "invalid URL escape \"%.*s\"", (int)el, s + i);
        free(out);
        return NULL;
      }
      out[j++] = (char)(unhex(s[i + 1]) << 4 | unhex(s[i + 2]));
      i += 2;
    } else {
      out[j++] = s[i] == '+' ? ' ' : s[i];
    }
  }
  out[j] = '\0';
  return out;
}

bool buckets_tags_parse_query(const char *s, bool is_object, buckets_tags *out, buckets_tags_error *err) {
  memset(out, 0, sizeof(*out));
  memset(err, 0, sizeof(*err));
  /* Faithful to tagSet.parseTags: an unescape error is remembered, but a
   * later successful set() overwrites it. */
  while (*s) {
    const char *amp = strchr(s, '&');
    size_t pl = amp ? (size_t)(amp - s) : strlen(s);
    const char *pair = s;
    s = amp ? amp + 1 : s + pl;
    if (!pl) continue;
    const char *eq = memchr(pair, '=', pl);
    size_t kl = eq ? (size_t)(eq - pair) : pl;
    char detail[64];
    char *k = query_unescape(pair, kl, detail, sizeof(detail));
    char *v = k && eq ? query_unescape(eq + 1, pl - kl - 1, detail, sizeof(detail)) : k ? buckets_xstrdup("") : NULL;
    if (!k || !v) {
      if (!err->code) {
        err->code = BUCKETS_TAGS_BAD_ESCAPE;
        snprintf(err->detail, sizeof(err->detail), "%s", detail);
      }
      free(k);
      free(v);
      continue;
    }
    err->code = set(out, k, v, is_object);
    free(k);
    free(v);
    if (err->code) {
      buckets_tags_free(out);
      return false;
    }
  }
  if (err->code) buckets_tags_free(out);
  return !err->code;
}

static bool text_of(const buckets_xml_doc *d, size_t node, buckets_buf *out) {
  buckets_buf_reset(out);
  return buckets_xml_unescape(d->nodes[node].text, out);
}

static const char *cstr(const buckets_buf *b) { return b->data ? b->data : ""; }

bool buckets_tags_parse_xml(const char *xml, size_t len, bool is_object, buckets_tags *out, buckets_tags_error *err) {
  memset(out, 0, sizeof(*out));
  memset(err, 0, sizeof(*err));
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d)) {
    if (d.nodes) buckets_xml_doc_free(&d);
    err->code = BUCKETS_TAGS_MALFORMED_XML;
    /* Go's decoder reports io.EOF when no element starts at all. */
    snprintf(err->detail, sizeof(err->detail), "%s", memchr(xml, '<', len) ? "XML syntax error" : "EOF");
    return false;
  }
  if (!buckets_str_eq_c(d.nodes[0].name, "Tagging")) {
    err->code = BUCKETS_TAGS_MALFORMED_XML;
    snprintf(err->detail, sizeof(err->detail), "expected element type <Tagging> but have <%.*s>",
             (int)BUCKETS_MIN(d.nodes[0].name.n, 64), d.nodes[0].name.p);
    buckets_xml_doc_free(&d);
    return false;
  }
  buckets_buf k = BUCKETS_BUF_INIT, v = BUCKETS_BUF_INIT;
  for (size_t ts = d.nodes[0].first_child; ts && !err->code; ts = d.nodes[ts].next_sibling) {
    if (!buckets_str_eq_c(d.nodes[ts].name, "TagSet")) continue;
    /* Each TagSet replaces the previous one (tagSet.UnmarshalXML). */
    buckets_tags list = {0};
    for (size_t tg = d.nodes[ts].first_child; tg && !err->code; tg = d.nodes[tg].next_sibling) {
      if (!buckets_str_eq_c(d.nodes[tg].name, "Tag")) continue;
      buckets_buf_reset(&k);
      buckets_buf_reset(&v);
      for (size_t f = d.nodes[tg].first_child; f; f = d.nodes[f].next_sibling) {
        if (buckets_str_eq_c(d.nodes[f].name, "Key")) text_of(&d, f, &k);
        else if (buckets_str_eq_c(d.nodes[f].name, "Value")) text_of(&d, f, &v);
      }
      if (!(err->code = check_key(cstr(&k)))) err->code = check_value(cstr(&v));
      if (!err->code) append(&list, cstr(&k), cstr(&v));
    }
    if (!err->code && list.n > (is_object ? BUCKETS_TAGS_MAX_OBJECT : BUCKETS_TAGS_MAX_BUCKET))
      err->code = is_object ? BUCKETS_TAGS_TOO_MANY_OBJECT : BUCKETS_TAGS_TOO_MANY;
    for (size_t i = 0; i < list.n && !err->code; i++)
      for (size_t j = 0; j < i; j++)
        if (strcmp(list.keys[i], list.keys[j]) == 0) err->code = BUCKETS_TAGS_DUPLICATE_KEY;
    buckets_tags_free(out);
    *out = list;
  }
  buckets_buf_free(&k);
  buckets_buf_free(&v);
  buckets_xml_doc_free(&d);
  if (err->code) buckets_tags_free(out);
  return !err->code;
}

static int cmp_idx(const void *a, const void *b, void *ud) {
  const buckets_tags *t = ud;
  return strcmp(t->keys[*(const size_t *)a], t->keys[*(const size_t *)b]);
}

/* Insertion sort of indices by key (tag sets are small). */
static size_t *sorted(const buckets_tags *t) {
  size_t *ix = buckets_xmalloc((t->n ? t->n : 1) * sizeof(size_t));
  for (size_t i = 0; i < t->n; i++) {
    size_t j = i;
    for (; j > 0 && cmp_idx(&ix[j - 1], &i, (void *)t) > 0; j--) ix[j] = ix[j - 1];
    ix[j] = i;
  }
  return ix;
}

static void query_escape(buckets_buf *out, const char *s) {
  static const char hex[] = "0123456789ABCDEF";
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
        c == '~') {
      buckets_buf_append_char(out, (char)c);
    } else if (c == ' ') {
      buckets_buf_append_char(out, '+');
    } else {
      char e[3] = {'%', hex[c >> 4], hex[c & 15]};
      buckets_buf_append(out, e, 3);
    }
  }
}

void buckets_tags_string(const buckets_tags *t, buckets_buf *out) {
  size_t *ix = sorted(t);
  for (size_t i = 0; i < t->n; i++) {
    if (i) buckets_buf_append_char(out, '&');
    query_escape(out, t->keys[ix[i]]);
    buckets_buf_append_char(out, '=');
    query_escape(out, t->values[ix[i]]);
  }
  free(ix);
}

void buckets_tags_xml(const buckets_tags *t, buckets_buf *out) {
  size_t *ix = sorted(t);
  buckets_xml_open(out, "Tagging");
  buckets_xml_open(out, "TagSet");
  for (size_t i = 0; i < t->n; i++) {
    buckets_xml_open(out, "Tag");
    buckets_xml_elem(out, "Key", t->keys[ix[i]]);
    buckets_xml_elem(out, "Value", t->values[ix[i]]);
    buckets_xml_close(out, "Tag");
  }
  buckets_xml_close(out, "TagSet");
  buckets_xml_close(out, "Tagging");
  free(ix);
}

const char *buckets_tags_err_code(const buckets_tags_error *err) {
  switch (err->code) {
  case BUCKETS_TAGS_TOO_MANY_OBJECT:
  case BUCKETS_TAGS_TOO_MANY: return "BadRequest";
  case BUCKETS_TAGS_BAD_ESCAPE: return "XMinioInvalidObjectName";
  case BUCKETS_TAGS_MALFORMED_XML: return "MalformedXML";
  case BUCKETS_TAGS_OK: return "";
  default: return "InvalidTag";
  }
}

void buckets_tags_err_message(const buckets_tags_error *err, char *out, size_t cap) {
  switch (err->code) {
  case BUCKETS_TAGS_TOO_MANY_OBJECT: snprintf(out, cap, "Tags cannot be more than 10"); break;
  case BUCKETS_TAGS_TOO_MANY: snprintf(out, cap, "Tags cannot be more than 50"); break;
  case BUCKETS_TAGS_INVALID_KEY: snprintf(out, cap, "The TagKey you have provided is invalid"); break;
  case BUCKETS_TAGS_INVALID_VALUE: snprintf(out, cap, "The TagValue you have provided is invalid"); break;
  case BUCKETS_TAGS_DUPLICATE_KEY: snprintf(out, cap, "Cannot provide multiple Tags with the same key"); break;
  case BUCKETS_TAGS_BAD_ESCAPE:
    snprintf(out, cap, "Object name contains unsupported characters. (%s)", err->detail);
    break;
  case BUCKETS_TAGS_MALFORMED_XML: snprintf(out, cap, "%s", err->detail); break;
  default: *out = '\0';
  }
}
