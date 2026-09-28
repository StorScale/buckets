/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "s3/xml.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- writer -------------------------------------------------------------- */

void buckets_xml_header(buckets_buf *out) {
  buckets_buf_append_c(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
}

void buckets_xml_open(buckets_buf *out, const char *tag) { buckets_buf_appendf(out, "<%s>", tag); }

void buckets_xml_open_ns(buckets_buf *out, const char *tag, const char *xmlns) {
  buckets_buf_appendf(out, "<%s xmlns=\"%s\">", tag, xmlns);
}

void buckets_xml_close(buckets_buf *out, const char *tag) { buckets_buf_appendf(out, "</%s>", tag); }

void buckets_xml_text(buckets_buf *out, const char *s, size_t n) {
  size_t run = 0;
  for (size_t i = 0; i < n; i++) {
    const char *rep = NULL;
    switch (s[i]) {
      case '&': rep = "&amp;"; break;
      case '<': rep = "&lt;"; break;
      case '>': rep = "&gt;"; break;
      case '"': rep = "&#34;"; break; /* as Go's xml.EscapeText */
      case '\'': rep = "&#39;"; break;
      case '\r': rep = "&#xD;"; break;
      case '\n': rep = "&#xA;"; break;
      case '\t': rep = "&#x9;"; break;
      default: break;
    }
    if (rep) {
      buckets_buf_append(out, s + run, i - run);
      buckets_buf_append_c(out, rep);
      run = i + 1;
    }
  }
  buckets_buf_append(out, s + run, n - run);
}

void buckets_xml_elem_str(buckets_buf *out, const char *tag, buckets_str text) {
  buckets_xml_open(out, tag);
  buckets_xml_text(out, text.p, text.n);
  buckets_xml_close(out, tag);
}

void buckets_xml_elem(buckets_buf *out, const char *tag, const char *text) {
  buckets_xml_elem_str(out, tag, buckets_str_c(text ? text : ""));
}

/* ---- reader -------------------------------------------------------------- */

enum { MAX_DEPTH = 32, MAX_NODES = 100000 };

typedef struct {
  size_t idx;
  size_t last_child;
  const char *qname;
  size_t qlen;
  const char *text_start;
  bool has_child;
} frame;

static bool is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static bool is_name_char(char c) {
  return !is_space(c) && c != '>' && c != '/' && c != '=' && c != '<' && c != '"' && c != '\'' &&
         c != '\0';
}

static bool starts(const char *p, const char *end, const char *lit) {
  size_t n = strlen(lit);
  return (size_t)(end - p) >= n && memcmp(p, lit, n) == 0;
}

static const char *find(const char *p, const char *end, const char *lit) {
  size_t n = strlen(lit);
  for (; (size_t)(end - p) >= n; p++) {
    if (memcmp(p, lit, n) == 0) return p;
  }
  return NULL;
}

static buckets_str local_name(const char *q, size_t n) {
  const char *colon = memchr(q, ':', n);
  if (!colon) return (buckets_str){q, n};
  return (buckets_str){colon + 1, n - (size_t)(colon + 1 - q)};
}

static size_t add_node(buckets_xml_doc *doc) {
  if (doc->count == doc->cap) {
    doc->cap = doc->cap ? doc->cap * 2 : 16;
    doc->nodes = buckets_xrealloc(doc->nodes, doc->cap * sizeof(buckets_xml_node));
  }
  memset(&doc->nodes[doc->count], 0, sizeof(buckets_xml_node));
  return doc->count++;
}

bool buckets_xml_parse(buckets_str input, buckets_xml_doc *doc) {
  memset(doc, 0, sizeof(*doc));
  const char *p = input.p, *end = input.p + input.n;
  frame stack[MAX_DEPTH];
  int sp = 0;
  bool root_done = false;

  while (p < end) {
    if (sp == 0) {
      if (is_space(*p)) {
        p++;
        continue;
      }
      if (*p != '<') goto fail; /* text outside the root element */
    } else if (*p != '<') {
      p++;
      continue;
    }

    if (starts(p, end, "<?")) {
      const char *q = find(p + 2, end, "?>");
      if (!q) goto fail;
      p = q + 2;
      continue;
    }
    if (starts(p, end, "<!--")) {
      const char *q = find(p + 4, end, "-->");
      if (!q) goto fail;
      p = q + 3;
      continue;
    }
    if (starts(p, end, "<!")) goto fail; /* DOCTYPE, ENTITY, CDATA: refused */

    if (starts(p, end, "</")) {
      const char *lt = p;
      p += 2;
      const char *name = p;
      while (p < end && is_name_char(*p)) p++;
      size_t nlen = (size_t)(p - name);
      while (p < end && is_space(*p)) p++;
      if (p >= end || *p != '>' || sp == 0) goto fail;
      frame *f = &stack[sp - 1];
      if (f->qlen != nlen || memcmp(f->qname, name, nlen) != 0) goto fail;
      if (!f->has_child) doc->nodes[f->idx].text = (buckets_str){f->text_start, (size_t)(lt - f->text_start)};
      p++;
      if (--sp == 0) root_done = true;
      continue;
    }

    /* open tag */
    if (root_done && sp == 0) goto fail; /* second root */
    p++;
    const char *name = p;
    while (p < end && is_name_char(*p)) p++;
    size_t nlen = (size_t)(p - name);
    if (nlen == 0) goto fail;
    bool self_close = false;
    for (;;) { /* attributes are skipped (only xmlns appears in practice) */
      while (p < end && is_space(*p)) p++;
      if (p >= end) goto fail;
      if (*p == '>') {
        p++;
        break;
      }
      if (*p == '/') {
        if (p + 1 >= end || p[1] != '>') goto fail;
        p += 2;
        self_close = true;
        break;
      }
      const char *an = p;
      while (p < end && is_name_char(*p)) p++;
      if (p == an) goto fail;
      while (p < end && is_space(*p)) p++;
      if (p >= end || *p != '=') goto fail;
      p++;
      while (p < end && is_space(*p)) p++;
      if (p >= end || (*p != '"' && *p != '\'')) goto fail;
      char quote = *p++;
      const char *close = memchr(p, quote, (size_t)(end - p));
      if (!close) goto fail;
      p = close + 1;
    }

    if (doc->count >= MAX_NODES) goto fail;
    size_t idx = add_node(doc);
    doc->nodes[idx].name = local_name(name, nlen);
    doc->nodes[idx].depth = sp;
    if (sp > 0) {
      frame *parent = &stack[sp - 1];
      if (parent->last_child == 0 && !parent->has_child) {
        doc->nodes[parent->idx].first_child = idx;
      } else {
        doc->nodes[parent->last_child].next_sibling = idx;
      }
      parent->last_child = idx;
      parent->has_child = true;
    }
    if (self_close) {
      doc->nodes[idx].text = (buckets_str){p, 0};
      if (sp == 0) root_done = true;
      continue;
    }
    if (sp == MAX_DEPTH) goto fail;
    stack[sp++] = (frame){idx, 0, name, nlen, p, false};
  }
  if (sp == 0 && root_done) return true;

fail:
  buckets_xml_doc_free(doc);
  return false;
}

void buckets_xml_doc_free(buckets_xml_doc *doc) {
  free(doc->nodes);
  memset(doc, 0, sizeof(*doc));
}

size_t buckets_xml_child(const buckets_xml_doc *doc, size_t parent, const char *name) {
  for (size_t i = doc->nodes[parent].first_child; i; i = doc->nodes[i].next_sibling) {
    if (buckets_str_eq_c(doc->nodes[i].name, name)) return i;
  }
  return 0;
}

static void put_utf8(buckets_buf *out, unsigned long cp) {
  char b[4];
  if (cp < 0x80) {
    b[0] = (char)cp;
    buckets_buf_append(out, b, 1);
  } else if (cp < 0x800) {
    b[0] = (char)(0xC0 | (cp >> 6));
    b[1] = (char)(0x80 | (cp & 0x3F));
    buckets_buf_append(out, b, 2);
  } else if (cp < 0x10000) {
    b[0] = (char)(0xE0 | (cp >> 12));
    b[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    b[2] = (char)(0x80 | (cp & 0x3F));
    buckets_buf_append(out, b, 3);
  } else {
    b[0] = (char)(0xF0 | (cp >> 18));
    b[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    b[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    b[3] = (char)(0x80 | (cp & 0x3F));
    buckets_buf_append(out, b, 4);
  }
}

bool buckets_xml_unescape(buckets_str text, buckets_buf *out) {
  static const struct {
    const char *name;
    char ch;
  } named[] = {{"amp", '&'}, {"lt", '<'}, {"gt", '>'}, {"quot", '"'}, {"apos", '\''}};
  for (size_t i = 0; i < text.n; i++) {
    if (text.p[i] != '&') {
      buckets_buf_append_char(out, text.p[i]);
      continue;
    }
    const char *semi = memchr(text.p + i, ';', text.n - i);
    if (!semi) return false;
    buckets_str ent = {text.p + i + 1, (size_t)(semi - (text.p + i + 1))};
    bool ok = false;
    if (ent.n >= 2 && ent.p[0] == '#') {
      bool hex = ent.p[1] == 'x' || ent.p[1] == 'X';
      unsigned long cp = 0;
      size_t j = hex ? 2 : 1;
      if (j == ent.n || ent.n - j > 8) return false;
      for (; j < ent.n; j++) {
        char c = ent.p[j];
        int d = (c >= '0' && c <= '9') ? c - '0'
                : (hex && c >= 'a' && c <= 'f') ? c - 'a' + 10
                : (hex && c >= 'A' && c <= 'F') ? c - 'A' + 10
                                                : -1;
        if (d < 0) return false;
        cp = cp * (hex ? 16 : 10) + (unsigned long)d;
      }
      if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
      put_utf8(out, cp);
      ok = true;
    } else {
      for (size_t k = 0; k < BUCKETS_ARRAY_LEN(named); k++) {
        if (buckets_str_eq_c(ent, named[k].name)) {
          buckets_buf_append_char(out, named[k].ch);
          ok = true;
          break;
        }
      }
    }
    if (!ok) return false;
    i = (size_t)(semi - text.p);
  }
  return true;
}

bool buckets_xml_root_xmlns(buckets_str input, char *out, size_t cap) {
  const char *p = input.p, *end = input.p + input.n;
  /* skip the declaration, comments and whitespace up to the root's start tag */
  while (p < end) {
    while (p < end && *p != '<') p++;
    if (p + 1 >= end) return false;
    if (p[1] == '?' || p[1] == '!') {
      p++;
      continue;
    }
    break;
  }
  const char *gt = memchr(p, '>', (size_t)(end - p));
  if (!gt) return false;
  for (const char *a = p; a + 6 < gt; a++) {
    if (memcmp(a, "xmlns=", 6) != 0 || !(a[-1] == ' ' || a[-1] == '\t' || a[-1] == '\n' || a[-1] == '\r')) continue;
    char q = a[6];
    if (q != '"' && q != '\'') return false;
    const char *v = a + 7, *ve = memchr(v, q, (size_t)(gt - v));
    if (!ve) return false;
    snprintf(out, cap, "%.*s", (int)(ve - v), v);
    return true;
  }
  return false;
}
