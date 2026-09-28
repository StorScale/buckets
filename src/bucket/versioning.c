/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "bucket/versioning.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/common.h"
#include "s3/xml.h"

void buckets_versioning_free(buckets_versioning *v) {
  for (size_t i = 0; i < v->nexcluded; i++) free(v->excluded[i]);
  free(v->excluded);
  memset(v, 0, sizeof(*v));
}

static bool text_of(const buckets_xml_doc *d, size_t node, buckets_buf *out) {
  buckets_buf_reset(out);
  return buckets_xml_unescape(d->nodes[node].text, out);
}

bool buckets_versioning_parse(const char *xml, size_t len, buckets_versioning *out, char *err, size_t errlen) {
  memset(out, 0, sizeof(*out));
  buckets_xml_doc d = {0};
  if (!buckets_xml_parse((buckets_str){xml, len}, &d) || !buckets_str_eq_c(d.nodes[0].name, "VersioningConfiguration")) {
    if (d.nodes) buckets_xml_doc_free(&d);
    snprintf(err, errlen, "malformed XML");
    return false;
  }
  buckets_buf t = BUCKETS_BUF_INIT;
  bool ok = true;
  for (size_t c = d.nodes[0].first_child; c && ok; c = d.nodes[c].next_sibling) {
    const buckets_str name = d.nodes[c].name;
    if (buckets_str_eq_c(name, "Status")) {
      ok = text_of(&d, c, &t);
      if (ok && t.len) {
        if (strcmp(t.data, "Enabled") == 0) out->status = BUCKETS_VERSIONING_ENABLED;
        else if (strcmp(t.data, "Suspended") == 0) out->status = BUCKETS_VERSIONING_SUSPENDED;
        else {
          snprintf(err, errlen, "unsupported Versioning status %s", t.data);
          ok = false;
          out->status = -1;
        }
      }
    } else if (buckets_str_eq_c(name, "ExcludedPrefixes")) {
      size_t p = buckets_xml_child(&d, c, "Prefix");
      ok = !p || text_of(&d, p, &t);
      if (ok) {
        out->excluded = buckets_xrealloc(out->excluded, (out->nexcluded + 1) * sizeof(char *));
        out->excluded[out->nexcluded++] = buckets_xstrdup(p ? t.data : "");
      }
    } else if (buckets_str_eq_c(name, "ExcludeFolders")) {
      ok = text_of(&d, c, &t);
      out->exclude_folders = ok && strcmp(t.data, "true") == 0;
      if (ok && strcmp(t.data, "true") != 0 && strcmp(t.data, "false") != 0 && t.len) {
        snprintf(err, errlen, "strconv.ParseBool: parsing \"%s\": invalid syntax", t.data);
        ok = false;
      }
    }
  }
  if (!ok && !*err) snprintf(err, errlen, "malformed XML");
  if (ok) {
    /* Validate */
    if (out->status == BUCKETS_VERSIONING_ENABLED && out->nexcluded > 10) {
      snprintf(err, errlen, "too many excluded prefixes");
      ok = false;
    } else if (out->status == BUCKETS_VERSIONING_SUSPENDED && out->nexcluded) {
      snprintf(err, errlen, "excluded prefixes extension supported only when versioning is enabled");
      ok = false;
    } else if (out->status == BUCKETS_VERSIONING_UNSET) {
      snprintf(err, errlen, "unsupported Versioning status ");
      ok = false;
    }
  }
  buckets_buf_free(&t);
  buckets_xml_doc_free(&d);
  if (!ok) buckets_versioning_free(out);
  return ok;
}

void buckets_versioning_xml(const buckets_versioning *v, buckets_buf *out) {
  buckets_xml_open_ns(out, "VersioningConfiguration", BUCKETS_S3_XMLNS);
  if (v->status == BUCKETS_VERSIONING_ENABLED) buckets_xml_elem(out, "Status", "Enabled");
  else if (v->status == BUCKETS_VERSIONING_SUSPENDED) buckets_xml_elem(out, "Status", "Suspended");
  for (size_t i = 0; i < v->nexcluded; i++) {
    buckets_xml_open(out, "ExcludedPrefixes");
    buckets_xml_elem(out, "Prefix", v->excluded[i]);
    buckets_xml_close(out, "ExcludedPrefixes");
  }
  if (v->exclude_folders) buckets_xml_elem(out, "ExcludeFolders", "true");
  buckets_xml_close(out, "VersioningConfiguration");
}

/* wildcard.MatchSimple(prefix + "*", object): a plain prefix match unless the
 * pattern itself has wildcards. */
static bool match_simple(const char *pat, const char *s) {
  for (; *pat; pat++, s++) {
    if (*pat == '*') {
      if (!pat[1]) return true;
      for (; *s; s++)
        if (match_simple(pat + 1, s)) return true;
      return match_simple(pat + 1, s);
    }
    if (!*s || (*pat != '?' && *pat != *s)) return false;
  }
  return !*s;
}

static bool excluded(const buckets_versioning *v, const char *object) {
  size_t n = strlen(object);
  if (v->exclude_folders && n && object[n - 1] == '/') return true;
  for (size_t i = 0; i < v->nexcluded; i++) {
    buckets_buf p = BUCKETS_BUF_INIT;
    buckets_buf_appendf(&p, "%s*", v->excluded[i]);
    bool m = match_simple(p.data, object);
    buckets_buf_free(&p);
    if (m) return true;
  }
  return false;
}

bool buckets_versioning_enabled_for(const buckets_versioning *v, const char *object) {
  if (!v || v->status != BUCKETS_VERSIONING_ENABLED) return false;
  return !*object || !excluded(v, object);
}

bool buckets_versioning_suspended_for(const buckets_versioning *v, const char *object) {
  if (!v) return false;
  if (v->status == BUCKETS_VERSIONING_SUSPENDED) return true;
  return v->status == BUCKETS_VERSIONING_ENABLED && *object && excluded(v, object);
}
