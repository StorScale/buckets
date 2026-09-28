/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_XML_H
#define BUCKETS_S3_XML_H

#include "core/buf.h"
#include "core/str.h"

#define BUCKETS_S3_XMLNS "http://s3.amazonaws.com/doc/2006-03-01/"

/* ---- writer: S3 response documents ---- */
void buckets_xml_header(buckets_buf *out);
void buckets_xml_open(buckets_buf *out, const char *tag);
void buckets_xml_open_ns(buckets_buf *out, const char *tag, const char *xmlns);
void buckets_xml_close(buckets_buf *out, const char *tag);
void buckets_xml_text(buckets_buf *out, const char *s, size_t n); /* escaped */
void buckets_xml_elem(buckets_buf *out, const char *tag, const char *text);
void buckets_xml_elem_str(buckets_buf *out, const char *tag, buckets_str text);

/* ---- reader: small request documents ----
 * A strict, non-validating reader for the small XML bodies S3 clients send
 * (CreateBucketConfiguration, Delete, Tagging, ...). It rejects DOCTYPE and
 * entity declarations outright, so there is no XXE or entity-expansion surface.
 * Large or schema-heavy documents (lifecycle, replication) will move to expat. */
typedef struct {
  buckets_str name; /* local name, namespace prefix stripped */
  buckets_str text; /* raw (still-escaped) character data for leaf elements */
  int depth;
  size_t first_child; /* index of first child, or 0 if leaf */
  size_t next_sibling; /* index of next sibling, or 0 if last */
} buckets_xml_node;

typedef struct {
  buckets_xml_node *nodes;
  size_t count;
  size_t cap;
} buckets_xml_doc;

/* Returns false on malformed input. node[0] is the root element. */
bool buckets_xml_parse(buckets_str input, buckets_xml_doc *doc);
void buckets_xml_doc_free(buckets_xml_doc *doc);
/* Finds a direct child by local name; returns its index or 0. */
size_t buckets_xml_child(const buckets_xml_doc *doc, size_t parent, const char *name);
/* The root element's default namespace (its xmlns="..." attribute), copied
 * into out; false when it has none. Go's encoding/xml keeps it in an
 * `xml:"xmlns,attr"` field and marshals it back. */
bool buckets_xml_root_xmlns(buckets_str input, char *out, size_t cap);
/* Unescapes a node's text into out (entities: amp lt gt quot apos, &#N; &#xN;). */
bool buckets_xml_unescape(buckets_str text, buckets_buf *out);

#endif
