/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_BUCKET_TAGS_H
#define BUCKETS_BUCKET_TAGS_H

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* Object and bucket tags, as minio-go's pkg/tags: at most 10 tags on an
 * object and 50 on a bucket, keys of 1-128 and values of 0-256 characters
 * from [a-zA-Z0-9+\-._:/@ =]. */

#define BUCKETS_TAGS_MAX_OBJECT 10
#define BUCKETS_TAGS_MAX_BUCKET 50

typedef struct {
  size_t n;
  char **keys;
  char **values;
} buckets_tags;

typedef enum {
  BUCKETS_TAGS_OK = 0,
  BUCKETS_TAGS_TOO_MANY_OBJECT, /* BadRequest: Tags cannot be more than 10 */
  BUCKETS_TAGS_TOO_MANY,        /* BadRequest: Tags cannot be more than 50 */
  BUCKETS_TAGS_INVALID_KEY,     /* InvalidTag */
  BUCKETS_TAGS_INVALID_VALUE,   /* InvalidTag */
  BUCKETS_TAGS_DUPLICATE_KEY,   /* InvalidTag */
  BUCKETS_TAGS_BAD_ESCAPE,      /* url.EscapeError in the query form; detail holds the escape */
  BUCKETS_TAGS_MALFORMED_XML,   /* the document does not parse; detail holds Go's message */
} buckets_tags_err;

typedef struct {
  buckets_tags_err code;
  char detail[128];
} buckets_tags_error;

void buckets_tags_free(buckets_tags *t);
/* The value of key, or NULL. */
const char *buckets_tags_get(const buckets_tags *t, const char *key);

/* "k1=v1&k2=v2" (X-Amz-Tagging and the stored form). */
bool buckets_tags_parse_query(const char *s, bool is_object, buckets_tags *out, buckets_tags_error *err);
/* A <Tagging><TagSet><Tag>... document. */
bool buckets_tags_parse_xml(const char *xml, size_t len, bool is_object, buckets_tags *out, buckets_tags_error *err);

/* tags.String(): keys sorted, both sides url.QueryEscape'd. */
void buckets_tags_string(const buckets_tags *t, buckets_buf *out);
/* <Tagging><TagSet>...</TagSet></Tagging>, keys sorted. */
void buckets_tags_xml(const buckets_tags *t, buckets_buf *out);

/* The S3 error code and message for err (Go's errTag and friends). */
const char *buckets_tags_err_code(const buckets_tags_error *err);
void buckets_tags_err_message(const buckets_tags_error *err, char *out, size_t cap);

#endif
