/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_YAML_H
#define BUCKETS_CORE_YAML_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buf.h"

/* YAML documents as gopkg.in/yaml.v3 sees them (libyaml underneath): a
 * node tree with yaml.v3's tag resolution, its error messages, and a
 * writer that emits what yaml.Marshal does (4-space indents, sequences
 * indented under their key, yaml.v3's choice of quoting). */

typedef enum { BUCKETS_YAML_SCALAR, BUCKETS_YAML_SEQ, BUCKETS_YAML_MAP } buckets_yaml_kind;

typedef struct buckets_yaml_node {
  buckets_yaml_kind kind;
  /* The resolved short tag: "!!str", "!!int", "!!float", "!!bool", "!!null",
   * "!!timestamp", "!!seq", "!!map" (or an explicit tag as written). */
  char *tag;
  char *value; /* scalars */
  int line, col; /* 1-based, as yaml.Node.Line/Column */
  bool quoted;   /* not a plain scalar */
  struct buckets_yaml_node **items; /* sequence items; mappings: key, value, key, value, ... */
  size_t n;                         /* items (2 per mapping pair) */
} buckets_yaml_node;

/* The first document of s; NULL with yaml.v3's message in err ("yaml:
 * line 1: did not find expected node content") on a syntax error. An empty
 * document gives a null scalar. */
buckets_yaml_node *buckets_yaml_parse(const char *s, size_t n, char *err, size_t errlen);
void buckets_yaml_free(buckets_yaml_node *node);

bool buckets_yaml_is_null(const buckets_yaml_node *n);
/* A mapping's value for key (the last one given), or NULL. */
const buckets_yaml_node *buckets_yaml_get(const buckets_yaml_node *map, const char *key);

/* yaml.v3's timestamp formats ("2006-1-2T15:4:5.999999999Z07:00", "2006-1-2
 * 15:4:5.999999999", "2006-1-2"), to UTC. */
bool buckets_yaml_parse_timestamp(const char *s, int64_t *sec, int32_t *nsec);

/* The decoder's accumulated type errors (yaml.TypeError). */
typedef struct {
  buckets_buf terrors; /* "\n  line N: cannot unmarshal ..." each */
  char *fatal;         /* an unmarshaler's own error, which stops decoding */
} buckets_yaml_dec;

void buckets_yaml_dec_free(buckets_yaml_dec *d);
/* "cannot unmarshal !!str `abc` into int" for n, into the Go type named. */
void buckets_yaml_terror(buckets_yaml_dec *d, const buckets_yaml_node *n, const char *gotype);
void buckets_yaml_fail(buckets_yaml_dec *d, const char *msg);
/* The error yaml.Unmarshal would return, or NULL when decoding succeeded. */
char *buckets_yaml_dec_error(const buckets_yaml_dec *d);

/* Decoders for yaml.v3's rules on Go kinds; null leaves the output alone. */
void buckets_yaml_dec_str(buckets_yaml_dec *d, const buckets_yaml_node *n, char **out);
void buckets_yaml_dec_int(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *out, const char *gotype);
void buckets_yaml_dec_bool(buckets_yaml_dec *d, const buckets_yaml_node *n, bool *out);
/* time.Duration: a string time.ParseDuration takes. */
void buckets_yaml_dec_duration(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *out);
/* time.Time; *set tells a zero time apart. */
void buckets_yaml_dec_time(buckets_yaml_dec *d, const buckets_yaml_node *n, int64_t *sec, int32_t *nsec, bool *set);

/* ---- writing ---------------------------------------------------------------------------- */

typedef struct {
  buckets_buf *out;
  int depth;        /* the column of the current mapping's keys */
  bool in_seq_item; /* the next key starts a "- " item */
  struct {
    int indent, seq_col; /* the column to restore; a sequence's "- " column */
    bool seq;
  } frames[32];
  int sp;
} buckets_yaml_writer;

/* "key: value" with yaml.v3's quoting of value. */
void buckets_yaml_w_str(buckets_yaml_writer *w, const char *key, const char *value);
/* A value written as is (numbers, booleans, null, durations, timestamps). */
void buckets_yaml_w_raw(buckets_yaml_writer *w, const char *key, const char *value);
void buckets_yaml_w_int(buckets_yaml_writer *w, const char *key, int64_t v);
void buckets_yaml_w_bool(buckets_yaml_writer *w, const char *key, bool v);
/* "key:" opening a nested mapping (end it with buckets_yaml_w_end). */
void buckets_yaml_w_map(buckets_yaml_writer *w, const char *key);
void buckets_yaml_w_end(buckets_yaml_writer *w);
/* "key:" opening a sequence of n items ("key: []" when n is 0); each item
 * starts with buckets_yaml_w_item (a mapping) or is a scalar written with
 * buckets_yaml_w_seq_str. End it with buckets_yaml_w_end unless n is 0. */
void buckets_yaml_w_seq(buckets_yaml_writer *w, const char *key, size_t n);
void buckets_yaml_w_item(buckets_yaml_writer *w);
void buckets_yaml_w_seq_str(buckets_yaml_writer *w, const char *value);
/* A scalar as yaml.v3 quotes it: plain, 'single' or "double". */
void buckets_yaml_scalar(buckets_buf *out, const char *s);

/* Go's time.Duration.String ("1h30m0s", "500ms", "0s"). */
void buckets_go_duration_string(int64_t ns, char *out, size_t cap);

#endif
