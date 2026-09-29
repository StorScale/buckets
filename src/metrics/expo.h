/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_METRICS_EXPO_H
#define BUCKETS_METRICS_EXPO_H

#include <stdbool.h>
#include <stddef.h>

#include "core/buf.h"

/* The Prometheus text exposition as MinIO's client_golang writes it:
 * families sorted by name with their HELP and TYPE, samples sorted by
 * label values, labels by name, values in Go's shortest float format. Only
 * metrics in MinIO's catalog (catalog.inc) can be added: the names, types
 * and help are MinIO's. */

typedef enum { BUCKETS_MT_GAUGE, BUCKETS_MT_COUNTER, BUCKETS_MT_HISTOGRAM, BUCKETS_MT_SUMMARY } buckets_metric_type;

typedef struct {
  const char *name;
  buckets_metric_type type;
  const char *help;
  const char *path; /* v3: the collector path serving it */
} buckets_metric_def;

/* The catalogs: v2 (cluster, node and bucket endpoints), the v2 resource
 * endpoint (node names with their own help) and v3. */
typedef enum { BUCKETS_CATALOG_V2, BUCKETS_CATALOG_V2_RESOURCE, BUCKETS_CATALOG_V3 } buckets_metric_catalog_kind;

/* The catalog entry for name, or NULL. */
const buckets_metric_def *buckets_metric_lookup(buckets_metric_catalog_kind k, const char *name);
/* A whole catalog (for the catalog check). */
const buckets_metric_def *buckets_metric_catalog(buckets_metric_catalog_kind k, size_t *n);

typedef struct buckets_expo buckets_expo;

/* Names from catalog k; v2 writes histograms as gauges, as MinIO's v2
 * collector does. */
buckets_expo *buckets_expo_new(buckets_metric_catalog_kind k);
void buckets_expo_free(buckets_expo *e);

/* A sample of the family name. labels: n name/value pairs (names need not
 * be sorted). A name outside the catalog is dropped (and counted). */
void buckets_expo_add(buckets_expo *e, const char *name, double v, const char *const *labels, size_t n);
/* A sample of family `name` written under name+suffix (a summary's _sum
 * and _count). */
void buckets_expo_add_suffixed(buckets_expo *e, const char *name, const char *suffix, double v,
                               const char *const *labels, size_t n);
/* Convenience: labels as NULL-terminated name, value, ... arguments. */
void buckets_expo_addl(buckets_expo *e, const char *name, double v, ...);
/* Samples dropped because their family is not in the catalog. */
size_t buckets_expo_dropped(const buckets_expo *e);

/* Names of the families added so far, sorted (caller frees the array only). */
size_t buckets_expo_names(const buckets_expo *e, const char ***out);

void buckets_expo_write(buckets_expo *e, buckets_buf *out);

/* Go's strconv.FormatFloat(v, 'g', -1, 64) as expfmt writes values. */
void buckets_go_float(double v, char out[40]);

#endif
