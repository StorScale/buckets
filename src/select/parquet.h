/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SELECT_PARQUET_H
#define BUCKETS_SELECT_PARQUET_H

/* Parquet input for S3 Select: rows of a file's leaf columns by their
 * flattened names, values converted by their logical types as MinIO's
 * parquet reader converts them. */

#include "select/sel.h"
#include "select/select.h"

typedef struct sel_parquet sel_parquet;

sel_parquet *sel_parquet_open(const buckets_select_source *src, sel_err *e);
void sel_parquet_free(sel_parquet *p);
/* 1: a row (an object in a), 0: the end, -1: an error (e set). */
int sel_parquet_next(sel_parquet *p, sel_arena *a, sel_record *out, sel_err *e);

#endif
