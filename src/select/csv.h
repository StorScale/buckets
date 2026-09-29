/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_SELECT_CSV_H
#define BUCKETS_SELECT_CSV_H

#include "select/sel.h"

typedef enum { SEL_CSV_HEADER_NONE, SEL_CSV_HEADER_USE, SEL_CSV_HEADER_IGNORE } sel_csv_header;

typedef struct {
  sel_csv_header header;
  const char *record_delim; /* replaced by \n before parsing */
  uint32_t field_delim;
  uint32_t quote;        /* 0: no quoting */
  uint32_t quote_escape;
  uint32_t comment;
} sel_csv_ropts;

typedef struct sel_csv_reader sel_csv_reader;

/* Reads the header line and checks the first block is UTF-8 (the checks
 * MinIO makes before answering); NULL with e set otherwise. */
sel_csv_reader *sel_csv_reader_new(sel_read_fn rd, void *ud, const sel_csv_ropts *o, sel_err *e);
void sel_csv_reader_free(sel_csv_reader *r);
/* 1: a record (its fields in a), 0: the end, -1: an error (e set). */
int sel_csv_reader_next(sel_csv_reader *r, sel_arena *a, sel_record *out, sel_err *e);

#endif
