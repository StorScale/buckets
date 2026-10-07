/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_USAGE_STORE_H
#define BUCKETS_USAGE_STORE_H

/* The usage history's daily records in .minio.sys (usage/history.h says what they hold). */

#include "object/object.h"
#include "scanner/usage.h"
#include "usage/history.h"

/* Adds the deltas a server counted to today's record of its own. server: its name in the cluster. */
buckets_obj_err buckets_usage_store_traffic(buckets_objlayer *L, const char *server,
                                            const buckets_usage_traffic_add *add, size_t n);
/* Adds a scanner cycle's sizes to today's storage record, then removes the days no longer kept. The leader's. */
void buckets_usage_store_sample(buckets_objlayer *L, const buckets_data_usage *u);
/* Removes the days before buckets_usage_history_days() up to today. */
void buckets_usage_store_prune(buckets_objlayer *L);
/* A source of records for buckets_usage_report. */
buckets_usage_source buckets_usage_store_source(buckets_objlayer *L);

#endif
