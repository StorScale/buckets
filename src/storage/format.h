/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_STORAGE_FORMAT_H
#define BUCKETS_STORAGE_FORMAT_H

#include "storage/drive.h"

/* Multi-drive format.json negotiation (MinIO cmd/format-erasure.go):
 *   {"version":"1","format":"xl"|"xl-single","id":<deployment>,
 *    "xl":{"version":"3","this":<drive uuid>,"sets":[[uuid...]...],
 *          "distributionAlgo":"SIPMOD+PARITY"}}
 * Drives are placed by their own "this" UUID within "sets", not by the order
 * they were given on the command line, exactly as MinIO does. */

typedef struct {
  size_t nsets, set_size;
  buckets_drive **slots; /* nsets*set_size; NULL = offline or unrecoverable */
  char deployment_id[BUCKETS_UUID_STR_LEN + 1];
  uint8_t deployment_id_bytes[16];
  size_t formatted_fresh; /* drives formatted (or healed) in this call */
} buckets_format_result;

/* drives[i] may be NULL (unreachable). Takes ownership of the drives: each is
 * either placed in a slot or closed. Returns false (err set) on a hard error:
 * no quorum, foreign deployment, or layout mismatch. */
bool buckets_format_negotiate(buckets_drive **drives, size_t ndrives, size_t set_size, buckets_format_result *out,
                              char *err, size_t errlen);
void buckets_format_result_free(buckets_format_result *r);

#endif
