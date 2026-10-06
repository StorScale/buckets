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
 * no quorum, foreign deployment, or layout mismatch. deployment_id, when
 * given (pools after the first), is used for a fresh format and required of
 * an existing one. */
typedef struct {
  bool may_format_fresh; /* in: this node formats a fresh pool (it owns its first endpoint) */
  bool fatal;            /* out: the failure will not go away by waiting */
} buckets_format_opts;
/* opts may be NULL (single node: may format, errors are final). */
bool buckets_format_negotiate(buckets_drive **drives, size_t ndrives, size_t set_size, const char *deployment_id,
                              buckets_format_opts *opts, buckets_format_result *out, char *err, size_t errlen);
void buckets_format_result_free(buckets_format_result *r);

/* A local drive found empty while the server runs (a replaced disk): formats it into its slot as the
 * deployment's other drives describe it (a set member's format.json, with "this" set to the slot's drive
 * ID), so it can be healed. Only when its directory exists and holds nothing but .minio.sys scaffolding
 * (and lost+found); a drive with data but no format.json, or one from another deployment, is left alone.
 * set: the drives of d's erasure set (d among them). False and why when it was not formatted. */
bool buckets_format_replace(buckets_drive *d, buckets_drive *const *set, size_t n, char *err, size_t errlen);

#endif
