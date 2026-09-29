/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CORE_UUID_H
#define BUCKETS_CORE_UUID_H

#include "core/common.h"

#define BUCKETS_UUID_STR_LEN 36

/* Fills buf with cryptographically secure random bytes (aborts on failure). */
void buckets_random_bytes(void *buf, size_t n);
/* Random (v4) UUID in canonical lowercase form; out holds 37 bytes. */
void buckets_uuid_v4(char *out);

/* shortuuid.New(): a random UUID in 22 base-57 digits (out: 23 bytes). */
void buckets_shortuuid(char *out);

#endif
