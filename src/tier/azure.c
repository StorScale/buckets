/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* The Azure Blob Storage warm backend (MinIO's warm-backend-azure.go). */
#include <stdio.h>

#include "tier/internal.h"

buckets_warm *buckets_warm_azure_new(const buckets_tier_config *t, buckets_tls_client *tls, char *err, size_t errlen) {
  (void)t;
  (void)tls;
  snprintf(err, errlen, "Azure tiers are not supported yet");
  return NULL;
}
