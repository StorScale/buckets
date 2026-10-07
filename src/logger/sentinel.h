/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_LOGGER_SENTINEL_H
#define BUCKETS_LOGGER_SENTINEL_H

/* Microsoft Sentinel as an audit target (docs/audit-log.md): entries go in batches, each a JSON array, to Azure
 * Monitor's Logs Ingestion API (a data collection rule and its stream), signed in as an Entra ID app with the
 * client credentials grant; the token is kept until shortly before it expires. Queued, retried and stored on
 * disk as the webhook target does (logger/httptarget.h). Set by the environment, not config.json, which stays
 * MinIO's:
 *   BUCKETS_AUDIT_SENTINEL_ENDPOINT       the data collection endpoint, or the DCR's own ingestion endpoint
 *   BUCKETS_AUDIT_SENTINEL_DCR_ID         the rule's immutable ID (dcr-...)
 *   BUCKETS_AUDIT_SENTINEL_STREAM         e.g. Custom-BucketsAudit_CL
 *   BUCKETS_AUDIT_SENTINEL_TENANT_ID, _CLIENT_ID, _CLIENT_SECRET (or _CLIENT_SECRET_FILE)
 *   BUCKETS_AUDIT_SENTINEL_BATCH_SIZE (100), _QUEUE_DIR, _QUEUE_SIZE (100000)
 *   BUCKETS_AUDIT_SENTINEL_LOGIN_URL      Entra ID's (https://login.microsoftonline.com), for tests and sovereign
 *                                         clouds
 *   BUCKETS_AUDIT_SENTINEL_SCOPE          https://monitor.azure.com/.default */

#include <stddef.h>

#include "logger/httptarget.h"

/* The ingestion URL: <endpoint>/dataCollectionRules/<dcr>/streams/<stream>?api-version=2023-01-01. */
void buckets_sentinel_url(const char *endpoint, const char *dcr, const char *stream, char *out, size_t cap);

/* The target the environment sets up; NULL with err "" when it sets none, or NULL and why when it is wrong. */
buckets_http_target *buckets_sentinel_target_from_env(const char *deployment_id, const char *ca_file,
                                                      char *err, size_t errlen);

#endif
