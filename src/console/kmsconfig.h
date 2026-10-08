/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_CONSOLE_KMSCONFIG_H
#define BUCKETS_CONSOLE_KMSCONFIG_H

#include "net/http.h"

/* The console's KMS settings, where buckets-operator runs the cluster: KES's
 * key store settings live in Secret <cluster>-kms, and the operator tries new
 * ones (Secret <cluster>-kms-candidate) when the cluster's buckets.io/kms-test
 * annotation names a new trial, reporting on it in status.kms.test.
 *
 *   GET  /api/v1/kms-config        -> {"managed", "cluster", "namespace", "kesServiceAccount",
 *                                      "enabled", "keyName", "settings" (secrets left out), "status"}
 *   POST /api/v1/kms-config/test   {"settings", "keyName", "createKey", "requiredKeys"} -> {"testId"}
 *   POST /api/v1/kms-config/apply  {"testId"}: the tested settings go live
 *
 * Secret fields left empty keep their saved values. Outside Kubernetes (no
 * BUCKETS_CONSOLE_CLUSTER), GET says {"managed": false}. */

typedef struct buckets_console_kms buckets_console_kms;

/* From BUCKETS_CONSOLE_CLUSTER and BUCKETS_CONSOLE_NAMESPACE, and the pod's
 * service account; NULL when not set (the console then manages no KMS). */
buckets_console_kms *buckets_console_kms_new(void);
void buckets_console_kms_free(buckets_console_kms *k);

/* sub: the path after /api/v1/kms-config ("", "/test", "/apply"). The caller
 * has checked that the session may change the server's configuration. */
void buckets_console_kms_handle(buckets_console_kms *k, const buckets_http_request *req, const char *sub,
                                buckets_http_response *resp);

/* GET /api/v1/declared-buckets: the cluster's Bucket resources (buckets-operator keeps what they declare, putting
 * back changes made elsewhere) -> {"managed", "namespace", "buckets": [{"bucket", "resource", "lifecycle",
 * "replication", "spec"}]}. Outside Kubernetes, {"managed": false, "buckets": []}. */
void buckets_console_declared_buckets(buckets_console_kms *k, buckets_http_response *resp);

#endif
