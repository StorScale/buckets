/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_S3_RANSOMGUARD_H
#define BUCKETS_S3_RANSOMGUARD_H

/* Ransomware alerts' cluster view (docs/design/ransomware-alerts.md): on the server leading pool 0, set 0, every
 * BUCKETS_RANSOMWARE_INTERVAL seconds (30), the servers' recent counts and protection changes are gathered,
 * bursts found against each bucket's usual rate (ransomware/ransomware.h), and incidents opened, kept up to date
 * and closed in .minio.sys/buckets/incidents.json: each one sent to the bucket's notification targets
 * (s3:Buckets:*), logged, counted, and with BUCKETS_RANSOMWARE_RESPONSE=disable, the credential behind it turned
 * off. */

#include <stdbool.h>

#include "net/http.h"
#include "s3/server.h"

typedef struct buckets_ransomguard buckets_ransomguard;
buckets_ransomguard *buckets_ransomguard_new(void);
void buckets_ransomguard_free(buckets_ransomguard *g);
/* One round; nothing unless this server leads pool 0, set 0. */
void buckets_ransomguard_run(buckets_s3_server *s, buckets_ransomguard *g);
/* The peer side (op "ransomware": window, since): this server's snapshot. False for other ops. */
bool buckets_ransomguard_peer(buckets_s3_server *s, const char *op, const buckets_query *q,
                              buckets_http_response *resp);
/* Turns a credential off as the response to an incident: "disabled", "revoked", or "none" (root, anonymous,
 * or it failed: why in err). */
const char *buckets_ransomguard_disable(buckets_s3_server *s, const char *access_key, const char *user,
                                        const char *type, char *err, size_t errlen);
/* Undoes it: false (and why) when it can't be (revoked sessions are gone). */
bool buckets_ransomguard_undo(buckets_s3_server *s, const char *action, const char *access_key,
                              const char *type, char *err, size_t errlen);

#endif
