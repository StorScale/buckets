/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_KMS_H
#define BUCKETS_OPERATOR_KMS_H

#include <yyjson.h>

#include "manifests.h"
#include "reconcile.h"

/* The annotation the console sets on a BucketsCluster to try the settings in
 * Secret <name>-kms-candidate: its value names the trial, and
 * status.kms.test reports on the trial of that name. */
#define BC_KMS_TEST_ANNOTATION "buckets.io/kms-test"

/* Why a KES server failed, from its log: the "Error: ..." it exited with
 * (to the end: Vault's errors go on over several lines) or its last ERROR
 * line's message, as one line. "" when the log says nothing of the kind. */
void op_kes_log_reason(const char *text, char *out, size_t cap);

/* One pass over a cluster's KMS: the Secrets KES needs, the live KES server
 * when spec.kms.kes is set and settings are saved (its default key created),
 * and a trial of new settings when the console asks for one. Sets
 * s->kes.active once bucketsd may use KES, and fills kms (an object in d)
 * with status.kms. */
void op_kms_reconcile(op_ctx *o, yyjson_val *bc, bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *kms);

#endif
