/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_IDENTITY_H
#define BUCKETS_OPERATOR_IDENTITY_H

#include <yyjson.h>

#include "manifests.h"
#include "reconcile.h"

/* One pass over a cluster's identity-provider settings (Secret
 * <name>-identity, which the console's Identity page writes; see
 * iam/idpsettings.h). Empty: not managed, and the servers' own settings are
 * left alone. Otherwise, once they change: refused while spec.env,
 * spec.console.env or config.env set identity themselves (they would win);
 * else applied to the servers through the admin API (bucketsd checks the
 * provider or the directory first), then given to the console. Sets
 * s->identity.ldap_hash (LDAP is read at startup: a change restarts the
 * servers) and fills idn (an object in d) with status.identity. */
void op_identity_reconcile(op_ctx *o, yyjson_val *bc, bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *idn);

/* The identity settings spec.env, spec.console.env and config.env (text)
 * already set, as "spec.env MINIO_IDENTITY_OPENID_CONFIG_URL, ...", or "" when
 * none. */
void op_identity_conflicts(const bc_spec *s, const char *config_env, char *out, size_t cap);

#endif
