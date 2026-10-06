/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_MONITORING_H
#define BUCKETS_OPERATOR_MONITORING_H

#include <yyjson.h>

#include "manifests.h"
#include "reconcile.h"

/* One pass over a cluster's monitoring (docs/design/monitoring.md). When the
 * Prometheus Operator's API is installed and spec.monitoring.enabled is not
 * false: a metrics user allowed only admin:Prometheus (policy
 * buckets-prometheus), its bearer token in Secret <name>-prometheus, and the
 * ServiceMonitor <name>. Off: the ServiceMonitor goes. Fills mon (an object
 * in d) with status.monitoring: phase Ready, Disabled, NotInstalled or
 * Error, and a message. Call it once the servers are applied. */
void op_monitoring_reconcile(op_ctx *o, yyjson_val *bc, const bc_spec *s, yyjson_mut_doc *d, yyjson_mut_val *mon);

/* The bearer token Prometheus presents for user ak (secret sk): a JWT
 * {"exp", "sub": ak, "iss": "prometheus"}, HS512 with sk, valid for 100
 * years, as `mc admin prometheus generate` makes. */
void op_prometheus_token(const char *ak, const char *sk, long long now, buckets_buf *out);

#endif
