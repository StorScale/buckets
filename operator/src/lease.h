/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_OPERATOR_LEASE_H
#define BUCKETS_OPERATOR_LEASE_H

#include "kube.h"

/* Leader election on a coordination.k8s.io/v1 Lease, like client-go's: the
 * holder renews it; anyone may take it over once it has gone unrenewed for
 * its duration. Updates carry the resourceVersion read, so two contenders
 * cannot both win. Returns whether `identity` holds the lease now. */
bool lease_acquire_or_renew(kube *k, const char *ns, const char *name, const char *identity, int duration_s);
/* Gives the lease up (holder cleared) so a successor need not wait it out. */
void lease_release(kube *k, const char *ns, const char *name, const char *identity);

#endif
