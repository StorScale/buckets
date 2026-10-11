/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef BUCKETS_DIST_RPCSTATS_H
#define BUCKETS_DIST_RPCSTATS_H

#include <stddef.h>
#include <stdint.h>

/* Internode calls by operation ("storage/read_at", "lock/lock", ...): those
 * this node made and the time it waited for each answer, and those it served
 * and the time it spent handling them. A call's wait less its peer's handling
 * is what the network and the queues cost it. */

typedef enum { BUCKETS_RPC_CALLED, BUCKETS_RPC_SERVED } buckets_rpc_side;

/* op: "<kind>/<name>"; only the first 31 bytes are kept. */
void buckets_rpcstats_add(buckets_rpc_side side, const char *kind, const char *name, int64_t ns);

typedef struct {
  const char *op;
  uint64_t calls, ns;
} buckets_rpcstat;

/* Calls fn for each operation seen on a side. */
void buckets_rpcstats_each(buckets_rpc_side side, void (*fn)(void *ud, const buckets_rpcstat *st), void *ud);

int64_t buckets_rpcstats_now_ns(void);

#endif
