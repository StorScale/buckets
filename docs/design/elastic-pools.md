# Design: elastic pools

Status: under consideration, for 2.0. Nothing here is agreed or scheduled. Roadmap: "Under consideration for 2.0".

## The problem

A Buckets pool, like a MinIO pool, has a fixed shape:
- its drives are divided into **erasure sets** when it is created, and each drive's `format.json` records the set it
  belongs to;
- an object's set is **computed, never looked up**: `sipHashMod(object, number of sets, deployment ID)`
  (`buckets_set_index`, `src/erasure/layout.h`).

So nothing about a pool's drives can change:
- **Adding a set** changes the number the hash divides by, and almost every object would be in the wrong set.
- **Adding a drive to a set** changes the set's stripe width, and every object in it would need re-encoding.
- **Removing a drive** is only possible as a failure: healing rebuilds it onto a replacement of the same size.

The only way to grow is a **whole new pool**, typically as many drives as the first. Retiring hardware means adding
a pool and decommissioning the old one. For a cluster of four servers this is a step of 100% at a time. Bigger
drives help only once every drive in a set is bigger.

What people ask for instead:
- **add one drive, or one server,** and have the space;
- **remove a drive** that is old or slow without a failure and a rebuild;
- **mix drive sizes,** with each drive filled in proportion to its size.

## What it does

An **elastic pool** is a new kind of pool beside the MinIO kind. It puts one level of indirection between an object
and its drives:

```
object name ──hash──▶ placement group (a fixed count for the pool's life, e.g. 1024)
placement group ──layout map──▶ the drives holding its stripes (e.g. 6+3: 9 drives)
```

- **The hash never changes:** an object belongs to the same placement group for ever, since the count of groups is
  fixed.
- **The layout map** says which drives hold each group's stripes. It is versioned: each change is a new **epoch**,
  agreed by the servers and kept on their drives.
- **Adding a drive** makes a new map in which some groups move one stripe onto it. Only those stripes are copied.
- **Removing a drive** is a **drain**: the drive is marked out, its groups are given other drives, and its stripes
  are copied off. Then it can go.
- **The stripe width belongs to the pool,** not to the number of drives: a pool of 6+3 needs 9 drives at least, and
  can then grow one drive at a time.
- **Weights:** each drive gets a share of stripes in proportion to its size.
- **Failure domains:** no group has more stripes on one server than its parity covers, so losing a server loses no
  data. Racks and zones can be declared as larger domains.

Below the map, nothing changes: `xl.meta`, stripes, bitrot checks, versions, encryption and compression are written
as today, on the drives the map names.

### A worked example

Four servers of four 8 TB drives, 16 drives in all, at 6+3 with 1024 placement groups:
- each group is on 9 of the 16 drives, no more than 3 on any server, so a server lost costs 3 stripes, which parity
  covers;
- 9216 stripes over 16 drives: 576 per drive;
- usable space: 16 × 8 TB × 6/9 ≈ 85 TB.

**A 16 TB drive is added to server 2.** By weight it should hold 16/144 of all stripes, about 1020.
- The new map moves about 1020 stripes onto it, one from each of about 1020 groups. Each other drive gives up about
  64. Nothing else moves.
- On a half-full cluster that copies about 7 TB: a few hours at a throttled 500 MB/s.
- Usable space grows by about 10.7 TB.
- Server 2 now holds a third of the weight, which is also the most any server may hold of a group (3 of 9). A larger
  drive there could not be used in full. **Uneven servers are where weighting meets its limit**, and the preview
  says so.

**An 8 TB drive on server 4 is drained.**
- Its stripes, about 510 by now, are given to other drives, keeping to 3 per server.
- A healthy drive's stripes are **copied**, read once. A failing drive's are **rebuilt** from the other stripes of
  each group, read six times. A planned drain is much cheaper than a failure.
- The drain is refused if the drives left cannot hold the data with headroom.

## The layout map

**Stored, not computed.** Two families exist:
- *computed placement* (Ceph's CRUSH, rendezvous hashing): the map is only the drives and their weights, and every
  node computes the same assignment. Small, but some imbalance is built in, and correcting it needs overrides.
- *a stored table* (Garage): each change computes the whole assignment once, as an optimisation with movement
  minimised, and stores it. 1024 groups × 9 drives is about 10,000 entries.

A stored table can be shown exactly before it is committed ("these 1020 groups gain a stripe on the new drive"),
inspected afterwards, and tested by comparing tables.

**Agreed by the servers.** The map must be the same everywhere, and today Buckets has distributed locks (dsync) but
no replicated log. Layout changes are rare and made by one writer (an administrator, or the operator):
- the server leading the pool proposes epoch N+1, built on epoch N;
- a majority of the pool's servers store it on their drives and acknowledge;
- then it is committed, and the others take it at their next exchange.

This is one round of agreement per change, not a general log. A full Raft log is the alternative if more state comes
to need it.

**Kept on the drives.** Every drive of the pool holds the current map and the one before it, in a file of its own
beside `format.json`. A server starting reads the newest epoch a majority agrees on.

## Moving data

A new epoch starts a **move**. Each group whose drives changed is moved on its own:

1. **Copy:** each stripe that has a new drive is written there, copied from its old drive, or rebuilt from the
   group's other stripes when the old drive is failing or gone.
2. **Reads** of a group being moved use epoch N's drives. Once the group is copied, it is marked settled in epoch
   N+1, and reads use the new drives.
3. **Writes** to a group being moved go to **both** layouts until the group settles. An object written during a move
   must never exist only on drives that are about to stop holding it.
4. **Old stripes** are deleted once the group has settled and no read can still be using them.
5. **Progress** is kept per group, on the drives, so a restart carries on where it stopped.
6. **A second change during a move** (a drive failing during a drain): epoch N+2 is built on N+1, and the groups
   still moving to N+1 move straight to N+2.
7. **Throttled,** as healing and rebalance are, so clients keep their speed.

Moving a whole object between layouts is already done by decommission and rebalance (`src/s3/datamove.c`). A move
reads a version's full record from one place and writes it to another, keeping version IDs, ETags, encryption and
metadata. Moving between epochs is the same work for one group's objects, per stripe.

## What it changes elsewhere

- **Healing:** a missing stripe is rebuilt onto the drive the map names, and a drive replaced takes its
  predecessor's place in the map (a new epoch with the same assignment).
- **The scanner and usage:** they walk groups, not sets.
- **Listing:** each drive keeps its groups' objects under one tree, and a listing merges per drive, as today's merge
  across sets and pools does. Not per group, of which there are a thousand.
- **Capacity:** a pool's free space is what the map can still place, which is less than the sum of the drives' free
  space when servers are uneven.
- **Admin API, console and operator:** add, drain and preview operations; the move's progress; alerts for a move
  that stalls, and for a pool that cannot place its groups as its failure domains require.

## Setting it up

In the console or the cluster's spec:
1. Add drives, or a server (`servers: 5` with the same `drivesPerServer`). The operator makes the new volumes.
2. Buckets shows a preview: "1020 groups gain a stripe on the new drive; 7.1 TB will move, about 4 hours at the
   current limit; usable space +10.7 TB."
3. Confirm. The new epoch is committed, the move runs, and its progress shows per group.
4. To remove a drive: "Drain drive X: 510 stripes to copy; the pool will be 78% full afterwards."

Adding a server and adding a drive become the same operation.

## Compatibility

**An elastic pool is not MinIO's format.** MinIO cannot read it, and an elastic pool cannot be rolled back to MinIO.
That is why it is 2.0.

The promise of 1.x is kept for everyone who doesn't choose to move:
- **existing pools stay MinIO pools,** unchanged, and can still be rolled back to MinIO;
- a cluster moves by **adding an elastic pool** and **decommissioning** its MinIO pools into it, with the decommission
  that exists today;
- the console says plainly, before the first elastic pool is created, that the cluster can no longer return to
  MinIO once data is in it.

A cluster with both kinds runs both: MinIO pools as today, elastic pools by their map.

## Code

- **`src/erasure/layout.h` and a new `src/erasure/placement.{c,h}`:** placement groups, the map, its epochs, and the
  optimisation that builds a new map with least movement within the failure domains.
- **`src/object/`:** an elastic pool beside `buckets_epool`, finding a group's drives through the map, with the
  read and write rules of a move.
- **A new `src/dist/` agreement round:** proposing and committing an epoch.
- **`src/s3/datamove.c`:** moves per group, beside decommission and rebalance.
- **`src/heal/`, `src/scanner/`:** groups instead of sets.
- **Admin API:** layout get, preview, add, drain, and the move's status.
- **Operator:** volumes added and removed one by one; a pool's kind in the spec.
- **Console:** the preview, the move's progress, drains.

## Tests

- **Unit:** the map's optimisation:
  - least movement on a drive added or drained;
  - failure domains always kept;
  - weights followed within a bound;
  - epochs built on epochs.
- **Integration:**
  - drives added and drained one at a time under load, every object read back intact;
  - a server killed at each step of a move, and the move resumed;
  - a drive failing during a drain;
  - two changes in a row;
  - a MinIO pool decommissioned into an elastic pool, keeping versions, ETags and encryption.
- **Cluster:** the operator adding a server and draining one on the shared cluster.
- **Long-running:** a move of a few terabytes, with clients' latency watched throughout.

## Open questions, with a recommendation each

1. **A stored table or computed placement?** **Recommended: a stored table.** It can be previewed exactly, inspected
   and tested, and at about 10,000 entries it is small.
2. **One round of agreement per change, or a Raft log?** Changes are rare and have one writer. **Recommended: one
   round per change,** with Raft only if more state comes to need it.
3. **Can a pool's stripe width change?** A pool that grows from 16 drives to 200 would do better at 12+4 than 6+3.
   **Recommended: fixed at first,** with a sensible default for the starting size; widening (re-encoding groups) as a
   later step.
4. **How many placement groups?** Too few and adding a drive can't balance; too many and per-group state and moves
   cost more. **Recommended: fixed at creation,** from the largest size expected, about 50 to 100 groups per drive
   then: 1024 to 4096. Splitting groups later is possible but complex.
5. **Writes during a move: to both layouts, or to the new one only with reads falling back?** **Recommended: both,**
   until the group settles. It costs extra writes for the minutes a group moves, and no read can miss an object.
6. **The smallest elastic pool?** **Recommended: the stripe width plus one server's drives,** so that a server can be
   drained without the pool falling below its width.
7. **A smaller first step?** Groups moved between whole sets (drives added and drained a set at a time) need the map
   and the moves but not per-drive placement or weights. **Recommended: only if the full design proves too large.**
   It gives less, and most of the work is the same.
