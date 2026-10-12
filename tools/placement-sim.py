#!/usr/bin/env python3
"""Placement simulation for elastic pools (docs/design/elastic-pools.md#performance).

Builds stored layout maps as the design describes (placement groups, each on
`width` drives, no server holding more than `parity` stripes of a group,
stripes shared by weight) and changes them with least movement. For each
layout it reports what decides speed and space when every drive is equally
fast:

- touch: the share of objects that use a drive (a group on it / all groups).
  Every PUT syncs each of its drives twice, so the drive used most is the
  first to saturate when the storage's syncs are the limit;
- small-object throughput: objects per second until the busiest drive is
  saturated, relative to one MinIO set over the same 16 drives at 12+4, which
  uses every drive for every object;
- large-object throughput: the same with bytes (a drive writes size/data per
  object it is in);
- usable space: what can be stored before the first drive is full;
- moved: stripes copied by the change.

    tools/placement-sim.py            # the scenarios of the design doc
"""
import random
from collections import Counter

TB = 1


class Layout:
    def __init__(self, drives, groups, width, parity, weights=None, seed=1):
        # drives: list of (server, capacity); weights default to capacity
        self.drives = list(drives)
        self.G, self.W, self.m = groups, width, parity
        self.k = width - parity
        self.weights = list(weights) if weights else [c for _, c in self.drives]
        self.rng = random.Random(seed)
        self.map = []

    # ---- targets: stripes per drive by weight, within one stripe per group per drive and
    # parity stripes per group per server (water-filling)
    def targets(self, live):
        total = self.G * self.W
        t = {d: 0.0 for d in live}
        free = set(live)
        left = float(total)
        while free and left > 1e-9:
            wsum = sum(self.weights[d] for d in free)
            share = {d: left * self.weights[d] / wsum for d in free}
            capped = False
            for d in list(free):  # one stripe per group per drive
                if t[d] + share[d] > self.G:
                    left -= self.G - t[d]
                    t[d] = self.G
                    free.discard(d)
                    capped = True
            if capped:
                continue
            servers = Counter()
            for d in live:
                servers[self.drives[d][0]] += t[d] + share.get(d, 0)
            over = [s for s, v in servers.items() if v > self.G * self.m + 1e-6]
            if not over:
                for d in free:
                    t[d] += share[d]
                break
            for s in over:  # a server's drives share its cap by weight
                ds = [d for d in live if self.drives[d][0] == s]
                fixed = sum(t[d] for d in ds if d not in free)
                room = self.G * self.m - fixed
                fw = sum(self.weights[d] for d in ds if d in free)
                for d in ds:
                    if d in free:
                        t[d] += room * self.weights[d] / fw
                        free.discard(d)
            left = total - sum(t.values())
        return t

    def counts(self):
        c = Counter()
        for g in self.map:
            c.update(g)
        return c

    def ok(self, g, add, drop=None):
        if add in g:
            return False
        s = self.drives[add][0]
        on = sum(1 for d in g if d != drop and self.drives[d][0] == s)
        return on < self.m

    def build(self):
        live = range(len(self.drives))
        t = self.targets(live)
        have = Counter()
        self.map = []
        for _ in range(self.G):
            g = []
            order = sorted(live, key=lambda d: (have[d] - t[d], self.rng.random()))
            for d in order:
                if len(g) == self.W:
                    break
                if self.ok(g, d):
                    g.append(d)
            assert len(g) == self.W, "cannot place a group within the failure domains"
            have.update(g)
            self.map.append(g)
        return self

    def change(self, add=(), drain=()):
        """Adds drives ((server, capacity[, weight])) and drains drive indexes; returns stripes moved."""
        for srv, cap, *w in add:
            self.drives.append((srv, cap))
            self.weights.append(w[0] if w else cap)
        out = set(drain)
        live = [d for d in range(len(self.drives)) if d not in out]
        t = self.targets(live)
        moved = 0
        have = self.counts()

        def best_for(g, drop):
            cands = [d for d in live if self.ok(g, d, drop)]
            return max(cands, key=lambda d: (t[d] - have[d], self.rng.random())) if cands else None

        for g in self.map:  # drained drives' stripes go first
            for i, d in enumerate(g):
                if d in out:
                    n = best_for(g, d)
                    assert n is not None, "drain leaves a group without room"
                    g[i] = n
                    have[d] -= 1
                    have[n] += 1
                    moved += 1
        while True:  # then least movement: one stripe at a time from the fullest to the emptiest
            under = max(live, key=lambda d: t[d] - have[d])
            if t[under] - have[under] < 1:
                break
            done = False
            for g in sorted(self.map, key=lambda g: -max(have[d] - t[d] for d in g)):
                o = max(g, key=lambda d: have[d] - t[d])
                if have[o] - t[o] <= 0:
                    break
                if self.ok(g, under, o):
                    g[g.index(o)] = under
                    have[o] -= 1
                    have[under] += 1
                    moved += 1
                    done = True
                    break
            if not done:
                break
        return moved

    def report(self, name, ref_small, ref_large, moved=None, capacity=True):
        c = self.counts()
        live = [d for d in range(len(self.drives)) if c[d]]
        touch = {d: c[d] / self.G for d in live}
        hot = max(touch.values())
        small = 1 / hot  # objects per unit of time, a drive doing 1 unit of syncs
        large = 1 / (hot / self.k)  # bytes in objects per unit of time, a drive writing 1 unit
        stored = min(self.drives[d][1] * self.k / touch[d] for d in live) if capacity else None
        raw = sum(self.drives[d][1] for d in live)
        srv = Counter()
        for d in live:
            srv[self.drives[d][0]] += c[d]
        nsrv = len(srv)
        srv_hot = max(srv.values()) / (self.G * self.W) * nsrv
        return {
            "name": name,
            "drives": len(live),
            "touch": f"{min(touch.values()):.2f}–{hot:.2f}",
            "small": small / ref_small,
            "large": large / ref_large,
            "syncs": 2 * self.W,
            "usable": stored,
            "raw": raw,
            "server": srv_hot,
            "moved": moved,
        }


def fixed_set(drives_n, k):
    """One MinIO set over all drives: every object uses every drive."""
    return 1.0, 1 / (1 / k)


def main():
    G, W, M = 1024, 9, 3
    base = [(s, 8 * TB) for s in range(4) for _ in range(4)]
    ref_small, ref_large = fixed_set(16, 12)
    notes = []
    rows = [{
        "name": "MinIO set: 16 drives, 12+4",
        "drives": 16, "touch": "1.00–1.00", "small": 1.0, "large": 1.0, "syncs": 32,
        "usable": 16 * 8 * 12 / 16, "raw": 128, "server": 1.0, "moved": None,
    }, {
        "name": "MinIO pool: 2 sets of 8, 4+4", "drives": 16, "touch": "0.50–0.50", "small": 2.0,
        "large": (1 / (0.5 / 4)) / ref_large, "syncs": 16, "usable": 16 * 8 * 4 / 8, "raw": 128, "server": 1.0,
        "moved": None,
    }]

    a = Layout(base, G, W, M).build()
    rows.append(a.report("Elastic 6+3, 16 × 8 TB", ref_small, ref_large))

    b = Layout(base, G, W, M).build()
    mv = b.change(add=[(1, 16 * TB)])
    rows.append(b.report("+ 16 TB drive on server 2 (by size)", ref_small, ref_large, mv))
    want = b.targets(range(len(b.drives)))[16]
    notes.append(f"By size, the 16 TB drive should hold {want:.0f} stripes (one in {want / G:.0%} of groups, the most"
                 f" a drive can hold is {G}); least movement placed {b.counts()[16]} before the per-server limit"
                 " left no swap.")

    c = Layout(base, G, W, M).build()
    mv = c.change(add=[(1, 16 * TB, 8 * TB)])  # weight by speed: as fast as the others, the same share
    rows.append(c.report("+ 16 TB drive, weighted as an 8 TB", ref_small, ref_large, mv))

    d = Layout(base, G, W, M).build()
    mv = d.change(add=[(4, 8 * TB) for _ in range(4)])
    rows.append(d.report("+ a 5th server, 4 × 8 TB", ref_small, ref_large, mv))

    e = Layout(base, G, W, M).build()
    mv = e.change(drain=[15])
    rows.append(e.report("drain one 8 TB drive", ref_small, ref_large, mv))

    mixed = [(s, (8 if i < 2 else 16) * TB) for s in range(4) for i in range(4)]
    f = Layout(mixed, G, W, M).build()
    rows.append(f.report("Elastic 6+3, 4 × (2 × 8 + 2 × 16 TB)", ref_small, ref_large))

    g = Layout(mixed, G, W, M, weights=[8 * TB] * 16).build()
    rows.append(g.report("same, weighted equally", ref_small, ref_large))

    print("| Layout | Drives | Objects using a drive | Small-object throughput | Large-object throughput"
          " | Syncs per PUT | Usable / raw | Busiest server's share | Stripes moved |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['name']} | {r['drives']} | {r['touch']} | {r['small']:.2f}× | {r['large']:.2f}× | {r['syncs']} "
              f"| {r['usable']:.0f} / {r['raw']:.0f} TB | {r['server']:.2f}× | "
              f"{'' if r['moved'] is None else r['moved']} |")
    for n in notes:
        print("\n" + n)


if __name__ == "__main__":
    main()
