# Design: usage and chargeback reports

Status: agreed, being built. Roadmap: Phase 4, "Usage and chargeback reports
per bucket and per team, exportable as CSV". With the access review (1.4.0)
and the retention and encryption reports (1.11.0), it completes the reports
in Phase 4's gate: "an auditor can get usage, access and retention reports
from the console".

## The problem

Someone who runs Buckets for several teams wants to answer: who stores how
much, who moves how much, and what does that cost each team this month?
Today the console shows only the present: each bucket's size from the
scanner's last cycle, and live request rates in Prometheus. Nothing keeps
history. Per-bucket traffic and request counts live in each server's memory,
since it started, and are lost when it restarts. So a month's usage can't be
told, let alone charged.

## What the report shows

A **Usage** page with a period picker (this month so far, last month, or any
range of days), in two views. Each has **Export CSV**.

**By team.** Teams are the ones on the Teams page (1.3.0). Each row shows:
- storage, averaged over the period (GB-months) and at its peak;
- data in, data out, and requests (reads, writes, deletes);
- the cost, when rates are set.

Buckets in no team are summed as **No team**.

**By bucket.** The same columns per bucket, with its team. A bucket's daily
storage shows as a small chart when its row is opened.

**Costs** come from rates an admin sets on the page:
- a price per GB-month stored;
- a price per GB out, and optionally per GB in;
- a price per 10,000 requests, by kind (reads, writes, deletes);
- one currency.

With no rates set, the page shows usage only. Costs are worked out from the
usage when the page is viewed, so changing a rate re-prices past months too;
the CSV records the rates it used.

## Where the history comes from

Everything is kept in daily files under `.minio.sys/buckets/usage/`, apart
from MinIO's own data usage, so the MinIO round trip is unaffected.

- **Storage:** at the end of each scanner cycle, the leader adds that cycle's
  size per bucket to the day's `storage.json`, as a running average and a
  count of samples, plus the day's peak and latest size. (A running average,
  not a sum, so it can't overflow.) The
  period's GB-months are the daily averages added up, divided by the days in
  the month: `sum(daily average bytes) / days in month / 10^9`. A day with no
  completed cycle carries the last known size forward.
- **Traffic and requests:** every server already counts per bucket in memory.
  Every 5 minutes each server adds what it counted since the last time to the
  day's file of its own, `<day>/traffic-<server>.json`. Only the deltas are written,
  and each server writes only its own file, so there are no conflicts between
  servers. A restart loses at most the last 5 minutes on that server. Requests
  are grouped by S3 API: reads (GET, HEAD, LIST), writes (PUT, POST, copy,
  multipart) and deletes.
- **Kept for 13 months,** so this month can be compared with the same month
  last year. The leader removes older days. `BUCKETS_USAGE_HISTORY_DAYS`
  changes this.

The cost is small: one write per server every 5 minutes, and one per scanner
cycle on the leader. A year is a few hundred small files per server.

## Teams and buckets

A bucket belongs to one team, so nothing is charged twice:
- the team that names it;
- otherwise, the team whose prefix matches it most closely.

Teams can't overlap by prefix; the Teams page already refuses that. If two
teams name the same bucket, it goes to the first by name, and the page says
so. Teams are read from the policies when the page is viewed, so the report
always uses today's teams; the CSV records which team each bucket was given.

## API

These are Buckets extensions to the admin API, like `buckets/compliance`:

```
GET /minio/admin/v3/buckets/usage?from=2026-10-01&to=2026-10-31
  -> {"from", "to", "days", "rates": {...} | null,
      "buckets": [{"name", "team",
                   "storage": {"gbMonths", "peakBytes", "lastBytes"},
                   "dataIn", "dataOut", "requests": {"read", "write", "delete"},
                   "daily": [{"day", "bytes", "in", "out"}]}],
      "teams": [{"name", "buckets", same totals}],
      "missingDays": [days with no record, e.g. before 1.12.0]}
PUT /minio/admin/v3/buckets/usage-rates   {"currency", "storageGbMonth", "outGb", "inGb",
                                           "per10kRead", "per10kWrite", "per10kDelete"}
DELETE /minio/admin/v3/buckets/usage-rates
```

- **Reading** needs `admin:DataUsageInfo`, as the compliance report does.
- **Setting or removing rates** needs `admin:ConfigUpdate`.
- **Rates are stored** in `.minio.sys/buckets/usage-rates.json`.
- **Teams are resolved on the server,** with the Teams code
  (`buckets_teams_from_policies`), so other tools get the same grouping.

## Code

- **`src/usage/history.{c,h}`:** reading and writing the daily records, the
  per-server delta flush, the leader's storage sample and pruning, and the
  period's totals. Pure, apart from the file reads and writes, and unit
  tested.
- **`src/usage/store.{c,h}`:** the records' reads and writes in `.minio.sys`.
- **`src/s3/server.c`:** each server's flush thread, which takes the per-bucket
  counters (`src/metrics/stats.c`) as deltas since its last flush.
- **`src/admin`:** the two endpoints.
- **Console:** `Usage.tsx`, with the period picker, the team and bucket views,
  per-bucket charts, rates, and CSV.

## Tests

- **Unit:** GB-month arithmetic across months of 28, 30 and 31 days; carrying
  a size forward over a day with no cycle; summing deltas from several
  servers; assigning buckets to teams by name and prefix; and pruning.
- **Integration** (`tests/integration/usage-reports.sh`):
  - two servers with traffic to three buckets in two teams;
  - a few scanner cycles, with the clock moved over midnight
    (`BUCKETS_USAGE_TEST_DAY` sets "today");
  - a server restarted mid-day: its earlier deltas are kept;
  - then the endpoint's totals compared with what the test sent.
- **Browser:** the page, its views, rates and CSV.

## Decisions

1. **Traffic and requests too,** as above, not storage alone.
2. **The sidebar's Compliance section becomes Reports,** holding Retention,
   Encryption coverage and Usage. The old `/compliance/...` addresses lead to
   the new ones.
3. **History kept for 13 months.**
4. **No cost metrics for now.** Usage is in Prometheus already, as rates.
