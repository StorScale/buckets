# Usage and chargeback reports

**Reports → Usage** in the console answers who stores how much, who moves how
much, and what that costs each team. The other reports in the section are
retention and encryption coverage ([compliance.md](compliance.md)).

## The page

Pick a period: **this month so far**, **last month**, or any range of days (up
to 400). Days are UTC days, as the servers record them.

**By team** has one row per team on the **Teams** page, plus **No team** for
buckets in none. **By bucket** has one row per bucket, with its team. Click a
bucket for a chart of its size day by day.

| Column | What it is |
| --- | --- |
| GB-months | Storage averaged over the period: 30 GB held for a whole month is 30 GB-months, whatever the month's length. |
| Peak | The most the bucket held on any day of the period. For a team, the sum of its buckets' peaks. |
| Data in, Data out | Bytes received and sent by S3 requests to the bucket. |
| Reads, Writes, Deletes | S3 requests: reads are GET, HEAD and LIST; writes are PUT, POST, copies and multipart uploads; deletes are DELETE requests. Failed requests count too. |
| Cost | With rates set: what the usage costs at those rates. |

**Export CSV** saves the view shown. It ends with the period, any days without
records, and the rates used, so the file says what its figures rest on.

### Teams

A bucket is charged to one team, so nothing is counted twice: the team that
names it, else the team whose prefix matches it most closely. If two teams name
the same bucket, it goes to the first by name and the row says so. Teams are
read when the report is viewed, so a past month is grouped by today's teams.

### Rates

**Rates** sets one currency and any of these prices:

- per GB-month stored;
- per GB out, and per GB in;
- per 10,000 reads, writes and deletes.

Costs are worked out from the usage when the report is viewed, so changing a
rate re-prices past months too. **Remove rates** goes back to usage only.
Setting rates needs `admin:ConfigUpdate`.

## Where the figures come from

Usage history starts when a server runs 1.12.0. Earlier days are listed as
having no records. It's kept in daily records under
`.minio.sys/buckets/usage/`, apart from MinIO's own data usage, so moving back
to MinIO is unaffected.

- **Storage:** at the end of each data scanner cycle, the leader records every
  bucket's size. A day's figure is the average of that day's cycles. A day
  without a finished cycle carries the last known size forward.
- **Traffic and requests:** each server adds what it counted to a record of its
  own every 5 minutes. A server that stops loses at most the last 5 minutes of
  its counts.
- **Kept for 13 months** (396 days), so a month can be compared with the same
  month last year. The leader removes older days.

| Setting | Default | |
| --- | --- | --- |
| `BUCKETS_USAGE_FLUSH_INTERVAL` | `300` | Seconds between each server's traffic records. |
| `BUCKETS_USAGE_HISTORY_DAYS` | `396` | Days of history kept. |

## For other tools

These are Buckets extensions to the admin API; they return JSON (see
`src/admin/usage.c` and `src/usage/history.h`):

- `GET /minio/admin/v3/buckets/usage?from=YYYY-MM-DD&to=YYYY-MM-DD` needs
  `admin:DataUsageInfo`. Without `from` and `to`, it reports this month so
  far. The reply has `buckets` and `teams`, each with `storage` (`gbMonths`,
  `peakBytes`), `dataIn`, `dataOut` and `requests` (`read`, `write`,
  `delete`). It also has each bucket's `daily` figures, the `rates`, and
  `missingDays`.
- `PUT /minio/admin/v3/buckets/usage-rates` sets the rates, as JSON:
  `{"currency": "EUR", "storageGbMonth": 0.02, "outGb": 0.05}`. The other
  fields are `inGb`, `per10kRead`, `per10kWrite` and `per10kDelete`.
  `DELETE` removes the rates. Both need `admin:ConfigUpdate`.

Live rates per bucket are in Prometheus already, in the per-bucket metrics.
