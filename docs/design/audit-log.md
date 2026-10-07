# Design: audit log viewer, and forwarding to Sentinel and Splunk

Status: proposed, for review. Roadmap: Phase 4, "An audit log viewer, with
forwarding to Microsoft Sentinel or Splunk. With Entra ID sign-in, this gives a
Microsoft-centric organisation one identity and audit story."

## The problem

Every request can produce an audit entry: who (access key and the person
behind it), what (the API, bucket, object, status, bytes), when, and from
where. Today those entries only leave the server, and only when an audit
target is set up (a webhook or Kafka). Nothing keeps them, and nothing shows
them. So the obvious questions after a ransomware incident (1.14.0) or an
access review (1.4.0) can't be answered in Buckets:

- What else did this credential do, and from where?
- Who read or deleted this object, and when?
- What did this person change in the configuration last week?

Organisations that run Microsoft Sentinel also want the entries there, beside
their Entra ID sign-in logs. Sentinel takes custom logs through Azure
Monitor's Logs Ingestion API. The older HTTP Data Collector API loses support
on 14 September 2026, so new integrations shouldn't use it.

## What it does

**An audit log in the console** (Reports → Audit log):
- a time range (the last hour, day or week, or any range);
- filters: person, access key, bucket, object prefix, API (or kind: reads,
  writes, deletes, admin), status (succeeded, denied, failed) and source IP;
- a table, newest first, paged, with each entry's details on click (the full
  JSON);
- **Export CSV** of what the filters select.

Other pages link into it already filtered:
- an Activity incident links to "what this credential did";
- a bucket's settings link to "who used this bucket";
- a user, or the access review, links to "this person's actions".

**Forwarding:**
- **Microsoft Sentinel:** a new audit target, `audit_sentinel`. It sends
  entries in batches through the Logs Ingestion API, to a data collection rule
  (DCR) and its stream, signed in as an Entra ID app (client credentials). It
  queues entries on disk while Azure can't be reached, as the webhook target
  does. The docs give the custom table's schema, the DCR, and KQL queries
  (for example, deletes by a person, or access joined with `SigninLogs` by
  user).
- **Splunk:** the existing `audit_webhook` target already works with Splunk's
  HTTP Event Collector: the endpoint `.../services/collector/raw`, and
  `auth_token="Splunk <token>"`, sent as the `Authorization` header as it is.
  The docs show this, and a test proves it against a fake collector.

## Where the console's entries come from

Audit entries are built today only while an audit target exists. The viewer
needs them always, so each server **keeps a local copy of what it served:**

- **On the server's first local drive**, outside the erasure-coded data:
  `<drive>/.minio.sys/buckets/audit/<YYYY-MM-DD>/<HH>.jsonl`, one entry per
  line. Each server writes only its own, so there's no locking and no network
  traffic. A copy survives restarts, but not the loss of that drive. For a
  record that must survive, forward to a SIEM: that is the system of record.
- **Written in the background:** request threads hand entries to a writer
  thread, which appends and flushes every second. A full queue drops entries
  rather than slow requests, and counts what it dropped (a metric, and a note
  on the page).
- **Compressed** (gzip, with the libdeflate already linked) once an hour is
  over. Audit JSON compresses about tenfold.
- **Kept** for 30 days or 10 GiB per server, whichever comes first, oldest
  hours first (`BUCKETS_AUDIT_LOCAL_DAYS`, `BUCKETS_AUDIT_LOCAL_MAX`).
  `BUCKETS_AUDIT_LOCAL=off` turns the local copy off.

What it costs: an entry is about 1 KB before compression. A server answering
500 requests a second all day writes about 4 GB of compressed audit a day, so
the 10 GiB cap holds a little over two days at that rate. Quieter servers
keep the full 30 days. The page shows how far back each server's entries go.

**Querying:** the server that gets the request asks every server (a peer
call) for its entries in the time range that match the filters, newest first,
up to the page size. It merges them by time, and pages with a cursor. Each
server scans only the hours in the range, so a narrow time range is cheap and
a month-long one is slow. The page defaults to the last hour.

## API

Buckets extensions to the admin API:

```
GET /minio/admin/v3/buckets/audit?from=&to=&user=&accessKey=&bucket=&prefix=&api=&kind=&status=&ip=&limit=&cursor=
    admin:ServerInfo (as the trace and the logs are)
  -> {"entries": [{the audit entry, as MinIO writes it, plus "node"}], "cursor": "..." | null,
      "coverage": [{"node", "oldest", "dropped"}]}
```

`audit_sentinel` is configured like the other audit targets, through
`mc admin config set` or the console's Configuration page:
- `endpoint`: the data collection endpoint, or the DCR's own ingestion
  endpoint;
- `dcr_id` (immutable ID) and `stream` (for example `Custom-BucketsAudit_CL`);
- `tenant_id`, `client_id` and `client_secret`;
- `batch_size`, `queue_dir` and `queue_size`, as the webhook target has.

## Code

- **`src/audit/store.{c,h}`:** the writer thread, the hourly files,
  compression, retention and the query scan. Pure parts unit tested: the
  filter, the cursor, retention choices.
- **`src/s3`:** build the entry whenever the local copy is on, as well as for
  targets, and hand it to the store.
- **`src/logger/sentineltarget.c`:** the Sentinel target: the Entra token
  (cached until it expires), batches, gzip, retries and the queue.
- **`src/admin/audit.c`:** the endpoint and the peer op.
- **Console:** `AuditLog.tsx`, with the links from Activity, bucket settings,
  Users and the access review.

## Tests

- **Unit:** the filters and the cursor; files across an hour boundary and
  across compression; retention by days and by size; the Sentinel batch format
  and its token request.
- **Integration:**
  - two servers serve requests by two people; the endpoint, asked of either
    server, returns them merged, filtered and paged;
  - a restart keeps entries;
  - retention removes old hours;
  - a fake Logs Ingestion API (with a fake Entra token endpoint) receives
    batches with the right DCR, stream and token, and the queue holds entries
    while it is down;
  - a fake Splunk collector receives them through `audit_webhook`.
- **Browser:** the page, its filters, the details, CSV, and a link from an
  Activity incident.

## Open questions for review

1. **The local copy on by default?** It's what makes the viewer work without
   any setup, but it costs some CPU per request (building the entry) and disk
   (as above). I recommend on, with the caps above, and `off` for those who
   only want forwarding.
2. **Reads too, or writes, deletes and admin only?** Reads are most of the
   volume, but "who downloaded this" is a common question after a leak. I
   recommend recording everything, with `BUCKETS_AUDIT_LOCAL_READS=off` to
   leave reads out.
3. **Each server's own drive, or erasure-coded objects?** Erasure coding
   survives a drive's loss, but costs a quorum write per batch on every server
   and competes with real traffic. I recommend the server's own drive, with
   forwarding to a SIEM as the record that must last.
4. **Sentinel sign-in:** a client secret now, and Azure workload identity
   (federated tokens from the pod's service account, no secret) later? Or
   both now?
