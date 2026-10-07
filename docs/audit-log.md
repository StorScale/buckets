# Audit log

Every request makes an audit entry: who (the access key, and the person behind
it), what (the API, bucket, object, result and bytes), when, and from where.
Buckets keeps these entries on each server and shows them in the console. It
can also forward them to Microsoft Sentinel, Splunk, or any other webhook or
Kafka target.

The design is in [design/audit-log.md](design/audit-log.md).

## In the console

**Reports → Audit log** shows what was done, newest first:

- **When:** the last hour, day or week, or a range of your choice.
- **Filters:** person, access key, bucket, object prefix, API (such as
  `DeleteObject`), kind (reads, writes, deletes, administration), result
  (succeeded, denied, failed) and source IP. Press **Apply** to run the
  filters again, which also picks up entries that arrived since.
- **Details:** click an entry to see all of it, as JSON.
- **Who:** a user or service account's owner by name. For someone signed in
  through OpenID (Entra ID, Okta, Keycloak), Buckets' own name for them is a
  hash, so the page shows the token's `preferred_username`, `upn` or `email`
  instead, and the person filter matches any of these.
- **Older entries** loads the next page. **Export CSV** saves up to 10,000
  entries that the filters select.

The filters are part of the page's address, so a filtered view can be
bookmarked or shared. Other pages link to it with filters already set:

- **Activity:** an incident's **What it did** shows that credential's actions,
  from half an hour before the incident to ten minutes after it.
- **A bucket's settings:** **Who used it** shows the last day of requests to
  the bucket.
- **Users:** **Actions** shows the last week of that person's actions.

The page says how far back the entries go. It also says when a server is not
answering, since its entries are then missing, and how many entries the
servers dropped because they were too busy (see below).

Seeing the audit log takes `admin:ServerInfo`, as the trace and the logs do.

## Where the entries are kept

Each server keeps the entries for the requests it served. They go on its first
drive, in `.buckets-audit/<date>/<hour>-<n>.jsonl`, one entry per line. A file
is compressed with gzip when its hour ends, or sooner if it reaches 64 MiB.
This copy is outside the erasure-coded data:

- It survives restarts and upgrades, but not the loss of that drive.
- Neither Buckets nor MinIO takes the directory for a bucket. Its name starts
  with a dot, which no bucket name can.

**For a record that must last, forward the entries to a SIEM** (below). The
local copy is there for quick answers, not as the system of record.

Entries are written in the background, and requests never wait for them. If
a server receives requests faster than it can write their entries, it drops
entries rather than slowing requests down, and counts how many it dropped.
Forwarding is not affected.

| Variable | Default | |
| --- | --- | --- |
| `BUCKETS_AUDIT_LOCAL` | on | `off`: keep no local copy |
| `BUCKETS_AUDIT_LOCAL_READS` | on | `off`: leave reads (GET, HEAD, listing, Select) out of the local copy; forwarding still gets them |
| `BUCKETS_AUDIT_LOCAL_DAYS` | `30` | days kept |
| `BUCKETS_AUDIT_LOCAL_MAX` | `10G` | bytes kept per server, such as `500M` or `50G`; the oldest hours go first |

Set them on every server, for example in the BucketsCluster's `spec.env`.

**What it costs:** an entry is about 1 KB, and compressed it takes about a
tenth of that. A server answering 500 requests a second all day writes about
4 GB a day, so 10 GiB holds a little over two days at that rate. A quieter
server keeps the full 30 days. Leaving reads out cuts the size the most on a
read-heavy server.

**Querying:** the server you ask fetches matching entries from every server
and merges them by time. Each server reads only the hours in the range, so a
short range answers quickly and a month-long one is slower.

**Metrics,** per server:
- `buckets_node_audit_local_bytes`: the bytes the local copy holds.
- `buckets_node_audit_dropped_total`: entries the local copy dropped. Any
  increase means the drive is too slow or too full for the request rate.

## Microsoft Sentinel

Buckets sends entries to Sentinel through Azure Monitor's
[Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview).
It sends them in batches, as a data collection rule (DCR) expects, signed in
as an Entra ID app. (The older HTTP Data Collector API is retired on
14 September 2026, so Buckets doesn't use it.)

### In Azure

1. **A custom table** in the Sentinel workspace, `BucketsAudit_CL`:

   | Column | Type |
   | --- | --- |
   | `TimeGenerated` | datetime |
   | `time` | datetime |
   | `version`, `deploymentid`, `event`, `trigger` | string |
   | `api` | dynamic (name, bucket, object, status, statusCode, rx, tx, timings) |
   | `remotehost`, `requestID`, `userAgent`, `requestPath`, `requestHost` | string |
   | `requestClaims`, `tags` | dynamic |
   | `accessKey`, `parentUser`, `error` | string |

2. **A data collection endpoint** (DCE), or use the DCR's own ingestion
   endpoint.
3. **A data collection rule** with:
   - a stream `Custom-BucketsAudit_CL` with the columns above, apart from
     `TimeGenerated`;
   - the workspace as its destination;
   - this transform: `source | extend TimeGenerated = todatetime(time)`.

   Note the rule's **immutable ID** (`dcr-...`).
4. **An app registration** in Entra ID, with a client secret. Give it the
   **Monitoring Metrics Publisher** role on the DCR.

### In Buckets

| Variable | |
| --- | --- |
| `BUCKETS_AUDIT_SENTINEL_ENDPOINT` | the DCE's logs ingestion URL, such as `https://buckets-abcd.westeurope-1.ingest.monitor.azure.com` |
| `BUCKETS_AUDIT_SENTINEL_DCR_ID` | the DCR's immutable ID |
| `BUCKETS_AUDIT_SENTINEL_STREAM` | `Custom-BucketsAudit_CL` |
| `BUCKETS_AUDIT_SENTINEL_TENANT_ID` | the Entra ID tenant |
| `BUCKETS_AUDIT_SENTINEL_CLIENT_ID` | the app's client ID |
| `BUCKETS_AUDIT_SENTINEL_CLIENT_SECRET` | its secret, or `_CLIENT_SECRET_FILE`: a file that holds it |
| `BUCKETS_AUDIT_SENTINEL_BATCH_SIZE` | entries per request (100) |
| `BUCKETS_AUDIT_SENTINEL_QUEUE_DIR` | a directory that holds entries while Azure can't be reached; without it, they wait in memory |
| `BUCKETS_AUDIT_SENTINEL_QUEUE_SIZE` | entries held at most (100000) |
| `BUCKETS_AUDIT_SENTINEL_CA_FILE` | extra CA certificates, if a proxy re-signs TLS |
| `BUCKETS_AUDIT_SENTINEL_LOGIN_URL` | Entra ID's sign-in URL (`https://login.microsoftonline.com`); change it for a sovereign cloud |

These settings are environment variables, not `mc admin config` settings. That
keeps the server's configuration readable by MinIO after a rollback. For
example, in a BucketsCluster, with the secret in a Kubernetes Secret:

```yaml
spec:
  env:
    - {name: BUCKETS_AUDIT_SENTINEL_ENDPOINT, value: https://buckets-abcd.westeurope-1.ingest.monitor.azure.com}
    - {name: BUCKETS_AUDIT_SENTINEL_DCR_ID, value: dcr-00112233445566778899aabbccddeeff}
    - {name: BUCKETS_AUDIT_SENTINEL_STREAM, value: Custom-BucketsAudit_CL}
    - {name: BUCKETS_AUDIT_SENTINEL_TENANT_ID, value: 00000000-0000-0000-0000-000000000000}
    - {name: BUCKETS_AUDIT_SENTINEL_CLIENT_ID, value: 11111111-1111-1111-1111-111111111111}
    - name: BUCKETS_AUDIT_SENTINEL_CLIENT_SECRET
      valueFrom: {secretKeyRef: {name: buckets-sentinel, key: client-secret}}
```

When a server starts, its log says `audit: entries go to Microsoft Sentinel`.
If a setting is missing, the log names it. A failed sign-in or upload is
logged and counted in `minio_audit_failed_messages{target_id="audit-sentinel"}`,
and the entries wait in the queue until Azure accepts them. Buckets keeps the
access token until shortly before it expires.

Workload identity (signing in without a secret) is not supported yet.

### Queries

```kusto
// Who: a user's name, or for an OpenID sign-in the token's (parentUser is then a hash)
BucketsAudit_CL
| extend person = coalesce(tostring(requestClaims.upn), tostring(requestClaims.preferred_username), parentUser, accessKey)

// What a person deleted in the last week
BucketsAudit_CL
| extend person = coalesce(tostring(requestClaims.upn), tostring(requestClaims.preferred_username), parentUser, accessKey)
| where TimeGenerated > ago(7d) and person == "alice@example.com"
| where tostring(api.name) in ("DeleteObject", "DeleteObjects", "DeleteBucket")
| project TimeGenerated, api = tostring(api.name), bucket = tostring(api.bucket), object = tostring(api.object), remotehost

// Denied requests by source, hourly
BucketsAudit_CL
| where toint(api.statusCode) in (401, 403)
| summarize denied = count() by remotehost, bin(TimeGenerated, 1h)

// Object access beside the person's Entra ID sign-ins
BucketsAudit_CL
| where TimeGenerated > ago(1d)
| extend upn = tostring(requestClaims.upn)
| where isnotempty(upn)
| summarize requests = count(), sources = make_set(remotehost) by upn
| join kind=leftouter (
    SigninLogs | where TimeGenerated > ago(1d)
    | summarize signins = count(), signinIPs = make_set(IPAddress) by UserPrincipalName
  ) on $left.upn == $right.UserPrincipalName
```

Entries made with temporary credentials from an OpenID sign-in carry the ID
token's claims in `requestClaims`. Entra ID puts `upn` in the token when the
app registration's optional claims include it, and `preferred_username` is
usually the same ([identity.md](identity.md)).

## Splunk

The standard audit webhook target already works with Splunk's HTTP Event
Collector (HEC). Send to the `raw` endpoint, with the HEC token as the
`Authorization` header (`auth_token` is sent as it is):

```sh
mc admin config set store audit_webhook:splunk \
  endpoint="https://splunk.example.com:8088/services/collector/raw?sourcetype=minio:audit" \
  auth_token="Splunk 0123abcd-..." \
  queue_dir=/data/audit-splunk enable=on
```

The same works through `MINIO_AUDIT_WEBHOOK_*_<name>` environment variables,
or the console's **Configuration** page. Each entry arrives as one JSON event.
Use `INDEXED_EXTRACTIONS = json` for the source type, and `time` as its
timestamp (`TIME_PREFIX = "time":"`).

## For other tools

```
GET /minio/admin/v3/buckets/audit?from=&to=&user=&accessKey=&bucket=&prefix=&api=&kind=&status=&ip=&limit=&cursor=
```

- `admin:ServerInfo`.
- `from` and `to` are RFC 3339 times. The defaults are the hour up to now.
- `kind` is `read`, `write`, `delete` or `admin`. `status` is `ok`, `denied`
  or `failed`. `limit` is 1 to 1000, and 100 by default.

It returns
`{"enabled", "entries": [...], "cursor", "coverage": [{"node", "reachable", "enabled", "oldest", "dropped"}]}`:

- `entries` are MinIO's audit entries, each with the `node` that served it,
  newest first.
- To get the next page, pass `cursor` back while it is not null.
- `oldest` is unix seconds.
