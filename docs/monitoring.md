# Monitoring

Buckets exports MinIO's Prometheus metrics, with the same names and labels.
On Kubernetes with the Prometheus Operator (kube-prometheus-stack, Rancher
monitoring), the operator and its Helm chart set up the rest: scraping, alert
rules and Grafana dashboards.

## With the operator

Install or upgrade the chart as usual. When the Prometheus Operator's CRDs are
in the cluster:

- **The chart** installs the alert rules (a `PrometheusRule`, below) and four
  Grafana dashboards (ConfigMaps for Grafana's dashboard sidecar), once for all
  clusters.
- **The operator** gives every BucketsCluster:
  - a metrics user `<cluster>-prometheus`, allowed only `admin:Prometheus`
    (policy `buckets-prometheus`), so it can read metrics but no data;
  - its bearer token in Secret `<cluster>-prometheus`;
  - a ServiceMonitor `<cluster>` that scrapes every server's
    `/minio/v2/metrics/node`, `/cluster` and `/bucket` endpoints, using the
    cluster's TLS settings;
  - a ServiceMonitor `<cluster>-console` for the console's failed sign-ins.

Every series is labelled `buckets_cluster=<cluster>` and
`scope=node|cluster|bucket`. The rules and dashboards use these labels.

```sh
kubectl get bucketscluster store -o jsonpath='{.status.monitoring}'
# {"phase":"Ready","message":"Prometheus scrapes every server and the console through ServiceMonitor store and its -console one."}
```

`status.monitoring.phase` is one of:

| Phase | Meaning |
|---|---|
| `Ready` | The metrics user, its token and the ServiceMonitor(s) are in place. |
| `NotInstalled` | No Prometheus Operator. Scrape the servers yourself (see below). |
| `Disabled` | `spec.monitoring.enabled` is false. |
| `Error` | The message says what failed, for example the servers could not be reached to create the metrics user. |

The cluster's spec can tune or turn off the ServiceMonitor:

```yaml
spec:
  monitoring:
    enabled: true        # default: on when the Prometheus Operator's CRDs exist
    interval: 30s
    labels:              # for a Prometheus that selects ServiceMonitors by label
      release: kube-prometheus-stack
```

To rotate the token, delete Secret `<cluster>-prometheus`. The operator makes
a new user secret and a new token.

The chart's values:

```yaml
monitoring:
  rules:
    enabled: true
    labels: {}           # for a Prometheus that selects rules by label
  dashboards:
    enabled: true
    namespace: ""        # default: the release's namespace
    labels: {grafana_dashboard: "1"}
    folder: Buckets
```

**On Rancher**, Grafana loads dashboards only from `cattle-dashboards`:

```sh
helm upgrade buckets-operator oci://ghcr.io/storscale/charts/buckets-operator \
  -n buckets-system --reuse-values --set monitoring.dashboards.namespace=cattle-dashboards
```

**If Prometheus picks rules or ServiceMonitors by label** (kube-prometheus-stack
with `ruleSelectorNilUsesHelmValues: true`, the default), set
`monitoring.rules.labels` in the chart and `spec.monitoring.labels` in each
cluster to the labels it selects, for example `release: kube-prometheus-stack`.

## Without the Prometheus Operator

The rules and dashboards are plain files in the chart, so they also work
outside Kubernetes:
- `monitoring/rules.yaml`, a Prometheus rule file;
- `monitoring/dashboards/*.json`, which you import into Grafana.

They expect the two labels the ServiceMonitor adds, so add them in your scrape
configuration:

```sh
mc admin prometheus generate mycluster   # prints a bearer token for the alias's user
```

```yaml
scrape_configs:
  - job_name: buckets-node
    metrics_path: /minio/v2/metrics/node
    bearer_token: <token>
    scheme: https
    static_configs:
      - targets: [server1:9000, server2:9000, server3:9000, server4:9000]
        labels: {buckets_cluster: store, scope: node, namespace: storage}
  # the same for /minio/v2/metrics/cluster (scope: cluster) and /minio/v2/metrics/bucket (scope: bucket)
```

Use a user allowed only `admin:Prometheus` for the token, rather than root:

```sh
mc admin policy create mycluster buckets-prometheus <(echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["admin:Prometheus"],"Resource":["arn:aws:s3:::*"]}]}')
mc admin user add mycluster prometheus <secret>
mc admin policy attach mycluster buckets-prometheus --user prometheus
```

Then generate the token with an alias for that user.

`namespace` is the label the rules group clusters by; set it to anything that
names where the cluster runs. The console's metrics are at `/metrics` on the
console, with the same token. If the servers' metrics are public
(`MINIO_PROMETHEUS_AUTH_TYPE=public`), so are the console's.

## Try it locally

[`examples/monitoring`](../examples/monitoring) runs all of this on one machine: a four-drive Buckets server with steady traffic, Prometheus scraping it as above with the rules loaded, and Grafana with the four dashboards. Its test checks the scraping, the rules and the dashboards' queries, then empties a drive under load, as a swapped disk looks: Buckets reports the drive offline and the drive alerts start, then it formats the drive back into its slot, heals it, and the alerts resolve.

```bash
cd examples/monitoring
docker compose up -d --wait
docker compose run --rm test
```

## Alerts

Each alert links to its section here.

### BucketsDriveOffline

**What:** a drive has been offline for 5 minutes. Data is still served while
every erasure set keeps its quorum, but redundancy is reduced.

**Check:**
- `kubectl get pods` for a server that is not ready;
- the server's log, for the drive's error;
- on Kubernetes, the PVC and its PV, and whether the volume is attached.

**Then:** bring the drive back, or replace it.
- **A disk swapped under the same mount point:** within one check (15
  seconds), the server formats the new, empty disk into the old one's slot
  and heals it in the background. The log says "drive ... was replaced".
- **On Kubernetes:** delete the drive's PVC and then its server's pod. The
  StatefulSet makes a new volume, and the server formats and heals it when it
  starts.

A drive found without its `format.json` refuses reads and writes within
about a second, so nothing lands on an emptied disk before it is formatted
back. One that still holds data from before it lost its `format.json` is
never formatted over: the log says so once. Restore its `format.json`, or
wipe it to have it treated as a new disk.

### BucketsNodeOffline

**What:** a whole server has been unreachable for 5 minutes, so every drive on
it is offline.

**Check:** the pod's status and events (scheduling, the node, OOM kills); the
network between servers.

### BucketsErasureSetDegraded

**What:** an erasure set has only as many drives online as its write quorum.
One more failure in that set stops writes to it, and two stop reads.

**Then:** treat this as urgent. Bring back the set's offline drives before
anything else; `BucketsDriveOffline` names how many are gone.

### BucketsDriveErrors

**What:** a drive keeps returning I/O errors or timeouts. Drives often do this
shortly before they fail.

**Check:** the node's kernel log (`dmesg`) and SMART data for that disk. Plan
to replace the drive.

### BucketsHealingSlow

**What:** an erasure set has been healing for more than 6 hours. Large drives
take a long time; this alert is informational.

**Check:** `mc admin heal --verbose` (or the Drives and healing dashboard)
shows whether objects are still being healed. If nothing moves, check the
servers' logs for heal errors.

### BucketsCapacityLow

Three alerts link here:
- `BucketsCapacityLow`: less than 15% of usable capacity free;
- `BucketsCapacityCritical`: less than 5% free;
- `BucketsCapacityFullIn7Days`: at the rate of the last 6 hours, usable
  capacity runs out within a week.

**Then:**
- add a pool (`spec.pools`), which needs no downtime;
- expire old data with lifecycle rules;
- set bucket quotas.

Writes fail once the drives are full.

### BucketsHighErrorRate

**What:** more than 5% of S3 requests have failed with server errors (5xx) for
10 minutes.

**Check:** the Overview dashboard's requests by API; the servers' logs. Often
this follows offline drives or servers, or an unreachable KMS.

### BucketsAuthFailuresSpike

**What:** more than one failed sign-in every 5 seconds for 10 minutes. This
counts S3 requests with bad credentials together with failed console sign-ins.

**Check:**
- the Access and services dashboard, for which kind is rising;
- the audit log or trace (`mc admin trace --errors`), for which access key and
  source address.

A client with an old secret looks the same as someone guessing passwords.

### BucketsKMSFailing

Two alerts link here:
- `BucketsKMSOffline`: no KES endpoint has answered its status check for 5
  minutes;
- `BucketsKMSFailing`: requests to the KMS are failing.

Either way, encrypted objects cannot be read or written meanwhile.

**Check:** the KMS's status on the console's Encryption page. For KES run by
the operator, its pods and `status.kms`. For an external KES or Vault, the
network path and its certificate.

### BucketsMetricsDown

**What:** Prometheus has not been able to scrape a server for 5 minutes. While
this lasts, the other alerts cannot fire for that server.

**Check:**
- the pod;
- `status.monitoring` on the BucketsCluster;
- Prometheus' Targets page, which shows the scrape error. A 403 means the
  token is wrong: delete Secret `<cluster>-prometheus` to have it made again.

## Dashboards

Each dashboard has a namespace and a cluster picker.

| Dashboard | Shows |
|---|---|
| Buckets / Overview | Health, drives and servers online, healing, capacity, S3 requests, errors, latency and throughput |
| Buckets / Drives and healing | Erasure sets against their write quorum, every drive's space, errors and latency, healing progress |
| Buckets / Buckets | Size, objects, versions and quota per bucket; replication |
| Buckets / Access and services | Requests rejected for bad credentials, failed console sign-ins, client errors by API, the KMS |

They are written by `tools/dashboards/gen.py`. `tests/monitoring/check_metrics.py`
checks that every metric they and the alert rules use is one Buckets exports,
on the endpoint each query asks for.
