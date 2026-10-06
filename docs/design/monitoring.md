# Design: monitoring shipped with the operator

Status: agreed, built. What changed while building it is under "As built" at the end. Roadmap: Phase 3, "Monitoring shipped with the
operator". Phase 3 is done when, among other things, "a failing drive raises
an alert without anyone looking".

## The problem

`bucketsd` already exports MinIO's metrics, with the same names and labels
(`tests/integration/metrics-names.sh` holds them to MinIO's), on both of
MinIO's endpoints:

- the v2 cluster, node, bucket and resource endpoints under
  `/minio/v2/metrics/`;
- v3 under `/minio/metrics/v3`.

The metrics needed for alerts are all there:

| Area | Metrics |
|---|---|
| Drives and nodes | `minio_cluster_drive_offline_total`, `minio_cluster_nodes_offline_total`, `minio_node_drive_errors_{ioerror,timeout,availability}`, `minio_node_drive_free_bytes` |
| Erasure sets | `minio_cluster_health_erasure_set_status`, `_online_drives`, `_write_quorum`, `_healing_drives` |
| Capacity | `minio_cluster_capacity_usable_{free,total}_bytes` |
| Healing | `minio_heal_objects_*` |
| Requests | `minio_s3_requests_5xx_errors_total`, `minio_s3_requests_rejected_auth_total`, TTFB distributions |
| Services | `minio_cluster_kms_online`, `minio_node_iam_sync_failures` |

But nothing uses them. Nobody scrapes a Buckets cluster unless someone writes
the scrape configuration by hand. That configuration needs a bearer token,
because metrics are authenticated by default, and the cluster's TLS settings.
There are no alerts and no dashboards. A drive can fail and stay failed until
someone opens the console.

The shared dev cluster shows the typical setup. It runs Rancher's monitoring:
the Prometheus Operator, Prometheus, Alertmanager and Grafana. Its Prometheus
picks up every `ServiceMonitor` and `PrometheusRule` in every namespace, and
its Grafana loads dashboards from ConfigMaps labelled `grafana_dashboard=1` in
`cattle-dashboards`. That's the same layout as kube-prometheus-stack, which
most clusters with Prometheus use.

## What it does

### Per cluster: the operator connects Prometheus to it

For each BucketsCluster, when the Prometheus Operator's CRDs are installed,
`buckets-operator` creates two things.

**1. Metrics credentials.** These are created, never shared with people:
- a policy `buckets-prometheus` allowing only `admin:Prometheus`;
- a local user `<cluster>-prometheus` with that policy;
- a Secret `<cluster>-prometheus-token` holding the bearer token. That's a
  JWT with issuer `prometheus`, signed with that user's secret key, which is
  what `mc admin prometheus generate` makes. Rotating means deleting the
  Secret; the operator makes a new one.

**2. A ServiceMonitor `<cluster>`** with:
- one endpoint for `/minio/v2/metrics/cluster`, through the cluster Service,
  so the cluster-wide figures are scraped once;
- one endpoint for `/minio/v2/metrics/node` on every server, through the
  headless Service, for per-drive and per-node figures;
- the bearer token Secret, and the cluster's TLS: its CA and server name, from
  `spec.tls`;
- labels and an interval from `spec.monitoring`.

The status reports it: `status.monitoring: {phase: Ready | NotInstalled |
Error, message}`. NotInstalled means there are no Prometheus Operator CRDs,
and the console's Dashboard says how to scrape by hand.

```yaml
spec:
  monitoring:
    enabled: true          # default: on when the Prometheus Operator's CRDs exist
    interval: 30s
    labels: {}             # extra labels for the ServiceMonitor, for Prometheus setups that select by label
```

### Once per installation: alert rules and dashboards, from the Helm chart

The rules and dashboards are the same for every cluster: they group by
`namespace` and `service`. So the operator's Helm chart installs them once,
rather than the operator writing a copy per cluster:

```yaml
monitoring:
  rules:
    enabled: true          # a PrometheusRule "buckets" in the chart's namespace
    labels: {}
    capacityWarningPercent: 15
    capacityCriticalPercent: 5
  dashboards:
    enabled: true          # ConfigMaps with the Grafana sidecar's label
    namespace: ""          # e.g. cattle-dashboards (Rancher), or the chart's namespace
    labels: {grafana_dashboard: "1"}
```

The same files are also in the repo as plain YAML and JSON, for setups without
the chart or without the Prometheus Operator:
- `operator/monitoring/rules.yaml`, a Prometheus rule file;
- `operator/monitoring/dashboards/*.json`, for Grafana's import;
- `docs/monitoring.md`, with a scrape configuration to copy.

### The alerts

Each alert has a summary naming the cluster (`namespace/service`), and a
`runbook_url` pointing to its section of `docs/monitoring.md`, which says
what to check and what to do.

| Alert | When | Severity |
|---|---|---|
| `BucketsDriveOffline` | `minio_cluster_drive_offline_total > 0` for 5m | warning |
| `BucketsNodeOffline` | `minio_cluster_nodes_offline_total > 0` for 5m | critical |
| `BucketsErasureSetDegraded` | an erasure set's online drives at or below its write quorum, for 2m: one more failure stops writes | critical |
| `BucketsDriveErrors` | I/O or timeout errors on a drive rising over 15m | warning |
| `BucketsHealingSlow` | drives still healing after 6h | info |
| `BucketsCapacityLow` / `BucketsCapacityCritical` | usable free space below 15% / 5% for 15m | warning / critical |
| `BucketsCapacityFullIn7Days` | `predict_linear` of free space reaches 0 within 7 days | warning |
| `BucketsHighErrorRate` | 5xx responses over 5% of requests for 10m | warning |
| `BucketsAuthFailuresSpike` | requests rejected for bad credentials far above their usual rate for 10m | warning |
| `BucketsKMSOffline` | `minio_cluster_kms_online == 0` for 5m (clusters with a KMS) | critical |
| `BucketsIAMSyncFailing` | IAM sync failures rising for 15m | warning |
| `BucketsMetricsDown` | the ServiceMonitor's targets down for 5m | critical |

The roadmap asks for alerts on failed sign-ins. On the S3 side,
`minio_s3_requests_rejected_auth_total` covers bad signatures and keys. The
console's own sign-in failures have no metric yet. `consoled` gets one,
`buckets_console_logins_failed_total`, and the auth-failure alert covers both.

### The dashboards

Four dashboards, each with a cluster picker (`namespace`/`service`):

1. **Overview:** health, capacity and its trend, drives and nodes online,
   requests, errors and latency.
2. **Drives and healing:** per-drive free space, errors and latency, erasure
   sets against their quorum, healing progress.
3. **Buckets:** usage, object counts, quotas, replication backlog and failures.
4. **Access and services:** auth rejections, console sign-in failures, IAM
   sync, KMS.

They are written for Buckets rather than copied from MinIO's. They use only
metrics that `bucketsd` exports, which a test enforces (see below).

## Code

- **Operator** (`operator/src/monitoring.c`):
  - create the policy, user and token Secret, and keep them;
  - create, update or delete the ServiceMonitor, when the CRD exists (checked
    at start and each resync);
  - set `status.monitoring`;
  - add `spec.monitoring` to the CRD.
- **`consoled`:** `buckets_console_logins_failed_total` (by method: password,
  OpenID, LDAP), on a `/metrics` endpoint with the same bearer-token rules as
  the servers' metrics.
- **Helm chart:** `templates/prometheusrule.yaml` and
  `templates/dashboards.yaml`, rendered from `operator/monitoring/`;
  `values.yaml` as above.
- **Docs:** `docs/monitoring.md`, covering setup with and without the
  Prometheus Operator, each alert's runbook, and the dashboards.

## Tests

- **Every metric name used is real.** A test reads every PromQL expression in
  the rules and dashboards, and checks each `minio_*` / `buckets_*` name
  against `src/metrics/minio-catalog.tsv`, `extra-catalog.tsv` and the console
  metric. So no alert or panel can watch a metric that does not exist.
- **Rules:** `promtool check rules`, and `promtool test rules` unit tests with
  synthetic series for each alert. For example: a drive offline for 4 minutes
  is silent, and for 6 minutes fires. Run in CI, with `promtool` downloaded
  like the other test tools.
- **Operator:** envtest. A cluster gets its ServiceMonitor, token Secret and
  status, and loses them when monitoring is turned off. Without the CRDs it
  reports NotInstalled and creates nothing.
- **Integration:** the token the operator makes can scrape a real `bucketsd`,
  both endpoints, with TLS. The console's failed-login counter rises.
- **Cluster** (`tests/e2e-k8s/monitoring.sh`), on the shared cluster with
  Rancher's Prometheus:
  1. A test cluster's targets come up in Prometheus.
  2. Every dashboard query returns data.
  3. A drive is taken away: its PVC's pod gets a broken mount, or the drive
     directory is made unreadable. `BucketsDriveOffline` fires in Prometheus
     within 6 minutes and clears after the drive is back.

## Decisions

1. **On by default** when the Prometheus Operator's CRDs are installed.
   `spec.monitoring.enabled: false` opts a cluster out, and the chart's
   `monitoring.rules.enabled` / `dashboards.enabled` opt the installation
   out.
2. **Metrics authentication: a dedicated least-privilege user and a bearer
   token**, not public metrics.
3. **v2 endpoints now**; v3 later, once its label set settles in MinIO.
4. **The console's sign-in failure metric is included.**
5. **Dashboards go to `monitoring.dashboards.namespace`**, defaulting to the
   chart's namespace. On Rancher it is set to `cattle-dashboards`, as the
   docs and the chart's notes say.

## As built

What changed from the design while building it:

- **Every server is scraped for every endpoint.** A ServiceMonitor scrapes a
  Service's pods, not its address, so the cluster and bucket endpoints are
  scraped on every server too. The rules take `max` over servers for the
  cluster-wide figures.
- **A third endpoint.** Per-bucket figures exist only on
  `/minio/v2/metrics/bucket`, so the ServiceMonitor scrapes it too
  (`scope="bucket"`).
- **The headless Service.** The ServiceMonitor selects it by a new label,
  `buckets.io/service: headless`. The console Service gets
  `buckets.io/service: console`.
- **`BucketsKMSOffline` became `BucketsKMSFailing`.** `minio_cluster_kms_online`
  is 1 whenever a KMS is configured, even an unreachable external KES, so the
  alert watches KMS request failures instead.
- **`BucketsIAMSyncFailing` is left out.** `minio_node_iam_sync_*` exists only
  with an identity plugin, as in MinIO, so it would be silent on almost every
  cluster.
- **Fixed capacity thresholds.** They are 15% and 5%, not chart values: the
  rule file is shipped verbatim, so it works without Helm too.
- **Checking the console's token.** The console cannot check a token itself, so
  it asks `bucketsd`: the same Authorization header on
  `/minio/metrics/v3/cluster/health`, cached for a minute. That way exactly
  the tokens `bucketsd` accepts read the console's metrics.
- **A bug found and fixed.** The console's test found that the sanitizer
  builds of `bucketsd` aborted on that v3 path when no storage tier was
  configured (a `memcpy` from NULL). That was fixed on `main` first.
