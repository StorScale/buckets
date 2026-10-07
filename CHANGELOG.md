# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.15.0] - 2026-10-07

### Added
- **The audit log** ([docs/audit-log.md](docs/audit-log.md), [the design](docs/design/audit-log.md)): what was done, by whom, from where and with what result, in the console, and forwarded to Microsoft Sentinel.
  - **Kept on each server:** the audit entries for the requests it served, on its first drive (`.buckets-audit`, outside the erasure-coded data), written in the background and compressed hourly. They are kept for 30 days or 10 GiB per server, whichever comes first (`BUCKETS_AUDIT_LOCAL_DAYS`, `BUCKETS_AUDIT_LOCAL_MAX`). `BUCKETS_AUDIT_LOCAL=off` turns the copy off, and `BUCKETS_AUDIT_LOCAL_READS=off` leaves reads out. A busy server drops entries rather than slowing requests, and counts them (`buckets_node_audit_dropped_total`). `buckets_node_audit_local_bytes` shows the space the copy uses.
  - **Reports → Audit log** in the console: a time range, filters (person, access key, bucket, object prefix, API, kind, result, source IP), each entry's details, paging, and CSV export. Someone signed in through OpenID appears under the name their token gives. Activity incidents, bucket settings and users link to it already filtered.
  - **Microsoft Sentinel:** entries go through Azure Monitor's Logs Ingestion API to a data collection rule, signed in as an Entra ID app (`BUCKETS_AUDIT_SENTINEL_*`). They wait in a queue, in memory or on disk, while Azure can't be reached. The docs give the table, the rule's transform and KQL queries.
  - **Splunk:** the audit webhook target, sent to the HTTP Event Collector with `auth_token="Splunk <token>"`, is now documented and tested.
  - **For other tools:** `GET /minio/admin/v3/buckets/audit` (`admin:ServerInfo`) asks every server and merges the answers.

### Fixed
- When the console's browser tests failed to start (a server binary missing, say), the processes they had already started were left running and their data left behind. They are now stopped and removed.

## [1.14.0] - 2026-10-07

### Added
- **Ransomware alerts** ([docs/ransomware.md](docs/ransomware.md), [the design](docs/design/ransomware-alerts.md)). Buckets notices mass deletion, mass overwriting and weakened protection as they happen, names the bucket and the credential, and can turn that credential off.
  - **Bursts:** at least 1,000 objects in 5 minutes, and more than 10 times the bucket's usual rate, per bucket or per credential across buckets. Each object of a `DeleteObjects` call counts, as does each delete marker and each write over an existing object. The usual rate is the median of each day's busiest hour over the 14 days before today, so nightly clean-up jobs don't trigger it and an attack doesn't raise the bar for the next. The leader adds up every server's counts every 30 seconds.
  - **Protection removed,** reported every time: versioning suspended, a lifecycle rule expiring noncurrent versions, Governance retention bypassed, a bucket force-deleted, or a policy letting anyone write or delete.
  - **Each incident** goes to the bucket's notification targets (`s3:Buckets:MassDelete`, `MassOverwrite`, `ProtectionRemoved`), the server log and three new alerts. It also appears on the console's **Reports → Activity** page, where the credential can be turned off or back on, or the incident marked a false alarm.
  - **Response:** `BUCKETS_RANSOMWARE_RESPONSE=disable` turns the credential behind a burst off at once (an access key or user turned off, STS sessions revoked; never root).
  - **For other tools:** `GET` and `POST /minio/admin/v3/buckets/incidents`, per-bucket metrics (`buckets_bucket_objects_deleted_total`, `_versions_destroyed_total`, `_objects_overwritten_total`, `_protection_changes_total`), and `buckets_ransomware_incidents_total`.
- The usage history's traffic records also count objects deleted and overwritten, per UTC hour.

### Fixed
- On macOS, every memory reading (the metrics and `mc admin` health data) leaked a reference to the host's Mach port. The memory it holds is small, but the references never went away.
- `tests/integration/certsts.sh` failed with OpenSSL's default configuration: its self-signed client certificate came out as a CA, which the server rightly counts as an intermediate, so it reported no certificate instead of an untrusted one. The certificate now says it isn't a CA.
- The console's sidebar now scrolls when it is taller than the window. Before, the links at the bottom (Configuration, Encryption) could not be reached on a short screen.
- The metrics endpoints passed `qsort` a null pointer when they had nothing to report: undefined behaviour, on which a sanitizer build stops. A server with no bucket activity hit it when asked for bucket metrics.
- `tests/integration/ldap.sh` sometimes failed with `STSNotInitialized`: after a start or restart it waited only for root, which works before IAM has loaded. It now waits for STS too.

## [1.13.0] - 2026-10-07

### Added
- **FIPS 140-3 mode** ([docs/fips.md](docs/fips.md), [the design](docs/design/fips-mode.md)). Every security function runs in the OpenSSL FIPS Provider 3.1.2 (FIPS 140-3 certificate #4985), with only the algorithms it approves.
  - **Images:** each of the four images also comes as a `-fips` build (`<version>-fips`), which always runs in FIPS mode. On every start it installs and self-tests the module for that machine, as the module's security policy requires, and it refuses to start if that fails.
  - **The operator:** `spec.fips: true` runs a cluster's servers, console and KES on the `-fips` images; the chart's `fips` value does the same for the operator.
  - **Seeing it:** the log names the module, `mc admin info` reports it per server, the metric `buckets_node_fips_mode` is 1, and the console's Dashboard shows **FIPS 140-3**.
  - **Inside the module:** TLS uses only AES-GCM and the NIST curves; signatures, tokens, SSE and KMS keys run through it; the server sends admin payloads with PBKDF2.
  - **Outside, documented:** MD5 ETags, bitrot checksums and placement hashing, which protect nothing. Argon2id admin payloads from a standard `mc` are accepted too, unless `BUCKETS_FIPS_STRICT=on`.
  - **Refused, saying why:** data, KES keys and TLS that need ChaCha20; Ed25519 SFTP host keys; PostgreSQL MD5 password authentication.
  - **Before switching:** the encryption coverage report counts versions encrypted with ChaCha20-Poly1305, which MinIO uses on CPUs without AES, so a site can re-encrypt them first.

### Changed
- Every hash now goes through OpenSSL's provider interface rather than its low-level functions, so that FIPS mode covers it. Throughput is unchanged (docs/fips.md has the figures).

## [1.12.0] - 2026-10-07

### Added
- **Usage** reports in the console ([docs/usage-reports.md](docs/usage-reports.md), [the design](docs/design/usage-reports.md)). They show who stores and moves how much, per team and per bucket, for this month, last month or any range of days, with **Export CSV**.
  - **What is counted:** storage averaged over the period (GB-months) and at its peak, data in and out, and requests (reads, writes and deletes). Each bucket also has a chart of its daily size.
  - **Teams:** each bucket is charged to one team, the one that names it, else the one whose prefix matches it most closely. Buckets in no team are summed as **No team**.
  - **Costs:** rates per GB-month, per GB in and out, and per 10,000 requests of each kind, in one currency. Costs are worked out when the report is viewed.
  - **History:** at each scanner cycle the leader records the buckets' sizes, and each server records its traffic every 5 minutes. The history is kept for 13 months under `.minio.sys/buckets/usage/`, apart from MinIO's data usage. `BUCKETS_USAGE_HISTORY_DAYS` and `BUCKETS_USAGE_FLUSH_INTERVAL` change this.
  - **For other tools:** `GET /minio/admin/v3/buckets/usage` serves the report (`admin:DataUsageInfo`). `PUT` and `DELETE /minio/admin/v3/buckets/usage-rates` set and remove the rates (`admin:ConfigUpdate`).

### Changed
- The console's **Compliance** section is now **Reports**, holding Usage, Retention and Encryption coverage. Its old `/compliance/...` addresses lead to the new `/reports/...` ones.

### Fixed
- `bucketsd` now frees everything it made when it stops or fails to start, so sanitizer builds report no leaks at exit. Before, a stopping server left its IAM, configuration, replication, tiering, batch, site replication and decommission state to the process's exit. It also lost the pool list it starts with when it read the one stored on the drives.
- A drive heal on a deployment with no buckets passed `qsort` a null pointer (undefined behaviour, reported by the sanitizer build).

## [1.11.1] - 2026-10-07

### Fixed
- Directories on the drives that no bucket could be named, such as the `lost+found` an ext4 filesystem keeps at its root, counted as buckets in the data usage, the scanner and the compliance report. On the dev cluster `lost+found` showed up there. They are now skipped, as MinIO skips them, and left untouched. `tests/integration/stray-dirs.sh` covers it.

## [1.11.0] - 2026-10-07

### Added
- Keys the identity sync turned off say so. The Users page, the Access Keys page and the access review show when the owner left the identity provider and when the key will be deleted. The admin API's key listings and key info carry this as `ownerLeft` (`since`, `deleteAt`), which MinIO clients ignore.
- A **Compliance** section in the console ([docs/compliance.md](docs/compliance.md), [the design](docs/design/compliance-reports.md)). Each page has one row per bucket and **Export CSV**.
  - **Retention:** object lock, default retention, versioning, the versions and bytes under Governance or Compliance retention or legal hold, the furthest retain-until date, and whether lifecycle rules expire versions.
  - **Encryption coverage:** default encryption and key (flagged when the key no longer works), and the versions and bytes stored with SSE-S3, SSE-KMS, SSE-C or unencrypted, with a link to encrypt what is left.
  - **Where the figures come from:** bucket settings are read live. The counts come from the data scanner's last complete cycle, stored apart from MinIO's data usage.
  - **For other tools:** `GET /minio/admin/v3/buckets/compliance` serves the same data (`admin:DataUsageInfo`). The per-bucket metrics gain `buckets_bucket_unencrypted_bytes` and `_versions`, `_encrypted_bytes{kind}`, `_retained_bytes{mode}` and `_legal_hold_versions`.

### Fixed
- The access review counted access keys that are turned off as routes to a bucket, and "Would this be allowed?" said yes for them. It now reads each key's status: an off key is listed as disabled, and the check answers "The account is disabled."

## [1.10.0] - 2026-10-06

### Added
- People who leave Keycloak or Okta lose their Buckets access too, as with Entra ID since 1.9.0 ([docs/identity.md](docs/identity.md#people-who-leave)).
  - **Keycloak:** the sync signs in as the sign-in client, whose service account needs realm-management's `view-users`.
  - **Okta:** it uses a read-only API token, kept as a secret like the client secret.
  - **Matching:** their people are matched by the token's issuer and subject.
  - **Console:** the Sign-in page shows each provider's steps. **Check every** sets how often the servers ask (60 minutes by default). **Look up a person** takes a Keycloak user name or an Okta login.
  - **Cluster test:** `tests/e2e-k8s/identity.sh` disables a real Keycloak user and checks that their access key turns off, then on again when they return.

## [1.9.1] - 2026-10-06

### Fixed
- `BucketsCapacityFullIn7Days` could fire during a rolling restart. While a server is down, the other servers leave its drives out of the free space for a few minutes. The rule read those dips as a trend toward full: after the 1.9.0 rollout on the dev cluster it predicted -2 GB free in a week, when 20.7 GB was free and steady. With servers slow to rejoin, an hour of dips made it fire. The rule now fits the trend to the most free space in each half hour, so restarts don't count, and a real decline still fires half an hour later. The rule tests cover both cases.

## [1.9.0] - 2026-10-06

### Added
- People who leave Entra ID lose their Buckets access ([docs/identity.md](docs/identity.md#people-who-leave), [the design](docs/design/identity-sync.md)). Every hour, one server asks Microsoft Graph about each person holding credentials.
  - Someone deleted or disabled loses their temporary credentials and console sessions at once.
  - Their access keys are turned off at once and deleted after 30 days; they come back on if the person returns before then.
  - A lookup that fails removes no one, and more people leaving at once than a limit (10) are held until someone raises it. `BucketsIdentitySyncFailing` and `BucketsIdentitySyncHeld` alert on both, from new `buckets_node_identity_sync_*` metrics.
  - It is set up on **Identity → Sign-in** ("People who leave"), with the sign-in app and Graph's User.Read.All application permission. **Look up a person** tests it, and Apply needs that test to pass. Okta, Keycloak and SCIM come later.

## [1.8.0] - 2026-10-06

### Added
- `examples/airflow` and [docs/integrations/airflow.md](docs/integrations/airflow.md): Apache Airflow 3.3 on the lakehouse. People sign in with Keycloak (FAB auth manager), with their groups as Airflow roles (engineers Op, analysts Viewer) and anyone in neither group refused. Pipelines run as a Keycloak service account in group `pipelines`: each task gets a short-lived token for Buckets (through STS, policy `pipelines`) and Trino (Ranger's policies for the group, audited by name). Airflow stores only the client secret. 11 checks, including a run triggered through Airflow's API.
- `examples/monitoring`: Buckets with four drives and steady traffic, Prometheus scraping it as docs/monitoring.md describes (a metrics-only user's token) with the chart's alert rules, and Grafana with the chart's four dashboards. Its test checks the scraping, the rules and the dashboards' queries, then empties a drive under load, as a swapped disk looks, and checks that the drive goes offline and the drive alerts start. `docker compose run --rm screenshots` captures the dashboards with headless Chromium. docs/monitoring.md gains "Try it locally".
- `lakekit.audited()`: count a user's allowed or denied requests in Ranger's audit log.
- `Bucket` resources apply their settings and keep them: versioning, object lock with a default retention, a hard quota, default encryption (`{kmsKey}` or `{sse: S3}`), lifecycle rules and replication. The operator applies a changed spec at once and reads the settings back every 10 minutes, putting back what was changed by hand and naming it in `status.drift`. A field left out is not managed; `quota: ""`, `encryption: {}`, `lifecycle: []` and `replication: {}` remove the setting.
  - `replication.target.cluster` names another BucketsCluster in the namespace. The operator makes the target bucket, versions it, and makes a user on the target that may only replicate into that bucket. It then registers the target and writes the replication rule; `deletes`, `deleteMarkers` and `existingObjects` default to true. The user's secret key is derived from the target's root key, so no Secret holds it. Otherwise, `target: {endpoint, bucket, credsSecret}` replicates to any S3 endpoint that supports MinIO-style replication. With TLS, the source cluster must trust the target's CA. Object lock is turned on only when the operator makes the bucket, as S3 allows; declaring it on an existing bucket without lock is an error in the status. `kubectl get buckets` shows the phase and the last check. Design: [docs/design/declarative-buckets.md](docs/design/declarative-buckets.md); example: `operator/examples/bucket.yaml`.
- `BucketsSiteReplication` (short name `bsr`): site replication between BucketsClusters, and other sites given by endpoint and a credentials Secret. The operator sets it up through the first site, or through the one site with buckets when the first is empty. It adds sites added to the list and removes sites taken out. A list of one site stops the replication, and deleting the resource leaves it running. Example: `operator/examples/site-replication.yaml`.
- [docs/gitops.md](docs/gitops.md) and `operator/examples/gitops`: a whole setup in one repository. It covers two clusters, their policies, a user, and buckets with their settings and replication. The doc explains how the operator treats what is in Git and gives an Argo CD health check. The envtest validates the examples against the CRDs.

### Changed
- A `Bucket`'s `versioning`, `objectLock` and `quota` were accepted but not applied ("not applied yet" in the status). They are now applied, so a Bucket that declared them changes its bucket when the operator is upgraded.

### Fixed
- A drive emptied under write load, as a swapped disk looks, could stay offline for good. A wipe that races writes can't remove the directories those writes are filling, so some are left behind with their older times. The replacement check counted those leftover directories as data "from before", and so never formatted the drive back into its slot. Now only files count as data, so a drive holding just leftover directories is formatted and healed. A drive with older files, such as one that lost only its `format.json`, is still left alone. `tests/integration/drive-health.sh` has a new case, a drive wiped file by file with its directories left behind. Found by `examples/monitoring`, where 2 of 4 swaps under load left the drive offline.
- The Drives and Buckets dashboards' tables named their columns "Value #A" to "Value #E", and showed sizes as raw numbers. `tools/dashboards/gen.py` now renames each column to its label and gives it a unit, such as bytes.

## [1.7.0] - 2026-10-06

### Added
- `spec.tls.certManager` and `spec.console.tls.certManager`: the operator asks cert-manager for the certificates. They name every Service and each server, and come from your issuer (`issuerRef`) or a CA of the cluster's own. The servers and console pick up renewals without restarting, and `status.tls` shows each certificate's readiness and expiry. Without cert-manager, the cluster says so. `privateKey` picks the key type when an issuer needs one (Vault PKI roles may sign only RSA).

### Fixed
- An emptied drive was marked offline but kept taking writes. New objects landed on it, so it never counted as an empty replacement, and the 1.6.0 auto-format and heal never ran. A drive in any offline state now refuses calls. Calls also check, at most once a second, that the drive's `format.json` is still there, so an emptied drive stops taking writes within about a second. What did land in that second is newer than the moment the drive was found empty: it is cleared, and the drive is formatted and healed. Data from before that moment still keeps a drive from being formatted over.
- `tests/integration/cluster.sh` waits for the peers to notice two nodes are gone before checking the cluster health endpoint, instead of failing now and then.

## [1.6.0] - 2026-10-06

### Added
- Drives replaced while the server runs: an empty disk under a drive's mount point is formatted into the old drive's slot within one check and healed in the background, as MinIO does. A drive that still holds data but lost its `format.json` is left alone, and the log says why once.
- `spec.console.nodeSelector`, `tolerations` and `affinity`: where the console's pods run, as pools have.
- The `BucketsKMSOffline` alert: no KES endpoint has answered for 5 minutes.
- `examples/superset` and [docs/integrations/superset.md](docs/integrations/superset.md): Apache Superset 6.1 on the lakehouse. People sign in with Keycloak, their groups are their Superset roles (and anyone in neither group is refused), and Superset runs every query in Trino as the person who asked. So Ranger's policies, masks and row filters, and its audit log, follow each person into SQL Lab and charts. Trino accepts a password for Superset's service account, beside Keycloak tokens for people. 8 checks.
- `examples/dremio` and [docs/integrations/dremio.md](docs/integrations/dremio.md): Dremio 26 (open-source edition) on the lakehouse's Nessie catalog. Dremio reads the Iceberg tables Trino writes, at any Nessie commit, and raw Parquet in Buckets. Its Buckets account may only read, so Buckets refuses its writes. The guide sets out what Dremio's open-source edition does for identity and access, and what needs Enterprise. 7 checks.
- Examples can include the lakehouse stack, `examples/lakehouse/stack.yaml` (Compose `include`): the lakehouse's own `compose.yaml` includes it and adds its checks. Compose releases before 5 refuse a service that an included file already defines, so the stack file has no `test` service. The examples are checked with Compose 2.24 and later. `lakekit.load_sales_tables()` is their shared sample data.

### Fixed
- The access review named the root user only when root had access keys (otherwise "the root user"). It now always shows root's name.
- `minio_cluster_kms_online` was 1 whenever a KMS was configured, even an external KES that did not answer. It now probes KES's status (at most every 30 seconds), as MinIO reports it.

## [1.5.0] - 2026-10-06

### Added
- `examples/jupyterhub` and [docs/integrations/jupyterhub.md](docs/integrations/jupyterhub.md): JupyterHub 6 on Buckets, with Keycloak sign-in through OAuthenticator. Keycloak's groups decide who may sign in and who administers the hub. Each person's notebook (DockerSpawner) reaches Buckets as that person: `buckets_lake` exchanges their Keycloak token, kept and refreshed by the hub, through STS for temporary credentials. Everyone gets a private `home/${jwt:preferred_username}/` prefix, and groups decide access to shared datasets. `docker compose run --rm test` checks 10 claims, signing people in through Keycloak's login form and running code in their notebooks. The shared realm gains the `jupyterhub` client.
- The operator's Helm chart carries Artifact Hub metadata: links to https://storscale.io and the migration guide, the source, keywords, an icon, the license, and its operator capability level.
- `examples/hive-spark` and [docs/integrations/hive-spark.md](docs/integrations/hive-spark.md): Hive Metastore 4.2.1 (on Postgres) as the one catalog for Spark 4.1.3 (a Spark Connect server) and Trino. It holds Hive tables (partitioned Parquet) and Iceberg tables in Buckets, with Ranger and Keycloak as in the lakehouse. `docker compose run --rm test` checks 13 claims: Spark writes and Trino reads, Trino writes and Spark reads, time travel from both engines, and Ranger's and Buckets' access rules. The guide covers what metastore 4 needs: Spark's Hive 4.1 client, Iceberg through the metastore's REST catalog, separate managed and external warehouse directories, and Trino writing to tables the metastore records as external.
- `examples/common`: what the examples share. That's Trino's sign-in and Ranger plugin, the Keycloak realm, the Ranger bootstrap stub, and the setup and test image with its helpers (`lakekit.py`).
- Monitoring with the Prometheus Operator (docs/monitoring.md). For each BucketsCluster, the operator makes a metrics user allowed only `admin:Prometheus`, its bearer token, and ServiceMonitors for the servers and the console (`spec.monitoring`, `status.monitoring`). The Helm chart ships 12 alert rules, each with a runbook: drives or servers offline, an erasure set at its write quorum, drive errors, slow healing, capacity, server errors, failed sign-ins, KMS failures, scraping down. It also ships four Grafana dashboards. The console counts failed sign-ins (`buckets_console_logins_failed_total`) on `/metrics`.
- Local drive health, as MinIO tracks it. Every 15 seconds each server checks that each of its drives still has its own `format.json` and can be written and read. A drive that fails, hangs (a check over 30 seconds) or was emptied under its mount point goes offline: it no longer counts toward quorum, `mc admin info` and the drive metrics say so on every server, and calls to a failed or hung drive are refused at once instead of waiting on it. It comes back when it works again. `BUCKETS_DRIVE_CHECK_INTERVAL` and `BUCKETS_DRIVE_CHECK_TIMEOUT` tune it. Until now, a server reported its own drives online whatever state they were in.

### Changed
- `.github/workflows/lakehouse.yml` is now `.github/workflows/examples.yml`, and runs every example. The lakehouse example's shared parts moved to `examples/common`.

### Fixed
- `bucketsd` built with the undefined-behaviour sanitizer aborted on `/minio/metrics/v3/cluster/health` (and the other v3 paths that report tiering) when no storage tier was configured: the tiering statistics were copied from a null pointer. Release builds were not affected.

## [1.4.2] - 2026-10-06

### Added
- Images for linux/arm64 as well as linux/amd64. `.github/workflows/images.yml` builds each image natively on amd64 and arm64 runners and publishes both under each tag as one multi-arch image, signed as before. Images up to 1.4.0 are amd64 only.
- `examples/lakehouse` and [docs/integrations/lakehouse.md](docs/integrations/lakehouse.md): a lakehouse on Buckets. It has Iceberg tables in Buckets, Nessie as the catalog, Trino as the SQL engine, Apache Ranger for access policies, column masks, row filters and audit, and Keycloak as the one identity provider. `docker compose run --rm test` checks 12 claims, including that analysts can't read the warehouse's files around Ranger. `.github/workflows/lakehouse.yml` runs it against Buckets built from each change.

### Fixed
- `src/console/console.c` didn't build on macOS (`st_mtim` is Linux's name; macOS has `st_mtimespec`), so neither did the unit tests that link it.

## [1.4.1] - 2026-10-06

### Fixed
- The console's Configuration page no longer lists subnet and callhome, MinIO's own license and call-home services, which do nothing for Buckets. The server still accepts their settings, for MinIO's tools.

## [1.4.0] - 2026-10-06

### Added
- Access review (Identity → Access review, and **Access** on each bucket): who can reach a bucket at a level (read, write, delete, manage settings, any), through which users, groups, LDAP entities, OpenID roles, access keys and bucket-policy statements, with limits and conditions, exported as CSV; whether a given principal would be allowed an action, with the statements that decide it; and the local users left while a provider handles sign-in. Answers come from the servers' policy evaluator. See [identity.md](docs/identity.md#access-review).

## [1.3.0] - 2026-10-04

### Added
- Teams (Identity → Teams): a team is a name and its buckets, named or by prefix, and each access level (read, read and write, admin) becomes a `team-<name>-<level>` policy. The page shows the identity-provider step for each level, adds local and LDAP members, warns before replacing a policy edited by hand, and keeps teams as plain policies that survive a MinIO round trip. See [identity.md](docs/identity.md#teams).

### Fixed
- The Sign-in page's LDAP lookup always said no policy was attached to the user or their groups, even when one was: it read the servers' policy mappings under the wrong field names. It now lists the policies that apply.

## [1.2.2] - 2026-10-04

### Fixed
- The console's Configuration page listed policy_opa and region, deprecated subsystems the server keeps only for old settings and has no help for, so opening them showed "unknown sub-system policy_opa (XMinioConfigError)". The page now lists the subsystems the server documents, which also adds the ones it was missing (batch, heal, ilm, browser, identity_tls, identity_plugin, policy_plugin, lambda_webhook, etcd and others).

## [1.2.1] - 2026-10-04

### Fixed
- The Sign-in page's test sign-in failed in browsers with a provider on another site (Entra ID, Okta, a hosted Keycloak): coming back from the provider is a cross-site navigation, which leaves off the console's session cookie (SameSite=Strict), and the test said "Your console session ended during the test". The tokens now go back to the console from its own origin, sealed, and are checked there with the session.

## [1.2.0] - 2026-10-04

Sign-in set up from the console. Identity → Sign-in connects Microsoft Entra ID, Okta, Keycloak or another OpenID provider, and LDAP or Active Directory: it shows the steps to take in the provider, tests a sign-in (or an LDAP lookup) before anything changes, and applies through buckets-operator, which carries the settings to the servers and the console. Tested on the shared cluster against a real Keycloak and OpenLDAP.

### Added
- Sign-in set up from the console (Identity → Sign-in), where buckets-operator runs the cluster: Microsoft Entra ID, Okta, Keycloak or another OpenID provider, and LDAP or Active Directory.
  - **Guided:** the page lists the steps to take in the provider, with the console's redirect URI to copy, and fills in each provider's claim, scopes and discovery URL (or the directory's filters).
  - **Tested before it applies:** a test sign-in in a popup checks the ID token as the servers will and shows the roles and the policies they map to, without changing the session; an LDAP lookup shows a user's DN, groups and policies. Only settings that passed apply, and only the very settings tested.
  - **Applied by the operator:** settings live in Secret `<cluster>-identity`. The operator gives them to the servers through the admin API (OpenID at once; LDAP, read at startup, by restarting the servers one at a time), then to the console, which takes them up without a restart. `status.identity` reports the outcome. It refuses while `spec.env`, `spec.console.env` or `config.env` also set sign-in, naming them.
  - `src/iam/idpsettings.{c,h}`: the settings, their checks and their renderings; `tests/integration/identity.sh` and a Playwright test cover them.

### Added
- `docs/compatibility.md`: the compatibility promise. What every 1.x release keeps compatible, across releases and with MinIO (on-disk format, S3, admin and STS APIs, clients and SDKs, events, audit and trace, metrics, configuration, KES, the CRDs, rolling upgrades), the test that proves each, and what is not promised.

### Changed
- Roadmap: Phase 1's items are all done; its gate, the round trip in CI, waits for cluster access. Cluster throughput is measured; memory is not yet.

## [1.1.1] - 2026-10-04

Faster reads in distributed clusters. On a development Kubernetes cluster, 64 KiB GETs went from about 2,000 to 3,850 op/s (MinIO on the same volumes: 2,800) and 1 MiB GETs from 384 to 604 MiB/s (MinIO: 544); see `docs/performance.md`.

### Fixed
- Every read stat-ed the bucket on every drive of the pool, one drive after another, before looking up the object: in a distributed cluster, one internode round trip per remote drive on every GET and HEAD (7.6 round trips and 6.6 ms of a 12.7 ms 64 KiB GET). Reads now check the bucket only when the object is missing, to answer `NoSuchBucket` rather than `NoSuchKey`, and the check, which PUTs, deletes and multipart uploads still make, asks every drive at once.
- A read's distributed lock was released synchronously, so the request waited for the release to reach every node (2.5 ms per GET). Read locks are now released in the background, as MinIO does; write locks are still released before the request finishes.

### Added
- `tests/bench/cluster.sh`: MinIO and Buckets under the same load on a Kubernetes cluster, on the same volumes and nodes (MinIO, adopted by Buckets, rolled back to MinIO), with `tests/bench/s3bench` from a client pod.
- `.github/workflows/images.yml` also builds pushes to `perf/*` branches, so a change can be measured on a cluster before it reaches `main`.

### Changed
- README: install the operator from the published Helm chart (`oci://ghcr.io/storscale/charts/buckets-operator`) and run `bucketsd` from its published image; installing from a checkout is the alternative.
- Migration guide: install the operator from the published Helm chart; the adoption uses the published `bucketsd` image unless `--image` names a mirror.
- Roadmap: release artifacts (public signed images, a signed Helm chart, SBOMs) and the migration guide are done.

## [1.1.0] - 2026-10-04

### Changed
- The main repository is now https://github.com/StorScale/buckets. GitHub Actions (`.github/workflows/images.yml`) builds the four images into `ghcr.io/storscale` on every push to `main` and on tags, each with an SBOM and build provenance; release images are signed with cosign (keyless) and the operator's Helm chart is published to `oci://ghcr.io/storscale/charts`.
- The operator's default images, the CRDs' and Helm chart's defaults and the examples now name `ghcr.io/storscale/...` (were `ghcr.io/buckets-io/...`).
- Security reports go to GitHub's private vulnerability reporting.

### Added
- CI: `adopt-roundtrip` in the GitLab pipeline moves a MinIO tenant to Buckets and back on the shared cluster, without and with KES, on release tags and by hand on main.
- `buckets-kes identity of` takes a KES API key (`kes:v1:...`) as well as a certificate.
- `tests/integration/kes-diff.sh`: buckets-kes and a real MinIO KES answer the same 111 requests, are compared, and then serve each other's keystore (`KES_BIN`, `KMSREQ`, with `tests/integration/kmsreq` sending the requests with Go's TLS). `kes.sh` also runs MinIO and Buckets against buckets-kes (`BUCKETS_KES`) or a real KES (`KES_BIN`).

### Fixed
- buckets-kes refused request bodies sent without a length, which is how stock MinIO's KES client sends them, so MinIO could not generate data keys from it ("request body too large"). Bodies are now read however they arrive, up to the route's limit.
- buckets-kes now matches MinIO KES where it differed:
  - the error body layout;
  - 404s for unknown APIs;
  - the 1000000-byte body limit;
  - `os` on macOS;
  - import errors (no body, not JSON);
  - the identity list, which now includes the admin, is sorted, and matches by prefix;
  - `created_by` in identity descriptions;
  - `/v1/identity/self/describe` for identities without a policy (404 rather than 403);
  - new keys' cipher, which KES chooses by CPU.
- `/v1/identity/self/describe` answers non-admin identities in the shape KES's client decodes, so `kes identity info` works against buckets-kes. KES itself answers only its admin, because of a lookup bug.
- `tests/unit/test_object.c` built on Linux only (`mkdtemp` needs `<unistd.h>` on macOS).

## [1.0.0] - 2026-10-03

The first stable release. Buckets takes over existing MinIO deployments in place and hands them back: `scripts/adopt-minio.sh` adopts a tenant's drives with no data copy, KES and its keys included, and `scripts/rollback-to-minio.sh` returns them to MinIO, both tested end to end on Kubernetes. Buckets no longer depends on MinIO's images: it ships its own KES-compatible key server, `buckets-kes`. Encryption is set up from the console, and existing objects can be encrypted in place.

### Added
- Adoption carries a tenant's KES over (`scripts/adopt-minio.sh`). The keys stay in the tenant's key store.
  - **Settings:** the tenant's KES configuration, as it runs (its `${VAR}`s resolved from the KES pods' Secrets), becomes Secret `<tenant>-kms`. Vault, AWS, Azure and Google key stores carry over; the `fs` key store and Vault client certificates are refused.
  - **Spec:** `spec.kms.kes` names the tenant's default key with `createKey: false`, runs as the tenant's KES ServiceAccount (which a Vault Kubernetes role names) and keeps its node selector, tolerations and affinity. Its objects are named `<tenant>-buckets-kes`, so the tenant's own `<tenant>-kes` objects stay for a rollback.
  - **Pre-flight:** before MinIO stops, `buckets-kes check` reads the default key in a one-off pod with the tenant's own KES configuration; adoption stops if it can't. `--check-kes` runs it in a dry run too.
  - **config.env:** if it holds `MINIO_KMS_*` lines, Buckets reads a copy without them (Secret `<tenant>-buckets-config`); MinIO's stays as it was.
  - **Credentials** never reach the plan, the state directory or the output. Rollback removes the copies.
- Operator: `spec.kms.kes.createKey`, `name`, `serviceAccountName`, `nodeSelector`, `tolerations` and `affinity`. A new cluster with KES starts its storage servers only once KES serves the default key (phase `WaitingForKMS`).
- `buckets-kes check --config FILE --key NAME`: reads a key with a KES configuration, and exits non-zero if it can't.
- `buckets-kes` (`src/kes`, image `buckets-kes`): Buckets' own key server.
  - **Compatibility:** it speaks MinIO KES's API and reads its configuration file.
  - **Same storage:** it keeps keys as KES does, so either server reads the other's keys and ciphertexts.
  - **Key stores:**
    - HashiCorp Vault: KV v1/v2, Transit, AppRole or Kubernetes sign-in.
    - AWS Secrets Manager: static keys, environment, IRSA, EKS Pod Identity or IMDSv2.
    - Azure Key Vault: client secret, workload identity or managed identity.
    - Google Secret Manager: a service account key or the metadata server.
    - A directory, for tests.
  - **Operator:** runs it by default. MinIO's KES still works in its place.
- KMS setup in the console. Encryption → Set up the KMS chooses a key store, connects to it, names the default key, then tests and applies.
  - **Test:** a temporary key server (`<cluster>-kes-test`) signs in to the key store, makes sure the default key exists, and encrypts and decrypts with it. It also checks that every key in use is there. Each step is reported with the key store's own error.
  - **Apply:** saves the settings in Secret `<cluster>-kms` and sets `spec.kms.kes`. The operator then runs the key server and switches the storage servers over one at a time.
  - **Status:** `status.kms` reports it.
  - **Access:** the console runs as its own ServiceAccount, allowed only its cluster and the two KMS Secrets, and needs `admin:ConfigUpdate`.
- Encrypt existing objects. A keyrotate job with `encryption.includeUnencrypted` (or `onlyUnencrypted`) rewrites unencrypted versions encrypted, in place.
  - Each version keeps its ID, modification time, metadata, tags, object lock and checksum.
  - A version changed during the rewrite is left alone.
  - Bucket settings start the job ("Encrypt existing objects") and show its progress.
- The console's Encryption page: the KMS backend, default key and endpoints, and every key with a live check and the buckets using it. KES keys can be created there, and deleted after typing the key's name.
- `POST /minio/kms/v1/key/delete?key-id=` (`kms:DeleteKey`). It refuses the default key and keys a bucket encrypts with by default (409 `KMSKeyInUse`).
- Bucket settings pick the SSE-KMS key from the KMS's keys.
- Adopting a MinIO Operator tenant's volumes in place, and handing them back:
  - `scripts/adopt-minio.sh`;
  - `scripts/rollback-to-minio.sh`;
  - `tests/e2e-k8s/adopt-minio.sh`, which passes 29/29 on the shared cluster.

  It comes with the `BucketsCluster` fields `configuration`, `drives`, `securityContext`, `servicePort`, `volumes` and `volumeMounts`.
- `MINIO_CONFIG_ENV_FILE` (`BUCKETS_CONFIG_ENV_FILE`), as MinIO reads it.
- `BUCKETS_XL_META_VERSION=2` keeps drives readable by MinIO older than `RELEASE.2024-10-29`, which refuses xl.meta metaVersion 3. `tests/integration/minio-rollback.sh` checks it.
- `docs/encryption.md`, and `operator/examples/cluster-kms.yaml`.
- `spec.console.tls.certSecret`: the console serves HTTPS itself (`consoled --certs-dir`), so it can sit behind a LoadBalancer on 443 without an Ingress. Its probes switch to HTTPS, its Service port becomes `https-console`, and a console Ingress gets ingress-nginx's `backend-protocol: HTTPS` unless one is set.
- `spec.console.env`: extra environment for the console, after the operator's own, with `valueFrom` allowed. It carries the console's OpenID sign-in settings.
- The console's Users page lists people from the OpenID provider that Buckets knows of (signed in now, or holding access keys), read-only, with their name, sign-in name and roles. `ListAccessKeysOpenIDBulk` returns `displayName`, `email` and `policies` for them, a Buckets extension that MinIO clients ignore.
- `BUCKETS_CONSOLE_LOCAL_USERS`: whether the Users page offers Create user. Off by default while OpenID sign-in is on; `login-methods` reports it as `localUsers`.
- `docs/identity.md`: sign-in with Microsoft Entra ID and role-based access from Entra app roles, with `operator/examples/cluster-entra.yaml`.
- `docs/roadmap.md`: what comes next, and why.
- A GitLab pipeline (`.gitlab-ci.yml`) that builds the `bucketsd`, `buckets-operator`, `buckets-console` and `buckets-kes` images with Kaniko and pushes them to Harbor.
- `SECURITY.md`: how to report a vulnerability (a confidential GitLab issue) and which releases get fixes.

### Fixed
- bucketsd listed no keys from KES. It asked for every key with an empty name prefix, which Go's KES answers only through a redirect. It now asks for `*`, and a pattern's trailing `*` is taken off.
- Choosing SSE-KMS in bucket settings without a key ID always failed (the key ID is required). The KMS's default key is now named.
- The HTTP client refused responses without a `Content-Length`: bodyless ones such as Vault's 204, and ones that end when the connection closes.
- Under UBSan, bucketsd stopped at startup on a zero-length `memcpy` in replication's health check.
- The operator wrote CA files for TLS clusters to `/tmp` on a read-only root filesystem. It now gets an `emptyDir` there.
- Configure accepted a system OpenSSL older than 3.2, and the build then failed in `src/crypto/madmin.c` (Argon2id). It now requires 3.2 and builds the pinned release when the system's is older, as on Ubuntu 24.04 (3.0).
- The Users page flashed a loading spinner under the provider's users while it loaded the hidden local-users list.
- `tests/e2e-k8s/envtest.sh` failed in its rolling-update step when the operator deleted a pod between `kubectl apply`'s read and its patch; the test's stand-in for the StatefulSet controller now retries.
- OpenID sign-in returned to the login page with no error: response headers were formatted into a 1 KB buffer and cut, and a session cookie carrying an Entra ID session token is about 2 KB. Formatted headers are no longer truncated, and `tests/integration/console.sh` signs in with Entra-sized claims.
- The libssh download falls back to snapshot.debian.org (the identical tarball, checked against the same SHA-256) when www.libssh.org cannot be reached, as from some corporate networks.
- Test data committed by mistake with the batch jobs (`src/sb`, about 19 MB of random bytes) is gone.

### Changed
- The operator's RBAC adds:
  - patching `bucketsclusters`, which it grants to each console;
  - updating and deleting Secrets;
  - managing ServiceAccounts, Roles and RoleBindings;
  - reading pod logs.

  Its Kubernetes client moved into libbuckets (`src/k8s`), so the console uses it too.
- The console has a new logo (a bucket of data blocks, in `console/web/public` with the artwork in `docs/brand`) and a blue accent to match; dark mode uses a lighter blue with dark text on primary buttons.
- Streamed responses are sent by the worker that produces them, straight from the stream's own buffer when it offers one (`stream_view`/`stream_consume`; object GETs send from the verified shard buffers without a copy), until the socket is full, the response ends or 4 MiB have gone. They no longer cross three threads per 256 KiB. Under warp, 10 MiB GETs at 16 clients went from 8.5% behind MinIO to 3% behind, and 1 MiB GETs from 7% to 23% ahead.

## [0.10.0] - 2026-09-30

Phase 10: hardening. Against MinIO under warp (same machine and drives), every PUT and GET case is ahead except 10 MiB GETs at 16 clients (−8.5%), inside the 10% gate. Fuzzing ran all targets under libFuzzer with coverage. Also: a Helm chart for the operator.

### Added
- `tests/bench/warp.sh` and `tests/bench/s3bench`: warp-style concurrent PUT/GET benchmarks of bucketsd against MinIO on the same drives (`docs/performance.md`); with `WARP` set it drives MinIO's warp itself.
- A Helm chart for the operator (`operator/helm/buckets-operator`): CRDs, RBAC (a Role when `watchNamespace` is set, else a ClusterRole), the leader-election Role, and the Deployment; ctest checks that its CRDs match `operator/deploy/crds`.
- `BUCKETS_NET_THREADS`: the number of network event loops.
- `tests/fuzz/soak.sh`: every fuzz target under libFuzzer (ASan + UBSan) in a Linux container, with the library instrumented for coverage (`BUCKETS_FUZZ_INSTRUMENT`); corpora carry over between soaks.
- Fuzz targets for xl.meta (parse, serialize and object round trips), the msgpack reader (typed walk against skip) and S3 Select (SQL and input from the fuzzer).

### Changed
- Default images (`BucketsCluster` `spec.image`, the console, the operator manifest and examples) are 0.10.0.
- The HTTP server runs several event loops (CPUs / 2 by default) and deals connections across them; one loop saturated on large concurrent GETs.
- GET resolves an object's metadata once instead of twice (stat, then open).
- Drive directories are created leaf first, parents only when missing (MinIO's osMkdirAll): a PUT made 20 mkdir calls per drive, now 4.
- Writing an object's xl.meta no longer fsyncs its directory, which MinIO does not do either; format.json still does.
- Event loops write one wake per batch of posts instead of one per post, and the epoll backend skips interest changes that change nothing.
- The worker pool wakes only as many threads as a parallel batch has tasks, and each waiting caller has its own condition variable, instead of waking every idle worker and every waiter (lock contention under concurrent GETs).

### Fixed
- S3 Select: SQL with deeply nested parentheses took time and memory exponential in the depth (a few hundred bytes exhausted gigabytes); the parser now memoizes its expression rules. Found by fuzzing.
- S3 Select: expressions nested more than 127 levels deep overflowed a worker's stack; they now fail with ParseSelectFailure. Found by fuzzing.
- S3 Select on Parquet: a column chunk may claim at most 4096 values per byte and a page at most 256 MiB uncompressed, and a v2 page's level lengths must fit its uncompressed size, so a small file can no longer demand gigabytes. Found by fuzzing.
- S3 Select on Parquet: a repeated schema name or list field in the footer leaked, and list lengths are checked against the bytes left, so a small footer can no longer claim millions of row groups or columns; a footer map of booleans claiming 2^64 entries no longer spins forever. Found by fuzzing.
- The bucketsd image ships /data owned by its nonroot user, so `docker run` without a writable host directory no longer finds no drives.
- Linux builds failed to link since 0.9.0 (libm was not linked; macOS includes it), which broke the container images.
- libssh's one-time build failed where OpenSSL has no static libraries (Debian); it now builds against the very OpenSSL libraries Buckets links.
- Worker threads get 8 MiB stacks everywhere (macOS gave 512 KiB).
- A node waiting for its peers retried the cluster leader lock in a tight loop, logging tens of thousands of warnings a second; it now retries once a second.
- warp's result files, committed by mistake, are gone and ignored; `tests/bench/warp.sh` keeps them in its temp directory.
- Stray test drive files committed by mistake (a directory named after a space-separated endpoint list) are gone.
- A data race on the lazily read namespace lock timeout (found by ThreadSanitizer).
- A data race between startup and the resource metrics sampler, which polled the cluster description unsynchronized (found by ThreadSanitizer).
- A server stopped while it still waited for its LDAP directory at startup now exits, instead of retrying forever.

## [0.9.0] - 2026-09-30

### Added
- S3 Select (Phase 9): `SelectObjectContent` as MinIO answers it, request for request:
  - MinIO's SQL (its participle grammar, parsed by backtracking recursive descent taking the same alternatives), query analysis and errors, value inference, comparison and arithmetic, the string, date and conversion functions, and COUNT/SUM/AVG/MIN/MAX;
  - CSV input with every option (header use/ignore/none, field and multi-byte record delimiters, quote, quote escape, comments, lazy quotes) and output quoting; JSON DOCUMENT and LINES input as MinIO's jstream reads it (key order, float numbers, the 10 MiB document limit, its error messages); Parquet input (MINIO_API_SELECT_PARQUET) with every encoding and PLAIN/SNAPPY/GZIP/ZSTD/LZ4 pages, v1 and v2 data pages, converted by logical type as MinIO does;
  - GZIP, BZIP2, ZSTD, LZ4, S2 and SNAPPY input, scan ranges, and objects stored encrypted or compressed;
  - the event stream (Records batching, Cont keep-alives, Progress, Stats, End and error messages) byte for byte as MinIO frames it;
  - RestoreObject of type SELECT answers as MinIO's does (the output path, nothing written);
  - `tests/integration/select.sh` runs 393 cases against MinIO (MinIO's own test queries, every input format and compression, 120k-row inputs, Parquet generated with MinIO's own library, errors); `test_select` checks MinIO's exact event streams.
- Object lambda (`GET ?lambdaArn=arn:minio:s3-object-lambda::<id>:webhook`): the `lambda_webhook` target gets MinIO's event (a presigned URL signed as the caller, the output route and token, the user request and identity) and its answer is checked (route, token) and relayed with its forwarded status, headers and errors; `tests/integration/lambda.sh` runs a local lambda function against both servers.
- Streaming decompression (`src/compress/stream.c`: zlib, bzip2, zstd, LZ4 built from source) shared by S3 Select and snowball uploads.
- Snowball uploads (PutObjectExtract) of gzip, bzip2, zstd and LZ4 archives, as well as S2 and plain tar; `tests/integration/snowball.sh`.
- Files inside zip objects (`x-minio-extract: true`): GET and HEAD of `archive.zip/path/in/zip` and ListObjectsV2 under such a prefix, from MinIO's zipindex of the archive's central directory (zip64, stored/deflate/zstd entries, data descriptors, CRCs checked), kept in `x-minio-internal-archive-info` in all four of zipindex's forms and sealed for SSE-S3/KMS objects as MinIO seals it, so each server reads the other's; indexed at upload with the header too. Content types as Go's `mime` table and `net/http` sniffing give them. `tests/integration/zip.sh` compares with MinIO and swaps the servers' drives.
- `mc admin heal` (`POST /minio/admin/v3/heal/[bucket[/prefix]]`): heal sequences as MinIO's admin-heal-ops runs them -- the config prefix and the buckets newest first, one result item per bucket and object version with each drive's state before and after, dry runs, deep scans, pool/set filters, collected by client token (a sequence waits once 1000 items are uncollected), force start/stop, already-running and overlapping-path errors; in a cluster the token names the node running the sequence and other nodes forward status requests there.
- StorageInfo and BackgroundHealStatus, with MinIO's per-drive `apiCalls`/`lastMinute` metrics and the heal tracker of a drive being healed; ServerInfo returns drive metrics with `?metrics=true`.
- `mc admin top locks` and `mc admin unlock` in distributed setups: lock servers record who holds what (owner, quorum, source, time), and one node holds the cluster leader lock (`.minio.sys/leader.lock`) as MinIO's does.
- `mc admin cluster bucket export|import`: every bucket's configurations in a zip, each written as MinIO marshals it (bucket policies as Go's `json.Marshal` writes them, remote targets as `xml.Marshal` does, credentials and all), and imported in MinIO's order with its report (object lock first, then versioning, then the rest; replication and targets are not imported).
- `mc support inspect` (InspectData): the raw files matching a pattern (path.Match per element, `**` across them) on every drive, local or remote, with each drive's format.json, the command line and the start script, zipped; sent as madmin's estream (the zip under a key encrypted to the caller's RSA key with RSA-OAEP/SHA-512, cluster.info to SUBNET's key, sio-go STREAM sealing) or in the legacy keyed form. `tests/integration/inspectdec` opens both with mc's own libraries.
- Veeam Smart Object Storage API: the virtual `.system-d26a9498-cb7c-4a87-a44a-8ae204f5ba6c/system.xml` and `capacity.xml` objects in every bucket (capacity from the bucket's hard quota, else the usable capacity), and `_MINIO_VEEAM_FORCE_SC` for Veeam clients' storage classes.
- Realtime metrics (`mc admin scanner status`, `mc support top disk|net|rpc`, the console's monitoring): every type MinIO's MetricsHandler reports -- the scanner (cycle number, start and last 16 completions, counts, the path being scanned), drives (per-drive calls, last minute, healing/offline, Linux I/O counters), OS calls, batch jobs, network interface counters, memory, CPU times and load, and internode RPC traffic per peer -- collected on every node and merged as madmin's Merge methods do (by host, by drive, host and drive filters, `n` and `interval`).
- The drives' system calls are counted and timed (MinIO's osMetrics) and traced as `os.*` records (`mc admin trace --call os`).
- KES as the KMS (`MINIO_KMS_KES_ENDPOINT`, `_KEY_NAME`, `_API_KEY` or `_CERT_FILE`/`_KEY_FILE`/`_KEY_PASSWORD`, `_CAPATH`), as kms-go's client speaks to it: several endpoints (ellipses too) in turn, API keys turned into their Ed25519 client certificate, KES's errors mapped as MinIO maps them (kms:KeyNotFound, kms:NotAuthorized, kms:KeyGenerationFailed, ...), and the KMS APIs (status of every endpoint, version, apis, key create/list/status) answered from it; MinIO's configuration checks and messages. `tests/integration/kes.sh` shares one KES between MinIO and bucketsd (`tests/integration/fakekes`) and swaps their drives.
- With a KMS configured, config.json, its history and the IAM files are sealed with it as MinIO seals them (config.EncryptBytes: a KMS data key, then a sio-go stream), and read either way, so drives from a MinIO with a KMS keep their users and configuration.
- The SFTP server (`--sftp address=:8022,ssh-private-key=...`, over libssh, built once into `.deps` like OpenSSL): MinIO's options (algorithm lists checked against its names, `trusted-user-ca-key`, `disable-password-auth`) and logins -- IAM users and service accounts by password (`=svc`), LDAP users by password or by their `sshPublicKey` attribute (`=ldap`), and OpenSSH user certificates signed by the trusted CA, checked as x/crypto's CertChecker does (principals, validity, critical options, the CA's Ed25519/ECDSA/RSA signature) -- and pkg/sftp's request server over the same file system as FTP: READDIR pages of 100 with its long names, ranged reads, out-of-order writes reassembled as MinIO's writerAt does, uploads streamed as minio-go's unknown-length multipart, pkg/sftp's status codes and messages, and FTP-type trace records. `tests/integration/sftp.sh` compares every request with MinIO through `tests/integration/sftpclient` (x/crypto/ssh and pkg/sftp).
- The FTP server (`--ftp address=:8021`, `passive-port-range`, `tls-private-key`/`tls-public-cert` for explicit FTPS): goftp's commands and replies word for word (LIST/NLST/MLSD, RETR with REST, STOR/APPE, MKD/RMD/DELE, SIZE/MDTM/STAT, passive and active data connections, TLS data connections), buckets as directories, every operation an S3 request to this server with the user's own credentials as MinIO's driver makes it (minio-go's argument checks and error messages, its unknown-length multipart uploads with a full-object CRC32C), LDAP users and service accounts included, and `os`-style FTP trace records; `tests/integration/ftp.sh` runs the same sessions against MinIO.
- `mc admin speedtest` / `mc support perf object|drive`: MinIO's object speedtest on every node (autotuning concurrency while GET throughput grows, S3 frozen meanwhile, the perf bucket and objects cleaned up) and dperf's drive test, streamed as madmin results with MinIO's keepalives; peers stream whitespace while they run so internode calls outlive their read timeout.
- The network speedtests: client perf (`/speedtest/client/devnull` and its extra time), node netperf across a cluster (every node streams to every other's internode devnull; TX/RX per second), and site-replication perf between MinIO and Buckets sites (MinIO's unsigned `/site-replication/devnull` and `/netperf`, the latter answering in gob). Chunked request bodies to the devnull endpoints are streamed rather than spooled, on a worker pool of their own.
- Profiling (`mc admin profile`, StartProfiling/DownloadProfiling/Profile) across the cluster with MinIO's profile types and zip layout: CPU profiles sampled with SIGPROF at 100 Hz and written in pprof's format (read by `go tool pprof`, symbolized against the binary), the heap in use, threads, and empty block/mutex profiles.
- `mc support diag` (HealthInfo): madmin.HealthInfo streamed after each section as MinIO does -- every node's CPUs, partitions, network interface, OS, memory, process, system errors, services and system configuration (from /proc and /sys on Linux; MinIO's own errors elsewhere), the redacted server configuration, and the server info with drive metrics.
- The bucket filter of `list-users` (ListBucketUsers) and `list-canned-policies` (ListBucketPolicies): policies whose resources match the bucket (Policy.MatchResource), and the users they reach.
- `tests/integration/adminops.sh` (single node) and `adminops-dist.sh` (4 nodes) compare these admin APIs with MinIO.

### Changed
- ServerInfo matches MinIO's: object, version and delete-marker counts and usage from the scanner's data usage, `kms`/`kmsStatus`/`ldap`/`logger`/`audit` services, `go_max_procs`, `runtime_version` and the (redacted) MINIO/BUCKETS environment, the backend's fields in MinIO's order, no `scheme`, an empty `edition`.
- Unknown admin API routes, and known routes with another method, answer 426 XMinioAdminVersionMismatch as MinIO does.

### Fixed
- Listings under a prefix naming an object (`key/`) no longer show the object's data directory as a common prefix.
- HEAD errors carry MinIO's `X-Minio-Error-Code` and `X-Minio-Error-Desc` headers and no Content-Type (minio-go reads the error from them).
- ListBuckets answers AccessDenied when the caller may list none of the buckets, as MinIO does.
- CompleteMultipartUpload leaves empty parts out of a full-object checksum (MinIO's AddPart), so one of empty parts only matches no client checksum.
- 204 and 304 responses carry no Content-Length, as Go's net/http sends them.
- GET bucket versioning, object lock configuration and notification configuration carry no XML declaration, as MinIO writes them.
- ListObjects (V1 and V2) elements are in MinIO's order (NextContinuationToken before KeyCount, NextMarker after Marker, EncodingType last).
- JSON strings with invalid UTF-8 carry the replacement character itself, as Go's encoding/json writes it, not the `\ufffd` escape (event records too).

## [0.8.0] - 2026-09-29

Phase 8: bucket and site replication, tiering, batch jobs, decommission and rebalance, all interoperable with MinIO, with the two-cluster/three-site gate run on kind.

### Added
- Bucket replication (Phase 8), interoperable with MinIO in both directions:
  - remote targets (`mc admin bucket remote add|ls|rm`, `set-remote-target` and friends), stored in the bucket metadata as MinIO does (SSE-S3-sealed when a KMS is configured), with health checks of each endpoint;
  - `PutBucketReplication` / `GetBucketReplication` / `DeleteBucketReplication` with MinIO's parsing, validation and marshalling;
  - replication of new versions (single-part and multipart, keeping version IDs, modification times and ETags), metadata changes (tags, retention, legal hold, as in-place metadata copies), delete markers and versioned deletes, recording per-target status in `xl.meta` as MinIO does;
  - the receiving side: `X-Minio-Source-*` requests keep the source's version ID, mtime and ETag, replicas are marked `REPLICA`, replicated delete markers are created by version ID, and metadata-only copies update the version in place;
  - active-active proxying of GET/HEAD to a target when a version is missing locally;
  - an outbound S3 client (`src/net/s3client.c`) for replication and, later, tiering and batch jobs;
  - existing-object replication: `mc replicate resync` (`?replication-reset`, its status in `.replication/resync.bin`) and the scanner's replication healing of pending, failed and never-replicated versions;
  - replication statistics: `GetBucketReplicationMetrics(V2)` (`mc replicate status`) and the v2/v3 replication metrics, per target and per node (metric-name diff against MinIO with replication active: 0);
  - `mc replicate diff` (`/replication/diff`), the MRF backlog (`/replication/mrf`) and `?replication-check` credential validation;
  - failed replications wait in the MRF queue, saved at shutdown (MinIO's `mrf/<node>.bin`) and re-checked after restart; per-target bandwidth limits;
  - SSE-C objects replicate as stored (single-part and multipart), over TLS; `tests/integration/replication.sh` covers every MinIO/Buckets pairing.
- Site replication (Phase 8), wire compatible with MinIO, so MinIO and Buckets sites can share a group:
  - `mc admin replicate add|info|status|edit|rm|resync` and the peer API (`/site-replication/peer/join`, `bucket-ops`, `iam-item`, `bucket-meta`, `idp-settings`, `edit`, `remove`, `state/edit`, `metainfo`), with the state in `.minio.sys/config/site-replication/state.json` and the shared `site-replicator-0` service account, as MinIO keeps them;
  - joining validates the sites as MinIO does (deployment IDs, existing members, one site with data, matching LDAP/OpenID settings) and then syncs buckets, bucket metadata, policies, users, groups, service accounts and policy mappings to the new sites;
  - hooks push local changes to every peer: bucket creation (versioned, with `site-repl-<deployment>` replication rules and targets between every pair) and deletion (kept as MinIO's `.minio.sys/buckets/.deleted/<bucket>` marker until the sites agree), bucket policy, tags, object lock, encryption, versioning and quota, IAM users, groups, policies, mappings (built-in and LDAP), service accounts and STS credentials;
  - STS session tokens are signed with the site replicator's secret while replication is on (MinIO's getTokenSigningKey), so temporary credentials from any site work on all of them;
  - a periodic heal (on the cluster leader; `BUCKETS_SITE_REPLICATION_HEAL_INTERVAL`, default 30s) compares every site's `metainfo` and pushes the newest version of what differs: buckets, bucket metadata, replication rules, policies, users, groups and mappings;
  - versioning cannot be suspended, replication rules edited by non-root users, or remote targets added, while a site is in a group, as with MinIO;
  - `DeleteBucket` honours `X-Minio-Force-Delete`;
  - `tests/integration/siterepl.sh` runs mixed three-site groups set up from a MinIO site and from a Buckets site (changes from every site, a site catching up after downtime, `replicate status` from each), and a MinIO→Buckets handover (a Buckets site joins a MinIO group, is resynced, and the MinIO sites leave).

- Tiering (Phase 8), compatible with MinIO's on-disk and wire formats:
  - remote tiers: `mc admin tier add|ls|edit|rm|check` with MinIO's validation (probe object put, read and removed; bucket, credential and in-use checks), stored in `.minio.sys/config/tier-config.bin` (msgp, SSE-S3-sealed when a KMS is configured), reloaded across nodes; S3 and MinIO warm backends, Azure Blob (shared key or service principal; block uploads above 256 MiB) and Google Cloud Storage (service-account or refresh-token credentials; `STORAGE_EMULATOR_HOST`), over their REST APIs;
  - lifecycle transitions and noncurrent-version transitions, by the scanner and right after writes (`enqueueTransitionImmediate`), through a pool of transition workers; the stored bytes move as they are (encrypted and compressed data stay so) under MinIO's remote names, and the version keeps its metadata (`x-minio-internal-transition-*`);
  - reads of transitioned versions (ranges included) from the tier; the tier is the storage class in HEAD/GET and listings;
  - `PostRestoreObject`: the bytes come back to the drives in their original part layout, with `x-amz-restore` (`202` for a repeated restore, `RestoreAlreadyInProgress`, MinIO's validation errors); restored copies expire (`DeleteRestored`);
  - free versions: a deleted or overwritten transitioned version leaves a free version that the scanner sweeps (remote copy first); expiry removes remote copies directly; overwriting or deleting a transitioned version in an unversioned or suspended bucket, or deleting one by version ID, removes its remote copy right away (MinIO's objSweeper); free versions are hidden from reads, listings and version counts, and heal treats transitioned versions as metadata only;
  - `mc admin tier info` (`/tier-stats`): the scanner keeps MinIO's per-tier usage (`tierStats` in `.usage.json`: remote tiers, `STANDARD` and `REDUCED_REDUNDANCY`), merged with every node's hourly transitions of the last day; the tier metrics (`minio_cluster_ilm_transitioned_*`, `minio_node_tier_requests_*`, `minio_node_tier_ttlb_seconds_distribution`) and live transition queue gauges (v2 and v3);
  - MinIO reads what bucketsd transitioned and restored, and bucketsd reads (and deletes, and restores) what MinIO transitioned; `tests/integration/tier.sh` (with Azurite and fake-gcs-server when `AZURITE_BIN` / `FAKE_GCS_BIN` are set).

- Batch jobs (Phase 8), compatible with MinIO's API and files:
  - `mc batch start|list|describe|status|cancel` (`/start-job`, `/list-jobs`, `/status-job`, `/describe-job`, `/cancel-job`): job definitions parsed as yaml.v3 does (libyaml; the same unmarshal and syntax errors), MinIO's validation and error responses, and `describe`'s YAML byte for byte; jobs in `.minio.sys/batch-jobs/<id>` and reports in `batch-jobs/reports/<id>/`, in MinIO's msgp, so either server lists, describes, reports and resumes the other's jobs;
  - replicate: pushes to a remote MinIO/Buckets/S3 target and pulls from a remote source, keeping version IDs, modification times, ETags, delete markers, metadata and tags, multipart layouts included; filters, retries and notifications as MinIO has them;
  - keyrotate: SSE-S3 and SSE-KMS object keys re-sealed under new KMS data keys, in place;
  - expire: rules by type, name, age, creation date, tags, metadata and size, with `purge.retainVersions`;
  - the realtime metrics stream (`/metrics`) for batch jobs, which `mc batch status` follows; `minio_bucket_batch_*` metrics; batch trace records; the `batch` config's per-object waits; jobs resumed after a restart; finished jobs cleaned up after three days;
  - `PutObjectExtract`: snowball archives (tar, plain or S2) are unpacked into objects, as MinIO's batch replication and `mc` send them;
  - `tests/integration/batch.sh` runs every scenario on MinIO and bucketsd and compares them, replicate in every MinIO/Buckets pairing both ways.

- Pool decommission and rebalance (Phase 8), compatible with MinIO's API and files:
  - `mc admin decommission start|status|cancel` (`/pools/list`, `/pools/status`, `/pools/decommission`, `/pools/cancel`) and `mc admin rebalance start|status|stop`, with MinIO's checks and errors; pools are named by their command-line argument as MinIO names them;
  - a decommission moves every version of every object (and the configuration under `.minio.sys`) out of the pool, oldest first, keeping version IDs, times, ETags, metadata, delete markers and part layouts; lifecycle-expired versions and lone delete markers are left behind as MinIO leaves them; the pool is then checked, and marked complete or failed; new objects stay off it from the start;
  - a rebalance moves objects out of pools fuller than the cluster's free-space goal, until they are within 5% of it;
  - progress in MinIO's `.minio.sys/pool.bin` (every pool) and `.minio.sys/rebalance.bin`, so either server reports and resumes what the other started; a decommission resumes after a restart (after three minutes, as in MinIO), a rebalance at once; operations are forwarded to the node that runs them;
  - decommission and rebalance trace records and audit events;
  - `tests/integration/decom.sh`: decommissions by each server read back by the other, errors as MinIO answers them, cancel and restart, and rebalances between pools on disk images.

- Kubernetes end to end on kind, run for the first time (kind 0.33, Kubernetes 1.37, in a Lima VM):
  - `tests/e2e-k8s/kind.sh` (17 checks): a 4-server cluster through pod loss, PVC replacement and healing, pool expansion and an image rollout, then the console Deployment and its Playwright suite against the cluster;
  - `tests/e2e-k8s/multisite.sh` (48 checks): two operator-run Buckets clusters and a MinIO site in separate namespaces, reached by Service DNS: active-active bucket replication between Buckets and MinIO, a three-site group (Buckets, MinIO, Buckets) with changes from every site, and a multi-server decommission started and followed through servers that forward it to the pool's owner;
  - a shared `tests/e2e-k8s/lib.sh` and a client image (`tests/e2e-k8s/tools`, with curl, jq and optionally mc and MinIO), so tests reach clusters through their Services from inside the cluster instead of a port-forward that dies with its pod; `KIND_E2E=1 scripts/ci.sh` runs both.
- `BucketsCluster` `spec.console.s3URL`: the S3 endpoint as browsers reach it, passed to the console as `BUCKETS_CONSOLE_S3_URL`, so an operator-run console offers share links.

### Changed
- The container images build on Debian trixie and run on distroless `cc-debian13`. Bookworm's OpenSSL 3.0 has no Argon2id, which the admin API's encrypted payloads (madmin) need.

### Fixed
- Completing an SSE-S3 multipart upload compared part ETags using the wrong state (the completion hook's user data), so uploads with small parts, such as `mc pipe --enc-s3`, could fail with `InvalidPart`.
- Objects whose drives' erasure indexes no longer follow their distribution (MinIO's metadata-only rewrites, such as its key rotation, renumber them) are read by the distribution, as MinIO reads them.
- `ListBuckets` gives bucket creation times with milliseconds, as MinIO does.
- `GET` of a `null` delete marker in a versioning-suspended bucket carries `x-amz-version-id: null` and `x-amz-delete-marker: true`, as MinIO's does.
- Peers' last-day tier statistics lost their update times when merged.
- `GetBucketLifecycle`'s `X-Minio-LifecycleConfig-UpdatedAt` is in MinIO's `20060102T150405Z` form (mc failed to parse it when adding a second rule).
- Resync of replication targets without a reset time no longer overflows computing the reset boundary.
- libyaml builds with GCC 14, which makes implicit declarations errors (`strdup` under `-std=c17`), so the images build again.

## [0.7.0] - 2026-09-29

Phase 7: notifications (all ten targets), audit (webhook, Kafka, internal events), metrics v2/v3 (metric-name diff vs MinIO: 0), trace and logs.

### Added
- Bucket notifications (Phase 7):
  - `?notification` GET and PUT with MinIO's validation and error order (unknown ARNs, regions, event names, filter rules, overlapping queues, topics and lambdas), stored in the bucket metadata as MinIO stores it; queues whose target is gone are left out when read back.
  - Events from every handler MinIO sends them from: Put, Post, Copy, CompleteMultipartUpload, Get, Head, GetObjectAttributes, tagging put and delete, retention and legal hold put and get, Delete, DeleteMarkerCreated, NoOP deletes, DeleteObjects, BucketCreated and BucketRemoved. Records match MinIO's byte for byte (field order, Go's JSON escaping, the escaped key for targets, userMetadata as cleanMetadata leaves it, content-length only where MinIO's handler had written the response).
  - The webhook target (`notify_webhook`: endpoint, auth_token, queue_dir, queue_limit, client_cert/client_key), with a worker per target and MinIO's queue store: `<queue_dir>/minio-webhook-<id>/<uuid>.event` files kept until delivered, retried every 3s, replayed after restarts; stores are interchangeable with MinIO's in both directions (batched and S2-compressed entries are read too). Targets are rebuilt when a `notify_*` subsystem changes, and `config set` validates them.
  - ListenNotification and ListenBucketNotification (`GET /?events=` and `GET /bucket?events=`, with prefix, suffix and ping), streamed as chunked `text/event-stream`: the HTTP server now sends chunked responses for streams of unknown length. Across a cluster a listener also gets every peer's events, as MinIO's peer.Listen does (`peer/listen` over internode with the same filter, relayed per peer).
  - Lifecycle expiry events from the scanner (Delete, DeleteMarkerCreated, DeleteAllVersions, ILMDelMarkerExpirationDelete), sent as MinIO sends internal events: no request parameters (`null`), this node as the source host, `Internal: [ILM-Expiry]` as the user agent.
  - `mc admin info` lists the targets' ARNs (`sqsARN`) and their status under `services.notifications`, checked live as MinIO's IsActive does (a HEAD for webhooks).
  - `x-minio-origin-endpoint` from `MINIO_SERVER_URL` (or `BUCKETS_SERVER_URL`), else the listen address, else the local IPv4 address MinIO would pick.
  - `tests/integration/notify-interop.sh` diffs MinIO and bucketsd (S3 transcript, webhook deliveries, both kinds of listener); `tests/integration/notify-store.sh` hands queue stores between them.

- Prometheus metrics v2 and v3 (Phase 7), wire compatible with MinIO:
  - `/minio/v2/metrics/{cluster,node,bucket,resource}` and `/minio/metrics/v3` with every collector path (and `/bucket/api/<bucket>`, `/bucket/replication/<bucket>`), with MinIO's metric groups, their conditions, labels and quirks: v2 keeps zero values and writes histograms as gauge buckets with `le="%.3f"`; v3 drops values that are not positive and names APIs as the handlers are named. Output is written as client_golang writes it (families by name, samples by label values, Go's shortest float format).
  - The names, types and help come from a catalog generated from MinIO's own metric definitions (`tools/metrics-catalog`, which dumps them through a compile overlay of MinIO's `cmd` package; `src/metrics/minio-catalog.tsv`, plus the Go/process collectors and the resource endpoint in `extra-catalog.tsv`); a sample outside it is dropped and logged. 425 of the catalog's 500 families can be emitted today; the rest belong to replication, batch jobs and object lambda (later phases).
  - In a cluster, the v2 cluster endpoint merges every node's per-node groups (over a new `peer/metrics` internode call), as MinIO does.
  - Authentication as MinIO's: `MINIO_PROMETHEUS_AUTH_TYPE=public`, or a bearer JWT issued by `prometheus` and signed with its key owner's secret, whose owner may `admin:Prometheus` (tokens from `mc admin prometheus generate` work).
  - New statistics behind them: requests per API (MinIO's route names, found by mirroring its router), time to first byte, traffic, rejections, per bucket too; per-drive call latency over the last minute, errors and calls in flight; scanner lifetime counts; IAM load statistics; internode traffic and dial times; dsync lock counts; healing activity; identity plugin calls per minute; host CPU, memory, drive I/O and network sampling for the resource endpoint.
  - `tests/integration/metrics-names.sh`, the phase gate: the same deployment and workload on MinIO and bucketsd, then every endpoint's families, label names and help must match: 0 differences on 11 endpoints, single node, a 4-node cluster (with a node stopped and healed) and with an identity plugin. `tests/integration/metrics-auth.sh` compares the authentication outcomes (32 probes).

- Audit logging and server log targets (Phase 7):
  - `audit_webhook` and `logger_webhook` targets as MinIO's logger HTTP target: batches of `batch_size` entries as newline-terminated JSON with MinIO's headers (the auth token as is, `x-minio-webhook-payload-count`, version and deployment), retried every `retry_interval` (`max_retry`, 0: forever), `http_timeout`, `queue_size`, and with `queue_dir` MinIO's compressed queue store (`<queue_dir>/minio-http-<name>/[<n>:]<uuid>.http.log.snappy`); validation as MinIO's (`config set` refuses bad values with its messages).
  - An audit entry per S3 request, as madmin-go's `audit.Entry`: API name, bucket and object as MinIO reports them (the copy source for CopyObject, the last object for DeleteObjects, with their `objects`), status, byte counts, header bytes, timings, request and response headers (the object's tags in the request's `X-Amz-Tagging`, as MinIO sets it), query, claims of session tokens, access key and parent user, and tags: the object layer's operations with where the object lives (`name=…,pool=…,set=…`) and the retention settings. `tests/integration/audit-interop.sh` diffs MinIO's and bucketsd's entries for 29 requests (0 differences; tags are compared by key, since they follow each server's internal calls) and the targets' metrics.
  - Warnings and errors go to the logger webhooks as MinIO's `log.Entry`.
  - The targets show in the metrics (`minio_audit_*` as `sys_http_<n>`/`audit_http_<n>`, `minio_cluster_webhook_*` and `minio_logger_webhook_*` by name and endpoint), next to the console target.

- `mc admin trace` and `mc admin logs` (Phase 7):
  - `GET /minio/admin/v3/trace` with MinIO's options (types, `err`, `threshold`, the deprecated `all`) and `admin:ServerTrace`: madmin.TraceInfo records as JSON lines, a space each idle second. HTTP records as MinIO's tracer writes them (function `s3.<API>`/`admin.<Handler>`, request and response headers, bodies or `<BLOB>` for header-only handlers, timings and byte counts, the path as Go reports it); `tests/integration/trace-interop.sh` finds them identical to MinIO's for 29 requests. Storage records (`storage.<Op>`, the drive and paths, errors) from every drive call.
  - `GET /minio/admin/v3/log` (`node`, `limit`, `logType`, `admin:ConsoleLog`): the last records of a 10000-entry ring, then new ones, as log.Info JSON (warnings and errors as entries, other messages as console messages).
  - Across a cluster both merge every node's records, as MinIO's handlers do: each node streams its own over internode (`peer/trace` with the same options, `peer/log` with the log mask; peers send their whole ring, as MinIO's do), read by one relay thread per peer that reconnects while the peer is down. `node` limits logs to one node. `tests/integration/cluster.sh` checks both.
  - Scanner, healing and ILM records, as MinIO writes them:
    - `scanner.ScanCycle` (the cycle number) for each cycle.
    - For each bucket walked: `scanner.ScanObject` (drive and `<bucket>/<key>/xl.meta`, `metasize`, `size`, `versions`), `scanner.CompactFolder` (MinIO's compaction rule: under 500 objects, or only single-object children) and `scanner.ScanFolder` (`new`/`existing`) for every folder level, children before parents, then `scanner.ScanBucketDrive`. The walk is over listings, so the drive is the first online one of the key's set.
    - `heal.Object` with the madmin.HealResultItem (drive states before and after, data and parity blocks, the scan mode and options) for every version healed by MRF, drive healing or reads. The scanner's own checks report only versions that needed healing, since ours checks every object each cycle where MinIO's checks about one in 1024.
    - `ilm:expiry` with the lcAuditEvent tags and MinIO's source-location message.
    - `tests/integration/trace-interop.sh` compares the record shapes with MinIO's for a scanner walk, a heal on read and two expiries.
  - Admin routes carry MinIO's handler names (the trace's function names).
  - Streams of unknown length (listen, trace, logs) end when the server shuts down instead of holding the drain.

- Notification targets `notify_redis`, `notify_nsq`, `notify_nats`, `notify_mqtt`, `notify_elasticsearch`, `notify_postgres`, `notify_mysql`, `notify_amqp` and `notify_kafka`, and the `audit_kafka` log target (Phase 7) — all ten notification targets:
  - Redis: namespace format (HSET `<bucket>/<object>` with `{"Records":[event]}`, HDEL for `s3:ObjectRemoved:Delete`) and access format (RPUSH `[{"Event":[event],"EventTime":…}]`), AUTH with or without a user, the key's type checked on first use. The connection pool behaves as MinIO's redigo pool does, including the PING before an idle connection is reused, so the command stream is the same as MinIO's.
  - NSQ: go-nsq's producer protocol (the V2 magic, IDENTIFY with feature negotiation, a TLS upgrade when `tls=on` and nsqd agrees, NOP pings, PUB of the event.Log JSON), with server heartbeats answered while idle.
  - NATS: nats.go's connection (INFO, TLS when `tls=on` or the server requires it, or first with `tls_handshake_first`; `cert_authority`, `client_cert`/`client_key`), CONNECT with user/password, token, an NKey seed file or a `.creds` file signing the server's nonce (ed25519), PING/PONG both ways and reconnects every 2s; PUB of the event.Log JSON, or with `jetstream=on` a JetStream publish on the connection's `_INBOX` that waits for the PubAck (retrying no-responders twice). As in MinIO, `nkey_seed`, `user_credentials` and `tls_handshake_first` come from the environment only, and `tls_skip_verify` does not turn verification off. NATS Streaming (end-of-life upstream) is not supported. Checked against nats-server 2.11 too (TLS, JetStream).
  - MQTT: paho's client (MQTT 3.1.1, falling back to 3.1 when refused; a clean session with a time-based client ID; username/password; QoS 0, 1 with PUBACK, 2 with PUBREC/PUBREL/PUBCOMP; PINGREQ on the keep-alive; reconnects with a doubling backoff up to `reconnect_interval`; DISCONNECT when the server stops) over tcp://, ssl://, tls://, tcps://, ws:// and wss:// brokers (WebSocket with the "mqtt" subprotocol). The broker URL is checked as MinIO's xnet.ParseURL does (a port is required).
  - Elasticsearch: go-elasticsearch v7's requests (the product check, the version from `GET /` — 7 or later —, index resolution and creation, `PUT /<index>/_doc/<id>` with MinIO's HighwayHash-256 document IDs and HEAD+DELETE removals in namespace format, `POST /<index>/_doc` in access format), Basic auth, retries on 502/503/504 and connection failures.
  - PostgreSQL: the table created when `SELECT 1 FROM` it fails, prepared upserts and deletes (namespace) or inserts (access) with the event time as lib/pq formats it, a ping before every delivery; a v3 protocol client that behaves as lib/pq does (key=value and URL connection strings over lib/pq's defaults and the PG* environment, SSLRequest per `sslmode` with `require` the default, cleartext/md5/SCRAM-SHA-256, non-driver settings sent as startup parameters, statements named "1", "2", ...). As in MinIO only `connection_string` is read. Checked against PostgreSQL 17: the statement log, the rows and the error messages match MinIO's.
  - MySQL: MinIO's tables (namespace keyed on SHA2(key_name) with ON DUPLICATE KEY UPDATE, access with DATETIME event times), server-side prepared statements, COM_PING before every delivery; a client that behaves as go-sql-driver 1.9 does (its DSN, unknown parameters set as session variables, `tls=true/skip-verify/preferred`, collation utf8mb4_general_ci and connection attributes, mysql_native_password, caching_sha2_password with full authentication over TLS or with the server's RSA key, sha256_password, cleartext when allowed). Checked against MySQL 8.4: the general log, the rows and the error messages match MinIO's.
  - AMQP 0-9-1: amqp091-go's connection (PLAIN or AMQPLAIN, Tune with a 10s heartbeat, heartbeats while idle, `amqps://` over TLS) and per-event channel (numbers from its rotating allocator; Confirm.Select with `publisher_confirms`, which as in MinIO is read from `MINIO_NOTIFY_AMQP_PUBLISHING_CONFIRMS`; Exchange.Declare with the durable/auto-delete/internal/no-wait flags; Basic.Publish with the mandatory/immediate flags, content type, delivery mode and the minio-bucket/minio-event headers; the ack or nack awaited; the channel closed). URLs are checked as amqp091.ParseURI does.
  - Kafka: a producer that behaves as sarama's SyncProducer does with MinIO's settings (net/kafka.c): metadata of all topics first (refreshed every 15 minutes, a topic's own when unknown), Produce of record batches (magic 2, CRC32C; gzip — at MinIO's default level 0 —, snappy, lz4 or zstd) keyed by "bucket/object" to the leader of the FNV-1a hash partition, acks 1, two retries; protocol versions from the configured Kafka version (Metadata v4–v10, Produce v3–v7, ApiVersions v3 from 2.4; before 0.11 is refused); SASL PLAIN and SCRAM-SHA-256/512 (handshake v1, SaslAuthenticate); TLS with client certificates. With `queue_dir`, `batch_size` gathers events as MinIO's store.Batch does (committed when full or every `batch_commit_timeout`, 30s by default) into one `<n>:<uuid>.event.snappy` entry, sent in one request. `lz4` and `zstd` produce valid frames of stored blocks (no size reduction yet). Checked against franz-go's kfake broker (the test's logger decompresses every codec with Go's decoders), including SASL and Kafka 1.1/2.1/3.6 request versions.
  - `audit_kafka`: audit entries as unkeyed messages (sarama's random partition) with MinIO's 10s timeouts and backoff, queued in memory (`queue_size`) or in MinIO's store (`<queue_dir>/minio-kafka-audit/<uuid>.kafka.log`), replayed with sorted keys as MinIO's re-encoding sends them; config set connects to validate, as MinIO does.
  - All take `queue_dir`/`queue_limit` (MinIO's queue store, sent as SendFromStore does) and validate their settings with MinIO's messages. Addresses are parsed as minio/pkg's `net.ParseHost` does, errors included.
  - `mc admin config set` of a notification target now checks that the targets it names are reachable, as MinIO's TestSubSysNotificationTargets does (`error (<name>:<type>): dial tcp …: connect: connection refused`); webhooks included.
  - `tests/integration/notify-targets.sh` diffs the commands MinIO and bucketsd send to logging Redis, nsqd, NATS, MQTT, Elasticsearch and AMQP stand-ins (Redis formats and AUTH, heartbeats, JetStream, NKey and credentials signatures, every MQTT QoS, WebSocket brokers, keep-alives, queue stores) and their config set messages.
  - Notification subsystems check their settings as MinIO's do: only the stored keys of targets explicitly enabled, not environment variables.
- Admin API calls are audited as MinIO's adminMiddleware audits them (the handler's name, no bucket or object).
- Audit entries for what the server does on its own (MinIO's auditLogInternal): `HealObject` for each healed version (tagged `healObject: name=…,pool=…,set=…`, with MinIO's "unable to heal N missing/corrupted blocks" errors) and `ILMExpiry` for each lifecycle expiry (trigger and event `ilm:expiry`, lcAuditEvent tags). trace-interop finds them identical to MinIO's.

- Console: Monitoring pages for live trace (types, errors only, threshold; each call's full record), server logs (by kind and node) and bucket events (bucket, prefix, suffix, event kinds), read as the streams come; consoled relays chunked replies as they arrive instead of buffering them. The Configuration page covers every notification target and `audit_kafka`. `tests/integration/console.sh` and the Playwright suite check all three streams.

### Changed
- Duration settings report time.ParseDuration's errors (`missing unit`, `unknown unit`).
- Notification and log targets are closed when the server stops.
- The TLS client can present a client certificate and trust extra CA files (used by the NATS target).
- Failed outbound HTTP connections are reported as Go reports them (`dial tcp HOST:PORT: connect: connection refused`, `i/o timeout`, `lookup HOST: no such host`).
- Drive paths are cleaned as MinIO's endpoints are (`filepath.Clean`: repeated and trailing slashes, `.` and `..`), for local paths and URLs alike, so they read the same in traces, metrics and admin info.
- Response headers MinIO writes in lowercase (`x-amz-version-id`, `x-amz-delete-marker`, `x-amz-mp-parts-count`, `x-amz-copy-source-version-id`) are written that way, `Vary` comes as separate headers as MinIO sends it, and S3 responses carry MinIO's `X-Ratelimit-Limit` and `X-Ratelimit-Remaining` (the API workers and how many are free).

### Fixed
- The server could spin forever while stopping when a streamed reply (trace, logs, event listening) was being refilled at that moment; it now closes such connections.
- Admin JSON errors are written as MinIO's writeErrorResponseJSON writes them: Go's escaping (`>` as `\u003e`), a trailing newline, and the deployment ID as `HostId`.
- The configuration's validators could be dropped silently once more than 16 were registered (notify_elasticsearch's was); the limit is higher and exceeding it now fails loudly.
- `tests/integration/notify-interop.sh` no longer fails now and then on the order of one DeleteObjects request's events: both servers hand events to several send workers, so the records of one request are compared in key order.
- A log message at exit (after the server's log targets were freed) no longer touches them.
- CopyObject now gives the copy a checksum as MinIO does: the algorithm asked for with `x-amz-checksum-algorithm` (an unknown one is ignored), else the source's (a composite multipart one is computed again whole), else a CRC64NVME computed on the way; the response carries the ETag and the checksum. CompleteMultipartUpload's response carries the ETag header. New s3diff scenario `copy`.
- MRF healing no longer drops an object healed while one of its drives is still offline, which left that drive's copy unwritten once it came back: such entries, and ones that fail with a passing error, are retried with backoff (up to 20 times, about a quarter of an hour) instead of three times at once.
- Requests with `.` or `..` path segments in a query value (other than `delimiter`), or an invalid or reserved bucket name, are now rejected before authentication and without `BucketName`/`Key` in the error, as MinIO's request validity filter does.

## [0.6.0] - 2026-09-28

Phase 6: the web console as its own Deployment. Verified here with the
Playwright suite (11 tests) against bucketsd and consoled, also under
ASan/UBSan, and `tests/integration/console.sh` (31 checks). The gate's kind
run (`tests/e2e-k8s/kind.sh`, which now deploys the console and runs the
same Playwright suite through it) needs Docker and kind and has not been run
in this environment yet, like the Phase 3 kind check.

### Added
- The web console (Phase 6), deployed apart from storage:
  - `consoled` (`src/console`, `src/cmd/consoled`): serves the SPA and logs users in by exchanging their keys for STS credentials at bucketsd (AssumeRole), kept in an AES-256-GCM cookie keyed by PBKDF2 of `CONSOLE_PBKDF_PASSPHRASE`/`SALT` (MinIO console's names; replicas share it). The SPA's S3 and admin calls go through a SigV4-signing proxy to bucketsd (`/api/v1/s3/*`, `/api/v1/admin/*`), streaming uploads (UNSIGNED-PAYLOAD) and downloads, with madmin encryption of admin bodies and replies done server side. Unsafe requests need `X-Console-Request`, cookies are HttpOnly and SameSite=Strict, pages carry a strict CSP.
  - `console/web`: React 18 + TypeScript + Vite SPA: dashboard (servers, drives, usage), buckets, an object browser (folders, uploads with progress, downloads, bulk and recursive deletes, versions, object metadata and tags), bucket settings (versioning, quota, tags, access policy with presets, default encryption, object lock retention, lifecycle), users, groups, policies, access keys (service accounts, secret shown once) and configuration by subsystem.
  - Playwright end-to-end suite (`console/web/e2e`, 11 tests) against a real bucketsd and consoled, in `scripts/ci.sh` under ASan/UBSan.
  - The operator deploys it from `spec.console` (`enabled`, `replicas`, `image`, `serviceType`, `resources`, `ingress` with host, class, TLS and annotations): a `<name>-console` Deployment (non-root, read-only root filesystem, trusting the cluster CA under TLS), Service and Ingress, and a generated cookie-key Secret; console pods never match the storage Service. Disabling it removes them. `docker/Dockerfile.console` builds the image; `tests/e2e-k8s/kind.sh` runs the Playwright suite against the console on kind.
  - OpenID sign-in: the authorization code flow against the provider of `BUCKETS_CONSOLE_OIDC_CONFIG_URL` (or `MINIO_IDENTITY_OPENID_*`), with state and nonce in a short-lived encrypted cookie, then AssumeRoleWithWebIdentity with the ID token; provider and storage errors come back to the sign-in page. Tested against `tests/integration/oidcmock.py` with curl and in the browser.
  - LDAP sign-in (AssumeRoleWithLDAPIdentity, offered when `CONSOLE_LDAP_ENABLED` is on), share links (presigned GETs at `BUCKETS_CONSOLE_S3_URL`, as long as the session lasts and at most 7 days), inline preview of images and small text objects, and object retention and legal hold in buckets with object locking.
  - `tests/integration/console.sh` (no browser needed): key, LDAP and OpenID sign-in against the mocks, the signed proxy (a 20 MiB streamed round trip, encrypted admin calls), share links, CSRF and sessions; in CI under ASan/UBSan.
  - libbuckets gains a streaming HTTP client and a SigV4 request signer and presigner (`src/s3/sign.c`).

## [0.5.0] - 2026-09-28

Phase 5: versioning, object lock, tagging, CORS, quotas, lifecycle expiry,
SSE-S3/SSE-KMS/SSE-C with the builtin KMS, and compression. Gate: mint over
HTTPS 149 PASS / 0 FAIL (with and without compression), and ceph s3-tests
(`tests/conformance/s3-tests.sh`, same harness for both) 324 passed against
MinIO RELEASE.2025-10-15's 315, with no test that MinIO passes failing.

### Added
- Bucket versioning (Phase 5):
  - `?versioning` GET/PUT with MinIO's excluded-prefix and exclude-folders extensions; object lock prevents suspending
  - versioned PUT, CopyObject and CompleteMultipartUpload create new versions; suspended buckets replace the "null" version
  - DeleteObject and DeleteObjects create delete markers (with a new version ID, or "null" when suspended), or remove a version for good by `versionId`, with MinIO's response headers and `DeleteMarker`/`DeleteMarkerVersionId` results
  - GET/HEAD/GetObjectAttributes of a delete marker: NoSuchKey (or MethodNotAllowed by version ID) with the marker's headers
  - `ListObjectVersions` (`?versions`), with key and version-id markers, delimiters and `metadata=true`
  - delete markers on disk are byte-compatible with MinIO's `xlMetaV2DeleteMarker`; `tests/integration/versioning-interop.sh` moves versioned buckets between MinIO and bucketsd both ways
- Object lock (Phase 5):
  - `X-Amz-Bucket-Object-Lock-Enabled` on CreateBucket (turns on versioning), and `?object-lock` GET/PUT with default GOVERNANCE/COMPLIANCE retention in days or years
  - `?retention` and `?legal-hold` GET/PUT on objects, updating the version's metadata in place, and the `x-amz-object-lock-*` headers on PUT, CopyObject and CreateMultipartUpload
  - locked versions refuse deletion unless governance is bypassed with `x-amz-bypass-governance-retention` and the matching permission; COMPLIANCE can only be extended
  - retention and legal hold are stored under MinIO's metadata keys, so locks carry over between the two servers
- Tagging (Phase 5):
  - object `?tagging` GET/PUT/DELETE, per version, stored in the version's `X-Amz-Tagging` metadata as MinIO does
  - bucket `?tagging` GET/PUT/DELETE, stored as the bucket metadata's `TaggingConfigXML`
  - `X-Amz-Tagging` validated on PutObject and CreateMultipartUpload (minio-go's rules: 10 object / 50 bucket tags, key and value charset and lengths, duplicates), the `tagging` field of POST policy uploads, and `x-amz-tagging-directive` COPY/REPLACE on CopyObject
  - `x-amz-tagging-count` on GET/HEAD (plus the tags themselves with MinIO's `X-Amz-Tagging-Directive: ACCESS`), and `UserTags` in `metadata=true` listings
- CORS: the global middleware MinIO runs (rs/cors with `api cors_allow_origin`): preflights answered with 204 and the requested method and headers, `Access-Control-Allow-Origin`/`-Expose-Headers`/`-Allow-Credentials` on allowed origins.
- MinIO's fixed sub-resources: bucket `?cors` (NoSuchCORSConfiguration / NotImplemented), `?website`, `?accelerate`, `?requestPayment`, `?logging` and `?policyStatus` (public when the bucket policy lets anyone list and write); the rejected GETs (`?inventory`, `?metrics`, `?publicAccessBlock`, `?ownershipControls`, `?intelligent-tiering`, `?analytics`) and object `?torrent` / DELETE `?acl` answer NotImplemented without naming the bucket, as MinIO does.
- Bucket quotas (Phase 5): `mc quota set|info|clear` (admin `set-bucket-quota` / `get-bucket-quota`, stored as the bucket metadata's `QuotaConfigJSON`), enforced as MinIO's hard quota on PutObject, CopyObject, UploadPart and UploadPartCopy, counting the bucket's size from the latest data usage (refreshed every 10s).
- Data scanner and data usage: the scanner moved out of the healer into `src/scanner/`. Each cycle the cluster leader walks every version, counts objects, versions, delete markers, sizes and MinIO's size and version histograms per bucket, and stores them as MinIO's `DataUsageInfo` in `.minio.sys/buckets/.usage.json` (with `.bkp` every tenth time and the `.bloomcycle.bin` cycle counter); every node still heals the objects of the sets it leads. The cycle follows `scanner speed` (`MINIO_SCANNER_SPEED`; `BUCKETS_SCANNER_INTERVAL` still overrides it). Admin `datausageinfo` serves the stored usage.
- Lifecycle expiry (Phase 5): bucket `?lifecycle` GET/PUT/DELETE with MinIO's parser, validation and error mapping (every rule element, including And/Tag/size filters, ExpiredObjectAllVersions, DelMarkerExpiration and NewerNoncurrentVersions), stored as MinIO's marshalled `LifecycleConfigXML` with `ExpiryUpdatedAt`; `withUpdatedAt`. The scanner applies Expiration, NoncurrentVersionExpiration, ExpiredObjectDeleteMarker, ExpiredObjectAllVersions and DelMarkerExpiration as MinIO's evaluator does (object lock respected). `x-amz-expiration` is predicted on GET, HEAD, PUT, CopyObject and CompleteMultipartUpload. Transition rules wait for tiering (Phase 8): their storage class is refused as unknown, as MinIO does without that tier.
- KMS APIs (Phase 5): `/minio/kms/v1` status, metrics (request counters and latency histogram), apis, version, key create/list/status, and the admin v3 `kms/status`, `kms/key/create`, `kms/key/status` that `mc admin kms` uses, over the builtin KMS, with MinIO's responses and errors.
- Bucket default encryption (Phase 5): `?encryption` GET/PUT/DELETE with MinIO's parser and errors (a KMS key is test-generated before it is accepted), stored as `EncryptionConfigXML`; writes that ask for no encryption (PutObject, CopyObject, CreateMultipartUpload, POST uploads) get the bucket's SSE-S3 or SSE-KMS default, or SSE-KMS with the default key under `MINIO_KMS_AUTO_ENCRYPTION`. POST policy uploads honor SSE form fields.
- SSE-C (Phase 5): customer-key encryption over TLS on every path above, with copy-source keys for encrypted sources; GetObjectAttributes and `x-amz-checksum-mode` unseal the stored checksums of encrypted objects and report plaintext sizes. mint over HTTPS: 149 PASS, 0 FAIL (the NA tests are CORS, S3 zip and notifications).
- Encrypted multipart uploads (Phase 5): CreateMultipartUpload with SSE-S3/SSE-KMS seals the object key into the upload; each part is DARE-encrypted with its part key and MinIO's derived nonce, recording the sealed plaintext MD5, plaintext size and checksum; ListParts, UploadPart responses and CompleteMultipartUpload use the client-visible part ETags (unsealed for SSE-S3), and the final checksum is sealed. UploadPartCopy into an encrypted upload encrypts the copied range. Reads decrypt across parts with per-part keys.
- Server-side encryption (Phase 5), single-part objects and copies: SSE-S3 and SSE-KMS (builtin KMS; key ID, ARN and encryption context) on PutObject, GET/HEAD with ranges across DARE packages, ListObjects/Versions with plaintext sizes and ETags (and the encryption entry in `metadata=true` listings), CopyObject between any mix of encrypted and plain objects (re-encrypting onto itself included) and UploadPartCopy from encrypted sources. Stored exactly as MinIO stores them (sealed keys in system metadata, sealed ETags, encrypted checksums); `tests/integration/sse-interop.sh` moves encrypted objects between MinIO and bucketsd both ways. Request validation and errors follow MinIO (InvalidArgument for bad SSE headers on writes, BadRequest for SSE-S3/KMS headers on reads, `kms:KeyNotFound`).
- Encryption groundwork (Phase 5): DARE 2.0 streams (`src/crypto/dare.c`, byte-for-byte with minio/sio), object keys with MinIO's key derivation, sealing, part keys and ETag sealing (`src/crypto/objkey.c`), and the builtin KMS of `MINIO_KMS_SECRET_KEY` / `_FILE` (`src/kms/`) with `kms.Context` marshalling; unit tests use vectors produced by MinIO's own `internal/crypto` and `internal/kms`.
- Object compression (Phase 5): the `compression` config subsystem (`enable`, `allow_encryption`, `extensions`, `mime_types`, with MinIO's environment variables and legacy names) and MinIO's rules for what qualifies (never the standard compressed extensions and content types; encrypted writes, bucket defaults included, only with `allow_encryption`; single writes over 4 KiB). Qualifying PutObject, CopyObject and multipart parts are stored as S2 streams (`klauspost/compress/s2` in `X-Minio-Internal-compression`, the plaintext size in `X-Minio-Internal-actual-size` and the part records), with an S2 index for each part over 8 MiB (`PartIdx` in xl.meta). Encrypted objects compress before they encrypt, with streams padded to 256 bytes and indexes sealed with the object key. Reads decompress, using the index to start ranges near their offset; sizes in HEAD, listings, ListParts, GetObjectAttributes and data usage are the plaintext sizes. `tests/integration/compress-interop.sh` moves compressed objects (with and without SSE, single and multipart, with indexes) between MinIO and bucketsd both ways, and `scenarios/compress.json` matches MinIO line for line. mint with compression on: 149 PASS, 0 FAIL.
- S2 codec (`src/compress/s2.c`): block encoder and decoder, the stream format with CRCs, padding, concatenated streams and snappy-framed input, and the stream index; the encoder is byte-for-byte klauspost's pure-Go `encodeBlock` (unit tests use vectors from klauspost/compress v1.20.1), with a `fuzz_s2` target for blocks, streams and indexes.
- xl.meta `PartIdx` and part records' `i` field, and puts of unknown size in the object layer (compressed streams).
- A ListMultipartUploads without a prefix answers from the node's cache of uploads it started (MinIO's `mpCache`), dropped on complete, abort or after a day.
- `tests/integration/s3diff.sh`: runs request scenarios against real MinIO and bucketsd and diffs the normalized responses (`scenarios/{versioning,objectlock,uploads,tagging,subresources,quota,usage,lifecycle,sse,kms,compress}.json` match line for line, a `NAME.env` file sets server environment and `repeat` builds large bodies; admin JSON errors are normalized too, and a `sleep` step waits for the scanner); `tests/integration/usage.sh` covers usage-based quotas.; it signs requests itself, since curl's `--aws-sigv4` misorders `x-amz-tagging` and `x-amz-tagging-directive`.

### Changed
- XML escaping follows Go's `xml.EscapeText` (`&#34;`, `&#39;`), and S3 timestamps in XML carry milliseconds, as MinIO's do.
- DeleteObjects requires Content-MD5 or an `x-amz-checksum-*` header and verifies it (`MissingContentMD5`, `BadDigest`), as MinIO does.
- HEAD error responses have no body.
- Emptiness checks for bucket deletion count every version and delete marker.
- Bucket configuration documents keep the `xmlns` of the document that was PUT, as MinIO does.
- ListMultipartUploads matches MinIO: uploads oldest first, paging by `upload-id-marker` with `NextUploadIdMarker` and `IsTruncated`, the 10000 default, `EncodingType` echoed, and empty Initiator/Owner/StorageClass.

### Fixed
- Found by ceph s3-tests against MinIO:
  - listings put a directory object (`a/`) before the keys under it, so paged version listings no longer skip it (bucket cleanup failed with BucketNotEmpty)
  - an empty `delimiter` is not echoed in ListObjects V1/V2
  - PutObject, CreateMultipartUpload and CompleteMultipartUpload honor `If-Match` / `If-None-Match` against the current version (PreconditionFailed; NoSuchKey for an If-Match on a missing key), as MinIO's checkPreconditionsPUT does
  - `response-content-type` and the other response overrides replace the header instead of adding a second value
  - a presigned URL with `X-Amz-Expires=0` has expired
  - requests wait for a namespace lock as long as MinIO's globalOperationTimeout allows (5 minutes, `BUCKETS_LOCK_TIMEOUT` to override) instead of 30 seconds, so a write outlasts a reader that stalls mid-download (dropped after 60 seconds) as it does on MinIO
  - `x-amz-copy-source` splits its query at the first literal `?` before decoding, so keys with an encoded `?` (or ` `) and version IDs copy correctly
- A client that stops reading a response no longer holds it (and the object's read lock, blocking every writer of that key) forever: a response that makes no progress for 60 seconds is closed (found by ceph s3-tests).
- An unsatisfiable range answers MinIO's InvalidRange (the range and `ActualObjectSize`/`RangeRequested` in the document, no `Content-Range`), and a malformed one fails before the object is looked up.
- An `x-amz-checksum-algorithm` header without a checksum value asks for nothing (getContentChecksum); bucketsd computed and stored one.
- GetObjectAttributes reports the stored size of each part of an encrypted object, as MinIO does (the object size stays the plaintext one).
- Encrypted (and compressed) writes of a known size read to the end of the body, so trailing checksums of aws-chunked uploads are seen; a longer body fails.
- test_dare read past a short stream's buffer (ASan).
- ListParts follows MinIO: 10000 parts by default and at most, NextPartNumberMarker only when truncated, the owner ID as display name, and ChecksumAlgorithm/ChecksumType always present.
- A completed multipart object records the sum of its parts' actual (plaintext) sizes, and internal (`x-minio-internal-*`) upload metadata is stored as system metadata and carried to the object, as in MinIO.
- s3diff passes request bodies through a file, so large parts fit.
- UploadPartCopy ranges follow MinIO: an unparsable range is InvalidCopyPartRange and one past the source's end InvalidCopyPartRangeSource (it was clamped), and errors name the source object.
- DELETE without a version ID on a key that never existed, in a versioned or suspended bucket, stores no delete marker (MinIO's DeleteObject); DeleteObjects still reports one, as MinIO does.
- Shutdown no longer frees the object layer under the IAM loader, its periodic refresh or the LDAP sync thread: they sleep on a condition variable and are joined first (an ASan use-after-free in the cluster test).
- PUT, DELETE and HEAD on a bucket with an unrecognized query go to CreateBucket, DeleteBucket and HeadBucket, like MinIO's catch-all routes, instead of NotImplemented; `?acl` and `?policy` only take the methods MinIO routes to them.
- `metadata=true` listings report each object's real erasure data and parity counts in `Internal`, not 1/0.
- Errors from CopyObject after the source is authorized name the source bucket and key, as MinIO's do.
- `encoding-type=url` listings encode keys as MinIO does (space as `+`, `*` kept, `~` escaped).

## [0.4.0] - 2026-09-28

### Added
- Kubernetes (Phase 3):
  - CRDs: `BucketsCluster` (with status and printer columns), `BucketsUser`, `BucketsPolicy` and `Bucket`.
  - `buckets-operator` in C:
    - server-side-applies a headless Service (publishing unready pods), the S3 Service, a StatefulSet per pool and PodDisruptionBudgets
    - generates root credentials that outlive the cluster
    - restarts every server together on a topology change, and rolls other changes one server at a time
    - reports status, and elects a leader on a Lease
  - Manifests: `operator/deploy/operator.yaml` (namespace, least-privilege RBAC, a 2-replica Deployment), `docker/Dockerfile.operator`, and examples, including TLS with cert-manager.
  - bucketsd:
    - reads drives from `BUCKETS_VOLUMES`/`MINIO_VOLUMES`
    - reads root credentials from `*_FILE`
    - treats endpoints whose first DNS label is the pod's hostname as local
  - Tests:
    - operator manifest unit tests
    - `tests/e2e-k8s/envtest.sh`: 34 checks against a real kube-apiserver and etcd, as the operator's own ServiceAccount
    - `tests/e2e-k8s/kind.sh`: the full kind end to end (not yet run: needs docker)
- HTTP client: chunked responses, and CA bundles given as a file.
- IAM (Phase 4, in progress):
  - The IAM policy engine, ported from minio/pkg v3.1.3 and checked against golden vectors from the Go package.
  - madmin `EncryptData`/`DecryptData` (Argon2id, AES-256-GCM or ChaCha20-Poly1305 over sio).
  - The IAM store (`src/iam/iam.c`): users, groups, policies, policy mappings, service accounts and STS credentials. They are cached in memory and stored in MinIO's `.minio.sys/config/iam` layout, so MinIO deployments carry their IAM state over. It also:
    - reloads on a timer
    - loads keys on a cache miss
    - takes per-item peer reload notifications
  - HS256/384/512 JWTs for session tokens, and `.minio.sys` config object helpers.
  - The madmin-compatible admin API (`/minio/admin/v3`) for IAM, which works with `mc admin user|group|policy|user svcacct`. It covers:
    - add-user, remove-user, list-users, user-info, set-user-status
    - update-group-members, group, groups, set-group-status
    - list-, info-, add- and remove-canned-policy, set-user-or-group-policy, and `idp/builtin/policy/attach|detach`
    - add-, update-, info-, list- and delete-service-account
    - list-access-keys-bulk, info-access-key, temporary-account-info, and `idp/builtin/policy-entities`
    - madmin encryption where MinIO uses it, and JSON errors
  - Bucket policies (`policy.BucketPolicy`):
    - parsing and evaluation, checked against 5,323 golden vectors from the Go package (`policygen bpvectors`)
    - `?policy` PUT, GET and DELETE
    - anonymous requests authorized against the policy; works with `mc anonymous`, and in both directions with MinIO
  - `mc admin info` (ServerInfo). Every server reports its own drives (state, space, inodes, pool/set/drive index) over a new peer RPC, and the answer combines them with the backend's shape and per-set capacity. Unreachable servers show as offline.
  - Peer notifications (`src/dist/peer`): IAM and bucket-metadata changes are pushed asynchronously to every other server over internode RPC, so they take effect cluster-wide at once. `cluster.sh` checks this across nodes.
  - A bucket-metadata cache (`src/bucket/metasys`): refcounted snapshots, invalidated on local writes, with a TTL in distributed mode.
  - STS `AssumeRole`:
    - SigV4 for the `sts` service, over the body's hash
    - session policies, `DurationSeconds`, and `MINIO_STS_DURATION`
    - MinIO's XML responses and errors
  - The operator reconciles `BucketsUser`, `BucketsPolicy` and `Bucket` through the cluster's admin and S3 APIs, using a SigV4-signing client with madmin encryption:
    - users, with their policies and group memberships, and policies, are applied idempotently; unchanged objects are skipped by a hash kept in status
    - a finalizer removes users and policies from the cluster when their objects are deleted; deleting a `Bucket` leaves the bucket and its data
    - `buckets.io/endpoint` overrides the service address
    - envtest now checks all of this against a real bucketsd (45 checks)
  - OpenID Connect:
    - `AssumeRoleWithWebIdentity` and `AssumeRoleWithClientGrants`, taking form or query parameters
    - `identity_openid` providers from config or env: discovery document, JWKS (RSA, EC, Ed25519, and client-secret HMAC; refetched when a key is unknown), claim-based policies with a prefix, or role-policy providers selected by `RoleArn`
    - `aud`/`azp` checks, UserInfo claims, DurationSeconds, session policies, and MinIO's parent-user derivation
    - `tests/integration/openid.sh` runs against a mock identity provider
  - HTTP plugins:
    - `policy_plugin` (and the older `policy_opa`), to which every authorization decision is delegated
    - `identity_plugin`, for `AssumeRoleWithCustomToken`, with its `idmp-` role ARN
    - Both are probed when set through `mc admin config`; `tests/integration/plugins.sh` covers them.
  - `AssumeRoleWithCertificate` (identity_tls, enabled by `MINIO_IDENTITY_TLS_ENABLE`): the TLS server asks for (never requires) a client certificate; it must be the only leaf, verify for client authentication against the system roots and `certs/CAs` (or carry the clientAuth usage with `skip_verify`), and its CN names the policy of the `tls/<CN>` credentials, whose expiry never outlives the certificate (`tests/integration/certsts.sh`).
  - LDAP / Active Directory:
    - `src/net/ldap.c`, a compact LDAPv3 client (BER, simple bind, search, StartTLS, LDAPS) with go-ldap's filter compiler, filter escaping and DN normalization, checked against vectors generated from go-ldap (`tools/ldapvec`)
    - `identity_ldap` (`src/iam/ldapidp.c`, from MinIO's `identity/ldap` and minio/pkg `ldap`): validated against the directory on startup and on `mc admin config set`, lookup bind, user and group search with several base DNs, user attributes, SRV records, and trust in `certs/CAs`
    - `AssumeRoleWithLDAPIdentity`, with the `ldapUser`/`ldapActualUser`/`ldapUsername`/`ldapAttrib_*` claims, DurationSeconds and session policies
    - IAM's LDAP mode: policies mapped on user and group DNs (`policydb/sts-users`, `policydb/groups`), and built-in user/group changes refused as in MinIO
    - admin `idp/ldap/policy/attach|detach`, `policy-entities`, `add-service-account`, `list-access-keys` and `list-access-keys-bulk`, and LDAP handling in `set-user-or-group-policy`
    - an hourly sync (MinIO's purgeExpiredCredentialsForLDAP and updateGroupMembershipsForLDAP) removes the credentials of users gone from the directory and updates the groups of the rest
    - `tests/integration/ldap.sh` runs `mc idp ldap` against a mock directory (`ldapmock.py`), over plain LDAP, LDAPS and StartTLS
  - `mc admin accesskey sts-revoke` (`revoke-tokens`, by token type or all), `mc idp openid accesskey ls` (`idp/openid/list-access-keys-bulk`), and the provider details (`userProvider`, LDAP user, OpenID config and claims) in `info-access-key`
  - `mc admin cluster iam export|import` (`export-iam`, `import-iam`, `import-iam-v2`): the zip of policies, users, groups, service accounts and mappings, with MinIO's import semantics (LDAP DN normalization included); archives move between MinIO and bucketsd in both directions (`iam-interop.sh`). `src/core/zip.c` reads and writes the archives on libdeflate, now a dependency.
  - `mc admin service restart|stop|freeze|unfreeze` (`service`, v1 and v2 responses), applied across the cluster: freeze holds S3 calls until unfreeze, restart drains and re-executes the server in place, stop drains and exits. The admin API and health probes now run on their own small worker pool, so a frozen API never blocks them (`tests/integration/service.sh`, and three new `cluster.sh` checks).
  - admin `accountinfo`: the effective policy (consoleAdmin for root or with an authorization plugin, role or claim policies, else the mapped ones), the backend layout, and the buckets the account can read or write. Usage figures and bucket feature details stay zero until the scanner and bucket metadata land.
  - `mc idp openid|ldap add|update|info|ls|rm` (the `idp-config` admin API): configuration shown without defaults or secrets, with its environment overrides, role ARNs and live state, and LDAP validation errors in MinIO's format
  - The server configuration (`src/config`), a port of MinIO's `internal/config`:
    - all 34 sub-systems, with their keys, defaults and help, generated from MinIO's own registry (`tools/configgen`)
    - set/reset validation, `MINIO_*` (and `BUCKETS_*`) environment overrides and env-defined targets, and `config.json` and history in `.minio.sys` (MinIO-compatible in both directions)
    - admin `mc admin config get|set|reset|export|import|history|restore`, and changes pushed to peers
  - Tests:
    - `tests/integration/config.sh`: `mc admin config`, with MinIO interop
    - `tests/integration/iam.sh`: the `mc admin` suite, including a restart
    - `tests/integration/iam-interop.sh`: IAM state written by real MinIO is honoured by bucketsd, and the reverse
  - S3 requests authenticate against IAM, covering users, service accounts and STS with session-token checks. Each route is authorized with MinIO's policy action, using MinIO's condition values (`getConditionValues`), including copy sources, DeleteObjects keys and POST policy uploads. Keys that are disabled or unknown before IAM loads get MinIO's error codes.

### Fixed
- The HTTP server allows 16 prefix routes (was 4, too few once internode and control routes are both present).
- The inherited policy reported for a service account now includes its parent's group policies.
- RFC 3339 parsing no longer relies on `timegm()`, which fails on macOS for Go's zero time (year 1).
- ctest now registers tests outside `tests/unit` (`enable_testing()` moved before the subdirectories).

### Changed
- PUT and GET throughput. Single-stream PUT went from 2.6–3.3× MinIO's time to MinIO's speed or better, at the MD5 floor. GET is 30–50% faster than MinIO warm and 2–4× faster cold. Details and numbers are in `docs/performance.md`.
  - MD5 and SHA-256 use OpenSSL's optimized block functions, with value-type contexts and no allocation.
  - Payload hashes run one block behind in the background, overlapping reads, parity and writes.
  - Reed-Solomon parity is computed in parallel byte ranges.
  - Large request bodies (with Content-Length) stream to the handler through a bounded pipe with socket backpressure, instead of being spooled to disk first.
  - HighwayHash has NEON and SSSE3 update loops, bit-identical to the portable one.
  - Object readers keep part files open.
  - Response streams are double-buffered.
  - On Linux, shard data syncs with `fdatasync`.
  - Reed-Solomon uses split-nibble SIMD (NEON and SSSE3). A randomized test checks it against the scalar code.
  - Multi-block PUTs hash on a dedicated thread fed through a four-buffer ring. On macOS the thread prefers a performance core.
  - Local drive writers buffer 1 MiB, and shard writes are grouped per pool task.
  - GETs copy straight out of the verified shards and read the next block ahead.
- The default drive I/O pool is the set size + 2 threads (it now also runs the payload hashes).

### Fixed
- SigV4 canonicalization of an unsigned `content-length` header used the in-memory body length, which is 0 for spooled or streamed bodies.

### Added
- `tests/bench/putget.sh`: single-stream PUT/GET timings, side by side with MinIO when `MINIO_BIN` is set.

## [0.3.0] - 2026-09-28

Phase 2: erasure coding, pools, distributed mode.

### Added
- Reed-Solomon erasure codec (GF(2^8), klauspost-compatible matrix), verified against all 60 of MinIO's erasure self-test vectors.
- MinIO ellipsis drive syntax (`/data{1...16}`, zero-padded and hex ranges), set sizing identical to MinIO's `getSetIndexes`, SipHash set selection, and CRC32 `hashOrder` shard distribution.
- A StorageAPI on local drives (ReadAll, WriteAll, CreateFile, ReadAt, RenameData, Delete, ListDir) that mirrors MinIO's, ready for remote drives.
- `format.json` negotiation across drives: fresh deployments, quorum-voted reference layouts, foreign-deployment rejection, and healing of replaced drives into their slot.
- Multi-drive erasure object layer: per-block encoding with HighwayHash bitrot, read/write quorum, bitrot detection with parity reconstruction, quorum-consistent metadata, merged listings and multipart across erasure sets. Real MinIO reads erasure sets written by Buckets, and Buckets reads MinIO's.
- `bucketsd server` accepts multiple drives and ellipsis patterns and honors `ERASURE_SET_DRIVE_COUNT` and `STORAGE_CLASS_STANDARD=EC:N` (`BUCKETS_` or `MINIO_` prefixed).
- Drive I/O thread pool (`core/pool`): metadata loads, shard hashing and writes, fsyncs, commits, deletes and shard reads now run on all drives of a set at once. `BUCKETS_IO_THREADS` sets its size (default: set size - 1). GETs from a 16-drive set run about 2x faster. The code is clean under ThreadSanitizer.
- Request handlers and response-stream pulls run on a worker pool (`BUCKETS_API_THREADS`, default 2 x CPUs, minimum 8). The event-loop thread only moves bytes, so a slow drive or request no longer stalls other clients.
- Namespace locks (`object/nslock`): object writes lock only their commit, as in MinIO. Reads hold a shared lock until EOF, and multipart parts share their upload's lock while complete and abort take it exclusively. A lock not granted in 30 s fails with `RequestTimeout`.
- Object healing (`buckets_obj_heal`, after MinIO's erasure-healing.go):
  - finds drives missing a version, or holding missing, truncated or (deep scan) bitrotten shards
  - rebuilds only those shards from the intact drives and commits them to the outdated drives
  - purges dangling versions by MinIO's `isObjectDangling` rules: offline or unreadable drives block a verdict, and corrupt shards never count
- Background healer (`heal/healer`):
  - an MRF queue fed by reads that hit a missing or rotten shard (bitrot queues a deep scan) and by writes that missed a drive
  - replaced drives are filled in the background, with a resumable tracker in `.minio.sys/buckets-healing.json`
- `tests/integration/heal.sh` covers bitrot, missing and inline repairs, an unreadable object that must not be purged, a dangling object that must be, and a replaced drive.
- Server pools (`object/pools.c`, after MinIO's erasure-server-pool.go):
  - each ellipsis argument is a pool, and a new pool joins the deployment's format
  - buckets are created on every pool
  - reads resolve the pool with the newest copy, and overwrites stay in their pool
  - new objects go to a pool picked at random, weighted by free space
  - listings merge across pools, deletes reach every pool, and multipart uploads find their pool
  - real MinIO reads an expanded deployment written by Buckets (`tests/integration/pools.sh`)
- HTTPS (OpenSSL 3), after MinIO's certs directory:
  - `--certs-dir` holds `public.crt` and `private.key`; the default is `~/.buckets/certs`, then `~/.minio/certs`
  - certificates in subdirectories are chosen by SNI
  - certificates reload when their files change, without a restart
  - TLS 1.2 minimum with MinIO's AEAD cipher suites, and `BUCKETS_CERT_PASSWD` for encrypted keys
  - certificates with explicit EC parameters are refused at startup, as Go-based MinIO does
- CMake uses the system OpenSSL 3, or builds a pinned 3.5.4 once into `.deps/`.
- `tests/integration/tls.sh` covers the above. `TLS=1` runs minio-go conformance over HTTPS: 80 pass, 0 fail.
- Distributed mode:
  - drives given as `http(s)://host:port/path` URLs, and a node recognizes its own drives by port and interface address
  - remote drives work over internode RPC (our own protocol: HTTP/1.1 under `/buckets/internode/v1/`, HMAC-authenticated, pooled, TLS-capable, on a separate worker pool)
  - dsync locks with quorum, refresh and expiry, failing fast when quorum is unreachable
  - bootstrap waits for peers, only a pool's first node formats it, and S3 answers `XMinioServerNotInitialized` until ready
  - `tests/integration/cluster.sh` runs 4 nodes, including node loss, rejoin, and loss beyond quorum; with `MINIO_BIN`, a real MinIO cluster reads the drives
  - minio-go gives 78/0 with `CLUSTER=1` and 80/0 over HTTPS
- A background scanner walks the sets each node leads and heals what it finds. `BUCKETS_SCANNER_INTERVAL` sets the cycle.
- `/minio/health/cluster` and `/cluster/read` report per-set quorum.
- `tests/integration/concurrency.sh`: racing PUTs of one key (every drive must agree), 24 parallel round trips, overwrite during a slow read, CopyObject onto itself, and parallel multipart parts.
- `tests/integration/erasure.sh`: 4- and 16-drive sets, bitrot, drive loss up to and beyond parity, drive replacement, and MinIO interop. `DRIVES=4` runs the minio-go conformance suite on an erasure set.

### Changed
- The single-drive layer is now the erasure layer with one drive (EC 1+0); on-disk output is unchanged.
- Requests with server-side encryption are refused until SSE lands (Phase 5), instead of being stored unencrypted:
  - SSE-C over plain HTTP gets `InsecureSSECustomerRequest`
  - SSE-S3/KMS gets MinIO's no-KMS `NotImplemented`
  - SSE-C keys on GET or HEAD get `InvalidRequest`
- `Location` headers use `https` on TLS connections.
- The object namespace check (a key vs. an existing prefix) runs under the object lock. Racing writers of one key could briefly see each other's directory and fail with `XMinioObjectExistsAsDirectory`.
- GetObject loads the first block before sending headers, so an object without enough intact shards gets `503 SlowDownRead` instead of a truncated `200`.

## [0.2.0] - 2026-09-27

### Changed
- The error generator splits acronym boundaries (for example `ErrMalformedPOSTRequest` becomes `BUCKETS_ERR_MALFORMED_POST_REQUEST`).
- Signed aws-chunked trailers are hashed with exactly one trailing newline, as in MinIO. minio-go already sends one.
- The storage class is stored under MinIO's lowercase `x-amz-storage-class` key, and `STANDARD` is not stored.
- Object uploads now read the body to EOF after the declared length. Extra bytes are rejected as IncompleteBody, and trailers are always consumed.
- `ListObjects` now returns real objects instead of the 0.1.0 empty placeholder.

### Added
- HighwayHash-256 (MinIO bitrot), XXH64 and XXH3-64, ported to C and verified against the Go libraries MinIO links.
- A MessagePack encoder/decoder that reproduces tinylib/msgp's exact encodings, as groundwork for xl.meta and bucket metadata.
- xl.meta v2 (format 1.3) codec: parse, serialize, version ordering, inline data, and object version encode/decode with MinIO's exact signatures. It round-trips files written by real MinIO byte for byte (`tests/data/minio-ref`).
- Single-drive object layer in MinIO's exact on-disk layout: xl.meta, bitrot-framed `part.N` files, inline data under 128 KiB, and `__XLDIR__` folder objects. Real MinIO reads drives written by Buckets, and Buckets reads MinIO's.
- S3 object APIs: PutObject, GetObject (ranges, conditional requests, response-* overrides), HeadObject, DeleteObject, DeleteObjects, CopyObject (metadata directives and copy-source conditions), and ListObjects v1/v2 with real results (prefix, delimiter, marker, continuation token, url encoding).
- Multipart uploads: Create, UploadPart, UploadPartCopy (with ranges), ListParts, Complete (ETag = md5-of-md5s-N), Abort, and ListMultipartUploads, in MinIO's `.minio.sys/multipart` layout.
- S3 additional checksums (CRC32, CRC32C, CRC64NVME, SHA1, SHA256):
  - via headers or aws-chunked trailers
  - verified before commit and stored in MinIO's `x-minio-internal-crc` format
  - returned with `x-amz-checksum-mode: ENABLED`
  - multipart composite (`-N`) and full-object checksums, merged with CRC combination
  - real MinIO reports identical values for objects Buckets wrote
- AWS Signature V2 (header and presigned), verified against AWS's published examples.
- `partNumber` on GET/HEAD (206, `x-amz-mp-parts-count`, per-part checksums).
- GetObjectAttributes (ETag, Checksum, ObjectParts, StorageClass, ObjectSize).
- POST-policy browser uploads:
  - multipart/form-data parsed as a stream
  - V4 and V2 policy signatures
  - MinIO's condition rules and exact failure messages
  - `content-length-range`
  - checksum form fields
  - `success_action_redirect` and `success_action_status`
- Bucket and object ACL APIs: canned `private` only, as in MinIO.
- `ListObjectsV2` with `metadata=true` (MinIO's ListObjectsV2M extension).
- `tests/conformance/minio-go.sh` runs minio-go's functional suite (mint's Go suite). Current result: 78 pass, 0 fail, 24 not implemented (versioning, tagging, CORS, policies and notifications come in later phases).
- `tests/integration/interop.sh`: round trips through `mc` and a real MinIO build in both directions. `tools/build-oracles.sh` builds the oracles.
- aws-chunked uploads: signed chunks (chained chunk signatures), signed trailers, and unsigned trailers.
- HTTP request bodies over 1 MiB spool to disk (up to 5 TiB), and responses stream from the object reader.
- Bucket metadata (`.minio.sys/buckets/<b>/.metadata.bin`), byte-compatible with MinIO. It is written on CreateBucket, used for ListBuckets creation dates, and removed on DeleteBucket.
- `tools/golden`, a Go program that generates reference vectors (`tests/unit/golden_vectors.inc`) from those libraries.

## [0.1.0] - 2026-09-27

### Added
- Repository scaffolding:
  - CMake build with pinned dependencies (llhttp, yyjson, cmocka)
  - strict warnings, and sanitizer builds via `BUCKETS_SANITIZE`
  - `scripts/ci.sh` gate
  - distroless `docker/Dockerfile.bucketsd`
- Core runtime: buffers, string slices, S3 time formats, Go-compatible query parsing, JSON-lines logging, UUIDs, and an epoll/kqueue event loop.
- HTTP/1.1 server:
  - keep-alive and pipelining
  - `Expect: 100-continue`
  - idle timeouts
  - 413 and 400 handling
  - correct half-close behavior
  - graceful drain on SIGTERM
- Crypto: SHA-256, HMAC-SHA256, MD5, base64 and constant-time compare, tested against NIST and RFC vectors.
- AWS Signature V4 for signed headers and presigned URLs, with MinIO's exact parsing and error semantics:
  - region and service checks
  - 15-minute clock skew
  - presign expiry
  - `Content-MD5` and `x-amz-content-sha256` payload verification
- S3 error table generated from MinIO's `cmd/api-errors.go` (327 codes) by `scripts/gen-s3-errors.py`.
- Strict XML reader that rejects DOCTYPE, entities and CDATA and limits nesting depth, plus an escaping XML writer.
- Single-drive storage with a MinIO-compatible `.minio.sys/format.json` (`xl-single`), and bucket volumes.
- `bucketsd server [--address HOST:PORT] DIR`, with `BUCKETS_*` configuration and `MINIO_*` fallbacks.
- S3 handlers:
  - ListBuckets, CreateBucket (with LocationConstraint), HeadBucket, DeleteBucket
  - GetBucketLocation
  - GetBucketVersioning (always unversioned)
  - ListObjects v1 and v2 (validated parameters, empty results until the object layer exists)
- Health endpoints `/minio/health/*`, also served under `/buckets/health/*`.
- Unit tests, fuzz harnesses (SigV4, XML) with seed corpora, and an end-to-end smoke test driven by curl's SigV4 signer.
- `docs/architecture.md`, and `docs/parity.md` generated from MinIO's routers (222 handlers tracked).
