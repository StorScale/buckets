# Buckets Roadmap

As of 2026-10-02 · Russell Myers

## Summary

Buckets should become the maintained home for MinIO users, then win on enterprise identity and Kubernetes operations. Matching MinIO is done: Buckets is a C rewrite of MinIO's last public release and implements 220 of its 222 API handlers. MinIO's community project was archived in April 2026, so its users now need a supported successor more than another feature.

The order below leads with what builds on work that already exists (MinIO on-disk compatibility, the operator, Entra ID sign-in) and needs no storage-engine changes. Performance claims wait until benchmarks back them.

## Priorities at a glance

![Buckets roadmap: five phases, each with the gate that must pass before the next](roadmap.svg)

Phases 1 and 2 carry the case for choosing Buckets; Phases 3 and 4 make it easier to adopt and to sell to regulated teams. No dates are set yet: each phase starts when the gate before it passes.

## Phase 0: Housekeeping

Small fixes that decide whether people trust Buckets as the maintained successor. Each is days of work, not weeks.

- [ ] Update the README: it says "Status: 0.3.0" and "Next up is the Kubernetes operator", but `VERSION` is 0.10.0 and the operator ships.
- [ ] Require OpenSSL 3.2 or later at configure time. The build accepts 3.0, then fails compiling Argon2 code.
- [ ] Fix the brief loading spinner on the Users page when local users are hidden.
- [ ] Fix the envtest rolling-update step, which fails on a race with or without recent changes ("pod not found").
- [ ] Keep CHANGELOG.md current with each release, and publish a security contact so users can report issues.

## Phase 1: The maintained home for MinIO users

The goal is a safe, supported move from an archived MinIO deployment to Buckets. Buckets already reads and writes MinIO's exact on-disk format, so this is packaging and tooling, not storage work.

- **Adopt existing MinIO tenants.** The operator takes over a running MinIO deployment's volumes in place, with no data copy.
- **A tested rollback.** Document and test switching the same volumes back to MinIO `RELEASE.2025-10-15T17-29-55Z`.
- **A compatibility promise.** State what stays compatible across releases: the on-disk format, `mc`, the AWS and MinIO SDKs, and the admin API.
- **Release artifacts.** Signed images in a public registry, a published Helm chart for the operator, and an SBOM per release.
- **A migration guide** covering identity (MinIO config to Entra ID or Okta), TLS, and monitoring.

Done when: a MinIO tenant with real data moves to Buckets and back again in CI, with no data loss.

## Phase 2: Enterprise identity

Identity-provider sign-in with role-based access should be a feature people choose Buckets for, not a set of environment variables. Entra ID sign-in with app roles works today; this phase makes it easy to set up and to audit.

- **Guided setup in the console** for Entra ID, Okta and Keycloak, replacing hand-written `MINIO_IDENTITY_OPENID_*` settings.
- **Per-bucket and per-team roles.** Ship policy templates such as `team-<name>-rw`, with matching app-role guidance for each identity provider.
- **Automatic provisioning and removal (SCIM).** People who leave lose access and their access keys without manual cleanup.
- **An access review page.** Answer "who can read this bucket, and why", and test whether a given user would be allowed an action.
- **Local-users policy.** Keep the current default (no local users while identity-provider sign-in is on), and report any local users that remain.

Done when: a new admin connects Entra ID from the console without editing environment variables, and an auditor can list everyone with access to a bucket.

## Phase 3: Kubernetes-native operations

Everything about a Buckets cluster should be declared in Kubernetes and watched by default. The operator already handles pool expansion, drive replacement, rolling upgrades, TLS and console TLS; this phase fills the gaps found while deploying to the dev cluster.

- **More resources as CRDs.** `BucketsUser`, `BucketsPolicy` and `Bucket` exist; add bucket replication, site replication, lifecycle rules and quotas, so a whole setup lives in Git.
- **Monitoring shipped with the operator.** Prometheus scrape configuration, Grafana dashboards and alert rules for drive health, healing backlog, capacity and failed sign-ins.
- **cert-manager by default.** The operator requests certificates itself; today they are created by hand.
- **Console scheduling fields.** Add `nodeSelector`, `affinity` and `tolerations` to `spec.console`, as pools have. The dev cluster needed a manual patch to keep the console off two nodes.
- **Exportable manifests.** A documented layout for keeping a cluster's resources in a repo, so a cluster can be recreated from Git.

Done when: a cluster, its buckets, policies and replication are created from one Git repository, and a failing drive raises an alert without anyone looking.

## Phase 4: Console and compliance

The full admin console and OpenSSL 3 are already in place; this phase turns them into reporting and compliance features that regulated buyers ask for.

**Console**

- Usage and chargeback reports per bucket and per team, exportable as CSV.
- A lifecycle and replication editor, instead of JSON and `mc` commands.
- An audit log viewer, with forwarding to Microsoft Sentinel or Splunk. With Entra ID sign-in, this gives a Microsoft-centric organisation one identity and audit story.

**Compliance and security**

- **FIPS 140-3 mode** using the OpenSSL 3 FIPS provider. Buckets links OpenSSL 3.5, which makes this more practical than in a Go codebase.
- **WORM compliance reports** built on the existing object lock: which buckets are locked, in which mode, until when.
- **Ransomware alerts** for unusual bursts of deletes or overwrites, using the existing event notifications.

Done when: an auditor can get usage, access and retention reports from the console, and FIPS mode is documented and tested.

## Held until benchmarks exist: footprint and performance

A C server in a distroless image should use less memory than the Go original, which matters for edge and small-node deployments. That is a hypothesis, not a claim, until it is measured.

- Run the existing benchmarks (`tests/bench/`, `docs/performance.md`) against MinIO `RELEASE.2025-10-15T17-29-55Z` on the same hardware: memory at idle and under load, throughput, and latency.
- Publish the method and the raw results with each comparison.
- Market footprint or speed only where the numbers show a clear difference.

## Already delivered

The roadmap builds on what exists: MinIO's exact on-disk format, 220 of 222 MinIO API handlers, the operator, and a console deployed apart from storage. This week's work, deployed to the shared dev cluster:

| Date | Change | What it gives |
| --- | --- | --- |
| 2026-10-02 | Users page lists Entra ID users | Name, sign-in name and roles of people who have signed in; no local users by default |
| 2026-10-02 | Session cookie fix | Entra ID sign-in works; headers over 1 KB were cut off |
| 2026-10-02 | `spec.console.env` | Console sign-in settings, with the client secret from a Kubernetes Secret |
| 2026-10-02 | New logo and blue accent | Branding across the tab, sidebar and login page |
| 2026-10-01 | Console HTTPS (`spec.console.tls`) | Console and S3 each on their own load balancer on port 443 |
| 2026-10-01 | GitLab pipeline to Harbor | Images built on every push to `main` |

## Risks and open questions

- **Taking over live MinIO data is high-stakes.** One bad adoption loses trust permanently. Mitigation: read-only dry runs, a tested rollback, and the CI round trip before any release claims it.
- **AGPL licensing.** Buckets inherits MinIO's AGPL-3.0. Confirm how that affects internal use and any hosted offering before positioning beyond internal use.
- **Scope versus team size.** Five phases is a lot for a small team; Phases 0 to 2 are the core, and 3 and 4 can slip.
- **Identity-provider differences.** Entra ID is proven; Okta and Keycloak send roles in different claims and need their own tests.
- Who owns the roadmap, and who are the first users outside this team?
- Should FIPS mode come before Phase 3, if a regulated customer needs it?
