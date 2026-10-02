# Security policy

## Reporting a vulnerability

Report security problems privately, not in a public issue or merge request:

1. Open a new issue in the project on GitLab: https://gitlab.com/vericast/HarlandClarke/hc-corpit/buckets/-/issues/new
2. Tick **This issue is confidential**, so only project members can see it.
3. Describe the problem, the affected version or commit, and how to reproduce it. Leave out real credentials, keys and customer data.

A maintainer acknowledges the report and keeps the confidential issue updated until a fix ships. Fixes are listed under **Security** in [CHANGELOG.md](CHANGELOG.md).

## Supported versions

Security fixes go into the next release from `main`. Only the latest release (currently 0.10.x) is supported; older releases get no backported fixes.

## Scope

In scope: `bucketsd`, `consoled` and the web console, `buckets-operator` and its Helm chart, and the container images built from `docker/`.

Buckets reimplements MinIO's behavior. A problem that also affects MinIO `RELEASE.2025-10-15T17-29-55Z` is in scope: MinIO's community project is archived and will not fix it.
