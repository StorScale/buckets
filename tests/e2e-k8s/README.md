# Kubernetes end-to-end tests

| Script | What it checks |
|---|---|
| `envtest.sh` | The operator against a real kube-apiserver and etcd (no nodes); needs nothing but curl |
| `kind.sh` | One 4-server cluster on kind: pod loss, drive (PVC) replacement, pool expansion, image rollout, and the console as its own Deployment (its Playwright suite when npm is present) |
| `multisite.sh` | Two Buckets clusters and a MinIO site: bucket replication Buckets↔MinIO (active-active), three-site site replication (Buckets, MinIO, Buckets), and a forwarded multi-server decommission |

Both kind scripts build the images from this checkout (`docker/Dockerfile.*`),
create or reuse the kind cluster `buckets-e2e` (`KIND_CLUSTER`), install the
operator, and delete the cluster at the end unless `KEEP_CLUSTER=1`. S3 and
admin traffic comes from a client pod (`tests/e2e-k8s/tools`, curl, jq and,
for `multisite.sh`, mc and MinIO) through Service DNS names, as real clients
and peer sites would reach each other.

## Requirements

`docker`, `kind` and `kubectl` on the PATH. The VM needs about 4 CPUs and
8 GiB. On macOS without Docker Desktop, [Lima](https://lima-vm.io) works
without root:

```bash
limactl start --name=docker --cpus=4 --memory=8 template://docker
export DOCKER_HOST=unix://$HOME/.lima/docker/sock/docker.sock
```

`multisite.sh` also needs linux builds of MinIO and mc for the node's
architecture, at `MINIO_LINUX` and `MC_LINUX` (default
`$TMPDIR/buckets-tools/linux/{minio,mc}`); it is skipped without them. Build
them at the release Buckets targets:

```bash
git -C ~/minio worktree add /tmp/minio-tag RELEASE.2025-10-15T17-29-55Z
(cd /tmp/minio-tag && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $TMPDIR/buckets-tools/linux/minio .)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go install github.com/minio/mc@v0.0.0-20250313080218-cf909e1063a9
cp "$(go env GOPATH)/bin/linux_arm64/mc" $TMPDIR/buckets-tools/linux/mc
```

Use `GOARCH=amd64` (and `linux_amd64`) on x86 nodes.
