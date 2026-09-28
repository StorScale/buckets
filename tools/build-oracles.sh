#!/usr/bin/env bash
# Builds the compatibility oracles from source: the last MinIO release, the
# matching mc client, and MinIO's xl-meta decoder. Needs Go (>= 1.24) and git.
#   tools/build-oracles.sh [OUT_DIR]      (default: .oracles)
# Then:  MC_BIN=.oracles/mc MINIO_BIN=.oracles/minio tests/integration/interop.sh
set -euo pipefail
OUT=${1:-.oracles}
MINIO_TAG=RELEASE.2025-10-15T17-29-55Z
MC_TAG=RELEASE.2025-08-13T08-35-41Z
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
SRC=$OUT/src
mkdir -p "$SRC"
export CGO_ENABLED=0 # MinIO's cgo CPU probe crashes on recent macOS

fetch() { [[ -d "$SRC/$1" ]] || git clone -q --depth 1 --branch "$2" "https://github.com/minio/$1.git" "$SRC/$1"; }
fetch minio "$MINIO_TAG"
fetch mc "$MC_TAG"
(cd "$SRC/minio" && go build -o "$OUT/minio" .)
(cd "$SRC/mc" && go build -o "$OUT/mc" .)
(cd "$SRC/minio/docs/debugging/xl-meta" && { [[ -f go.mod ]] || go mod init xlmeta >/dev/null 2>&1; } && go mod tidy >/dev/null 2>&1 && go build -o "$OUT/xl-meta" .)
echo "oracles in $OUT: minio mc xl-meta"
