#!/usr/bin/env bash
# Regenerates src/metrics/minio-catalog.tsv from a MinIO source tree: every
# metric MinIO defines, as "V2<TAB>endpoint<TAB>name<TAB>type<TAB>help" and
# "V3<TAB>path<TAB>name<TAB>type<TAB>help<TAB>labels". Needs Go and MinIO's
# modules; nothing in the MinIO tree is modified (the dump is an overlay).
#   tools/metrics-catalog/run.sh ~/minio
set -euo pipefail
MINIO=${1:?usage: run.sh <minio source>}
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/../../src/metrics/minio-catalog.tsv"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export CGO_ENABLED=0 GOFLAGS=-mod=mod
GO111MODULE=off go run "$HERE/gen.go" "$MINIO/cmd" "$WORK/zz_dump_test.go"
printf '{"Replace":{"%s":"%s"}}' "$MINIO/cmd/zz_dump_test.go" "$WORK/zz_dump_test.go" >"$WORK/overlay.json"
# Descriptions built from local variables do not compile outside their
# function: drop them (the run-time names above cover the ones that matter).
for _ in $(seq 20); do
  bad=$(cd "$MINIO" && go vet -overlay "$WORK/overlay.json" ./cmd 2>&1 | grep -oE "zz_dump_test.go:[0-9]+" | cut -d: -f2 | sort -un || true)
  [[ -z "$bad" ]] && break
  for l in $(echo "$bad" | sort -rn); do sed -i.bak "${l}s|^|// |" "$WORK/zz_dump_test.go"; done
done
(cd "$MINIO" && go test -v -overlay "$WORK/overlay.json" -run TestDumpMetricCatalog -count=1 ./cmd) |
  grep -E '^V[23]	' | LC_ALL=C sort -u >"$OUT"
echo "$(wc -l <"$OUT" | tr -d ' ') entries -> $OUT"
