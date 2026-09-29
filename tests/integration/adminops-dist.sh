#!/usr/bin/env bash
# The distributed-only admin APIs against MinIO: a 4-node cluster of each on
# this machine (a port and 2 drives per node, one 8-drive set), compared on
# top locks, forced unlocks, heal sequences followed through another node,
# storage info and background heal status across nodes.
#   MINIO_BIN=/path/to/minio tests/integration/adminops-dist.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "adminops-dist: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
BASE=${PORT:-19820}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-adminops-dist-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
# MinIO on BASE+1..4, bucketsd on BASE+11..14
MEPS=() BEPS=()
for n in 1 2 3 4; do
  for d in 1 2; do
    MEPS+=("http://127.0.0.1:$((BASE + n))$WORK/m/n$n/d$d")
    BEPS+=("http://127.0.0.1:$((BASE + 10 + n))$WORK/b/n$n/d$d")
    mkdir -p "$WORK/m/n$n/d$d" "$WORK/b/n$n/d$d"
  done
done
for n in 1 2 3 4; do
  MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$((BASE + n))" "${MEPS[@]}" \
    >"$WORK/m$n.log" 2>&1 &
  PIDS+=($!)
  "$BIN" server --address "127.0.0.1:$((BASE + 10 + n))" "${BEPS[@]}" 2>>"$WORK/b$n.log" &
  PIDS+=($!)
done
for p in $((BASE + 1)) $((BASE + 2)) $((BASE + 3)) $((BASE + 4)) $((BASE + 11)) $((BASE + 12)) $((BASE + 13)) $((BASE + 14)); do
  for _ in $(seq 600); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/cluster") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/adminops_dist_cases.py" "$BASE" rootadmin rootsecret123 "$WORK"
