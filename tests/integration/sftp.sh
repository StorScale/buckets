#!/usr/bin/env bash
# The SFTP server (--sftp) against MinIO's: both get the same SFTP sessions
# (password, service account and certificate logins; every request pkg/sftp
# clients send) and must answer alike and store the same objects.
#   MINIO_BIN=/path/to/minio MC=/path/to/mc SFTPCLIENT=/path/to/sftpclient tests/integration/sftp.sh [bucketsd]
# (SFTPCLIENT: tests/integration/sftpclient built, see its main.go)
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${SFTPCLIENT:-}" ]]; then
  echo "sftp: skipped (set MINIO_BIN and SFTPCLIENT)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19600}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-sftp-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
ssh-keygen -q -t ed25519 -N "" -f "$WORK/hostkey"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/ca" -C ca
ARGS=(--sftp="ssh-private-key=$WORK/hostkey" --sftp="trusted-user-ca-key=$WORK/ca.pub")
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" \
  --sftp="address=127.0.0.1:$((PORT + 2))" "${ARGS[@]}" "$WORK/m/d{1...4}" >"$WORK/m.log" 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 1))" --sftp="address=127.0.0.1:$((PORT + 3))" "${ARGS[@]}" \
  "$WORK/b/d{1...4}" 2>>"$WORK/b.log" &
PIDS+=($!)
for p in $PORT $((PORT + 1)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/sftp_cases.py" "$PORT" rootadmin rootsecret123 "$WORK"
