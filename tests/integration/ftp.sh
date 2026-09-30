#!/usr/bin/env bash
# The FTP server (--ftp) against MinIO's: both get the same FTP sessions and
# must answer alike, reply for reply, and store the same objects.
#   MINIO_BIN=/path/to/minio MC=/path/to/mc tests/integration/ftp.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "ftp: skipped (set MINIO_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19500}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-ftp-XXXXXX")
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK"/m/d{1..4} "$WORK"/b/d{1..4}
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" \
  --ftp="address=127.0.0.1:$((PORT + 2))" --ftp="passive-port-range=$((PORT + 20))-$((PORT + 59))" \
  "$WORK/m/d{1...4}" >"$WORK/m.log" 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 1))" --ftp="address=127.0.0.1:$((PORT + 3))" \
  --ftp="passive-port-range=$((PORT + 60))-$((PORT + 99))" "$WORK/b/d{1...4}" 2>>"$WORK/b.log" &
PIDS+=($!)
for p in $PORT $((PORT + 1)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
# FTPS: explicit TLS (AUTH TLS), required (force-tls), on a second pair
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" \
  -keyout "$WORK/private.key" -out "$WORK/public.crt" >/dev/null 2>&1
mkdir -p "$WORK"/tm/d{1..4} "$WORK"/tb/d{1..4}
TLSARGS=(--ftp="tls-private-key=$WORK/private.key" --ftp="tls-public-cert=$WORK/public.crt" --ftp="force-tls=true")
MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$((PORT + 10))" \
  --ftp="address=127.0.0.1:$((PORT + 12))" "${TLSARGS[@]}" "$WORK/tm/d{1...4}" >"$WORK/tm.log" 2>&1 &
PIDS+=($!)
"$BIN" server --address "127.0.0.1:$((PORT + 11))" --ftp="address=127.0.0.1:$((PORT + 13))" "${TLSARGS[@]}" \
  "$WORK/tb/d{1...4}" 2>>"$WORK/tb.log" &
PIDS+=($!)
for p in $((PORT + 10)) $((PORT + 11)); do
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
done
python3 "$HERE/ftp_cases.py" "$PORT" rootadmin rootsecret123 "$WORK"
