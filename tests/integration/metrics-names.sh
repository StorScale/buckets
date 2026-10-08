#!/usr/bin/env bash
# The metrics gate: the same deployment and workload on MinIO and bucketsd,
# then the metric families and their label names on every endpoint (v2
# cluster, node, bucket and resource; v3 and its paths) must match.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/metrics-names.sh [bucketsd]
# Skips (exit 0) without MINIO_BIN and MC_BIN.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "metrics-names: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19860}
SINK_PORT=$((PORT + 5))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-metrics-XXXXXX")
EP="http://127.0.0.1:$PORT"
PID= SINK=
PIDS=()
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"} $SINK; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_PROMETHEUS_AUTH_TYPE=public MINIO_SCANNER_SPEED=fastest
export MINIO_KMS_SECRET_KEY=metrics-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
export MINIO_NOTIFY_WEBHOOK_ENABLE_primary=on MINIO_NOTIFY_WEBHOOK_ENDPOINT_primary="http://127.0.0.1:$SINK_PORT/hook"
export MC_CONFIG_DIR="$WORK/mc"
python3 "$HERE/webhooksink.py" "$SINK_PORT" "$WORK/sink.log" &
SINK=$!
if [[ -n "${PLUGIN:-}" ]]; then # an identity plugin (the IAM plugin metrics)
  PLUGIN_PORT=$((PORT + 6))
  cat >"$WORK/idp.py" <<'PY'
import http.server, json, sys, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length') or 0))
        tok = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get('token', [''])[0]
        if tok == 'good-token':
            return self.reply(200, {'user': 'carol', 'maxValiditySeconds': 3600})
        self.reply(403, {'reason': 'unknown token'})
    def reply(self, code, doc):
        b = json.dumps(doc).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
  python3 "$WORK/idp.py" "$PLUGIN_PORT" &
  SINK="$SINK $!"
  export MINIO_IDENTITY_PLUGIN_URL="http://127.0.0.1:$PLUGIN_PORT/idp" MINIO_IDENTITY_PLUGIN_ROLE_POLICY=readonly
  export MINIO_IDENTITY_PLUGIN_ROLE_ID=metricsplugin
fi
MC() { "$MC_BIN" --quiet --no-color "$@"; }

NODES=${NODES:-1} # 4: a distributed deployment, one drive per node
PIDS=()
EPS=()
start_node() { # kind n
  local port=$((PORT + 10 * ($2 - 1)))
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$port" \
      --console-address "127.0.0.1:$((port + 1))" "${EPS[@]}" >>"$WORK/$1.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$port" "${EPS[@]}" 2>>"$WORK/$1.log" &
  fi
  PIDS[$(($2 - 1))]=$!
}
healthy() { # every node answers /minio/health/cluster
  for _ in $(seq 900); do
    local ok=1
    for n in $(seq "$NODES"); do
      [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$((PORT + 10 * (n - 1)))/minio/health/cluster") == 200 ]] || ok=0
    done
    [[ $ok == 1 ]] && return 0
    sleep 0.1
  done
  return 1
}
start() { # minio|buckets drives-dir
  EPS=()
  if [[ $NODES -gt 1 ]]; then
    for n in $(seq "$NODES"); do mkdir -p "$2/n$n"; EPS+=("http://127.0.0.1:$((PORT + 10 * (n - 1)))$2/n$n"); done
  else
    mkdir -p "$2"/d{1..4}
    EPS=("$2/d{1...4}")
  fi
  for n in $(seq "$NODES"); do start_node "$1" "$n"; done
  PID=${PIDS[0]}
  healthy || { echo "$1 did not start"; exit 1; }
}
TPID=
stop() {
  kill "${PIDS[@]}" $TPID; wait "${PIDS[@]}" $TPID 2>/dev/null || true
  PIDS=(); PID=; TPID=
}

workload() {
  MC alias set m "$EP" rootadmin rootsecret123 >/dev/null
  MC mb m/mbkt >/dev/null
  MC mb --with-versioning m/vbkt >/dev/null
  MC event add m/mbkt arn:minio:sqs::primary:webhook --event put >/dev/null
  head -c 1000 /dev/urandom >"$WORK/small"
  head -c 20000000 /dev/urandom >"$WORK/big" # multipart
  MC cp "$WORK/small" m/mbkt/a >/dev/null
  MC cp "$WORK/big" m/mbkt/big >/dev/null
  MC cp "$WORK/small" m/vbkt/v >/dev/null
  MC cp "$WORK/small" m/vbkt/v >/dev/null
  MC cat m/mbkt/a >/dev/null
  MC ls m/mbkt >/dev/null
  MC stat m/mbkt/missing >/dev/null 2>&1 || true
  MC rm m/vbkt/v >/dev/null
  MC quota set m/mbkt --size 1GiB >/dev/null 2>&1 || true
  MC admin user add m metricsuser metricspass123 >/dev/null
  curl -s -o /dev/null "$EP/mbkt/a" # anonymous: AccessDenied
  if [[ -n "${PLUGIN:-}" ]]; then
    for t in good-token bad-token; do
      curl -s -o /dev/null -X POST "$EP/" -d "Action=AssumeRoleWithCustomToken&Version=2011-06-15&Token=$t&RoleArn=arn:minio:iam:::role/idp-metricsplugin"
    done
  fi
  # replication to a second deployment of the same kind (the replication metrics)
  local tport=$((PORT + 50)) tdir="$WORK/$1-target"
  mkdir -p "$tdir"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$tport" \
      --console-address "127.0.0.1:$((tport + 1))" "$tdir/d{1...4}" >>"$WORK/$1-target.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$tport" "$tdir/d{1...4}" 2>>"$WORK/$1-target.log" &
  fi
  TPID=$!
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$tport/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
  MC alias set t "http://127.0.0.1:$tport" rootadmin rootsecret123 >/dev/null
  MC mb --with-versioning t/rbkt >/dev/null
  MC mb --with-versioning m/rsrc >/dev/null
  MC replicate add m/rsrc --remote-bucket "http://rootadmin:rootsecret123@127.0.0.1:$tport/rbkt" --priority 1 >/dev/null
  MC cp "$WORK/small" m/rsrc/r1 >/dev/null
  MC cp "$WORK/small" m/rsrc/r2 >/dev/null
  if [[ $NODES -gt 1 ]]; then # writes that miss a node, healed (MRF) once it is back
    kill "${PIDS[$((NODES - 1))]}"; wait "${PIDS[$((NODES - 1))]}" 2>/dev/null || true
    for i in 1 2 3; do MC cp "$WORK/small" "m/mbkt/degraded$i" >/dev/null; done
    start_node "$1" "$NODES"
    healthy
  fi
  sleep 15 # a scanner cycle (usage), resource sampling, healing
}

fetch() { # kind
  local d="$WORK/$1"
  mkdir -p "$d"
  for p in v2/metrics/cluster v2/metrics/node v2/metrics/bucket v2/metrics/resource \
    metrics/v3 metrics/v3/api/requests metrics/v3/system/drive metrics/v3/cluster/health \
    metrics/v3/bucket/api/mbkt metrics/v3/bucket/replication/mbkt metrics/v3/bucket/replication/rsrc \
    metrics/v3/debug/go; do
    local f="$d/$(echo "$p" | tr / _)"
    curl -s "$EP/minio/$p" >"$f.txt"
    python3 "$HERE/metrics/signatures.py" --help <"$f.txt" >"$f.sig"
  done
}

for kind in minio buckets; do
  start "$kind" "$WORK/$kind-data"
  workload "$kind"
  fetch "$kind"
  stop
done

# Families whose presence depends on timing rather than behaviour are not
# compared: v3 leaves out zero values, so a duration in whole milliseconds
# comes and goes with the machine's speed; internode dial errors depend on
# the order nodes start in; and whether a heal attempt fails depends on
# whether it ran before the stopped node was back; a replication's upload
# latency in whole milliseconds is 0 (and left out) on a fast enough machine.
# shown only while non-zero, which depends on the moment: I/O waiting on a drive, and bytes read from the drives
# rather than the page cache
TIMING_FAMILIES='minio_cluster_iam_last_sync_duration_millis|minio_system_network_internode_dial_errors_total|minio_heal_objects_errors_total|minio_bucket_replication_latency_ms|minio_system_drive_waiting_io|minio_system_process_io_read_bytes|minio_node_io_read_bytes'
TIMING="^(\\(help\\) )?($TIMING_FAMILIES)[ :]"
# Buckets' own families (buckets_*, src/metrics/buckets-catalog.tsv) are additions MinIO does not have; the
# compatibility promise allows new metrics, so they are not compared either.
OWN="^(\\(help\\) )?buckets_"
for f in "$WORK"/minio/*.sig "$WORK"/buckets/*.sig; do
  grep -Ev "$TIMING" "$f" | grep -Ev "$OWN" >"$f.tmp" || true
  mv "$f.tmp" "$f"
done
fails=0
for f in "$WORK"/minio/*.sig; do
  b="$WORK/buckets/$(basename "$f")"
  name=$(basename "$f" .sig)
  if diff -u "$f" "$b" >"$WORK/$name.diff"; then
    echo "  ok    $name ($(wc -l <"$f" | tr -d ' ') families)"
  else
    echo "  FAIL  $name"; sed 's/^/        /' "$WORK/$name.diff" | head -n "${DIFF_LINES:-40}"
    fails=$((fails + 1))
  fi
done
# every sample bucketsd writes is in MinIO's catalog (unknown names are dropped and logged)
if grep -q "outside the catalog" "$WORK/buckets.log"; then
  echo "  FAIL  samples outside MinIO's catalog:"; grep "outside the catalog" "$WORK/buckets.log" | head -3
  fails=$((fails + 1))
fi
echo "metrics-names: $fails of $(ls "$WORK"/minio/*.sig | wc -l | tr -d ' ') endpoints differ"
[[ $fails -eq 0 ]]
