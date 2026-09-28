#!/usr/bin/env bash
# A 4-node cluster on one machine (a port and 2 drives per node, one 8-drive
# erasure set, EC 4+4): bootstrap and format by the first node, S3 through
# any node, distributed locks, a node going down (reads and writes carry on),
# and the node coming back (it rejoins and gets healed).
#   tests/integration/cluster.sh [bucketsd]
# TLS=1 runs the whole cluster, internode traffic included, over HTTPS.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
BASE=${PORT:-19800}
AK=clusteruser
SK=clustersecret1
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-cluster-XXXXXX")
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK")
PIDS=(0 0 0 0 0)
cleanup() {
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

md5of() { (md5sum 2>/dev/null || md5 -r) | cut -d' ' -f1; }
SCHEME=http
TLSARGS=()
if [[ -n "${TLS:-}" ]]; then
  SCHEME=https
  mkdir -p "$WORK/certs/CAs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes \
    -days 1 -keyout "$WORK/certs/private.key" -out "$WORK/certs/public.crt" -subj /CN=localhost \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null
  cp "$WORK/certs/public.crt" "$WORK/certs/CAs/cluster.crt" # peers trust each other
  TLSARGS=(--certs-dir "$WORK/certs")
  S3+=(--cacert "$WORK/certs/public.crt")
fi
CURLTLS=()
[[ -n "${TLS:-}" ]] && CURLTLS=(--cacert "$WORK/certs/public.crt")
ep() { echo "$SCHEME://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do for d in 1 2; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d$d"); done; done
start() { # node
  BUCKETS_SCANNER_INTERVAL=1 BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK "$BIN" server --address "127.0.0.1:$((BASE + $1))" \
    ${TLSARGS[@]+"${TLSARGS[@]}"} "${ENDPOINTS[@]}" 2>>"$WORK/log$1" &
  PIDS[$1]=$!
}
stop() { kill "${PIDS[$1]}"; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
ready() { [[ $(curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$(ep "$1")/minio/health/ready") == 200 ]]; }
until_true() { for _ in $(seq 150); do eval "$1" && return 0; sleep 0.1; done; return 1; }
pass=0
fail=0
expect() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$@"; }

head -c 5000000 /dev/urandom >"$WORK/big"
head -c 700 /dev/urandom >"$WORK/small"
BIG=$(md5of <"$WORK/big")
SMALL=$(md5of <"$WORK/small")

echo "== bootstrap"
for n in 4 3 2 1; do start "$n"; done # the formatting node starts last
until_true 'ready 1 && ready 2 && ready 3 && ready 4' || true
ok=0; for n in 1 2 3 4; do ready "$n" && ok=$((ok + 1)); done
expect "all four nodes ready" "$ok" 4
ids=$(for n in 1 2 3 4; do for d in 1 2; do sed -n 's/.*"id":"\([^"]*\)".*/\1/p' "$WORK/n$n/d$d/.minio.sys/format.json"; done; done | sort -u | wc -l | tr -d ' ')
expect "one deployment across all drives" "$ids" 1
expect "cluster health" "$(curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$(ep 3)/minio/health/cluster")" 200

echo "== S3 through any node"
expect "create bucket via node 1" "$(status -X PUT "$(ep 1)/clusterbucket")" 200
expect "bucket visible via node 4" "$(status -I "$(ep 4)/clusterbucket")" 200
expect "put large via node 2" "$(status -T "$WORK/big" "$(ep 2)/clusterbucket/big.bin")" 200
expect "put small via node 3" "$(status -T "$WORK/small" "$(ep 3)/clusterbucket/small.bin")" 200
expect "read large via node 4" "$(curl -s "${S3[@]}" "$(ep 4)/clusterbucket/big.bin" | md5of)" "$BIG"
expect "read small via node 1" "$(curl -s "${S3[@]}" "$(ep 1)/clusterbucket/small.bin" | md5of)" "$SMALL"
shards=0; for n in 1 2 3 4; do for d in 1 2; do [[ -f "$WORK/n$n/d$d/clusterbucket/big.bin/xl.meta" ]] && shards=$((shards + 1)); done; done
expect "large object spread over all 8 drives" "$shards" 8
keys=$(curl -s "${S3[@]}" "$(ep 3)/clusterbucket?list-type=2" | grep -o '<Key>' | wc -l | tr -d ' ')
expect "listing via node 3" "$keys" 2

echo "== racing writers on different nodes"
for i in $(seq 1 8); do head -c $((200000 + i)) /dev/urandom >"$WORK/v$i"; md5of <"$WORK/v$i" >>"$WORK/versions"; done
pids=()
for i in $(seq 1 8); do
  n=$(( (i % 4) + 1 ))
  curl -s -o /dev/null "${S3[@]}" -T "$WORK/v$i" "$(ep "$n")/clusterbucket/hot" & pids+=($!)
done
wait "${pids[@]}"
a=$(curl -s "${S3[@]}" "$(ep 1)/clusterbucket/hot" | md5of)
b=$(curl -s "${S3[@]}" "$(ep 3)/clusterbucket/hot" | md5of)
expect "nodes agree on the winner" "$a" "$b"
expect "the winner is one of the uploads" "$(grep -c "^$a\$" "$WORK/versions")" 1

echo "== a node goes down"
stop 4
expect "read with node 4 down" "$(curl -s "${S3[@]}" "$(ep 1)/clusterbucket/big.bin" | md5of)" "$BIG"
head -c 3000000 /dev/urandom >"$WORK/during"
expect "write with node 4 down" "$(status -T "$WORK/during" "$(ep 2)/clusterbucket/during.bin")" 200
expect "read it back" "$(curl -s "${S3[@]}" "$(ep 3)/clusterbucket/during.bin" | md5of)" "$(md5of <"$WORK/during")"
expect "cluster still has write quorum" "$(curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$(ep 1)/minio/health/cluster")" 200
expect "node 4 missed the write" "$([[ -e "$WORK/n4/d1/clusterbucket/during.bin" ]] && echo has || echo missing)" missing

echo "== the node comes back"
start 4
until_true 'ready 4' || true
expect "node 4 ready again" "$(ready 4 && echo yes)" yes
# Nobody reads the object: the scanner must notice and heal it.
until_true '[[ -f "$WORK/n4/d1/clusterbucket/during.bin/xl.meta" && -f "$WORK/n4/d2/clusterbucket/during.bin/xl.meta" ]]' || true
expect "the scanner healed what node 4 missed" "$([[ -f "$WORK/n4/d2/clusterbucket/during.bin/xl.meta" ]] && echo healed)" healed
expect "read via node 4" "$(curl -s "${S3[@]}" "$(ep 4)/clusterbucket/during.bin" | md5of)" "$(md5of <"$WORK/during")"

echo "== two nodes down: beyond write quorum"
stop 3
stop 4
t0=$(date +%s)
code=$(status -T "$WORK/small" "$(ep 1)/clusterbucket/nope.bin")
expect "write refused without quorum" "$([[ $code == 503 ]] && echo refused || echo "$code")" refused
expect "refused promptly" "$(( $(date +%s) - t0 < 5 ))" 1
expect "reads still work (EC 4+4)" "$(curl -s "${S3[@]}" "$(ep 2)/clusterbucket/big.bin" | md5of)" "$BIG"
expect "cluster health reports it" "$(curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$(ep 1)/minio/health/cluster")" 503
start 3
start 4

for n in 1 2 3 4; do stop "$n"; done

if [[ -n "${MINIO_BIN:-}" && -z "${TLS:-}" ]]; then
  echo "== a real MinIO cluster reads the drives"
  for n in 1 2 3 4; do
    MINIO_CI_CD=on MINIO_ROOT_USER=$AK MINIO_ROOT_PASSWORD=$SK "$MINIO_BIN" server --address "127.0.0.1:$((BASE + n))" \
      --console-address "127.0.0.1:$((BASE + 10 + n))" "${ENDPOINTS[@]}" >"$WORK/minio$n.log" 2>&1 &
    PIDS[$n]=$!
  done
  until_true 'ready 1 && ready 2 && ready 3 && ready 4' || true
  # MinIO's readiness can pass a moment before buckets answer: wait for a 200.
  until_true '[[ $(status "$(ep 3)/clusterbucket/big.bin") == 200 && $(status "$(ep 2)/clusterbucket/during.bin") == 200 ]]' || true
  expect "minio reads the large object" "$(curl -s "${S3[@]}" "$(ep 3)/clusterbucket/big.bin" | md5of)" "$BIG"
  expect "minio reads the object healed by the scanner" "$(curl -s "${S3[@]}" "$(ep 2)/clusterbucket/during.bin" | md5of)" \
    "$(md5of <"$WORK/during")"
  for n in 1 2 3 4; do stop "$n"; done
fi
if cat "$WORK"/log* | grep -q 'Sanitizer\|runtime error'; then
  fail=$((fail + 1)); echo "  FAIL  sanitizer report:"; cat "$WORK"/log* | grep -A20 'Sanitizer\|runtime error' | head -40
fi
echo "cluster: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
