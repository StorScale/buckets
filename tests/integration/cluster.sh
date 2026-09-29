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

if [[ -z "${TLS:-}" ]]; then
  echo "== trace, logs and events from every node (mc admin trace, mc admin logs, mc event listen)"
  HERE=$(cd "$(dirname "$0")" && pwd)
  python3 "$HERE/listen.py" "$(ep 1)" "$AK" "$SK" /minio/admin/v3/trace "s3=true&err=false&threshold=0s" >"$WORK/trace.raw" &
  LT=$!
  python3 "$HERE/listen.py" "$(ep 1)" "$AK" "$SK" /minio/admin/v3/log "limit=5&logType=ALL" >"$WORK/log.raw" &
  LA=$!
  python3 "$HERE/listen.py" "$(ep 1)" "$AK" "$SK" /minio/admin/v3/log "node=127.0.0.1:$((BASE + 3))" >"$WORK/log3.raw" &
  LN=$!
  sleep 1.5
  for n in 1 2 3 4; do status -X PUT "$(ep "$n")/tracebucket$n" >/dev/null; done
  sleep 1.5
  kill $LT $LA $LN 2>/dev/null || true; wait $LT $LA $LN 2>/dev/null || true
  nodes() { grep -o "\"$1\":\"[^\"]*\"" "$2" | sort -u | wc -l | tr -d ' '; }
  expect "trace records from all four nodes" "$(grep -c '"funcname":"s3.PutBucket"' "$WORK/trace.raw")/$(nodes nodename "$WORK/trace.raw")" 4/4
  expect "log records from all four nodes" "$(nodes node "$WORK/log.raw")" 4
  expect "log records from the named node only" "$(grep -o '"node":"[^"]*"' "$WORK/log3.raw" | sort -u)" "\"node\":\"127.0.0.1:$((BASE + 3))\""
  python3 "$HERE/listen.py" "$(ep 1)" "$AK" "$SK" / "events=s3:ObjectCreated:*" >"$WORK/listen.raw" &
  LT=$!
  python3 "$HERE/listen.py" "$(ep 1)" "$AK" "$SK" /tracebucket3 "events=s3:ObjectCreated:*&suffix=.txt&ping=1" >"$WORK/listen3.raw" &
  LA=$!
  sleep 1.5
  for n in 1 2 3 4; do status -T "$WORK/small" "$(ep "$n")/tracebucket$n/o$n.txt" >/dev/null; done
  status -T "$WORK/small" "$(ep 4)/tracebucket3/other.bin" >/dev/null
  sleep 1.5
  kill $LT $LA 2>/dev/null || true; wait $LT $LA 2>/dev/null || true
  expect "events put through every node reach a listener on node 1" "$(grep -o '"key":"[^"]*"' "$WORK/listen.raw" | sort | tr '\n' ' ')" '"key":"o1.txt" "key":"o2.txt" "key":"o3.txt" "key":"o4.txt" "key":"other.bin" '
  expect "a bucket listener gets its bucket's matching events only" "$(grep -o '"key":"[^"]*"' "$WORK/listen3.raw" | tr '\n' ' ')" '"key":"o3.txt" '
  for n in 1 2 3 4; do status -X DELETE "$(ep "$n")/tracebucket$n/o$n.txt" >/dev/null; done
  status -X DELETE "$(ep 1)/tracebucket3/other.bin" >/dev/null
  for n in 1 2 3 4; do status -X DELETE "$(ep "$n")/tracebucket$n" >/dev/null; done
fi

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

echo "== IAM and bucket metadata across nodes"
# Node 2 caches "no policy" first, so a pass proves the peer notification.
anon() { curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$@"; }
expect "anonymous read before policy (node 2)" "$(anon "$(ep 2)/clusterbucket/small.bin")" 403
echo '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::clusterbucket/*"}]}' >"$WORK/bp.json"
expect "put bucket policy (node 1)" "$(status -X PUT -T "$WORK/bp.json" "$(ep 1)/clusterbucket?policy")" 204
sleep 1 # well inside the 5 s metadata TTL: only the notification can explain a change
expect "anonymous read after policy (node 2)" "$(anon "$(ep 2)/clusterbucket/small.bin")" 200
expect "delete bucket policy (node 3)" "$(status -X DELETE "$(ep 3)/clusterbucket?policy")" 204
sleep 1
expect "anonymous read after delete (node 2)" "$(anon "$(ep 2)/clusterbucket/small.bin")" 403
r=$(curl -s --aws-sigv4 "aws:amz:us-east-1:sts" --user "$AK:$SK" ${CURLTLS[@]+"${CURLTLS[@]}"} -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" --data "Action=AssumeRole&Version=2011-06-15" "$(ep 1)/")
tak=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$r")
tsk=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$r")
ttok=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$r")
expect "STS credentials from node 1 work on node 3" "$(anon --aws-sigv4 "aws:amz:us-east-1:s3" --user "$tak:$tsk" \
  -H "X-Amz-Security-Token: $ttok" "$(ep 3)/clusterbucket/small.bin")" 200
if [[ -n "${MC_BIN:-}" ]]; then
  mcc() { "$MC_BIN" --config-dir "$WORK/mc" ${TLS:+--insecure} "$@"; }
  for n in 1 2 3 4; do mcc alias set "n$n" "$(ep "$n")" "$AK" "$SK" >/dev/null; done
  mcc admin user add n1 dora dorasecret123 >/dev/null
  mcc admin policy attach n2 readonly --user dora >/dev/null
  dora() { anon --aws-sigv4 "aws:amz:us-east-1:s3" --user dora:dorasecret123 "$@"; }
  expect "user from node 1, policy from node 2, read on node 4" "$(dora "$(ep 4)/clusterbucket/small.bin")" 200
  mcc admin user disable n3 dora >/dev/null
  until_true '[[ $(dora "$(ep 4)/clusterbucket/small.bin") == 403 ]]' || true
  expect "disabled on node 3, refused on node 4" "$(dora "$(ep 4)/clusterbucket/small.bin")" 403
  mcc admin user rm n2 dora >/dev/null
  info=$(mcc admin info n2 --json)
  expect "admin info: servers online" "$(grep -o '"state":"online"' <<<"$info" | wc -l | tr -d ' ')" 4
  expect "admin info: drives online" "$(sed -n 's/.*"onlineDisks":\([0-9]*\).*/\1/p' <<<"$info")" 8
  mcc admin service freeze n1 >/dev/null
  sleep 1
  expect "frozen via node 1, node 3 holds S3 calls" "$(status --max-time 2 "$(ep 3)/clusterbucket/small.bin")" 000
  expect "frozen: health still answers" "$(anon "$(ep 3)/minio/health/live")" 200
  mcc admin service unfreeze n2 >/dev/null
  sleep 1
  expect "unfrozen via node 2, node 3 serves" "$(status "$(ep 3)/clusterbucket/small.bin")" 200
else
  echo "  (set MC_BIN for the admin API checks)"
fi

echo "== a node goes down"
stop 4
expect "read with node 4 down" "$(curl -s "${S3[@]}" "$(ep 1)/clusterbucket/big.bin" | md5of)" "$BIG"
head -c 3000000 /dev/urandom >"$WORK/during"
expect "write with node 4 down" "$(status -T "$WORK/during" "$(ep 2)/clusterbucket/during.bin")" 200
expect "read it back" "$(curl -s "${S3[@]}" "$(ep 3)/clusterbucket/during.bin" | md5of)" "$(md5of <"$WORK/during")"
expect "cluster still has write quorum" "$(curl -s -o /dev/null -w '%{http_code}' ${CURLTLS[@]+"${CURLTLS[@]}"} "$(ep 1)/minio/health/cluster")" 200
expect "node 4 missed the write" "$([[ -e "$WORK/n4/d1/clusterbucket/during.bin" ]] && echo has || echo missing)" missing
if [[ -n "${MC_BIN:-}" ]]; then
  info=$(mcc admin info n1 --json)
  expect "admin info: node 4 offline" "$(grep -o '"state":"offline","endpoint":"127.0.0.1:'"$((BASE + 4))"'"' <<<"$info" | wc -l | tr -d ' ')" 1
  expect "admin info: drives offline" "$(sed -n 's/.*"offlineDisks":\([0-9]*\).*/\1/p' <<<"$info")" 2
fi

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
