#!/usr/bin/env bash
# Bucket replication between two clusters, for every pairing of MinIO and
# bucketsd (source -> target): new objects (single-part and multipart, with
# metadata and tags), metadata updates, delete markers, versioned deletes,
# existing objects (resync), SSE-S3 objects, and active-active setups.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/replication.sh [bucketsd]
# PAIRS limits the pairings ("buckets:buckets minio:buckets ...").
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "replication: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19720}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-repl-XXXXXX")
export MC_CONFIG_DIR="$WORK/mc" MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
# the same builtin KMS key on both sides (SSE-S3)
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
export BUCKETS_REPLICATION_MRF_DELAY_MS=500
PIDS=()
pass=0 fail=0
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
MC() { "$MC_BIN" "$@"; }
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL [$PAIR] $*"; }
check() { # name got want
  if [[ "$2" == "$3" ]]; then ok; else bad "$1: got '$2' want '$3'"; fi
}
start() { # kind port alias dir
  mkdir -p "$4"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$2" "$4/d{1...4}" >>"$4.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$2" "$4/d{1...4}" 2>>"$4.log" &
  fi
  PIDS+=($!)
  for _ in $(seq 200); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$2/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
  MC alias set "$3" "http://127.0.0.1:$2" rootadmin rootsecret123 >/dev/null
}
stop_all() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  PIDS=()
}
# jq-free JSON field of `mc stat --json`
field() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"; }
stat() { MC stat --json "$@" 2>/dev/null; }
# versions as "vid:DEL|PUT" lines, newest first
versions() { MC ls --versions --json "$1" 2>/dev/null | python3 -c 'import json,sys
for l in sys.stdin:
    d=json.loads(l)
    if d.get("status") != "success": continue
    print(d["versionId"] + (":DEL" if d.get("isDeleteMarker") else ":PUT"))'; }
wait_for() { # seconds cmd... : retries until the command succeeds
  local n=$(( $1 * 10 )); shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}
repl_status() { stat "$1" | field replicationStatus; }
is_completed() { [[ $(repl_status "$1") == COMPLETED ]]; }

run_pair() { # source-kind target-kind
  PAIR="$1->$2"
  local dir="$WORK/${1}_$2"
  start "$1" "$PORT" a "$dir/a"
  start "$2" "$((PORT + 1))" b "$dir/b"
  MC mb a/src b/dst >/dev/null
  MC version enable a/src >/dev/null
  MC version enable b/dst >/dev/null
  # an object from before replication was configured
  echo existing >"$dir/e"
  MC cp "$dir/e" a/src/existing >/dev/null
  local out
  out=$(MC replicate add a/src --remote-bucket "http://rootadmin:rootsecret123@127.0.0.1:$((PORT + 1))/dst" \
    --priority 1 --replicate "delete,delete-marker,existing-objects" 2>&1)
  check "replicate add" "$out" "Replication configuration rule applied to a/src successfully."
  local arn
  arn=$(MC replicate ls a/src --json | field rule.Destination.Bucket)
  check "rule destination" "${arn##*:}" dst
  check "replication-check" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/src?replication-check" \
    --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)" 200

  # 1. a new object with metadata and tags
  echo hello >"$dir/f"
  MC cp --attr "x-amz-meta-color=blue" --tags "k1=v1&k2=v2" "$dir/f" a/src/obj1 >/dev/null
  wait_for 10 is_completed a/src/obj1 || bad "obj1 not COMPLETED: $(repl_status a/src/obj1)"
  local sa sb
  sa=$(stat a/src/obj1) sb=$(stat b/dst/obj1)
  check "obj1 version" "$(field versionID <<<"$sb")" "$(field versionID <<<"$sa")"
  check "obj1 etag" "$(field etag <<<"$sb")" "$(field etag <<<"$sa")"
  check "obj1 size" "$(field size <<<"$sb")" 6
  check "obj1 mtime" "$(field lastModified <<<"$sb")" "$(field lastModified <<<"$sa")"
  check "obj1 meta" "$(field metadata.X-Amz-Meta-Color <<<"$sb")" blue
  check "obj1 replica" "$(field replicationStatus <<<"$sb")" REPLICA
  check "obj1 tags" "$(MC tag list b/dst/obj1 --json | field tagset.k2)" v2

  # 2. multipart
  head -c $((20 * 1024 * 1024)) /dev/urandom >"$dir/big"
  MC cp "$dir/big" a/src/big >/dev/null
  wait_for 20 is_completed a/src/big || bad "big not COMPLETED: $(repl_status a/src/big)"
  sa=$(stat a/src/big) sb=$(stat b/dst/big)
  check "big version" "$(field versionID <<<"$sb")" "$(field versionID <<<"$sa")"
  check "big etag" "$(field etag <<<"$sb")" "$(field etag <<<"$sa")"
  check "big data" "$(MC cat b/dst/big | md5)" "$(md5 <"$dir/big")"

  # 3. a metadata update
  MC tag set a/src/obj1 "k3=v3" >/dev/null
  wait_for 10 bash -c "[[ \$('$MC_BIN' tag list b/dst/obj1 --json | python3 -c 'import json,sys; print(json.load(sys.stdin).get(\"tagset\",{}).get(\"k3\",\"\"))') == v3 ]]" ||
    bad "tag update not replicated"
  check "tag update version" "$(stat b/dst/obj1 | field versionID)" "$(stat a/src/obj1 | field versionID)"
  check "no new version" "$(versions b/dst/obj1 | wc -l | tr -d ' ')" 1

  # 4. SSE-S3
  MC cp --enc-s3 "a/src/sse" "$dir/f" a/src/sse >/dev/null
  wait_for 10 is_completed a/src/sse || bad "sse not COMPLETED: $(repl_status a/src/sse)"
  check "sse data" "$(MC cat b/dst/sse)" hello
  check "sse encrypted" "$(stat b/dst/sse | field metadata.X-Amz-Server-Side-Encryption)" AES256

  # 5. a delete marker
  MC rm a/src/obj1 >/dev/null
  local dm
  dm=$(versions a/src/obj1 | head -1)
  wait_for 10 bash -c "'$MC_BIN' ls --versions b/dst/obj1 | grep -q DEL" || bad "delete marker not replicated"
  check "marker" "$(versions b/dst/obj1 | head -1)" "$dm"

  # 6. a versioned delete
  local v
  v=$(stat a/src/big | field versionID)
  MC rm --version-id "$v" a/src/big >/dev/null
  wait_for 10 bash -c "! '$MC_BIN' stat --version-id '$v' b/dst/big" || bad "versioned delete not replicated"
  check "purged on source" "$(versions a/src/big | wc -l | tr -d ' ')" 0

  check "status replicated" "$(MC replicate status a/src --json | python3 -c 'import json,sys
d=json.load(sys.stdin); print(sum(v.get("replicationCount",0) for v in d["replicationstats"]["currStats"]["Stats"].values()) > 0)')" True
  # 7. existing objects: resync
  MC replicate resync start a/src --remote-bucket "$arn" >/dev/null 2>&1
  wait_for 20 bash -c "'$MC_BIN' stat b/dst/existing" || bad "existing object not replicated"
  check "existing version" "$(stat b/dst/existing | field versionID)" "$(stat a/src/existing | field versionID)"

  stop_all
}

# active-active: each side replicates to the other
run_active() { # kind-a kind-b
  PAIR="$1<->$2"
  local dir="$WORK/aa_${1}_$2"
  start "$1" "$PORT" a "$dir/a"
  start "$2" "$((PORT + 1))" b "$dir/b"
  MC mb a/rrb b/rrb >/dev/null
  MC version enable a/rrb >/dev/null
  MC version enable b/rrb >/dev/null
  # B -> A first: an object put on A now is on A only, and B proxies to A
  MC replicate add b/rrb --remote-bucket "http://rootadmin:rootsecret123@127.0.0.1:$PORT/rrb" --priority 1 \
    --replicate "delete,delete-marker,existing-objects" >/dev/null 2>&1
  echo only-on-a >"$dir/p"
  MC cp "$dir/p" a/rrb/proxied >/dev/null
  check "proxied GET" "$(MC cat b/rrb/proxied 2>&1)" only-on-a
  local hv
  hv=$(curl -s -I "http://127.0.0.1:$((PORT + 1))/rrb/proxied" --aws-sigv4 "aws:amz:us-east-1:s3" \
    --user rootadmin:rootsecret123 | tr -d '\r' | awk -F': ' 'tolower($1)=="x-amz-version-id"{print $2}')
  check "proxied HEAD version" "$hv" "$(stat a/rrb/proxied | field versionID)"
  MC replicate add a/rrb --remote-bucket "http://rootadmin:rootsecret123@127.0.0.1:$((PORT + 1))/rrb" --priority 1 \
    --replicate "delete,delete-marker,existing-objects" >/dev/null 2>&1
  echo from-a >"$dir/fa"
  echo from-b >"$dir/fb"
  MC cp "$dir/fa" a/rrb/fa >/dev/null
  MC cp "$dir/fb" b/rrb/fb >/dev/null
  wait_for 10 is_completed a/rrb/fa || bad "fa not COMPLETED: $(repl_status a/rrb/fa)"
  wait_for 10 is_completed b/rrb/fb || bad "fb not COMPLETED: $(repl_status b/rrb/fb)"
  check "fa on b" "$(MC cat b/rrb/fa)" from-a
  check "fb on a" "$(MC cat a/rrb/fb)" from-b
  check "fa replica" "$(repl_status b/rrb/fa)" REPLICA
  check "fb replica" "$(repl_status a/rrb/fb)" REPLICA
  sleep 1 # no ping-pong: one version each side
  check "fa versions on a" "$(versions a/rrb/fa | wc -l | tr -d ' ')" 1
  check "fb versions on b" "$(versions b/rrb/fb | wc -l | tr -d ' ')" 1
  # a delete marker made on B reaches A
  MC rm b/rrb/fa >/dev/null
  wait_for 10 bash -c "'$MC_BIN' ls --versions a/rrb/fa | grep -q DEL" || bad "marker from b not on a"
  check "marker ids" "$(versions a/rrb/fa | head -1)" "$(versions b/rrb/fa | head -1)"
  stop_all
}

PAIRS=${PAIRS:-"buckets:buckets minio:buckets buckets:minio minio:minio"}
for p in $PAIRS; do run_pair "${p%%:*}" "${p##*:}"; done
for p in ${ACTIVE:-$PAIRS}; do run_active "${p%%:*}" "${p##*:}"; done
echo "replication: $pass passed, $fail failed"
[[ $fail == 0 ]]
