#!/usr/bin/env bash
# Batch jobs against MinIO: every scenario runs on a MinIO server and on
# bucketsd, and what mc and the admin API report must be the same:
#  - mc batch start|list|describe|status|cancel and their errors (describe's
#    YAML, status JSON), with replicate, keyrotate and expire definitions;
#  - expire (rules, tags, purge.retainVersions, deleted objects);
#  - keyrotate (SSE-S3 and SSE-KMS), and each server reading what the other
#    rotated;
#  - replicate pushed and pulled between every pairing of MinIO and bucketsd
#    (versions, delete markers, metadata, tags, multipart; MinIO pushes small
#    objects as snowball archives, which bucketsd extracts);
#  - job files written by one server listed, described and resumed by the
#    other; a job resumed after a restart; mc batch status's metrics stream.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/batch.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "batch: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19880}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-batch-XXXXXX")
export MC_CONFIG_DIR="$WORK/mc" MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
export _BUCKETS_BATCH_RESUME_DELAY=0s
PIDS=()
pass=0 fail=0
CASE=batch
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
MC() { "$MC_BIN" "$@"; }
ok() { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); echo "FAIL [$CASE] $*"; }
check() { if [[ "$2" == "$3" ]]; then ok; else bad "$1: got '$2' want '$3'"; fi; }
same() { # name file-a file-b
  if diff "$2" "$3" >/dev/null; then ok; else bad "$1 differs:"; diff "$2" "$3" | head -20; fi
}
start() { # kind port alias dir
  mkdir -p "$4"/d{1..4}
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$2" "$4/d{1...4}" >>"$4.log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$2" "$4/d{1...4}" 2>>"$4.log" &
  fi
  PIDS+=($!)
  eval "PID_$3=$!"
  for _ in $(seq 300); do
    [[ $(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$2/minio/health/ready") == 200 ]] && break
    sleep 0.1
  done
  MC alias set "$3" "http://127.0.0.1:$2" rootadmin rootsecret123 >/dev/null
}
stop() { local v="PID_$1"; kill "${!v}" 2>/dev/null; wait "${!v}" 2>/dev/null; }
admin() { # port path
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 "http://127.0.0.1:$1/minio/admin/v3/$2"
}
job_ids() { MC batch list "$1" --json | python3 -c 'import json,sys
for l in sys.stdin:
    for j in json.loads(l).get("jobs") or []: print(j["id"])'; }
# normalizes job IDs and times
norm() { sed -E 's/(replicate|keyrotate|expire)-[A-Za-z0-9]{22}:-?[0-9]+/\1-ID/g; s/[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9:.]+( \+0000 UTC|Z)/TIME/g; s/"RequestId":"[^"]*","HostId":"[^"]*"//'; }
wait_done() { # alias port
  for _ in $(seq 100); do
    local all=1
    for id in $(job_ids "$1"); do
      [[ $(admin "$2" "status-job?jobId=$id" | python3 -c 'import json,sys
try:
    m = json.load(sys.stdin)["LastMetric"]
    print(m["complete"] or m["failed"])
except Exception: print(False)' 2>/dev/null) == True ]] || all=0
    done
    [[ $all == 1 ]] && return 0
    sleep 0.2
  done
  return 1
}
statuses() { # alias port: the jobs' metrics, sorted, IDs and times normalized (which object
  # finished last depends on the workers)
  for id in $(job_ids "$1"); do admin "$2" "status-job?jobId=$id"; echo; done | norm |
    sed -E 's/"lastObject":"[^"]*"//' | sort
}

# ---- job definitions, the admin API and its errors ----
defs() { # kind -> out file
  CASE="defs $1"
  local dir="$WORK/defs_$1" port=$PORT out=$2
  start "$1" "$port" m "$dir"
  MC mb m/srcbkt m/dstbkt >/dev/null
  cat >"$WORK/repl.yaml" <<Y
replicate:
  apiVersion: v1
  source:
    type: minio
    bucket: srcbkt
    prefix: [docs/, img]
  target:
    type: minio
    bucket: dstbkt
    prefix: copy
    endpoint: "http://127.0.0.1:$port"
    credentials:
      accessKey: rootadmin
      secretKey: rootsecret123
  flags:
    filter:
      newerThan: "7d"
      olderThan: 1h30m
      createdAfter: "2020-01-01T00:00:00Z"
      tags:
        - key: "env"
          value: "prod*"
      metadata:
        - key: "content-type"
          value: "image/*"
    notify:
      endpoint: "http://127.0.0.1:1"
      token: "Bearer xyz"
    retry:
      attempts: 5
      delay: 500ms
Y
  cat >"$WORK/rot.yaml" <<'Y'
keyrotate:
  apiVersion: v1
  bucket: srcbkt
  prefix: docs/
  encryption:
    type: sse-s3
  flags:
    filter:
      newerThan: 24h
      createdBefore: 2030-01-01T00:00:00Z
      kmskeyid: my-minio-key
    retry:
      attempts: 2
      delay: 1s
Y
  cat >"$WORK/exp.yaml" <<'Y'
expire:
  apiVersion: v1
  bucket: srcbkt
  prefix: img/
  rules:
    - type: object
      name: "*.jpg"
      olderThan: 70h
      createdBefore: "2025-01-01T00:00:00Z"
      tags:
        - key: name
          value: pick*
      size:
        lessThan: "10MiB"
        greaterThan: 1KiB
      purge:
        retainVersions: 2
    - type: deleted
      name: "x"
  retry:
    attempts: 10
    delay: 500ms
Y
  {
    for f in repl rot exp; do MC batch start m "$WORK/$f.yaml" 2>&1 | norm; done
    wait_done m "$port" || echo "jobs did not finish"
    MC batch list m --json | norm
    for id in $(job_ids m); do
      echo "== $id" | norm
      MC batch describe m "$id"
      admin "$port" "status-job?jobId=$id" | norm
      echo
    done
    local y="$WORK/bad.yaml"
    printf 'expire:\n  apiVersion: v1\n  bucket: srcbkt\n  retry:\n    attempts: abc\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'expire:\n  apiVersion: v2\n  bucket: srcbkt\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'expire:\n  apiVersion: v1\n  bucket: nosuchbkt\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'expire:\n  apiVersion: v1\n  bucket: srcbkt\n  rules:\n    - type: foo\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'expire:\n  apiVersion: v1\n  bucket: srcbkt\n  rules:\n    - type: object\n      olderThan: 3x\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'keyrotate:\n  apiVersion: v1\n  bucket: srcbkt\n  encryption:\n    type: sse-x\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'replicate:\n  apiVersion: v1\n  source:\n    bucket: srcbkt\n  target:\n    bucket: dstbkt\n' >"$y"; MC batch start m "$y" 2>&1
    printf 'replicate:\n  apiVersion: v1\n  source:\n    type: minio\n    bucket: srcbkt\n  target:\n    type: minio\n    bucket: nosuch\n    endpoint: "http://127.0.0.1:%s"\n    credentials:\n      accessKey: rootadmin\n      secretKey: rootsecret123\n' "$port" >"$y"; MC batch start m "$y" 2>&1
    printf 'foo: [\n' >"$y"; MC batch start m "$y" 2>&1
    printf '{}\n' >"$y"; MC batch start m "$y" 2>&1
    MC batch describe m expire-nope 2>&1
    admin "$port" "status-job?jobId=expire-nope" | norm; echo
  } >"$out"
  stop m
}
defs minio "$WORK/defs.minio"
defs buckets "$WORK/defs.buckets"
CASE=defs
same "definitions and admin API" "$WORK/defs.minio" "$WORK/defs.buckets"

# ---- expire ----
expire_case() { # kind out
  CASE="expire $1"
  local dir="$WORK/exp_$1"
  start "$1" "$PORT" m "$dir"
  MC mb m/unv m/ver >/dev/null
  MC version enable m/ver >/dev/null
  for i in 1 2 3; do echo "a$i" | MC pipe "m/unv/img/a$i.jpg" >/dev/null; done
  echo keep | MC pipe m/unv/img/keep.png >/dev/null
  echo t | MC pipe --tags "env=prod" m/unv/img/t.jpg >/dev/null
  for v in 1 2 3 4; do echo "v$v" | MC pipe m/ver/obj >/dev/null; done
  for v in 1 2; do echo "v$v" | MC pipe m/ver/gone >/dev/null; done
  MC rm m/ver/gone >/dev/null
  echo x | MC pipe m/ver/other >/dev/null
  printf 'expire:\n  apiVersion: v1\n  bucket: unv\n  prefix: img/\n  rules:\n    - type: object\n      name: "*.jpg"\n      tags:\n        - key: env\n          value: prod\n    - type: object\n      name: "img/a[12]*"\n' >"$WORK/e1.yaml"
  printf 'expire:\n  apiVersion: v1\n  bucket: ver\n  rules:\n    - type: object\n      name: obj\n      purge:\n        retainVersions: 2\n    - type: deleted\n      name: "g*"\n' >"$WORK/e2.yaml"
  for f in e1 e2; do MC batch start m "$WORK/$f.yaml" >/dev/null; done
  wait_done m "$PORT" || bad "expire jobs did not finish"
  {
    MC ls -r m/unv | awk '{print $NF}'
    MC ls -r --versions --json m/ver | python3 -c 'import json,sys
for l in sys.stdin:
    d = json.loads(l); print(d["key"], d.get("size"), d.get("isDeleteMarker", False))'
    statuses m "$PORT" | sed -E 's/"lastUpdate":"[^"]*"//'
  } >"$2"
  stop m
}
expire_case minio "$WORK/exp.minio"
expire_case buckets "$WORK/exp.buckets"
CASE=expire
same "expire results" "$WORK/exp.minio" "$WORK/exp.buckets"

# ---- keyrotate, and the other server reading what was rotated ----
rotate_case() { # kind out
  CASE="keyrotate $1"
  local dir="$WORK/rot_$1" other
  other=$([[ $1 == minio ]] && echo buckets || echo minio)
  start "$1" "$PORT" m "$dir"
  MC mb m/enc >/dev/null
  for i in 1 2 3; do echo "s3data$i" | MC pipe --enc-s3 m/enc m/enc/s3/o$i >/dev/null; done
  head -c 12000000 /dev/urandom >"$dir/big"
  MC cp --enc-s3 m/enc "$dir/big" m/enc/s3/big >/dev/null
  echo kms | MC pipe --enc-kms "m/enc=my-minio-key" m/enc/kms/k1 >/dev/null
  echo plain | MC pipe m/enc/plain >/dev/null
  find "$dir/d1/enc" -name xl.meta | sort | xargs md5 -q >"$dir/before" 2>/dev/null ||
    find "$dir/d1/enc" -name xl.meta | sort | xargs md5sum | cut -d' ' -f1 >"$dir/before"
  printf 'keyrotate:\n  apiVersion: v1\n  bucket: enc\n  encryption:\n    type: sse-s3\n' >"$WORK/r1.yaml"
  printf 'keyrotate:\n  apiVersion: v1\n  bucket: enc\n  prefix: kms/\n  encryption:\n    type: sse-kms\n    key: my-minio-key\n' >"$WORK/r2.yaml"
  MC batch start m "$WORK/r1.yaml" >/dev/null
  wait_done m "$PORT"
  MC batch start m "$WORK/r2.yaml" >/dev/null
  wait_done m "$PORT" || bad "keyrotate jobs did not finish"
  find "$dir/d1/enc" -name xl.meta | sort | xargs md5 -q >"$dir/after" 2>/dev/null ||
    find "$dir/d1/enc" -name xl.meta | sort | xargs md5sum | cut -d' ' -f1 >"$dir/after"
  {
    echo "changed: $(diff "$dir/before" "$dir/after" | grep -c '^>')"
    statuses m "$PORT" | sed -E 's/"lastUpdate":"[^"]*"//'
  } >"$2"
  stop m
  start "$other" "$PORT" m "$dir"
  CASE="keyrotate $1, read by $other"
  check "o1" "$(MC cat m/enc/s3/o1)" s3data1
  check "o3" "$(MC cat m/enc/s3/o3)" s3data3
  check "k1" "$(MC cat m/enc/kms/k1)" kms
  check "plain" "$(MC cat m/enc/plain)" plain
  check "big" "$(MC cat m/enc/s3/big | md5)" "$(md5 <"$dir/big")"
  stop m
}
rotate_case minio "$WORK/rot.minio"
rotate_case buckets "$WORK/rot.buckets"
CASE=keyrotate
same "keyrotate results" "$WORK/rot.minio" "$WORK/rot.buckets"

# ---- replicate: push and pull between every pairing ----
repl_case() { # src-kind dst-kind push|pull out
  CASE="replicate $1->$2 $3"
  local dir="$WORK/repl_$1_$2_$3" sp=$PORT dp=$((PORT + 1)) run rport
  start "$1" "$sp" src "$dir/src"
  start "$2" "$dp" dst "$dir/dst"
  MC mb src/srcbkt dst/dstbkt >/dev/null
  MC version enable src/srcbkt >/dev/null
  MC version enable dst/dstbkt >/dev/null
  for v in 1 2 3; do echo "v$v" | MC pipe --attr "Color=red" src/srcbkt/docs/a >/dev/null; done
  echo tagged | MC pipe --tags "env=prod" src/srcbkt/docs/t >/dev/null
  head -c 7000000 /dev/urandom >"$dir/big"
  MC cp "$dir/big" src/srcbkt/docs/big >/dev/null
  head -c 12000000 /dev/urandom >"$dir/mp"
  MC cp "$dir/mp" src/srcbkt/docs/mp >/dev/null
  echo gone | MC pipe src/srcbkt/docs/gone >/dev/null
  MC rm src/srcbkt/docs/gone >/dev/null
  echo skip | MC pipe src/srcbkt/other/x >/dev/null
  if [[ $3 == push ]]; then
    run=src rport=$sp
    printf 'replicate:\n  apiVersion: v1\n  source:\n    type: minio\n    bucket: srcbkt\n    prefix: docs/\n  target:\n    type: minio\n    bucket: dstbkt\n    endpoint: "http://127.0.0.1:%s"\n    credentials:\n      accessKey: rootadmin\n      secretKey: rootsecret123\n' "$dp" >"$dir/job.yaml"
  else
    run=dst rport=$dp
    printf 'replicate:\n  apiVersion: v1\n  source:\n    type: minio\n    bucket: srcbkt\n    prefix: docs/\n    endpoint: "http://127.0.0.1:%s"\n    credentials:\n      accessKey: rootadmin\n      secretKey: rootsecret123\n  target:\n    type: minio\n    bucket: dstbkt\n' "$sp" >"$dir/job.yaml"
  fi
  MC batch start "$run" "$dir/job.yaml" >/dev/null
  wait_done "$run" "$rport" || bad "replicate job did not finish"
  lst() { MC ls -r --versions --json "$1" | python3 -c 'import json,sys
for l in sys.stdin:
    d = json.loads(l); print(d["key"], d.get("versionId"), d.get("etag"), d.get("size"), d.get("lastModified"), d.get("isDeleteMarker", False))' | sort; }
  lst src/srcbkt/docs/ >"$dir/s"
  lst dst/dstbkt/docs/ >"$dir/d"
  same "versions" "$dir/s" "$dir/d"
  check "metadata" "$(MC stat --json dst/dstbkt/docs/a | python3 -c 'import json,sys; print(json.load(sys.stdin)["metadata"].get("X-Amz-Meta-Color"))')" red
  check "mp data" "$(MC cat dst/dstbkt/docs/mp | md5)" "$(md5 <"$dir/mp")"
  check "big data" "$(MC cat dst/dstbkt/docs/big | md5)" "$(md5 <"$dir/big")"
  check "outside prefix" "$(MC ls -r dst/dstbkt/other 2>/dev/null | wc -l | tr -d ' ')" 0
  statuses "$run" "$rport" | sed -E 's/"lastUpdate":"[^"]*"//' >"$4"
  stop src
  stop dst
}
for pair in "minio minio" "buckets buckets" "buckets minio" "minio buckets"; do
  set -- $pair
  for mode in push pull; do
    repl_case "$1" "$2" "$mode" "$WORK/repl.$1.$2.$mode"
    CASE="replicate $1->$2 $mode"
    same "job status vs minio->minio" "$WORK/repl.minio.minio.$mode" "$WORK/repl.$1.$2.$mode"
  done
done

# ---- one server's jobs on the other; resume; mc batch status; cancel ----
CASE="jobs across servers"
dir="$WORK/cross"
start buckets "$PORT" m "$dir"
MC mb m/srcbkt >/dev/null
for i in 1 2 3; do echo "a$i" | MC pipe "m/srcbkt/a$i" >/dev/null; done
printf 'expire:\n  apiVersion: v1\n  bucket: srcbkt\n  rules:\n    - type: object\n      name: "a*"\n' >"$WORK/e.yaml"
MC batch start m "$WORK/e.yaml" >/dev/null
wait_done m "$PORT"
id=$(job_ids m)
st=$(MC batch status m "$id" --json 2>&1 | tail -1)
check "mc batch status" "$(echo "$st" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], d["metric"]["expired"]["objects"])')" "complete 3"
stop m
start minio "$PORT" m "$dir"
check "minio lists bucketsd's job" "$(job_ids m)" "$id"
check "minio describes it" "$(MC batch describe m "$id" | grep -c 'name: a\*')" 1
check "minio reports it" "$(admin "$PORT" "status-job?jobId=$id" | python3 -c 'import json,sys; print(json.load(sys.stdin)["LastMetric"]["expired"]["objects"])')" 3
for i in 1 2; do echo "b$i" | MC pipe "m/srcbkt/b$i" >/dev/null; done
sleep 2 # MinIO's job pool starts after the listener
printf 'expire:\n  apiVersion: v1\n  bucket: srcbkt\n  rules:\n    - type: object\n      name: "b*"\n' >"$WORK/e2.yaml"
MC batch start m "$WORK/e2.yaml" >/dev/null
wait_done m "$PORT"
stop m
start buckets "$PORT" m "$dir"
check "bucketsd lists both" "$(job_ids m | wc -l | tr -d ' ')" 2
for j in $(job_ids m); do
  check "bucketsd reports $j" "$(admin "$PORT" "status-job?jobId=$j" | python3 -c 'import json,sys; print(json.load(sys.stdin)["LastMetric"]["complete"])')" True
done
MC batch cancel m "$id" >/dev/null
check "cancel" "$(job_ids m | grep -c "$id")" 0
stop m

CASE="resume"
dir="$WORK/resume"
export _MINIO_BATCH_REPLICATION_WORKERS=1
start buckets "$PORT" m "$dir"
start minio "$((PORT + 1))" dst "$dir/dst"
MC mb m/srcbkt dst/dstbkt >/dev/null
for i in $(seq 1 40); do echo "o$i" | MC pipe "m/srcbkt/o$i" >/dev/null; done
MC admin config set m batch replication_workers_wait=150ms >/dev/null
printf 'replicate:\n  apiVersion: v1\n  source:\n    type: minio\n    bucket: srcbkt\n  target:\n    type: minio\n    bucket: dstbkt\n    endpoint: "http://127.0.0.1:%s"\n    credentials:\n      accessKey: rootadmin\n      secretKey: rootsecret123\n' "$((PORT + 1))" >"$WORK/slow.yaml"
MC batch start m "$WORK/slow.yaml" >/dev/null
sleep 2
stop m
before=$(MC ls dst/dstbkt | wc -l | tr -d ' ')
[[ $before -gt 0 && $before -lt 40 ]] && ok || bad "interrupted job copied $before objects"
start buckets "$PORT" m "$dir"
wait_done m "$PORT" || bad "resumed job did not finish"
check "resumed job finished the copy" "$(MC ls dst/dstbkt | wc -l | tr -d ' ')" 40
stop m
stop dst

for log in "$WORK"/*/*.log "$WORK"/*.log; do
  [[ -f $log ]] && grep -l "AddressSanitizer\|runtime error:\|LeakSanitizer" "$log" && bad "sanitizer report in $log"
done
echo "batch: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
