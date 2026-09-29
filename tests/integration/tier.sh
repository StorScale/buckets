#!/usr/bin/env bash
# Remote tiers and lifecycle transitions against MinIO:
#  - mc admin tier add/ls/edit/rm (and its errors), with MinIO and bucketsd
#    as the warm tier;
#  - transitions (immediate and by the scanner) of plain, multipart,
#    SSE-S3 and compressed objects; reads (and ranges) from the tier;
#  - RestoreObject, repeated and invalid restores;
#  - Azure (Azurite) and GCS (fake-gcs-server) tiers, when AZURITE_BIN and
#    FAKE_GCS_BIN are set;
#  - mc admin tier info (per-tier usage, last-day transitions), tier metrics;
#  - deletes, overwrites and expiry of transitioned versions: the remote
#    copies go (free versions swept by the scanner);
#  - compatibility: MinIO reads what bucketsd transitioned and restored,
#    bucketsd reads what MinIO transitioned, both read each other's
#    tier-config.bin (SSE-S3-sealed).
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/tier.sh [bucketsd]
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "tier: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19840}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-tier-XXXXXX")
export MC_CONFIG_DIR="$WORK/mc" MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_PROMETHEUS_AUTH_TYPE=public
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
PIDS=()
pass=0 fail=0
CASE=tier
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
contains() { if [[ "$2" == *"$3"* ]]; then ok; else bad "$1: '$2' lacks '$3'"; fi; }
start() { # kind port alias dir
  eval "ARGS_$3=\"\$*\""
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
stop_site() { local v="PID_$1"; kill "${!v}" 2>/dev/null; wait "${!v}" 2>/dev/null; }
stop_all() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  PIDS=()
}
field() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"; }
wait_for() {
  local n=$(( $1 * 10 )); shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}
sclass() { MC stat --json "$1" 2>/dev/null | field metadata.X-Amz-Storage-Class; }
is_tier() { [[ $(sclass "$1") == "$2" ]]; }
remote_count() { MC ls -r "$1" 2>/dev/null | wc -l | tr -d ' '; }
restored() { curl_s3 -I "http://127.0.0.1:$PORT/$1" | grep -qi '^x-amz-restore: ongoing-request="false"'; }
remote_is() { [[ $(remote_count "$1") == "$2" ]]; }
lc_import() { # alias/bucket json
  echo "$2" | MC ilm rule import "$1" >/dev/null
}
TRANSITION='{"Rules":[{"ID":"t1","Status":"Enabled","Filter":{"Prefix":""},"Transition":{"Date":"2024-01-01T00:00:00Z","StorageClass":"WARM1"}}]}'
curl_s3() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 "$@"; }

run_hot_buckets() { # warm kind
  CASE="hot=buckets warm=$1"
  local dir="$WORK/b_$1"
  start buckets "$PORT" hot "$dir/hot"
  start "$1" "$((PORT + 1))" warm "$dir/warm"
  MC admin config set hot scanner speed=fastest >/dev/null 2>&1
  MC mb warm/tierbkt >/dev/null
  local out
  # admin
  out=$(MC admin tier add minio hot WARM1 --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket tierbkt --prefix pre/ 2>&1)
  check "tier add" "$out" "Added remote tier WARM1 of type minio"
  out=$(MC admin tier add minio hot WARM1 --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket tierbkt 2>&1)
  contains "tier add twice" "$out" "Specified remote tier already exists"
  out=$(MC admin tier add minio hot WARM2 --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket nosuchbucket 2>&1)
  contains "tier add missing bucket" "$out" "failed to perform PUT: The specified bucket does not exist"
  out=$(MC admin tier add minio hot WARM2 --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key wrongsecret123 --bucket tierbkt 2>&1)
  contains "tier add bad credentials" "$out" "signature we calculated does not match"
  out=$(MC admin tier add minio hot STANDARD --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket tierbkt 2>&1)
  contains "tier add reserved" "$out" "Cannot use reserved tier name"
  local ls
  ls=$(MC admin tier ls hot --json)
  check "tier ls type" "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tiers"][0]["Type"])' "$ls")" minio
  check "tier ls secret" "$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["tiers"][0]["MinIO"]["SecretKey"])' "$ls")" REDACTED
  check "tier edit" "$(MC admin tier edit hot WARM1 --access-key rootadmin --secret-key rootsecret123 2>&1)" "Updated remote tier WARM1"
  check "ilm with unknown tier" "$(MC ilm rule add hot/nosuch --transition-days 1 --transition-tier NOPE 2>&1 | grep -c 'Invalid storage class\|does not exist')" 1

  # transitions right after writes
  MC mb hot/data >/dev/null
  lc_import hot/data "$TRANSITION"
  echo small >"$dir/small"
  head -c 3000000 /dev/urandom >"$dir/big"
  head -c $((12 * 1024 * 1024)) /dev/urandom >"$dir/mp"
  yes buckets | head -c 2000000 >"$dir/comp"
  MC cp "$dir/small" hot/data/small >/dev/null
  MC cp "$dir/big" hot/data/big >/dev/null
  MC cp "$dir/mp" hot/data/mp >/dev/null
  MC cp --enc-s3 hot/data "$dir/small" hot/data/enc >/dev/null
  MC admin config set hot compression enable=on extensions=.txt >/dev/null 2>&1
  MC cp "$dir/comp" hot/data/comp.txt >/dev/null
  for k in small big mp enc comp.txt; do
    wait_for 20 is_tier "hot/data/$k" WARM1 || bad "$k not transitioned: '$(sclass hot/data/$k)'"
  done
  check "remote objects" "$(remote_count warm/tierbkt/pre/)" 5
  check "small data" "$(MC cat hot/data/small)" small
  check "big data" "$(MC cat hot/data/big | md5)" "$(md5 <"$dir/big")"
  check "mp data" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"
  check "enc data" "$(MC cat hot/data/enc)" small
  check "comp data" "$(MC cat hot/data/comp.txt | md5)" "$(md5 <"$dir/comp")"
  check "range" "$(curl_s3 -r 1000-1015 "http://127.0.0.1:$PORT/data/big" | md5)" "$(dd if="$dir/big" bs=1 skip=1000 count=16 2>/dev/null | md5)"
  check "list class" "$(MC ls hot/data --json | head -1 | field storageClass)" WARM1

  out=$(MC admin tier add minio hot WARMX --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket tierbkt --prefix pre/ 2>&1)
  contains "tier add in use" "$out" "Specified remote tier is already in use"

  # the scanner transitions what was there before the rule
  MC mb hot/later >/dev/null
  MC cp "$dir/small" hot/later/old >/dev/null
  lc_import hot/later "$TRANSITION"
  wait_for 60 is_tier hot/later/old WARM1 || bad "scanner did not transition later/old"

  # tier info: the scanner's per-tier usage and the last day's transitions;
  # the tier metrics
  tier_info_ok() { MC admin tier info hot --json | python3 -c 'import json,sys
t = {x["Name"]: x for x in json.load(sys.stdin)["tiers"]}
w = t["WARM1"]
assert w["API"] == "minio" and w["Type"] == "warm" and w["Stats"]["numVersions"] == 6, w["Stats"]
assert t["STANDARD"]["API"] == "internal" and "REDUCED_REDUNDANCY" in t
assert sum(b["numVersions"] for b in w["DailyStats"]["Bins"]) == 6'; }
  wait_for 60 tier_info_ok || bad "tier info: $(MC admin tier info hot --json 2>&1 | head -c 600)"
  local metrics
  metrics=$(curl -s "http://127.0.0.1:$PORT/minio/v2/metrics/cluster")
  contains "transitioned metric" "$metrics" 'minio_cluster_ilm_transitioned_versions{server="127.0.0.1:'"$PORT"'",tier="WARM1"} 6'
  contains "tier requests metric" "$metrics" 'minio_node_tier_requests_success{server="127.0.0.1:'"$PORT"'",tier="WARM1"}'
  contains "tier ttlb metric" "$metrics" 'minio_node_tier_ttlb_seconds_distribution{le="+Inf"'

  # restore
  out=$(curl_s3 -s -o /dev/null -w '%{http_code}' -X POST \
    --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>2</Days></RestoreRequest>' \
    "http://127.0.0.1:$PORT/data/big?restore")
  check "restore" "$out" 200
  wait_for 20 restored data/big || bad "restore did not complete"
  check "restored data" "$(MC cat hot/data/big | md5)" "$(md5 <"$dir/big")"
  check "restored parts" "$(find "$dir/hot" -path '*data/big/*' -name 'part.1' | wc -l | tr -d ' ')" 4
  out=$(curl_s3 -s -o /dev/null -w '%{http_code}' -X POST \
    --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>3</Days></RestoreRequest>' \
    "http://127.0.0.1:$PORT/data/big?restore")
  check "restore again" "$out" 202
  out=$(curl_s3 -X POST --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></RestoreRequest>' \
    "http://127.0.0.1:$PORT/data/big?restore")
  contains "restore without days" "$out" "restoration days should be at least 1"
  MC cp "$dir/small" hot/later/plain >/dev/null 2>&1
  MC ilm rule rm --all --force hot/later >/dev/null 2>&1
  MC cp "$dir/small" hot/later/notier >/dev/null
  out=$(curl_s3 -X POST --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>' \
    "http://127.0.0.1:$PORT/later/notier?restore")
  contains "restore of a hot object" "$out" "InvalidObjectState"

  # deletes and overwrites: the remote copies go
  local before
  before=$(remote_count warm/tierbkt/pre/)
  MC rm hot/data/small >/dev/null
  echo new >"$dir/new"
  MC cp "$dir/new" hot/data/enc >/dev/null # overwrite (the new version transitions too)
  wait_for 60 remote_is warm/tierbkt/pre/ "$((before - 1))" || bad "remote copies after delete+overwrite: $(remote_count warm/tierbkt/pre/) want $((before - 1))"
  # a versioned bucket keeps the remote copy behind a delete marker
  MC mb hot/ver >/dev/null
  MC version enable hot/ver >/dev/null
  lc_import hot/ver "$TRANSITION"
  MC cp "$dir/small" hot/ver/obj >/dev/null
  wait_for 20 is_tier hot/ver/obj WARM1 || bad "ver/obj not transitioned"
  local vid n0
  vid=$(MC stat --json hot/ver/obj | field versionID)
  n0=$(remote_count warm/tierbkt/pre/)
  MC rm hot/ver/obj >/dev/null
  sleep 3
  check "marker keeps remote" "$(remote_count warm/tierbkt/pre/)" "$n0"
  check "old version readable" "$(MC cat --version-id "$vid" hot/ver/obj)" small
  MC rm --version-id "$vid" hot/ver/obj >/dev/null
  wait_for 60 remote_is warm/tierbkt/pre/ "$((n0 - 1))" || bad "remote copy of a deleted version still there"

  # expiry of transitioned objects removes the remote copies
  MC mb hot/exp >/dev/null
  lc_import hot/exp "$TRANSITION"
  MC cp "$dir/small" hot/exp/a >/dev/null
  wait_for 20 is_tier hot/exp/a WARM1 || bad "exp/a not transitioned"
  n0=$(remote_count warm/tierbkt/pre/)
  lc_import hot/exp '{"Rules":[{"ID":"t1","Status":"Enabled","Filter":{"Prefix":""},"Transition":{"Date":"2024-01-01T00:00:00Z","StorageClass":"WARM1"}},{"ID":"e1","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Date":"2024-01-01T00:00:00Z"}}]}'
  wait_for 60 bash -c "! '$MC_BIN' stat hot/exp/a" || bad "exp/a not expired"
  wait_for 30 remote_is warm/tierbkt/pre/ "$((n0 - 1))" || bad "expired object's remote copy still there"

  # removing a tier in use is refused
  out=$(MC admin tier rm hot WARM1 2>&1)
  contains "tier rm in use" "$out" "Specified remote backend is not empty"

  # restart: the configuration is read back
  stop_site hot
  local v="ARGS_hot"
  start ${!v}
  check "after restart" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"

  # MinIO on the same drives reads what bucketsd transitioned and restored
  stop_site hot
  start minio "$PORT" hot "$dir/hot"
  check "minio: tiers" "$(MC admin tier ls hot --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["tiers"]))')" 1
  check "minio: transitioned" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"
  check "minio: sse" "$(MC cat hot/data/enc)" new
  check "minio: compressed" "$(MC cat hot/data/comp.txt | md5)" "$(md5 <"$dir/comp")"
  check "minio: restored" "$(MC cat hot/data/big | md5)" "$(md5 <"$dir/big")"
  check "minio: class" "$(sclass hot/data/mp)" WARM1
  stop_all
}

run_hot_minio() { # MinIO transitions, bucketsd reads (and deletes)
  CASE="hot=minio"
  local dir="$WORK/m"
  start minio "$PORT" hot "$dir/hot"
  start minio "$((PORT + 1))" warm "$dir/warm"
  MC mb warm/tierbkt >/dev/null
  MC admin tier add minio hot WARM1 --endpoint "http://127.0.0.1:$((PORT + 1))" --access-key rootadmin \
    --secret-key rootsecret123 --bucket tierbkt --prefix pre/ >/dev/null
  MC mb hot/data >/dev/null
  lc_import hot/data "$TRANSITION"
  head -c $((12 * 1024 * 1024)) /dev/urandom >"$dir/mp"
  echo small >"$dir/small"
  MC cp "$dir/mp" hot/data/mp >/dev/null
  MC cp --enc-s3 hot/data "$dir/small" hot/data/enc >/dev/null
  MC cp "$dir/small" hot/data/gone >/dev/null
  for k in mp enc gone; do wait_for 30 is_tier "hot/data/$k" WARM1 || bad "minio did not transition $k"; done
  stop_site hot
  start buckets "$PORT" hot "$dir/hot"
  MC admin config set hot scanner speed=fastest >/dev/null 2>&1
  check "tiers" "$(MC admin tier ls hot --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["tiers"]))')" 1
  check "transitioned" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"
  check "sse" "$(MC cat hot/data/enc)" small
  check "class" "$(sclass hot/data/mp)" WARM1
  local n0
  n0=$(remote_count warm/tierbkt/pre/)
  MC rm hot/data/gone >/dev/null
  wait_for 60 remote_is warm/tierbkt/pre/ "$((n0 - 1))" || bad "remote copy of a MinIO-transitioned object not removed"
  out=$(curl_s3 -s -o /dev/null -w '%{http_code}' -X POST \
    --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>' \
    "http://127.0.0.1:$PORT/data/mp?restore")
  check "restore" "$out" 200
  wait_for 20 restored data/mp || bad "restore did not complete"
  check "restored" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"
  stop_all
}

# Azure Blob (Azurite) and GCS (fake-gcs-server) warm tiers, when the
# emulators are given: AZURITE_BIN (azurite-blob), FAKE_GCS_BIN.
cloud_count() { # kind port: the objects under p/ in the tier's container or bucket
  python3 - "$@" <<'PY'
import base64, email.utils, hashlib, hmac, json, re, sys, urllib.request
kind, port = sys.argv[1], sys.argv[2]
if kind == "gcs":
    d = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/storage/v1/b/tierg/o?prefix=p/"))
    print(len(d.get("items", [])))
    sys.exit()
acct, key = "devstoreaccount1", "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
date = email.utils.formatdate(usegmt=True)
sts = ("GET\n" + "\n" * 11 + f"x-ms-date:{date}\nx-ms-version:2021-08-06\n"
       f"/{acct}/{acct}/tierc\ncomp:list\nprefix:p/\nrestype:container")
sig = base64.b64encode(hmac.new(base64.b64decode(key), sts.encode(), hashlib.sha256).digest()).decode()
req = urllib.request.Request(f"http://127.0.0.1:{port}/{acct}/tierc?restype=container&comp=list&prefix=p/",
                             headers={"x-ms-date": date, "x-ms-version": "2021-08-06", "Authorization": f"SharedKey {acct}:{sig}"})
print(len(re.findall(r"<Blob>", urllib.request.urlopen(req).read().decode())))
PY
}
cloud_is() { [[ $(cloud_count "$1" "$2" 2>/dev/null) == "$3" ]]; }
make_container() { # port
  python3 - "$1" <<'PY'
import base64, email.utils, hashlib, hmac, sys, urllib.request
port, acct = sys.argv[1], "devstoreaccount1"
key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
date = email.utils.formatdate(usegmt=True)
sts = "PUT\n" + "\n" * 11 + f"x-ms-date:{date}\nx-ms-version:2021-08-06\n/{acct}/{acct}/tierc\nrestype:container"
sig = base64.b64encode(hmac.new(base64.b64decode(key), sts.encode(), hashlib.sha256).digest()).decode()
urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{port}/{acct}/tierc?restype=container", method="PUT",
    headers={"x-ms-date": date, "x-ms-version": "2021-08-06", "Authorization": f"SharedKey {acct}:{sig}", "Content-Length": "0"}))
PY
}
run_hot_cloud() { # azure|gcs
  CASE="hot=buckets warm=$1"
  local dir="$WORK/c_$1" ep=$((PORT + 5)) out
  mkdir -p "$dir"
  if [[ $1 == azure ]]; then
    "$AZURITE_BIN" --blobHost 127.0.0.1 --blobPort "$ep" --location "$dir/az" --silent --skipApiVersionCheck >"$dir/az.log" 2>&1 &
  else
    "$FAKE_GCS_BIN" -scheme http -host 127.0.0.1 -port "$ep" -backend memory >"$dir/gcs.log" 2>&1 &
  fi
  PIDS+=($!)
  for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$ep/" && break; sleep 0.1; done
  if [[ $1 == azure ]]; then
    make_container "$ep"
    start buckets "$PORT" hot "$dir/hot"
    out=$(MC admin tier add azure hot CLOUD1 --endpoint "http://127.0.0.1:$ep/devstoreaccount1" --account-name devstoreaccount1 \
      --account-key "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==" \
      --bucket tierc --prefix p/ 2>&1)
  else
    curl -s -o /dev/null -X POST -H 'Content-Type: application/json' -d '{"name":"tierg"}' "http://127.0.0.1:$ep/storage/v1/b"
    STORAGE_EMULATOR_HOST="127.0.0.1:$ep" start buckets "$PORT" hot "$dir/hot"
    echo '{"type":"service_account","client_email":"x@y","private_key":"none"}' >"$dir/creds.json"
    out=$(MC admin tier add gcs hot CLOUD1 --credentials-file "$dir/creds.json" --bucket tierg --prefix p/ 2>&1)
  fi
  check "tier add" "$out" "Added remote tier CLOUD1 of type $1"
  MC admin config set hot scanner speed=fastest >/dev/null 2>&1
  MC mb hot/data >/dev/null
  lc_import hot/data '{"Rules":[{"ID":"t1","Status":"Enabled","Filter":{"Prefix":""},"Transition":{"Date":"2024-01-01T00:00:00Z","StorageClass":"CLOUD1"}}]}'
  echo small >"$dir/small"
  head -c 3000000 /dev/urandom >"$dir/big"
  head -c $((12 * 1024 * 1024)) /dev/urandom >"$dir/mp"
  MC cp "$dir/small" hot/data/small >/dev/null
  MC cp "$dir/big" hot/data/big >/dev/null
  MC cp "$dir/mp" hot/data/mp >/dev/null
  for k in small big mp; do
    wait_for 20 is_tier "hot/data/$k" CLOUD1 || bad "$k not transitioned: '$(sclass hot/data/$k)'"
  done
  check "remote objects" "$(cloud_count "$1" "$ep")" 3
  check "small data" "$(MC cat hot/data/small)" small
  check "big data" "$(MC cat hot/data/big | md5)" "$(md5 <"$dir/big")"
  check "mp data" "$(MC cat hot/data/mp | md5)" "$(md5 <"$dir/mp")"
  check "range" "$(curl_s3 -r 1000-1015 "http://127.0.0.1:$PORT/data/big" | md5)" "$(dd if="$dir/big" bs=1 skip=1000 count=16 2>/dev/null | md5)"
  out=$(curl_s3 -s -o /dev/null -w '%{http_code}' -X POST \
    --data '<RestoreRequest xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Days>1</Days></RestoreRequest>' \
    "http://127.0.0.1:$PORT/data/big?restore")
  check "restore" "$out" 200
  wait_for 20 restored data/big || bad "restore did not complete"
  check "restored data" "$(MC cat hot/data/big | md5)" "$(md5 <"$dir/big")"
  MC rm hot/data/small >/dev/null
  wait_for 30 cloud_is "$1" "$ep" 2 || bad "remote copy after delete: $(cloud_count "$1" "$ep") want 2"
  contains "tier rm in use" "$(MC admin tier rm hot CLOUD1 2>&1)" "Specified remote backend is not empty"
  stop_all
}

for w in ${WARM:-minio buckets}; do run_hot_buckets "$w"; done
[[ -n "${AZURITE_BIN:-}" ]] && run_hot_cloud azure
[[ -n "${FAKE_GCS_BIN:-}" ]] && run_hot_cloud gcs
[[ -z "${NO_MINIO_HOT:-}" ]] && run_hot_minio
echo "tier: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
