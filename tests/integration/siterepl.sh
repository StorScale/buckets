#!/usr/bin/env bash
# Site replication across mixed MinIO / bucketsd groups:
#  - three sites, set up from a MinIO site and from a bucketsd site: the
#    initial sync (buckets, bucket metadata, IAM), then buckets, objects,
#    bucket metadata and IAM changed on any site reaching the others;
#  - handover: a bucketsd site joins a MinIO group, is resynced, and the
#    MinIO sites leave.
#   MINIO_BIN=/path/to/minio MC_BIN=/path/to/mc tests/integration/siterepl.sh [bucketsd]
# SR_GROUPS limits the three-site layouts ("minio,buckets,buckets buckets,minio,minio").
set -uo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" || -z "${MC_BIN:-}" ]]; then
  echo "siterepl: skipped (set MINIO_BIN and MC_BIN)"
  exit 0
fi
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
PORT=${PORT:-19740}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-sr-XXXXXX")
export MC_CONFIG_DIR="$WORK/mc" MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
export MINIO_KMS_SECRET_KEY="my-minio-key:OSMM+vkKUTCvQs9YL/CVMIMt43HFhkUpqJxTmGl6rYw="
export BUCKETS_REPLICATION_MRF_DELAY_MS=500 BUCKETS_SITE_REPLICATION_HEAL_INTERVAL=${HEAL:-5}
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
bad() { fail=$((fail + 1)); echo "FAIL [$CASE] $*"; }
md5sum_() { if command -v md5 >/dev/null; then md5; else md5sum | cut -d" " -f1; fi; } # macOS, or Linux
check() { # name got want
  if [[ "$2" == "$3" ]]; then ok; else bad "$1: got '$2' want '$3'"; fi
}
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
restart_site() { local v="ARGS_$1"; start ${!v}; }
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
wait_for() { # seconds cmd...
  local n=$(( $1 * 10 )); shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}
has_bucket() { MC ls "$1" 2>/dev/null | grep -q " $2/\$"; }
no_bucket() { ! has_bucket "$@"; }
has_object() { MC stat "$1" >/dev/null 2>&1; }
has_user() { MC admin user info "$1" "$2" >/dev/null 2>&1; }
no_user() { ! has_user "$@"; }
has_policy() { MC admin policy info "$1" "$2" >/dev/null 2>&1; }
no_policy() { ! has_policy "$@"; }
user_policy() { MC admin user info "$1" "$2" --json 2>/dev/null | field policyName; }
has_user_policy() { [[ $(user_policy "$1" "$2") == "$3" ]]; }
has_group() { MC admin group info "$1" "$2" >/dev/null 2>&1; }
group_members() { MC admin group info "$1" "$2" --json 2>/dev/null | field members; }
has_members() { [[ $(group_members "$1" "$2") == "$3" ]]; }
has_svc() { MC admin user svcacct info "$1" "$2" >/dev/null 2>&1; }
no_svc() { ! has_svc "$@"; }
bucket_tags() { MC tag list "$1" --json 2>/dev/null | field tagset.team; }
has_tag() { [[ $(bucket_tags "$1") == "$2" ]]; }
anon() { MC anonymous get "$1" 2>/dev/null | awk '{print $NF}' | tr -d '`'; }
has_anon() { [[ $(anon "$1") == "$2" ]]; }
versioning() { MC version info "$1" --json 2>/dev/null | field versioning.status; }
enc() { MC encrypt info "$1" --json 2>/dev/null | field encryption.algorithm; }
has_enc() { [[ $(enc "$1") == "$2" ]]; }
quota() { MC quota info "$1" --json 2>/dev/null | field quota; }
has_quota() { [[ $(quota "$1") == "$2" ]]; }
sr_sites() { MC admin replicate info "$1" --json 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); print(" ".join(sorted(s["name"] for s in d.get("sites") or [])))'; }
same_object() { # alias/bucket/key alias/bucket/key
  local a b
  a=$(MC stat --json "$1" 2>/dev/null | field versionID)
  b=$(MC stat --json "$2" 2>/dev/null | field versionID)
  [[ -n "$a" && "$a" == "$b" ]]
}
cat_eq() { [[ $(MC cat "$1" 2>/dev/null) == "$2" ]]; }
# mc support perf site-replication, as the admin API answers it: the number
# of sites, whether each sent and received, their errors
siteperf() { # alias port
  curl -s -X POST --aws-sigv4 aws:amz:us-east-1:s3 --user rootadmin:rootsecret123 \
    "http://127.0.0.1:$2/minio/admin/v3/speedtest/site?duration=10s" | python3 -c 'import json,sys
r=json.load(sys.stdin)["nodeResults"]
print(len(r), all(x["tx"] > 0 for x in r), all(x["rx"] > 0 for x in r), sorted(x.get("error", "") for x in r),
      len({x["endpoint"] for x in r}))' 2>&1
}

# Three sites s1 s2 s3 of the given kinds, joined from s1 (which has data).
run_group() { # kind1 kind2 kind3
  CASE="$1,$2,$3"
  local dir="$WORK/g_$1_$2_$3"
  start "$1" "$PORT" s1 "$dir/s1"
  start "$2" "$((PORT + 1))" s2 "$dir/s2"
  start "$3" "$((PORT + 2))" s3 "$dir/s3"
  # data on s1 only
  MC mb s1/pre >/dev/null
  echo before >"$dir/f0"
  MC cp "$dir/f0" s1/pre/old >/dev/null
  MC tag set s1/pre "team=pre" >/dev/null
  cat >"$dir/pol.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::pre/*"]}]}
EOF
  MC admin policy create s1 prepol "$dir/pol.json" >/dev/null
  MC admin user add s1 preuser presecret123 >/dev/null
  MC admin policy attach s1 prepol --user preuser >/dev/null

  local out
  out=$(MC admin replicate add s1 s2 s3 --json 2>&1)
  check "replicate add" "$(field success <<<"$out")" True
  check "info s1" "$(sr_sites s1)" "s1 s2 s3"
  check "info s2" "$(sr_sites s2)" "s1 s2 s3"
  check "site perf from s1" "$(siteperf s1 "$PORT")" "3 True True ['', '', ''] 3"
  check "site perf from s2" "$(siteperf s2 "$((PORT + 1))")" "3 True True ['', '', ''] 3"
  check "info s3" "$(sr_sites s3)" "s1 s2 s3"

  # the initial sync
  for s in s2 s3; do
    wait_for 10 has_bucket $s pre || bad "$s: pre not created"
    check "$s pre versioning" "$(versioning $s/pre)" Enabled
    wait_for 10 has_tag $s/pre pre || bad "$s: pre tags: '$(bucket_tags $s/pre)'"
    wait_for 10 has_policy $s prepol || bad "$s: prepol missing"
    wait_for 10 has_user $s preuser || bad "$s: preuser missing"
    wait_for 10 has_user_policy $s preuser prepol || bad "$s: preuser policy '$(user_policy $s preuser)'"
  done

  # buckets and objects from each site
  local i=0
  for s in s1 s2 s3; do
    i=$((i + 1))
    MC mb "$s/bkt$i" >/dev/null || bad "$s: mb bkt$i"
    for t in s1 s2 s3; do
      [[ $t == "$s" ]] && continue
      wait_for 10 has_bucket $t "bkt$i" || bad "$t: bkt$i (made on $s) missing"
    done
    echo "data-$i" >"$dir/o$i"
    MC cp "$dir/o$i" "$s/bkt$i/obj" >/dev/null
    for t in s1 s2 s3; do
      [[ $t == "$s" ]] && continue
      wait_for 15 same_object "$s/bkt$i/obj" "$t/bkt$i/obj" || bad "$t: bkt$i/obj (put on $s) not replicated"
      check "$t bkt$i/obj data" "$(MC cat "$t/bkt$i/obj" 2>/dev/null)" "data-$i"
    done
  done
  # an object written on s3 into a bucket made on s1 reaches both others
  echo cross >"$dir/x"
  MC cp "$dir/x" s3/bkt1/cross >/dev/null
  wait_for 15 cat_eq s1/bkt1/cross cross || bad "s1: bkt1/cross (put on s3) missing"
  wait_for 15 cat_eq s2/bkt1/cross cross || bad "s2: bkt1/cross (put on s3) missing"

  # bucket metadata from each site
  MC tag set s2/bkt1 "team=two" >/dev/null
  wait_for 10 has_tag s1/bkt1 two || bad "s1: bkt1 tags '$(bucket_tags s1/bkt1)'"
  wait_for 10 has_tag s3/bkt1 two || bad "s3: bkt1 tags '$(bucket_tags s3/bkt1)'"
  MC anonymous set download s3/bkt2 >/dev/null
  wait_for 10 has_anon s1/bkt2 download || bad "s1: bkt2 anonymous '$(anon s1/bkt2)'"
  wait_for 10 has_anon s2/bkt2 download || bad "s2: bkt2 anonymous '$(anon s2/bkt2)'"
  MC encrypt set sse-s3 s1/bkt3 >/dev/null
  wait_for 10 has_enc s2/bkt3 AES256 || bad "s2: bkt3 encryption '$(enc s2/bkt3)'"
  wait_for 10 has_enc s3/bkt3 AES256 || bad "s3: bkt3 encryption '$(enc s3/bkt3)'"
  MC quota set s2/bkt3 --size 1GiB >/dev/null
  wait_for 10 has_quota s1/bkt3 1073741824 || bad "s1: bkt3 quota '$(quota s1/bkt3)'"
  wait_for 10 has_quota s3/bkt3 1073741824 || bad "s3: bkt3 quota '$(quota s3/bkt3)'"
  check "suspend refused" "$(MC version suspend s2/bkt1 >/dev/null 2>&1 && echo yes || echo no)" no

  # IAM from each site
  MC admin user add s2 usr2 u2secret1234 >/dev/null
  MC admin policy create s2 pol2 "$dir/pol.json" >/dev/null
  MC admin policy attach s2 pol2 --user usr2 >/dev/null
  for t in s1 s3; do
    wait_for 10 has_user $t usr2 || bad "$t: usr2 (added on s2) missing"
    wait_for 10 has_policy $t pol2 || bad "$t: pol2 (made on s2) missing"
    wait_for 10 has_user_policy $t usr2 pol2 || bad "$t: usr2 policy '$(user_policy $t usr2)'"
  done
  MC admin user add s1 usr1 u1secret1234 >/dev/null
  MC admin group add s3 grp3 usr1 usr2 >/dev/null
  for t in s1 s2; do
    wait_for 10 has_members $t grp3 "['usr1', 'usr2']" || bad "$t: grp3 members '$(group_members $t grp3)'"
  done
  wait_for 10 has_user s3 usr1 || bad "s3: usr1 (added on s1) missing"
  MC admin user disable s3 usr1 >/dev/null
  wait_for 10 bash -c "[[ \$('$MC_BIN' admin user info s1 usr1 --json | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"userStatus\"])') == disabled ]]" ||
    bad "s1: usr1 not disabled"
  MC admin user svcacct add s2 usr2 --access-key svc2acct --secret-key svc2secret1234 >/dev/null
  for t in s1 s3; do
    wait_for 10 has_svc $t svc2acct || bad "$t: svc2acct (made on s2) missing"
  done
  MC alias set svc1 "http://127.0.0.1:$PORT" svc2acct svc2secret1234 >/dev/null
  check "svc on s1" "$(MC cat svc1/pre/old 2>/dev/null)" before
  # STS from a bucketsd or MinIO site works on the others
  local sts
  sts=$(curl -s -X POST "http://127.0.0.1:$((PORT + 1))/" --aws-sigv4 "aws:amz:us-east-1:sts" --user usr2:u2secret1234 \
    -d "Action=AssumeRole&Version=2011-06-15&DurationSeconds=3600")
  local ak sk tok
  ak=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$sts")
  sk=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$sts")
  tok=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$sts")
  if [[ -z "$ak" ]]; then
    bad "AssumeRole on s2: $sts"
  else
    for p in $PORT $((PORT + 2)); do
      local code
      for _ in $(seq 50); do
        code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$p/pre/old" --aws-sigv4 "aws:amz:us-east-1:s3" \
          --user "$ak:$sk" -H "X-Amz-Security-Token: $tok")
        [[ $code == 200 ]] && break
        sleep 0.2
      done
      check "STS from s2 on :$p" "$code" 200
    done
  fi

  # deletions
  MC admin user svcacct rm s1 svc2acct >/dev/null
  wait_for 10 no_svc s2 svc2acct || bad "s2: svc2acct not deleted"
  MC admin policy detach s1 pol2 --user usr2 >/dev/null
  MC admin policy rm s3 pol2 >/dev/null
  wait_for 10 no_policy s1 pol2 || bad "s1: pol2 not deleted"
  MC admin user rm s1 usr2 >/dev/null
  wait_for 10 no_user s2 usr2 || bad "s2: usr2 not deleted"
  wait_for 10 no_user s3 usr2 || bad "s3: usr2 not deleted"
  MC rb --force s2/bkt2 >/dev/null 2>&1
  wait_for 10 no_bucket s1 bkt2 || bad "s1: bkt2 not deleted"
  wait_for 10 no_bucket s3 bkt2 || bad "s3: bkt2 not deleted"

  # the status each site reports
  local st
  for s in s1 s2 s3; do
    st=$(MC admin replicate status "$s" --json 2>&1)
    check "$s status enabled" "$(field Enabled <<<"$st")" True
    check "$s status maxBuckets" "$(field MaxBuckets <<<"$st")" "$(MC ls $s | wc -l | tr -d ' ')"
  done

  # a site that was down catches up through the heal routine
  stop_site s3
  MC admin user add s1 lateuser latesecret123 >/dev/null
  MC admin policy attach s1 readonly --user lateuser >/dev/null
  MC mb s1/latebkt >/dev/null
  MC tag set s2/bkt1 "team=late" >/dev/null
  MC admin policy create s2 latepol "$dir/pol.json" >/dev/null
  restart_site s3
  wait_for 120 has_user s3 lateuser || bad "s3: lateuser not healed"
  wait_for 60 has_user_policy s3 lateuser readonly || bad "s3: lateuser policy not healed '$(user_policy s3 lateuser)'"
  wait_for 60 has_policy s3 latepol || bad "s3: latepol not healed"
  wait_for 60 has_bucket s3 latebkt || bad "s3: latebkt not healed"
  wait_for 60 has_tag s3/bkt1 late || bad "s3: bkt1 tags not healed '$(bucket_tags s3/bkt1)'"
  echo healed >"$dir/h"
  MC cp "$dir/h" s3/latebkt/obj >/dev/null
  wait_for 15 cat_eq s1/latebkt/obj healed || bad "s1: latebkt/obj (put on s3) missing"

  # the existing object (from before the group) arrives after a resync
  MC admin replicate resync start s1 s2 >/dev/null 2>&1 || bad "resync start s1 -> s2"
  wait_for 30 cat_eq s2/pre/old before || bad "s2: pre/old not resynced"
  stop_all
}

# A bucketsd site joins a MinIO group, is resynced, and the MinIO sites leave.
run_handover() {
  CASE="handover"
  local dir="$WORK/handover"
  start minio "$PORT" s1 "$dir/s1"
  start minio "$((PORT + 1))" s2 "$dir/s2"
  start buckets "$((PORT + 2))" s3 "$dir/s3"
  MC admin replicate add s1 s2 >/dev/null || bad "minio group"
  MC mb s1/data >/dev/null
  head -c $((12 * 1024 * 1024)) /dev/urandom >"$dir/big"
  echo small >"$dir/small"
  MC cp "$dir/big" s1/data/big >/dev/null
  MC cp "$dir/small" s2/data/small >/dev/null
  MC admin user add s1 app appsecret1234 >/dev/null
  MC admin policy attach s1 readwrite --user app >/dev/null
  wait_for 15 cat_eq s2/data/small small || bad "minio group not replicating"

  local out
  out=$(MC admin replicate add s1 s2 s3 --json 2>&1)
  check "add s3" "$(field success <<<"$out")" True
  wait_for 10 has_bucket s3 data || bad "s3: data missing"
  wait_for 10 has_user s3 app || bad "s3: app missing"
  MC admin replicate resync start s1 s3 >/dev/null 2>&1 || bad "resync s1 -> s3"
  wait_for 60 cat_eq s3/data/small small || bad "s3: small not resynced"
  wait_for 60 same_object s1/data/big s3/data/big || bad "s3: big not resynced"
  check "s3 big data" "$(MC cat s3/data/big | md5sum_)" "$(md5sum_ <"$dir/big")"
  # new writes on a MinIO site keep flowing until the switch
  echo late >"$dir/late"
  MC cp "$dir/late" s2/data/late >/dev/null
  wait_for 15 cat_eq s3/data/late late || bad "s3: late write missing"

  # the MinIO sites leave; s3 carries on alone
  out=$(MC admin replicate rm s3 s1 s2 --force --json 2>&1)
  check "rm minio sites" "$(field status <<<"$out")" "Requested site(s) were removed from cluster replication successfully."
  check "s3 info" "$(MC admin replicate info s3 --json | field enabled)" False
  stop_all
  start buckets "$((PORT + 2))" s3 "$dir/s3" # after a restart too
  check "s3 data" "$(MC cat s3/data/small)" small
  MC alias set app3 "http://127.0.0.1:$((PORT + 2))" app appsecret1234 >/dev/null
  check "app on s3" "$(MC cat app3/data/late 2>/dev/null)" late
  check "s3 writable" "$(echo x | MC pipe app3/data/new >/dev/null 2>&1 && echo ok)" ok
  stop_all
}

for g in ${SR_GROUPS:-minio,buckets,buckets buckets,minio,minio}; do
  IFS=, read -r k1 k2 k3 <<<"$g"
  run_group "$k1" "$k2" "$k3"
done
[[ -z "${NO_HANDOVER:-}" ]] && run_handover
echo "siterepl: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
