#!/usr/bin/env bash
# The lifecycle and replication editor's server side (docs/design/lifecycle-replication-editor.md), in a cluster of
# four with a console:
#   - POST buckets/lifecycle-preview: what draft rules would do, now and within 7 and 30 days, without acting;
#     stopped short ("at least") at BUCKETS_LIFECYCLE_PREVIEW_MAX; refused without the bucket's permissions;
#   - incomplete multipart uploads: removed after stale_uploads_expiry, or sooner by an
#     AbortIncompleteMultipartUpload rule for their prefix; the upload's recorded key stays off the object;
#   - GET buckets/replication: a bucket's targets and every server's counts added up;
#     buckets_bucket_replication_pending_count in the bucket metrics;
#   - POST buckets/replication-test (madmin-encrypted, through consoled): SetRemoteTarget's checks, nothing saved.
#   tests/integration/lifecycle-editor.sh [bucketsd] [consoled]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
BASE=${PORT:-19940}
CPORT=$((BASE + 9))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-lceditor-XXXXXX")
AK=rootadmin
SK=rootsecret123
PIDS=(0 0 0 0 0)
CPID=0
cleanup() {
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  [[ $CPID != 0 ]] && kill "$CPID" 2>/dev/null || true
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
until_true() { for _ in $(seq "${2:-150}"); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

ep() { echo "http://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d1"); done
start() { # node [env...]
  local n=$1
  shift
  env MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_UPLOADS_SWEEP_INTERVAL=2 "$@" \
    BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
}
stop() { kill "${PIDS[$1]}"; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
ready() { [[ $(curl -s -o /dev/null -w "%{http_code}" "$(ep "$1")/minio/health/cluster") == 200 ]]; }
all_ready() { ready 1 && ready 2 && ready 3 && ready 4; }
# expiry 7 days: only lifecycle's abort rules remove uploads in the first part
for n in 1 2 3 4; do
  if [[ $n == 2 ]]; then start "$n" MINIO_API_STALE_UPLOADS_EXPIRY=168h BUCKETS_LIFECYCLE_PREVIEW_MAX=3
  else start "$n" MINIO_API_STALE_UPLOADS_EXPIRY=168h; fi
done
until_true all_ready 300
s3() { # node method path [curl args]
  local n=$1 m=$2 p=$3
  shift 3
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" -X "$m" "$@" "$(ep "$n")$p"
}
admin() { local n=$1 m=$2 p=$3; shift 3; s3 "$n" "$m" "/minio/admin/v3/$p" "$@"; }
q() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
export MC_HOST_a="http://$AK:$SK@127.0.0.1:$((BASE + 1))"
export MC_HOST_b="http://$AK:$SK@127.0.0.1:$((BASE + 3))"

# ---- the preview ----------------------------------------------------------------------------------------------
mc mb -q a/logs >/dev/null
mc version enable a/logs >/dev/null
for k in logs/a.log logs/b.log keep/k.txt logs/a.log; do echo "$k" | mc pipe -q "a/logs/$k" >/dev/null; done
RULES='<LifecycleConfiguration><Rule><ID>old-logs</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Date>2020-01-01T00:00:00Z</Date></Expiration></Rule><Rule><ID>versions</ID><Status>Enabled</Status><Filter></Filter><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>'
prev() { admin "$1" POST "buckets/lifecycle-preview?bucket=${2:-logs}" -H "Content-Type: application/xml" --data "${3:-$RULES}"; }
expect "logs expire on the next run, the old version within 7 days" \
  "$(prev 1 | q "sorted((a['rule'], a['action'], a['when'], a['objects']) for a in d['actions'])")" \
  "[('old-logs', 'expire', 'next-run', 2), ('versions', 'delete-version', '7d', 1)]"
expect "every version looked at; saving would open a ransomware alert" "$(prev 3 | q "(d['scanned'], d['complete'], d['opensIncident'])")" "(4, True, True)"
expect "examples name the keys" "$(prev 1 | q "[a['examples'] for a in d['actions'] if a['rule']=='old-logs'][0]")" "['logs/a.log', 'logs/b.log']"
expect "nothing changed by looking" "$(mc ls --versions a/logs --recursive | wc -l | tr -d ' ')" 4
expect "stopped short at the limit: at least" "$(prev 2 | q "(d['scanned'] >= 3, d['scanned'] < 4, d['complete'])")" "(True, True, False)"
expect "rules S3 refuses are refused, in words" \
  "$(prev 1 logs '<LifecycleConfiguration><Rule><ID>x</ID><Status>Enabled</Status><Filter></Filter></Rule></LifecycleConfiguration>' | q "d['Code']")" InvalidArgument
expect "a bucket that isn't there" "$(prev 1 nosuch | q "d['Code']")" NoSuchBucket
mc admin user add a reader readersecret1 >/dev/null
mc admin policy attach a readonly --user reader >/dev/null
expect "without the bucket's lifecycle permission: refused" \
  "$(curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user reader:readersecret1 -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" -X POST --data "$RULES" "$(ep 1)/minio/admin/v3/buckets/lifecycle-preview?bucket=logs" | q "d['Code']")" AccessDenied

# ---- incomplete uploads ---------------------------------------------------------------------------------------
mc mb -q a/upl >/dev/null
s3 1 PUT "/upl?lifecycle" -H "Content-MD5: $(printf '%s' '<LifecycleConfiguration><Rule><ID>tmp</ID><Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>' | openssl md5 -binary | base64)" \
  --data '<LifecycleConfiguration><Rule><ID>tmp</ID><Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>' >/dev/null
expect "the abort rule is kept and returned" "$(s3 1 GET "/upl?lifecycle" | grep -o '<DaysAfterInitiation>1</DaysAfterInitiation>')" "<DaysAfterInitiation>1</DaysAfterInitiation>"
new_upload() { s3 "$1" POST "/upl/$2?uploads" | grep -o '<UploadId>[^<]*' | cut -c11-; }
uploads() { s3 1 GET "/upl?uploads&prefix=$1" | grep -c '<UploadId>' || true; }
new_upload 1 tmp/old.bin >/dev/null
new_upload 2 keep/old.bin >/dev/null
new_upload 3 tmp/new.bin >/dev/null
expect "three uploads under way" "$(($(uploads tmp/old.bin) + $(uploads keep/old.bin) + $(uploads tmp/new.bin)))" 3
# two days pass for the "old" ones: their directories say when they started
python3 - "$WORK" <<'PY'
import os, sys, time, subprocess
work = sys.argv[1]
old = (time.time_ns() - 2 * 86400 * 10**9)
for n in range(1, 5):
    mp = f"{work}/n{n}/d1/.minio.sys/multipart"
    for sha in os.listdir(mp) if os.path.isdir(mp) else []:
        for u in os.listdir(f"{mp}/{sha}"):
            meta = open(f"{mp}/{sha}/{u}/xl.meta", "rb").read()
            if b"old.bin" in meta:
                os.rename(f"{mp}/{sha}/{u}", f"{mp}/{sha}/{u.rsplit('x', 1)[0]}x{old}")
PY
expect "each upload records which object it is for" \
  "$(find "$WORK"/n*/d1/.minio.sys/multipart -name xl.meta | xargs grep -al 'buckets-upload-key' | wc -l | awk '{print ($1 >= 3)}')" 1
until_true '[[ $(uploads tmp/old.bin) == 0 ]]' 100 || true
expect "an old upload under tmp/ is aborted by the rule" "$(uploads tmp/old.bin)" 0
expect "an old one elsewhere, and a new one under tmp/, stay" "$(uploads keep/old.bin) $(uploads tmp/new.bin)" "1 1"
expect "on every drive" "$(find "$WORK"/n*/d1/.minio.sys/multipart -name xl.meta 2>/dev/null | xargs grep -l 'tmp/old.bin' 2>/dev/null | wc -l | tr -d ' ')" 0
# a finished upload doesn't keep the key it recorded
ID=$(new_upload 1 done.bin)
dd if=/dev/urandom of="$WORK/part" bs=1k count=8 2>/dev/null
ET=$(s3 1 PUT "/upl/done.bin?partNumber=1&uploadId=$ID" --data-binary @"$WORK/part" -D - -o /dev/null | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
s3 1 POST "/upl/done.bin?uploadId=$ID" --data "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>$ET</ETag></Part></CompleteMultipartUpload>" >/dev/null
expect "the finished object" "$(mc stat --json a/upl/done.bin | q "d['size']")" 8192
expect "doesn't carry the upload's recorded key" \
  "$(grep -al 'buckets-upload-key' "$WORK"/n*/d1/upl/done.bin/xl.meta 2>/dev/null | wc -l | tr -d ' ')" 0
# then uploads simply expire: a day here is 6 seconds
for n in 1 2 3 4; do stop "$n"; start "$n" MINIO_API_STALE_UPLOADS_EXPIRY=6s; done
until_true all_ready 300
until_true '[[ $(uploads keep/old.bin) == 0 && $(uploads tmp/new.bin) == 0 ]]' 150 || true
expect "past stale_uploads_expiry, every upload goes" "$(uploads keep/old.bin) $(uploads tmp/new.bin)" "0 0"
expect "and the servers say so" "$(cat "$WORK"/log* | grep -c 'removed .* incomplete multipart uploads' | awk '{print ($1 > 0)}')" 1

# ---- replication: state from every server ---------------------------------------------------------------------
mc mb -q a/src a/dst a/dst2 >/dev/null
mc version enable a/src >/dev/null
mc version enable a/dst >/dev/null
mc replicate add a/src --remote-bucket "http://$AK:$SK@127.0.0.1:$((BASE + 1))/dst" >/dev/null
for i in 1 2 3 4 5 6 7 8; do
  n=$(((i % 4) + 1))
  echo "object $i" | MC_HOST_x="http://$AK:$SK@127.0.0.1:$((BASE + n))" mc pipe -q "x/src/o$i.txt" >/dev/null
done
repl() { admin "$1" GET "buckets/replication${2:+?bucket=$2}"; }
until_true '[[ $(repl 2 src | q "d[\"buckets\"][0][\"targets\"][0][\"replicated\"]") == 8 ]]' 150 || true
expect "every server's replicated objects, added up, from any server" \
  "$(repl 2 src | q "(d['servers'], d['serversAnswering'], d['buckets'][0]['targets'][0]['replicated'], d['buckets'][0]['targets'][0]['bucket'])")" "(4, 4, 8, 'dst')"
expect "the bucket's rule names the target" "$(repl 3 src | q "d['buckets'][0]['rules'][0]['arn'] == d['buckets'][0]['targets'][0]['arn']")" True
until_true '[[ $(repl 1 src | q "d[\"buckets\"][0][\"targets\"][0][\"online\"]") == True ]]' 100 || true
expect "the target is online" "$(repl 1 src | q "d['buckets'][0]['targets'][0]['online']")" True
expect "every bucket that replicates, and only those" "$(repl 4 | q "[b['bucket'] for b in d['buckets']]")" "['src']"
expect "objects arrived" "$(mc ls a/dst | wc -l | tr -d ' ')" 8
expect "the bucket metrics say what waits" \
  "$(curl -s "$(ep 1)/minio/v2/metrics/bucket" | grep -c '^buckets_bucket_replication_pending_count{bucket="src"' | awk '{print ($1 > 0)}')" 1

# ---- replication-test, through the console (it madmin-encrypts) -----------------------------------------------
CONSOLE_MINIO_SERVER="$(ep 1)" BUCKETS_CONSOLE_S3_URL="$(ep 1)" CONSOLE_PBKDF_PASSPHRASE=t CONSOLE_PBKDF_SALT=t \
  "$CBIN" --address "127.0.0.1:$CPORT" 2>>"$WORK/console.log" &
CPID=$!
C="http://127.0.0.1:$CPORT"
until_true "curl -sf $C/healthz"
J="$WORK/jar"
curl -s -c "$J" -H "X-Console-Request: 1" -d "{\"accessKey\":\"$AK\",\"secretKey\":\"$SK\"}" "$C/api/v1/login" >/dev/null
rtest() { # bucket target-bucket secret
  curl -s -b "$J" -H "X-Console-Request: 1" -H "X-Console-Encrypt: 1" -H "X-Console-Decrypt: 1" -X POST \
    --data "{\"sourcebucket\":\"$1\",\"endpoint\":\"127.0.0.1:$((BASE + 1))\",\"secure\":false,\"api\":\"s3v4\",\"type\":\"replication\",\"targetbucket\":\"$2\",\"credentials\":{\"accessKey\":\"$AK\",\"secretKey\":\"$3\"}}" \
    "$C/api/v1/admin/buckets/replication-test?bucket=$1"
}
expect "a versioned target passes" "$(rtest logs dst "$SK")" '{"ok":true,"sourceVersioned":true}'
expect "the source's versioning is reported, not refused" "$(rtest upl dst "$SK" | q "(d['ok'], d['sourceVersioned'])")" "(True, False)"
expect "a target without versioning: refused, saying so" "$(rtest logs dst2 "$SK" | q "d['Code']")" RemoteTargetNotVersionedError
expect "wrong credentials: refused" "$(rtest logs dst wrongsecret | q "d['Code']")" XMinioAdminReplicationRemoteConnectionError
expect "nothing was saved" "$(mc admin bucket remote ls a/logs --json 2>/dev/null | grep -c '"arn"' || true)" 0

expect "no sanitizer reports" "$(cat "$WORK"/log* | grep -c 'Sanitizer\|runtime error' || true)" 0
echo "lifecycle-editor: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
