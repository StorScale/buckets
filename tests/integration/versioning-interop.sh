#!/usr/bin/env bash
# Versioned objects on disk, both ways between MinIO and bucketsd: versions,
# delete markers and null versions written by one are listed identically and
# read back byte for byte by the other; object and bucket tags carry over.
#   MINIO_BIN=/path/to/minio tests/integration/versioning-interop.sh [bucketsd]
# Skips (exit 0) when MINIO_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MINIO_BIN:-}" ]]; then
  echo "versioning-interop: skipped (set MINIO_BIN)"
  exit 0
fi
PORT=${PORT:-19810}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-verx-XXXXXX")
EP="http://127.0.0.1:$PORT"
D="$WORK/drives"
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- log"; tail -20 "$WORK/log"; exit 1; }
export MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123
S3=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
start() {
  if [[ $1 == minio ]]; then
    MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" "$D/d{1...4}" >>"$WORK/log" 2>&1 &
  else
    "$BIN" server --address "127.0.0.1:$PORT" "$D/d{1...4}" 2>>"$WORK/log" &
  fi
  PID=$!
  for _ in $(seq 150); do [[ $(curl -s -o /dev/null -w '%{http_code}' "${S3[@]}" "$EP/") == 200 ]] && return; sleep 0.1; done
  fail "$1 did not start"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }
put() { curl -s -D - -o /dev/null "${S3[@]}" -X PUT --data-binary "$2" "$EP/vxb/$1" | tr -d '\r' |
  sed -n 's/^[Xx]-[Aa]mz-[Vv]ersion-[Ii]d: //p'; }
versioning() {
  curl -sf "${S3[@]}" -X PUT --data-binary "<VersioningConfiguration><Status>$1</Status></VersioningConfiguration>" \
    "$EP/vxb?versioning" >/dev/null || fail "versioning $1"
}
# The listing without per-request noise.
listing() { curl -s "${S3[@]}" "$EP/vxb?versions" | perl -pe 's/<Owner>.*?<\/Owner>//g'; }
# Every version's content, in listing order.
contents() {
  python3 - "$EP" <<'PY'
import re, subprocess, sys
ep = sys.argv[1]
S3 = ["--aws-sigv4", "aws:amz:us-east-1:s3", "--user", "rootadmin:rootsecret123"]
x = subprocess.run(["curl", "-s"] + S3 + [ep + "/vxb?versions"], capture_output=True, text=True).stdout
for m in re.finditer(r"<Version><Key>([^<]*)</Key>.*?<VersionId>([^<]*)</VersionId></Version>", x):
    body = subprocess.run(["curl", "-s"] + S3 + [ep + "/vxb/" + m.group(1) + "?versionId=" + m.group(2)],
                          capture_output=True, text=True).stdout
    print(m.group(1), m.group(2), body)
PY
}

mkdir -p "$D"/d{1..4}
echo "== bucketsd writes versions, markers and null versions"
start buckets
curl -sf "${S3[@]}" -X PUT "$EP/vxb" >/dev/null || fail "make bucket"
put plain.txt "before versioning" >/dev/null
versioning Enabled
put a.txt one >/dev/null
put a.txt two >/dev/null
put big.bin "$(head -c 300000 /dev/zero | tr '\0' 'x')" >/dev/null
put gone.txt soon >/dev/null
curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/vxb/gone.txt"
versioning Suspended
put a.txt three >/dev/null
curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/vxb/plain.txt"
tagdoc='<Tagging><TagSet><Tag><Key>team</Key><Value>a b</Value></Tag></TagSet></Tagging>'
curl -sf "${S3[@]}" -X PUT --data-binary "$tagdoc" "$EP/vxb/big.bin?tagging" >/dev/null || fail "object tagging"
curl -sf "${S3[@]}" -X PUT --data-binary "$tagdoc" "$EP/vxb?tagging" >/dev/null || fail "bucket tagging"
listing >"$WORK/l1.buckets"
contents >"$WORK/c1.buckets"
stop
start minio
for t in "vxb/big.bin?tagging" "vxb?tagging"; do
  curl -s "${S3[@]}" "$EP/$t" | grep -q '<Key>team</Key><Value>a b</Value>' || fail "MinIO reads bucketsd's tags ($t)"
done
listing >"$WORK/l1.minio"
contents >"$WORK/c1.minio"
diff "$WORK/l1.buckets" "$WORK/l1.minio" >/dev/null || { diff "$WORK/l1.buckets" "$WORK/l1.minio"; fail "MinIO lists bucketsd's versions differently"; }
diff "$WORK/c1.buckets" "$WORK/c1.minio" >/dev/null || fail "MinIO reads bucketsd's versions differently"
[[ $(grep -o '<DeleteMarker>' "$WORK/l1.minio" | wc -l | tr -d ' ') == 2 ]] || fail "two delete markers expected"
echo "== MinIO writes, bucketsd reads"
versioning Enabled
put a.txt four >/dev/null
put b.txt bee >/dev/null
curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/vxb/b.txt"
listing >"$WORK/l2.minio"
contents >"$WORK/c2.minio"
stop
start buckets
listing >"$WORK/l2.buckets"
contents >"$WORK/c2.buckets"
diff "$WORK/l2.minio" "$WORK/l2.buckets" >/dev/null || { diff "$WORK/l2.minio" "$WORK/l2.buckets"; fail "bucketsd lists MinIO's versions differently"; }
diff "$WORK/c2.minio" "$WORK/c2.buckets" >/dev/null || fail "bucketsd reads MinIO's versions differently"
echo "== bucketsd removes a MinIO delete marker, MinIO agrees"
dm=$(perl -ne 'print $1 if /<DeleteMarker><Key>b\.txt<\/Key>.*?<VersionId>([^<]*)<\/VersionId>/' "$WORK/l2.buckets")
[[ -n "$dm" ]] || fail "no marker for b.txt"
curl -s -o /dev/null "${S3[@]}" -X DELETE "$EP/vxb/b.txt?versionId=$dm"
[[ $(curl -s "${S3[@]}" "$EP/vxb/b.txt") == bee ]] || fail "b.txt back"
stop
start minio
[[ $(curl -s "${S3[@]}" "$EP/vxb/b.txt") == bee ]] || fail "MinIO sees b.txt back"
stop
echo "PASS"
