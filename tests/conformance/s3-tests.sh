#!/usr/bin/env bash
# Runs ceph/s3-tests (functional/test_s3.py) against a fresh server over TLS
# and writes a JUnit report; s3-tests-compare.py diffs two reports.
#   tests/conformance/s3-tests.sh buckets [bucketsd]   -> $WORK/buckets.xml
#   tests/conformance/s3-tests.sh minio               -> $WORK/minio.xml (needs MINIO_BIN)
# Needs MC_BIN (the alt user is made with mc admin) and a Python with the
# s3-tests requirements plus pytest-timeout (S3TESTS_PYTHON). Extra pytest
# arguments go in S3TESTS_ARGS, a -k expression in S3TESTS_K (e.g. "versioning and not copy").
set -euo pipefail
KIND=${1:?buckets or minio}
BIN=${2:-build/src/bucketsd}
S3TESTS_REF=5522d1c351f75bc00ae0f64f742f3f095f5939d9 # ceph/s3-tests main, 2026-09-28
WORK=${WORK:-.conformance}
PORT=${PORT:-19550}
PY=${S3TESTS_PYTHON:-python3}
: "${MC_BIN:?set MC_BIN}"
[[ $KIND == minio ]] && : "${MINIO_BIN:?set MINIO_BIN}"
mkdir -p "$WORK"
WORK=$(cd "$WORK" && pwd)
if [[ ! -d "$WORK/s3-tests" ]]; then
  git clone -q https://github.com/ceph/s3-tests.git "$WORK/s3-tests"
  git -C "$WORK/s3-tests" checkout -q "$S3TESTS_REF"
fi

MAIN_AK=0555b35654ad1656d804 MAIN_SK='h7GhxuBLTrlhVUyxSPUKUV8r/2EI4ngqJxD7iBdBYLhwluN30JaT3Q=='
ALT_AK=NOPQRSTUVWXYZABCDEFG ALT_SK=nopqrstuvwxyzabcdefghijklmnabcdefghijklm
D=$(mktemp -d "${TMPDIR:-/tmp}/buckets-s3t-XXXXXX")
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true
  rm -rf "$D"
}
trap cleanup EXIT
mkdir -p "$D"/d{1..4} "$D/certs/CAs" "$D/mc"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 1 \
  -keyout "$D/certs/private.key" -out "$D/certs/public.crt" -subj /CN=localhost \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
cp "$D/certs/public.crt" "$D/certs/CAs/"
export MINIO_ROOT_USER=$MAIN_AK MINIO_ROOT_PASSWORD=$MAIN_SK
export MINIO_KMS_SECRET_KEY=s3tests-key:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=
if [[ $KIND == minio ]]; then
  MINIO_CI_CD=on MINIO_BROWSER=off "$MINIO_BIN" server --quiet --address "127.0.0.1:$PORT" --certs-dir "$D/certs" \
    "$D/d{1...4}" >"$WORK/$KIND.log" 2>&1 &
else
  "$BIN" server --address "127.0.0.1:$PORT" --certs-dir "$D/certs" "$D/d{1...4}" 2>"$WORK/$KIND.log" &
fi
PID=$!
for _ in $(seq 150); do curl -sk -o /dev/null "https://127.0.0.1:$PORT/minio/health/live" && break; sleep 0.1; done

export MC_CONFIG_DIR="$D/mc"
"$MC_BIN" alias set --insecure s3t "https://127.0.0.1:$PORT" "$MAIN_AK" "$MAIN_SK" >/dev/null
"$MC_BIN" admin user add --insecure s3t "$ALT_AK" "$ALT_SK" >/dev/null
"$MC_BIN" admin policy attach --insecure s3t readwrite --user "$ALT_AK" >/dev/null
# setup() lists (and cleans) buckets as every configured user
for u in HIJKLMNOPQRSTUVWXYZA:opqrstuvwxyzabcdefghijklmnopqrstuvwxyzab ABCDEFGHIJKLMNOPQRST:abcdefghijklmnopqrstuvwxyzabcdefghijklmn \
  AAAAAAAAAAAAAAAAAAaa:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa BBBBBBBBBBBBBBBBBBbb:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; do
  "$MC_BIN" admin user add --insecure s3t "${u%%:*}" "${u#*:}" >/dev/null
  "$MC_BIN" admin policy attach --insecure s3t readwrite --user "${u%%:*}" >/dev/null
done

cat >"$D/s3tests.conf" <<EOF
[DEFAULT]
host = 127.0.0.1
port = $PORT
is_secure = True
ssl_verify = False

[fixtures]
bucket prefix = s3t-{random}-

[s3 main]
display_name = minio
user_id = 02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4
email = main@example.com
api_name = us-east-1
access_key = $MAIN_AK
secret_key = $MAIN_SK

[s3 alt]
display_name = alt
email = alt@example.com
user_id = 02d6176db174dc93cb1b899f7c6078f08654445fe8cf1b6ce98d8855f66bdbf4
access_key = $ALT_AK
secret_key = $ALT_SK

[s3 tenant]
display_name = tenant
user_id = tenant
access_key = HIJKLMNOPQRSTUVWXYZA
secret_key = opqrstuvwxyzabcdefghijklmnopqrstuvwxyzab
email = tenant@example.com
tenant = testx

[iam]
email = s3@example.com
user_id = iam
access_key = ABCDEFGHIJKLMNOPQRST
secret_key = abcdefghijklmnopqrstuvwxyzabcdefghijklmn
display_name = iam

[iam root]
access_key = AAAAAAAAAAAAAAAAAAaa
secret_key = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
account_id = RGW11111111111111111
user_id = RGW11111111111111111
email = account1@example.com

[iam alt root]
access_key = BBBBBBBBBBBBBBBBBBbb
secret_key = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
account_id = RGW22222222222222222
user_id = RGW22222222222222222
email = account2@example.com
EOF
cd "$WORK/s3-tests"
# shellcheck disable=SC2086
S3TEST_CONF="$D/s3tests.conf" "$PY" -m pytest s3tests/functional/test_s3.py -q -p no:cacheprovider --timeout 120 \
  --junitxml "$WORK/$KIND.xml" ${S3TESTS_K:+-k "$S3TESTS_K"} ${S3TESTS_ARGS:-} >"$WORK/$KIND.out" 2>&1 || true
tail -1 "$WORK/$KIND.out"
