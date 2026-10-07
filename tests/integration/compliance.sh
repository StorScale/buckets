#!/usr/bin/env bash
# The compliance reports' data (docs/design/compliance-reports.md): three
# buckets (locked with a default retention, encrypted by default with a KMS
# key, plain with a lifecycle that expires versions), objects of each kind,
# a scanner cycle, then GET /minio/admin/v3/buckets/compliance's settings
# and counts, and the per-bucket metrics.
#   tests/integration/compliance.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19800}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-compliance-XXXXXX")
EP="http://127.0.0.1:$PORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
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

mkdir -p "$WORK"/d{1..4}
MINIO_KMS_SECRET_KEY="test-key:$(openssl rand -base64 32)" MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_SCANNER_INTERVAL=1 \
  BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
PIDS+=($!)
until_true "curl -sf $EP/minio/health/ready"
export MC_CONFIG_DIR="$WORK/mc" MC_HOST_b="http://rootadmin:rootsecret123@127.0.0.1:$PORT"
api() { curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123 "$EP/minio/admin/v3/$1"; }
py() { python3 -c "import json,sys; d=json.load(sys.stdin); b={x['name']: x for x in d['buckets']}; $1"; }

echo "== three buckets, objects of each kind"
mc mb --with-lock b/vault >/dev/null
mc retention set --default governance 1d b/vault >/dev/null
head -c 1000 /dev/urandom >"$WORK/k1"; head -c 3000 /dev/urandom >"$WORK/k3"
mc cp -q "$WORK/k1" b/vault/a.bin >/dev/null              # default retention: governance
mc cp -q "$WORK/k3" b/vault/b.bin >/dev/null
mc retention set --bypass compliance 30d b/vault/b.bin >/dev/null  # compliance now (governance needs the bypass)
mc legalhold set b/vault/a.bin >/dev/null
mc mb b/secure >/dev/null
mc encrypt set sse-kms test-key b/secure >/dev/null
mc cp -q "$WORK/k1" b/secure/x.bin >/dev/null
mc cp -q "$WORK/k1" b/secure/y.bin >/dev/null
mc mb b/plain >/dev/null
mc version enable b/plain >/dev/null
mc ilm rule add --noncurrent-expire-days 30 b/plain >/dev/null
mc cp -q "$WORK/k3" b/plain/p.bin >/dev/null
mc cp -q "$WORK/k3" b/plain/p.bin >/dev/null  # two versions
mc rm -q b/plain/p.bin >/dev/null              # and a delete marker, counted nowhere

echo "== the settings, read now"
R=$(api buckets/compliance)
expect "the KMS" "$(py 'print(d["kms"]["configured"], d["kms"]["online"])' <<<"$R")" "True True"
expect "vault: object lock, governance for a day" \
  "$(py 'v=b["vault"]; print(v["versioning"], v["objectLock"]["enabled"], v["objectLock"]["mode"], v["objectLock"]["days"])' <<<"$R")" \
  "Enabled True GOVERNANCE 1"
expect "secure: SSE-KMS with its key, which works" \
  "$(py 'e=b["secure"]["encryption"]; print(e["algorithm"], e["keyId"], e["keyStatus"])' <<<"$R")" "SSE-KMS test-key ok"
expect "plain: no encryption, no lock, a lifecycle that expires versions" \
  "$(py 'p=b["plain"]; print(repr(p["encryption"]["algorithm"]), p["objectLock"]["enabled"], p["lifecycleExpires"])' <<<"$R")" "'' False True"
expect "vault's lifecycle: none" "$(py 'print(b["vault"]["lifecycleExpires"])' <<<"$R")" False

echo "== the counts, after a scanner cycle"
until_true "[[ \$(api buckets/compliance | python3 -c 'import json,sys; d=json.load(sys.stdin); print(all(x[\"counts\"] for x in d[\"buckets\"]) and d[\"scannedAt\"] > 0)') == True ]]" 300 || true
R=$(api buckets/compliance)
expect "a cycle's time" "$(py 'import time; print(abs(time.time() - d["scannedAt"]) < 120)' <<<"$R")" True
expect "vault: one under governance, one under compliance, one on legal hold" \
  "$(py 'c=b["vault"]["counts"]; print(c["governance"]["versions"], c["governance"]["bytes"], c["compliance"]["versions"], c["compliance"]["bytes"], c["legalHold"]["versions"])' <<<"$R")" \
  "1 1000 1 3000 1"
expect "vault: retained until about 30 days from now" \
  "$(py 'import time; print(29*86400 < b["vault"]["counts"]["latestRetainUntil"] - time.time() <= 30*86400)' <<<"$R")" True
expect "secure: both versions SSE-KMS, none unencrypted" \
  "$(py 'c=b["secure"]["counts"]; print(c["sseKms"]["versions"], c["sseKms"]["bytes"], c["unencrypted"]["versions"])' <<<"$R")" "2 2000 0"
expect "plain: two unencrypted versions; the delete marker not counted" \
  "$(py 'c=b["plain"]["counts"]; print(c["unencrypted"]["versions"], c["unencrypted"]["bytes"])' <<<"$R")" "2 6000"

echo "== a bucket made after the cycle has settings but no counts yet"
mc mb b/newer >/dev/null
expect "counts: null" "$(api buckets/compliance | py 'print(b["newer"]["counts"])')" None

echo "== metrics"
M=$(curl -s "$EP/minio/v2/metrics/bucket")
val() { awk -v n="$1" '$1 == n {print $2}' <<<"$M" | head -1; }
expect "unencrypted bytes" "$(val 'buckets_bucket_unencrypted_bytes{bucket="plain",server="127.0.0.1:'$PORT'"}')" 6000
expect "encrypted bytes by kind" "$(val 'buckets_bucket_encrypted_bytes{bucket="secure",kind="sse-kms",server="127.0.0.1:'$PORT'"}')" 2000
expect "retained bytes by mode" "$(val 'buckets_bucket_retained_bytes{bucket="vault",mode="compliance",server="127.0.0.1:'$PORT'"}')" 3000
expect "no samples outside the catalog" "$(grep -c 'samples outside the catalog' "$WORK/log" || true)" 0

echo "== who may read it"
mc admin user add b nosy nosysecret123 >/dev/null
mc admin policy attach b readwrite --user nosy >/dev/null
expect "without admin:DataUsageInfo: refused" \
  "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user nosy:nosysecret123 "$EP/minio/admin/v3/buckets/compliance")" 403
expect "no sanitizer reports" "$(grep -c 'Sanitizer\|runtime error' "$WORK/log" || true)" 0
echo "compliance: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
