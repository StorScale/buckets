#!/usr/bin/env bash
# The usage and chargeback reports' history (docs/design/usage-reports.md): in
# a cluster of four (so that a slow one, under a sanitizer, holds no lock up),
# two servers count traffic to three buckets in two teams and add it to their own
# daily records, the leader samples sizes at each scanner cycle, the day moves
# over midnight (BUCKETS_USAGE_TEST_DAY) with the servers restarted, and
# GET buckets/usage adds it all up as sent, per bucket and per team. Then the
# rates, bad periods, and days older than what is kept being removed.
#   tests/integration/usage-reports.sh [bucketsd] [consoled]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
BASE=${PORT:-19830}
CPORT=$((BASE + 9))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-usage-reports-XXXXXX")
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
start() { # node day [env...]
  local n=$1 day=$2
  shift 2
  env BUCKETS_SCANNER_INTERVAL=1 BUCKETS_USAGE_FLUSH_INTERVAL=1 BUCKETS_USAGE_TEST_DAY="$day" "$@" \
    BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
}
stop() { kill "${PIDS[$1]}"; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
ready() { [[ $(curl -s -o /dev/null -w "%{http_code}" "$(ep "$1")/minio/health/cluster") == 200 ]]; } # write quorum, locks too
s3() { # node method path [curl args] -> HTTP status
  local n=$1 m=$2 p=$3
  shift 3
  curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X "$m" "$@" "$(ep "$n")$p"
}
admin() { # node method path [curl args]
  local n=$1 m=$2 p=$3
  shift 3
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X "$m" "$@" "$(ep "$n")/minio/admin/v3/$p"
}
# until each node takes write locks on the other: health can answer before a peer's lock server does
locks() {
  local n
  for n in 1 2 3 4; do
    [[ $(admin "$n" PUT buckets/usage-rates -o /dev/null -w '%{http_code}' -d '{"currency":"X"}') == 200 ]] || return 1
    [[ $(admin "$n" DELETE buckets/usage-rates -o /dev/null -w '%{http_code}') == 200 ]] || return 1
  done
}
report() { admin 1 GET "buckets/usage?from=$1&to=$2"; }
# a figure from the report: report FROM TO | q 'python expression over d'
q() { python3 -c "import json,sys; d=json.load(sys.stdin); B={b['name']:b for b in d.get('buckets',[])}; T={t['name']:t for t in d.get('teams',[])}; print($1)"; }

for n in 1 2 3 4; do start "$n" 2026-09-30; done
until_true "ready 1 && ready 2 && ready 3 && ready 4 && locks" 300
env CONSOLE_MINIO_SERVER="$(ep 1)" CONSOLE_PBKDF_PASSPHRASE=it CONSOLE_PBKDF_SALT=it \
  "$CBIN" --address "127.0.0.1:$CPORT" 2>"$WORK/clog" &
CPID=$!
until_true "curl -s -o /dev/null http://127.0.0.1:$CPORT/healthz"
C="http://127.0.0.1:$CPORT"
H=(-H "X-Console-Request: 1" -H "Content-Type: application/json" -b "$WORK/jar")
curl -s -o /dev/null -c "$WORK/jar" "${H[@]}" -d "{\"accessKey\":\"$AK\",\"secretKey\":\"$SK\"}" "$C/api/v1/login"

for b in logs web-site misc; do s3 1 PUT "/$b" >/dev/null; done
curl -s -o /dev/null "${H[@]}" -X PUT -d '{"team":{"name":"ops","buckets":["logs"],"levels":["rw"]}}' "$C/api/v1/teams/ops"
curl -s -o /dev/null "${H[@]}" -X PUT -d '{"team":{"name":"web","prefixes":["web-"],"levels":["rw"]}}' "$C/api/v1/teams/web"
expect "two teams saved" "$(curl -s "${H[@]}" "$C/api/v1/teams" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["teams"]))')" 2

# ---- 30 September: traffic through both servers ---------------------------------------------
head -c 1000 /dev/urandom >"$WORK/k1"
head -c 500 /dev/urandom >"$WORK/k05"
expect "the traffic sent" "$(s3 1 PUT /logs/a --data-binary @"$WORK/k1") $(s3 2 PUT /web-site/index.html --data-binary @"$WORK/k05") \
$(s3 1 PUT /misc/x --data-binary @"$WORK/k05") $(s3 2 GET /logs/a) $(s3 2 GET /logs/a) $(s3 2 DELETE /misc/x)" "200 200 200 200 200 204"
until_true "[[ \$(report 2026-09-30 2026-09-30 | q 'B[\"logs\"][\"dataOut\"] >= 2000 and B[\"logs\"][\"dataIn\"] == 1000 and B[\"misc\"][\"dataIn\"] == 500 and B[\"web-site\"][\"dataIn\"] == 500 and B[\"web-site\"][\"storage\"][\"lastBytes\"] == 500 and B[\"misc\"][\"requests\"][\"delete\"] == 1') == True ]]" 300 || true
R=$(report 2026-09-30 2026-09-30)
expect "logs: 1000 bytes in, through server 1" "$(q 'B["logs"]["dataIn"]' <<<"$R")" 1000
expect "logs: read twice through server 2" "$(q 'B["logs"]["dataOut"], B["logs"]["requests"]["read"]' <<<"$R")" "2000 2"
expect "logs: one write" "$(q 'B["logs"]["requests"]["write"]' <<<"$R")" 1
expect "misc: a write and a delete" "$(q 'B["misc"]["requests"]["write"], B["misc"]["requests"]["delete"]' <<<"$R")" "1 1"
expect "sizes from the scanner" "$(q 'B["logs"]["storage"]["lastBytes"], B["web-site"]["storage"]["peakBytes"]' <<<"$R")" "1000 500"
expect "each bucket's team: by name, by prefix, none" "$(q '[B[b]["team"] for b in ("logs", "web-site", "misc")]' <<<"$R")" "['ops', 'web', None]"
expect "the teams' totals, with No team" "$(q 'sorted((t["name"] or "-", t["buckets"], t["dataIn"]) for t in d["teams"])' <<<"$R")" \
  "[('-', ['misc'], 500), ('ops', ['logs'], 1000), ('web', ['web-site'], 500)]"
expect "one day, none missing, no rates" "$(q 'd["days"], d["missingDays"], d["rates"]' <<<"$R")" "1 [] None"

# ---- over midnight: the servers restarted on 1 October ---------------------------------------
sleep 2 # one more flush of anything counted
for n in 1 2 3 4; do stop "$n"; done
for n in 1 2 3 4; do start "$n" 2026-10-01; done
until_true "ready 1 && ready 2 && ready 3 && ready 4 && locks" 300
expect "the traffic sent" "$(s3 2 PUT /logs/b --data-binary @"$WORK/k1") $(s3 1 GET /logs/b)" "200 200"
until_true "[[ \$(report 2026-10-01 2026-10-01 | q 'B[\"logs\"][\"dataOut\"] == 1000 and B[\"logs\"][\"dataIn\"] == 1000 and B[\"logs\"][\"storage\"][\"lastBytes\"] == 2000') == True ]]" 300 || true
R=$(report 2026-09-30 2026-10-01)
expect "logs: the deltas from before the restart kept" "$(q 'B["logs"]["dataIn"], B["logs"]["dataOut"]' <<<"$R")" "2000 3000"
expect "logs: day by day" "$(q '[(x["day"], x["in"], x["out"]) for x in B["logs"]["daily"]]' <<<"$R")" \
  "[('2026-09-30', 1000, 2000), ('2026-10-01', 1000, 1000)]"
expect "logs: the day's average size, between what the cycles saw" \
  "$(q '[0 < x["bytes"] <= m for x, m in zip(B["logs"]["daily"], (1000, 2000))]' <<<"$R")" "[True, True]"
expect "two days, none missing" "$(q 'd["days"], d["missingDays"]' <<<"$R")" "2 []"
expect "GB-months: daily averages over the days in their month" \
  "$(q 'abs(B["logs"]["storage"]["gbMonths"] * 1e9 - (B["logs"]["daily"][0]["bytes"] / 30 + B["logs"]["daily"][1]["bytes"] / 31)) < 0.05' <<<"$R")" True
expect "days before the first record are missing" "$(report 2026-09-28 2026-09-30 | q 'd["missingDays"]')" "['2026-09-28', '2026-09-29']"
expect "the default period: this month so far" "$(admin 1 GET buckets/usage | q 'd["from"], d["to"]')" "2026-10-01 2026-10-01"

# ---- rates -------------------------------------------------------------------------------------
expect "rates: a bad one refused, in words" \
  "$(admin 1 PUT buckets/usage-rates -d '{"currency":"USD","outGb":-1}' | q 'd["Message"]')" "outGb is a price from 0"
expect "rates: set" "$(admin 1 PUT buckets/usage-rates -o /dev/null -w '%{http_code}' -d '{"currency":"EUR","storageGbMonth":0.02,"outGb":0.05,"junk":1}')" 200
expect "rates: in the report, as stored" "$(report 2026-10-01 2026-10-01 | q 'd["rates"]')" "{'currency': 'EUR', 'storageGbMonth': 0.02, 'outGb': 0.05}"
expect "rates: read by the other server" "$(admin 2 GET 'buckets/usage?from=2026-10-01&to=2026-10-01' | q 'd["rates"]["currency"]')" EUR
expect "rates: removed" "$(admin 1 DELETE buckets/usage-rates -o /dev/null -w '%{http_code}')" 200
expect "rates: none" "$(report 2026-10-01 2026-10-01 | q 'd["rates"]')" None

# ---- bad periods, and who may ------------------------------------------------------------------
expect "a period backwards" "$(admin 1 GET 'buckets/usage?from=2026-10-02&to=2026-10-01' -o /dev/null -w '%{http_code}')" 400
expect "not a day" "$(admin 1 GET 'buckets/usage?from=2026-02-30&to=2026-10-01' -o /dev/null -w '%{http_code}')" 400
mcx() { MC_CONFIG_DIR="$WORK/mc" mc "$@"; }
mcx alias set it "$(ep 1)" "$AK" "$SK" >/dev/null
mcx admin user add it reader readersecret1 >/dev/null
mcx admin policy attach it readonly --user reader >/dev/null
expect "a user without admin:DataUsageInfo is refused" \
  "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user reader:readersecret1 "$(ep 1)/minio/admin/v3/buckets/usage")" 403

# ---- days older than kept are removed ------------------------------------------------------------
for n in 1 2 3 4; do stop "$n"; done
for n in 1 2 3 4; do start "$n" 2026-10-02 BUCKETS_USAGE_HISTORY_DAYS=1; done
until_true "ready 1 && ready 2 && ready 3 && ready 4 && locks" 300
until_true "[[ \$(report 2026-09-30 2026-10-01 | q 'd[\"missingDays\"]') == \"['2026-09-30', '2026-10-01']\" ]]" 300 || true
expect "older days removed; today's kept" "$(report 2026-09-30 2026-10-02 | q 'd["missingDays"], B["logs"]["storage"]["lastBytes"]')" \
  "['2026-09-30', '2026-10-01'] 2000"
expect "no sanitizer reports, leaks at the restarts included" "$(cat "$WORK"/log* | grep -c 'Sanitizer\|runtime error' || true)" 0
echo "usage-reports: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
