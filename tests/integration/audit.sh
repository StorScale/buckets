#!/usr/bin/env bash
# The audit log viewer and forwarding (docs/design/audit-log.md), in a cluster
# of four. Two people's requests through different servers are kept on each
# server's own drive and come back from any server through GET buckets/audit:
# merged newest first, filtered by person, key, bucket, prefix, kind, status
# and API, and paged with a cursor without repeats; a restarted server keeps
# its entries. Entries also reach Microsoft Sentinel (a fake Entra ID token
# endpoint and Logs Ingestion API: the DCR, the stream, a bearer token got once,
# JSON arrays), held while it is down, and Splunk (a fake HTTP Event Collector)
# through the audit webhook. BUCKETS_AUDIT_LOCAL_READS=off leaves reads out.
#   tests/integration/audit.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
BASE=${PORT:-19930} # clear of the console browser tests (19889-19892)
FPORT=$((BASE + 9))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-audit-XXXXXX")
AK=rootadmin
SK=rootsecret123
PIDS=(0 0 0 0 0)
FPID=0
cleanup() {
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  [[ $FPID != 0 ]] && kill "$FPID" 2>/dev/null || true
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

# Entra ID's token endpoint, Azure Monitor's Logs Ingestion API and Splunk's HEC, all fakes
cat >"$WORK/fakes.py" <<'PY'
import http.server, json, sys, urllib.parse
work = sys.argv[2]
def log(name, obj):
    with open(f"{work}/{name}", "a") as f: f.write(json.dumps(obj) + "\n")
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.path == "/tenant-1/oauth2/v2.0/token":
            f = urllib.parse.parse_qs(body.decode())
            log("tokens", {k: v[0] for k, v in f.items() if k != "client_secret"} | {"secret_ok": f.get("client_secret") == ["s3cret"]})
            out = json.dumps({"access_token": "tok-1", "expires_in": 3600, "token_type": "Bearer"}).encode()
        elif self.path.startswith("/dataCollectionRules/"):
            if self.headers.get("Authorization") != "Bearer tok-1":
                self.send_response(401); self.end_headers(); return
            log("sentinel", {"path": self.path, "records": json.loads(body)})
            self.send_response(204); self.end_headers(); return
        elif self.path.startswith("/services/collector/raw"):
            log("splunk", {"auth": self.headers.get("Authorization"), "lines": body.decode().count("\n")})
            out = b'{"text":"Success","code":0}'
        else:
            self.send_response(404); self.end_headers(); return
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
fakes() { python3 "$WORK/fakes.py" "$FPORT" "$WORK" & FPID=$!; }
fakes
F="http://127.0.0.1:$FPORT"

ep() { echo "http://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d1"); done
start() { # node [env...]
  local n=$1
  shift
  env BUCKETS_AUDIT_SENTINEL_ENDPOINT="$F" BUCKETS_AUDIT_SENTINEL_DCR_ID=dcr-0123 \
    BUCKETS_AUDIT_SENTINEL_STREAM=Custom-BucketsAudit_CL BUCKETS_AUDIT_SENTINEL_TENANT_ID=tenant-1 \
    BUCKETS_AUDIT_SENTINEL_CLIENT_ID=app-1 BUCKETS_AUDIT_SENTINEL_CLIENT_SECRET=s3cret BUCKETS_AUDIT_SENTINEL_LOGIN_URL="$F" \
    MINIO_AUDIT_WEBHOOK_ENABLE_splunk=on MINIO_AUDIT_WEBHOOK_ENDPOINT_splunk="$F/services/collector/raw?sourcetype=minio:audit" \
    MINIO_AUDIT_WEBHOOK_AUTH_TOKEN_splunk="Splunk hec-token" "$@" \
    MINIO_PROMETHEUS_AUTH_TYPE=public BUCKETS_ROOT_USER=$AK BUCKETS_ROOT_PASSWORD=$SK \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
}
stop() { kill "${PIDS[$1]}"; wait "${PIDS[$1]}" 2>/dev/null || true; PIDS[$1]=0; }
for n in 1 2 3 4; do start "$n"; done
ready() { [[ $(curl -s -o /dev/null -w "%{http_code}" "$(ep "$1")/minio/health/cluster") == 200 ]]; }
admin() { # node method path [curl args]
  local n=$1 m=$2 p=$3
  shift 3
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -X "$m" "$@" "$(ep "$n")/minio/admin/v3/$p"
}
locks() {
  local n
  for n in 1 2 3 4; do
    [[ $(admin "$n" PUT buckets/usage-rates -o /dev/null -w '%{http_code}' -d '{"currency":"X"}') == 200 ]] || return 1
    [[ $(admin "$n" DELETE buckets/usage-rates -o /dev/null -w '%{http_code}') == 200 ]] || return 1
  done
}
until_true "ready 1 && ready 2 && ready 3 && ready 4 && locks" 300
export MC_CONFIG_DIR="$WORK/mc" MC_HOST_r="http://$AK:$SK@127.0.0.1:$((BASE + 1))"
audit() { admin "${1:-1}" GET "buckets/audit?${2:-}"; }
q() { python3 -c "import json,sys; d=json.load(sys.stdin); E=d['entries']; print($1)"; }
FROM=$(date -u -d '-5 min' +%Y-%m-%dT%H:%M:%SZ)

# ---- two people, through different servers -------------------------------------------------------------------
for u in alice bob; do
  mc admin user add r "$u" "${u}secret123" >/dev/null
  mc admin user svcacct add r "$u" --access-key "${u}key01" --secret-key "${u}keysecret1" >/dev/null
done
mc admin policy attach r readwrite --user alice >/dev/null
mc admin policy attach r readonly --user bob >/dev/null
mc mb -q r/ledger >/dev/null
export MC_HOST_a="http://alicekey01:alicekeysecret1@127.0.0.1:$((BASE + 2))"
export MC_HOST_b="http://bobkey01:bobkeysecret1@127.0.0.1:$((BASE + 3))"
# mc cp of a small file is one PutObject (mc pipe would be a multipart upload)
mkdir -p "$WORK/files"
for i in $(seq 12); do echo "entry $i" >"$WORK/files/$i.csv"; mc cp -q "$WORK/files/$i.csv" "a/ledger/2026/q4/$i.csv" >/dev/null; done
mc cat a/ledger/2026/q4/1.csv >/dev/null
mc rm -q a/ledger/2026/q4/12.csv >/dev/null
mc cat b/ledger/2026/q4/2.csv >/dev/null
mc cp -q "$WORK/files/1.csv" b/ledger/2026/q4/bob.csv >/dev/null 2>&1 || true # readonly: denied
sleep 2 # each server's writer flushes every second

expect "alice's actions, through server 2, asked of server 1" \
  "$(audit 1 "from=$FROM&user=alice&bucket=ledger&limit=100" | q "({'DeleteMultipleObjects', 'GetObject', 'PutObject'} <= {e['api']['name'] for e in E}, all(e['node'].endswith(':$((BASE + 2))') for e in E))")" \
  "(True, True)"
expect "newest first" "$(audit 1 "from=$FROM&user=alice&limit=100" | q "[e['time'] for e in E] == sorted([e['time'] for e in E], reverse=True)")" True
expect "by access key and kind" "$(audit 4 "from=$FROM&accessKey=bobkey01&kind=read" | q "('GetObject' in {e['api']['name'] for e in E}, all(e['accessKey'] == 'bobkey01' for e in E))")" "(True, True)"
expect "by kind: deletes" "$(audit 1 "from=$FROM&bucket=ledger&kind=delete" | q "[(e['parentUser'], e['api']['objects'][0]['objectName'] if e['api'].get('objects') else e['api'].get('object')) for e in E]")" \
  "[('alice', '2026/q4/12.csv')]"
expect "by status: bob's denied write among his refusals" \
  "$(audit 2 "from=$FROM&status=denied&bucket=ledger" | q "(('bob', 'PutObject', 403) in {(e['parentUser'], e['api']['name'], e['api']['statusCode']) for e in E}, all(e['api']['statusCode'] in (401, 403) for e in E))")" \
  "(True, True)"
expect "by prefix and API" "$(audit 3 "from=$FROM&prefix=2026/q4/1&api=PutObject" | q "len(E)")" 4 # 1, 10, 11, 12
expect "admin calls, as admin" "$(audit 1 "from=$FROM&kind=admin&limit=500" | q "'AddServiceAccount' in {e['api']['name'] for e in E}")" True
expect "every server answered" "$(audit 1 "from=$FROM&limit=1" | q "[(c['reachable'], c['enabled'], c['oldest'] > 0, c['dropped']) for c in d['coverage']]")" \
  "[(True, True, True, 0), (True, True, True, 0), (True, True, True, 0), (True, True, True, 0)]"
# paging: 5 at a time, all of alice's puts, none twice
pages=0 seen=""
cursor=""
while :; do
  r=$(audit 1 "from=$FROM&user=alice&api=PutObject&limit=5${cursor:+&cursor=$cursor}")
  seen+=$(q "' '.join(e['requestID'] for e in E) + ' '" <<<"$r")
  cursor=$(q "d['cursor'] or ''" <<<"$r")
  pages=$((pages + 1))
  [[ -z $cursor || $pages -gt 10 ]] && break
done
expect "paged with a cursor: every entry once" "$(tr ' ' '\n' <<<"$seen" | grep -c . ) $(tr ' ' '\n' <<<"$seen" | grep . | sort -u | wc -l)" "12 12"
expect "bad parameters are refused, in words" "$(audit 1 'kind=everything' | python3 -c 'import json,sys; print(json.load(sys.stdin)["Message"])')" \
  "kind is read, write, delete, admin or system"
expect "a user without admin:ServerInfo is refused" \
  "$(curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user bobkey01:bobkeysecret1 "$(ep 1)/minio/admin/v3/buckets/audit")" 403

# ---- a restart keeps what was written --------------------------------------------------------------------------
stop 2
start 2
until_true "ready 2 && locks" 300
expect "after server 2 restarts, alice's entries are still there" \
  "$(audit 1 "from=$FROM&user=alice&api=PutObject&limit=100" | q "len(E)")" 12

# ---- Sentinel ---------------------------------------------------------------------------------------------------
until_true "[[ -s '$WORK/sentinel' ]]" 100 || true
expect "Sentinel: batches to the DCR's stream" \
  "$(python3 -c 'import json,sys; p={json.loads(l)["path"] for l in open(sys.argv[1])}; print(p)' "$WORK/sentinel")" \
  "{'/dataCollectionRules/dcr-0123/streams/Custom-BucketsAudit_CL?api-version=2023-01-01'}"
expect "each a JSON array of audit entries, alice's among them" \
  "$(python3 -c '
import json,sys
recs=[r for l in open(sys.argv[1]) for r in json.loads(l)["records"]]
print(all("api" in r and "time" in r for r in recs), any(r.get("parentUser")=="alice" for r in recs))' "$WORK/sentinel")" "True True"
expect "the token asked for once per server, as the app, for Azure Monitor" \
  "$(python3 -c '
import json,sys
t=[json.loads(l) for l in open(sys.argv[1])]
print(len(t) <= 5, {(x["grant_type"], x["client_id"], x["scope"], x["secret_ok"]) for x in t})' "$WORK/tokens")" \
  "True {('client_credentials', 'app-1', 'https://monitor.azure.com/.default', True)}"
# while Azure is down, entries wait; then they arrive
kill "$FPID"; wait "$FPID" 2>/dev/null || true
: >"$WORK/sentinel"
echo late | mc pipe -q a/ledger/late.csv >/dev/null
sleep 2
fakes
until_true "grep -q 'late.csv' '$WORK/sentinel'" 150 || true
expect "held while Sentinel was down, sent once it was back" "$(grep -c 'late.csv' "$WORK/sentinel")" 1

# ---- Splunk, through the audit webhook ---------------------------------------------------------------------------
until_true "[[ -s '$WORK/splunk' ]]" 100 || true
expect "Splunk's collector got entries with its token" \
  "$(python3 -c 'import json,sys; s=[json.loads(l) for l in open(sys.argv[1])]; print({x["auth"] for x in s}, sum(x["lines"] for x in s) > 10)' "$WORK/splunk")" \
  "{'Splunk hec-token'} True"

# ---- metrics ----------------------------------------------------------------------------------------------------
expect "each server says what its copy holds, and that it dropped none" \
  "$(for n in 1 2 3 4; do curl -s "$(ep "$n")/minio/v2/metrics/node"; done | awk '/^buckets_node_audit_local_bytes/ && $2 > 0 {k++} /^buckets_node_audit_dropped_total/ {d += $2} END {print k, d}')" "4 0"

# ---- reads left out ---------------------------------------------------------------------------------------------
stop 4
start 4 BUCKETS_AUDIT_LOCAL_READS=off
until_true "ready 4 && locks" 300
export MC_HOST_c="http://alicekey01:alicekeysecret1@127.0.0.1:$((BASE + 4))"
mc cat c/ledger/2026/q4/3.csv >/dev/null
mc cp -q "$WORK/files/1.csv" c/ledger/reads-off.csv >/dev/null
sleep 2
expect "with reads off, server 4 keeps the write and not the read" \
  "$(audit 1 "from=$FROM&prefix=reads-off&api=PutObject" | q "len(E)") $(audit 1 "from=$FROM&prefix=2026/q4/3.csv&api=GetObject" | q "len([e for e in E if e['node'].endswith(':$((BASE + 4))')])")" "1 0"

expect "no sanitizer reports" "$(cat "$WORK"/log* | grep -c 'Sanitizer\|runtime error' || true)" 0
echo "audit: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
