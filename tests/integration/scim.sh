#!/usr/bin/env bash
# SCIM (docs/design/scim.md), in a cluster of four. Requests reach servers other than the one that syncs:
#   - SCIM only: Entra's provisioning sequence (look up, create, turn off with its "Replace"/"False" patch, turn on,
#     delete) and Okta's PUT turn the people's access keys off and on within seconds; a deleted person's keys go
#     after the grace period; someone SCIM never named is left alone; everyone unassigned at once is held by the
#     safety limit; a wrong token is refused and counted; Groups are not supported; changes are audited; the admin
#     API's view (buckets/scim) shows the people and who is matched.
#   - SCIM beside Entra's API: what SCIM says wins for the people it names, Graph answers for the rest, and the
#     previous token still works while a new one rolls out.
#   tests/integration/scim.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
BASE=${PORT:-19960}
OPORT=$((BASE + 9))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-scim-XXXXXX")
ISS="http://127.0.0.1:$OPORT"
TENANT=tenant-1
AKR=rootadmin
SKR=rootsecret123
PIDS=(0 0 0 0 0)
SPID=0
cleanup() {
  for n in 1 2 3 4; do [[ ${PIDS[$n]} != 0 ]] && kill "${PIDS[$n]}" 2>/dev/null || true; done
  [[ $SPID != 0 ]] && kill "$SPID" 2>/dev/null || true
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

# ---- the stand-in: an OpenID provider (ID tokens), Microsoft's sign-in and Graph --------------------------------
openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
cat >"$WORK/standin.py" <<'PY'
import base64, http.server, json, subprocess, sys, time, urllib.parse
port, work, iss = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def run(*a, data=None): return subprocess.run(a, input=data, capture_output=True, check=True).stdout
mod = run('openssl', 'rsa', '-in', work + '/rsa.pem', '-noout', '-modulus').decode().strip().split('=')[1]
JWK = {'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': b64(bytes.fromhex(mod)), 'e': 'AQAB'}
people = {}  # oid -> active | disabled | gone, for Graph
def mint(claims):
    now = int(time.time())
    body = {'iss': iss, 'aud': 'buckets-app', 'iat': now, 'exp': now + 3600, **claims}
    msg = (b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'}).encode()) + '.' + b64(json.dumps(body).encode())).encode()
    return msg.decode() + '.' + b64(run('openssl', 'dgst', '-sha256', '-sign', work + '/rsa.pem', data=msg))
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, status, doc):
        b = json.dumps(doc).encode()
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/.well-known/openid-configuration':
            return self.reply(200, {'issuer': iss, 'jwks_uri': iss + '/jwks', 'authorization_endpoint': iss + '/authorize',
                                    'token_endpoint': iss + '/token'})
        if u.path == '/jwks': return self.reply(200, {'keys': [JWK]})
        if u.path == '/mint': return self.reply(200, mint(json.loads(urllib.parse.parse_qs(u.query)['claims'][0])))
        if u.path.startswith('/v1.0/users/'):
            oid = urllib.parse.unquote(u.path[len('/v1.0/users/'):])
            st = people.get(oid, 'gone')
            if st == 'gone': return self.reply(404, {'error': {'code': 'Request_ResourceNotFound'}})
            return self.reply(200, {'id': oid, 'accountEnabled': st == 'active'})
        self.reply(404, {})
    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if u.path.startswith('/control/'):
            _, _, oid, st = u.path.split('/'); people[oid] = st
            return self.reply(200, {})
        if u.path.endswith('/oauth2/v2.0/token'):
            return self.reply(200, {'access_token': 'graph-token', 'expires_in': 3599})
        self.reply(404, {})
http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$WORK/standin.py" "$OPORT" "$WORK" "$ISS" 2>>"$WORK/standin.log" &
SPID=$!
until_true "curl -sf $ISS/jwks" || { echo "stand-in did not start"; cat "$WORK/standin.log"; exit 1; }
graph() { curl -sf -X POST "$ISS/control/$1/$2" >/dev/null; } # oid state

# ---- the cluster ------------------------------------------------------------------------------------------------
TOKEN=$(openssl rand -hex 32)
TOKEN_SHA=$(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)
ep() { echo "http://127.0.0.1:$((BASE + $1))"; }
ENDPOINTS=()
for n in 1 2 3 4; do ENDPOINTS+=("$(ep "$n")$WORK/n$n/d1"); done
start() { # node [env...]
  local n=$1
  shift
  env MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
    BUCKETS_SCIM_POLL=1 BUCKETS_OPENID_REMOVE_AFTER=8s BUCKETS_OPENID_REMOVE_MAX=2 MINIO_PROMETHEUS_AUTH_TYPE=public "$@" \
    BUCKETS_ROOT_USER=$AKR BUCKETS_ROOT_PASSWORD=$SKR \
    "$BIN" server --address "127.0.0.1:$((BASE + n))" "${ENDPOINTS[@]}" 2>>"$WORK/log$n" &
  PIDS[$n]=$!
}
stop_all() { for n in 1 2 3 4; do kill "${PIDS[$n]}"; wait "${PIDS[$n]}" 2>/dev/null || true; PIDS[$n]=0; done; }
ready() { [[ $(curl -s -o /dev/null -w "%{http_code}" "$(ep "$1")/minio/health/cluster") == 200 ]]; }
all_ready() { ready 1 && ready 2 && ready 3 && ready 4; }
SCIM_ONLY=(BUCKETS_OPENID_SYNC_PROVIDER=scim BUCKETS_OPENID_SYNC_TENANT_ID=$TENANT BUCKETS_SCIM_TOKEN_SHA256=$TOKEN_SHA
  BUCKETS_OPENID_SYNC_INTERVAL=3)
for n in 1 2 3 4; do start "$n" "${SCIM_ONLY[@]}"; done
until_true all_ready 300
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user $AKR:$SKR)
until_true "curl -sf ${R[*]@Q} -X PUT $(ep 1)/docs" 150 || true # IAM and the drives may still be coming up
until_true "echo hello | curl -sf ${R[*]@Q} -X PUT --data-binary @- $(ep 1)/docs/a.txt" 150 || true
export MC_CONFIG_DIR="$WORK/mc"
export MC_HOST_rootalias="http://$AKR:$SKR@127.0.0.1:$((BASE + 1))"

# scim <node> <method> <path> [json] [token]: the body, then the status on its own line
scim() {
  local args=(-s -w '\n%{http_code}' -X "$2" -H "Authorization: Bearer ${5:-$TOKEN}" -H "Content-Type: application/scim+json")
  [[ -n "${4:-}" ]] && args+=(--data "$4")
  curl "${args[@]}" "$(ep "$1")/minio/scim/v2$3"
}
status() { tail -n1; }
body() { sed '$d'; }
q() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# sign_in <name> <oid> [tid]: temporary credentials from an ID token (AK SK TK), and an mc alias for them
sign_in() {
  local claims='{"sub":"sub-'$1'","oid":"'$2'","tid":"'${3:-$TENANT}'","preferred_username":"'$1'","policy":"readwrite"}'
  local tok r
  tok=$(curl -sf --get --data-urlencode "claims=$claims" "$ISS/mint" | tr -d '"')
  r=$(curl -s -X POST --data-urlencode Action=AssumeRoleWithWebIdentity --data-urlencode Version=2011-06-15 \
    --data-urlencode "WebIdentityToken=$tok" "$(ep 1)/")
  AK=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$r")
  SK=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$r")
  TK=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$r")
  [[ -n $AK ]] || { echo "no credentials for $1: $r"; exit 1; }
  export "MC_HOST_$1=http://$AK:$SK:$TK@127.0.0.1:$((BASE + 1))"
}
sts_code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" -H "X-Amz-Security-Token: $3" "$(ep 1)/docs/a.txt"; }
key_code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:${1}secret123" "$(ep 2)/docs/a.txt"; }
new_key() { mc admin accesskey create "$1" --access-key "$2" --secret-key "${2}secret123" >/dev/null; }
key_status() { mc admin accesskey info rootalias "$1" --json 2>/dev/null | sed -n 's/.*"accountStatus":"\([a-z]*\)".*/\1/p'; }
user_json() { printf '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"%s","externalId":"%s","active":true,"displayName":"%s","emails":[{"primary":true,"type":"work","value":"%s"}]}' "$1" "$2" "$1" "$1"; }
entra_off() { printf '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"%s"}]}' "$1"; }

until_true '[[ $(scim 1 GET /Users | status) == 200 ]]' 150 || true
echo "== discovery and the token"
expect "ServiceProviderConfig, from any server" "$(scim 3 GET /ServiceProviderConfig | body | q "(d['patch']['supported'], d['bulk']['supported'], d['filter']['supported'])")" "(True, False, True)"
expect "a wrong token is refused" "$(scim 2 GET /Users '' wrong-token | status)" 401
expect "no token at all" "$(curl -s -o /dev/null -w '%{http_code}' "$(ep 2)/minio/scim/v2/Users")" 401
expect "Groups are not supported" "$(scim 1 GET /Groups | status)" 501
expect "the refusal is counted" \
  "$(curl -s "$(ep 2)/minio/v2/metrics/node" | awk '/^buckets_scim_requests_total.*result="unauthorized"/ {s += $2} END {print s}')" 2

echo "== Entra provisions ann, bob and cat"
expect "ann isn't there yet" "$(scim 3 GET '/Users?filter=userName+eq+%22ann%40contoso.com%22' | body | q "d['totalResults']")" 0
R1=$(scim 3 POST /Users "$(user_json ann@contoso.com o-ann)"); echo "$R1" | grep -q "\"id\"" || echo "create said: $R1"; ANN_ID=$(echo "$R1" | body | q "d['id']")
BOB_ID=$(scim 4 POST /Users "$(user_json bob@contoso.com o-bob)" | body | q "d['id']")
CAT_ID=$(scim 2 POST /Users "$(user_json cat@contoso.com o-cat)" | body | q "d['id']")
expect "ann found by userName, any case" "$(scim 4 GET '/Users?filter=userName+eq+%22ANN%40contoso.com%22' | body | q "(d['totalResults'], d['Resources'][0]['externalId'])")" "(1, 'o-ann')"
expect "and by externalId" "$(scim 1 GET '/Users?filter=externalId+eq+%22o-bob%22' | body | q "d['Resources'][0]['id']")" "$BOB_ID"
expect "a second ann is refused" "$(scim 1 POST /Users "$(user_json ann@contoso.com o-other)" | status)" 409
expect "ann by ID, with where she is" "$(scim 2 GET "/Users/$ANN_ID" | body | q "d['meta']['location'].endswith('/minio/scim/v2/Users/$ANN_ID')")" True
expect "someone not there" "$(scim 2 GET /Users/nope | status)" 404

echo "== people sign in and make access keys; zed is never named by SCIM"
sign_in ann o-ann; ANN=("$AK" "$SK" "$TK"); new_key ann KEYANN0001
sign_in bob o-bob; new_key bob KEYBOB0001
sign_in cat o-cat; new_key cat KEYCAT0001
sign_in zed o-zed; new_key zed KEYZED0001
expect "ann's key works" "$(key_code KEYANN0001)" 200
expect "the admin API sees who is matched" "$(admin() { curl -s "${R[@]}" "$(ep 3)/minio/admin/v3/$1"; }; admin buckets/scim | q "(d['enabled'], d['provider'], d['holders'], d['matched'], len(d['people']))")" "(True, 'scim', 4, 3, 3)"

echo "== Entra turns ann off (\"Replace\", \"False\"): her keys go within seconds"
expect "the patch is taken" "$(scim 4 PATCH "/Users/$ANN_ID" "$(entra_off False)" | body | q "d['active']")" False
until_true "[[ \$(key_status KEYANN0001) == off ]]" 100 || true
expect "ann's key turned off" "$(key_code KEYANN0001)" 403
expect "her temporary credentials gone" "$(sts_code "${ANN[@]}")" 403
expect "bob's key still works" "$(key_code KEYBOB0001)" 200
expect "zed, never named by SCIM, is left alone" "$(key_code KEYZED0001)" 200
expect "logged by the server that syncs" "$(cat "$WORK"/log* | grep -c 'identity sync: disable access key KEYANN0001 (owner disabled in the provider)')" 1

echo "== Entra turns ann back on: her key comes back"
scim 1 PATCH "/Users/$ANN_ID" '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","value":{"active":true}}]}' >/dev/null
until_true "[[ \$(key_status KEYANN0001) == on ]]" 100 || true
expect "ann's key back on" "$(key_code KEYANN0001)" 200

echo "== Okta's way, a PUT with active false: bob's key goes"
expect "the PUT is taken" "$(scim 2 PUT "/Users/$BOB_ID" '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"bob@contoso.com","externalId":"o-bob","active":false}' | body | q "d['active']")" False
until_true "[[ \$(key_status KEYBOB0001) == off ]]" 100 || true
expect "bob's key turned off" "$(key_code KEYBOB0001)" 403

echo "== cat is deleted: her key goes, and after the grace period is gone"
expect "deleted" "$(scim 3 DELETE "/Users/$CAT_ID" | status)" 204
expect "and no longer found" "$(scim 3 GET "/Users/$CAT_ID" | status)" 404
until_true "[[ \$(key_status KEYCAT0001) == off ]]" 100 || true
expect "cat's key turned off" "$(key_code KEYCAT0001)" 403
until_true "[[ -z \$(key_status KEYCAT0001) ]]" 150 || true
expect "and deleted after the grace period (8s here)" "$(key_status KEYCAT0001)" ""

echo "== everyone unassigned at once is held by the safety limit"
for p in dee eve fay; do
  scim 1 POST /Users "$(user_json $p@contoso.com o-$p)" >/dev/null
  sign_in "$p" "o-$p"; new_key "$p" "KEY${p^^}0001"
done
for p in dee eve fay; do
  id=$(scim 4 GET "/Users?filter=externalId+eq+%22o-$p%22" | body | q "d['Resources'][0]['id']")
  scim 4 PATCH "/Users/$id" "$(entra_off False)" >/dev/null
done
until_true "cat $WORK/log* | grep -q 'more than BUCKETS_OPENID_REMOVE_MAX'" 100 || true
expect "three at once, more than 2: held, and logged" "$(cat "$WORK"/log* | grep -c 'more than BUCKETS_OPENID_REMOVE_MAX' | awk '{print ($1 > 0)}')" 1
expect "their keys still work" "$(key_code KEYDEE0001) $(key_code KEYEVE0001) $(key_code KEYFAY0001)" "200 200 200"

echo "== audit and metrics"
sleep 2
expect "SCIM's changes are in the audit log" \
  "$(curl -s "${R[@]}" "$(ep 1)/minio/admin/v3/buckets/audit?api=SCIMUpdateUser&limit=100" | q "len(d['entries']) >= 2")" True
expect "requests counted, by op" \
  "$(for n in 1 2 3 4; do curl -s "$(ep "$n")/minio/v2/metrics/node"; done | awk '/^buckets_scim_requests_total.*op="update".*result="ok"/ {s += $2} END {print (s >= 6)}')" 1
expect "people counted by the server that syncs: bob, dee, eve and fay off" \
  "$(for n in 1 2 3 4; do curl -s "$(ep "$n")/minio/v2/metrics/node"; done | awk '/^buckets_scim_people.*state="off"/ {s += $2} END {print s}')" 4

echo "== SCIM beside Entra's API, with a new token rolling out"
NEW=$(openssl rand -hex 32)
NEW_SHA=$(printf '%s' "$NEW" | sha256sum | cut -d' ' -f1)
stop_all
graph o-zed gone   # Graph says zed left; SCIM never named him
graph o-ann active # Graph says ann is active, SCIM is told she's off
for p in bob dee eve fay; do graph "o-$p" active; done
for n in 1 2 3 4; do
  start "$n" BUCKETS_OPENID_SYNC_PROVIDER=entra BUCKETS_OPENID_SYNC_TENANT_ID=$TENANT BUCKETS_OPENID_SYNC_CLIENT_ID=app \
    BUCKETS_OPENID_SYNC_CLIENT_SECRET=s BUCKETS_OPENID_SYNC_LOGIN_URL="$ISS" BUCKETS_OPENID_SYNC_GRAPH_URL="$ISS" \
    BUCKETS_OPENID_SYNC_INTERVAL=2 BUCKETS_OPENID_REMOVE_MAX=10 BUCKETS_SCIM=on BUCKETS_SCIM_TOKEN_SHA256=$NEW_SHA \
    BUCKETS_SCIM_TOKEN_SHA256_PREVIOUS=$TOKEN_SHA
done
until_true all_ready 300
expect "the new token works" "$(scim 1 GET /ServiceProviderConfig '' "$NEW" | status)" 200
expect "and the previous one, meanwhile" "$(scim 1 GET /ServiceProviderConfig | status)" 200
until_true "curl -sf ${R[*]@Q} $(ep 3)/minio/admin/v3/buckets/scim" 100 || true
expect "the admin API says SCIM is on beside Entra" "$(curl -s "${R[@]}" "$(ep 3)/minio/admin/v3/buckets/scim" | q "(d['enabled'], d['provider'])")" "(True, 'entra')"
expect "turned off with the new token" "$(scim 2 PATCH "/Users/$ANN_ID" "$(entra_off False)" "$NEW" | body | q "d['active']")" False
until_true "[[ \$(key_status KEYANN0001) == off ]]" 100 || true
expect "SCIM wins for the people it names: ann's key off though Graph says active" "$(key_code KEYANN0001)" 403
until_true "[[ \$(key_status KEYZED0001) == off ]]" 100 || true
expect "Graph answers for the rest: zed's key off" "$(key_code KEYZED0001)" 403
expect "the held ones go now the limit allows: dee's key off" "$(until_true "[[ \$(key_status KEYDEE0001) == off ]]" 100; key_code KEYDEE0001)" 403

expect "no sanitizer reports" "$(cat "$WORK"/log* | grep -c 'Sanitizer\|runtime error' || true)" 0
echo "scim: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
