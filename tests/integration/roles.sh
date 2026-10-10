#!/usr/bin/env bash
# Roles kept current (docs/design/roles-current.md), with Entra ID's app roles: a stand-in plays the OpenID
# provider, Microsoft's sign-in and Graph (the sign-in app's roles and who holds them, paged as Graph pages them;
# people's direct groups). A person moved between roles finds their access key and console session follow within a
# sync; roles taken away entirely leave them nothing (not the old roles in their tokens); a role given through a
# group counts; roles taken from too many people at once are held. With MINIO_BIN, MinIO reads the updated key
# after a rollback and grants what it now says.
#   [MINIO_BIN=...] tests/integration/roles.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19980}
OPORT=$((PORT + 1))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-roles-XXXXXX")
EP="http://127.0.0.1:$PORT"
ISS="http://127.0.0.1:$OPORT"
TENANT=tenant-1
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
until_true() { for _ in $(seq "${2:-100}"); do eval "$1" >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
cat >"$WORK/standin.py" <<'PY'
import base64, http.server, json, subprocess, sys, time, urllib.parse
port, work, iss = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def run(*a, data=None): return subprocess.run(a, input=data, capture_output=True, check=True).stdout
mod = run('openssl', 'rsa', '-in', work + '/rsa.pem', '-noout', '-modulus').decode().strip().split('=')[1]
JWK = {'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': b64(bytes.fromhex(mod)), 'e': 'AQAB'}
ROLES = [{'id': 'r-rw', 'value': 'readwrite', 'isEnabled': True}, {'id': 'r-ro', 'value': 'readonly', 'isEnabled': True},
         {'id': 'r-off', 'value': 'diagnostics', 'isEnabled': False}]
grants = []     # [principalId, roleId]
members = {}    # oid -> [group ids]
graph = {'calls': 0}
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
        u = urllib.parse.urlparse(self.path); q = urllib.parse.parse_qs(u.query)
        if u.path == '/.well-known/openid-configuration':
            return self.reply(200, {'issuer': iss, 'jwks_uri': iss + '/jwks', 'authorization_endpoint': iss + '/authorize', 'token_endpoint': iss + '/token'})
        if u.path == '/jwks': return self.reply(200, {'keys': [JWK]})
        if u.path == '/mint': return self.reply(200, mint(json.loads(q['claims'][0])))
        if u.path.startswith('/v1.0/') and self.headers.get('Authorization') != 'Bearer graph-token':
            return self.reply(401, {'error': {'code': 'InvalidAuthenticationToken'}})
        if u.path == "/v1.0/servicePrincipals(appId='app-1')":
            return self.reply(200, {'id': 'sp-1', 'appRoles': ROLES})
        if u.path == '/v1.0/servicePrincipals/sp-1/appRoleAssignedTo':
            # two pages, as Graph pages them
            skip = int(q.get('skip', ['0'])[0]); page = grants[skip:skip + 2]
            out = {'value': [{'principalId': p, 'principalType': 'Group' if p.startswith('g-') else 'User', 'appRoleId': r} for p, r in page]}
            if skip + 2 < len(grants): out['@odata.nextLink'] = iss + '/v1.0/servicePrincipals/sp-1/appRoleAssignedTo?skip=%d' % (skip + 2)
            return self.reply(200, out)
        if u.path.startswith('/v1.0/users/') and u.path.endswith('/memberOf'):
            oid = u.path.split('/')[3]
            return self.reply(200, {'value': [{'@odata.type': '#microsoft.graph.group', 'id': g} for g in members.get(oid, [])]})
        if u.path.startswith('/v1.0/users/'):
            graph['calls'] += 1
            return self.reply(200, {'id': u.path.split('/')[3], 'accountEnabled': True})
        self.reply(404, {})
    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if u.path == '/control':
            st = json.loads(body); grants[:] = st.get('grants', grants); members.update(st.get('members', {}))
            return self.reply(200, {})
        if u.path.endswith('/oauth2/v2.0/token'):
            return self.reply(200, {'access_token': 'graph-token', 'expires_in': 3599})
        self.reply(404, {})
http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$WORK/standin.py" "$OPORT" "$WORK" "$ISS" 2>>"$WORK/standin.log" &
PIDS+=($!)
until_true "curl -sf $ISS/jwks" || { echo "stand-in did not start"; cat "$WORK/standin.log"; exit 1; }
control() { curl -sf -X POST --data "$1" "$ISS/control" >/dev/null; }
control '{"grants": [["o-ann","r-rw"],["o-bob","r-rw"],["o-cat","r-rw"],["o-dan","r-rw"]]}'

mkdir -p "$WORK"/d{1..4}
start() {
  env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
    MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
    MINIO_IDENTITY_OPENID_CLAIM_NAME=roles \
    BUCKETS_OPENID_SYNC_PROVIDER=entra BUCKETS_OPENID_SYNC_TENANT_ID=$TENANT BUCKETS_OPENID_SYNC_CLIENT_ID=app-1 \
    BUCKETS_OPENID_SYNC_CLIENT_SECRET=sync-secret BUCKETS_OPENID_SYNC_LOGIN_URL="$ISS" BUCKETS_OPENID_SYNC_GRAPH_URL="$ISS" \
    BUCKETS_OPENID_SYNC_INTERVAL=1 BUCKETS_OPENID_REMOVE_MAX=2 BUCKETS_OPENID_SYNC_ROLES=on "$@" \
    "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
  PIDS+=($!)
  SPID=$!
  until_true "curl -sf $EP/minio/health/ready" 150
}
start
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
until_true "curl -sf ${R[*]@Q} -X PUT $EP/docs" 100 || true
echo hello | curl -sf "${R[@]}" -X PUT --data-binary @- "$EP/docs/a.txt" >/dev/null
export MC_CONFIG_DIR="$WORK/mc"
export MC_HOST_rootalias="http://rootadmin:rootsecret123@127.0.0.1:$PORT"

sign_in() { # name oid -> AK SK TK, and an mc alias
  local claims='{"sub":"sub-'$1'","oid":"'$2'","tid":"'$TENANT'","preferred_username":"'$1'","roles":["readwrite"]}'
  local tok r
  tok=$(curl -sf --get --data-urlencode "claims=$claims" "$ISS/mint" | tr -d '"')
  r=$(curl -s -X POST --data-urlencode Action=AssumeRoleWithWebIdentity --data-urlencode Version=2011-06-15 \
    --data-urlencode "WebIdentityToken=$tok" "$EP/")
  AK=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$r")
  SK=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$r")
  TK=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$r")
  [[ -n $AK ]] || { echo "no credentials for $1: $r"; exit 1; }
  export "MC_HOST_$1=http://$AK:$SK:$TK@127.0.0.1:$PORT"
}
key_read() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:${1}secret123" "$EP/docs/a.txt"; }
key_write() { echo x | curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:${1}secret123" -X PUT --data-binary @- "$EP/docs/$1.txt"; }
sts_read() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" -H "X-Amz-Security-Token: $3" "$EP/docs/a.txt"; }
sts_write() { echo x | curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" -H "X-Amz-Security-Token: $3" -X PUT --data-binary @- "$EP/docs/sts.txt"; }
new_key() { mc admin accesskey create "$1" --access-key "$2" --secret-key "${2}secret123" >/dev/null; }

echo "== people sign in as readwrite and make access keys"
sign_in ann o-ann; ANN=("$AK" "$SK" "$TK"); new_key ann KEYANN0001
sign_in bob o-bob; new_key bob KEYBOB0001
sign_in cat o-cat; new_key cat KEYCAT0001
sign_in dan o-dan; new_key dan KEYDAN0001
expect "ann's key writes" "$(key_write KEYANN0001)" 200
sleep 2.5
expect "nothing changed while the roles agree" "$(grep -c 'roles of' "$WORK/log" || true)" 0

echo "== ann is moved to readonly: her key and her session follow"
control '{"grants": [["o-ann","r-ro"],["o-bob","r-rw"],["o-cat","r-rw"],["o-dan","r-rw"]]}'
until_true "[[ \$(key_write KEYANN0001) == 403 ]]" 100 || true
expect "ann's key may no longer write" "$(key_write KEYANN0001)" 403
expect "but still reads" "$(key_read KEYANN0001)" 200
expect "her console session follows too, with the token it holds: no writes" "$(sts_write "${ANN[@]}")" 403
expect "but reads" "$(sts_read "${ANN[@]}")" 200
expect "bob is untouched" "$(key_write KEYBOB0001)" 200
expect "logged, with what changed" "$(grep -c 'identity sync: roles of o-ann changed: \[readwrite\] -> \[readonly\]; 1 credentials updated' "$WORK/log")" 1

echo "== ann loses every role: her credentials allow nothing, not the roles in their tokens"
control '{"grants": [["o-bob","r-rw"],["o-cat","r-rw"],["o-dan","r-rw"]]}'
until_true "[[ \$(key_read KEYANN0001) == 403 ]]" 100 || true
expect "ann's key reads nothing" "$(key_read KEYANN0001)" 403
expect "her session, whose token still names readwrite, ends" "$(sts_read "${ANN[@]}")" 403
expect "and is still there, still on" "$(mc admin accesskey info rootalias KEYANN0001 --json | sed -n 's/.*"accountStatus":"\([a-z]*\)".*/\1/p')" on

echo "== a role given through a group she belongs to counts"
control '{"grants": [["o-bob","r-rw"],["o-cat","r-rw"],["o-dan","r-rw"],["g-data","r-rw"]], "members": {"o-ann": ["g-data"]}}'
until_true "[[ \$(key_write KEYANN0001) == 200 ]]" 100 || true
expect "ann's key writes again, through the group (and Graph's second page)" "$(key_write KEYANN0001)" 200

echo "== roles taken from too many people at once are held"
control '{"grants": [["g-data","r-rw"]], "members": {"o-ann": ["g-data"]}}'
until_true "grep -q 'roles would be taken from more people at once' '$WORK/log'" 50 || true
expect "three at once, more than 2: held, and logged" "$(grep -c 'roles would be taken from more people at once' "$WORK/log" | awk '{print ($1 > 0)}')" 1
expect "their keys still write" "$(key_write KEYBOB0001) $(key_write KEYCAT0001) $(key_write KEYDAN0001)" "200 200 200"
expect "audited" "$(curl -s "${R[@]}" "$EP/minio/admin/v3/buckets/audit?api=IdentitySyncRoles&limit=10" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["entries"]) >= 3)')" True

if [[ -n "${MINIO_BIN:-}" ]]; then
  echo "== rolled back to MinIO, the updated key is read and grants what it now says"
  control '{"grants": [["o-ann","r-ro"],["o-bob","r-rw"],["o-cat","r-rw"],["o-dan","r-rw"]], "members": {"o-ann": []}}'
  until_true "[[ \$(key_write KEYANN0001) == 403 ]]" 100 || true
  kill "$SPID"; wait "$SPID" 2>/dev/null || true
  MINIO_CI_CD=on MINIO_BROWSER=off MINIO_ROOT_USER=rootadmin MINIO_ROOT_PASSWORD=rootsecret123 \
    MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
    MINIO_IDENTITY_OPENID_CLAIM_NAME=roles \
    "$MINIO_BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" >>"$WORK/minio.log" 2>&1 &
  PIDS+=($!)
  until_true "curl -sf $EP/minio/health/ready" 150
  sleep 2
  expect "MinIO: ann's key reads" "$(key_read KEYANN0001)" 200
  expect "MinIO: and may not write" "$(key_write KEYANN0001)" 403
  expect "MinIO: bob's key writes" "$(key_write KEYBOB0001)" 200
fi

expect "no sanitizer reports" "$(grep -c 'Sanitizer\|runtime error' "$WORK/log" || true)" 0
echo "roles: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
