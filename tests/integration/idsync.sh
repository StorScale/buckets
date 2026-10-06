#!/usr/bin/env bash
# Identity sync (docs/design/identity-sync.md): people signed in through
# Entra ID who leave it lose their temporary credentials at once, and their
# access keys are turned off, then deleted after the grace period; a person
# back within it gets their keys back. A stand-in plays the OpenID provider,
# Microsoft's token endpoint and Microsoft Graph, with each person's state
# set by the test. Also: a provider answering errors removes no one, too
# many people leaving at once are held, and other tenants are left alone.
#   tests/integration/idsync.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19760}
OPORT=${OPORT:-19761}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-idsync-XXXXXX")
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

# ---- the stand-in: OpenID provider, Microsoft sign-in and Graph ---------------------------------
openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
cat >"$WORK/standin.py" <<'PY'
import base64, http.server, json, subprocess, sys, time, urllib.parse
port, work, iss = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def run(*a, data=None): return subprocess.run(a, input=data, capture_output=True, check=True).stdout
mod = run('openssl', 'rsa', '-in', work + '/rsa.pem', '-noout', '-modulus').decode().strip().split('=')[1]
JWK = {'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': b64(bytes.fromhex(mod)), 'e': 'AQAB'}
people = {}          # oid -> active | disabled | gone | error
graph_calls = [0]
def mint(claims):
    now = int(time.time())
    body = {'iss': iss, 'aud': 'buckets-app', 'iat': now, 'exp': now + 3600, **claims}
    msg = (b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'}).encode()) + '.' + b64(json.dumps(body).encode())).encode()
    return msg.decode() + '.' + b64(run('openssl', 'dgst', '-sha256', '-sign', work + '/rsa.pem', data=msg))
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, status, doc):
        b = json.dumps(doc).encode() if not isinstance(doc, str) else doc.encode()
        self.send_response(status); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == '/.well-known/openid-configuration':
            return self.reply(200, {'issuer': iss, 'jwks_uri': iss + '/jwks', 'authorization_endpoint': iss + '/authorize',
                                    'token_endpoint': iss + '/token'})
        if u.path == '/jwks': return self.reply(200, {'keys': [JWK]})
        if u.path == '/mint': return self.reply(200, mint(json.loads(urllib.parse.parse_qs(u.query)['claims'][0])))
        if u.path == '/graph-calls': return self.reply(200, graph_calls[0])
        if u.path.startswith('/v1.0/users/'):
            if not self.headers.get('Authorization', '').startswith('Bearer graph-token-'):
                return self.reply(401, {'error': {'code': 'InvalidAuthenticationToken'}})
            graph_calls[0] += 1
            oid = urllib.parse.unquote(u.path[len('/v1.0/users/'):])
            st = people.get(oid, 'gone')
            if st == 'error': return self.reply(503, {'error': {'code': 'ServiceUnavailable'}})
            if st == 'gone': return self.reply(404, {'error': {'code': 'Request_ResourceNotFound',
                                                               'message': "Resource '%s' does not exist" % oid}})
            return self.reply(200, {'id': oid, 'accountEnabled': st == 'active'})
        self.reply(404, {'error': {'code': 'NoRoute'}})
    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        body = self.rfile.read(int(self.headers.get('Content-Length', 0))).decode()
        if u.path.startswith('/control/'):      # /control/<oid>/<state>
            _, _, oid, st = u.path.split('/'); people[oid] = st
            return self.reply(200, {})
        if u.path.endswith('/oauth2/v2.0/token'):
            f = urllib.parse.parse_qs(body)
            ok = u.path == '/tenant-1/oauth2/v2.0/token' and f.get('client_id') == ['sync-app'] and \
                 f.get('client_secret') == ['sync-secret'] and f.get('grant_type') == ['client_credentials']
            if not ok: return self.reply(401, {'error': 'invalid_client', 'error_description': 'AADSTS7000215: Invalid client secret'})
            return self.reply(200, {'access_token': 'graph-token-%d' % int(time.time()), 'expires_in': 3599})
        self.reply(404, {})
http.server.ThreadingHTTPServer(('127.0.0.1', port), H).serve_forever()
PY
python3 "$WORK/standin.py" "$OPORT" "$WORK" "$ISS" 2>>"$WORK/standin.log" &
PIDS+=($!)
until_true "curl -sf $ISS/jwks" || { echo "stand-in did not start"; cat "$WORK/standin.log"; exit 1; }
person() { curl -sf -X POST "$ISS/control/$1/$2" >/dev/null; } # oid state

# ---- the server -----------------------------------------------------------------------------
mkdir -p "$WORK"/d{1..4}
BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
  BUCKETS_OPENID_SYNC_PROVIDER=entra BUCKETS_OPENID_SYNC_TENANT_ID=$TENANT BUCKETS_OPENID_SYNC_CLIENT_ID=sync-app \
  BUCKETS_OPENID_SYNC_CLIENT_SECRET=sync-secret BUCKETS_OPENID_SYNC_LOGIN_URL="$ISS" BUCKETS_OPENID_SYNC_GRAPH_URL="$ISS" \
  BUCKETS_OPENID_SYNC_INTERVAL=1 BUCKETS_OPENID_REMOVE_AFTER=8s BUCKETS_OPENID_REMOVE_MAX=2 \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
PIDS+=($!)
until_true "curl -sf $EP/minio/health/ready"
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
curl -sf "${R[@]}" -X PUT "$EP/docs" >/dev/null
echo hello | curl -sf "${R[@]}" -X PUT --data-binary @- "$EP/docs/a.txt" >/dev/null
export MC_CONFIG_DIR="$WORK/mc"

# sign_in <name> <oid> [tid]: temporary credentials from an ID token (AK SK TK), and an mc alias for them
sign_in() {
  local claims='{"sub":"sub-'$1'","oid":"'$2'","tid":"'${3:-$TENANT}'","preferred_username":"'$1'","policy":"readwrite"}'
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
sts_code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" -H "X-Amz-Security-Token: $3" "$EP/docs/a.txt"; }
key_code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" "$EP/docs/a.txt"; }
new_key() { mc admin accesskey create "$1" --access-key "$2" --secret-key "${2}secret123" >/dev/null; } # alias key
key_status() { mc admin accesskey info rootalias "$1" --json 2>/dev/null | sed -n 's/.*"accountStatus":"\([a-z]*\)".*/\1/p'; }
export MC_HOST_rootalias="http://rootadmin:rootsecret123@127.0.0.1:$PORT"

echo "== people sign in and make access keys"
for p in ann bob cat dan; do person "o-$p" active; done
sign_in ann o-ann; ANN=("$AK" "$SK" "$TK"); new_key ann KEYANN0001
sign_in bob o-bob; new_key bob KEYBOB0001
sign_in cat o-cat; new_key cat KEYCAT0001
sign_in dan o-dan; new_key dan KEYDAN0001
sign_in zed o-zed other-tenant; new_key zed KEYZED0001 # another tenant's person: not this sync's
expect "ann's temporary credentials work" "$(sts_code "${ANN[@]}")" 200
expect "ann's access key works" "$(key_code KEYANN0001 KEYANN0001secret123)" 200
sleep 2.5
expect "nothing done while everyone is active" "$(grep -c 'identity sync: \(revoke\|disable\|delete\)' "$WORK/log" || true)" 0
until_true "[[ \$(curl -s $ISS/graph-calls) -ge 4 ]]" 50 || true
expect "Graph asked about the tenant's people" "$([[ $(curl -s "$ISS/graph-calls") -ge 4 ]] && echo yes)" yes

echo "== ann leaves: temporary credentials go, the access key is turned off"
person o-ann gone
until_true "[[ \$(key_status KEYANN0001) == off ]]" || true
expect "ann's access key turned off" "$(key_status KEYANN0001)" off
expect "and refused" "$(key_code KEYANN0001 KEYANN0001secret123)" 403
expect "ann's temporary credentials gone" "$(sts_code "${ANN[@]}")" 403
expect "bob's key still works" "$(key_code KEYBOB0001 KEYBOB0001secret123)" 200
expect "another tenant's person left alone" "$(key_code KEYZED0001 KEYZED0001secret123)" 200
expect "logged" "$(grep -c 'identity sync: disable access key KEYANN0001 (owner gone in the provider)' "$WORK/log")" 1

echo "== ann comes back within the grace period: the key comes back on"
person o-ann active
until_true "[[ \$(key_status KEYANN0001) == on ]]" || true
expect "ann's key back on" "$(key_code KEYANN0001 KEYANN0001secret123)" 200

echo "== a key its owner turned off stays off"
mc admin accesskey disable rootalias KEYBOB0001 >/dev/null
sleep 2.5
expect "bob's own choice kept" "$(key_status KEYBOB0001)" off
mc admin accesskey enable rootalias KEYBOB0001 >/dev/null

echo "== ann is disabled for good: the key is deleted after the grace period"
person o-ann disabled
until_true "[[ \$(key_status KEYANN0001) == off ]]" || true
expect "turned off" "$(key_status KEYANN0001)" off
sleep 4
expect "kept during the grace period" "$(key_status KEYANN0001)" off
until_true "! mc admin accesskey info rootalias KEYANN0001" 100 || true
expect "deleted after it" "$(mc admin accesskey info rootalias KEYANN0001 >/dev/null 2>&1 && echo there || echo deleted)" deleted

echo "== the provider failing removes no one"
person o-bob error
sleep 3
expect "bob kept while Graph fails" "$(key_code KEYBOB0001 KEYBOB0001secret123)" 200
expect "the failure logged" "$([[ $(grep -c 'identity sync: Microsoft Graph answered 503' "$WORK/log") -ge 1 ]] && echo yes)" yes

echo "== three people leaving at once are held (BUCKETS_OPENID_REMOVE_MAX=2)"
person o-bob gone; person o-cat gone; person o-dan gone
until_true "grep -q 'identity sync: 3 people left the provider at once' $WORK/log" || true
expect "held, and said why" "$(grep -c 'identity sync: 3 people left the provider at once, more than BUCKETS_OPENID_REMOVE_MAX (2)' "$WORK/log" | sed 's/^[1-9][0-9]*$/yes/')" yes
expect "nobody's key turned off" "$(key_code KEYBOB0001 KEYBOB0001secret123)$(key_code KEYCAT0001 KEYCAT0001secret123)$(key_code KEYDAN0001 KEYDAN0001secret123)" 200200200
person o-dan active # two leaving: within the limit
until_true "[[ \$(key_status KEYBOB0001) == off && \$(key_status KEYCAT0001) == off ]]" || true
expect "within the limit, removed" "$(key_status KEYBOB0001) $(key_status KEYCAT0001) $(key_status KEYDAN0001)" "off off on"

errs=$(grep -c "Sanitizer\|runtime error" "$WORK/log" || true)
expect "no sanitizer reports" "$errs" 0
echo "idsync: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
