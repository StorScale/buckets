#!/usr/bin/env bash
# OpenID Connect: AssumeRoleWithWebIdentity/ClientGrants against a mock
# identity provider (discovery document + JWKS with an RSA and an EC key,
# tokens signed with the openssl CLI). Claim-based policies, role-policy
# providers (RoleArn), expiry, audience, DurationSeconds, and the
# credentials' access.
#   tests/integration/openid.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19750}
OPORT=${OPORT:-19751}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-oidc-XXXXXX")
EP="http://127.0.0.1:$PORT"
ISS="http://127.0.0.1:$OPORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }

# ---- the identity provider -------------------------------------------------
openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ec.pem" 2>/dev/null
cat >"$WORK/idp.py" <<'PY'
import base64, hashlib, http.server, json, subprocess, sys, time
work, iss = sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def run(*a, data=None): return subprocess.run(a, input=data, capture_output=True, check=True).stdout
def rsa_jwk():
    mod = run('openssl', 'rsa', '-in', work + '/rsa.pem', '-noout', '-modulus').decode().strip().split('=')[1]
    return {'kty': 'RSA', 'kid': 'rs1', 'alg': 'RS256', 'use': 'sig', 'n': b64(bytes.fromhex(mod)), 'e': 'AQAB'}
def ec_jwk():
    der = run('openssl', 'ec', '-in', work + '/ec.pem', '-pubout', '-outform', 'DER')
    pt = der[-64:]
    return {'kty': 'EC', 'kid': 'ec1', 'crv': 'P-256', 'x': b64(pt[:32]), 'y': b64(pt[32:])}
def der_to_raw(sig):
    # SEQUENCE { INTEGER r, INTEGER s }
    i = 2
    out = b''
    for _ in range(2):
        assert sig[i] == 2
        n = sig[i + 1]
        v = sig[i + 2:i + 2 + n].lstrip(b'\0')
        out += v.rjust(32, b'\0')
        i += 2 + n
    return out
def mint(claims, kid='rs1'):
    alg = 'ES256' if kid == 'ec1' else 'RS256'
    head = b64(json.dumps({'alg': alg, 'typ': 'JWT', 'kid': kid}).encode())
    body = b64(json.dumps(claims).encode())
    msg = (head + '.' + body).encode()
    sig = run('openssl', 'dgst', '-sha256', '-sign', work + ('/ec.pem' if kid == 'ec1' else '/rsa.pem'), data=msg)
    if kid == 'ec1': sig = der_to_raw(sig)
    return head + '.' + body + '.' + b64(sig)
if sys.argv[1] == 'serve':
    port = int(sys.argv[4])
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith('/.well-known/openid-configuration'):
                doc = {'issuer': iss, 'jwks_uri': iss + '/jwks', 'userinfo_endpoint': iss + '/userinfo'}
            elif self.path == '/jwks':
                doc = {'keys': [rsa_jwk(), ec_jwk()]}
            else:
                self.send_response(404); self.end_headers(); return
            b = json.dumps(doc).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        def log_message(self, *a): pass
    http.server.HTTPServer(('127.0.0.1', port), H).serve_forever()
elif sys.argv[1] == 'mint':
    claims = json.loads(sys.argv[4])
    for k in ('exp', 'iat'):
        if isinstance(claims.get(k), str) and claims[k].startswith('+'):
            claims[k] = int(time.time()) + int(claims[k][1:])
        elif isinstance(claims.get(k), str) and claims[k].startswith('-'):
            claims[k] = int(time.time()) - int(claims[k][1:])
    print(mint(claims, sys.argv[5] if len(sys.argv) > 5 else 'rs1'))
elif sys.argv[1] == 'arn':
    print('arn:minio:iam:::role/' + b64(hashlib.sha1(sys.argv[4].encode()).digest()))
PY
python3 "$WORK/idp.py" serve "$WORK" "$ISS" "$OPORT" &
PIDS+=($!)
for _ in $(seq 50); do curl -sf "$ISS/jwks" >/dev/null && break; sleep 0.1; done
mint() { python3 "$WORK/idp.py" mint "$WORK" "$ISS" "$@"; }

# ---- the server: a claim-based provider and a role-policy one --------------
mkdir -p "$WORK"/d{1..4}
BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
  MINIO_IDENTITY_OPENID_CONFIG_URL_ROLES="$ISS/.well-known/openid-configuration" \
  MINIO_IDENTITY_OPENID_CLIENT_ID_ROLES=role-app MINIO_IDENTITY_OPENID_ROLE_POLICY_ROLES=readwrite \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 100); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
curl -sf "${R[@]}" -X PUT "$EP/docs" >/dev/null || fail "make bucket"
echo hello | curl -sf "${R[@]}" -X PUT --data-binary @- "$EP/docs/a.txt" >/dev/null || fail "put object"

sts() { # action token [extra form fields...]
  local action=$1 tok=$2
  shift 2
  curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode "Action=$action" \
    --data-urlencode Version=2011-06-15 --data-urlencode "WebIdentityToken=$tok" "$@" "$EP/"
}
xml() { sed -n "s:.*<$1>\\(.*\\)</$1>.*:\\1:p"; }
as_creds() { # response -> sets AK SK TK
  AK=$(xml AccessKeyId <<<"$1"); SK=$(xml SecretAccessKey <<<"$1"); TK=$(xml SessionToken <<<"$1")
  [[ -n "$AK" ]] || fail "no credentials: $1"
}
code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  -H "X-Amz-Security-Token: $TK" "$@"; }

echo "== claim-based policy (RS256)"
tok=$(mint '{"sub":"u1","iss":"'"$ISS"'","aud":"buckets-app","exp":"+600","iat":"-5","policy":"readonly"}')
r=$(sts AssumeRoleWithWebIdentity "$tok")
as_creds "$r"
grep "<SubjectFromWebIdentityToken>u1</SubjectFromWebIdentityToken>" >/dev/null <<<"$r" || fail "subject: $r"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "readonly read"
[[ $(code -X PUT --data x "$EP/docs/b.txt") == 403 ]] || fail "readonly write"

echo "== ES256, array audience, ClientGrants, query parameters"
tok=$(mint '{"sub":"u2","iss":"'"$ISS"'","aud":["other","buckets-app"],"exp":"+600","policy":["readwrite","nosuch"]}' ec1)
r=$(curl -s -X POST "$EP/?Action=AssumeRoleWithClientGrants&Version=2011-06-15&Token=$tok")
as_creds "$r"
grep "<SubjectFromToken>u2</SubjectFromToken>" >/dev/null <<<"$r" || fail "client grants subject: $r"
[[ $(code -X PUT --data x "$EP/docs/c.txt") == 200 ]] || fail "readwrite write"

echo "== role-policy provider (RoleArn)"
arn=$(python3 "$WORK/idp.py" arn "$WORK" "$ISS" role-app)
tok=$(mint '{"sub":"u3","iss":"'"$ISS"'","aud":"role-app","exp":"+600"}')
r=$(sts AssumeRoleWithWebIdentity "$tok" --data-urlencode "RoleArn=$arn")
as_creds "$r"
[[ $(code -X PUT --data x "$EP/docs/d.txt") == 200 ]] || fail "role policy write"

echo "== DurationSeconds and session policy"
tok=$(mint '{"sub":"u4","iss":"'"$ISS"'","aud":"buckets-app","exp":"+600","policy":"readwrite"}')
r=$(sts AssumeRoleWithWebIdentity "$tok" --data-urlencode DurationSeconds=3600 --data-urlencode \
  'Policy={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::docs/*"]}]}')
as_creds "$r"
exp=$(xml Expiration <<<"$r")
python3 -c "import datetime,sys; e=datetime.datetime.fromisoformat(sys.argv[1].replace('Z','+00:00')); d=(e-datetime.datetime.now(datetime.timezone.utc)).total_seconds(); sys.exit(0 if 3500<d<3700 else 1)" "$exp" ||
  fail "DurationSeconds expiry: $exp"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "session policy read"
[[ $(code -X PUT --data x "$EP/docs/e.txt") == 403 ]] || fail "session policy narrows"

echo "== rejected tokens"
tok=$(mint '{"sub":"u5","iss":"'"$ISS"'","aud":"buckets-app","exp":"-60","policy":"readonly"}')
sts AssumeRoleWithWebIdentity "$tok" | grep "<Code>ExpiredToken</Code>" >/dev/null || fail "expired token"
tok=$(mint '{"sub":"u6","iss":"'"$ISS"'","aud":"someone-else","exp":"+600","policy":"readonly"}')
sts AssumeRoleWithWebIdentity "$tok" | grep '`azp` must match' >/dev/null || fail "wrong audience"
tok=$(mint '{"sub":"u7","iss":"'"$ISS"'","aud":"buckets-app","exp":"+600","policy":"nosuch"}')
sts AssumeRoleWithWebIdentity "$tok" | grep "are defined" >/dev/null || fail "unknown policy"
tok=$(mint '{"sub":"u8","iss":"'"$ISS"'","aud":"buckets-app","exp":"+600"}')
sts AssumeRoleWithWebIdentity "$tok" | grep "claim missing" >/dev/null || fail "no policy claim"
tok=$(mint '{"iss":"'"$ISS"'","aud":"buckets-app","exp":"+600","policy":"readonly"}')
sts AssumeRoleWithWebIdentity "$tok" | grep "sub" >/dev/null || fail "no sub"
tok=$(mint '{"sub":"u9","iss":"'"$ISS"'","aud":"buckets-app","exp":"+600","policy":"readonly"}')
# Flip a character inside the signature (the last one may only carry padding bits).
c=${tok: -10:1}
[[ $c == A ]] && r=B || r=A
bad="${tok:0:${#tok}-10}$r${tok: -9}"
sts AssumeRoleWithWebIdentity "$bad" | grep "InvalidParameterValue" >/dev/null || fail "bad signature"

if [[ -n "${MC_BIN:-}" ]]; then
  echo "== mc idp openid"
  mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
  mc alias set root "$EP" rootadmin rootsecret123 >/dev/null || fail "alias"
  out=$(mc idp openid add root dex config_url="$ISS/.well-known/openid-configuration" client_id=dex-app client_secret=dexsecret \
    role_policy=readonly 2>&1) || fail "idp openid add: $out"
  out=$(mc idp openid add root dex client_id=x 2>&1 || true)
  grep "already exists" >/dev/null <<<"$out" || fail "add twice: $out"
  out=$(mc --json idp openid ls root 2>&1) || fail "idp openid ls: $out"
  arn=$(python3 "$WORK/idp.py" arn "$WORK" "$ISS" dex-app)
  grep '"name":"dex"' >/dev/null <<<"$out" || fail "ls dex: $out"
  grep -F "\"roleARN\":\"$arn\"" >/dev/null <<<"$out" || fail "ls role ARN: $out"
  grep '"name":"ROLES"\|"name":"roles"' >/dev/null <<<"$out" || fail "ls env target: $out"
  out=$(mc idp openid info root dex 2>&1) || fail "idp openid info: $out"
  grep "client_id.*dex-app" >/dev/null <<<"$out" || fail "info: $out"
  tok=$(mint '{"sub":"u10","iss":"'"$ISS"'","aud":"dex-app","exp":"+600"}')
  as_creds "$(sts AssumeRoleWithWebIdentity "$tok" --data-urlencode "RoleArn=$arn")"
  [[ $(code "$EP/docs/a.txt") == 200 ]] || fail "provider added by mc idp openid"
  out=$(mc idp openid rm root ROLES 2>&1 || true)
  grep "overridden\|environment" >/dev/null <<<"$out" || fail "rm env-defined: $out"
  out=$(mc idp openid rm root dex 2>&1) || fail "idp openid rm: $out"
  out=$(mc idp openid info root dex 2>&1 || true)
  grep "does not exist\|not found\|No such" >/dev/null <<<"$out" || fail "info after rm: $out"
fi
echo "PASS"
