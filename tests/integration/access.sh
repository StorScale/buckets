#!/usr/bin/env bash
# The console's access review without a browser (src/console/access.c,
# iam/access.c), on real servers: a local user with a team's policy, a group,
# a Deny, a disabled user, an access key with its own policy, a public bucket
# policy and an OpenID role. The review of a bucket lists exactly who reaches
# it and how; and for every "would this be allowed?" answer, the same request
# made with that principal's real credentials gets the same answer from the
# servers.
#   MC_BIN=/path/to/mc tests/integration/access.sh [bucketsd] [consoled]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
if [[ -z "${MC_BIN:-}" ]]; then
  echo "access: skipped (set MC_BIN)"
  exit 0
fi
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
PORT=${PORT:-19795}
CPORT=$((PORT + 1)) OPORT=$((PORT + 2))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-access-XXXXXX")
EP="http://127.0.0.1:$PORT"
C="http://127.0.0.1:$CPORT"
ISS="http://127.0.0.1:$OPORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
pass=0
fail=0
check() { # name got want
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); else
    fail=$((fail + 1))
    echo "FAIL: $1: got '$2', want '$3'"
  fi
}
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# ---- an identity provider whose tokens we mint ---------------------------------------------
openssl genrsa -out "$WORK/rsa.pem" 2048 2>/dev/null
cat >"$WORK/idp.py" <<'PY'
import base64, http.server, json, subprocess, sys, time
work, iss = sys.argv[2], sys.argv[3]
def b64(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()
def run(*a, data=None): return subprocess.run(a, input=data, capture_output=True, check=True).stdout
if sys.argv[1] == 'serve':
    mod = run('openssl', 'rsa', '-in', work + '/rsa.pem', '-noout', '-modulus').decode().strip().split('=')[1]
    jwks = {'keys': [{'kty': 'RSA', 'kid': 'k1', 'alg': 'RS256', 'use': 'sig', 'n': b64(bytes.fromhex(mod)), 'e': 'AQAB'}]}
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            doc = {'issuer': iss, 'jwks_uri': iss + '/jwks'} if self.path.startswith('/.well-known') else jwks if self.path == '/jwks' else None
            if doc is None:
                self.send_response(404); self.end_headers(); return
            b = json.dumps(doc).encode()
            self.send_response(200); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
        def log_message(self, *a): pass
    http.server.HTTPServer(('127.0.0.1', int(sys.argv[4])), H).serve_forever()
else:  # mint NAME ROLE...
    now = int(time.time())
    claims = {'sub': 'u-' + sys.argv[4], 'preferred_username': sys.argv[4], 'iss': iss, 'aud': 'buckets-app',
              'iat': now - 5, 'exp': now + 900, 'roles': sys.argv[5:]}
    head = b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': 'k1'}).encode())
    msg = head + '.' + b64(json.dumps(claims).encode())
    print(msg + '.' + b64(run('openssl', 'dgst', '-sha256', '-sign', work + '/rsa.pem', data=msg.encode())))
PY
python3 "$WORK/idp.py" serve "$WORK" "$ISS" "$OPORT" &
PIDS+=($!)
for _ in $(seq 50); do curl -sf "$ISS/jwks" >/dev/null && break; sleep 0.1; done

mkdir -p "$WORK"/d{1..4}
env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=buckets-app \
  MINIO_IDENTITY_OPENID_CLAIM_NAME=roles \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 150); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done
env CONSOLE_MINIO_SERVER="$EP" CONSOLE_PBKDF_PASSPHRASE=it CONSOLE_PBKDF_SALT=it \
  "$CBIN" --address "127.0.0.1:$CPORT" 2>"$WORK/clog" &
PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "$C/healthz" && break; sleep 0.1; done

mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
mc alias set it "$EP" rootadmin rootsecret123 >/dev/null
H="X-Console-Request: 1"
J="Content-Type: application/json"
R="$WORK/root.jar"
curl -s -o /dev/null -c "$R" -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login"
api() { curl -s -b "$R" -H "$H" -H "$J" "$@"; }

echo "== the setup"
mc mb -q it/finance-reports it/hr-payroll >/dev/null
for o in q3.csv reports/q3.pdf public/notice.txt secret/keys.txt; do echo "$o" | mc pipe -q "it/finance-reports/$o" >/dev/null; done
echo hr | mc pipe -q it/hr-payroll/staff.csv >/dev/null
api -X PUT -d '{"team":{"name":"finance","buckets":["finance-reports"],"prefixes":[],"levels":["rw"]}}' "$C/api/v1/teams/finance" >/dev/null
cat >"$WORK/audit-ro.json" <<'JSON'
{"Version":"2012-10-17","Statement":[
 {"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::finance-reports"]},
 {"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::finance-reports/reports/*"]}]}
JSON
cat >"$WORK/deny-secret.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Sid":"NoSecrets","Effect":"Deny","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::finance-reports/secret/*"]}]}
JSON
cat >"$WORK/key-ro.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::finance-reports/*"]}]}
JSON
cat >"$WORK/public.json" <<'JSON'
{"Version":"2012-10-17","Statement":[{"Sid":"PublicRead","Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::finance-reports/public/*"]}]}
JSON
mc admin policy create it audit-ro "$WORK/audit-ro.json" >/dev/null
mc admin policy create it deny-secret "$WORK/deny-secret.json" >/dev/null
for u in alice bob dave erin; do mc admin user add it "$u" "${u}secret123" >/dev/null; done
mc admin policy attach it team-finance-rw --user alice >/dev/null
mc admin group add it auditors bob >/dev/null
mc admin policy attach it audit-ro --group auditors >/dev/null
mc admin policy attach it readwrite deny-secret --user dave >/dev/null
mc admin policy attach it readwrite --user erin >/dev/null
mc admin user disable it erin >/dev/null
mc admin user svcacct add --access-key AKALICEREADONLY1 --secret-key keysecret1234567 --policy "$WORK/key-ro.json" it alice >/dev/null
mc anonymous set-json "$WORK/public.json" it/finance-reports >/dev/null
# an OpenID sign-in with the team's role: kcteam is then "seen"
TOK=$(python3 "$WORK/idp.py" mint "$WORK" "$ISS" kcteam team-finance-rw)
STS=$(curl -s -X POST --data-urlencode Action=AssumeRoleWithWebIdentity --data-urlencode Version=2011-06-15 \
  --data-urlencode "WebIdentityToken=$TOK" "$EP/")
OAK=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$STS")
OSK=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$STS")
OTK=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$STS")

echo "== who can read finance-reports"
REV=$(api "$C/api/v1/access/bucket/finance-reports?level=read")
row() { jq_ "[r for r in d['rows'] if r['name'] == '$1'] and [(r['kind'], r['access']) for r in d['rows'] if r['name'] == '$1'][0]" <<<"$REV"; }
check "root" "$(row 'the root user')" "('root', 'full')"
check "alice, through the team" "$(row alice)" "('user', 'full')"
check "bob, through his group: reports only" "$(jq_ "[a.get('limits') for r in d['rows'] if r['name'] == 'bob' for a in r['actions'] if a['action'] == 's3:GetObject'][0]" <<<"$REV")" "['reports/*']"
check "the group, with its member" "$(jq_ "[(r['kind'], r['members']) for r in d['rows'] if r['name'] == 'auditors'][0]" <<<"$REV")" "('group', ['bob'])"
check "dave" "$(row dave)" "('user', 'full')"
check "erin, disabled" "$(jq_ "[r['status'] for r in d['rows'] if r['name'] == 'erin'][0]" <<<"$REV")" disabled
check "alice's key with its own policy" "$(jq_ "[(r['owner'], r['access']) for r in d['rows'] if r['name'] == 'AKALICEREADONLY1'][0]" <<<"$REV")" "('alice', 'limited')"
check "the OpenID role, with who was seen" "$(jq_ "[(r['kind'], r['seen']) for r in d['rows'] if r['name'] == 'team-finance-rw'][0]" <<<"$REV")" "('openid-role', ['kcteam'])"
check "everyone, for the public part" "$(jq_ "[(r['kind'], r['actions'][0]['limits']) for r in d['rows'] if r['kind'] == 'anyone'][0]" <<<"$REV")" "('anyone', ['public/*'])"
check "nothing missing for root" "$(jq_ 'd["missing"]' <<<"$REV")" "[]"
check "a bad level" "$(api "$C/api/v1/access/bucket/finance-reports?level=owner" | jq_ 'd["code"]')" InvalidLevel
check "hr-payroll: no team, nobody but the admins" \
  "$(api "$C/api/v1/access/bucket/hr-payroll?level=read" | jq_ "sorted(r['name'] for r in d['rows'] if r['kind'] in ('user', 'group', 'key', 'anyone'))")" "['dave', 'erin']"

echo "== would this be allowed? the servers agree"
decide() { # who-json action bucket object -> decision
  api -d "{\"who\":$1,\"action\":\"$2\",\"bucket\":\"$3\",\"object\":\"$4\"}" "$C/api/v1/access/check" | jq_ 'd["decision"]'
}
real() { # ak sk token method path -> allowed/denied, as the servers answer
  local st
  st=$(curl -s -o /dev/null -w '%{http_code}' -X "$4" --aws-sigv4 "aws:amz:us-east-1:s3" --user "$1:$2" \
    ${3:+-H "X-Amz-Security-Token: $3"} ${6:+--data-binary "$6"} "$EP$5")
  [[ $st == 200 || $st == 204 ]] && echo allowed || echo denied
}
agree() { # label who-json action bucket object  ak sk token method path [body]
  local want got
  want=$(decide "$2" "$3" "$4" "$5")
  got=$(real "$6" "$7" "$8" "$9" "${10}" "${11:-}")
  check "$1: the review says $want, the servers $got" "$want" "$got"
  echo "   $1: $want"
}
U() { echo "{\"kind\":\"user\",\"name\":\"$1\"}"; }
agree "alice writes" "$(U alice)" s3:PutObject finance-reports new.csv alice alicesecret123 "" PUT /finance-reports/new.csv x
agree "alice, another bucket" "$(U alice)" s3:GetObject hr-payroll staff.csv alice alicesecret123 "" GET /hr-payroll/staff.csv
agree "bob, a report" "$(U bob)" s3:GetObject finance-reports reports/q3.pdf bob bobsecret123 "" GET /finance-reports/reports/q3.pdf
agree "bob, not a report" "$(U bob)" s3:GetObject finance-reports q3.csv bob bobsecret123 "" GET /finance-reports/q3.csv
agree "dave, a secret: the Deny wins" "$(U dave)" s3:GetObject finance-reports secret/keys.txt dave davesecret123 "" GET /finance-reports/secret/keys.txt
agree "dave, the rest" "$(U dave)" s3:GetObject finance-reports q3.csv dave davesecret123 "" GET /finance-reports/q3.csv
agree "erin, disabled" "$(U erin)" s3:GetObject finance-reports q3.csv erin erinsecret123 "" GET /finance-reports/q3.csv
K='{"kind":"key","name":"AKALICEREADONLY1"}'
agree "the key reads" "$K" s3:GetObject finance-reports q3.csv AKALICEREADONLY1 keysecret1234567 "" GET /finance-reports/q3.csv
agree "the key cannot write" "$K" s3:PutObject finance-reports k.csv AKALICEREADONLY1 keysecret1234567 "" PUT /finance-reports/k.csv x
O='{"kind":"openid","roles":["team-finance-rw"]}'
agree "the OpenID role writes" "$O" s3:PutObject finance-reports o.csv "$OAK" "$OSK" "$OTK" PUT /finance-reports/o.csv x
agree "the OpenID role, another bucket" "$O" s3:GetObject hr-payroll staff.csv "$OAK" "$OSK" "$OTK" GET /hr-payroll/staff.csv
pub() { [[ $(curl -s -o /dev/null -w '%{http_code}' "$EP$1") == 200 ]] && echo allowed || echo denied; }
check "anyone, the public part" "$(decide '{"kind":"anonymous"}' s3:GetObject finance-reports public/notice.txt)" "$(pub /finance-reports/public/notice.txt)"
check "anyone, the rest" "$(decide '{"kind":"anonymous"}' s3:GetObject finance-reports q3.csv)" "$(pub /finance-reports/q3.csv)"
check "the reason names the Deny" \
  "$(api -d "{\"who\":$(U dave),\"action\":\"s3:GetObject\",\"bucket\":\"finance-reports\",\"object\":\"secret/a\"}" "$C/api/v1/access/check" | jq_ 'd["by"][0]["policy"], d["by"][0]["sid"]')" \
  "deny-secret NoSecrets"
check "someone unknown" "$(api -d '{"who":{"kind":"user","name":"zed"},"action":"s3:GetObject","bucket":"finance-reports"}' "$C/api/v1/access/check" | jq_ 'd["code"]')" NoSuchPrincipal

echo "== pickers, local users, and who may review"
P=$(api "$C/api/v1/access/principals")
check "the principals to pick from" "$(jq_ "sorted(p['name'] for p in d['principals'] if p['kind'] in ('user', 'group', 'key'))" <<<"$P")" \
  "['AKALICEREADONLY1', 'alice', 'auditors', 'bob', 'dave', 'erin']"
check "OpenID is on, LDAP is not" "$(jq_ 'd["openid"], d["ldap"]' <<<"$P")" "True False"
L=$(api "$C/api/v1/access/local-users")
check "local users while OpenID is on" "$(jq_ "d['provider'], sorted(u['name'] for u in d['users'])" <<<"$L")" "OpenID ['alice', 'bob', 'dave', 'erin']"
check "with their keys" "$(jq_ "[u['keys'] for u in d['users'] if u['name'] == 'alice'][0]" <<<"$L")" 1
A="$WORK/alice.jar"
curl -s -o /dev/null -c "$A" -H "$H" -d '{"accessKey":"alice","secretKey":"alicesecret123"}' "$C/api/v1/login"
check "alice cannot review: she cannot read the policies" \
  "$(curl -s -b "$A" -H "$H" "$C/api/v1/access/bucket/finance-reports" | jq_ 'd["code"]')" AccessDenied

echo "access: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
