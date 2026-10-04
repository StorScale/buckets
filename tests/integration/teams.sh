#!/usr/bin/env bash
# The console's Teams page without a browser (src/console/teams.c, iam/teams.c):
# a team saved through consoled becomes team-<name>-ro/rw/admin policies, and
# the servers enforce them: a token whose role names the rw policy reaches the
# team's buckets (named and by prefix) and nothing else, admin creates buckets
# under the prefix, a change to the team applies to a session already signed
# in, a policy edited outside the page is reported and only overwritten when
# asked, a local user added as a member gets the level, a level dropped loses
# its members, and deleting the team cuts access.
#   MC_BIN=/path/to/mc tests/integration/teams.sh [bucketsd] [consoled]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
if [[ -z "${MC_BIN:-}" ]]; then
  echo "teams: skipped (set MC_BIN)"
  exit 0
fi
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
PORT=${PORT:-19790}
CPORT=$((PORT + 1)) OPORT=$((PORT + 2))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-teams-XXXXXX")
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
else:  # mint ROLE...
    now = int(time.time())
    claims = {'sub': 'u-' + sys.argv[4], 'iss': iss, 'aud': 'buckets-app', 'iat': now - 5, 'exp': now + 900, 'roles': sys.argv[4:]}
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
for b in finance-reports ledger hr-payroll; do
  mc mb -q "it/$b" >/dev/null
  echo "$b data" | mc pipe -q "it/$b/a.txt" >/dev/null
done

H="X-Console-Request: 1"
J="Content-Type: application/json"
R="$WORK/root.jar"
curl -s -o /dev/null -c "$R" -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login"
api() { curl -s -b "$R" -H "$H" -H "$J" "$@"; }
status() { curl -s -o /dev/null -w '%{http_code}' -b "$R" -H "$H" -H "$J" "$@"; }

# credentials for a token with these roles (AK SK TK), and S3 as them
sts_as() {
  local r
  r=$(curl -s -X POST --data-urlencode Action=AssumeRoleWithWebIdentity --data-urlencode Version=2011-06-15 \
    --data-urlencode "WebIdentityToken=$(python3 "$WORK/idp.py" mint "$WORK" "$ISS" "$@")" "$EP/")
  AK=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$r")
  SK=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$r")
  TK=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$r")
  [[ -n $AK ]] || echo "no credentials for $*: $r" >&2
}
s3() { # method path [curl args] -> HTTP status, as AK/SK/TK
  local m=$1 p=$2
  shift 2
  curl -s -o /dev/null -w '%{http_code}' -X "$m" --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
    ${TK:+-H "X-Amz-Security-Token: $TK"} "$@" "$EP$p"
}
buckets_listed() {
  curl -s --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" ${TK:+-H "X-Amz-Security-Token: $TK"} "$EP/" |
    grep -o '<Name>[^<]*</Name>' | sed 's:</*Name>::g' | tr '\n' ' ' | sed 's/ $//'
}

echo "== no teams yet"
check "an empty list, LDAP off" "$(api "$C/api/v1/teams" | jq_ 'd["teams"], d["ldap"]')" "[] False"
check "the API needs a session" "$(curl -s -o /dev/null -w '%{http_code}' "$C/api/v1/teams")" 401

echo "== saving a team"
FIN='{"name":"finance","buckets":["finance-reports","ledger"],"prefixes":["finance-"],"levels":["ro","rw","admin"]}'
check "saved" "$(status -X PUT -d '{"team":'"$FIN"'}' "$C/api/v1/teams/finance")" 200
check "its policies" "$(mc admin policy ls it | grep -c '^team-finance-')" 3
check "listed, as saved" "$(api "$C/api/v1/teams" | jq_ '[(t["name"], t["buckets"], t["prefixes"], t["levels"], t["edited"]) for t in d["teams"]]')" \
  "[('finance', ['finance-reports', 'ledger'], ['finance-'], ['ro', 'rw', 'admin'], [])]"
check "a name not matching the address" "$(api -X PUT -d '{"team":'"$FIN"'}' "$C/api/v1/teams/other" | jq_ 'd["code"]')" InvalidTeam
check "a bad team, in words" "$(api -X PUT -d '{"team":{"name":"x2","levels":["rw"]}}' "$C/api/v1/teams/x2" | jq_ 'd["message"]')" \
  "Give the team at least one bucket or prefix"
check "a prefix overlapping another team's" \
  "$(api -X PUT -d '{"team":{"name":"fin2","prefixes":["finance-q"],"levels":["rw"]}}' "$C/api/v1/teams/fin2" | jq_ 'd["code"]')" Overlap

echo "== a token with role team-finance-rw"
sts_as team-finance-rw
RW_AK=$AK RW_SK=$SK RW_TK=$TK
check "writes its named bucket" "$(echo x | s3 PUT /finance-reports/new.txt --data-binary @-)" 200
check "reads a bucket under its prefix" "$(mc mb -q it/finance-q1 >/dev/null; s3 GET /finance-q1/)" 200
check "not another team's bucket" "$(s3 GET /hr-payroll/a.txt)" 403
check "sees only its buckets" "$(buckets_listed)" "finance-q1 finance-reports ledger"
check "rw cannot create buckets" "$(s3 PUT /finance-q2)" 403
check "nor change a bucket's settings" "$(s3 PUT '/ledger?versioning' --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')" 403

echo "== team-finance-admin"
sts_as team-finance-admin
check "creates a bucket under the prefix" "$(s3 PUT /finance-q2)" 200
check "not outside it" "$(s3 PUT /hr-q2)" 403
check "changes a bucket's settings" "$(s3 PUT '/ledger?versioning' --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')" 200
check "but cannot share it with a bucket policy" \
  "$(s3 PUT '/ledger?policy' --data '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::ledger/*"}]}')" 403
check "and has no admin API" "$(s3 GET /minio/admin/v3/list-users)" 403

echo "== a change applies to sessions already signed in"
FIN2='{"name":"finance","buckets":["finance-reports"],"prefixes":["finance-"],"levels":["ro","rw","admin"]}'
check "ledger taken out" "$(status -X PUT -d '{"team":'"$FIN2"'}' "$C/api/v1/teams/finance")" 200
AK=$RW_AK SK=$RW_SK TK=$RW_TK
check "the rw session loses ledger at once" "$(s3 GET /ledger/a.txt)" 403
check "and keeps finance-reports" "$(s3 GET /finance-reports/a.txt)" 200

echo "== a policy edited outside the Teams page"
mc admin policy info it team-finance-ro | python3 -c '
import json, sys
d = json.load(sys.stdin); p = d.get("Policy", d)
p["Statement"][0]["Action"].append("s3:PutBucketPolicy")
json.dump(p, open(sys.argv[1], "w"))' "$WORK/edited.json"
mc admin policy create it team-finance-ro "$WORK/edited.json" >/dev/null
check "reported" "$(api "$C/api/v1/teams" | jq_ 'd["teams"][0]["edited"]')" "['ro']"
check "saving asks first" "$(api -X PUT -d '{"team":'"$FIN2"'}' "$C/api/v1/teams/finance" | jq_ 'd["code"], d["edited"]')" "Edited ['ro']"
check "overwritten when asked" "$(status -X PUT -d '{"team":'"$FIN2"',"overwrite":true}' "$C/api/v1/teams/finance")" 200
check "no longer edited" "$(api "$C/api/v1/teams" | jq_ 'd["teams"][0]["edited"]')" "[]"

echo "== members: a local user"
mc admin user add it alice alicesecret123 >/dev/null
check "alice added to ro" "$(status -d '{"level":"ro","user":"alice"}' "$C/api/v1/teams/finance/members")" 204
check "listed as a member" "$(api "$C/api/v1/teams" | jq_ 'd["teams"][0]["members"]["ro"]["users"]')" "['alice']"
AK=alice SK=alicesecret123 TK=
check "alice reads the team's bucket" "$(s3 GET /finance-reports/a.txt)" 200
check "but cannot write" "$(echo x | s3 PUT /finance-reports/b.txt --data-binary @-)" 403
check "a level the team lacks" "$(api -d '{"level":"owner","user":"alice"}' "$C/api/v1/teams/finance/members" | jq_ 'd["code"]')" NoSuchTeam
A="$WORK/alice.jar"
curl -s -o /dev/null -c "$A" -H "$H" -d '{"accessKey":"alice","secretKey":"alicesecret123"}' "$C/api/v1/login"
check "alice cannot list teams: the servers refuse her" "$(curl -s -o /dev/null -w '%{http_code}' -b "$A" -H "$H" "$C/api/v1/teams")" 403

echo "== a level dropped loses its members"
FIN3='{"name":"finance","buckets":["finance-reports"],"prefixes":["finance-"],"levels":["rw","admin"]}'
check "ro dropped" "$(status -X PUT -d '{"team":'"$FIN3"'}' "$C/api/v1/teams/finance")" 200
check "its policy is gone" "$(mc admin policy ls it | grep -c '^team-finance-ro$' || true)" 0
check "alice with it" "$(s3 GET /finance-reports/a.txt)" 403

echo "== deleting the team"
check "deleted" "$(status -X DELETE "$C/api/v1/teams/finance")" 204
check "no teams left" "$(api "$C/api/v1/teams" | jq_ 'd["teams"]')" "[]"
check "and no policies" "$(mc admin policy ls it | grep -c '^team-' || true)" 0
AK=$RW_AK SK=$RW_SK TK=$RW_TK
check "the rw session loses access" "$(s3 GET /finance-reports/a.txt)" 403
check "deleting it again" "$(status -X DELETE "$C/api/v1/teams/finance")" 404

echo "teams: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
