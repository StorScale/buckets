#!/usr/bin/env bash
# The HTTP plugins: policy_plugin (every authorization decision goes to the
# plugin) and identity_plugin (AssumeRoleWithCustomToken), against a mock.
#   tests/integration/plugins.sh [bucketsd]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
PORT=${PORT:-19760}
PPORT=${PPORT:-19761}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-plugins-XXXXXX")
EP="http://127.0.0.1:$PORT"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; echo "--- plugin log"; tail -20 "$WORK/plugin.log"; exit 1; }

cat >"$WORK/plugin.py" <<'PY'
import http.server, json, sys, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n) if n else b''
        u = urllib.parse.urlparse(self.path)
        if u.path == '/authz':
            if self.headers.get('Authorization') != 'Bearer authz-secret':
                return self.reply(401, {})
            if not body:
                return self.reply(200, {})
            inp = json.loads(body)['input']
            sys.stderr.write(json.dumps(inp) + '\n')
            # Root may do anything; "custom/carol" (the identity plugin's user)
            # may only read; everything else is denied.
            acct, act, parent = inp['account'], inp['action'], (inp.get('claims') or {}).get('parent', '')
            if inp['owner']:
                return self.reply(200, {'result': True})
            if parent == 'custom/carol' and act in ('s3:GetObject', 's3:ListBucket'):
                return self.reply(200, {'result': {'allow': True}})
            return self.reply(200, {'result': False})
        if u.path == '/idp':
            tok = urllib.parse.parse_qs(u.query).get('token', [''])[0]
            if tok == 'good-token':
                return self.reply(200, {'user': 'carol', 'maxValiditySeconds': 3600, 'claims': {'team': 'blue'}})
            return self.reply(403, {'reason': 'unknown token'})
        self.reply(404, {})
    def reply(self, code, doc):
        b = json.dumps(doc).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
PY
python3 "$WORK/plugin.py" "$PPORT" 2>"$WORK/plugin.log" &
PIDS+=($!)
for _ in $(seq 50); do curl -s -o /dev/null -X POST "http://127.0.0.1:$PPORT/idp" && break; sleep 0.1; done

mkdir -p "$WORK"/d{1..4}
BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_POLICY_PLUGIN_URL="http://127.0.0.1:$PPORT/authz" MINIO_POLICY_PLUGIN_AUTH_TOKEN="Bearer authz-secret" \
  MINIO_IDENTITY_PLUGIN_URL="http://127.0.0.1:$PPORT/idp" MINIO_IDENTITY_PLUGIN_ROLE_POLICY=readonly \
  MINIO_IDENTITY_PLUGIN_ROLE_ID=testplugin \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 100); do curl -sf "$EP/minio/health/ready" >/dev/null && break; sleep 0.1; done
sleep 0.5
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
[[ $(curl -s -o /dev/null -w '%{http_code}' "${R[@]}" -X PUT "$EP/docs") == 200 ]] || fail "root is allowed by the plugin"
echo hi | curl -sf "${R[@]}" -X PUT --data-binary @- "$EP/docs/a.txt" >/dev/null || fail "root put"

echo "== identity plugin"
arn="arn:minio:iam:::role/idmp-testplugin"
r=$(curl -s -X POST "$EP/?Action=AssumeRoleWithCustomToken&Version=2011-06-15&Token=bad-token&RoleArn=$arn")
grep "unknown token" >/dev/null <<<"$r" || fail "rejected token: $r"
r=$(curl -s -X POST "$EP/?Action=AssumeRoleWithCustomToken&Version=2011-06-15&Token=good-token&RoleArn=$arn&DurationSeconds=1800")
grep "<AssumedUser>custom/carol</AssumedUser>" >/dev/null <<<"$r" || fail "custom token: $r"
AK=$(sed -n 's:.*<AccessKeyId>\(.*\)</AccessKeyId>.*:\1:p' <<<"$r")
SK=$(sed -n 's:.*<SecretAccessKey>\(.*\)</SecretAccessKey>.*:\1:p' <<<"$r")
TK=$(sed -n 's:.*<SessionToken>\(.*\)</SessionToken>.*:\1:p' <<<"$r")
C=(--aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" -H "X-Amz-Security-Token: $TK")

echo "== policy plugin decides"
[[ $(curl -s -o /dev/null -w '%{http_code}' "${C[@]}" "$EP/docs/a.txt") == 200 ]] || fail "plugin allows the read"
[[ $(curl -s -o /dev/null -w '%{http_code}' "${C[@]}" -X PUT --data x "$EP/docs/b.txt") == 403 ]] ||
  fail "plugin denies the write (readonly's policy is not consulted either way)"
grep '"account": "'"$AK"'"' "$WORK/plugin.log" >/dev/null || fail "plugin saw the account"
grep '"team": "blue"' "$WORK/plugin.log" >/dev/null || fail "plugin saw the claims"
echo "PASS"
