#!/usr/bin/env bash
# consoled end to end without a browser: key and LDAP sign-in (against the
# LDAP mock), the signed S3 and admin proxy (streamed 20 MiB round trip,
# madmin-encrypted admin calls), share links, CSRF and session handling.
#   tests/integration/console.sh [bucketsd] [consoled]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19770}
CPORT=${CPORT:-19771}
LPORT=${LPORT:-19772}
LSPORT=${LSPORT:-19773}
OPORT=${OPORT:-19774}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-console-XXXXXX")
EP="http://127.0.0.1:$PORT"
C="http://127.0.0.1:$CPORT"
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
H="X-Console-Request: 1"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# the directory
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes -days 1 \
  -keyout "$WORK/ldap.key" -out "$WORK/ldap.crt" -subj /CN=localhost -addext "subjectAltName=IP:127.0.0.1" 2>/dev/null
LDAPMOCK_PATCH="$WORK/patch.json" python3 "$HERE/ldapmock.py" "$LPORT" "$LSPORT" "$WORK/ldap.crt" "$WORK/ldap.key" 2>"$WORK/ldap.log" &
PIDS+=($!)
for _ in $(seq 50); do nc -z 127.0.0.1 "$LPORT" 2>/dev/null && break; sleep 0.1; done
BASE=dc=example,dc=com
ISS="http://127.0.0.1:$OPORT"
# Entra-sized claims (a name, a few dozen group IDs): the session cookie then tops 1 KB, as real ones do.
CLAIMS=$(python3 -c 'import json; print(json.dumps({"sub": "u-42", "preferred_username": "oidcuser", "name": "OIDC User",
  "policy": "readwrite", "groups": ["%08x-0000-4000-8000-%012x" % (i, i) for i in range(32)]}))')
python3 "$HERE/oidcmock.py" "$OPORT" "$WORK" console s3cr3t "$CLAIMS" 2>"$WORK/oidc.log" &
PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "$ISS/jwks" && break; sleep 0.1; done

mkdir -p "$WORK"/d{1..4}
env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_INSECURE=on \
  MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN="cn=lookup,ou=svc,$BASE" MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD=lookup123 \
  MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN="ou=people,$BASE" MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER="(uid=%s)" \
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN="ou=groups,$BASE" \
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER="(&(objectclass=groupOfNames)(member=%d))" \
  MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=console \
  MINIO_IDENTITY_OPENID_CLAIM_NAME=policy \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 150); do curl -s -o /dev/null "$EP/minio/health/live" && break; sleep 0.1; done
env CONSOLE_MINIO_SERVER="$EP" CONSOLE_PBKDF_PASSPHRASE=it CONSOLE_PBKDF_SALT=it CONSOLE_LDAP_ENABLED=on \
  BUCKETS_CONSOLE_S3_URL="$EP" BUCKETS_CONSOLE_OIDC_CONFIG_URL="$ISS/.well-known/openid-configuration" \
  BUCKETS_CONSOLE_OIDC_CLIENT_ID=console BUCKETS_CONSOLE_OIDC_CLIENT_SECRET=s3cr3t BUCKETS_CONSOLE_OIDC_DISPLAY_NAME="Mock IdP" \
  "$CBIN" --address "127.0.0.1:$CPORT" 2>"$WORK/clog" &
PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "$C/healthz" && break; sleep 0.1; done

echo "== health, login methods, CSRF"
check "healthz" "$(curl -s "$C/healthz")" ok
check "login methods" "$(curl -s "$C/api/v1/login-methods")" '{"ldap":true,"share":true,"oidc":true,"oidcName":"Mock IdP","localUsers":false}'
check "no session" "$(code "$C/api/v1/session")" 401
check "no SPA installed" "$(code "$C/buckets")" 404
check "login without CSRF header" "$(code -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login")" 403

echo "== keys: sign in, admin through the proxy"
R="$WORK/root.jar"
check "bad keys" "$(code -H "$H" -d '{"accessKey":"rootadmin","secretKey":"wrongwrong"}' "$C/api/v1/login")" 401
check "root signs in" "$(code -c "$R" -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login")" 204
grep -q "HttpOnly" <(curl -s -D - -o /dev/null -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login") &&
  check "cookie is HttpOnly" yes yes || check "cookie is HttpOnly" no yes
check "session user" "$(curl -s -b "$R" "$C/api/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin)["accessKey"])')" rootadmin
# (JSON in a variable: bash keeps \" inside "$(...)", and brace expansion would split the body)
ATTACH='{"policies":["readwrite"],"group":"cn=devs,ou=groups,'"$BASE"'"}'
check "ldap group -> readwrite (encrypted admin body)" \
  "$(code -b "$R" -H "$H" -H 'X-Console-Encrypt: 1' -X POST --data "$ATTACH" "$C/api/v1/admin/idp/ldap/policy/attach")" 200
check "attaching again is refused" \
  "$(curl -s -b "$R" -H "$H" -H 'X-Console-Encrypt: 1' -X POST --data "$ATTACH" "$C/api/v1/admin/idp/ldap/policy/attach" |
    python3 -c 'import json,sys;print(json.load(sys.stdin)["Code"])')" XMinioAdminPolicyChangeAlreadyApplied
check "encrypted admin reply decrypted" \
  "$(curl -s -b "$R" -H 'X-Console-Decrypt: 1' "$C/api/v1/admin/list-users" | head -c 1)" "{"
check "the KMS API through the proxy (no KMS here)" \
  "$(curl -s -b "$R" "$C/api/v1/kms/status" | python3 -c 'import json,sys;print(json.load(sys.stdin)["Message"])')" \
  "Server side encryption specified but KMS is not configured"

echo "== LDAP: a directory user signs in and works"
A="$WORK/alice.jar"
check "wrong LDAP password" "$(code -H "$H" -d '{"accessKey":"alice","secretKey":"nope","method":"ldap"}' "$C/api/v1/login")" 401
check "alice signs in" "$(code -c "$A" -H "$H" -d '{"accessKey":"alice","secretKey":"alice123","method":"ldap"}' "$C/api/v1/login")" 204
check "alice's session" "$(curl -s -b "$A" "$C/api/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin)["accessKey"])')" alice
check "alice makes a bucket" "$(code -b "$A" -H "$H" -X PUT "$C/api/v1/s3/alicebucket")" 200
check "carol (no policy) is refused" \
  "$(code -c "$WORK/carol.jar" -H "$H" -d '{"accessKey":"carol","secretKey":"carol123","method":"ldap"}' "$C/api/v1/login")" 401

echo "== OpenID: through the provider and back"
O="$WORK/oidc.jar"
check "redirects to the provider" \
  "$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$C/api/v1/login/oidc" | cut -d'?' -f1)" "302 $ISS/authorize"
check "round trip ends at the console" \
  "$(curl -s -L -c "$O" -b "$O" -o /dev/null -w '%{url_effective}' "$C/api/v1/login/oidc")" "$C/"
check "oidc session" "$(curl -s -b "$O" "$C/api/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin)["accessKey"])')" oidcuser
check "oidc user makes a bucket" "$(code -b "$O" -H "$H" -X PUT "$C/api/v1/s3/oidcbucket")" 200
check "the Users page lists who signed in, with name and roles" \
  "$(curl -s -b "$R" -H 'X-Console-Decrypt: 1' "$C/api/v1/admin/idp/openid/list-access-keys-bulk?all=true&listType=all" |
    python3 -c 'import json,sys; u=[u for c in json.load(sys.stdin) for u in c["users"]][0]; print(u["displayName"], u["email"], u["policies"], len(u["stsKeys"]))')" \
  "OIDC User oidcuser ['readwrite'] 1"
check "a forged callback" "$(curl -s -o /dev/null -w '%{redirect_url}' "$C/oauth_callback?code=x&state=y" | cut -d'?' -f1)" "$C/login"
check "a provider error is shown" \
  "$(curl -s -o /dev/null -w '%{redirect_url}' "$C/oauth_callback?error=access_denied")" "$C/login?error=access_denied"

echo "== streamed round trip, share link"
head -c 20971520 /dev/urandom >"$WORK/big"
check "20 MiB upload" "$(code -b "$A" -H "$H" -H 'Content-Type: application/x-bin' -X PUT --data-binary @"$WORK/big" "$C/api/v1/s3/alicebucket/dir/big.bin")" 200
curl -s -b "$A" "$C/api/v1/s3/alicebucket/dir/big.bin" -o "$WORK/back"
cmp -s "$WORK/big" "$WORK/back" && check "download identical" yes yes || check "download identical" no yes
check "range" "$(curl -s -b "$A" -H 'Range: bytes=10-19' -o /dev/null -w '%{http_code} %{size_download}' "$C/api/v1/s3/alicebucket/dir/big.bin")" "206 10"
URL=$(curl -s -b "$A" "$C/api/v1/share?bucket=alicebucket&key=dir/big.bin&expires=300" | python3 -c 'import json,sys;print(json.load(sys.stdin)["url"])')
curl -s "$URL" -o "$WORK/shared"
cmp -s "$WORK/big" "$WORK/shared" && check "share link fetch" yes yes || check "share link fetch" no yes
check "tampered share link" "$(code "${URL/expires=300/expires=301}X")" 403

echo "== live streams (trace, logs, events) relayed as they come"
code -b "$R" -H "$H" -X PUT "$C/api/v1/s3/streambucket" >/dev/null
curl -s -N -b "$R" "$C/api/v1/admin/trace?s3=true&internal=false&storage=false&os=false&err=false&threshold=0s" >"$WORK/trace.out" &
TP=$!
curl -s -N -b "$R" "$C/api/v1/admin/log?limit=5&logType=ALL" >"$WORK/log.out" &
LP=$!
curl -s -N -b "$R" "$C/api/v1/s3/streambucket?events=s3:ObjectCreated:*&prefix=&suffix=&ping=10" >"$WORK/events.out" &
EVP=$!
sleep 1.5
code -b "$R" -H "$H" -X PUT --data-binary "hello" "$C/api/v1/s3/streambucket/live.txt" >/dev/null
sleep 1.5
kill $TP $LP $EVP 2>/dev/null || true; wait $TP $LP $EVP 2>/dev/null || true
check "trace shows the upload" "$(grep -c '"funcname":"s3.PutObject"' "$WORK/trace.out")" 1
check "logs stream" "$(grep -c '"node"' "$WORK/log.out" | awk '{print ($1 > 0)}')" 1
check "event of the upload" "$(grep -o '"key":"live.txt"' "$WORK/events.out" | head -1)" '"key":"live.txt"'

echo "== sign out"
check "logout" "$(code -b "$A" -c "$A" -H "$H" -X POST "$C/api/v1/logout")" 204
check "session gone" "$(code -b "$A" "$C/api/v1/session")" 401
check "a forged cookie" "$(code -b 'buckets-session=AAAA' "$C/api/v1/session")" 401

echo "console: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
