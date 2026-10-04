#!/usr/bin/env bash
# The console's Identity page without a browser (src/console/idpconfig.c):
# candidate settings saved and checked, secrets kept, a test sign-in with the
# candidate (oidcmock.py: a working one, a token whose roles name no policy, a
# wrong client secret), an LDAP lookup (ldapmock.py), Apply refused until
# tested, and consoled taking up the sign-in settings the operator writes to
# its identity file, and dropping them when it goes. The Kubernetes API and
# the operator are kubemock.py.
#   tests/integration/identity.sh [bucketsd] [consoled]
set -euo pipefail
BIN=${1:-build/src/bucketsd}
CBIN=${2:-build/src/consoled}
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19780}
CPORT=$((PORT + 1)) KPORT=$((PORT + 2)) OPORT=$((PORT + 3)) O2PORT=$((PORT + 4)) LPORT=$((PORT + 5))
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-identity-XXXXXX")
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
J="Content-Type: application/json"
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
jq_() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
state() { curl -sk "https://127.0.0.1:$KPORT/_state" | jq_ "$1"; }

# two providers: one whose token carries a role that is a policy, one whose roles are none
python3 "$HERE/oidcmock.py" "$OPORT" "$WORK" idp-console s3cret \
  '{"sub": "u-1", "preferred_username": "admin1", "roles": ["readwrite", "nosuchrole"]}' 2>"$WORK/oidc.log" &
PIDS+=($!)
mkdir -p "$WORK/o2"
python3 "$HERE/oidcmock.py" "$O2PORT" "$WORK/o2" idp-console s3cret '{"sub": "u-2", "roles": ["nosuchrole"]}' 2>"$WORK/oidc2.log" &
PIDS+=($!)
python3 "$HERE/ldapmock.py" "$LPORT" 2>"$WORK/ldap.log" &
PIDS+=($!)
python3 "$HERE/kubemock.py" "$KPORT" "$WORK" data store 2>"$WORK/kube.log" &
PIDS+=($!)
ISS="http://127.0.0.1:$OPORT"
for _ in $(seq 100); do curl -s -o /dev/null "$ISS/jwks" && curl -s -o /dev/null "http://127.0.0.1:$O2PORT/jwks" &&
  nc -z 127.0.0.1 "$LPORT" 2>/dev/null && [[ -f $WORK/kube-ca.pem ]] && curl -sk -o /dev/null "https://127.0.0.1:$KPORT/_state" && break; sleep 0.1; done

mkdir -p "$WORK"/d{1..4} "$WORK/identity"
BASE=dc=example,dc=com
# the servers have LDAP too, so the LDAP lookup can report the policies attached in the directory's terms
env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 \
  MINIO_IDENTITY_OPENID_CONFIG_URL="$ISS/.well-known/openid-configuration" MINIO_IDENTITY_OPENID_CLIENT_ID=idp-console \
  MINIO_IDENTITY_OPENID_CLAIM_NAME=roles \
  MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_INSECURE=on \
  MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN="cn=lookup,ou=svc,$BASE" MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD=lookup123 \
  MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN="ou=people,$BASE" MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER="(uid=%s)" \
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN="ou=groups,$BASE" \
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER="(&(objectclass=groupOfNames)(member=%d))" \
  "$BIN" server --address "127.0.0.1:$PORT" "$WORK/d{1...4}" 2>"$WORK/log" &
PIDS+=($!)
for _ in $(seq 150); do curl -s -o /dev/null "$EP/minio/health/live" && break; sleep 0.1; done
IDFILE="$WORK/identity/identity.json"
env CONSOLE_MINIO_SERVER="$EP" CONSOLE_PBKDF_PASSPHRASE=it CONSOLE_PBKDF_SALT=it \
  BUCKETS_KUBE_API="https://127.0.0.1:$KPORT" BUCKETS_KUBE_CA="$WORK/kube-ca.pem" BUCKETS_KUBE_TOKEN=kubemock-token \
  BUCKETS_CONSOLE_CLUSTER=store BUCKETS_CONSOLE_NAMESPACE=data BUCKETS_CONSOLE_IDENTITY_FILE="$IDFILE" \
  "$CBIN" --address "127.0.0.1:$CPORT" 2>"$WORK/clog" &
PIDS+=($!)
for _ in $(seq 100); do curl -s -o /dev/null "$C/healthz" && break; sleep 0.1; done

R="$WORK/root.jar"
check "root signs in" "$(code -c "$R" -H "$H" -d '{"accessKey":"rootadmin","secretKey":"rootsecret123"}' "$C/api/v1/login")" 204
api() { curl -s -b "$R" -H "$H" -H "$J" "$@"; }

echo "== nothing set up"
check "no OpenID or LDAP sign-in yet" "$(curl -s "$C/api/v1/login-methods" | jq_ 'd["oidc"], d["ldap"]')" "False False"
G=$(api "$C/api/v1/identity-config")
check "managed" "$(jq_ 'd["managed"], d["settings"], d["candidate"]' <<<"$G")" "True None None"
check "the redirect URI to register" "$(jq_ 'd["redirectUri"]' <<<"$G")" "http://127.0.0.1:$CPORT/oauth_callback"

echo "== the candidate: checked, saved, secrets kept"
check "a missing secret is explained" \
  "$(api -X PUT -d '{"settings":{"openid":{"provider":"generic","configUrl":"'"$ISS"'/.well-known/openid-configuration","clientId":"idp-console"}}}' \
    "$C/api/v1/identity-config/candidate" | jq_ 'd["message"]')" \
  "Enter the application's client secret: the console signs people in as a confidential client."
OIDC='{"provider":"generic","configUrl":"'"$ISS"'/.well-known/openid-configuration","clientId":"idp-console","clientSecret":"s3cret","claimName":"roles","displayName":"Mock IdP"}'
P=$(api -X PUT -d '{"settings":{"openid":'"$OIDC"'}}' "$C/api/v1/identity-config/candidate")
check "saved, the secret not sent back" "$(jq_ 'repr(d["candidate"]["openid"]["clientSecret"]), d["candidate"]["secretsSet"]' <<<"$P")" \
  "'' ['openid.clientSecret']"
P=$(api -X PUT -d '{"settings":{"openid":'"${OIDC/s3cret/}"'}}' "$C/api/v1/identity-config/candidate")
HASH=$(jq_ 'd["candidateHash"]' <<<"$P")
check "an edit without the secret keeps it" "$(state 'd["secrets"]["store-identity-candidate"]["settings.json"]["openid"]["clientSecret"]')" s3cret
check "apply before a test: refused" "$(api -d '{"candidateHash":"'"$HASH"'"}' "$C/api/v1/identity-config/apply" | jq_ 'd["code"]')" NotTested

echo "== the test sign-in"
signin_test() { # follows the popup as a browser does: console start -> provider -> console callback,
  # which (a cross-site navigation) carries no session cookie (SameSite=Strict); then the handoff
  # page's script posts the sealed tokens back from the console with the session. Prints what the page shows.
  local loc page blob
  loc=$(curl -s -b "$R" -c "$R" -o /dev/null -w '%{redirect_url}' "$C/api/v1/login/oidc?test=1")
  loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$loc")
  grep -v buckets-session "$R" > "$R.cross"
  page=$(curl -s -b "$R.cross" "$loc")
  blob=$(grep -o "blob:'[A-Za-z0-9_-]*'" <<<"$page" | cut -d"'" -f2)
  if [[ -z $blob ]]; then echo "$page"; return; fi
  api -d '{"blob":"'"$blob"'"}' "$C/api/v1/identity-config/test-finish" | jq_ 'd["message"] + (" passed:true" if d["passed"] else " passed:false")'
}
PAGE=$(signin_test)
check "the page says it worked" "$(grep -o 'Signed in as admin1: the settings work.' <<<"$PAGE")" "Signed in as admin1: the settings work."
check "and tells the Identity page" "$(grep -o "passed:true" <<<"$PAGE")" "passed:true"
T=$(api "$C/api/v1/identity-config" | jq_ 'json.dumps(d["test"]["openid"])')
check "recorded: roles matched to policies" "$(jq_ 'd["passed"], d["user"], d["claimName"], d["policies"], d["unmatched"]' <<<"$T")" \
  "True admin1 roles ['readwrite'] ['nosuchrole']"
check "the test was a test: no session for admin1" "$(curl -s -b "$R" "$C/api/v1/session" | jq_ 'd["accessKey"]')" rootadmin

echo "== apply"
check "applied" "$(api -d '{"candidateHash":"'"$HASH"'"}' "$C/api/v1/identity-config/apply" | jq_ 'd["applied"], d["description"]')" \
  "True OpenID provider $ISS/.well-known/openid-configuration"
check "the settings Secret holds the candidate" "$(state 'd["secrets"]["store-identity"]["settings.json"]["openid"]["clientId"]')" idp-console
check "status from the operator" "$(sleep 1; api "$C/api/v1/identity-config" | jq_ 'd["status"]["phase"]')" Ready

echo "== failing tests say why"
api -X PUT -d '{"settings":{"openid":'"${OIDC/$OPORT/$O2PORT}"'}}' "$C/api/v1/identity-config/candidate" >/dev/null
PAGE=$(signin_test)
check "roles that name no policy" "$(grep -o 'none of the token.s roles names a policy' <<<"$PAGE")" "none of the token's roles names a policy"
check "recorded as failed" "$(api "$C/api/v1/identity-config" | jq_ 'd["test"]["openid"]["passed"]')" False
HASH=$(api "$C/api/v1/identity-config" | jq_ 'd["candidateHash"]')
check "a failed test cannot be applied" "$(api -d '{"candidateHash":"'"$HASH"'"}' "$C/api/v1/identity-config/apply" | jq_ 'd["code"]')" NotTested
api -X PUT -d '{"settings":{"openid":'"${OIDC/s3cret/wrongsecret}"'}}' "$C/api/v1/identity-config/candidate" >/dev/null
PAGE=$(signin_test)
check "a wrong client secret: the provider's words" "$(grep -o 'did not issue a token for this client: invalid_grant' <<<"$PAGE")" \
  "did not issue a token for this client: invalid_grant"
check "a test needs an admin session" "$(curl -s "$C/api/v1/login/oidc?test=1" | grep -o "needs an administrator's session")" \
  "needs an administrator's session"
check "the finish needs the session too" "$(code -H "$H" -H "$J" -d '{"blob":"x"}' "$C/api/v1/identity-config/test-finish")" 401
check "a forged blob is refused" "$(api -d '{"blob":"bm90LWEtYmxvYg"}' "$C/api/v1/identity-config/test-finish" | jq_ 'd["passed"], d["message"][:22]')" \
  "False The test expired or di"

echo "== LDAP"
LDAP='{"preset":"openldap","serverAddr":"127.0.0.1:'"$LPORT"'","tls":"plain","lookupBindDn":"cn=lookup,ou=svc,'"$BASE"'","lookupBindPassword":"lookup123","userSearchBase":"ou=People,'"$BASE"'","groupSearchBase":"ou=groups,'"$BASE"'"}'
api -X PUT -d '{"settings":{"ldap":'"$LDAP"'}}' "$C/api/v1/identity-config/candidate" >/dev/null
L=$(api -d '{"username":"alice"}' "$C/api/v1/identity-config/ldap-test")
check "a user found, with groups" "$(jq_ 'd["passed"], d["dn"], d["groups"]' <<<"$L")" \
  "True uid=alice,ou=People,$BASE ['cn=devs,ou=groups,$BASE']"
check "no policy attached yet: said so" "$(jq_ 'd["note"].startswith("Found, but no policy is attached")' <<<"$L")" True
MC_BIN=${MC_BIN:-$(command -v mc)}
mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
mc alias set it "$EP" rootadmin rootsecret123 >/dev/null
mc idp ldap policy attach it readwrite --group "cn=devs,ou=groups,$BASE" >/dev/null
L=$(api -d '{"username":"alice"}' "$C/api/v1/identity-config/ldap-test")
check "her group's policy, once attached" "$(jq_ 'd["passed"], d["policies"], d.get("note")' <<<"$L")" "True ['readwrite'] None"
mc idp ldap policy detach it readwrite --group "cn=devs,ou=groups,$BASE" >/dev/null
check "an unknown user" "$(api -d '{"username":"zed"}' "$C/api/v1/identity-config/ldap-test" | jq_ 'd["passed"], d["error"].startswith("No such user under the user search base")')" \
  "False True"
check "a wrong password" "$(api -d '{"username":"alice","password":"nope"}' "$C/api/v1/identity-config/ldap-test" | jq_ 'd["passed"], d["error"].startswith("The user cannot sign in")')" \
  "False True"
api -d '{"username":"alice","password":"alice123"}' "$C/api/v1/identity-config/ldap-test" >/dev/null
api -d '{"username":"alice","password":"nope"}' "$C/api/v1/identity-config/ldap-test" >/dev/null
check "a later failed lookup does not take back a pass" "$(api "$C/api/v1/identity-config" | jq_ 'd["test"]["ldap"]["passed"]')" True
HASH=$(api "$C/api/v1/identity-config" | jq_ 'd["candidateHash"]')
check "a passed LDAP test can be applied" "$(api -d '{"candidateHash":"'"$HASH"'"}' "$C/api/v1/identity-config/apply" | jq_ 'd["applied"]')" True
BADL=${LDAP/lookup123/wrongpw}
api -X PUT -d '{"settings":{"ldap":'"$BADL"'}}' "$C/api/v1/identity-config/candidate" >/dev/null
check "a wrong service account password" \
  "$(api -d '{"username":"alice"}' "$C/api/v1/identity-config/ldap-test" | jq_ 'd["passed"], d["error"].startswith("The directory cannot be used with these settings")')" \
  "False True"

echo "== consoled takes up the settings the operator applies"
python3 - "$IDFILE" "$ISS" <<'PY'
import json, os, sys
f, iss = sys.argv[1], sys.argv[2]
v = {"oidc": {"configUrl": iss + "/.well-known/openid-configuration", "clientId": "idp-console", "clientSecret": "s3cret",
              "scopes": "openid profile", "displayName": "From the Identity page", "redirectUri": ""},
     "ldap": {"displayName": "LDAP"}}
open(f + ".tmp", "w").write(json.dumps(v))
os.rename(f + ".tmp", f)  # as the kubelet swaps a mounted Secret
PY
sleep 1.2
check "OpenID and LDAP offered" "$(curl -s "$C/api/v1/login-methods" | jq_ 'd["oidc"], d["oidcName"], d["ldap"], d["localUsers"]')" \
  "True From the Identity page True False"
U="$WORK/user.jar"
loc=$(curl -s -c "$U" -o /dev/null -w '%{redirect_url}' "$C/api/v1/login/oidc")
check "sign-in goes to the provider" "${loc%%\?*}" "$ISS/authorize"
loc=$(curl -s -o /dev/null -w '%{redirect_url}' "$loc")
check "and back signs in" "$(curl -s -b "$U" -c "$U" -o /dev/null -w '%{redirect_url}' "$loc")" "$C/"
check "as the provider's user" "$(curl -s -b "$U" "$C/api/v1/session" | jq_ 'd["accessKey"]')" admin1
rm "$IDFILE"
sleep 1.2
check "the file gone: the startup settings again" "$(curl -s "$C/api/v1/login-methods" | jq_ 'd["oidc"], d["ldap"]')" "False False"

echo "identity: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
