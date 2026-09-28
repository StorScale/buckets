#!/usr/bin/env bash
# LDAP / Active Directory: AssumeRoleWithLDAPIdentity against a mock
# directory (tests/integration/ldapmock.py), policy mappings on user and
# group DNs (mc idp ldap policy), policy entities, LDAP access keys, config
# validation, persistence, and LDAPS / StartTLS.
#   MC_BIN=/path/to/mc tests/integration/ldap.sh [bucketsd]
# Skips (exit 0) when MC_BIN is not set.
set -euo pipefail
BIN=${1:-build/src/bucketsd}
if [[ -z "${MC_BIN:-}" ]]; then
  echo "ldap: skipped (set MC_BIN)"
  exit 0
fi
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${PORT:-19760}
LPORT=${LPORT:-19761}
LSPORT=${LSPORT:-19762}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/buckets-ldap-XXXXXX")
EP="http://127.0.0.1:$PORT"
PIDS=()
PID=
cleanup() {
  [[ -n "$PID" ]] && kill "$PID" 2>/dev/null || true
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${KEEP:-}" ]] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; echo "--- server log"; tail -20 "$WORK/log"; exit 1; }
mc() { "$MC_BIN" --config-dir "$WORK/mc" --no-color "$@"; }
has() { grep -e "$2" >/dev/null <<<"$1" || fail "$3: $(head -c 600 <<<"$1")"; }

# ---- the directory: plain + StartTLS, and LDAPS ------------------------------
mkdir -p "$WORK/certs/CAs"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -nodes \
  -days 1 -keyout "$WORK/ldap.key" -out "$WORK/ldap.crt" -subj /CN=localhost \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null
cp "$WORK/ldap.crt" "$WORK/certs/CAs/ldap.crt"
LDAPMOCK_PATCH="$WORK/ldap-patch.json" python3 "$HERE/ldapmock.py" "$LPORT" "$LSPORT" "$WORK/ldap.crt" "$WORK/ldap.key" \
  2>"$WORK/ldap.log" &
PIDS+=($!)
for _ in $(seq 50); do nc -z 127.0.0.1 "$LPORT" 2>/dev/null && break; sleep 0.1; done

BASE=dc=example,dc=com
LDAP_ENV=(
  MINIO_IDENTITY_LDAP_LOOKUP_BIND_DN="cn=lookup,ou=svc,$BASE" MINIO_IDENTITY_LDAP_LOOKUP_BIND_PASSWORD=lookup123
  MINIO_IDENTITY_LDAP_USER_DN_SEARCH_BASE_DN="ou=people,$BASE" MINIO_IDENTITY_LDAP_USER_DN_SEARCH_FILTER="(uid=%s)"
  MINIO_IDENTITY_LDAP_USER_DN_ATTRIBUTES=mail
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_BASE_DN="ou=groups,$BASE"
  MINIO_IDENTITY_LDAP_GROUP_SEARCH_FILTER="(&(objectclass=groupOfNames)(member=%d))"
)
mkdir -p "$WORK"/d{1..4}
start() { # extra env...
  echo "-- start $*" >>"$WORK/log"
  local envs=()
  [[ -z "${NO_LDAP_ENV:-}" ]] && envs=("${LDAP_ENV[@]}")
  env BUCKETS_ROOT_USER=rootadmin BUCKETS_ROOT_PASSWORD=rootsecret123 ${envs[@]+"${envs[@]}"} "$@" \
    "$BIN" server --address "127.0.0.1:$PORT" --certs-dir "$WORK/certs" "$WORK/d{1...4}" 2>>"$WORK/log" &
  PID=$!
  for _ in $(seq 150); do
    mc alias set root "$EP" rootadmin rootsecret123 >/dev/null 2>&1 && mc admin info root >/dev/null 2>&1 && return
    sleep 0.1
  done
  fail "server did not start"
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null || true; PID=; }

sts() { # user password [extra form fields...]
  local u=$1 p=$2
  shift 2
  curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" --data-urlencode Action=AssumeRoleWithLDAPIdentity \
    --data-urlencode Version=2011-06-15 --data-urlencode "LDAPUsername=$u" --data-urlencode "LDAPPassword=$p" "$@" "$EP/"
}
xml() { sed -n "s:.*<$1>\\(.*\\)</$1>.*:\\1:p"; }
as_creds() { # response -> AK SK TK
  AK=$(xml AccessKeyId <<<"$1"); SK=$(xml SecretAccessKey <<<"$1"); TK=$(xml SessionToken <<<"$1")
  [[ -n "$AK" ]] || fail "no credentials: $1"
}
code() { curl -s -o /dev/null -w '%{http_code}' --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AK:$SK" \
  -H "X-Amz-Security-Token: $TK" "$@"; }

start MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_INSECURE=on
R=(--aws-sigv4 "aws:amz:us-east-1:s3" --user rootadmin:rootsecret123)
curl -sf "${R[@]}" -X PUT "$EP/docs" >/dev/null || fail "make bucket"
echo hello | curl -sf "${R[@]}" -X PUT --data-binary @- "$EP/docs/a.txt" >/dev/null || fail "put object"

echo "== no policy yet"
r=$(sts alice alice123)
has "$r" "expecting a policy to be set for user .uid=alice,ou=People,$BASE. or one of their groups: .cn=devs,ou=groups,$BASE." "no policy"
has "$r" "<Code>InvalidParameterValue</Code>" "no policy code"

echo "== mc idp ldap policy attach (group and user)"
out=$(mc idp ldap policy attach root readwrite --group "CN=devs,ou=groups,$BASE" 2>&1) || fail "attach group: $out"
out=$(mc idp ldap policy attach root readonly --user bob 2>&1) || fail "attach user: $out"
out=$(mc idp ldap policy attach root readonly --user nosuchuser 2>&1 || true)
has "$out" "does not exist" "attach unknown user"
out=$(mc idp ldap policy attach root readonly --group "cn=nosuch,ou=groups,$BASE" 2>&1 || true)
has "$out" "does not exist" "attach unknown group"

echo "== AssumeRoleWithLDAPIdentity"
r=$(sts alice alice123)
has "$r" "<AssumeRoleWithLDAPIdentityResult><Credentials>" "result shape"
as_creds "$r"
[[ $(code -X PUT --data x "$EP/docs/alice.txt") == 200 ]] || fail "group policy write"
r=$(sts bob bob123 --data-urlencode DurationSeconds=900)
as_creds "$r"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "user policy read"
[[ $(code -X PUT --data x "$EP/docs/bob.txt") == 403 ]] || fail "user policy write denied"
r=$(sts 'dave(jr)' dave123)
as_creds "$r"
[[ $(code -X PUT --data x "$EP/docs/dave.txt") == 200 ]] || fail "escaped DN user in group"
has "$(sts alice wrong)" "LDAP auth failed for DN uid=alice,ou=People,$BASE" "wrong password"
has "$(sts nobody x)" "User DN not found for: nobody" "unknown user"
has "$(sts carol carol123)" "expecting a policy" "no policy for carol"
has "$(sts alice alice123 --data-urlencode DurationSeconds=60)" "InvalidParameterValue" "too short duration"
has "$(sts '' x)" "<Code>MissingParameter</Code>" "missing username"
r=$(sts alice alice123 --data-urlencode \
  'Policy={"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::docs/*"]}]}')
as_creds "$r"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "session policy read"
[[ $(code -X PUT --data x "$EP/docs/sp.txt") == 403 ]] || fail "session policy narrows"

echo "== policy entities"
out=$(mc idp ldap policy entities root 2>&1) || fail "entities: $out"
has "$out" "cn=devs,ou=groups,$BASE" "entities group"
has "$out" "uid=bob,ou=people,$BASE\|uid=bob,ou=People,$BASE" "entities user"
out=$(mc idp ldap policy entities root --user alice 2>&1) || fail "entities user query: $out"
has "$out" "readwrite" "alice's group mapping"
out=$(mc admin user add root someone somesecret123 2>&1); echo "$out" >>"$WORK/log"
out=$(mc admin group disable root devs 2>&1 || true)
has "$out" "not allowed" "group status in LDAP mode"

echo "== LDAP access keys"
out=$(mc idp ldap accesskey create root alice --access-key alicekey1 --secret-key alicesecret123 2>&1) ||
  fail "accesskey create: $out"
AK=alicekey1 SK=alicesecret123 TK=
[[ $(code -X PUT --data x "$EP/docs/svc.txt") == 200 ]] || fail "access key inherits group policy"
out=$(mc idp ldap accesskey create root carol 2>&1 || true)
has "$out" "No policy set for user" "access key for user without policy"
out=$(mc idp ldap accesskey create root "uid=alice,ou=People,$BASE" 2>&1 || true)
has "$out" "User DN not found for: uid=alice" "access key for a DN (XMinioLDAPExpectedLoginName)"
r=$(sts bob bob123)
as_creds "$r"
MC_HOST_bob="http://$AK:$SK:$TK@127.0.0.1:$PORT" "$MC_BIN" --config-dir "$WORK/mc" idp ldap accesskey create bob \
  --access-key bobkey1 --secret-key bobsecret1234 >/dev/null 2>&1 || fail "self access key from STS"
out=$(mc idp ldap accesskey ls root alice bob 2>&1) || fail "accesskey ls: $out"
has "$out" "alicekey1" "ls alice"
has "$out" "bobkey1" "ls bob"
AK=bobkey1 SK=bobsecret1234 TK=
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "bob's key reads"
[[ $(code -X PUT --data x "$EP/docs/b2.txt") == 403 ]] || fail "bob's key cannot write"

echo "== STS revocation"
as_creds "$(sts alice alice123 --data-urlencode TokenRevokeType=t1)"
A1=($AK $SK $TK)
as_creds "$(sts alice alice123 --data-urlencode TokenRevokeType=t2)"
A2=($AK $SK $TK)
# (mc sends these with the builtin provider, so the user is given as its DN)
out=$(mc idp ldap accesskey sts-revoke root "uid=alice,ou=People,$BASE" --token-type t1 2>&1) || fail "sts-revoke type: $out"
AK=${A1[0]} SK=${A1[1]} TK=${A1[2]}
[[ $(code "$EP/docs/a.txt") == 403 ]] || fail "t1 token revoked"
AK=${A2[0]} SK=${A2[1]} TK=${A2[2]}
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "t2 token kept"
out=$(mc idp ldap accesskey sts-revoke root "uid=alice,ou=People,$BASE" --all 2>&1) || fail "sts-revoke all: $out"
[[ $(code "$EP/docs/a.txt") == 403 ]] || fail "all tokens revoked"

echo "== detach"
out=$(mc idp ldap policy detach root readwrite --group "cn=devs,ou=groups,$BASE" 2>&1) || fail "detach: $out"
has "$(sts alice alice123)" "expecting a policy" "detached"

echo "== persistence"
mc idp ldap policy attach root readwrite --group "cn=devs,ou=groups,$BASE" >/dev/null 2>&1 || fail "re-attach"
stop
start MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_INSECURE=on
as_creds "$(sts alice alice123)"
[[ $(code -X PUT --data x "$EP/docs/after.txt") == 200 ]] || fail "mapping survives restart"
AK=alicekey1 SK=alicesecret123 TK=
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "access key survives restart"

echo "== directory changes reach existing credentials (periodic sync)"
stop
start MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_INSECURE=on BUCKETS_LDAP_SYNC_INTERVAL=1
as_creds "$(sts 'dave(jr)' dave123)"
D1=($AK $SK $TK)
[[ $(code -X PUT --data x "$EP/docs/dave2.txt") == 200 ]] || fail "dave writes through devs"
as_creds "$(sts bob bob123)"
B1=($AK $SK $TK)
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "bob reads"
cat >"$WORK/ldap-patch.json" <<JSON
{"remove": ["uid=bob,ou=People,$BASE"], "members": {"cn=devs,ou=groups,$BASE": ["uid=alice,ou=People,$BASE"]}}
JSON
AK=${D1[0]} SK=${D1[1]} TK=${D1[2]}
for _ in $(seq 60); do [[ $(code -X PUT --data x "$EP/docs/dave3.txt") == 403 ]] && break; sleep 0.2; done
[[ $(code -X PUT --data x "$EP/docs/dave3.txt") == 403 ]] || fail "dave's credential lost devs"
AK=${B1[0]} SK=${B1[1]} TK=${B1[2]}
for _ in $(seq 60); do [[ $(code "$EP/docs/a.txt") == 403 ]] && break; sleep 0.2; done
[[ $(code "$EP/docs/a.txt") == 403 ]] || fail "bob's credential removed"
grep "no longer in the directory" "$WORK/log" >/dev/null || fail "sync log"
rm -f "$WORK/ldap-patch.json"

echo "== LDAPS (CA from certs/CAs) and StartTLS"
stop
start MINIO_IDENTITY_LDAP_SERVER_ADDR="localhost:$LSPORT"
as_creds "$(sts alice alice123)"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "ldaps"
stop
start MINIO_IDENTITY_LDAP_SERVER_ADDR="127.0.0.1:$LPORT" MINIO_IDENTITY_LDAP_SERVER_STARTTLS=on
as_creds "$(sts bob bob123)"
[[ $(code "$EP/docs/a.txt") == 200 ]] || fail "starttls"

echo "== identity_ldap from the stored config, validated on set"
stop
rm -rf "$WORK"/d{1..4} && mkdir -p "$WORK"/d{1..4}
NO_LDAP_ENV=1 start
has "$(sts alice alice123)" "LDAP is not configured" "LDAP off"
L=(lookup_bind_dn="cn=lookup,ou=svc,$BASE"
  group_search_base_dn="ou=groups,$BASE" group_search_filter="(&(objectclass=groupOfNames)(member=%d))")
out=$(mc admin config set root identity_ldap server_addr=127.0.0.1:1 server_insecure=on "${L[@]}" user_dn_search_base_dn="ou=people,$BASE" lookup_bind_password=lookup123 \
  user_dn_search_filter="(uid=%s)" 2>&1 || true)
has "$out" "LDAP Server Connection Error" "unreachable server rejected"
out=$(mc admin config set root identity_ldap server_addr=127.0.0.1:$LPORT server_insecure=on "${L[@]}" user_dn_search_base_dn="ou=people,$BASE" lookup_bind_password=lookup123 \
  user_dn_search_filter="(cn=x)" 2>&1 || true)
has "$out" "does not contain" "filter without %s rejected"
out=$(mc admin config set root identity_ldap server_addr=127.0.0.1:$LPORT server_insecure=on "${L[@]}" user_dn_search_base_dn="ou=people,$BASE" \
  lookup_bind_password=wrong user_dn_search_filter="(uid=%s)" 2>&1 || true)
has "$out" "LDAP Lookup Bind Error" "bad lookup password rejected"
out=$(mc admin config set root identity_ldap server_addr=127.0.0.1:$LPORT server_insecure=on "${L[@]}" lookup_bind_password=lookup123 \
  user_dn_search_base_dn="ou=nosuch,$BASE" user_dn_search_filter="(uid=%s)" 2>&1 || true)
has "$out" "not found in the LDAP server" "missing base DN rejected"
out=$(mc idp ldap update root server_addr=127.0.0.1:$LPORT 2>&1 || true)
has "$out" "No such IDP configuration exists" "update before add"
out=$(mc idp ldap add root server_addr=127.0.0.1:$LPORT server_insecure=on "${L[@]}" user_dn_search_base_dn="ou=people,$BASE" \
  lookup_bind_password=lookup123 user_dn_search_filter="(uid=%s)" 2>&1) || fail "mc idp ldap add: $out"
out=$(mc idp ldap add root server_addr=127.0.0.1:$LPORT 2>&1 || true)
has "$out" "already exists" "add twice"
out=$(mc idp ldap info root 2>&1) || fail "idp ldap info: $out"
has "$out" "user_dn_search_filter.*(uid=%s)" "info shows the filter"
if grep lookup123 >/dev/null <<<"$out"; then fail "info leaks the lookup password"; fi
out=$(mc idp ldap update root group_search_filter="(&(objectclass=groupOfNames)(member=%d)(cn=*))" 2>&1) ||
  fail "idp ldap update: $out"
out=$(mc idp ldap update root lookup_bind_password=wrong 2>&1 || true)
has "$out" "LDAP Lookup Bind Error" "update validated"
out=$(mc idp openid ls root 2>&1) || fail "idp openid ls: $out"
stop
NO_LDAP_ENV=1 start
out=$(mc --json idp ldap ls root 2>&1) || fail "idp ldap ls: $out"
has "$out" "\"enabled\":true" "ldap enabled after restart"
mc idp ldap policy attach root readwrite --user alice >/dev/null 2>&1 || fail "attach after config"
as_creds "$(sts alice alice123)"
c=$(code -X PUT "$EP/docs2"); [[ $c == 200 ]] || fail "config-driven LDAP: $c"
out=$(mc idp ldap rm root 2>&1) || fail "idp ldap rm: $out"
out=$(mc idp ldap info root 2>&1) || fail "info after rm: $out"
if grep server_addr >/dev/null <<<"$out"; then fail "rm left the config: $out"; fi
echo "PASS"
