#!/usr/bin/env bash
# The console's Sign-in page on a real cluster, against a real Keycloak and a
# real OpenLDAP: settings saved and tested (Keycloak's own login form, in a
# client pod playing the browser), applied by the operator to the servers,
# taken up by the console without a restart, and a real sign-in; a team made
# on the Teams page, reached by a Keycloak user whose only role names it; then LDAP
# added, looked up, tested again, applied (the servers restart one at a time
# for it) and offered by the console.
#
#   REGISTRY=ghcr.io/storscale BUCKETS_TAG=<tag> tests/e2e-k8s/identity.sh
#
# KUBECONTEXT     the cluster (default: the current context)
# NS              a namespace it creates and deletes (default buckets-identity-test)
# REGISTRY, BUCKETS_TAG   the bucketsd, buckets-console and buckets-operator images (required)
# KEYCLOAK_IMAGE  default quay.io/keycloak/keycloak:26.0
# OPENLDAP_IMAGE  default osixia/openldap:1.5.0
# AVOID_NODES     node names the pods must not run on
# KEEP=1          leaves the namespace
#
# LDAP's policies are attached by an admin call no tool in the cluster can
# make, so the LDAP sign-in is checked up to the servers' bind (their answer
# names the missing policy); tests/integration/ldap.sh covers the rest.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-identity-test}
KEYCLOAK_IMAGE=${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:26.0}
OPENLDAP_IMAGE=${OPENLDAP_IMAGE:-osixia/openldap:1.5.0}
[[ -n ${REGISTRY:-} && -n ${BUCKETS_TAG:-} ]] || { echo "set REGISTRY and BUCKETS_TAG"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
rc=0
cleanup() {
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS"; return; fi
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall idp-operator >/dev/null 2>&1 || true
  kc delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT
AFF=
if [[ -n ${AVOID_NODES:-} ]]; then
  AFF=$(python3 -c 'import json,sys; print(json.dumps({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"NotIn","values":sys.argv[1:]}]}]}}}))' $AVOID_NODES)
fi

echo "== Keycloak, OpenLDAP and a client pod"
kc create namespace "$NS" >/dev/null
k create configmap identity-driver --from-file="$ROOT/tests/e2e-k8s/identity_driver.py" >/dev/null
k create configmap ldap-seed --from-literal=seed.ldif="dn: ou=People,dc=example,dc=org
objectClass: organizationalUnit
ou: People

dn: uid=alice,ou=People,dc=example,dc=org
objectClass: inetOrgPerson
uid: alice
cn: Alice Smith
sn: Smith
userPassword: alice123

dn: uid=bob,ou=People,dc=example,dc=org
objectClass: inetOrgPerson
uid: bob
cn: Bob Jones
sn: Jones
userPassword: bob123

dn: ou=groups,dc=example,dc=org
objectClass: organizationalUnit
ou: groups

dn: cn=devs,ou=groups,dc=example,dc=org
objectClass: groupOfNames
cn: devs
member: uid=alice,ou=People,dc=example,dc=org
" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: keycloak, labels: {app: keycloak}}
    spec:
      ${AFF:+affinity: $AFF}
      containers:
        - name: keycloak
          image: $KEYCLOAK_IMAGE
          args: [start-dev, --http-port=8080]
          env:
            - {name: KC_BOOTSTRAP_ADMIN_USERNAME, value: admin}
            - {name: KC_BOOTSTRAP_ADMIN_PASSWORD, value: admin}
          readinessProbe: {httpGet: {path: /realms/master, port: 8080}, periodSeconds: 5}
  - apiVersion: v1
    kind: Service
    metadata: {name: keycloak}
    spec: {selector: {app: keycloak}, ports: [{port: 8080}]}
  - apiVersion: v1
    kind: Pod
    metadata: {name: openldap, labels: {app: openldap}}
    spec:
      ${AFF:+affinity: $AFF}
      containers:
        - name: openldap
          image: $OPENLDAP_IMAGE
          args: [--copy-service]
          env:
            - {name: LDAP_ORGANISATION, value: Example}
            - {name: LDAP_DOMAIN, value: example.org}
            - {name: LDAP_ADMIN_PASSWORD, value: adminpw}
            - {name: LDAP_READONLY_USER, value: "true"}
            - {name: LDAP_READONLY_USER_USERNAME, value: readonly}
            - {name: LDAP_READONLY_USER_PASSWORD, value: readonlypw}
            - {name: LDAP_TLS, value: "false"}
          readinessProbe: {tcpSocket: {port: 389}, periodSeconds: 5}
          # one file (subPath): a ConfigMap directory also holds ..data copies, which would be added twice
          volumeMounts: [{name: seed, mountPath: /container/service/slapd/assets/config/bootstrap/ldif/custom/50-seed.ldif, subPath: seed.ldif}]
      volumes: [{name: seed, configMap: {name: ldap-seed}}]
  - apiVersion: v1
    kind: Service
    metadata: {name: openldap}
    spec: {selector: {app: openldap}, ports: [{port: 389}]}
YAML
k wait --for=condition=Ready pod/keycloak pod/openldap --timeout=600s >/dev/null
KCADM="/opt/keycloak/bin/kcadm.sh"
kca() { k exec keycloak -- "$KCADM" "$@"; }
kca config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null
kca create realms -s realm=buckets -s enabled=true >/dev/null
kca create clients -r buckets -s clientId=buckets-console -s enabled=true -s publicClient=false -s secret=kcsecret \
  -s 'redirectUris=["*"]' -s standardFlowEnabled=true -s protocol=openid-connect >/dev/null
CID=$(kca get clients -r buckets -q clientId=buckets-console --fields id --format csv --noquotes)
kca create "clients/$CID/protocol-mappers/models" -r buckets -s name=roles -s protocol=openid-connect \
  -s protocolMapper=oidc-usermodel-realm-role-mapper -s 'config."claim.name"=roles' -s 'config."id.token.claim"=true' \
  -s 'config."access.token.claim"=true' -s 'config."multivalued"=true' -s 'config."jsonType.label"=String' >/dev/null
kca create roles -r buckets -s name=readwrite >/dev/null
kca create roles -r buckets -s name=consoleAdmin >/dev/null
kca create users -r buckets -s username=kcuser -s enabled=true -s email=kcuser@example.org -s emailVerified=true \
  -s firstName=KC -s lastName=User >/dev/null
kca set-password -r buckets --username kcuser --new-password kcpass123 >/dev/null
kca add-roles -r buckets --uusername kcuser --rolename readwrite >/dev/null
# a team member: only the team's role (the Teams page makes the policy)
kca create roles -r buckets -s name=team-finance-rw >/dev/null
kca create users -r buckets -s username=kcteam -s enabled=true -s email=kcteam@example.org -s emailVerified=true \
  -s firstName=KC -s lastName=Team >/dev/null
kca set-password -r buckets --username kcteam --new-password kcteam123 >/dev/null
kca add-roles -r buckets --uusername kcteam --rolename team-finance-rw >/dev/null
echo "   Keycloak: realm buckets, client buckets-console, user kcuser with readwrite, kcteam with team-finance-rw"

echo "== the operator and a cluster with its console ($REGISTRY, $BUCKETS_TAG)"
kc apply --server-side --force-conflicts -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install idp-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 ${AFF:+--set-json affinity="$AFF"} --wait --timeout 5m >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: idp}
spec:
  image: $REGISTRY/bucketsd:$BUCKETS_TAG
  pools:
    - servers: 4
      volumesPerServer: 1
      volumeClaimTemplate: {resources: {requests: {storage: 2Gi}}}
      ${AFF:+affinity: $AFF}
  console: {enabled: true, image: "$REGISTRY/buckets-console:$BUCKETS_TAG"${AFF:+, affinity: $AFF}}
YAML
for _ in $(seq 120); do [[ $(k get bc idp -o jsonpath='{.status.phase} {.status.readyServersText}' 2>/dev/null) == "Ready 4/4" ]] && break; sleep 5; done
k rollout status deploy/idp-console --timeout=300s >/dev/null
echo "   $(k get bc idp -o jsonpath='{.status.phase} {.status.readyServersText}'), console ready"
AK=$(k get secret idp-root -o jsonpath='{.data.rootUser}' | base64 -d)
SK=$(k get secret idp-root -o jsonpath='{.data.rootPassword}' | base64 -d)
k create secret generic driver-env --from-literal=ROOT_USER="$AK" --from-literal=ROOT_PASSWORD="$SK" >/dev/null
unset AK SK
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: client}
spec:
  ${AFF:+affinity: $AFF}
  containers:
    - name: client
      image: python:3.12-slim
      command: [sleep, infinity]
      env:
        - {name: CONSOLE, value: "http://idp-console.$NS.svc.cluster.local:9090"}
        - {name: KEYCLOAK, value: "http://keycloak.$NS.svc.cluster.local:8080"}
        - {name: LDAP_ADDR, value: "openldap.$NS.svc.cluster.local:389"}
      envFrom: [{secretRef: {name: driver-env}}]
      volumeMounts: [{name: driver, mountPath: /driver}]
  volumes: [{name: driver, configMap: {name: identity-driver}}]
YAML
k wait --for=condition=Ready pod/client --timeout=300s >/dev/null
drive() { k exec client -- python3 /driver/identity_driver.py "$1" || rc=1; }

echo "== Keycloak: saved, tested, applied, taken up by the console, a real sign-in"
drive oidc
echo "   status.identity: $(k get bc idp -o jsonpath='{.status.identity.phase}: {.status.identity.description}')"

echo "== Teams: a team made on the page, and a Keycloak role that names its policy"
drive teams

echo "== LDAP added: looked up, tested again, applied"
before=$(k get pods -l buckets.io/cluster=idp -o jsonpath='{range .items[*]}{.metadata.uid}{" "}{end}')
drive ldap
echo "   the servers restart one at a time for LDAP"
for _ in $(seq 120); do
  now=$(k get pods -l buckets.io/cluster=idp -o jsonpath='{range .items[*]}{.metadata.uid}{" "}{end}')
  ann=$(k get pods -l buckets.io/cluster=idp -o jsonpath='{range .items[*]}{.metadata.annotations.buckets\.io/identity-ldap}{" "}{end}' | wc -w)
  [[ $ann -eq 4 && $(k get bc idp -o jsonpath='{.status.phase} {.status.readyServersText}') == "Ready 4/4" ]] && break
  sleep 5
done
same=0; for u in $before; do [[ " $now " == *" $u "* ]] && same=$((same + 1)); done
if [[ $ann -eq 4 && $same -eq 0 ]]; then echo "ok    every server restarted with the LDAP settings"; else echo "FAIL  servers restarted for LDAP: $ann of 4 with the hash, $same not restarted"; rc=1; fi
drive ldap-signin

echo "== status: $(k get bc idp -o jsonpath='{.status.identity.phase}: {.status.identity.description}')"
[[ $rc -eq 0 ]] && echo "identity: passed" || echo "identity: FAILED"
exit $rc
