#!/usr/bin/env bash
# MinIO to Buckets and back, on a real cluster: a tenant laid out as the MinIO
# Operator lays one out (StatefulSet <t>-pool-0, Service <t>-hl, PVCs
# data<n>-<t>-pool-0-<i>, drives /export<n>/data, user 1000, config.env, TLS,
# the S3 Service on 443) runs MinIO, gets data, is adopted in place by Buckets
# (scripts/adopt-minio.sh), checked, written to, rolled back to MinIO
# (scripts/rollback-to-minio.sh) and checked again. No MinIO Operator needed.
#
#   BUCKETS_TAG=<image tag> tests/e2e-k8s/adopt-minio.sh
#
# KUBECONTEXT     the cluster (default: the current context)
# NS              a namespace it creates and deletes (default buckets-adopt-test)
# REGISTRY        where the bucketsd, buckets-operator and buckets-kes images live,
#                 e.g. ghcr.io/storscale (required)
# MINIO_IMAGE     the MinIO image, e.g. <mirror>/minio:RELEASE.2024-10-13T13-34-11Z
#                 (required: quay.io and Docker Hub no longer serve MinIO images)
# MINIO_BINARY_URL, MINIO_BINARY_SHA256
#                 instead of an image: a static minio binary the pods fetch
#                 (checked against the hash) and run on busybox. MinIO's
#                 community images and binaries are no longer published, so a
#                 binary built with tools/build-oracles.sh can stand in.
# STORAGE_CLASS   for the drives (default: the cluster's default)
# AVOID_NODES     node names the pods must not run on (space separated)
# KES=1           the tenant encrypts with MinIO's KES on a Vault (KV v1, AppRole), laid out as
#                 the MinIO Operator lays it out (StatefulSet <t>-kes, ${VAR}s from Secrets); the
#                 adoption carries it over to buckets-kes ($REGISTRY/buckets-kes:$BUCKETS_TAG)
# KES_IMAGE       MinIO's KES, e.g. <mirror>/minio-kes:2024-09-11T07-22-50Z (required with KES=1)
# VAULT_IMAGE     default hashicorp/vault:1.18
# MC_BIN          an mc binary here: adds a team (tests/data/team-plain-rw.json, as the console's
#                 Teams page writes it) and a user with it on Buckets, through a port-forward, and
#                 checks MinIO enforces it, and keeps the team's marker, after the rollback
# KEEP=1          leaves the namespace (and its PVs) for a look afterwards
# Needs the buckets.io CRDs (operator/deploy/crds) and permission to create a
# namespace, a namespaced operator (Helm) and to patch PersistentVolumes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
NS=${NS:-buckets-adopt-test}
T=minio
REGISTRY=${REGISTRY:-}
MINIO_IMAGE=${MINIO_IMAGE:-}
KES_IMAGE=${KES_IMAGE:-}
VAULT_IMAGE=${VAULT_IMAGE:-hashicorp/vault:1.18}
KES=${KES:-}
[[ -n $REGISTRY ]] || { echo "set REGISTRY to where the bucketsd, buckets-operator and buckets-kes images live"; exit 2; }
[[ -n $MINIO_IMAGE ]] || { echo "set MINIO_IMAGE to a MinIO image the cluster can pull (MinIO no longer publishes any)"; exit 2; }
[[ -z $KES || -n $KES_IMAGE ]] || { echo "KES=1 needs KES_IMAGE: MinIO's KES, from a mirror"; exit 2; }
[[ -n ${BUCKETS_TAG:-} ]] || { echo "set BUCKETS_TAG to the bucketsd/buckets-operator image tag"; exit 2; }
CTXARG=${KUBECONTEXT:+--context $KUBECONTEXT}
k() { kubectl $CTXARG -n "$NS" "$@"; }
kc() { kubectl $CTXARG "$@"; }
WORK=$(mktemp -d)
STATE=$WORK/state
pass=0
fail=0
expect() {
  if [[ "$2" == "$3" ]]; then pass=$((pass + 1)); printf '  ok    %s\n' "$1"
  else fail=$((fail + 1)); printf '  FAIL  %s: got %q want %q\n' "$1" "$2" "$3"; fi
}
cleanup() {
  if [[ -n ${KEEP:-} ]]; then echo "kept namespace $NS and $WORK"; return; fi
  # the adoption set the drives' PVs to Retain: back to Delete, so deleting the
  # namespace's PVCs deletes the volumes behind them too
  local pv
  for pv in $(k get pvc -o jsonpath='{range .items[*]}{.spec.volumeName}{" "}{end}' 2>/dev/null || true); do
    kc patch pv "$pv" -p '{"spec":{"persistentVolumeReclaimPolicy":"Delete"}}' >/dev/null 2>&1 || true
  done
  helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" uninstall adopt-operator >/dev/null 2>&1 || true
  kc delete namespace "$NS" --wait=true >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

affinity() { # the AVOID_NODES rule, as JSON, or nothing
  [[ -n ${AVOID_NODES:-} ]] || return 0
  python3 -c 'import json,sys; print(json.dumps({"nodeAffinity":{"requiredDuringSchedulingIgnoredDuringExecution":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"kubernetes.io/hostname","operator":"NotIn","values":sys.argv[1:]}]}]}}}))' $AVOID_NODES
}

echo "== a MinIO tenant, laid out as the MinIO Operator does"
kc create namespace "$NS" >/dev/null
# TLS from a CA of our own, for every name the servers and clients use
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=adopt-test-ca -keyout "$WORK/ca.key" -out "$WORK/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=$T" -keyout "$WORK/tls.key" -out "$WORK/tls.csr" 2>/dev/null
printf 'subjectAltName=DNS:%s,DNS:%s.%s.svc,DNS:%s.%s.svc.cluster.local,DNS:*.%s-hl.%s.svc.cluster.local\n' \
  "$T" "$T" "$NS" "$T" "$NS" "$T" "$NS" > "$WORK/san.cnf"
openssl x509 -req -in "$WORK/tls.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
  -extfile "$WORK/san.cnf" -out "$WORK/tls.crt" 2>/dev/null
k create secret generic tls-minio --type=kubernetes.io/tls --from-file=tls.crt="$WORK/tls.crt" \
  --from-file=tls.key="$WORK/tls.key" --from-file=ca.crt="$WORK/ca.crt" >/dev/null
# config.env: the root credentials and a static KMS key, so objects can be encrypted
ROOT_USER=adoptroot
ROOT_PASS=$(openssl rand -hex 16)
AFF=$(affinity)
if [[ -z $KES ]]; then
  KMS_KEY="adopt-key:$(openssl rand -base64 32)"
  printf 'export MINIO_ROOT_USER=%s\nexport MINIO_ROOT_PASSWORD="%s"\nexport MINIO_KMS_SECRET_KEY=%s\n' \
    "$ROOT_USER" "$ROOT_PASS" "$KMS_KEY" > "$WORK/config.env"
else
  echo "== a Vault, and MinIO's KES on it, as the MinIO Operator runs KES"
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Pod
    metadata: {name: vault, labels: {app: vault}}
    spec:
      ${AFF:+affinity: $AFF}
      containers:
        - name: vault
          image: $VAULT_IMAGE
          args: [server, -dev, -dev-root-token-id=root, -dev-listen-address=0.0.0.0:8200]
          env: [{name: SKIP_SETCAP, value: "true"}]
          readinessProbe: {httpGet: {path: /v1/sys/health, port: 8200}, periodSeconds: 2}
  - apiVersion: v1
    kind: Service
    metadata: {name: vault}
    spec: {selector: {app: vault}, ports: [{port: 8200}]}
YAML
  k wait --for=condition=Ready pod/vault --timeout=300s >/dev/null
  V() { k exec vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault "$@"; }
  V secrets enable -path=kv -version=1 kv >/dev/null      # KES's default: engine kv, version 1
  V auth enable approle >/dev/null
  k exec -i vault -- env VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root vault policy write kes - >/dev/null <<'HCL'
path "kv/minio/*" { capabilities = ["create", "read", "delete", "list"] }
path "kv/minio" { capabilities = ["list"] }
HCL
  V write auth/approle/role/kes token_policies=kes token_ttl=1h >/dev/null
  k create secret generic vault-approle --from-literal=id="$(V read -field=role_id auth/approle/role/kes/role-id)" \
    --from-literal=secret="$(V write -f -field=secret_id auth/approle/role/kes/secret-id)" >/dev/null
  # MinIO signs in to KES with an API key; KES knows it by its identity (the SHA-256 of its public key)
  SEED=$(openssl rand -hex 32)
  KES_API_KEY="kes:v1:$( (printf '\000'; echo "$SEED" | xxd -r -p) | base64 -w0)"
  KES_IDENTITY=$(echo "302e020100300506032b657004220420$SEED" | xxd -r -p | openssl pkey -inform DER -pubout -outform DER | sha256sum | cut -c1-64)
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$T-kes" -keyout "$WORK/kes.key" -out "$WORK/kes.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s-kes,DNS:%s-kes.%s.svc,DNS:%s-kes.%s.svc.cluster.local\n' "$T" "$T" "$NS" "$T" "$NS" > "$WORK/kes-san.cnf"
  openssl x509 -req -in "$WORK/kes.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial -days 2 \
    -extfile "$WORK/kes-san.cnf" -out "$WORK/kes.crt" 2>/dev/null
  k create secret tls $T-kes-tls --cert="$WORK/kes.crt" --key="$WORK/kes.key" >/dev/null
  cat > "$WORK/server-config.yaml" <<CONF
address: 0.0.0.0:7373
admin:
  identity: \${MINIO_KES_IDENTITY}
tls:
  key: /tmp/kes/server.key
  cert: /tmp/kes/server.crt
keystore:
  vault:
    endpoint: http://vault.$NS.svc.cluster.local:8200
    prefix: minio
    approle:
      id: \${VAULT_ROLE_ID}
      secret: \${VAULT_SECRET_ID}
CONF
  k create secret generic kes-configuration --from-file=server-config.yaml="$WORK/server-config.yaml" >/dev/null
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata: {name: $T-kes, labels: {v1.min.io/kes: $T-kes}}
    spec:
      selector: {v1.min.io/kes: $T-kes}
      ports: [{name: https-kes, port: 7373, targetPort: 7373}]
  - apiVersion: apps/v1
    kind: StatefulSet
    metadata: {name: $T-kes, labels: {v1.min.io/kes: $T-kes}}
    spec:
      serviceName: $T-kes-hl
      replicas: 1
      selector: {matchLabels: {v1.min.io/kes: $T-kes}}
      template:
        metadata: {labels: {v1.min.io/kes: $T-kes}}
        spec:
          ${AFF:+affinity: $AFF}
          containers:
            - name: kes
              image: $KES_IMAGE
              args: [server, --config=/tmp/kes/server-config.yaml]
              env:
                - {name: MINIO_KES_IDENTITY, value: "$KES_IDENTITY"}
                - {name: VAULT_ROLE_ID, valueFrom: {secretKeyRef: {name: vault-approle, key: id}}}
                - {name: VAULT_SECRET_ID, valueFrom: {secretKeyRef: {name: vault-approle, key: secret}}}
              ports: [{containerPort: 7373}]
              volumeMounts: [{name: $T-kes, mountPath: /tmp/kes}]
          volumes:
            - name: $T-kes
              projected:
                sources:
                  - secret: {name: kes-configuration, items: [{key: server-config.yaml, path: server-config.yaml}]}
                  - secret: {name: $T-kes-tls, items: [{key: tls.crt, path: server.crt}, {key: tls.key, path: server.key}]}
YAML
  for _ in $(seq 60); do k get pod "$T-kes-0" >/dev/null 2>&1 && break; sleep 2; done
  k wait --for=condition=Ready pod/$T-kes-0 --timeout=300s >/dev/null
  expect "MinIO's KES up" "$(k get pod $T-kes-0 -o jsonpath='{.status.containerStatuses[0].ready}')" true
  printf 'export MINIO_ROOT_USER=%s\nexport MINIO_ROOT_PASSWORD="%s"\n' "$ROOT_USER" "$ROOT_PASS" > "$WORK/config.env"
  printf 'export MINIO_KMS_KES_ENDPOINT=https://%s-kes.%s.svc.cluster.local:7373\nexport MINIO_KMS_KES_API_KEY=%s\n' \
    "$T" "$NS" "$KES_API_KEY" >> "$WORK/config.env"
  printf 'export MINIO_KMS_KES_KEY_NAME=minio-key\nexport MINIO_KMS_KES_CAPATH=/tmp/certs/CAs/ca.crt\n' >> "$WORK/config.env"
fi
k create secret generic myminio-env-configuration --from-file=config.env="$WORK/config.env" >/dev/null
SC=${STORAGE_CLASS:+\"storageClassName\": \"$STORAGE_CLASS\",}
RUN_IMAGE=$MINIO_IMAGE RUN_CMD= INIT= BINVOL= BINMOUNT=
if [[ -n ${MINIO_BINARY_URL:-} ]]; then
  [[ -n ${MINIO_BINARY_SHA256:-} ]] || { echo "MINIO_BINARY_URL needs MINIO_BINARY_SHA256"; exit 2; }
  RUN_IMAGE=busybox:1.36
  RUN_CMD="command: [/minio-bin/minio]"
  INIT="initContainers: [{name: fetch-minio, image: curlimages/curl:8.10.1, volumeMounts: [{name: minio-bin, mountPath: /minio-bin}], command: [sh, -c, 'curl -fsSk \"$MINIO_BINARY_URL\" -o /minio-bin/minio && echo \"$MINIO_BINARY_SHA256  /minio-bin/minio\" | sha256sum -c - && chmod 755 /minio-bin/minio']}]"
  BINVOL="- {name: minio-bin, emptyDir: {}}"
  BINMOUNT="- {name: minio-bin, mountPath: /minio-bin}"
fi
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: Service
    metadata: {name: $T-hl, labels: {v1.min.io/tenant: $T}}
    spec:
      clusterIP: None
      publishNotReadyAddresses: true
      selector: {v1.min.io/tenant: $T}
      ports: [{name: https-minio, port: 9000, targetPort: 9000}]
  - apiVersion: v1
    kind: Service
    metadata: {name: $T, labels: {v1.min.io/tenant: $T}}
    spec:
      selector: {v1.min.io/tenant: $T}
      ports: [{name: https-minio, port: 443, targetPort: 9000}]
  - apiVersion: apps/v1
    kind: StatefulSet
    metadata: {name: $T-pool-0, labels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
    spec:
      serviceName: $T-hl
      replicas: 4
      podManagementPolicy: Parallel
      selector: {matchLabels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
      template:
        metadata: {labels: {v1.min.io/tenant: $T, v1.min.io/pool: pool-0}}
        spec:
          securityContext: {runAsUser: 1000, runAsGroup: 1000, fsGroup: 1000, runAsNonRoot: true, fsGroupChangePolicy: OnRootMismatch}
          ${AFF:+affinity: $AFF}
          $INIT
          containers:
            - name: minio
              image: $RUN_IMAGE
              $RUN_CMD
              args: [server, --certs-dir, /tmp/certs]
              env:
                - {name: MINIO_VOLUMES, value: "https://$T-pool-0-{0...3}.$T-hl.$NS.svc.cluster.local:9000/export{0...1}/data"}
                - {name: MINIO_CONFIG_ENV_FILE, value: /tmp/minio/config.env}
              ports: [{containerPort: 9000}]
              readinessProbe: {httpGet: {path: /minio/health/ready, port: 9000, scheme: HTTPS}, periodSeconds: 5}
              volumeMounts:
                - {name: data0, mountPath: /export0}
                - {name: data1, mountPath: /export1}
                - {name: cfg, mountPath: /tmp/minio}
                - {name: certs, mountPath: /tmp/certs}
                $BINMOUNT
          volumes:
            - {name: cfg, secret: {secretName: myminio-env-configuration}}
            $BINVOL
            - name: certs
              projected:
                sources:
                  - secret: {name: tls-minio, items: [{key: tls.crt, path: public.crt}, {key: tls.key, path: private.key}, {key: ca.crt, path: CAs/ca.crt}]}
      volumeClaimTemplates:
        - metadata: {name: data0}
          spec: {$SC accessModes: [ReadWriteOnce], resources: {requests: {storage: 5Gi}}}
        - metadata: {name: data1}
          spec: {$SC accessModes: [ReadWriteOnce], resources: {requests: {storage: 5Gi}}}
YAML
for i in 0 1 2 3; do
  for _ in $(seq 60); do k get pod "$T-pool-0-$i" >/dev/null 2>&1 && break; sleep 5; done
done
k wait --for=condition=Ready pod -l v1.min.io/tenant=$T --timeout=600s >/dev/null
expect "MinIO tenant up" "$(k get pods -l v1.min.io/tenant=$T -o jsonpath='{range .items[*]}{.status.containerStatuses[0].ready}{" "}{end}')" "true true true true "

echo "== a client, and data written by MinIO"
k create configmap adopt-ca --from-file=ca.crt="$WORK/ca.crt" >/dev/null
k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: cli}
spec:
  ${AFF:+affinity: $AFF}
  containers:
    - name: cli
      image: amazon/aws-cli:2.22.35
      command: [sleep, infinity]
      env:
        - {name: AWS_ACCESS_KEY_ID, value: "$ROOT_USER"}
        - {name: AWS_SECRET_ACCESS_KEY, value: "$ROOT_PASS"}
        - {name: AWS_DEFAULT_REGION, value: us-east-1}
        - {name: AWS_CA_BUNDLE, value: /ca/ca.crt}
      volumeMounts: [{name: ca, mountPath: /ca}]
  volumes: [{name: ca, configMap: {name: adopt-ca}}]
YAML
k wait --for=condition=Ready pod/cli --timeout=300s >/dev/null
EP=https://$T.$NS.svc
s3() { k exec cli -- aws --endpoint-url "$EP" "$@"; }
k exec cli -- sh -c 'head -c 3000000 /dev/urandom > /tmp/small; head -c 40000000 /dev/urandom > /tmp/big; for i in $(seq 1 50); do head -c $((i * 1000)) /dev/urandom > /tmp/o$i; done'
s3 s3 mb s3://plain >/dev/null
s3 s3 mb s3://versioned >/dev/null
s3 s3api put-bucket-versioning --bucket versioned --versioning-configuration Status=Enabled
k exec cli -- sh -c "for i in \$(seq 1 50); do aws --endpoint-url $EP s3 cp --quiet /tmp/o\$i s3://plain/many/o\$i; done"
s3 s3 cp --quiet /tmp/big s3://plain/big.bin                       # multipart (40 MB)
s3 s3 cp --quiet /tmp/small s3://plain/meta.bin --metadata team=finance,purpose=adopt-test
s3 s3api put-object-tagging --bucket plain --key meta.bin --tagging 'TagSet=[{Key=keep,Value=yes}]'
s3 s3 cp --quiet /tmp/small s3://plain/sse.bin --sse AES256       # encrypted with the KMS key
s3 s3 cp --quiet /tmp/o1 s3://versioned/doc.txt
s3 s3 cp --quiet /tmp/o2 s3://versioned/doc.txt                    # a second version
sums() { # bucket/key list -> "key md5" lines, read back through the endpoint; a read
  # that still fails after a few tries prints the key and its error instead
  k exec cli -- sh -c "for o in $*; do
    ok=0
    for t in 1 2 3 4; do aws --endpoint-url $EP s3 cp --quiet s3://\$o /tmp/got 2>/tmp/err && { ok=1; break; }; sleep 5; done
    if [ \$ok = 1 ]; then echo \"\$o \$(md5sum < /tmp/got | cut -c1-32)\"; else echo \"\$o ERROR \$(tail -1 /tmp/err)\"; fi
    rm -f /tmp/got /tmp/err
  done"
}
OBJS="plain/big.bin plain/meta.bin plain/sse.bin versioned/doc.txt $(seq -f 'plain/many/o%g' 1 50 | tr '\n' ' ')"
k exec cli -- sh -c 'cd /tmp && md5sum big o3 | cut -c1-32' > "$WORK/local.md5"   # line 1: big, 2: o3
sums $OBJS > "$WORK/minio.sums"
check_data() { # label, objects expected in bucket plain
  local got
  got=$(sums $OBJS)
  expect "$1: all $(wc -l < "$WORK/minio.sums") objects MinIO wrote read back identical" "$got" "$(cat "$WORK/minio.sums")"
  expect "$1: listing" "$(s3 s3 ls s3://plain --recursive | wc -l | tr -d ' ')" "$2"
  expect "$1: versions of doc.txt" "$(s3 s3api list-object-versions --bucket versioned --prefix doc.txt --query 'length(Versions)' --output text)" 2
  expect "$1: encrypted object" "$(s3 s3api head-object --bucket plain --key sse.bin --query ServerSideEncryption --output text)" AES256
  expect "$1: user metadata" "$(s3 s3api head-object --bucket plain --key meta.bin --query Metadata.team --output text)" finance
  expect "$1: tags" "$(s3 s3api get-object-tagging --bucket plain --key meta.bin --query 'TagSet[0].Value' --output text)" yes
}
expect "the big object is what was written" "$(grep -c "^plain/big.bin $(sed -n 1p "$WORK/local.md5")" "$WORK/minio.sums")" 1
check_data "MinIO" 53

echo "== Buckets adopts the tenant in place"
kc apply -f "$ROOT/operator/deploy/crds/" >/dev/null
helm ${KUBECONTEXT:+--kube-context $KUBECONTEXT} -n "$NS" install adopt-operator "$ROOT/operator/helm/buckets-operator" \
  --set image.repository="$REGISTRY/buckets-operator" --set image.tag="$BUCKETS_TAG" --set watchNamespace="$NS" \
  --set replicaCount=1 --set kesImage="$REGISTRY/buckets-kes:$BUCKETS_TAG" ${AFF:+--set-json affinity="$AFF"} \
  --wait --timeout 5m >/dev/null
ADOPT=("$ROOT/scripts/adopt-minio.sh" -n "$NS" -t "$T" ${KUBECONTEXT:+--context $KUBECONTEXT} --state "$STATE"
  --image "$REGISTRY/bucketsd:$BUCKETS_TAG" ${KES:+--check-kes})
"${ADOPT[@]}" > "$WORK/adopt.log" 2>&1 && ok=yes || { ok=no; cat "$WORK/adopt.log"; }
expect "dry run passes" "$ok" yes
if [[ -n $KES ]]; then
  expect "dry run: buckets-kes reads the tenant's key" "$(grep -o "ok: key 'minio-key' (AES256)" "$WORK/adopt.log")" "ok: key 'minio-key' (AES256)"
  expect "the plan never shows the credentials" "$(grep -c -e "$(k get secret vault-approle -o jsonpath='{.data.secret}' | base64 -d)" -e "${KES_API_KEY#kes:v1:}" "$WORK/adopt.log")" 0
  expect "the check pod is gone" "$(k get pod $T-buckets-kes-check -o name 2>/dev/null || echo gone)" gone
fi
"${ADOPT[@]}" --apply > "$WORK/adopt.log" 2>&1 && ok=yes || { ok=no; cat "$WORK/adopt.log"; }
expect "adoption" "$ok" yes
if [[ -n $KES ]]; then
  expect "the state never holds the credentials" "$(grep -rc "$(k get secret vault-approle -o jsonpath='{.data.secret}' | base64 -d)" "$STATE" | grep -vc ':0$')" 0
  expect "KES carried over" "$(k get bc $T -o jsonpath='{.spec.kms.kes.keyName} {.spec.kms.kes.createKey} {.spec.kms.kes.name}')" "minio-key false $T-buckets-kes"
  expect "buckets-kes ready" "$(k get bc $T -o jsonpath='{.status.kms.phase}')" Ready
  expect "on the tenant's Vault" "$(k get bc $T -o jsonpath='{.status.kms.backend}' | grep -o "vault.$NS.svc.cluster.local:8200")" "vault.$NS.svc.cluster.local:8200"
  expect "bucketsd reads a config.env without the KES lines" "$(k get secret $T-buckets-config -o jsonpath='{.data.config\.env}' | base64 -d | grep -c MINIO_KMS_)" 0
  expect "MinIO's config.env untouched" "$(k get secret myminio-env-configuration -o jsonpath='{.data.config\.env}' | base64 -d | grep -c MINIO_KMS_KES_)" 4
  expect "the tenant's KES left as it was" "$(k get sts $T-kes -o jsonpath='{.spec.template.spec.containers[0].image}')" "$KES_IMAGE"
fi
expect "the same StatefulSet now runs bucketsd" "$(k get sts $T-pool-0 -o jsonpath='{.spec.template.spec.containers[0].name}')" bucketsd
expect "every PV is Retain" "$(for pv in $(k get pvc -o jsonpath='{range .items[*]}{.spec.volumeName}{" "}{end}'); do kc get pv $pv -o jsonpath='{.spec.persistentVolumeReclaimPolicy}{"\n"}'; done | sort -u)" Retain
check_data "Buckets" 53
if [[ -n $KES ]]; then
  s3 s3 cp --quiet /tmp/o3 s3://plain/sse-by-buckets.bin --sse AES256
  expect "Buckets encrypts with the tenant's key" "$(s3 s3api head-object --bucket plain --key sse-by-buckets.bin --query ServerSideEncryption --output text)" AES256
  expect "and makes no key of its own" "$(V list -format=json kv/minio | tr -d ' \n')" '["minio-key"]'
fi

# a team, as the Teams page writes it: its policy and a user with it, through the admin API
pf_mc() { # mc against the tenant through a fresh port-forward (pods come and go between uses)
  local port=19443 pid r=0
  kubectl $CTXARG -n "$NS" port-forward "svc/$T" "$port:443" >/dev/null 2>&1 &
  pid=$!
  for _ in $(seq 50); do nc -z 127.0.0.1 "$port" 2>/dev/null && break; sleep 0.2; done
  "$MC_BIN" --config-dir "$WORK/mc" --insecure --no-color alias set t "https://127.0.0.1:$port" "$ROOT_USER" "$ROOT_PASS" >/dev/null &&
    "$MC_BIN" --config-dir "$WORK/mc" --insecure --no-color "$@" || r=$?
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null || true
  return $r
}
team_s3() { k exec cli -- env AWS_ACCESS_KEY_ID=teamer AWS_SECRET_ACCESS_KEY=teamersecret123 aws --endpoint-url "$EP" "$@"; }
check_team() { # label: the team's user reads and writes plain, and cannot reach versioned
  expect "$1: the team's user reads its bucket" "$(team_s3 s3 cp --quiet s3://plain/meta.bin /tmp/t >/dev/null 2>&1 && echo yes || echo no)" yes
  expect "$1: and writes it" "$(team_s3 s3 cp --quiet /tmp/o1 s3://plain/team-probe >/dev/null 2>&1 && team_s3 s3 rm --quiet s3://plain/team-probe >/dev/null 2>&1 && echo yes || echo no)" yes
  expect "$1: but not another bucket" "$(team_s3 s3 ls s3://versioned 2>&1 | grep -c AccessDenied)" 1
}
if [[ -n ${MC_BIN:-} ]]; then
  echo "== a team on Buckets"
  pf_mc admin policy create t team-plain-rw "$ROOT/tests/data/team-plain-rw.json" >/dev/null
  pf_mc admin user add t teamer teamersecret123 >/dev/null
  pf_mc admin policy attach t team-plain-rw --user teamer >/dev/null
  check_team "Buckets"
fi

echo "== Buckets writes, then hands the drives back"
s3 s3 cp --quiet /tmp/o3 s3://plain/by-buckets.bin
s3 s3 cp --quiet /tmp/o3 s3://versioned/by-buckets.txt
expect "a write on Buckets" "$(s3 s3api head-object --bucket plain --key by-buckets.bin --query ContentLength --output text)" 3000
"$ROOT/scripts/rollback-to-minio.sh" -n "$NS" -t "$T" ${KUBECONTEXT:+--context $KUBECONTEXT} --state "$STATE" --apply \
  > "$WORK/rollback.log" 2>&1 && ok=yes || { ok=no; cat "$WORK/rollback.log"; }
expect "rollback" "$ok" yes
expect "the StatefulSet runs MinIO again" "$(k get sts $T-pool-0 -o jsonpath='{.spec.template.spec.containers[0].image}')" "$RUN_IMAGE"
check_data "MinIO after rollback" $([[ -n $KES ]] && echo 55 || echo 54)
expect "MinIO reads what Buckets wrote" "$(k exec cli -- sh -c "aws --endpoint-url $EP s3 cp --quiet s3://plain/by-buckets.bin /tmp/g && md5sum < /tmp/g | cut -c1-32")" "$(sed -n 2p "$WORK/local.md5")"
if [[ -n $KES ]]; then
  expect "MinIO decrypts what Buckets encrypted" "$(k exec cli -- sh -c "aws --endpoint-url $EP s3 cp --quiet s3://plain/sse-by-buckets.bin /tmp/g && md5sum < /tmp/g | cut -c1-32")" "$(sed -n 2p "$WORK/local.md5")"
  expect "the KMS settings went with Buckets" "$(k get secret $T-kms -o name 2>/dev/null || echo gone)" gone
fi
expect "MinIO sees Buckets' versioned object" "$(s3 s3api list-object-versions --bucket versioned --prefix by-buckets --query 'length(Versions)' --output text)" 1
if [[ -n ${MC_BIN:-} ]]; then
  check_team "MinIO after rollback"
  expect "MinIO keeps the team's marker, so Buckets reads it back as a team" \
    "$(pf_mc admin policy info t team-plain-rw | grep -o 'buckets-team:v1:plain:rw"' | head -1)" 'buckets-team:v1:plain:rw"'
fi

echo "adopt-minio: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
