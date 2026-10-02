# Encryption: a key management service, set up in the console

Buckets encrypts objects with SSE-S3 and SSE-KMS once it has a key management service (KMS). On Kubernetes, buckets-operator runs a [KES](https://github.com/minio/kes) server for each cluster, and you choose in the console where KES keeps the keys:

- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager

The console tests the settings with a temporary KES server before anything changes. The keys never touch the storage servers' drives.

## How it works

1. **Settings.** The console's **Encryption** page leads through the setup:
   1. Choose a key store.
   2. Connect to it. The page shows the policy or role to create in the key store, filled in from your settings.
   3. Name the default key.
   4. Test the settings, then apply them.
2. **Test.** The console saves the settings in Secret `<cluster>-kms-candidate` and asks the operator for a trial: it sets the BucketsCluster's `buckets.io/kms-test` annotation. The operator then:
   1. starts KES with those settings, as Deployment `<cluster>-kes-test`;
   2. signs in to the key store;
   3. makes sure the default key exists, creating it if you allowed that;
   4. encrypts and decrypts a data key with it;
   5. checks that every key the cluster uses now is also in the key store.

   Each step and its outcome is written to the BucketsCluster's `status.kms.test`. When a step fails, the console shows KES's own error, for example `invalid role or secret ID` or `permission denied`, with a hint at the usual cause. The trial server is removed afterwards.
3. **Apply.** Only a passed test can be applied. The console copies the tested settings to Secret `<cluster>-kms` (`settings.json`) and sets `spec.kms.kes.keyName`. The operator runs KES as Deployment `<cluster>-kes` (two replicas by default) and creates the default key if it's missing.
4. **Rollout.** The first time, the operator then restarts the storage servers one at a time with `MINIO_KMS_KES_*` set. Buckets stays available throughout.

   Later changes to where keys are kept restart only the KES servers. A new default key name restarts the storage servers, one at a time.

KES and bucketsd authenticate each other with keys and a certificate that the operator generates and keeps in Secrets `<cluster>-kes-identity` and `<cluster>-kes-tls`. Nobody needs to handle them.

### Who may change it

Changing the KMS needs the `admin:ConfigUpdate` permission. `consoleAdmin` has it.

The console runs as its own ServiceAccount, `<cluster>-console`. Its Role allows reading and patching its own BucketsCluster, and reading and updating the two KMS settings Secrets, nothing else. It can't change the cluster's status, so it can't pass a test that didn't pass.

Secret fields (AppRole secret IDs, AWS secret keys, Azure client secrets, GCP service account keys) are never sent back to the browser once saved. Leaving such a field empty when editing keeps the saved value.

## Preparing the key store

The **Connection** step shows these, filled in from your settings.

**HashiCorp Vault.** Create a KV engine (version 2 by default) and a policy for KES. Then create either an AppRole or a Kubernetes auth role bound to ServiceAccount `<cluster>-kes` in the cluster's namespace.

With KV version 2 and prefix `buckets/store`, the policy is:

```hcl
path "kv/data/buckets/store/*" { capabilities = ["create", "read", "delete"] }
path "kv/metadata/buckets/store/*" { capabilities = ["list", "delete"] }
```

Give each cluster its own prefix. If Vault's certificate isn't from a public CA, paste its CA certificate under **Advanced**.

**AWS Secrets Manager.** The identity KES uses needs these permissions:

- `secretsmanager:CreateSecret`, `DeleteSecret`, `GetSecretValue` and `ListSecrets`;
- `kms:Encrypt`, `kms:Decrypt` and `kms:DescribeKey` on the KMS key, if you name one.

KES signs in with an access key, or with no key at all, in which case the AWS SDK finds credentials itself (an IAM role for the KES pods, or the node's instance profile).

**Azure Key Vault.** Give the application or managed identity the **Key Vault Secrets Officer** role on the vault, or an access policy for secrets that allows Get, List, Set, Delete, Recover and Purge. A managed identity needs its client ID.

**Google Secret Manager.** Enable the Secret Manager API. Give the service account **Secret Manager Admin** (`roles/secretmanager.admin`) in the project, then paste or upload its JSON key.

## Without the console

The same settings can be applied from manifests, for GitOps. Create Secret `<cluster>-kms` with a `settings.json` key:

```yaml
apiVersion: v1
kind: Secret
metadata: {name: store-kms, namespace: buckets}
stringData:
  settings.json: |
    {"backend": "vault",
     "vault": {"endpoint": "https://vault.example.com:8200", "engine": "kv", "version": "v2",
               "prefix": "buckets/store", "auth": "kubernetes", "kubernetes": {"role": "buckets-kes"}}}
```

Then add the following to the BucketsCluster:

```yaml
spec:
  kms:
    kes:
      keyName: buckets-default # created if missing
      replicas: 2
```

The settings' fields are described in `src/kms/kesutil.h`. `status.kms` reports the KES servers' state:

- `phase`: `NotConfigured`, `Starting`, `Ready`, `Degraded` or `Error`
- `message`
- `readyReplicas`
- `activated`: whether the storage servers use KES yet

## The KES image

The operator runs `quay.io/minio/kes:2024-09-11T07-22-50Z` by default, the release Buckets is tested with. MinIO no longer publishes images there. Point the operator at a mirror with `BUCKETS_KES_IMAGE`, the Helm value `kesImage`, or `spec.kms.kes.image` per cluster. If the image can't be pulled, the console says so.

## Things to know

- **Keys are the data.** Deleting a key, or losing the key store, makes every object encrypted with it unreadable for good. The console refuses to delete the default key or a key that buckets encrypt with by default.
- **Moving between key stores** works only if the new one already holds every key in use: the test refuses otherwise. Copy the keys first; KES can import them.
- **Removing the KMS** isn't offered in the console. Removing `spec.kms` stops KES and takes the KMS settings off the storage servers, which leaves encrypted objects unreadable until it's restored.
- **Existing objects** stay as they were written. **Encrypt existing objects** in a bucket's settings encrypts them in place (see `docs/parity.md`).
- **Outside Kubernetes** there's no operator, so set the KMS on the servers: `MINIO_KMS_KES_*` for KES, or `MINIO_KMS_SECRET_KEY` for a single static key. The console then shows the KMS but doesn't configure it.
