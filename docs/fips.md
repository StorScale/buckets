# FIPS 140-3 mode

In FIPS mode, every security function in Buckets runs in a validated
cryptographic module: the **OpenSSL FIPS Provider 3.1.2**, [FIPS 140-3
certificate #4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985),
valid until 10 March 2030. Buckets itself is not certified. It *uses* that
module, the way US federal agencies, FedRAMP systems and many regulated buyers
require.

The design, and why it's built this way, is in
[design/fips-mode.md](design/fips-mode.md).

## Turning it on

FIPS mode comes in its own images. Each holds the module and always runs in
FIPS mode; the normal images don't change.

| Image | FIPS build |
| --- | --- |
| `ghcr.io/storscale/bucketsd:<version>` | `ghcr.io/storscale/bucketsd:<version>-fips` |
| `ghcr.io/storscale/buckets-console:<version>` | `...:<version>-fips` |
| `ghcr.io/storscale/buckets-kes:<version>` | `...:<version>-fips` |
| `ghcr.io/storscale/buckets-operator:<version>` | `...:<version>-fips` |

They're signed like the others; verify them with `cosign verify` as the
[README](../README.md) shows.

**With the operator,** set `spec.fips: true` on the BucketsCluster:

```yaml
apiVersion: buckets.io/v1alpha1
kind: BucketsCluster
metadata: {name: store}
spec:
  fips: true
  pools: [{servers: 4, volumesPerServer: 2}]
```

The servers, the console and KES then run the `-fips` images. If you name an
image yourself (`spec.image`, `spec.console.image`, `spec.kms.kes.image`), it's
used as given, so name a `-fips` one. Either way the operator turns FIPS mode
on in the pods, so an image without the module refuses to start rather than
run outside FIPS mode. For the operator itself, install its chart with
`--set fips=true`.

**Without the operator,** run a `-fips` image, or set `BUCKETS_FIPS=on` for a
build that has the module (see [Building](#building)).

### At startup

The module's security policy requires its self-tests to run, and its
configuration to be generated, on every machine it runs on, never copied from
another. So each server, on every start:

1. runs `openssl fipsinstall` for the module, into a private directory;
2. loads the module and makes it the default for everything;
3. refuses to start if any of this fails. It never falls back.

It then logs, for example:

```
fips: FIPS 140-3 mode, with OpenSSL FIPS Provider 3.1.2
```

**Checking it:**
- `mc admin info --json` shows `"fips": {"enabled": true, "module": "OpenSSL FIPS Provider 3.1.2"}` for each server;
- the metric `buckets_node_fips_mode` is 1;
- the console's Dashboard shows **FIPS 140-3**.

| Setting | Default | |
| --- | --- | --- |
| `BUCKETS_FIPS` | `on` in the `-fips` images | FIPS mode |
| `BUCKETS_FIPS_MODULE` | `/usr/lib/buckets/fips/fips.so` | the module |
| `BUCKETS_FIPS_OPENSSL` | `/usr/lib/buckets/fips/openssl` | the program that installs it (OpenSSL 3.1.2) |
| `BUCKETS_FIPS_DIR` | a new directory under `$TMPDIR` | the per-machine configuration. The operator mounts an in-memory volume here, since the pods' root filesystem is read-only. |
| `BUCKETS_FIPS_STRICT` | off | also refuse admin payloads sealed with Argon2id (below) |

## What runs in the module

| Function | In FIPS mode |
| --- | --- |
| TLS (S3, console, internode, FTPS, connections to targets, KES and identity providers) | TLS 1.2 with ECDHE and AES-GCM; TLS 1.3 with AES-GCM; curves P-256, P-384 and P-521 |
| SigV4 and SigV2 signatures, STS tokens, internode authentication | HMAC-SHA256 and HMAC-SHA1 |
| SSE-S3, SSE-KMS and SSE-C | AES-256-GCM (DARE), object keys sealed with HMAC-SHA256 and AES-256-GCM |
| The KMS secret key and KES keys | AES-256-GCM |
| Admin payloads the server sends (`mc admin`) | PBKDF2-SHA256 with AES-256-GCM, as madmin-go's FIPS build does |
| The console's sessions | PBKDF2-SHA256 with AES-256-GCM |
| OpenID Connect tokens | RSA (RS*, PS*), ECDSA (ES*) and HMAC (HS*) |
| SFTP | key exchange: ECDH over NIST curves, or Diffie-Hellman groups 14, 16 and 18 with SHA-2. Ciphers: AES-GCM and AES-CTR. MACs: HMAC-SHA2. Host keys: ECDSA (NIST curves) or RSA. |
| Random numbers (keys, nonces, credentials) | the module's DRBG |
| S3 checksums `x-amz-checksum-sha256` and `-sha1` | SHA-256 and SHA-1 |

## What runs outside it, and why

The module covers the security functions. A few hashes protect nothing, and the
S3 protocol or the storage format requires them, so they stay outside it:

- **MD5:** ETags and `Content-MD5`, which S3 clients compare but which secure
  nothing. MinIO's FIPS build and AWS's FIPS endpoints do the same.
- **HighwayHash:** bitrot checksums on the drives, which detect accidental
  damage, not tampering.
- **CRC32, CRC32C, CRC64NVME and xxHash:** checksums.
- **SipHash:** which erasure set an object goes to.

**Argon2id admin payloads from a standard `mc`.** `mc` seals admin payloads
(new users, access keys, configuration) with Argon2id, which isn't approved.
They already travel inside TLS from the module, which is what protects them.
So FIPS mode accepts them on the way in, deriving their key outside the module,
and sends only PBKDF2. If your auditors require refusing them, set
`BUCKETS_FIPS_STRICT=on`. The server then answers:

```
FIPS strict mode: the request is sealed with Argon2id, which is outside the FIPS module;
send it with PBKDF2 (a FIPS build of mc), or unset BUCKETS_FIPS_STRICT
```

Strict mode also can't read configuration that MinIO stored sealed with
Argon2id, from before it used a KMS for that.

## What stops working

| | Why | What to do |
| --- | --- | --- |
| Objects encrypted with ChaCha20-Poly1305 | MinIO picks it on CPUs without AES instructions; the module has no ChaCha20 | Before switching: **Reports → Encryption coverage** shows a ChaCha20 column when there is any. **Encrypt existing objects** re-encrypts it with AES-256-GCM. In FIPS mode, reading such an object answers `NotImplemented` and says why. |
| KES keys created with ChaCha20 (`buckets-kes` on CPUs without AES, or imported) | the same | Before switching, create a new key (outside FIPS mode on a CPU with AES, or in FIPS mode, where every new key is AES-256), make it the buckets' default, and re-encrypt with **Encrypt existing objects** |
| TLS clients that offer only ChaCha20, or only X25519 | not in the module | Current clients offer AES-GCM and P-256 |
| SFTP with an Ed25519 host key | the module has no Ed25519 | Use an ECDSA or RSA host key; the server refuses to start and says so |
| SFTP clients with Ed25519 keys or certificates | the same | ECDSA or RSA user keys |
| OpenID tokens signed with EdDSA | the same | RS256 or ES256 in the identity provider (the usual default) |
| NATS targets authenticated with nkeys | Ed25519 | User and password, or a token, over TLS |
| PostgreSQL targets using `md5` password authentication | MD5 would protect the password | `scram-sha-256` (PostgreSQL's default since 14) |

## Performance

Same server, four drives in tmpfs, 16 clients (`s3bench`), averaged over
three rounds:

| | 4 KiB PUT | 4 KiB GET | 10 MiB PUT | 10 MiB GET |
| --- | --- | --- | --- | --- |
| 1.12.0 | 2,944/s | 6,581/s | 550 MiB/s | 4,205 MiB/s |
| 1.13.0 | 2,959/s | 7,286/s | 550 MiB/s | 4,460 MiB/s |
| 1.13.0, FIPS mode | 3,216/s | 6,943/s | 562 MiB/s | 4,394 MiB/s |

The differences are within the noise between runs (about ±20%). The module
uses the same AES-NI and SHA instructions as the rest of OpenSSL.

## Building

`cmake -DBUCKETS_FIPS_PROVIDER=ON` builds the module once into
`.deps/fips-3.1.2`, with `scripts/build-fips-provider.sh`. That script holds
the version and checksum, and builds the module exactly as its security policy
says (`./Configure enable-fips`). The Dockerfiles' `fips` target builds the
same, for example:

```
docker build -f docker/Dockerfile.bucketsd --target fips -t bucketsd:fips .
```

`tests/unit/test_fips.c` and `tests/integration/fips.sh` run against it.

OpenSSL 3.5.4's FIPS provider is under CMVP review. Buckets will move to it
once it is certified.
