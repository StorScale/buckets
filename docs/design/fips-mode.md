# Design: FIPS 140-3 mode

Status: agreed, being built. Roadmap: Phase 4, "FIPS 140-3 mode using the
OpenSSL 3 FIPS provider". With the usage, access and retention reports done,
it is the last part of Phase 4's gate: "FIPS mode is documented and tested".

## The problem

US federal agencies, their contractors (FedRAMP), and many banks and health
providers may only protect data with cryptography from a FIPS 140-3 validated
module. They ask two things of a storage product: does every security function
go through a validated module, and can it prove it? Today Buckets can't say
yes:

- **No validated module.** The image uses Debian's OpenSSL. The source build
  links a static OpenSSL 3.5.4. Neither includes the FIPS provider.
- **Hashing bypasses providers altogether.** `src/crypto/sha256.c`, `sha1.c`
  and `md5.c` call OpenSSL's low-level `SHA256_Init`-style functions. Those
  never reach a provider, so SigV4 signatures, HMACs and key derivations
  would stay outside the module even with the FIPS provider loaded.
- **Some algorithms are not approved:**
  - Argon2id derives the key for encrypted admin payloads (`src/crypto/madmin.c`).
  - ChaCha20-Poly1305 is used in TLS cipher suites, in KES keys and the KMS
    secret key, and for reading DARE data MinIO wrote on CPUs without AES.
  - Ed25519 checks OIDC tokens, SSH certificates and NATS keys.

What is fine already: new SSE data is encrypted with AES-256-GCM, and random
keys come from `RAND_bytes`, which the FIPS provider serves from its own DRBG
once it is the default.

## What FIPS mode means

Every security function runs in the OpenSSL FIPS provider, using only
algorithms it approves. Anything else either uses an approved alternative or is
refused with an error that says why. Buckets itself is not certified; it *uses*
a validated module. The docs will name the module and its CMVP certificate, so
nobody claims more than that.

Some hashing stays outside the module, because it protects nothing:
- **MD5 ETags and `Content-MD5`**, which the S3 protocol requires;
- **bitrot checksums:** HighwayHash, and the CRC and xxHash checksums;
- **SipHash**, which places objects on erasure sets.

MinIO's FIPS build and AWS's FIPS endpoints treat these the same way. MD5 is
fetched explicitly from the default provider (`provider=default`), so it's the
one visible exception.

## How it's turned on

- **A FIPS image variant**, for example `ghcr.io/storscale/bucketsd:1.13.0-fips`,
  alongside `buckets-console` and `buckets-kes`. Each holds:
  - OpenSSL's FIPS provider (`fips.so`), built from the newest OpenSSL release
    with a FIPS 140-3 certificate;
  - its `fipsmodule.cnf`.

  The rest of OpenSSL can be newer, which OpenSSL supports. The normal images
  don't change.
- **`BUCKETS_FIPS=on`**, which the FIPS images set. At startup the server:
  - runs `openssl fipsinstall` for the module on this machine, into a private
    directory. The 3.1.2 module's security policy requires its config to be
    generated on every machine and never copied, so it can't be baked into the
    image;
  - loads the `fips` and `base` providers and makes `fips=yes` the default;
  - runs the module's self-tests;
  - refuses to start if any of this fails, and never falls back.

  It logs the module's name, version and certificate. Admin `info`,
  `buckets_node_fips_mode` and a console badge show FIPS mode is on.
- **The operator:** `spec.fips: true` on a BucketsCluster selects the `-fips`
  images for the servers, console and KES.

## Changes, by area

| Area | Today | In FIPS mode |
| --- | --- | --- |
| SHA-1/256, HMAC (SigV4, STS, internode auth, key derivation) | low-level OpenSSL functions | `EVP_MD`/`EVP_MAC`, fetched once and reused. This applies in all modes, so there is one code path. |
| MD5 (ETags, `Content-MD5`) | low-level | EVP with `provider=default` (non-security use) |
| TLS (S3, console, internode, FTPS, targets) | ECDHE with AES-GCM or ChaCha20; default groups | TLS 1.2 ECDHE AES-GCM and TLS 1.3 AES-GCM only. Curves P-256, P-384 and P-521. |
| SSE (DARE) | encrypts AES-256-GCM; reads ChaCha20 too | the same, but reading ChaCha20 data is refused, naming the object |
| Admin payloads (madmin) | sends Argon2id with AES-GCM | sends PBKDF2-SHA256 with AES-GCM, which madmin already defines and `mc` reads (open question 2) |
| KES keys and the KMS secret key | AES-256 or ChaCha20 | AES-256 only. ChaCha20 keys can't be created or used. |
| OIDC and JWT | RS*, PS*, ES*, EdDSA, HS* | whatever the provider approves. A refused token says which algorithm. |
| SFTP (libssh) | libssh defaults, curve25519 and ChaCha20 included | key exchange, ciphers, MACs and host keys limited to ECDH over NIST curves, AES-GCM or AES-CTR, HMAC-SHA2, and RSA-SHA2 or ECDSA |
| Notification targets | as configured | Postgres MD5 password authentication is refused (MD5 would protect the password); SCRAM-SHA-256 works. MySQL's password exchanges use SHA-1 and SHA-256 hashing, which the module provides. NATS nkeys (Ed25519) fail: the 3.1.2 module has no Ed25519. |
| Console sessions | PBKDF2 with AES-GCM | the same, through the FIPS provider |

**Before turning FIPS on** for an existing cluster, a site needs to know
whether it holds ChaCha20 data. The encryption coverage report (1.11.0)
gains a **ChaCha20** count per bucket from the scanner. The scanner reads only
metadata, so it uses the sealed object key's cipher: MinIO seals the key and
encrypts the data in the same request with the same cipher choice (`sio`
picks ChaCha20 for both on CPUs without AES). Reads still check each package's
cipher, so an object the count missed is refused all the same. If it's zero, the
switch is safe. If not, **Encrypt existing objects** re-encrypts those objects
with AES-256-GCM first.

## Performance

The move from low-level hashing to EVP adds a little work per call. Contexts
are fetched once and reused, and hardware SHA and AES-NI are still used. I'll
measure PUT and GET throughput and SigV4 overhead with `s3bench` before and
after, in normal and FIPS mode, and put the figures in the docs. A drop of more
than 5% in normal mode is a bug.

## Tests

- **Unit:**
  - in FIPS mode, the hashes, HMACs, AEADs and KDFs come from the `fips`
    provider (checked by asking each fetched algorithm for its provider);
  - Argon2id, ChaCha20 and MD5 fetched without `provider=default` fail;
  - madmin output in FIPS mode is PBKDF2 (id `0x02`) and round-trips.
- **Integration** (`tests/integration/fips.sh`, with the FIPS build):
  - smoke, SSE-S3 and SSE-KMS through KES, and STS;
  - `mc admin user add`, which sends an encrypted payload;
  - a ChaCha20-only TLS client is refused;
  - an object MinIO encrypted with ChaCha20 is refused, by name;
  - the encryption coverage report counts ChaCha20 data.
- **CI:** a job builds the `-fips` images and runs `fips.sh` and the smoke test
  in them. The images record the module version they carry.
- **Docs:** `docs/fips.md` covers:
  - what is in the module and what is outside it, and why;
  - how to turn FIPS on, and what stops working;
  - the module's certificate.

## Decisions

1. **A separate `-fips` image** for each of the four images, which always runs
   in FIPS mode. The normal images are unchanged.
2. **Argon2id admin payloads from a standard `mc` are accepted** on the way in,
   outside the module, as documented; the server sends only PBKDF2.
   `BUCKETS_FIPS_STRICT=on` refuses them.
3. **ChaCha20 data is refused** in FIPS mode, after the encryption report
   shows where it is.
4. **The module is OpenSSL's FIPS provider 3.1.2**, FIPS 140-3 certificate
   #4985, valid until 10 March 2030. OpenSSL 3.5.4's provider is under CMVP
   review and will be offered once it is certified. The rest of OpenSSL stays
   at 3.5.
