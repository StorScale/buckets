#!/usr/bin/env bash
# OpenSSL's FIPS provider for FIPS mode (docs/fips.md): the module of a release
# with a FIPS 140-3 certificate, built as its security policy says
# (./Configure enable-fips), and a static openssl program of that release to
# install it on each machine (openssl fipsinstall). The one place the version
# is set: cmake/OpenSSLFips.cmake and the -fips images run this.
#   scripts/build-fips-provider.sh PREFIX   -> PREFIX/lib/ossl-modules/fips.so, PREFIX/bin/openssl
#   scripts/build-fips-provider.sh --version
set -euo pipefail
VERSION=3.1.2 # FIPS 140-3 certificate #4985, valid until 2030-03-10
SHA256=a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539
if [[ ${1:-} == --version ]]; then echo "$VERSION"; exit 0; fi
PREFIX=${1:?usage: build-fips-provider.sh PREFIX}
WORK=${FIPS_BUILD_DIR:-$(mktemp -d)}
TAR="$WORK/openssl-$VERSION.tar.gz"
[[ -f $TAR ]] || curl -fsSL -o "$TAR" "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
echo "$SHA256  $TAR" | sha256sum -c - >/dev/null
JOBS=$(nproc 2>/dev/null || echo 4)
rm -rf "$WORK/module" "$WORK/tool" && mkdir -p "$WORK/module" "$WORK/tool"
tar xzf "$TAR" -C "$WORK/module" --strip-components=1
tar xzf "$TAR" -C "$WORK/tool" --strip-components=1
# the module, exactly as the security policy builds it
(cd "$WORK/module" && ./Configure enable-fips --prefix="$PREFIX" --libdir=lib && make -j"$JOBS" && make install_fips) >"$WORK/module.log" 2>&1 ||
  { tail -20 "$WORK/module.log"; exit 1; }
# the program that installs it: static, so it needs no libcrypto of that version
(cd "$WORK/tool" && ./Configure no-shared --prefix="$WORK/unused" && make -j"$JOBS" build_programs) >"$WORK/tool.log" 2>&1 ||
  { tail -20 "$WORK/tool.log"; exit 1; }
mkdir -p "$PREFIX/bin"
cp "$WORK/tool/apps/openssl" "$PREFIX/bin/openssl"
echo "OpenSSL $VERSION FIPS provider in $PREFIX"
