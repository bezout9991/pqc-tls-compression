#!/bin/sh
# patch_openssl_v2.sh - Rebuild OpenSSL with cert compression (RFC 8879)
# Run inside uma-tls-quic-pq-34 image

set -e

echo "=== Step 1: Install build deps ==="
apt-get update -qq 2>/dev/null
apt-get install -y -qq gcc make perl git pkg-config \
    zlib1g-dev libzstd-dev libbrotli-dev 2>&1 | tail -2

echo ""
echo "=== Step 2: Clone OpenSSL ==="
cd /tmp
rm -rf openssl-build
git clone --depth 1 --branch openssl-3.4.2 https://github.com/openssl/openssl.git openssl-build 2>&1 | tail -2

echo ""
echo "=== Step 3: Configure (static, no shared libs) ==="
cd openssl-build
./config no-shared --prefix=/opt/openssl-new 2>&1 | tail -3

echo ""
echo "=== Step 4: Patch generated configuration.h to disable NO_COMP_ALG ==="
# The generated header has the actual defines. Patch them directly.
sed -i 's/^#define OPENSSL_NO_COMP_ALG$/\/\* #undef OPENSSL_NO_COMP_ALG \*\//' include/openssl/configuration.h
sed -i 's/^#define OPENSSL_NO_BROTLI$/\/\* #undef OPENSSL_NO_BROTLI \*\//' include/openssl/configuration.h
sed -i 's/^#define OPENSSL_NO_ZLIB$/\/\* #undef OPENSSL_NO_ZLIB \*\//' include/openssl/configuration.h
sed -i 's/^#define OPENSSL_NO_ZSTD$/\/\* #undef OPENSSL_NO_ZSTD \*\//' include/openssl/configuration.h

echo "Patched configuration.h:"
grep -E "COMP_ALG|BROTLI|ZLIB|ZSTD" include/openssl/configuration.h | grep -v "BROTLI_DYNAMIC\|ZLIB_DYNAMIC\|ZSTD_DYNAMIC\|BROTLI_NO\|NO_BROTLI" | head -10

echo ""
echo "=== Step 5: Build ==="
make -j$(nproc) 2>&1 | tail -3

echo ""
echo "=== Step 6: Install ==="
make install_sw install_ssldirs 2>&1 | tail -2

echo ""
echo "=== Step 7: Verify cert_comp ==="
/opt/openssl-new/bin/openssl s_server -help 2>&1 | grep "cert_comp" && echo "SUCCESS!" || echo "FAILED"

echo ""
echo "=== Step 8: Replace system OpenSSL ==="
# Backup old
cp /opt/oqssa/bin/openssl /opt/oqssa/bin/openssl.bak 2>/dev/null || true
# Copy new (statically linked, no lib dependency issues)
cp /opt/openssl-new/bin/openssl /opt/oqssa/bin/openssl
# Copy libraries
cp /opt/openssl-new/lib64/libssl.a /opt/oqssa/lib64/ 2>/dev/null || true
cp /opt/openssl-new/lib64/libcrypto.a /opt/oqssa/lib64/ 2>/dev/null || true

echo ""
echo "=== Step 9: Final check ==="
/opt/oqssa/bin/openssl version 2>&1
/opt/oqssa/bin/openssl s_server -help 2>&1 | grep "cert_comp" && echo "SUCCESS: cert_comp available!" || echo "FAILED: cert_comp not found"

echo ""
echo "=== DONE ==="
