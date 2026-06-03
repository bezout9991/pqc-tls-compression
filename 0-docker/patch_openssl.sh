#!/bin/sh
# patch_openssl.sh - Rebuild OpenSSL with cert compression support
# Run this inside the uma-tls-quic-pq-34 image

set -e

echo "=== Step 1: Install build dependencies ==="
apt-get update -qq 2>/dev/null
apt-get install -y -qq gcc make perl git pkg-config \
    zlib1g-dev libzstd-dev libbrotli-dev 2>&1 | tail -3

echo ""
echo "=== Step 2: Download OpenSSL source ==="
cd /tmp
rm -rf openssl-3.4.2
git clone --depth 1 --branch openssl-3.4.2 https://github.com/openssl/openssl.git openssl-3.4.2 2>&1 | tail -2

echo ""
echo "=== Step 3: Patch configuration to force-enable compression ==="
cd openssl-3.4.2
# The config script auto-detects compression libs. We need to ensure OPENSSL_NO_COMP_ALG is NOT defined.
# Patch the configuration.h template to comment out the NO_COMP_ALG define
sed -i 's/#  define OPENSSL_NO_BROTLI/\/\* DISABLED: #  define OPENSSL_NO_BROTLI \*\//' include/openssl/configuration.h.in
sed -i 's/#  define OPENSSL_NO_BROTLI_DYNAMIC/\/\* DISABLED: #  define OPENSSL_NO_BROTLI_DYNAMIC \*\//' include/openssl/configuration.h.in
sed -i 's/#  define OPENSSL_NO_ZLIB/\/\* DISABLED: #  define OPENSSL_NO_ZLIB \*\//' include/openssl/configuration.h.in
sed -i 's/#  define OPENSSL_NO_ZLIB_DYNAMIC/\/\* DISABLED: #  define OPENSSL_NO_ZLIB_DYNAMIC \*\//' include/openssl/configuration.h.in
sed -i 's/#  define OPENSSL_NO_ZSTD/\/\* DISABLED: #  define OPENSSL_NO_ZSTD \*\//' include/openssl/configuration.h.in
sed -i 's/#  define OPENSSL_NO_ZSTD_DYNAMIC/\/\* DISABLED: #  define OPENSSL_NO_ZSTD_DYNAMIC \*\//' include/openssl/configuration.h.in
# Also disable the NO_COMP_ALG definition in the generated header
sed -i 's/# define OPENSSL_NO_COMP_ALG/\/\* DISABLED: # define OPENSSL_NO_COMP_ALG \*\//' include/openssl/configuration.h.in

echo ""
echo "=== Step 4: Configure OpenSSL ==="
./config shared --prefix=/opt/openssl-new 2>&1 | tail -5

echo ""
echo "=== Step 5: Verify compression is enabled in generated config ==="
grep -E "COMP_ALG|BROTLI|ZLIB|ZSTD" include/openssl/configuration.h | head -10

echo ""
echo "=== Step 6: Build OpenSSL ==="
make -j$(nproc) 2>&1 | tail -3

echo ""
echo "=== Step 7: Install to /opt/openssl-new ==="
make install_sw install_ssldirs 2>&1 | tail -3

echo ""
echo "=== Step 8: Verify cert_comp is available ==="
/opt/openssl-new/bin/openssl s_server -help 2>&1 | grep -i "cert_comp" && echo "SUCCESS: cert_comp available!" || echo "FAILED: cert_comp not found"

echo ""
echo "=== Step 9: Copy new OpenSSL over old one ==="
cp /opt/openssl-new/bin/openssl /opt/oqssa/bin/openssl
cp -r /opt/openssl-new/include/openssl/* /opt/oqssa/include/openssl/
cp /opt/openssl-new/lib64/libssl.* /opt/oqssa/lib64/
cp /opt/openssl-new/lib64/libcrypto.* /opt/oqssa/lib64/
ldconfig

echo ""
echo "=== Step 10: Final verification ==="
/opt/oqssa/bin/openssl version
/opt/oqssa/bin/openssl s_server -help 2>&1 | grep -i "cert_comp" && echo "SUCCESS!" || echo "FAILED"

echo ""
echo "=== DONE ==="
echo "OpenSSL rebuilt with certificate compression (RFC 8879) support"
echo "The matrix should now show different pcap sizes between nocompress and compressed"
