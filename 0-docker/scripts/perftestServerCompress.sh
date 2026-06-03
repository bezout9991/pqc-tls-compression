#!/bin/sh
set -e

# -------------------------------------------------------------------
# perftestServerCompress.sh
# Serveur TLS/QUIC avec option compression certificat (RFC 8879)
#
# OpenSSL 3.4.2 uses -cert_comp to pre-compress server certificates
# -no_tx_cert_comp explicitly disables sending compressed certificates
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$CERT_PATH" ]; then export CERT_PATH=/cert; fi
if [ -z "$COMPRESS_CERT" ]; then COMPRESS_CERT="false"; fi

INTERFAZ="eth0"
echo "[SERVER] netem on $INTERFAZ..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem512; fi
if [ -z "$SIG_ALG" ]; then export SIG_ALG=mldsa44; fi

echo "[SERVER] SIG=$SIG_ALG KEM=$KEM_ALG COMPRESS=$COMPRESS_CERT PROTO=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

# Export DEFAULT_GROUPS to avoid OpenSSL config errors
export DEFAULT_GROUPS="$KEM_ALG"

if [ "$USE_TLS" = "true" ]; then
    if [ "$COMPRESS_CERT" = "true" ]; then
        echo "[SERVER] Starting TLS with certificate compression (RFC 8879)..."
        /opt/oqssa/bin/openssl s_server \
            -cert "$CERT_PATH/server.crt" -key "$CERT_PATH/server.key" \
            -groups "$KEM_ALG" -www -tls1_3 -accept :4433 -cert_comp
    else
        echo "[SERVER] Starting TLS without certificate compression..."
        # -no_tx_cert_comp explicitly disables sending compressed certificates
        /opt/oqssa/bin/openssl s_server \
            -cert "$CERT_PATH/server.crt" -key "$CERT_PATH/server.key" \
            -groups "$KEM_ALG" -www -tls1_3 -accept :4433 -no_tx_cert_comp
    fi
else
    echo "[SERVER] Starting QUIC server..."
    quics_server -groups:"$KEM_ALG" \
        -cert_file:"$CERT_PATH/server.crt" -key_file:"$CERT_PATH/server.key"
fi
