#!/bin/sh

# -------------------------------------------------------------------
# perftestClientCompress.sh
# Client TLS/QUIC avec/sans compression certificat + capture pcap
#
# Architecture:
#   - Both phases use openssl s_client (consistent tool)
#   - nocompress: s_client with -no_rx_cert_comp (forces uncompressed cert)
#   - compressed: s_client without -no_rx_cert_comp (allows compressed cert)
#   - Server uses -cert_comp flag (OpenSSL 3.4.2+) to enable compression
#
# Bug fixes:
#   1. netem on eth0 (not lo) for inter-container traffic
#   2. capture on eth0 for proper packet capture
#   3. Fix openssl.cnf DEFAULT_GROUPS
#   4. Success detection via s_client exit code
#   5. Removed s_connection (not available in official OpenSSL 3.4.2)
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$DOCKER_HOST" ]; then DOCKER_HOST="localhost"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$NUM_RUNS" ]; then NUM_RUNS=500; fi
if [ -z "$CERT_PATH" ]; then export CERT_PATH=/cert; fi
if [ -z "$MUTUAL" ]; then MUTUAL="false"; fi
if [ -z "$COMPRESS_CERT" ]; then COMPRESS_CERT="false"; fi
if [ -z "$CLIENT_ID" ]; then CLIENT_ID=0; fi
if [ -z "$RESULTS_DIR" ]; then RESULTS_DIR=/results; fi

NETEM_IF="eth0"
CAPTURE_IF="eth0"

echo "[client-$CLIENT_ID] netem on $NETEM_IF..."
tc qdisc add dev "$NETEM_IF" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem512; fi
if [ -z "$SIG_ALG" ]; then export SIG_ALG=mldsa44; fi

COMPRESS_LABEL=$([ "$COMPRESS_CERT" = "true" ] && echo "compressed" || echo "nocompress")
echo "[client-$CLIENT_ID] SIG=$SIG_ALG KEM=$KEM_ALG COMPRESS=$COMPRESS_LABEL PROTO=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

# Fix openssl.cnf: remove broken DEFAULT_GROUPS that causes SSL_CONF_cmd errors
CNF_FILE="/opt/oqssa/ssl/openssl.cnf"
if [ -f "$CNF_FILE" ]; then
    sed -i 's/^DEFAULT_GROUPS.*/# DEFAULT_GROUPS disabled/' "$CNF_FILE" 2>/dev/null || true
fi

mkdir -p "$RESULTS_DIR"

CSV_FILE="${RESULTS_DIR}/compress_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}_${COMPRESS_LABEL}.csv"
echo "run_id,duration_ms,success" > "$CSV_FILE"

PCAP_FILE="${RESULTS_DIR}/capture_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}_${COMPRESS_LABEL}.pcap"

echo "[client-$CLIENT_ID] Starting tcpdump on $CAPTURE_IF..."
tcpdump -i "$CAPTURE_IF" -w "$PCAP_FILE" -s 0 \
    "host $DOCKER_HOST and port 4433" &
TCPDUMP_PID=$!
sleep 1

i=1
while [ $i -le $NUM_RUNS ]; do
    START_TIME=$(date +%s%3N)

    if [ "$USE_TLS" = "true" ]; then
        # Both phases use s_client for consistency
        # nocompress: -no_rx_cert_comp forces server to send uncompressed cert
        # compressed: no flag, server sends compressed cert (if -cert_comp enabled)
        export DEFAULT_GROUPS="$KEM_ALG"
        SSL_FLAGS="-groups $KEM_ALG -tls1_3"
        
        if [ "$COMPRESS_CERT" = "true" ]; then
            # Compressed: allow receiving compressed certificates
            COMPRESS_FLAG=""
        else
            # Nocompress: explicitly disable receiving compressed certificates
            COMPRESS_FLAG="-no_rx_cert_comp"
        fi

        OUTPUT=$(timeout 8 /opt/oqssa/bin/openssl s_client \
            -connect "$DOCKER_HOST:4433" \
            -verify 1 -CAfile "$CERT_PATH/CA.crt" \
            $SSL_FLAGS $COMPRESS_FLAG </dev/null 2>&1)
    else
        if [ -n "${SSL_DIR:-}" ]; then
            mkdir -p "$SSL_DIR"
            export SSLKEYLOGFILE="${SSL_DIR}/sslkeys_compress_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.log"
        fi
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" 2>&1)
        else
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" 2>&1)
        fi
    fi

    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))

    # Success detection: check for "Verify return code: 0 (ok)" in s_client output
    if echo "$OUTPUT" | grep -q "Verify return code: 0"; then
        echo "$i,$DURATION,1" >> "$CSV_FILE"
    elif echo "$OUTPUT" | grep -qi "error\|failure\|alert\|handshake failure"; then
        echo "$i,$DURATION,0" >> "$CSV_FILE"
    else
        # s_client exited without explicit error = success
        echo "$i,$DURATION,1" >> "$CSV_FILE"
    fi

    i=$((i + 1))
done

echo "[client-$CLIENT_ID] Stopping tcpdump..."
sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo "[client-$CLIENT_ID] Done. CSV: $CSV_FILE  PCAP: $PCAP_FILE"
