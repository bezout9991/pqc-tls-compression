#!/bin/sh
set -e

# -------------------------------------------------------------------
# perftestClientConcurrent.sh
# Client pour tests de charge concurrente
# Chaque client fait NUM_RUNS handshakes et écrit les durées dans un CSV
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then
    TC_DELAY=0ms
fi

if [ -z "$TC_LOSS" ]; then
    TC_LOSS="0%"
fi

if [ -z "$DOCKER_HOST" ]; then
    DOCKER_HOST="localhost"
fi

if [ -z "$USE_TLS" ]; then
    USE_TLS="true"
fi

if [ -z "$NUM_RUNS" ]; then
    NUM_RUNS=500
fi

if [ -z "$CERT_PATH" ]; then
    export CERT_PATH=/cert
fi

if [ -z "$MUTUAL" ]; then
    MUTUAL="false"
fi

if [ -z "$CLIENT_ID" ]; then
    CLIENT_ID=0
fi

if [ -z "$RESULTS_DIR" ]; then
    RESULTS_DIR=/results
fi

INTERFAZ="lo"

echo "[client-$CLIENT_ID] Applying netem rules to $INTERFAZ..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

# -------------------------------------------------------------------
# KEM and Signature algorithm
# -------------------------------------------------------------------
if [ -z "$KEM_ALG" ]; then
    KEM_ALG=mlkem512
fi
export DEFAULT_GROUPS=$KEM_ALG

if [ -z "$SIG_ALG" ]; then
    export SIG_ALG=mldsa44
fi

echo "[client-$CLIENT_ID] SIG_ALG=$SIG_ALG KEM_ALG=$KEM_ALG PROTOCOL=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

# -------------------------------------------------------------------
# Output CSV file
# -------------------------------------------------------------------
mkdir -p "$RESULTS_DIR"
CSV_FILE="${RESULTS_DIR}/client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.csv"
echo "run_id,duration_ms,success" > "$CSV_FILE"

# -------------------------------------------------------------------
# Execute handshakes
# -------------------------------------------------------------------
i=1
while [ $i -le $NUM_RUNS ]; do
    START_TIME=$(date +%s%3N)

    if [ "$USE_TLS" = "true" ]; then
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(openssl s_connection -connect "$DOCKER_HOST:4433" -new \
                -verify 1 -CAfile "$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" 2>&1)
        else
            OUTPUT=$(openssl s_connection -connect "$DOCKER_HOST:4433" -new \
                -verify 1 -CAfile "$CERT_PATH/CA.crt" 2>&1)
        fi
    else
        if [ -n "${SSL_DIR:-}" ]; then
            mkdir -p "$SSL_DIR"
            KEYLOG_PATH="${SSL_DIR}/sslkeys_client_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.log"
            export SSLKEYLOGFILE="$KEYLOG_PATH"
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

    # Vérifier si le handshake a réussi
    if echo "$OUTPUT" | grep -q "Handshake duration"; then
        HS_DURATION=$(echo "$OUTPUT" | grep "Handshake duration" | grep -oE '[0-9.]+')
        echo "$i,$HS_DURATION,1" >> "$CSV_FILE"
    elif echo "$OUTPUT" | grep -qi "error\|failed\|abort"; then
        echo "$i,$DURATION,0" >> "$CSV_FILE"
    else
        echo "$i,$DURATION,1" >> "$CSV_FILE"
    fi

    i=$((i + 1))
done

echo "[client-$CLIENT_ID] Done. Results in $CSV_FILE"
