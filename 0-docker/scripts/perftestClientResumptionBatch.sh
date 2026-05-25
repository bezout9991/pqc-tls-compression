#!/bin/sh

# -------------------------------------------------------------------
# perftestClientResumptionBatch.sh
# Approche Batch séparés (littérature)
#
# Phase 1 : N full handshakes consécutifs
#           - Chaque handshake établit une nouvelle session TLS
#           - Mesure : médiane, p95, p99 du coût full PQC
#
# Phase 2 : N resumed handshakes consécutifs
#           - Chaque handshake charge la session du dernier full
#           - Mesure : médiane, p95, p99 du coût resumed
#
# Sortie: CSV avec run_id, handshake_type, duration_ms, success
# -------------------------------------------------------------------

if [ -z "$TC_DELAY" ]; then TC_DELAY=0ms; fi
if [ -z "$TC_LOSS" ]; then TC_LOSS="0%"; fi
if [ -z "$DOCKER_HOST" ]; then DOCKER_HOST="localhost"; fi
if [ -z "$USE_TLS" ]; then USE_TLS="true"; fi
if [ -z "$NUM_RUNS" ]; then NUM_RUNS=500; fi         # N par phase
if [ -z "$CERT_PATH" ]; then export CERT_PATH=/cert; fi
if [ -z "$MUTUAL" ]; then MUTUAL="false"; fi
if [ -z "$CLIENT_ID" ]; then CLIENT_ID=0; fi
if [ -z "$RESULTS_DIR" ]; then RESULTS_DIR=/results; fi

INTERFAZ="lo"

echo "[client-$CLIENT_ID] Applying netem to $INTERFAZ..."
tc qdisc add dev "$INTERFAZ" root netem delay $TC_DELAY loss $TC_LOSS 2>/dev/null || true

if [ -z "$KEM_ALG" ]; then KEM_ALG=mlkem768; fi
export DEFAULT_GROUPS=$KEM_ALG

if [ -z "$SIG_ALG" ]; then export SIG_ALG=mldsa65; fi

echo "[client-$CLIENT_ID] SIG=$SIG_ALG KEM=$KEM_ALG PROTO=$([ "$USE_TLS" = "true" ] && echo TLS || echo QUIC)"

# Session file (TLS uniquement)
SESSION_FILE="/tmp/session_${CLIENT_ID}.pem"

# -------------------------------------------------------------------
# Phase 1 : N Full Handshakes
# -------------------------------------------------------------------
echo "[client-$CLIENT_ID] Phase 1: $NUM_RUNS full handshakes..."

mkdir -p "$RESULTS_DIR"
CSV_FILE="${RESULTS_DIR}/resumption_${CLIENT_ID}_${SIG_ALG}_${KEM_ALG}.csv"
echo "run_id,handshake_type,duration_ms,success" > "$CSV_FILE"

i=1
while [ $i -le $NUM_RUNS ]; do
    START_TIME=$(date +%s%3N)
    HS_TYPE="full"

    if [ "$USE_TLS" = "true" ]; then
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                -CAfile "$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                -sess_out "$SESSION_FILE" 2>&1)
        else
            OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                -CAfile "$CERT_PATH/CA.crt" \
                -sess_out "$SESSION_FILE" 2>&1)
        fi
    else
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

    if echo "$OUTPUT" | grep -q "Handshake duration"; then
        HS_DURATION=$(echo "$OUTPUT" | grep "Handshake duration" | grep -oE '[0-9.]+')
        echo "$i,$HS_TYPE,$HS_DURATION,1" >> "$CSV_FILE"
    elif echo "$OUTPUT" | grep -qi "error\|failed\|abort"; then
        echo "$i,$HS_TYPE,$DURATION,0" >> "$CSV_FILE"
    else
        echo "$i,$HS_TYPE,$DURATION,1" >> "$CSV_FILE"
    fi

    i=$((i + 1))
done

echo "[client-$CLIENT_ID] Phase 1 done. Last session saved: $SESSION_FILE"

# -------------------------------------------------------------------
# Phase 2 : N Resumed Handshakes
# -------------------------------------------------------------------
echo "[client-$CLIENT_ID] Phase 2: $NUM_RUNS resumed handshakes..."

j=1
while [ $j -le $NUM_RUNS ]; do
    RUN_ID=$((NUM_RUNS + j))
    START_TIME=$(date +%s%3N)
    HS_TYPE="resumed"

    if [ "$USE_TLS" = "true" ]; then
        if [ -f "$SESSION_FILE" ]; then
            if [ "$MUTUAL" = "true" ]; then
                OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                    -sess_in "$SESSION_FILE" -sess_out "$SESSION_FILE" 2>&1)
            else
                OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -sess_in "$SESSION_FILE" -sess_out "$SESSION_FILE" 2>&1)
            fi
        else
            # Fallback: pas de session disponible → full handshake
            HS_TYPE="full"
            if [ "$MUTUAL" = "true" ]; then
                OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                    -sess_out "$SESSION_FILE" 2>&1)
            else
                OUTPUT=$(echo | openssl s_client -connect "$DOCKER_HOST:4433" \
                    -curves "$KEM_ALG" -sigalgs "$SIG_ALG" \
                    -CAfile "$CERT_PATH/CA.crt" \
                    -sess_out "$SESSION_FILE" 2>&1)
            fi
        fi
    else
        # QUIC resumption via -resumption:1
        if [ "$MUTUAL" = "true" ]; then
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -cert "$CERT_PATH/user.crt" -key "$CERT_PATH/user.key" \
                -resumption:1 2>&1)
        else
            OUTPUT=$(quics_connection -groups:"$KEM_ALG" -target:"$DOCKER_HOST" \
                -CAfile:"$CERT_PATH/CA.crt" \
                -resumption:1 2>&1)
        fi
    fi

    END_TIME=$(date +%s%3N)
    DURATION=$((END_TIME - START_TIME))

    if echo "$OUTPUT" | grep -q "Handshake duration"; then
        HS_DURATION=$(echo "$OUTPUT" | grep "Handshake duration" | grep -oE '[0-9.]+')
        echo "$RUN_ID,$HS_TYPE,$HS_DURATION,1" >> "$CSV_FILE"
    elif echo "$OUTPUT" | grep -qi "error\|failed\|abort"; then
        echo "$RUN_ID,$HS_TYPE,$DURATION,0" >> "$CSV_FILE"
    else
        echo "$RUN_ID,$HS_TYPE,$DURATION,1" >> "$CSV_FILE"
    fi

    j=$((j + 1))
done

echo "[client-$CLIENT_ID] Done. Full=$NUM_RUNS Resumed=$NUM_RUNS. Results: $CSV_FILE"
