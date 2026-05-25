#!/bin/bash
set -euo pipefail

###############################################################################
#  Launcherv3_resumption.sh
#  Full Handshake vs Resumed Handshake — TLS/QUIC
#
#  Usage: ./Launcherv3_resumption.sh [tls|quic] [none|simple|stable|unstable] [loss-percent] [delay-ms]
#
#  Teste:
#    ML-DSA65 + ML-KEM768
#    ML-DSA87 + HQC256
###############################################################################

PROTOCOL=${1:-tls}
NETWORK_PROFILE=${2:-none}
LOSS_PERC=${3:-0}
DELAY_MS=${4:-0}

USAGE="Usage: $0 [tls|quic] [none|simple|stable|unstable] [loss-percent] [delay-ms]"

NETIF="eth0"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT="cliente"
os=""

RUNS_PER_TEST=101   # 1 full + 100 resumed

###############################################################################
#  Input Validation
###############################################################################
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "$USAGE"; exit 1
fi
if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile."; echo "$USAGE"; exit 1
fi
if ! [[ "$LOSS_PERC" =~ ^[0-9]+$ ]] || (( LOSS_PERC < 0 || LOSS_PERC > 100 )); then
    echo "Invalid loss-percent."; echo "$USAGE"; exit 1
fi
if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]]; then
    echo "Invalid delay-ms."; echo "$USAGE"; exit 1
fi

###############################################################################
#  CONFIGURATION
###############################################################################
USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)

# Paires (signature, KEM) à tester
declare -A PAIRS
PAIRS=(
    ["mldsa65"]="mlkem768"
    ["mldsa87"]="hqc256"
)

STABLE_GEMODEL=(10 50 70 10)
UNSTABLE_GEMODEL=(20 40 90 20)

RESULTS_HOST_DIR="/home/bruno/mldsa-mlkem-tls-quic-performance/results"
mkdir -p "$RESULTS_HOST_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="${PROTOCOL}_${NETWORK_PROFILE}_l${LOSS_PERC}_d${DELAY_MS}_${TIMESTAMP}"
RESULTS_RUN_DIR="${RESULTS_HOST_DIR}/${RUN_ID}"
mkdir -p "$RESULTS_RUN_DIR"

echo "=============================================================================="
echo "  FULL vs RESUMED HANDSHAKE"
echo "=============================================================================="
echo "  Protocol:        $PROTOCOL"
echo "  Runs/test:       $RUNS_PER_TEST (1 full + 100 resumed)"
echo "  Network Profile: $NETWORK_PROFILE"
echo "  Loss %:          $LOSS_PERC"
echo "  Delay (ms):      $DELAY_MS"
echo "  Pairs:           ${!PAIRS[*]}"
echo "  Results Dir:     $RESULTS_RUN_DIR"
echo "=============================================================================="

###############################################################################
#  Functions
###############################################################################
detect_platform() {
    os="$(uname -s)"
    case "$os" in
        Linux)  echo "Running on Linux" ;;
        Darwin) echo "Running on macOS" ;;
        *)      echo "Running on: $os" ;;
    esac
}

cleaning(){
    docker kill $OQS_SERVER &>/dev/null || true
    docker kill $OQS_CLIENT &>/dev/null || true
    sleep 1
    docker container prune -f || true
    docker volume rm cert || true
    docker network rm localNet || true
    sleep 1
}

###############################################################################
#  MAIN
###############################################################################
detect_platform
cleaning

if ! docker network inspect localNet >/dev/null 2>&1; then
    docker network create localNet
fi
if ! docker volume inspect cert >/dev/null 2>&1; then
    docker volume create cert
fi

for SIG_ALG in "${!PAIRS[@]}"; do
    KEM="${PAIRS[$SIG_ALG]}"

    echo ""
    echo "--------------------------------------------------------------------------------"
    echo "  Signature: $SIG_ALG  |  KEM: $KEM"
    echo "--------------------------------------------------------------------------------"

    # Nettoyer
    docker rm -f $OQS_SERVER $OQS_CLIENT &>/dev/null || true

    # Générer certificats
    echo " ==> Creating certificates..."
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh

    # ── Démarrer le serveur ─────────────────────────────────────────────
    echo "[SERVER] Starting..."
    docker run --cap-add=NET_ADMIN \
        --name $OQS_SERVER \
        --network localNet \
        -v cert:/cert \
        -e TC_DELAY=0ms \
        -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG=$KEM \
        -e SIG_ALG=$SIG_ALG \
        -e USE_TLS=$USE_TLS \
        -e MUTUAL=false \
        -d $IMAGE perftestServerTlsQuic.sh

    sleep 3

    SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER)
    echo "[SERVER] IP: $SERVER_IP"

    # ── Appliquer les dégradations réseau ───────────────────────────────
    PUMBA_PIDS=()
    case "$NETWORK_PROFILE" in
        simple)
            if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                echo "[NET] tc netem: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
                sleep 1
                docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                    delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
            fi
            ;;
        stable|unstable)
            args=("${STABLE_GEMODEL[@]}")
            [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
            echo "[NET] ${NETWORK_PROFILE} GE (pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
            /usr/local/bin/pumba netem --duration 1h --interface $NETIF \
                loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS+=($!)
            ;;
    esac
    sleep 2

    # ── Lancer le client ────────────────────────────────────────────────
    echo "[CLIENT] Starting resumption test..."
    GLOBAL_START=$(date +%s%3N)

    docker run --cap-add=NET_ADMIN \
        --network localNet \
        --name $OQS_CLIENT \
        -v cert:/cert \
        -v "${RESULTS_RUN_DIR}:/results" \
        -e DOCKER_HOST=$SERVER_IP \
        -e TC_DELAY=0ms \
        -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG=$KEM \
        -e SIG_ALG=$SIG_ALG \
        -e USE_TLS=$USE_TLS \
        -e NUM_RUNS=$RUNS_PER_TEST \
        -e MUTUAL=false \
        -e CLIENT_ID=1 \
        -e RESULTS_DIR=/results \
        $IMAGE ./perftestClientResumption.sh

    GLOBAL_END=$(date +%s%3N)
    TOTAL_TIME=$((GLOBAL_END - GLOBAL_START))
    echo "[CLIENT] Done in ${TOTAL_TIME} ms"

    # ── Sauvegarder les logs ────────────────────────────────────────────
    LOG_FILE="${RESULTS_RUN_DIR}/log_${SIG_ALG}_${KEM}.log"
    docker logs $OQS_CLIENT 2>&1 > "$LOG_FILE" || true

    # ── Métadonnées ─────────────────────────────────────────────────────
    META_FILE="${RESULTS_RUN_DIR}/metadata_${SIG_ALG}_${KEM}.txt"
    cat > "$META_FILE" <<EOF
protocol=$PROTOCOL
sig_alg=$SIG_ALG
kem_alg=$KEM
runs=$RUNS_PER_TEST
network_profile=$NETWORK_PROFILE
loss_percent=$LOSS_PERC
delay_ms=$DELAY_MS
total_time_ms=$TOTAL_TIME
timestamp=$TIMESTAMP
EOF

    # ── Nettoyer ────────────────────────────────────────────────────────
    docker rm -f $OQS_CLIENT &>/dev/null || true
    docker kill $OQS_SERVER &>/dev/null || true
    docker rm -f $OQS_SERVER &>/dev/null || true
    for pid in "${PUMBA_PIDS[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done

    echo "  ✅ Done: $SIG_ALG × $KEM"
done

cleaning

echo ""
echo "=============================================================================="
echo "  FULL vs RESUMED TESTS COMPLETED"
echo "  Results: $RESULTS_RUN_DIR"
echo "=============================================================================="
