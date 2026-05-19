#!/bin/bash
set -euo pipefail

###############################################################################
#  Launcherv3_concurrent.sh
#  Tests de charge concurrente TLS/QUIC post-quantique
#
#  Usage: ./Launcherv3_concurrent.sh [tls|quic] [num_clients] [none|simple|stable|unstable] [loss-percent] [delay-ms]
#
#  Exemples:
#    ./Launcherv3_concurrent.sh tls 10 none 0 0        # 10 clients, idéal
#    ./Launcherv3_concurrent.sh tls 50 simple 2 35     # 50 clients, 35ms/2%
#    ./Launcherv3_concurrent.sh quic 100 simple 10 200 # 100 clients, 200ms/10%
#    ./Launcherv3_concurrent.sh tls 500 stable 0 0     # 500 clients, GE stable
###############################################################################

PROTOCOL=${1:-tls}
NUM_CLIENTS=${2:-10}
NETWORK_PROFILE=${3:-none}
LOSS_PERC=${4:-0}
DELAY_MS=${5:-0}

USAGE="Usage: $0 [tls|quic] [num_clients] [none|simple|stable|unstable] [loss-percent] [delay-ms]"

NETIF="eth0"
IMAGE=uma-tls-quic-pq-34
OQS_SERVER="servidor"
OQS_CLIENT_PREFIX="cliente"
os=""

# Chaque client fait 500 handshakes
RUNS_PER_CLIENT=500

###############################################################################
#  Input Validation
###############################################################################
if [[ "$PROTOCOL" != "tls" && "$PROTOCOL" != "quic" ]]; then
    echo "$USAGE"
    exit 1
fi

if ! [[ "$NUM_CLIENTS" =~ ^[0-9]+$ ]] || (( NUM_CLIENTS < 1 )); then
    echo "Invalid num_clients: must be a positive integer."
    echo "$USAGE"
    exit 1
fi

if [[ "$NETWORK_PROFILE" != "none" && "$NETWORK_PROFILE" != "simple" && "$NETWORK_PROFILE" != "stable" && "$NETWORK_PROFILE" != "unstable" ]]; then
    echo "Invalid network profile: must be 'none', 'simple', 'stable', or 'unstable'."
    echo "$USAGE"
    exit 1
fi

if ! [[ "$LOSS_PERC" =~ ^[0-9]+$ ]] || (( LOSS_PERC < 0 || LOSS_PERC > 100 )); then
    echo "Invalid loss-percent: must be an integer between 0 and 100."
    echo "$USAGE"
    exit 1
fi

if ! [[ "$DELAY_MS" =~ ^[0-9]+$ ]] || (( DELAY_MS < 0 )); then
    echo "Invalid delay-ms: must be a non-negative integer."
    echo "$USAGE"
    exit 1
fi

###############################################################################
#  CONFIGURATION
###############################################################################
USE_TLS=$([[ "$PROTOCOL" == "tls" ]] && echo true || echo false)

# Signatures + KEMs pour les tests concurrents
# Focus: ML-DSA65 + ML-KEM768 (comme demandé par le Prof)
SUPPORTED_SIG_ALGS=("mldsa65")
KEMS=("mlkem768")

# Profils Gilbert-Elliott
STABLE_GEMODEL=(10 50 70 10)
UNSTABLE_GEMODEL=(20 40 90 20)

# Répertoire de résultats sur l'hôte
RESULTS_HOST_DIR="/home/bruno/mldsa-mlkem-tls-quic-performance/results"
mkdir -p "$RESULTS_HOST_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="${PROTOCOL}_c${NUM_CLIENTS}_${NETWORK_PROFILE}_l${LOSS_PERC}_d${DELAY_MS}_${TIMESTAMP}"
RESULTS_RUN_DIR="${RESULTS_HOST_DIR}/${RUN_ID}"
mkdir -p "$RESULTS_RUN_DIR"

echo "=============================================================================="
echo "  CONCURRENT LOAD TEST"
echo "=============================================================================="
echo "  Protocol:        $PROTOCOL"
echo "  Num Clients:     $NUM_CLIENTS"
echo "  Runs/Client:     $RUNS_PER_CLIENT"
echo "  Total Handshakes: $((NUM_CLIENTS * RUNS_PER_CLIENT))"
echo "  Network Profile: $NETWORK_PROFILE"
echo "  Loss %:          $LOSS_PERC"
echo "  Delay (ms):      $DELAY_MS"
echo "  Signatures:      ${SUPPORTED_SIG_ALGS[*]}"
echo "  KEMs:            ${KEMS[*]}"
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
    echo "[CLEAN] Stopping all containers..."
    docker kill $OQS_SERVER &>/dev/null || true
    for ((c=1; c<=NUM_CLIENTS; c++)); do
        docker kill "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
    done
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

# Créer réseau et volume
if ! docker network inspect localNet >/dev/null 2>&1; then
    docker network create localNet
    echo "[NET] Network localNet created."
fi

if ! docker volume inspect cert >/dev/null 2>&1; then
    docker volume create cert
    echo "[VOL] Volume cert created."
fi

for SIG_ALG in "${SUPPORTED_SIG_ALGS[@]}"; do
    echo ""
    echo " ==> Signature: $SIG_ALG"

    # Générer certificats
    echo " ==> Creating certificates..."
    docker run --rm -v cert:/cert -e CERT_PATH=/cert/ -e SIG_ALG=$SIG_ALG -i "$IMAGE" doCert.sh

    for KEM in "${KEMS[@]}"; do
        echo ""
        echo "--------------------------------------------------------------------------------"
        echo "  KEM: $KEM  |  Clients: $NUM_CLIENTS  |  Profile: $NETWORK_PROFILE"
        echo "--------------------------------------------------------------------------------"

        # Nettoyer les anciens conteneurs
        docker rm -f $OQS_SERVER &>/dev/null || true
        for ((c=1; c<=NUM_CLIENTS; c++)); do
            docker rm -f "${OQS_CLIENT_PREFIX}${c}" &>/dev/null || true
        done

        # ── Démarrer le serveur ─────────────────────────────────────────────
        echo "[SERVER] Starting server..."
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

        # Récupérer l'IP du serveur
        SERVER_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $OQS_SERVER)
        echo "[SERVER] IP: $SERVER_IP"

        # ── Appliquer les dégradations réseau au serveur ────────────────────
        PUMBA_PIDS=()
        case "$NETWORK_PROFILE" in
            simple)
                if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                    echo "[NET] Applying tc netem on server: delay=${DELAY_MS}ms loss=${LOSS_PERC}%"
                    sleep 1
                    docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                        delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
                fi
                ;;
            stable|unstable)
                args=("${STABLE_GEMODEL[@]}")
                [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
                echo "[NET] Applying ${NETWORK_PROFILE} GE model (pg${args[0]} pb${args[1]} h${args[2]} k${args[3]})"
                /usr/local/bin/pumba netem --duration 1h --interface $NETIF \
                    loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                    --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS+=($!)
                ;;
        esac

        sleep 2

        # ── Lancer tous les clients simultanément ───────────────────────────
        echo "[CLIENTS] Launching $NUM_CLIENTS clients simultaneously..."
        GLOBAL_START=$(date +%s%3N)

        CLIENT_IDS=()
        for ((c=1; c<=NUM_CLIENTS; c++)); do
            CLIENT_NAME="${OQS_CLIENT_PREFIX}${c}"

            docker run --cap-add=NET_ADMIN \
                --network localNet \
                --name "$CLIENT_NAME" \
                -v cert:/cert \
                -v "${RESULTS_RUN_DIR}:/results" \
                -e DOCKER_HOST=$SERVER_IP \
                -e TC_DELAY=0ms \
                -e TC_LOSS=0% \
                -e CERT_PATH=/cert/ \
                -e KEM_ALG=$KEM \
                -e SIG_ALG=$SIG_ALG \
                -e USE_TLS=$USE_TLS \
                -e NUM_RUNS=$RUNS_PER_CLIENT \
                -e MUTUAL=false \
                -e CLIENT_ID=$c \
                -e RESULTS_DIR=/results \
                -d $IMAGE ./perftestClientConcurrent.sh

            CLIENT_IDS+=("$CLIENT_NAME")
        done

        echo "[CLIENTS] All $NUM_CLIENTS clients launched. Waiting for completion..."

        # Attendre que tous les clients terminent
        for CLIENT_NAME in "${CLIENT_IDS[@]}"; do
            docker wait "$CLIENT_NAME" > /dev/null
        done

        GLOBAL_END=$(date +%s%3N)
        TOTAL_TIME=$((GLOBAL_END - GLOBAL_START))
        echo "[CLIENTS] All clients finished in ${TOTAL_TIME} ms"

        # ── Collecter les logs des clients ──────────────────────────────────
        echo "[LOGS] Collecting client logs..."
        LOG_FILE="${RESULTS_RUN_DIR}/all_clients_${SIG_ALG}_${KEM}.log"
        for CLIENT_NAME in "${CLIENT_IDS[@]}"; do
            echo "--- ${CLIENT_NAME} ---" >> "$LOG_FILE"
            docker logs "$CLIENT_NAME" 2>&1 >> "$LOG_FILE" || true
        done

        # ── Métadonnées du test ─────────────────────────────────────────────
        META_FILE="${RESULTS_RUN_DIR}/metadata_${SIG_ALG}_${KEM}.txt"
        cat > "$META_FILE" <<EOF
protocol=$PROTOCOL
sig_alg=$SIG_ALG
kem_alg=$KEM
num_clients=$NUM_CLIENTS
runs_per_client=$RUNS_PER_CLIENT
total_handshakes=$((NUM_CLIENTS * RUNS_PER_CLIENT))
network_profile=$NETWORK_PROFILE
loss_percent=$LOSS_PERC
delay_ms=$DELAY_MS
total_time_ms=$TOTAL_TIME
timestamp=$TIMESTAMP
EOF

        # ── Nettoyer les clients ────────────────────────────────────────────
        echo "[CLEAN] Removing client containers..."
        for CLIENT_NAME in "${CLIENT_IDS[@]}"; do
            docker rm -f "$CLIENT_NAME" &>/dev/null || true
        done

        # ── Arrêter le serveur et les dégradations ──────────────────────────
        echo "[CLEAN] Stopping server and impairments..."
        docker kill $OQS_SERVER &>/dev/null || true
        docker rm -f $OQS_SERVER &>/dev/null || true
        for pid in "${PUMBA_PIDS[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done

        echo "  ✅ Done: $SIG_ALG × $KEM ($NUM_CLIENTS clients)"
    done
done

# Nettoyage final
cleaning

echo ""
echo "=============================================================================="
echo "  CONCURRENT TESTS COMPLETED"
echo "  Results: $RESULTS_RUN_DIR"
echo "=============================================================================="
