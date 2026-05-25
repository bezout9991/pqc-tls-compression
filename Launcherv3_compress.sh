#!/bin/bash
set -euo pipefail

###############################################################################
#  Launcherv3_compress.sh
#  Certificate Compression (RFC 8879) — with vs without
#
#  Approche littérature-friendly :
#    Pour chaque (protocole, scénario, paire) :
#      - 500 handshakes SANS compression
#      - 500 handshakes AVEC compression
#
#  Usage: ./Launcherv3_compress.sh [tls|quic] [none|simple|stable|unstable] [loss-percent] [delay-ms]
#
#  Paires testées :
#    ML-DSA44 + ML-KEM512
#    ML-DSA65 + ML-KEM768
#    ML-DSA87 + ML-KEM1024
#    ML-DSA65 + HQC192
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

RUNS_PER_CONDITION=500

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
    ["mldsa44"]="mlkem512"
    ["mldsa65"]="mlkem768"
    ["mldsa87"]="mlkem1024"
    ["mldsa65_hqc"]="hqc192"
)

STABLE_GEMODEL=(10 50 70 10)
UNSTABLE_GEMODEL=(20 40 90 20)
PUMBA_PIDS=()

RESULTS_HOST_DIR="/home/bruno/mldsa-mlkem-tls-quic-performance/results"
mkdir -p "$RESULTS_HOST_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="${PROTOCOL}_${NETWORK_PROFILE}_l${LOSS_PERC}_d${DELAY_MS}_${TIMESTAMP}"
RESULTS_RUN_DIR="${RESULTS_HOST_DIR}/${RUN_ID}"
mkdir -p "$RESULTS_RUN_DIR"

echo ""
echo "================================================================================"
echo "  CERTIFICATE COMPRESSION TEST"
echo "  Protocol: $PROTOCOL   |   Profile: $NETWORK_PROFILE l${LOSS_PERC} d${DELAY_MS}"
echo "================================================================================"
echo "  Runs per condition: $RUNS_PER_CONDITION (nocompress + compressed)"
echo "  Results directory : $RESULTS_RUN_DIR"
echo "================================================================================"

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
    docker container prune -f &>/dev/null || true
    docker volume rm cert &>/dev/null || true
    docker network rm localNet &>/dev/null || true
    sleep 1
}

run_single_test() {
    local SIG_ALG=$1
    local KEM=$2
    local COMPRESS=$3
    local COMPRESS_LABEL=$4
    local RESULTS_SUBDIR=$5

    echo ""
    echo "  ── Phase: $COMPRESS_LABEL (500 runs) ───────────────────────────"

    docker rm -f $OQS_CLIENT &>/dev/null || true

    # ── Démarrer le client ────────────────────────────────────────────
    echo "  [CLIENT] Starting $COMPRESS_LABEL..."
    GLOBAL_START=$(date +%s%3N)

    docker run --cap-add=NET_ADMIN \
        --network localNet \
        --name $OQS_CLIENT \
        -v cert:/cert \
        -v "${RESULTS_SUBDIR}:/results" \
        -v "/home/bruno/mldsa-mlkem-tls-quic-performance/0-docker/scripts/perftestClientCompress.sh:/opt/oqssa/bin/perftestClientCompress.sh:ro" \
        -e DOCKER_HOST=$SERVER_IP \
        -e TC_DELAY=0ms \
        -e TC_LOSS=0% \
        -e CERT_PATH=/cert/ \
        -e KEM_ALG=$KEM \
        -e SIG_ALG=$SIG_ALG \
        -e USE_TLS=$USE_TLS \
        -e NUM_RUNS=$RUNS_PER_CONDITION \
        -e MUTUAL=false \
        -e COMPRESS_CERT=$COMPRESS \
        -e CLIENT_ID=$([ "$COMPRESS" = "true" ] && echo 2 || echo 1) \
        -e RESULTS_DIR=/results \
        $IMAGE ./perftestClientCompress.sh
    CONTAINER_EXIT=$?

    GLOBAL_END=$(date +%s%3N)
    TOTAL_TIME=$((GLOBAL_END - GLOBAL_START))
    echo "  [CLIENT] Done in ${TOTAL_TIME} ms"

    # Logs (on met le log au niveau du sous-dossier pour plus de clarté)
    LOG_FILE="${RESULTS_SUBDIR}/log_${SIG_ALG}_${KEM}_${COMPRESS_LABEL}.log"
    docker logs $OQS_CLIENT 2>&1 > "$LOG_FILE" || true

    docker rm -f $OQS_CLIENT &>/dev/null || true
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

for SIG_ALG_KEY in "${!PAIRS[@]}"; do
    KEM="${PAIRS[$SIG_ALG_KEY]}"

    # Extraire le vrai SIG_ALG (sans suffixe _hqc)
    SIG_ALG="${SIG_ALG_KEY%_hqc}"

    echo ""
    echo "================================================================================"
    echo "  Pair: $SIG_ALG + $KEM"
    echo "================================================================================"

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
        -e COMPRESS_CERT=false \
        -d $IMAGE perftestServerCompress.sh

    sleep 3

    # Robust IP wait for user-defined network (localNet)
    for i in {1..20}; do
        SERVER_IP=$(docker inspect -f '{{ (index .NetworkSettings.Networks "localNet").IPAddress }}' $OQS_SERVER 2>/dev/null || true)
        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        fi
        echo "  [SERVER] Waiting for valid IP on localNet... ($i/20)"
        sleep 1
    done

    if ! [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "  [ERROR] Could not get a valid server IP after restart. Got: '$SERVER_IP'"
        exit 1
    fi

    echo "  [SERVER] New IP after restart: $SERVER_IP"

    # Ré-appliquer les conditions réseau
    case "$NETWORK_PROFILE" in
        simple)
            if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                sleep 1
                docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                    delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
            fi
            ;;
        stable|unstable)
            args=("${STABLE_GEMODEL[@]}")
            [[ "$NETWORK_PROFILE" == "unstable" ]] && args=("${UNSTABLE_GEMODEL[@]}")
            /usr/local/bin/pumba netem --duration 1h --interface $NETIF \
                loss-gemodel --pg "${args[0]}" --pb "${args[1]}" \
                --one-h "${args[2]}" --one-k "${args[3]}" "$OQS_SERVER" & PUMBA_PIDS+=($!)
            ;;
    esac
    sleep 2

    # Create clean subdirectories for each condition (we keep the original file naming inside)
    NOCOMPRESS_DIR="${RESULTS_RUN_DIR}/nocompress"
    COMPRESSED_DIR="${RESULTS_RUN_DIR}/compressed"
    mkdir -p "$NOCOMPRESS_DIR" "$COMPRESSED_DIR"

    echo "      nocompress"
    run_single_test "$SIG_ALG" "$KEM" "false" "nocompress" "$NOCOMPRESS_DIR"

    # Restart server with COMPRESS=true so the second phase actually uses RFC 8879 on the server side
    echo "      [restart server for compression]"
    docker kill $OQS_SERVER &>/dev/null || true
    docker rm -f $OQS_SERVER &>/dev/null || true

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
        -e COMPRESS_CERT=true \
        -d $IMAGE perftestServerCompress.sh

    # Robust IP re-acquisition after the compression restart
    SERVER_IP=""
    for i in {1..20}; do
        SERVER_IP=$(docker inspect -f '{{ (index .NetworkSettings.Networks "localNet").IPAddress }}' $OQS_SERVER 2>/dev/null || true)
        if [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            break
        fi
        echo "  [SERVER] Waiting for valid IP on localNet after compress restart... ($i/20)"
        sleep 1
    done
    if ! [[ "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "  [ERROR] Could not get valid server IP after compress restart. Got: '$SERVER_IP'"
        exit 1
    fi
    echo "  [SERVER] New IP after compress restart: $SERVER_IP"

    # Re-apply network conditions (for none/simple profiles)
    case "$NETWORK_PROFILE" in
        simple)
            if [[ "$LOSS_PERC" != "0" || "$DELAY_MS" != "0" ]]; then
                sleep 1
                docker exec $OQS_SERVER tc qdisc add dev $NETIF root netem \
                    delay ${DELAY_MS}ms loss ${LOSS_PERC}% || true
            fi
            ;;
        stable|unstable)
            # pumba re-launch would be needed here; for Ideal "none" we skip
            ;;
    esac
    sleep 2

    echo "      compressed"
    run_single_test "$SIG_ALG" "$KEM" "true" "compressed" "$COMPRESSED_DIR"

    # ── Métadonnées ─────────────────────────────────────────────────────
    META_FILE="${RESULTS_RUN_DIR}/metadata_${SIG_ALG}_${KEM}.txt"
    cat > "$META_FILE" <<EOF
protocol=$PROTOCOL
sig_alg=$SIG_ALG
kem_alg=$KEM
runs_per_condition=$RUNS_PER_CONDITION
network_profile=$NETWORK_PROFILE
loss_percent=$LOSS_PERC
delay_ms=$DELAY_MS
timestamp=$TIMESTAMP
approach=certificate_compression_rfc8879
structure=nocompress_and_compressed_subfolders
EOF

    # ── Nettoyer ────────────────────────────────────────────────────────
    docker kill $OQS_SERVER &>/dev/null || true
    docker rm -f $OQS_SERVER &>/dev/null || true
    for pid in "${PUMBA_PIDS[@]:-}"; do kill -9 "$pid" &>/dev/null || true; done

    echo "  ✅ Done: $SIG_ALG × $KEM"
done

cleaning

echo ""
echo "================================================================================"
echo "  COMPRESSION TESTS COMPLETED"
echo "  Results: $RESULTS_RUN_DIR"
echo "================================================================================"
