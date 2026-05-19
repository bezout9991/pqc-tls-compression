#!/bin/bash
# ============================================================================
# run_concurrent_matrix.sh
# Exécute la matrice complète des tests de charge concurrente
#
# Matrice:
#   Protocoles : TLS, QUIC
#   Clients    : 10, 50, 100, 500
#   Scénarios  : Ideal (0ms/0%), Local YDE (35ms/2%), Degraded (200ms/10%)
#
# Total : 2 × 3 × 3 = 18 runs
#
# Usage: ./run_concurrent_matrix.sh [--dry-run] [--resume] [--start-from N]
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/Launcherv3_concurrent.sh"
DRY_RUN=false
RESUME=false
START_FROM=1
RESULTS_DIR="/home/bruno/mldsa-mlkem-tls-quic-performance/results"

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --resume) RESUME=true ;;
        --start-from) START_FROM="$2"; shift ;;
    esac
    shift 2>/dev/null || true
done

# Matrice de tests
PROTOCOLS=("tls" "quic")
CLIENTS=(10 50 100)
SCENARIOS=(
    "none 0 0:Ideal (0ms, 0%)"
    "simple 2 35:Local YDE (35ms, 2%)"
    "simple 10 200:Degraded (200ms, 10%)"
)

# Calculer le nombre total de runs
TOTAL_RUNS=$((${#PROTOCOLS[@]} * ${#CLIENTS[@]} * ${#SCENARIOS[@]}))
echo "=============================================================================="
echo "  CONCURRENT TEST MATRIX"
echo "  Total runs: $TOTAL_RUNS"
echo "  Protocols:  ${PROTOCOLS[*]}"
echo "  Clients:    ${CLIENTS[*]}"
echo "  Scenarios:  ${SCENARIOS[*]}"
echo "=============================================================================="
echo ""

RUN_NUM=0
for PROTO in "${PROTOCOLS[@]}"; do
    for N in "${CLIENTS[@]}"; do
        for SCENARIO_DEF in "${SCENARIOS[@]}"; do
            RUN_NUM=$((RUN_NUM + 1))

            # Parser le scénario
            SCENARIO_ARGS="${SCENARIO_DEF%%:*}"
            SCENARIO_LABEL="${SCENARIO_DEF##*:}"
            read -r PROFILE LOSS DELAY <<< "$SCENARIO_ARGS"

            if (( RUN_NUM < START_FROM )); then
                echo "[SKIP] Run $RUN_NUM/$TOTAL_RUNS: $PROTO | $N clients | $SCENARIO_LABEL"
                continue
            fi

            if $RESUME; then
                PATTERN="${PROTO}_c${N}_${PROFILE}_l${LOSS}_d${DELAY}_*"
                if ls "$RESULTS_DIR"/$PATTERN >/dev/null 2>&1; then
                    echo "[SKIP] Run $RUN_NUM/$TOTAL_RUNS: $PROTO | $N clients | $SCENARIO_LABEL (déjà fait)"
                    continue
                fi
            fi

            echo ""
            echo "=============================================================================="
            echo "  RUN $RUN_NUM/$TOTAL_RUNS"
            echo "  Protocol: $PROTO  |  Clients: $N  |  $SCENARIO_LABEL"
            echo "=============================================================================="

            if $DRY_RUN; then
                echo "[DRY-RUN] $LAUNCHER $PROTO $N $PROFILE $LOSS $DELAY"
            else
                "$LAUNCHER" "$PROTO" "$N" "$PROFILE" "$LOSS" "$DELAY"
                echo "[DONE] Run $RUN_NUM/$TOTAL_RUNS completed."
            fi
        done
    done
done

echo ""
echo "=============================================================================="
echo "  ALL RUNS COMPLETED"
echo "  Results in: $HOME/concurrent_results/"
echo ""
echo "  To analyze:"
echo "    python3 ${SCRIPT_DIR}/concurrent/analyse_concurrent.py /home/bruno/mldsa-mlkem-tls-quic-performance/results/<run_dir> --plots"
echo "    python3 ${SCRIPT_DIR}/concurrent/compare_concurrent.py /home/bruno/mldsa-mlkem-tls-quic-performance/results/"
echo "=============================================================================="
