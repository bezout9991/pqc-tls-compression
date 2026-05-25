#!/bin/bash
# ============================================================================
# run_resumption_batch_matrix.sh
# Matrice complète Batch séparés : N full → N resumed
#
# Matrice:
#   Protocoles : TLS, QUIC
#   Scénarios  : Ideal, Local YDE (35ms/2%), Degraded (200ms/10%), GE stable
#   Paires      : ML-DSA65+ML-KEM768, ML-DSA87+HQC256
#
# Total : 2 × 4 = 8 runs
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/Launcherv3_resumption_batch.sh"
DRY_RUN=false

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

PROTOCOLS=("tls" "quic")
SCENARIOS=(
    "none 0 0:Ideal (0ms, 0%)"
    "simple 2 35:Local YDE (35ms, 2%)"
    "simple 10 200:Degraded (200ms, 10%)"
    "stable 0 0:GE Stable"
)

TOTAL_RUNS=$((${#PROTOCOLS[@]} * ${#SCENARIOS[@]}))
echo "=============================================================================="
echo "  BATCH SÉPARÉ MATRIX : N Full → N Resumed"
echo "  Total runs: $TOTAL_RUNS"
echo "  Protocols:  ${PROTOCOLS[*]}"
echo "  Scenarios:  ${SCENARIOS[*]}"
echo "=============================================================================="

RUN_NUM=0
for PROTO in "${PROTOCOLS[@]}"; do
    for SCENARIO_DEF in "${SCENARIOS[@]}"; do
        RUN_NUM=$((RUN_NUM + 1))
        SCENARIO_ARGS="${SCENARIO_DEF%%:*}"
        SCENARIO_LABEL="${SCENARIO_DEF##*:}"
        read -r PROFILE LOSS DELAY <<< "$SCENARIO_ARGS"

        echo ""
        echo "=============================================================================="
        echo "  RUN $RUN_NUM/$TOTAL_RUNS: $PROTO | $SCENARIO_LABEL"
        echo "=============================================================================="

        if $DRY_RUN; then
            echo "[DRY-RUN] $LAUNCHER $PROTO $PROFILE $LOSS $DELAY"
        else
            "$LAUNCHER" "$PROTO" "$PROFILE" "$LOSS" "$DELAY"
            echo "[DONE] Run $RUN_NUM/$TOTAL_RUNS completed."
        fi
    done
done

echo ""
echo "=============================================================================="
echo "  ALL RUNS COMPLETED"
echo "  Results in: $SCRIPT_DIR/results/"
echo "=============================================================================="
