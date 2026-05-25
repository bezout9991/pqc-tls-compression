#!/bin/bash
# ============================================================================
# run_arm_validation.sh
# Exécute la matrice de validation multi-architecture
#
# Matrice:
#   Protocoles : TLS, QUIC
#   Scénarios  : Ideal, Local YDE (35ms/2%)
#
# Total : 2 × 2 = 4 runs par architecture
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/Launcherv3_arm.sh"
DRY_RUN=false

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

HOST_ARCH=$(uname -m)
echo "=============================================================================="
echo "  ARM VALIDATION MATRIX"
echo "  Host Architecture: $HOST_ARCH"
echo "=============================================================================="

PROTOCOLS=("tls" "quic")
SCENARIOS=(
    "none 0 0:Ideal (0ms, 0%)"
    "simple 2 35:Local YDE (35ms, 2%)"
)

TOTAL_RUNS=$((${#PROTOCOLS[@]} * ${#SCENARIOS[@]}))
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
        echo "  RUN $RUN_NUM/$TOTAL_RUNS: $PROTO | $SCENARIO_LABEL | arch=$HOST_ARCH"
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
echo "  VALIDATION COMPLETED on $HOST_ARCH"
echo "  Results in: $HOME/arch_results/"
echo ""
echo "  Pour comparer avec x86_64 (si les résultats x86 sont disponibles):"
echo "    python3 ${SCRIPT_DIR}/arm/compare_architectures.py \\"
echo "      /home/bruno/mldsa-mlkem-tls-quic-performance/results/<x86_run> /home/bruno/mldsa-mlkem-tls-quic-performance/results/<arm_run> --plots"
echo "=============================================================================="
