#!/bin/bash
# ============================================================================
# run_compress_matrix.sh
# Exécute la matrice complète compression certificat (RFC 8879)
#
# Approche :
#   Pour chaque (protocole, scénario, paire) on exécute :
#     - 500 handshakes SANS compression de certificat
#     - 500 handshakes AVEC compression de certificat
#
# Matrice actuelle :
#   Protocoles : TLS, QUIC
#   Scénarios  : Ideal (0/0), 35ms/2%, 200ms/4%, GE stable
#
# Structure des résultats :
#   results/<run_id>/
#       ├── nocompress/   (500 runs)
#       └── compressed/   (500 runs)
#
# Total runs : 2 protocoles × 4 scénarios × 4 paires = 32 conditions
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/Launcherv3_compress.sh"
DRY_RUN=false

[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=true

PROTOCOLS=("tls" "quic")
SCENARIOS=(
    "none 0 0:Ideal (0ms, 0%)"
    "simple 2 35:Local YDE (35ms, 2%)"
    "simple 4 200:Backbone (200ms, 4%)"
)

TOTAL_RUNS=$((${#PROTOCOLS[@]} * ${#SCENARIOS[@]}))
echo ""
echo "================================================================================"
echo "  CERTIFICATE COMPRESSION MATRIX"
echo "  Total runs: $TOTAL_RUNS   |   Protocols: ${PROTOCOLS[*]}"
echo "================================================================================"

RUN_NUM=0
for PROTO in "${PROTOCOLS[@]}"; do
    for SCENARIO_DEF in "${SCENARIOS[@]}"; do
        RUN_NUM=$((RUN_NUM + 1))
        SCENARIO_ARGS="${SCENARIO_DEF%%:*}"
        SCENARIO_LABEL="${SCENARIO_DEF##*:}"
        read -r PROFILE LOSS DELAY <<< "$SCENARIO_ARGS"

        echo ""
        echo "================================================================================"
        echo "  RUN $RUN_NUM/8: $PROTO | $SCENARIO_LABEL"
        echo "================================================================================"

        if $DRY_RUN; then
            echo "[DRY-RUN] $LAUNCHER $PROTO $PROFILE $LOSS $DELAY"
        else
            "$LAUNCHER" "$PROTO" "$PROFILE" "$LOSS" "$DELAY"
            echo "[DONE] Run $RUN_NUM/$TOTAL_RUNS completed."
        fi
    done
done


echo ""
echo "================================================================================"
echo "  ALL RUNS COMPLETED"
echo "  Results in: results/"
echo "  Analyse: python3 compress/analyse_compress.py results/ --all --plots"
echo "================================================================================"
