#!/bin/bash
# ============================================================================
# build_multiarch.sh
# Build l'image Docker pour x86_64 et ARM64
#
# Usage:
#   ./build_multiarch.sh                    # Build les deux architectures
#   ./build_multiarch.sh --push             # Build + push vers un registry
#   ./build_multiarch.sh --arch amd64       # Build x86_64 seulement
#   ./build_multiarch.sh --arch arm64       # Build ARM64 seulement
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DOCKER_DIR="${SCRIPT_DIR}/0-docker"
IMAGE_NAME="uma-tls-quic-pq-34"
IMAGE_TAG="multiarch"
PUSH=false
ARCHS="amd64,arm64"
REGISTRY="${DOCKER_REGISTRY:-}"  # ex: docker.io/monuser/

for arg in "$@"; do
    case "$arg" in
        --push) PUSH=true ;;
        --arch) ARCHS="$2"; shift ;;
    esac
    shift 2>/dev/null || true
done

echo "=============================================================================="
echo "  MULTI-ARCH DOCKER BUILD"
echo "  Image:    ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}"
echo "  Archs:    $ARCHS"
echo "  Push:     $PUSH"
echo "=============================================================================="

cd "$DOCKER_DIR"

# Vérifier/Créer un builder multi-arch
BUILDER_NAME="multiarch-builder"
if ! docker buildx inspect "$BUILDER_NAME" &>/dev/null; then
    echo "[SETUP] Creating buildx builder: $BUILDER_NAME"
    docker buildx create --name "$BUILDER_NAME" --use --bootstrap
else
    echo "[SETUP] Using existing builder: $BUILDER_NAME"
    docker buildx use "$BUILDER_NAME"
fi

# Construire
BUILD_ARGS="--platform linux/${ARCHS//,/,\"linux/} -t ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG}"

if $PUSH; then
    echo "[BUILD] Building and pushing..."
    docker buildx build $BUILD_ARGS --push .
else
    echo "[BUILD] Building (local)..."
    docker buildx build $BUILD_ARGS --load . 2>&1 || {
        echo ""
        echo "[WARN] --load ne supporte qu'une seule architecture."
        echo "       Pour multi-arch local, utilisez --push vers un registry local"
        echo "       ou construisez séparément:"
        echo ""
        echo "  docker buildx build --platform linux/amd64 -t ${IMAGE_NAME}:amd64 --load ."
        echo "  docker buildx build --platform linux/arm64 -t ${IMAGE_NAME}:arm64 --load ."
        echo ""
    }
fi

echo ""
echo "=============================================================================="
echo "  BUILD COMPLETED"
echo ""
echo "  Pour tester sur ARM64 (émulation QEMU):"
echo "    docker run --platform linux/arm64 --rm -it ${REGISTRY}${IMAGE_NAME}:${IMAGE_TAG} openssl version"
echo ""
echo "  Pour exécuter les tests sur ARM64:"
echo "    ./Launcherv3_arm.sh tls none 0 0"
echo "=============================================================================="
