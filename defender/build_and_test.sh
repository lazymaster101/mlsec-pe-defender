#!/usr/bin/env bash
#
# Build the defender Docker image and start the container.
#
# Usage:
#   ./build_and_test.sh
#
# Env overrides:
#   IMAGE_NAME       (default: defender_product)
#   CONTAINER_NAME   (default: defender_product)
#   PORT             (default: 8080)
#   READY_TIMEOUT    (default: 60)   seconds to wait for the service to come up
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

IMAGE_NAME="${IMAGE_NAME:-defender_product}"
CONTAINER_NAME="${CONTAINER_NAME:-defender_product}"
PORT="${PORT:-8080}"
READY_TIMEOUT="${READY_TIMEOUT:-60}"
URL="http://127.0.0.1:${PORT}"

echo "==> Building image $IMAGE_NAME from $SCRIPT_DIR"
docker build -t "$IMAGE_NAME" .

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  echo "==> Removing existing container $CONTAINER_NAME"
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

echo "==> Starting container $CONTAINER_NAME on port $PORT"
docker run -d --rm -p "${PORT}:8080" -m 1g --name "$CONTAINER_NAME" "$IMAGE_NAME" >/dev/null

echo "==> Waiting for service to become ready (timeout ${READY_TIMEOUT}s)"
ready=0
for ((i = 0; i < READY_TIMEOUT; i++)); do
  if curl -fsS -o /dev/null "${URL}/model" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "FAIL: service did not become ready within ${READY_TIMEOUT}s"
  echo "----- container logs -----"
  docker logs "$CONTAINER_NAME" || true
  exit 1
fi

echo "==> $CONTAINER_NAME is up at $URL"
