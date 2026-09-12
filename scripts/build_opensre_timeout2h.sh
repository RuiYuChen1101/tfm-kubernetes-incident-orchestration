#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${OPENSRE_SOURCE_DIR:-${PROJECT_ROOT}/opensre-src}"
IMAGE="${OPENSRE_IMAGE:-opensre-custom:0.1.2026.8.10-timeout2h-k8sfix4}"
EXPECTED_COMMIT="43aaba7cf88f94f3beeccb185a4422bc584048e9"

PATCH_FILES=(
  "${PROJECT_ROOT}/patches/opensre-v0.1.2026.8.10-timeout2h.patch"
  "${PROJECT_ROOT}/patches/opensre-kubernetes-input-and-diagnosis-fix.patch"
  "${PROJECT_ROOT}/patches/opensre-ollama-max-tokens6144.patch"
  "${PROJECT_ROOT}/patches/opensre-precollected-evidence-mode.patch"
  "${PROJECT_ROOT}/patches/opensre-evidence-grounding-guard.patch"
)

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
  echo "OpenSRE source repository not found: ${SOURCE_DIR}" >&2
  exit 1
fi

ACTUAL_COMMIT="$(git -C "${SOURCE_DIR}" rev-parse HEAD)"
if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT}" ]]; then
  echo "Unexpected OpenSRE commit: ${ACTUAL_COMMIT}" >&2
  echo "Expected: ${EXPECTED_COMMIT}" >&2
  exit 1
fi

BUILD_ROOT="$(mktemp -d)"
BUILD_SOURCE="${BUILD_ROOT}/opensre-src"

cleanup() {
  git -C "${SOURCE_DIR}" \
    worktree remove --force "${BUILD_SOURCE}" \
    >/dev/null 2>&1 || true

  rmdir "${BUILD_ROOT}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

git -C "${SOURCE_DIR}" \
  worktree add --detach "${BUILD_SOURCE}" "${EXPECTED_COMMIT}" \
  >/dev/null

for PATCH_FILE in "${PATCH_FILES[@]}"; do
  if [[ ! -f "${PATCH_FILE}" ]]; then
    echo "Patch not found: ${PATCH_FILE}" >&2
    exit 1
  fi

  if ! git -C "${BUILD_SOURCE}" \
    apply --check "${PATCH_FILE}" >/dev/null 2>&1; then

    echo "Patch cannot be applied cleanly: ${PATCH_FILE}" >&2
    exit 1
  fi

  git -C "${BUILD_SOURCE}" apply "${PATCH_FILE}"
  echo "Applied: $(basename "${PATCH_FILE}")"
done

git -C "${BUILD_SOURCE}" diff --check

docker build \
  --tag "${IMAGE}" \
  "${BUILD_SOURCE}"

echo "Built image: ${IMAGE}"
