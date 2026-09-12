#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="${KAGENT_SOURCE_DIR:-${PROJECT_ROOT}/kagent-src}"
PATCH_FILE="${PROJECT_ROOT}/patches/kagent-v0.10.0-rc1-timeout2h.patch"
IMAGE="${KAGENT_IMAGE:-kagent-golang-adk:0.10.0-rc1-timeout2h}"
EXPECTED_COMMIT="4ed5996bfb761771ecf83e4a56addf0d3d664627"

if [[ ! -d "${SOURCE_DIR}/.git" ]]; then
    echo "Missing Kagent source repository: ${SOURCE_DIR}" >&2
    exit 1
fi

ACTUAL_COMMIT="$(git -C "${SOURCE_DIR}" rev-parse HEAD)"
if [[ "${ACTUAL_COMMIT}" != "${EXPECTED_COMMIT}" ]]; then
    echo "Unexpected Kagent commit: ${ACTUAL_COMMIT}" >&2
    echo "Expected: ${EXPECTED_COMMIT}" >&2
    exit 1
fi

if git -C "${SOURCE_DIR}" apply --check "${PATCH_FILE}" >/dev/null 2>&1; then
    git -C "${SOURCE_DIR}" apply "${PATCH_FILE}"
elif git -C "${SOURCE_DIR}" apply --reverse --check "${PATCH_FILE}" >/dev/null 2>&1; then
    echo "Timeout patch already applied"
else
    echo "Timeout patch cannot be applied cleanly" >&2
    exit 1
fi

docker build \
    --build-arg BUILD_PACKAGE=adk/cmd/main.go \
    --tag "${IMAGE}" \
    --file "${SOURCE_DIR}/go/Dockerfile" \
    "${SOURCE_DIR}/go"

echo "Built image: ${IMAGE}"
