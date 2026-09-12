#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-oscar-test-mwi}"
KAGENT_NAMESPACE="${KAGENT_NAMESPACE:-kagent}"
KAGENT_VERSION="0.10.0-rc1"
KAGENT_IMAGE="${KAGENT_IMAGE:-kagent-golang-adk:0.10.0-rc1-timeout2h}"

VALUES_FILE="${PROJECT_ROOT}/manifests/kagent/values-local.yaml"
MODEL_CONFIG_FILE="${PROJECT_ROOT}/manifests/kagent/default-model-config.yaml"
AGENT_FILE="${PROJECT_ROOT}/manifests/kagent/k8s-agent.yaml"

docker image inspect "${KAGENT_IMAGE}" >/dev/null

kind load docker-image \
    "${KAGENT_IMAGE}" \
    --name "${KIND_CLUSTER_NAME}"

helm upgrade --install kagent-crds \
    oci://ghcr.io/kagent-dev/kagent/helm/kagent-crds \
    --version "${KAGENT_VERSION}" \
    --namespace "${KAGENT_NAMESPACE}" \
    --create-namespace \
    --wait \
    --timeout 10m

helm upgrade --install kagent \
    oci://ghcr.io/kagent-dev/kagent/helm/kagent \
    --version "${KAGENT_VERSION}" \
    --namespace "${KAGENT_NAMESPACE}" \
    --values "${VALUES_FILE}" \
    --wait \
    --timeout 20m

kubectl apply -f "${MODEL_CONFIG_FILE}"
kubectl apply -f "${AGENT_FILE}"

kubectl wait \
    --namespace "${KAGENT_NAMESPACE}" \
    --for=condition=Ready \
    agents.kagent.dev/k8s-agent \
    --timeout=20m

kubectl get agents.kagent.dev k8s-agent \
    --namespace "${KAGENT_NAMESPACE}"
