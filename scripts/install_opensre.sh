#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-oscar-test-mwi}"
OPENSRE_NAMESPACE="${OPENSRE_NAMESPACE:-opensre}"
OPENSRE_IMAGE="${OPENSRE_IMAGE:-opensre-custom:0.1.2026.8.10-timeout2h-k8sfix4}"

: "${OPENSRE_ALERT_LISTENER_TOKEN:?Set OPENSRE_ALERT_LISTENER_TOKEN before running this script}"

docker image inspect "${OPENSRE_IMAGE}" >/dev/null

kind load docker-image \
    "${OPENSRE_IMAGE}" \
    --name "${KIND_CLUSTER_NAME}"

kubectl apply \
    -f "${PROJECT_ROOT}/manifests/opensre/namespace.yaml"

kubectl create secret generic opensre-auth \
    --namespace "${OPENSRE_NAMESPACE}" \
    --from-literal="OPENSRE_ALERT_LISTENER_TOKEN=${OPENSRE_ALERT_LISTENER_TOKEN}" \
    --dry-run=client \
    -o yaml |
kubectl apply -f -

kubectl apply \
    -f "${PROJECT_ROOT}/manifests/opensre/configmap.yaml" \
    -f "${PROJECT_ROOT}/manifests/opensre/deployment.yaml" \
    -f "${PROJECT_ROOT}/manifests/opensre/service.yaml"

kubectl rollout status deployment/opensre \
    --namespace "${OPENSRE_NAMESPACE}" \
    --timeout=10m

kubectl exec \
    --namespace "${OPENSRE_NAMESPACE}" \
    deployment/opensre -- \
    python -c 'import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen("http://127.0.0.1:8000/health",timeout=10)),indent=2))'
