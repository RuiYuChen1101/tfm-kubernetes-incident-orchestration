#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p outputs

echo "=============================="
echo "1. STOP OLD LOCAL PROCESSES"
echo "=============================="

pkill -f "kagent invoke" || true
pkill -f "coordinator_v10.py" || true
pkill -f "coordinator_v11.py" || true
pkill -f "coordinator_v12.py" || true
pkill -f "kubectl.*port-forward" || true

sleep 2

echo "local listening ports:"
ss -ltnp | grep -E ':8083|:18083|:11434|:9090|:3100' || echo "no old local ports"

echo
echo "=============================="
echo "2. RESTORE KIND API"
echo "=============================="

docker start oscar-test-mwi-control-plane 2>/dev/null || true

docker rm -f kind-apiserver-proxy 2>/dev/null || true

docker run -d \
  --name kind-apiserver-proxy \
  --network kind \
  -p 127.0.0.1:40820:6443 \
  alpine/socat -d -d TCP-LISTEN:6443,fork,reuseaddr TCP:oscar-test-mwi-control-plane:6443 >/dev/null

echo "waiting for Kubernetes API..."
for i in $(seq 1 40); do
  if curl -sk --max-time 5 https://127.0.0.1:40820/healthz | grep -q ok; then
    echo "KUBERNETES_API_OK"
    break
  fi
  sleep 3
  if [ "$i" = "40" ]; then
    echo "KUBERNETES_API_FAILED"
    exit 10
  fi
done

kubectl get nodes --request-timeout=30s

echo
echo "=============================="
echo "3. REMOVE BROKEN GRAFANA MCP"
echo "=============================="

kubectl delete remotemcpserver kagent-grafana-mcp -n kagent --ignore-not-found || true
kubectl delete deployment kagent-grafana-mcp -n kagent --ignore-not-found || true
kubectl delete svc kagent-grafana-mcp -n kagent --ignore-not-found || true

echo
echo "=============================="
echo "4. RESTART KAGENT + OLLAMA"
echo "=============================="

kubectl rollout restart deployment/kagent-controller -n kagent
kubectl rollout restart deployment/kagent-tools -n kagent
kubectl rollout restart deployment/ollama -n ollama

kubectl rollout status deployment/kagent-controller -n kagent --timeout=180s
kubectl rollout status deployment/kagent-tools -n kagent --timeout=180s
kubectl rollout status deployment/ollama -n ollama --timeout=240s

echo
echo "kagent pods:"
kubectl get pods -n kagent -o wide | grep -E "kagent-controller|k8s-agent|kagent-tools" || true

echo
echo "ollama pods:"
kubectl get pods -n ollama -o wide || true

echo
echo "remote mcp servers:"
kubectl get remotemcpservers -n kagent || true

echo
echo "=============================="
echo "5. START CLEAN PORT-FORWARDS"
echo "=============================="

nohup kubectl -n kagent port-forward svc/kagent-controller 18083:8083 \
  > outputs/pf_kagent_18083.log 2>&1 &
echo $! > outputs/pf_kagent_18083.pid

nohup kubectl -n ollama port-forward svc/ollama 11434:80 \
  > outputs/pf_ollama_11434.log 2>&1 &
echo $! > outputs/pf_ollama_11434.pid

sleep 8

echo
echo "checking kagent controller on 18083..."
for i in $(seq 1 40); do
  if curl -fsS --max-time 5 http://127.0.0.1:18083/health >/dev/null 2>&1; then
    echo "KAGENT_CONTROLLER_OK_18083"
    break
  fi
  sleep 3
  if [ "$i" = "40" ]; then
    echo "KAGENT_CONTROLLER_FAILED_18083"
    echo "--- pf_kagent_18083.log ---"
    tail -120 outputs/pf_kagent_18083.log || true
    exit 20
  fi
done

echo
echo "checking ollama..."
curl -s --max-time 180 http://127.0.0.1:11434/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5:3b","stream":false,"messages":[{"role":"user","content":"Responde solo OK"}]}' \
  | python3 -m json.tool

echo
echo "=============================="
echo "6. CLEAN START FINISHED"
echo "=============================="

echo "Kagent URL: http://127.0.0.1:18083"
echo "Ollama URL: http://127.0.0.1:11434"
echo "Port-forward logs:"
echo "  outputs/pf_kagent_18083.log"
echo "  outputs/pf_ollama_11434.log"
