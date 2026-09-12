#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p outputs

echo "=== 1. clean local background processes ==="
pkill -f "kagent invoke" || true
pkill -f "kubectl.*port-forward" || true
sleep 2

echo "=== 2. restore kind api proxy ==="
docker start oscar-test-mwi-control-plane 2>/dev/null || true
docker rm -f kind-apiserver-proxy 2>/dev/null || true

docker run -d \
  --name kind-apiserver-proxy \
  --network kind \
  -p 127.0.0.1:40820:6443 \
  alpine/socat -d -d TCP-LISTEN:6443,fork,reuseaddr TCP:oscar-test-mwi-control-plane:6443 >/dev/null

for i in $(seq 1 40); do
  if curl -sk --max-time 5 https://127.0.0.1:40820/healthz | grep -q ok; then
    echo "KUBERNETES_API_OK"
    break
  fi
  sleep 3
  if [ "$i" = "40" ]; then
    echo "KUBERNETES_API_FAILED"
    exit 1
  fi
done

kubectl get nodes --request-timeout=30s

echo "=== 3. keep original k8s-agent, remove only broken grafana mcp ==="
kubectl delete remotemcpserver kagent-grafana-mcp -n kagent --ignore-not-found || true
kubectl delete deployment kagent-grafana-mcp -n kagent --ignore-not-found || true
kubectl delete svc kagent-grafana-mcp -n kagent --ignore-not-found || true

echo "=== 4. restart kagent core + ollama ==="
kubectl rollout restart deployment/kagent-controller -n kagent
kubectl rollout restart deployment/kagent-tools -n kagent
kubectl rollout restart deployment/ollama -n ollama

kubectl rollout status deployment/kagent-controller -n kagent --timeout=180s
kubectl rollout status deployment/kagent-tools -n kagent --timeout=180s
kubectl rollout status deployment/ollama -n ollama --timeout=240s

echo "=== 5. wait until kagent-tool-server Accepted=True ==="
for i in $(seq 1 60); do
  kubectl get remotemcpserver kagent-tool-server -n kagent || true
  STATUS="$(kubectl get remotemcpserver kagent-tool-server -n kagent -o jsonpath='{.status.accepted}' 2>/dev/null || true)"
  if [ "$STATUS" = "true" ] || [ "$STATUS" = "True" ]; then
    echo "KAGENT_TOOL_SERVER_TRUE"
    break
  fi
  sleep 5
  if [ "$i" = "60" ]; then
    echo "KAGENT_TOOL_SERVER_NOT_TRUE"
    kubectl describe remotemcpserver kagent-tool-server -n kagent || true
    exit 2
  fi
done

echo "=== 6. start port-forwards in background, same terminal ==="
nohup kubectl -n kagent port-forward svc/kagent-controller 8083:8083 > outputs/pf_kagent_8083.log 2>&1 &
echo $! > outputs/pf_kagent_8083.pid

nohup kubectl -n ollama port-forward svc/ollama 11434:80 > outputs/pf_ollama_11434.log 2>&1 &
echo $! > outputs/pf_ollama_11434.pid

sleep 8

echo "=== 7. check local 8083 and 11434 ==="
ss -ltnp | grep ':8083' || { echo "8083_NOT_LISTENING"; cat outputs/pf_kagent_8083.log; exit 3; }
ss -ltnp | grep ':11434' || { echo "11434_NOT_LISTENING"; cat outputs/pf_ollama_11434.log; exit 4; }

echo "=== 8. check ollama ==="
curl -s --max-time 180 http://127.0.0.1:11434/api/chat \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen2.5:3b","stream":false,"messages":[{"role":"user","content":"Responde solo OK"}]}' \
  | tee outputs/ollama_ok.json

grep -q '"content":"OK"\|"content": "OK"' outputs/ollama_ok.json || {
  echo "OLLAMA_NOT_OK"
  cat outputs/ollama_ok.json
  exit 5
}

echo "=== 9. manual k8s-agent tool test ==="
cat > outputs/kagent_manual_tool_test.txt <<'EOF'
List pods in namespace incident-demo using Kubernetes tools.
Do not answer from memory.
Use the Kubernetes tool first.
EOF

kagent invoke \
  --agent k8s-agent \
  --file outputs/kagent_manual_tool_test.txt \
  --stream \
  --timeout 300s \
  | tee outputs/kagent_manual_tool_test_stream_300s.txt

echo "=== 10. check tool call ==="
grep -nEi "function_call|function_response|k8s_get_resources|k8s_describe|k8s_get_pod_logs|incident-demo|error|failed|pods" \
  outputs/kagent_manual_tool_test_stream_300s.txt || true

if grep -qEi "function_call|function_response|k8s_get_resources|k8s_describe|k8s_get_pod_logs" outputs/kagent_manual_tool_test_stream_300s.txt; then
  echo "KAGENT_K8S_AGENT_TOOL_CALL_OK"
else
  echo "KAGENT_K8S_AGENT_TOOL_CALL_FAILED"
  echo "--- kagent stream tail ---"
  tail -120 outputs/kagent_manual_tool_test_stream_300s.txt || true
  echo "--- pf kagent log ---"
  tail -80 outputs/pf_kagent_8083.log || true
  exit 6
fi
