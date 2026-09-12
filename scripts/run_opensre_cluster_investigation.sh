#!/usr/bin/env bash
set -uo pipefail

ALERT_FILE="${1:?Usage: $0 ALERT_FILE OUTPUT_DIR}"
OUTPUT_DIR="${2:?Usage: $0 ALERT_FILE OUTPUT_DIR}"

NAMESPACE="${OPENSRE_NAMESPACE:-opensre}"
DEPLOYMENT="${OPENSRE_DEPLOYMENT:-opensre}"

mkdir -p "${OUTPUT_DIR}" || exit 1

OUTPUT_FILE="${OUTPUT_DIR}/opensre_output.json"
CLIENT_LOG="${OUTPUT_DIR}/client.log"
STATUS_FILE="${OUTPUT_DIR}/status.json"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STARTED_EPOCH="$(date +%s)"

# Create a local heartbeat before opening the long-lived exec stream. If the
# terminal disconnects, the last known state is still available on disk.
python3 - \
  "${STATUS_FILE}" \
  "${STARTED_AT}" \
  "${ALERT_FILE}" \
  "${OUTPUT_FILE}" \
  "${CLIENT_LOG}" <<'PY'
import json
import sys
from pathlib import Path

status_file, started_at, alert, output, log = sys.argv[1:]
Path(status_file).write_text(
    json.dumps({
        "ok": False,
        "state": "running",
        "return_code": None,
        "started_at": started_at,
        "alert_file": alert,
        "output_file": output,
        "client_log": log,
        "http_request_timeout_seconds": None,
    }, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
PY

kubectl exec -i \
  -n "${NAMESPACE}" \
  "deployment/${DEPLOYMENT}" \
  -- python -c '
import json
import os
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

raw = json.load(sys.stdin)

remote_directory = Path(tempfile.mkdtemp(prefix="opensre-coordinator-"))
remote_status = remote_directory / "status.json"
remote_output = remote_directory / "opensre_output.json"
started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
state = {
    "pod": os.environ.get("HOSTNAME"),
    "directory": str(remote_directory),
    "started_at": started_at,
    "state": "running",
    "ok": False,
    "http_request_timeout_seconds": None,
    "attempts": 0,
}

def save_state(**updates):
    state.update(updates)
    remote_status.write_text(
        json.dumps(state, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

save_state()
print(
    "OPENSRE_RECOVERY="
    + json.dumps({"directory": str(remote_directory), "status": str(remote_status), "output": str(remote_output)}),
    file=sys.stderr,
    flush=True,
)

payload = {
    "raw_alert": raw,
    "alert_name": raw.get("alert_name"),
    "severity": raw.get("severity"),
}

request_data = json.dumps(payload).encode("utf-8")

while True:
    state["attempts"] += 1
    request = urllib.request.Request(
        "http://127.0.0.1:8000/investigate",
        data=request_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": (
                "Bearer "
                + os.environ["OPENSRE_ALERT_LISTENER_TOKEN"]
            ),
        },
        method="POST",
    )
    save_state(state="requesting")
    try:
        # No client-side deadline: the model is allowed to finish naturally.
        with urllib.request.urlopen(request, timeout=None) as response:
            response_bytes = response.read()
        # Preserve the exact response before parsing it. A malformed response
        # must remain diagnosable rather than disappearing with the exception.
        remote_output.write_bytes(response_bytes)
        result = json.loads(response_bytes.decode("utf-8"))
        if not isinstance(result, dict) or result.get("error") or result.get("ok") is False or result.get("success") is False:
            raise RuntimeError("OpenSRE returned an application error")
        report = result.get("report") or result.get("final_report")
        if not isinstance(report, str) or not report.strip():
            raise RuntimeError("OpenSRE response contains no non-empty report")
        remote_output.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        save_state(
            state="completed",
            ok=True,
            finished_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        break
    except urllib.error.HTTPError as exc:
        body = exc.read()
        (remote_directory / "last_http_error.txt").write_bytes(body)
        try:
            detail = json.loads(body.decode("utf-8")).get("error", "")
        except (ValueError, AttributeError):
            detail = ""
        is_capacity = exc.code == 503 and detail == "OpenSRE is at capacity. Please try again shortly."
        if not is_capacity:
            save_state(state="failed", error=f"HTTPError: {exc}; {detail}",
                       http_status=exc.code, automatic_retry=False)
            print(f"OpenSRE HTTP failure {exc.code}: {detail}", file=sys.stderr, flush=True)
            raise
        save_state(state="waiting_for_capacity", error=detail)
        print(
            "OpenSRE explicitly at capacity; retrying in 30s | attempts="
            + str(state["attempts"]),
            file=sys.stderr, flush=True,
        )
        time.sleep(30)
    except urllib.error.URLError as exc:
        # Acceptance is ambiguous; do not submit a duplicate investigation.
        save_state(state="failed", error=f"URLError: {exc}",
                   acceptance_unknown=True, automatic_retry=False)
        raise
    except Exception as exc:
        save_state(state="failed", error=f"{type(exc).__name__}: {exc}")
        raise
' < "${ALERT_FILE}" > "${OUTPUT_FILE}" 2> "${CLIENT_LOG}"

RETURN_CODE=$?
ELAPSED_SECONDS="$(( $(date +%s) - STARTED_EPOCH ))"
FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - \
  "${STATUS_FILE}" \
  "${RETURN_CODE}" \
  "${STARTED_AT}" \
  "${FINISHED_AT}" \
  "${ELAPSED_SECONDS}" \
  "${ALERT_FILE}" \
  "${OUTPUT_FILE}" \
  "${CLIENT_LOG}" <<'PY'
import json
import sys
from pathlib import Path

status_file, return_code, started_at, finished_at, elapsed, alert, output, log = sys.argv[1:]

remote_recovery = None
try:
    for line in Path(log).read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("OPENSRE_RECOVERY="):
            remote_recovery = json.loads(line.split("=", 1)[1])
except Exception:
    pass

status = {
    "ok": int(return_code) == 0,
    "state": "completed" if int(return_code) == 0 else "failed",
    "return_code": int(return_code),
    "started_at": started_at,
    "finished_at": finished_at,
    "elapsed_seconds": int(elapsed),
    "alert_file": alert,
    "output_file": output,
    "client_log": log,
    "http_request_timeout_seconds": None,
    "remote_recovery": remote_recovery,
}

Path(status_file).write_text(
    json.dumps(status, indent=2, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
PY

STATUS_RETURN_CODE=$?
if [[ "${STATUS_RETURN_CODE}" -ne 0 ]]; then
  exit "${STATUS_RETURN_CODE}"
fi

exit "${RETURN_CODE}"
