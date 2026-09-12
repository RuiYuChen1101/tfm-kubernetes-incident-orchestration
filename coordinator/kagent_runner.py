"""Kagent integration for adaptive, read-only Kubernetes investigation."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

import requests

if __package__:
    from .evidence_normalizer import build_kagent_evidence_context, compact_value, check_payload_size
else:
    from evidence_normalizer import build_kagent_evidence_context, compact_value, check_payload_size


KAGENT_AGENT_URL = os.getenv(
    "KAGENT_AGENT_URL",
    "http://127.0.0.1:18080/",
).rstrip("/") + "/"
KAGENT_PROTOCOL_VERSION = os.getenv("KAGENT_PROTOCOL_VERSION", "0.3")
def request_timeouts() -> tuple[float, float | None]:
    """Bound connection setup; allow inference responses to finish naturally."""
    connect = float(os.getenv("KAGENT_CONNECT_TIMEOUT", "10"))
    raw = os.getenv("KAGENT_REQUEST_TIMEOUT", "none").strip().lower()
    read = None if raw in {"", "0", "none", "null", "off", "unlimited"} else float(raw)
    if connect <= 0 or (read is not None and read <= 0):
        raise ValueError("Use a positive connect timeout and a positive read timeout or 'none'")
    return connect, read


KAGENT_TIMEOUT = request_timeouts()
KAGENT_WAIT_LABEL = "unlimited" if KAGENT_TIMEOUT[1] is None else f"{KAGENT_TIMEOUT[1]:g}s"
KAGENT_MAX_ATTEMPTS = max(1, int(os.getenv("KAGENT_MAX_ATTEMPTS", "2")))
KAGENT_INITIAL_EVIDENCE_BUDGET = max(
    2000,
    int(os.getenv("KAGENT_INITIAL_EVIDENCE_BUDGET", "5000")),
)
KAGENT_RETRY_CONTEXT_BUDGET = max(
    1500,
    int(os.getenv("KAGENT_RETRY_CONTEXT_BUDGET", "4000")),
)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def build_kagent_task(
    initial_brief: dict[str, Any],
    previous_attempts: list[dict[str, Any]],
) -> str:
    target = initial_brief["target"]
    detected_risks = initial_brief.get("detected_risks") or []
    coordinator_scope = initial_brief.get("coordinator_scope") or {
        "selection_mode": "dynamic_per_detected_target",
        "current_target": target,
    }

    risk_focus = [
        {
            "risk_type": risk.get("risk_type"),
            "observed_reason": risk.get("observed_reason"),
            "observed_value": risk.get("observed_value"),
            "observed_value_suffix": risk.get("observed_value_suffix"),
            "threshold": risk.get("threshold"),
            "priority": risk.get("priority"),
            "detected_at": risk.get("detected_at"),
            "prometheus_query": risk.get("prometheus_query"),
        }
        for risk in detected_risks
    ]

    initial_evidence = initial_brief.get("evidence") or {}
    compact_initial_evidence = build_kagent_evidence_context(
        initial_evidence,
        remaining_budget=KAGENT_INITIAL_EVIDENCE_BUDGET,
    )

    previous = ""
    if previous_attempts:
        compact_previous_attempts = compact_value(
            previous_attempts,
            budget=KAGENT_RETRY_CONTEXT_BUDGET,
        )
        previous = f"""
COMPACT_PREVIOUS_ATTEMPTS
```json
{json.dumps(compact_previous_attempts, indent=2, ensure_ascii=False)}
```

This is a continuation, not a new investigation.

Before making another tool call:
- Review the successful live evidence already collected.
- Keep exactly the coordinator-selected current target and scope. Do not switch namespace, Pod or container.
- If a previous namespaced call omitted or mismatched the namespace, correct that call by using the exact current target namespace.
- Do not repeat a successful call for the same target unless a materially different parameter is necessary to answer the detected risk.
- Do not repeat a failed call with the same incorrect parameters.
- Ignore any previous write/mutation attempt as invalid investigation behavior. Do not retry it.
- Use the detected risks and the evidence already collected as the starting point for the continuation, not as a rigid checklist or a hard semantic boundary.
- You may follow a new live observation when it provides a reasonable investigative lead about the current target, even when its final relevance is still uncertain.
- Do not perform broad or unrelated cluster exploration without a concrete lead from the detected risks, supplied context or live tool results.
- Preserve uncertainty: collecting a live observation does not mean it is causal or ultimately relevant. Final relevance and diagnosis belong to OpenSRE.
- If the existing live evidence is sufficient and there is no reasonable unresolved lead or scope error, finish instead of searching for extra problems.
- If a read-only tool is unavailable, keep it as a limitation and decide adaptively whether another check is genuinely useful.
"""

    task = f"""
You are Kagent performing an adaptive, READ-ONLY Kubernetes investigation for a proactively detected risk.

TARGET
- namespace: {target['namespace']}
- pod: {target['pod']}
- container: {target['container']}

COORDINATOR_SELECTED_SCOPE
```json
{json.dumps(coordinator_scope, indent=2, ensure_ascii=False)}
```

DETECTED_RISK_FOCUS
```json
{json.dumps(risk_focus, indent=2, ensure_ascii=False)}
```

Investigate the live target using the Kubernetes tools available to you.

Rules:
- This task is investigation only. Do not remediate, modify, patch, create, delete, apply, update, replace, restart, scale, roll out, execute commands in workloads, or otherwise change cluster state.
- Do not create temporary Pods or other resources for testing.
- Use only read-only Kubernetes observations. Recommendations or remediation belong to the later OpenSRE analysis, not to Kagent.
- The coordinator has already selected dynamically which target must be investigated. Do not choose or broaden the target scope yourself.
- You decide dynamically HOW to investigate that target: choose the useful read-only tool or tools yourself from the current context and previous live results. Do not follow a fixed checklist or a risk-to-tool mapping.
- Use Kubernetes tools before answering. The investigation must contain at least one successful live read-only tool result when the environment permits it.
- Prefer one high-value read-only tool call at a time so that each new observation can guide the next decision.
- Do not request several overlapping Kubernetes observations in the same model turn when one narrower observation can answer the current unresolved question.
- Do not re-fetch information already present in the supplied initial evidence unless freshness, contradiction, or a specific missing field makes a live check necessary.
- After a successful live observation, finish the investigation when the detected risks are sufficiently covered instead of collecting additional corroborating evidence only for completeness.
- Interpret the detected risk types together with their observed evidence and use that context to choose the initial investigation direction. The risk context is a starting point, not a fixed tool sequence or a hard semantic boundary.
- Follow new live observations adaptively when they provide a reasonable investigative lead about the current target, even if OpenSRE may later determine that some collected evidence is secondary or unrelated to the final explanation.
- Do not perform broad, generic or unrelated cluster exploration without a concrete lead from the detected risks, supplied context or previous live tool results.
- When several detected risks belong to this same target, investigate them as one case and reuse evidence when appropriate; you do not need to decide their final causal relationship.
- Your role is to gather traceable live evidence, not to produce the final diagnosis or decide the ultimate relevance of every observation. Final interpretation belongs to OpenSRE.
- The namespace comes dynamically from the detected Prometheus target. For every namespaced call related to this case, pass exactly that namespace explicitly. Never rely on the Kubernetes default namespace.
- You may inspect a related Kubernetes resource when it is needed to understand the detected target, but keep the relationship explicit and remain read-only.
- If a read-only tool fails because of parameters or scope, correct the call when possible instead of treating the error as evidence.
- An empty result is negative evidence only for that exact query and scope. An omitted list is not an empty observation.
- Review every supplied Warning/Failed event, termination reason and log error before deciding which unresolved lead warrants a tool call. Reconcile different container attempts by their timestamps and identifiers.
- Repeating a log already present does not resolve a contradictory termination state. Follow a material unresolved lead when an appropriate read-only tool exists; otherwise explicitly mark that investigation incomplete.
- Capacity and resource requests/limits are configuration, not measured usage. They cannot by themselves rule out an earlier period of resource exhaustion.
- Do not repeat a successful tool call for the same target unless a materially different parameter is needed to resolve the detected risk.
- Base factual conclusions only on live tool responses and the supplied initial evidence.
- Stop when the detected risks have been investigated to a useful level and there is no reasonable unresolved lead from the current evidence. Do not search for extra problems merely to continue investigating.
- If a read-only check is unavailable, record the limitation and continue only when another check is reasonably justified by the current investigation context.
- If you state that another check is necessary or materially useful before finishing, execute that read-only check when possible.
- Never claim that a resource was changed, fixed or resolved. This investigation has no authority to change cluster state.
- Do not invent evidence. Failed calls and unavailable information must remain limitations.
- Keep the final prose short. The coordinator stores real function responses as evidence; your prose is non-authoritative.
- End the final answer with exactly one control marker. The last non-empty line of the response must be exactly INVESTIGATION_COMPLETE when the useful read-only investigation of the detected risks is finished, or exactly INVESTIGATION_INCOMPLETE when a necessary read-only check remains unavailable or unfinished. Do not write anything after that marker.
- Do not bold, quote, bullet, wrap in backticks, or otherwise format the control marker.

COMPACT_INITIAL_EVIDENCE

This is a bounded transport representation of the collected evidence. The complete
uncompressed evidence remains in brief_initial.json for audit. Omitted, duplicate
and truncated counters describe transport compaction and are not evidence of absence.
Read source identities, times and collection limitations together.

```json
{json.dumps(compact_initial_evidence, separators=(",", ":"), ensure_ascii=False)}
```
{previous}
""".strip()
    check_payload_size(task, "Kagent task")
    return task

def invoke_kagent(task: str, response_file: Path) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": f"coordinator-{uuid.uuid4()}",
        "method": "message/send",
        "params": {
            "configuration": {"blocking": True},
            "message": {
                "messageId": f"msg-{uuid.uuid4()}",
                "role": "user",
                "parts": [{"kind": "text", "text": task}],
            }
        },
    }

    try:
        response = requests.post(
            KAGENT_AGENT_URL,
            headers={"Content-Type": "application/json", "A2A-Version": KAGENT_PROTOCOL_VERSION},
            json=payload,
            timeout=KAGENT_TIMEOUT,
        )
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        body = {"transport_error": f"{type(exc).__name__}: {exc}"}
        write_json(response_file, body)
        return {"state": None, "text": "", "events": [], "error": body["transport_error"]}

    write_json(response_file, body)
    try:
        return parse_kagent_response(body)
    except (TypeError, ValueError, AttributeError, KeyError) as exc:
        return {"state": None, "text": "", "events": [], "error": f"invalid_a2a_response: {type(exc).__name__}: {exc}"}


def parse_kagent_response(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {"state": None, "text": "", "events": [], "error": "invalid_a2a_response"}
    if body.get("error"):
        return {"state": None, "text": "", "events": [], "error": str(body["error"])}

    result = body.get("result") or {}
    if not isinstance(result, dict):
        return {"state": None, "text": "", "events": [], "error": "invalid_a2a_result"}
    state = (result.get("status") or {}).get("state")
    texts: list[str] = []
    events: list[dict[str, Any]] = []

    for artifact in result.get("artifacts") or []:
        for part in artifact.get("parts") or []:
            if part.get("kind") == "text" and part.get("text"):
                texts.append(str(part["text"]))

    for message in result.get("history") or []:
        for part in message.get("parts") or []:
            metadata = part.get("metadata") or {}
            kind = metadata.get("adk_type") or metadata.get("kagent_type")
            if kind in {"function_call", "function_response"}:
                events.append({"type": kind, "data": part.get("data") or {}})

    error = None if state == "completed" else f"a2a_task_not_completed:{state}"
    return {
        "state": state,
        "text": "\n\n".join(texts).strip(),
        "events": events,
        "error": error,
        "task_id": result.get("id"),
        "context_id": result.get("contextId"),
    }


def response_value(raw: Any) -> tuple[str, bool, str | None]:
    if raw is None:
        return "", False, "missing_tool_response"

    if isinstance(raw, dict):
        if raw.get("isError") is True or raw.get("is_error") is True or raw.get("error"):
            return str(raw.get("output") or raw.get("error") or raw), False, "tool_error"
        if raw.get("output") is not None:
            return str(raw["output"]).strip(), True, None
        if raw.get("content"):
            text = "\n".join(
                str(item["text"])
                for item in raw["content"]
                if isinstance(item, dict) and item.get("text") is not None
            )
            return text.strip(), True, None
        return json.dumps(raw, ensure_ascii=False, default=str), True, None

    return str(raw).strip(), True, None


def extract_tool_evidence(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    calls = [event for event in events if event["type"] == "function_call"]
    responses = [event for event in events if event["type"] == "function_response"]
    used: set[int] = set()
    evidence: list[dict[str, Any]] = []

    for call in calls:
        call_data = call["data"]
        tool = str(call_data.get("name") or "unknown")
        call_id = call_data.get("id") or call_data.get("functionCallID") or call_data.get("function_call_id")

        exact = []
        legacy = []
        for index, candidate in enumerate(responses):
            if index in used:
                continue

            data = candidate["data"]
            response_id = data.get("id") or data.get("functionCallID") or data.get("function_call_id")

            if call_id and response_id and call_id == response_id:
                if data.get("name") in (None, "", tool):
                    exact.append((index, candidate))
            elif not call_id and not response_id and data.get("name") == tool:
                legacy.append((index, candidate))

        # A matching name must never override mismatched IDs. Legacy matching
        # is only safe when both sides omit IDs and the tool occurs once.
        legacy_calls = sum(1 for event in calls if event["data"].get("name") == tool)
        matches = exact or (legacy if legacy_calls == 1 else [])
        match_index, match = matches[0] if len(matches) == 1 else (None, None)

        if match_index is not None:
            used.add(match_index)

        response_data = match["data"] if match else {}
        raw = response_data.get("response") if match else None
        text, succeeded, error = response_value(raw)

        evidence.append({
            "tool": tool,
            "call": call_data,
            "response": response_data if match else None,
            "succeeded": bool(match) and succeeded,
            "error": error if match else "missing_function_response",
            "raw_output": text,
            "source": "kagent_a2a_result_history",
        })

    return evidence


NAMESPACED_KAGENT_TOOLS = {
    "k8s_get_pod_logs",
    "k8s_get_events",
    "k8s_get_resources",
    "k8s_describe_resource",
    "k8s_get_resource_yaml",
    "k8s_check_service_connectivity",
}

# Coordinator-side safety policy. Kagent remains free to choose its investigative
# path, but write-capable actions are never accepted as evidence. Actual cluster
# enforcement should also be provided by read-only Kubernetes RBAC.
FORBIDDEN_KAGENT_TOOL_TOKENS = (
    "patch",
    "create",
    "delete",
    "apply",
    "update",
    "replace",
    "restart",
    "scale",
    "rollout",
    "exec",
    "run_command",
)


def is_forbidden_write_tool(tool: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", (tool or "").lower()).strip("_")
    parts = set(normalized.split("_"))
    return any(token in parts or token in normalized for token in FORBIDDEN_KAGENT_TOOL_TOKENS)


def validate_tool_scope(
    tool_evidence: dict[str, Any], target: dict[str, str],
    related_resources: set[tuple[str, str]] | None = None,
    pod_containers: list[str] | None = None,
) -> dict[str, Any]:
    item = dict(tool_evidence)
    call = item.get("call") or {}
    args = call.get("args") or {}
    tool = str(item.get("tool") or "")
    if not isinstance(args, dict):
        args = {}
        scope_error = "invalid_tool_arguments"
    else:
        scope_error = None
    kind = str(args.get("resource_type") or "").lower().split(".")[0]
    aliases = {"pods": "pod", "po": "pod", "nodes": "node", "no": "node",
               "persistentvolumes": "persistentvolume", "pv": "persistentvolume",
               "namespaces": "namespace", "ns": "namespace"}
    kind = aliases.get(kind, kind)
    cluster_resource = kind in {"node", "persistentvolume", "namespace"}
    namespace = args.get("namespace")
    if namespace not in (None, "") and str(namespace) != target["namespace"]:
        scope_error = f"namespace_mismatch:{namespace}"
    elif tool in NAMESPACED_KAGENT_TOOLS and not cluster_resource and namespace in (None, ""):
        scope_error = "missing_namespace"
    for key in ("pod_name", "pod"):
        if args.get(key) not in (None, "", target["pod"]):
            scope_error = f"pod_mismatch:{args[key]}"
    if kind == "pod" and args.get("resource_name") not in (None, "", target["pod"]):
        scope_error = f"pod_mismatch:{args['resource_name']}"
    if args.get("container") not in (None, "", target["container"]):
        scope_error = f"container_mismatch:{args['container']}"
    if tool == "k8s_get_pod_logs":
        if not (args.get("pod_name") or args.get("pod")):
            scope_error = "missing_pod_name"
        if len(pod_containers or []) > 1 and not args.get("container"):
            scope_error = "missing_container_for_multicontainer_pod"
    if cluster_resource:
        identity = (kind, str(args.get("resource_name") or ""))
        if identity not in (related_resources or set()):
            scope_error = "unverified_cluster_resource_relation"

    forbidden = is_forbidden_write_tool(tool)
    recognized_read = tool.startswith(("k8s_get_", "k8s_describe_"))
    policy_error = "forbidden_write_tool" if forbidden else (
        None if recognized_read else "unverified_read_only_tool"
    )
    item.update({
        "scope_ok": scope_error is None, "scope_error": scope_error,
        "scope_validation": "namespace_and_explicit_target_parameters",
        "read_only_ok": policy_error is None, "policy_error": policy_error,
        "evidence_eligible": item.get("succeeded") is True and scope_error is None and policy_error is None,
    })
    return item


def kagent_completion_state(model_text: str) -> str | None:
    """
    Read the final non-empty line as the Kagent control marker.

    The marker remains protocol-only: mentions inside explanatory prose do not
    count. Common Markdown wrappers around the final marker are tolerated
    because some LLMs format a standalone final token automatically.
    """
    lines = [
        line.strip()
        for line in str(model_text or "").splitlines()
        if line.strip()
    ]
    if not lines:
        return None

    marker = lines[-1]

    wrappers = (
        ("**", "**"),
        ("__", "__"),
        ("`", "`"),
    )

    for left, right in wrappers:
        if (
            marker.startswith(left)
            and marker.endswith(right)
            and len(marker) > len(left) + len(right)
        ):
            marker = marker[len(left):-len(right)].strip()
            break

    if marker == "INVESTIGATION_COMPLETE":
        return "complete"

    if marker == "INVESTIGATION_INCOMPLETE":
        return "incomplete"

    return None


def kagent_completed(model_text: str) -> bool:
    return kagent_completion_state(model_text) == "complete"


def has_target_scope_violation(tool_evidence: list[dict[str, Any]]) -> bool:
    return any(item.get("scope_ok") is False or item.get("read_only_ok") is False for item in tool_evidence)


def summarize_attempt_for_retry(attempt: dict[str, Any]) -> dict[str, Any]:
    return {
        "attempt": attempt.get("attempt"),
        "state": attempt.get("state"),
        "error": attempt.get("error"),
        "completion_state": attempt.get("completion_state"),
        "completion_protocol_ok": attempt.get("completion_protocol_ok"),
        "investigation_complete": attempt.get("investigation_complete"),
        "scope_retry_required": attempt.get("scope_retry_required"),
        "tool_evidence": [
            {
                "tool": item.get("tool"),
                "args": (item.get("call") or {}).get("args") or {},
                "succeeded": item.get("succeeded"),
                "scope_ok": item.get("scope_ok"),
                "scope_error": item.get("scope_error"),
                "read_only_ok": item.get("read_only_ok"),
                "policy_error": item.get("policy_error"),
                "error": item.get("error"),
                "raw_output": item.get("raw_output"),
            }
            for item in attempt.get("tool_evidence") or []
        ],
        "model_text_non_authoritative": attempt.get("model_text_non_authoritative"),
    }


def run_kagent(initial_brief: dict[str, Any], case_dir: Path) -> dict[str, Any]:
    case_dir.mkdir(parents=True, exist_ok=True)
    target = initial_brief["target"]
    api = (initial_brief.get("evidence") or {}).get("kubernetes_api") or {}
    related_resources = {("namespace", target["namespace"])}
    if api.get("node"):
        related_resources.add(("node", str(api["node"])))
    for claim in api.get("persistent_volume_claims") or []:
        volume = claim.get("volume_name") or (claim.get("persistent_volume") or {}).get("name")
        if volume:
            related_resources.add(("persistentvolume", str(volume)))
    pod_containers = [item["name"] for item in api.get("containers", []) if item.get("name")]
    attempts: list[dict[str, Any]] = []
    successful: list[dict[str, Any]] = []

    for number in range(1, KAGENT_MAX_ATTEMPTS + 1):
        previous_attempts = [summarize_attempt_for_retry(item) for item in attempts]
        try:
            task = build_kagent_task(initial_brief, previous_attempts)
        except Exception as exc:
            attempts.append({"attempt": number, "state": None, "error": f"{type(exc).__name__}: {exc}",
                             "tool_evidence": [], "successful_tool_count": 0, "investigation_complete": False,
                             "completion_protocol_ok": False, "scope_retry_required": False})
            break

        task_file = case_dir / f"kagent_task_{number}.txt"
        response_file = case_dir / f"kagent_response_{number}.json"
        task_file.write_text(task, encoding="utf-8")

        print(f"Kagent attempt {number}/{KAGENT_MAX_ATTEMPTS}: waiting for A2A response | response_wait={KAGENT_WAIT_LABEL} | task characters={len(task)}", flush=True)
        started = time.monotonic()
        result = invoke_kagent(task, response_file)
        extracted = extract_tool_evidence(result["events"])
        tools = [validate_tool_scope(item, target, related_resources, pod_containers) for item in extracted]
        good = [item for item in tools if item["evidence_eligible"]]
        successful.extend(good)

        scope_retry_required = has_target_scope_violation(tools)
        completion_state = kagent_completion_state(result["text"])
        attempt = {
            "attempt": number,
            "state": result["state"],
            "error": result["error"],
            "tool_evidence": tools,
            "successful_tool_count": len(good),
            "completion_state": completion_state,
            "completion_protocol_ok": completion_state is not None,
            "investigation_complete": completion_state == "complete" and result.get("state") == "completed" and not result.get("error"),
            "scope_retry_required": scope_retry_required,
            "model_text_non_authoritative": result["text"],
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "task_id": result.get("task_id"), "context_id": result.get("context_id"),
        }
        attempts.append(attempt)
        write_json(case_dir / f"kagent_attempt_{number}.json", attempt)
        print(f"Kagent attempt {number}: state={attempt['state']} | accepted tools={len(good)} | error={attempt['error']}", flush=True)
        if result.get("error"):
            # A timed-out blocking request may still be executing remotely.
            # Record it; do not silently submit a duplicate investigation.
            break

        # A model completion marker is not enough if the same attempt used an
        # invalid namespace. The coordinator owns WHERE to investigate, so it
        # forces another adaptive attempt (when available) to repair the scope.
        if successful and attempt["investigation_complete"] and not scope_retry_required:
            break

    deduplicated: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in successful:
        tool = str(item.get("tool") or "")
        args = dict((item.get("call") or {}).get("args") or {})

        # A different log tail length does not make the same returned log evidence new.
        if tool == "k8s_get_pod_logs":
            args.pop("tail_lines", None)

        signature = json.dumps(
            {
                "tool": tool,
                "args": args,
                "raw_output": item.get("raw_output"),
            },
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )

        if signature not in seen:
            seen.add(signature)
            deduplicated.append(item)

    limitations: list[str] = []
    if not deduplicated:
        limitations.append("Kagent produced no successful in-scope Kubernetes tool evidence.")

    if attempts and not attempts[-1].get("investigation_complete"):
        limitations.append("Kagent did not explicitly mark the investigation as complete within the allowed attempts.")

    if attempts and not attempts[-1].get("completion_protocol_ok"):
        limitations.append("Kagent did not place a valid investigation control marker on the final non-empty line.")

    for attempt in attempts:
        if attempt.get("error"):
            limitations.append(f"Kagent attempt {attempt['attempt']}: {attempt['error']}")

        for item in attempt.get("tool_evidence") or []:
            if item.get("read_only_ok") is False:
                limitations.append(
                    f"Kagent tool {item['tool']}: {item.get('policy_error')}"
                )
            elif item.get("scope_ok") is False:
                limitations.append(
                    f"Kagent tool {item['tool']}: invalid_scope ({item.get('scope_error')})"
                )
            elif item.get("succeeded") is not True:
                limitations.append(f"Kagent tool {item['tool']}: {item.get('error')}")

    final_attempt = attempts[-1] if attempts else {}
    final_scope_ok = bool(final_attempt) and not bool(final_attempt.get("scope_retry_required"))
    final_complete = bool(
        deduplicated
        and final_attempt.get("investigation_complete")
        and final_scope_ok
    )

    return {
        "role": "adaptive_kubernetes_investigation",
        "mode": "read_only",
        "transport": "A2A JSON-RPC",
        "target": target,
        "investigation_complete": final_complete,
        "final_target_scope_ok": final_scope_ok,
        "successful_tool_count": len(deduplicated),
        "successful_tool_evidence": deduplicated,
        "attempts": attempts,
        "limitations": list(dict.fromkeys(limitations)),
    }
