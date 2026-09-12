"""Bounded, audit-friendly normalization for collected incident evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Any

import yaml


_VOLATILE_KEYS = {
    "managedfields",
    "resourceversion",
    "selflink",
}
# Character limits cover the supplied payload, not the model's hidden prompt or
# tool definitions. Component budgets are targets; this is the hard ceiling.
MAX_EVIDENCE_CHARACTERS = int(os.getenv("EVIDENCE_MAX_CHARACTERS", "32000"))
_SENSITIVE_KEY = re.compile(
    r"(^|_)(api_?key|authorization|bearer|client_secret|credential|passwd|password|"
    r"private_key|secret|token)($|_)",
    re.IGNORECASE,
)
_HIGH_SIGNAL = re.compile(
    r"\b(error|failed|failure|fatal|warning|critical|timeout|deadline|oom|"
    r"oomkilled|crash|backoff|restart|unhealthy|notready|evicted|throttl|denied|"
    r"invalid|exception|pending|terminated|killed|unable|refused|unavailable|"
    r"crashloopbackoff|imagepullbackoff|errimagepull)\b",
    re.IGNORECASE,
)
_IDENTITY_LINE = re.compile(
    r"^\s*(name|namespace|kind|status|reason|message|node|image|ready|restarts?|"
    r"limits?|requests?|state|last state|conditions?|events?)\s*:",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}")
_ASSIGNED_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|authorization|client[_-]?secret|credential|passwd|"
    r"password|private[_-]?key|secret|token)\s*[:=]\s*([^\s,;]+)"
)


def _stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(value: Any) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()


def _normalize_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _redact_text(value: str) -> str:
    value = _PRIVATE_KEY.sub("[redacted private key]", value)
    value = _BEARER.sub("Bearer [redacted]", value)
    return _ASSIGNED_SECRET.sub(lambda match: f"{match.group(1)}=[redacted]", value)


def _sanitize(value: Any, *, parent_key: str = "") -> Any:
    """Remove volatile metadata and redact credentials without mutating input."""
    if isinstance(value, Mapping):
        kind = str(value.get("kind") or "").lower()
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            normalized = _normalize_key(key)
            if normalized.replace("_", "") in _VOLATILE_KEYS:
                continue
            if key == "kubectl.kubernetes.io/last-applied-configuration":
                continue
            # Resource references are diagnostic identities, not secret values.
            reference = normalized.replace("_", "") in {
                "secretref", "secretkeyref", "secretname", "imagepullsecrets",
            } or (normalized == "secret" and isinstance(item, Mapping))
            env_secret = key == "value" and _SENSITIVE_KEY.search(
                _normalize_key(value.get("name", ""))
            )
            diagnostic_token_field = normalized.replace("_", "") in {
                "automountserviceaccounttoken", "serviceaccounttoken",
            } and isinstance(item, (bool, Mapping, type(None)))
            if env_secret or (_SENSITIVE_KEY.search(normalized) and not reference and not diagnostic_token_field):
                result[key] = "[redacted]"
                continue
            if kind == "secret" and normalized in {"data", "stringdata"}:
                result[key] = "[redacted]"
                continue
            result[key] = _sanitize(item, parent_key=normalized)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitize(item, parent_key=parent_key) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(str(value))


def _parse_raw(raw: Any) -> tuple[Any, str]:
    if not isinstance(raw, str):
        return raw, "structured"
    stripped = raw.strip()
    if not stripped:
        return "", "text"
    if stripped.startswith(("{", "[")):
        try:
            return json.loads(stripped), "json"
        except (json.JSONDecodeError, TypeError):
            pass
    if re.search(r"(?m)^(apiVersion|kind|metadata|spec|status):\s*", stripped):
        try:
            parsed = yaml.safe_load(stripped)
            if isinstance(parsed, (dict, list)):
                return parsed, "yaml"
        except yaml.YAMLError:
            pass
    return stripped, "text"


def _event_value(event: Mapping[str, Any], *names: str) -> Any:
    normalized = {_normalize_key(key): value for key, value in event.items()}
    for name in names:
        value = normalized.get(_normalize_key(name))
        if value not in (None, "", [], {}):
            return value
    return None


def _looks_like_event(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    keys = {_normalize_key(key) for key in value}
    if "status" in keys and keys & {"last_transition_time", "lasttransitiontime"}:
        return False
    return "reason" in keys and bool(keys & {"message", "note"})


def _event_fingerprint(event: Mapping[str, Any]) -> str:
    regarding = _event_value(event, "involvedObject", "regarding")
    if not isinstance(regarding, Mapping):
        regarding = {}
    metadata = event.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    identity = {
        "namespace": (
            regarding.get("namespace")
            or metadata.get("namespace")
            or _event_value(event, "namespace", "kube_namespace")
            or ""
        ),
        "kind": regarding.get("kind") or _event_value(event, "object_kind") or "",
        "name": (
            regarding.get("name")
            or _event_value(event, "object_name", "pod_name", "pod")
            or ""
        ),
        "type": _event_value(event, "type") or "",
        "reason": _event_value(event, "reason") or "",
        "message": re.sub(
            r"\s+", " ", str(_event_value(event, "message", "note") or "").strip().lower()
        ),
    }
    return "event:" + _sha256(identity)


def _event_content_fingerprint(event: Mapping[str, Any]) -> str:
    identity = {
        "type": _event_value(event, "type") or "",
        "reason": _event_value(event, "reason") or "",
        "message": re.sub(
            r"\s+", " ", str(_event_value(event, "message", "note") or "").strip().lower()
        ),
    }
    return "event-content:" + _sha256(identity)


def _event_fingerprints(event: Mapping[str, Any]) -> set[str]:
    return {
        _event_fingerprint(event),
        _event_content_fingerprint(event),
    }


def _compact_event(event: Mapping[str, Any]) -> dict[str, Any]:
    regarding = _event_value(event, "involvedObject", "regarding")
    if not isinstance(regarding, Mapping):
        regarding = {}
    metadata = event.get("metadata")
    if not isinstance(metadata, Mapping):
        metadata = {}
    compact = {
        "evidence_id": _event_value(event, "evidence_id") or _event_fingerprint(event),
        "namespace": regarding.get("namespace") or metadata.get("namespace") or event.get("namespace"),
        "object_kind": regarding.get("kind") or event.get("object_kind"),
        "object_name": regarding.get("name") or event.get("object_name"),
        "type": _event_value(event, "type"),
        "reason": _event_value(event, "reason"),
        "message": _event_value(event, "message", "note"),
        "count": _event_value(event, "count", "deprecatedCount") if not isinstance(event.get("series"), Mapping)
        else event["series"].get("count"),
        "count_semantics": _event_value(event, "count_semantics") or "aggregated_occurrence_count",
        "first_seen": _event_value(
            event, "firstTimestamp", "first_timestamp", "eventTime", "event_time",
            "first_seen"
        ),
        "last_seen": _event_value(
            event, "lastTimestamp", "last_timestamp", "eventTime", "event_time",
            "last_seen"
        ),
        "action": _event_value(event, "action"),
    }
    return {key: _sanitize(value) for key, value in compact.items() if value not in (None, "")}


def _line_fingerprint(line: str) -> str:
    normalized = re.sub(r"\s+", " ", line.strip().lower())
    normalized = re.sub(r"\b\d{4}-\d\d-\d\d[t ][0-9:.+z-]+\b", "<timestamp>", normalized)
    return "line:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def collect_semantic_fingerprints(value: Any, *, parent_key: str = "") -> set[str]:
    """Collect stable event and log-line identities already present in evidence."""
    found: set[str] = set()
    if _looks_like_event(value):
        found.update(_event_fingerprints(value))
    if isinstance(value, Mapping):
        for key, item in value.items():
            found.update(collect_semantic_fingerprints(item, parent_key=_normalize_key(key)))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            found.update(collect_semantic_fingerprints(item, parent_key=parent_key))
    elif isinstance(value, str) and any(
        token in parent_key for token in ("line", "log", "message", "output")
    ):
        for line in value.splitlines():
            if line.strip():
                found.add(_line_fingerprint(line))
    return found


def _signal_score(value: Any) -> int:
    text = _stable_json(value) if not isinstance(value, str) else value
    score = 10 if _HIGH_SIGNAL.search(text) else 0
    lowered = text.lower()
    if any(token in lowered for token in ("false", "unknown", "nonzero", "not ready")):
        score += 3
    return score


def _key_score(key: str) -> int:
    normalized = _normalize_key(key)
    critical = {
        "evidence_id", "error", "errors", "collection_limitations", "limitations",
        "conditions", "state", "last_state", "events", "containers", "measurements",
        "deployment", "replica_set", "node_details", "persistent_volume_claims",
        "persistent_volume", "phase", "restart_count", "restartcount",
    }
    high = {
        "reason", "message", "status", "container_statuses", "resources", "limits",
        "requests", "sample_lines", "target", "name", "namespace", "kind", "image",
        "ready", "value", "query", "capacity", "allocatable", "requested_storage",
        "storage_class_name", "volume_name", "access_modes", "volume_mode",
        "workload_controller", "count", "count_semantics", "restart_count_semantics",
    }
    if normalized in critical:
        return 30
    return 20 if normalized in high else 0


def _compact_events(
    events: Sequence[Any],
    *,
    seen: set[str],
    max_items: int,
) -> dict[str, Any]:
    unique: list[dict[str, Any]] = []
    duplicates = 0
    local_seen: set[str] = set()
    for item in events:
        if not isinstance(item, Mapping):
            continue
        compact = _compact_event(item)
        # Counts and observation times belong to the snapshot. An earlier
        # observation of the same event must not erase a later update.
        fingerprint = _sha256(compact)
        if fingerprint in local_seen:
            duplicates += 1
            continue
        local_seen.add(fingerprint)
        unique.append(compact)
    unique.sort(key=_signal_score, reverse=True)
    selected = unique[:max_items]
    # Hoist an identical object identity once; counts/times remain per event.
    # For multi-object queries, each event keeps its own explicit identity.
    scope = {}
    if selected:
        for key in ("namespace", "object_kind", "object_name"):
            if key in selected[0] and all(row.get(key) == selected[0][key] for row in selected):
                scope[key] = selected[0][key]
        selected = [{key: value for key, value in row.items() if key not in scope} for row in selected]
    result = {
        "format": "kubernetes_events",
        "input_count": len(events),
        "events": selected,
        "duplicate_count": duplicates,
        "omitted_count": max(0, len(unique) - len(selected)),
    }
    if scope:
        result["event_scope"] = scope
    return result


def _compact_structure(
    value: Any,
    *,
    seen: set[str],
    depth: int,
    max_depth: int,
    max_items: int,
    max_string: int,
) -> Any:
    if depth >= max_depth:
        if isinstance(value, Mapping):
            return {"summary": f"mapping with {len(value)} fields", "truncated": True}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return {"summary": f"sequence with {len(value)} items", "truncated": True}
    if isinstance(value, Mapping):
        if isinstance(value.get("items"), list) and value["items"] and all(
            _looks_like_event(item) for item in value["items"]
        ):
            return _compact_events(value["items"], seen=seen, max_items=max_items)
        ordered = sorted(
            value.items(),
            key=lambda pair: (_key_score(str(pair[0])) + _signal_score(pair[1])),
            reverse=True,
        )
        selected = ordered[:max_items]
        result = {
            str(key): _compact_structure(
                item,
                seen=seen,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for key, item in selected
        }
        if len(ordered) > len(selected):
            result["_omitted_fields"] = len(ordered) - len(selected)
        return result
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if value and all(_looks_like_event(item) for item in value):
            return _compact_events(value, seen=seen, max_items=max_items)
        unique: list[Any] = []
        signatures: set[str] = set()
        for item in value:
            signature = _sha256(item)
            if signature in signatures:
                continue
            signatures.add(signature)
            unique.append(item)
        ranked = sorted(enumerate(unique), key=lambda pair: _signal_score(pair[1]), reverse=True)
        selected_indices = sorted(index for index, _ in ranked[:max_items])
        result = [
            _compact_structure(
                unique[index],
                seen=seen,
                depth=depth + 1,
                max_depth=max_depth,
                max_items=max_items,
                max_string=max_string,
            )
            for index in selected_indices
        ]
        if len(unique) > len(result):
            result.append({"_omitted_items": len(unique) - len(result)})
        return result
    if isinstance(value, str):
        cleaned = _redact_text(value)
        if len(cleaned) <= max_string:
            return cleaned
        return cleaned[:max_string] + f"… [truncated {len(cleaned) - max_string} chars]"
    return value


def _compact_text(
    text: str,
    *,
    seen: set[str],
    max_lines: int,
    max_chars: int,
) -> dict[str, Any]:
    raw_lines = [_redact_text(line.rstrip()) for line in text.splitlines() if line.strip()]
    unique: list[tuple[int, str]] = []
    signatures: set[str] = set()
    duplicate_count = 0
    counts: dict[str, int] = {}
    indented = any(line[:1].isspace() for line in raw_lines)
    for index, line in enumerate(raw_lines):
        # Keep independent observations and case-sensitive log messages.
        # Repeated indented text can belong to different containers/sections.
        fingerprint = str(index) if indented else line
        counts[fingerprint] = counts.get(fingerprint, 0) + 1
        if fingerprint in signatures:
            duplicate_count += 1
            continue
        signatures.add(fingerprint)
        unique.append((index, line))
    important = [
        pair for pair in unique if _HIGH_SIGNAL.search(pair[1]) or _IDENTITY_LINE.search(pair[1])
    ]
    selected: list[tuple[int, str]] = []
    selected_indexes: set[int] = set()
    for pair in unique[:1] + important + unique[:8] + unique[-5:]:
        if pair[0] not in selected_indexes:
            selected.append(pair)
            selected_indexes.add(pair[0])
        if len(selected) >= max_lines:
            break
    # Preserve section headers for selected describe/log lines.
    if indented:
        parents: list[tuple[int, str]] = []
        wanted = set(selected_indexes)
        for index, line in unique:
            indent = len(line) - len(line.lstrip())
            while parents and len(parents[-1][1]) - len(parents[-1][1].lstrip()) >= indent:
                parents.pop()
            if index in wanted:
                for parent in parents:
                    if parent[0] not in selected_indexes:
                        selected.append(parent)
                        selected_indexes.add(parent[0])
            if line.rstrip().endswith(":"):
                parents.append((index, line))
    selected.sort(key=lambda pair: pair[0])
    lines: list[str] = []
    used = 0
    truncated = False
    for _, line in selected:
        remaining = max_chars - used
        if remaining <= 0:
            break
        rendered = line if len(line) <= remaining else line[:max(0, remaining - 14)] + " …[truncated]"
        truncated = truncated or len(line) > len(rendered)
        lines.append(rendered)
        used += len(rendered) + 1
    return {
        "format": "text",
        "input_lines": len(raw_lines),
        "selected_lines": lines,
        "duplicate_count": duplicate_count,
        "omitted_count": max(0, len(unique) - len(lines)),
        "selected_line_counts": [counts[str(index) if indented else line] for index, line in selected[:len(lines)]],
        "truncated": truncated,
    }


class EvidenceBudgetError(ValueError):
    """The budget cannot hold the protected facts; do not silently erase them."""


def check_payload_size(value: Any, label: str) -> int:
    size = len(value if isinstance(value, str) else _stable_json(value))
    if size > MAX_EVIDENCE_CHARACTERS:
        raise EvidenceBudgetError(
            f"{label} requires {size} characters; EVIDENCE_MAX_CHARACTERS="
            f"{MAX_EVIDENCE_CHARACTERS}. Full source evidence remains in the case artifacts."
        )
    return size


def _without_nulls(value: Any) -> Any:
    """Keep meaningful empty selectors, strings, and container-state objects."""
    if isinstance(value, Mapping):
        return {str(key): _without_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_without_nulls(item) for item in value]
    return value


def sanitize_evidence(value: Any) -> Any:
    return _without_nulls(_sanitize(value))


def _nonempty(value: Any) -> Any:
    """Drop null/default noise, preserving False, zero and empty query results."""
    if isinstance(value, Mapping):
        return {
            str(key): _nonempty(item)
            for key, item in value.items()
            if item not in (None, "", [], {}) or key in {
                "error", "sample_lines", "queries", "events", "measurements",
                "containers", "items", "environment_variable_names",
            }
        }
    if isinstance(value, list):
        return [_nonempty(item) for item in value]
    return value


def _pick(value: Any, fields: Sequence[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return _nonempty({key: _sanitize(value[key]) for key in fields if key in value})


def _conditions(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [_pick(item, (
        "type", "status", "reason", "lastTransitionTime", "last_transition_time",
        "lastUpdateTime", "last_update_time",
    )) for item in value if isinstance(item, Mapping)]


def _container_state(value: Any) -> dict[str, Any]:
    result = _pick(value, (
        "name", "image", "ready", "started", "restartCount", "restart_count",
        "restart_count_semantics", "evidence_id", "resources",
    ))
    for key in ("state", "lastState", "last_state"):
        if isinstance(value, Mapping) and isinstance(value.get(key), Mapping):
            result[key] = {
                state: _pick(details, (
                    "reason", "message", "exitCode", "exit_code", "signal",
                    "startedAt", "started_at", "finishedAt", "finished_at",
                ))
                for state, details in value[key].items() if isinstance(details, Mapping)
            }
    if "restartCount" in result and "restart_count_semantics" not in result:
        result["restart_count_semantics"] = "cumulative_since_container_creation"
    return result


def _container_spec(value: Any) -> dict[str, Any]:
    # Commands, probes and resource quantities are kept as complete structures.
    result = _pick(value, (
        "name", "image", "command", "args", "ports", "resources",
        "livenessProbe", "readinessProbe", "startupProbe",
        "liveness_probe", "readiness_probe", "startup_probe",
        "volumeMounts", "volume_mounts", "securityContext", "security_context",
        "environment_variable_names", "envFrom", "env_from",
    ))
    if isinstance(value, Mapping) and isinstance(value.get("env"), list):
        result["env"] = []
        for entry in value["env"]:
            row = _pick(entry, ("name", "value", "valueFrom"))
            if _SENSITIVE_KEY.search(_normalize_key(row.get("name", ""))) and "value" in row:
                row["value"] = "[redacted]"
            result["env"].append(row)
    return result


def _pod_spec(value: Any) -> dict[str, Any]:
    result = _pick(value, (
        "volumes", "nodeName", "node_name", "nodeSelector", "node_selector",
        "serviceAccountName", "service_account_name", "restartPolicy", "restart_policy",
        "securityContext", "security_context", "affinity", "tolerations",
        "terminationGracePeriodSeconds", "termination_grace_period_seconds",
    ))
    if not isinstance(value, Mapping):
        return result
    for key in ("containers", "initContainers", "init_containers"):
        if isinstance(value.get(key), list):
            result[key] = [_container_spec(item) for item in value[key]]
    return result


def _resource_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    """Project native Kubernetes objects without cutting their nesting depth."""
    kind = str(value.get("kind") or "")
    metadata = _pick(value.get("metadata"), (
        "name", "namespace", "generation", "ownerReferences", "annotations",
    ))
    result = _pick(value, ("apiVersion", "kind"))
    result["metadata"] = metadata
    spec = value.get("spec") or {}
    status = value.get("status") or {}
    if kind == "Pod":
        result["spec"] = _pod_spec(spec)
    elif kind in {"Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job"}:
        result["spec"] = _pick(spec, (
            "replicas", "selector", "strategy", "updateStrategy", "serviceName",
            "volumeClaimTemplates", "completions", "parallelism", "backoffLimit",
        ))
        template = spec.get("template") or {}
        result["spec"]["template"] = {"spec": _pod_spec(template.get("spec") or {})}
    else:
        result["spec"] = _nonempty(_sanitize(spec))
        # Endpoints/EndpointSlices and other objects may carry data outside spec.
        for key in ("subsets", "endpoints", "ports", "addressType", "data", "binaryData"):
            if key in value:
                result[key] = _nonempty(_sanitize(value[key]))
    result["status"] = _pick(status, (
        "phase", "reason", "message", "observedGeneration", "replicas",
        "readyReplicas", "availableReplicas", "unavailableReplicas", "updatedReplicas",
        "currentReplicas", "currentNumberScheduled", "desiredNumberScheduled",
        "numberReady", "numberAvailable", "numberUnavailable", "capacity", "allocatable",
        "accessModes", "podIP", "hostIP", "startTime", "succeeded", "failed", "active",
    ))
    if "conditions" in status:
        result["status"]["conditions"] = _conditions(status["conditions"])
    for key in ("containerStatuses", "initContainerStatuses"):
        if key in status:
            result["status"][key] = [_container_state(item) for item in status[key]]
    # Unknown CRDs keep their fields rather than assuming a built-in schema.
    known = {"Pod", "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job",
             "Service", "Endpoints", "EndpointSlice", "PersistentVolumeClaim",
             "PersistentVolume", "Node", "ConfigMap", "Secret"}
    if kind not in known:
        return _nonempty(_sanitize(value))
    return _nonempty(result)


def _fit_text(text: str, budget: int) -> dict[str, Any]:
    allowance = max(0, budget - 180)
    while allowance >= 0:
        result = _compact_text(text, seen=set(), max_lines=40, max_chars=allowance)
        size = len(_stable_json(result))
        if size <= budget and (result["selected_lines"] or not text.strip()):
            return result
        allowance -= max(1, size - budget)
    raise EvidenceBudgetError(f"Text evidence needs more than {budget} characters including provenance.")


def _describe_fields(text: str) -> list[dict[str, str]]:
    """Keep describe status values with their container/section path."""
    if not re.search(r"(?m)^Name:\s+", text) or not re.search(r"(?m)^Containers:\s*$", text):
        return []
    fields = []
    stack: list[tuple[int, str]] = []
    important = {"Name", "Namespace", "Status", "State", "Last State", "Reason",
                 "Exit Code", "Ready", "Restart Count", "Liveness", "Readiness",
                 "Startup", "Port", "Ports", "Image", "Started", "Finished"}
    for line in text.splitlines():
        match = re.match(r"^(\s*)([^:]+):\s*(.*)$", line)
        if not match:
            continue
        indent, label, value = len(match[1]), match[2].strip(), match[3].strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        context = "/".join(key for _, key in stack)
        if value and (label in important or any(key in {"Limits", "Requests"} for _, key in stack)):
            fields.append({"path": context + "/" + label, "value": _redact_text(value)})
        stack.append((indent, label))
    return fields


def compact_value(value: Any, *, seen: set[str] | None = None, budget: int = 4200) -> Any:
    """Keep typed facts and units together; never emit disconnected JSON lines.

    `seen` is accepted for compatibility. Deduplication is local to each source,
    because observing the same message elsewhere does not preserve its provenance.
    """
    parsed, data_format = _parse_raw(value)
    sanitized = _nonempty(_sanitize(parsed))
    if data_format == "text":
        protected_fields = _describe_fields(str(sanitized))
        if protected_fields:
            result = {"format": "kubectl_describe", "status_fields": protected_fields, "partial": True}
            size = len(_stable_json(result))
            if size > budget:
                raise EvidenceBudgetError(f"Protected describe status needs {size} characters; budget is {budget}.")
            extra = budget - size - 16
            if extra >= 180:
                try:
                    result["excerpt"] = _fit_text(str(sanitized), extra)
                except EvidenceBudgetError:
                    pass
            return result
        return _fit_text(str(sanitized), budget)
    events = None
    if isinstance(sanitized, Mapping) and isinstance(sanitized.get("items"), list):
        items = sanitized["items"]
        if str(sanitized.get("kind")) == "EventList" or (items and all(_looks_like_event(x) for x in items)):
            events = items
    elif isinstance(sanitized, list) and sanitized and all(_looks_like_event(x) for x in sanitized):
        events = sanitized
    if events is not None:
        for count in range(min(len(events), 20), -1, -1):
            content = _compact_events(events, seen=set(), max_items=count)
            wrapped = {"format": data_format, "content": content}
            if len(_stable_json(wrapped)) <= budget and (count or not events):
                return wrapped
        raise EvidenceBudgetError(f"A complete event observation does not fit in {budget} characters.")

    native_resource = isinstance(sanitized, Mapping) and "kind" in sanitized and "metadata" in sanitized
    if native_resource and "items" not in sanitized:
        projected = _resource_summary(sanitized)
        wrapped = {"format": data_format, "content": projected}
        if len(_stable_json(wrapped)) <= budget:
            return wrapped
        raise EvidenceBudgetError(
            f"Protected {sanitized['kind']} fields need {len(_stable_json(wrapped))} characters; budget is {budget}."
        )
    if isinstance(sanitized, Mapping) and isinstance(sanitized.get("items"), list):
        items = [_resource_summary(x) if isinstance(x, Mapping) and "metadata" in x else x for x in sanitized["items"]]
        for count in range(len(items), -1, -1):
            wrapped = {"format": data_format, "content": {
                "kind": sanitized.get("kind", "List"), "items": items[:count],
                "input_count": len(items), "omitted_count": len(items) - count,
            }}
            if len(_stable_json(wrapped)) <= budget and (count or not items):
                return wrapped
        raise EvidenceBudgetError(f"Resource summary does not fit in {budget} characters.")
    wrapped = {"format": data_format, "content": sanitized}
    if len(_stable_json(wrapped)) <= budget:
        return wrapped
    # Generic retry/extension data remains structured, with explicit omissions.
    # Known Kubernetes objects, metrics and initial observations use the typed
    # paths above/below, so their core fields never take this fallback.
    for count in (20, 12, 8, 5, 2):
        content = _compact_structure(sanitized, seen=set(), depth=0, max_depth=24,
                                     max_items=count, max_string=600)
        wrapped = {"format": data_format, "content": content, "partial": True}
        if len(_stable_json(wrapped)) <= budget:
            return wrapped
    raise EvidenceBudgetError(f"Structured evidence does not fit in {budget} characters.")


def _selected_fields(value: Any, fields: Sequence[str]) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        field: _sanitize(value[field])
        for field in fields
        if field in value and value[field] not in (None, "", [], {})
    }


def _kagent_related_kubernetes_resources(value: Mapping[str, Any]) -> dict[str, Any]:
    """Keep bounded diagnostic state for resources related to the selected Pod."""
    replica_set = _selected_fields(value.get("replica_set"), (
        "evidence_id", "kind", "namespace", "name", "generation",
        "desired_replicas", "current_replicas", "ready_replicas",
        "available_replicas", "conditions",
    ))
    deployment = _selected_fields(value.get("deployment"), (
        "evidence_id", "kind", "namespace", "name", "generation",
        "observed_generation", "desired_replicas", "ready_replicas",
        "available_replicas", "updated_replicas", "unavailable_replicas",
        "strategy", "conditions",
    ))
    deployment_source = value.get("deployment")
    if deployment is not None and isinstance(deployment_source, Mapping):
        pod_template = deployment_source.get("pod_template")
        if pod_template not in (None, "", [], {}):
            deployment["pod_template"] = {"format": "structured", "content": _pod_spec(pod_template)}
        if "conditions" in deployment:
            deployment["conditions"] = _conditions(deployment["conditions"])

    node = _selected_fields(value.get("node_details"), (
        "evidence_id", "kind", "name", "unschedulable", "taints",
        "capacity", "allocatable", "conditions",
    ))
    if node is not None and "conditions" in node:
        node["conditions"] = _conditions(node["conditions"])

    claim_rows: list[dict[str, Any]] = []
    raw_claims = value.get("persistent_volume_claims")
    claims = raw_claims if isinstance(raw_claims, list) else []
    for claim in claims[:8]:
        selected = _selected_fields(claim, (
            "evidence_id", "kind", "namespace", "name", "pod_volumes",
            "container_mounts", "api_read_ok", "phase", "storage_class_name",
            "requested_storage", "capacity", "access_modes", "volume_mode",
            "volume_name", "conditions", "usage",
        ))
        if selected is None:
            continue
        volume = _selected_fields(claim.get("persistent_volume"), (
            "evidence_id", "kind", "name", "phase", "storage_class_name",
            "capacity", "access_modes", "volume_mode", "reclaim_policy",
            "mount_options", "node_affinity", "claim_reference",
            "storage_source",
        ))
        if volume is not None:
            selected["persistent_volume"] = volume
        claim_rows.append(selected)

    pod = _selected_fields(value, (
            "evidence_id", "namespace", "pod", "phase", "node",
            "workload_controller", "pod_ip", "start_time",
        )) or {}
    pod["conditions"] = _conditions(value.get("conditions"))
    pod["containers"] = [_container_state(item) for item in value.get("containers", [])]
    result = {
        "pod": pod,
        "replica_set": replica_set,
        "deployment": deployment,
        "node": node,
        "persistent_volume_claims": {
            "input_count": len(claims),
            "selected_count": len(claim_rows),
            "omitted_count": max(0, len(claims) - len(claim_rows)),
            "items": claim_rows,
        },
        "collection_limitations": _sanitize(
            value.get("collection_limitations") or []
        ),
    }
    return {
        key: _nonempty(item)
        for key, item in result.items()
        if item not in (None, "", [], {})
    }


def _prometheus_summary(records: Any) -> list[dict[str, Any]]:
    result = []
    for entry in records if isinstance(records, list) else []:
        if not isinstance(entry, Mapping):
            continue
        evidence = entry.get("evidence") or {}
        risk = entry.get("risk") or {}
        item = _pick(risk, (
            "risk_type", "risk_stage", "detection_source", "namespace", "pod",
            "container", "resource_type", "observed_reason", "observed_value",
            "observed_value_suffix", "threshold", "priority", "detected_at",
            "prometheus_query",
        ))
        item["evidence"] = _pick(evidence, ("source", "role", "ok", "error", "detection_query"))
        item["evidence"]["measurements"] = []
        for observation in evidence.get("measurements") or []:
            row = _pick(observation, ("role", "metric", "ok", "error", "query", "value", "unit", "timestamp"))
            if isinstance(row.get("metric"), Mapping):
                row["metric"] = _pick(row["metric"], ("__name__", "namespace", "pod", "container", "node"))
            item["evidence"]["measurements"].append(row)
        result.append(item)
    return result


def _compact_error(value: Any, *, max_chars: int = 96) -> str:
    """Keep the failure class/status while dropping long request URLs."""
    text = re.sub(r"\s+", " ", _redact_text(str(value))).strip()
    text = re.sub(r"\s+for url:.*$", "", text, flags=re.IGNORECASE)
    if len(text) > max_chars:
        text = text[: max_chars - 14] + " …[truncated]"
    return text


def _loki_summary(value: Any, *, max_lines: int = 8, max_chars: int = 600) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {"source": "loki", "available": False, "queries": []}
    result = _pick(value, ("source", "role", "lookback_minutes", "ok"))
    if value.get("error") not in (None, ""):
        result["error"] = _compact_error(value["error"])
    result["queries"] = []
    for query in value.get("queries") or []:
        # Keep zero-result queries explicit (query + ok + sample_count), but
        # do not spend characters serializing null errors and empty arrays.
        row = _pick(query, ("query", "ok", "sample_count"))
        if query.get("error") not in (None, ""):
            row["error"] = _compact_error(query["error"])
        lines: dict[str, int] = {}
        for line in query.get("sample_lines") or []:
            clean = _redact_text(str(line))
            lines[clean] = lines.get(clean, 0) + 1
        ordered = list(lines)
        selected = ordered[:1]
        ranked = sorted(ordered[1:], key=_signal_score, reverse=True)
        selected.extend(ranked[:max(0, max_lines - len(selected))])
        selected = [line for line in ordered if line in selected]
        rendered = [line if len(line) <= max_chars else
                    line[:max_chars] + f" …[truncated {len(line) - max_chars} chars]"
                    for line in selected]
        if rendered:
            row["sample_lines"] = rendered
            row["sample_line_counts"] = [lines[line] for line in selected]
        duplicate_count = sum(lines.values()) - len(lines)
        omitted_count = len(lines) - len(selected)
        truncated_count = sum(len(line) > max_chars for line in selected)
        if duplicate_count:
            row["duplicate_count"] = duplicate_count
        if omitted_count:
            row["omitted_sample_lines"] = omitted_count
        if truncated_count:
            row["truncated_sample_lines"] = truncated_count
        result["queries"].append(row)
    return result


def _collection_limitations(initial: Any) -> list[str]:
    if not isinstance(initial, Mapping):
        return ["Initial evidence is not a structured collection."]
    limitations = []
    api = initial.get("kubernetes_api") or {}
    limitations.extend(str(x) for x in api.get("collection_limitations") or [])
    if api.get("ok") is False:
        limitations.append("Kubernetes API collection failed: " + str(api.get("error") or "unspecified error"))
    loki = initial.get("loki")
    if not isinstance(loki, Mapping):
        limitations.append("Loki collection is missing.")
    else:
        for query in loki.get("queries") or []:
            if query.get("ok") is False:
                limitations.append("Loki query failed: " + str(query.get("query")))
            if query.get("unattributed_sample_count"):
                limitations.append("Some Loki samples have no verified container identity; do not attribute them to the target container.")
            if query.get("omitted_before_normalization"):
                limitations.append("Loki collection retained a limited sample of returned entries; it is not the complete log history.")
            if any("unable to retrieve container logs" in str(line).lower()
                   for line in query.get("sample_lines") or []):
                limitations.append("A Loki result reports a container-log retrieval failure; log coverage may be incomplete.")
    for entry in initial.get("prometheus") or []:
        for measurement in (entry.get("evidence") or {}).get("measurements") or []:
            if measurement.get("ok") is False:
                limitations.append("Prometheus measurement failed: " + str(measurement.get("query") or measurement.get("role")))
    return list(dict.fromkeys(limitations))


def validate_initial_transport(initial: Mapping[str, Any], transport: Mapping[str, Any]) -> dict[str, Any]:
    """Check fact preservation against original records, not a success marker."""
    api = initial.get("kubernetes_api") or {}
    content = transport["remaining_evidence"]["content"]
    resources = transport["related_kubernetes_resources"]
    checks = {
        "events": content["kubernetes_api"]["events"]["events"] == sanitize_evidence(api.get("events") or []),
        "container_states": resources["pod"]["containers"] == sanitize_evidence(api.get("containers") or []),
        "pvc_records": resources["persistent_volume_claims"]["items"] == sanitize_evidence(api.get("persistent_volume_claims") or []),
    }
    for output_name, source_name in (("deployment", "deployment"), ("replica_set", "replica_set"), ("node", "node_details")):
        checks[output_name] = resources.get(output_name) == sanitize_evidence(api.get(source_name))
    source_metrics = initial.get("prometheus") or []
    checks["measurements"] = len(content["prometheus"]) == len(source_metrics) and all(
        row["evidence"] == sanitize_evidence(source.get("evidence") or {})
        for source, row in zip(source_metrics, content["prometheus"])
    )
    source_queries = (initial.get("loki") or {}).get("queries") or []
    sent_queries = content["loki"]["queries"]
    checks["loki_queries"] = len(source_queries) == len(sent_queries)
    for index, (source, sent) in enumerate(zip(source_queries, sent_queries)):
        checks[f"loki_query_{index}_status"] = all(
            sent.get(k) == sanitize_evidence(source.get(k)) for k in ("query", "ok", "error")
        )
        entries = source.get("sample_entries")
        if isinstance(entries, list):
            expanded = []
            for sample in sent.get("samples") or []:
                identity = {k: v for k, v in sample.items() if k not in (
                    "count", "timestamps_ns", "first_timestamp_ns", "last_timestamp_ns",
                )}
                for stamp in sample["timestamps_ns"]:
                    expanded.append(sanitize_evidence({**identity, "timestamp_ns": stamp}))
            checks[f"loki_query_{index}_entries"] = Counter(map(_stable_json, expanded)) == Counter(
                _stable_json(sanitize_evidence(entry)) for entry in entries
            )
            represented = {str(entry.get("line", "")) for entry in entries}
            extras = [_redact_text(str(line)) for line in source.get("sample_lines") or [] if str(line) not in represented]
            checks[f"loki_query_{index}_extras"] = sent.get("additional_sample_lines", []) == extras
        else:
            checks[f"loki_query_{index}_lines"] = sent.get("sample_lines") == [
                _redact_text(str(line)) for line in source.get("sample_lines") or []
            ]
    failed = [name for name, ok in checks.items() if not ok]
    if failed:
        raise ValueError("Evidence preservation check failed: " + ", ".join(failed))
    return {"ok": True, "checks": checks, "policy": "complete_collected_facts_after_redaction"}


def build_resource_preserving_initial_evidence(
    initial_evidence: Any,
    *,
    remaining_budget: int = 5000,
) -> Any:
    """Compact initial evidence without dropping related-resource state."""
    if not isinstance(initial_evidence, Mapping):
        return compact_value(initial_evidence, budget=remaining_budget)

    kubernetes = initial_evidence.get("kubernetes_api")
    if not isinstance(kubernetes, Mapping):
        return compact_value(initial_evidence, budget=remaining_budget)

    # Resource identities/configuration and live container state are protected
    # separately, as in v1. The remaining budget covers metrics, logs and events.
    remaining = {
        "prometheus": _prometheus_summary(initial_evidence.get("prometheus")),
        "loki": _loki_summary(initial_evidence.get("loki")),
        "kubernetes_api": _pick(kubernetes, ("source", "role", "ok", "error")),
    }
    events = kubernetes.get("events") or []
    event_summary = _compact_events(events, seen=set(), max_items=len(events))
    remaining["kubernetes_api"]["events"] = event_summary
    wrapped = {"format": "structured", "content": remaining}
    # Omit whole optional events, not random fields of the mandatory metrics or
    # status. Each omitted observation is counted and remains in the raw brief.
    while len(_stable_json(wrapped)) > remaining_budget and event_summary["events"]:
        event_summary["events"].pop()
        event_summary["omitted_count"] += 1
    for max_lines, max_chars in ((4, 400), (2, 240)):
        if len(_stable_json(wrapped)) <= remaining_budget:
            break
        remaining["loki"] = _loki_summary(initial_evidence.get("loki"), max_lines=max_lines, max_chars=max_chars)
    # Loki metadata can shrink after the first event pass. Re-check the total
    # and omit only whole, lower-priority event observations until the bounded
    # transport representation fits. The raw event list remains in the brief.
    while len(_stable_json(wrapped)) > remaining_budget and event_summary["events"]:
        event_summary["events"].pop()
        event_summary["omitted_count"] += 1
    actual_remaining = len(_stable_json(wrapped))
    return {
        "format": "resource_preserving_initial_evidence_v2",
        "related_kubernetes_resources": _kagent_related_kubernetes_resources(
            kubernetes
        ),
        "remaining_evidence": wrapped,
        "collection_limitations": _collection_limitations(initial_evidence),
        "remaining_budget_target": remaining_budget,
        "remaining_characters": actual_remaining,
        "remaining_budget_exceeded": actual_remaining > remaining_budget,
    }


def build_kagent_evidence_context(
    initial_evidence: Any,
    *,
    remaining_budget: int = 5000,
) -> Any:
    """Build the bounded resource-preserving initial context used by Kagent."""
    return build_resource_preserving_initial_evidence(
        initial_evidence,
        remaining_budget=remaining_budget,
    )


def _record_args(record: Mapping[str, Any]) -> Any:
    call = record.get("call")
    if isinstance(call, Mapping):
        for key in ("args", "arguments", "parameters"):
            if key in call:
                return _sanitize(call[key])
    for key in ("tool_args", "args", "arguments"):
        if key in record:
            return _sanitize(record[key])
    return {}


def compact_tool_evidence(
    records: Sequence[Any],
    *,
    seen: set[str],
    raw_reference: str,
    budget: int = 4800,
) -> dict[str, Any]:
    """Normalize, deduplicate and bound evidence records while retaining audit links."""
    prepared: list[dict[str, Any]] = []
    exact_seen: dict[str, dict[str, Any]] = {}
    input_count = 0
    for record in records:
        if not isinstance(record, Mapping):
            continue
        input_count += 1
        tool = str(record.get("tool") or record.get("tool_name") or "unknown")
        raw = record.get("raw_output")
        if raw is None:
            raw = record.get("response")
        args = _record_args(record)
        raw_text = raw if isinstance(raw, str) else _stable_json(raw)
        raw_digest = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
        signature = _sha256({"tool": tool, "arguments": args, "raw_sha256": raw_digest})
        if signature in exact_seen:
            exact_seen[signature]["duplicate_count"] += 1
            continue
        status = "success" if bool(record.get("succeeded", True)) else "failure"
        base = {
            "evidence_id": f"sha256:{signature[:16]}",
            "tool": tool,
            "status": status,
            "scope_ok": record.get("scope_ok"),
            "read_only_ok": record.get("read_only_ok"),
            "arguments": args,
            "original_chars": len(raw_text),
            "raw_sha256": raw_digest,
            "raw_reference": raw_reference,
            "duplicate_count": 0,
        }
        base = {key: value for key, value in base.items() if value is not None}
        variants: dict[str, Any] = {}
        for cap in sorted({max(2400, budget - len(_stable_json(base)) - 16), 2400, 2000, 1600, 1200, 800, 512}):
            try:
                compacted = compact_value(raw, budget=cap)
            except EvidenceBudgetError:
                continue
            rendered = _stable_json(compacted)
            variants[rendered] = compacted
        if not variants:
            raise EvidenceBudgetError(f"No complete minimum representation fits for tool {tool}.")
        candidate = {"base": base, "variants": sorted(variants.values(), key=lambda x: len(_stable_json(x))),
                     "rank": _signal_score(raw) + (5 if status == "failure" else 0), "index": len(prepared)}
        exact_seen[signature] = base
        prepared.append(candidate)

    def render(candidate: Mapping[str, Any], level: int) -> dict[str, Any]:
        return {**candidate["base"], "evidence": candidate["variants"][level]}

    # Reserve one minimum representation for each tool/source before expanding
    # any large result. A normal, short log must not lose to verbose YAML.
    selected_levels: dict[int, int] = {}
    groups: dict[str, list[dict[str, Any]]] = {}
    for candidate in prepared:
        groups.setdefault(candidate["base"]["tool"], []).append(candidate)
    used = 0
    for candidates in groups.values():
        candidates.sort(key=lambda x: (-x["rank"], x["index"]))
        candidate = candidates[0]
        size = len(_stable_json(render(candidate, 0)))
        selected_levels[candidate["index"]] = 0
        used += size
    if used > budget:
        raise EvidenceBudgetError(
            f"Minimum evidence for {len(groups)} tools needs {used} characters; adaptive budget is {budget}."
        )
    # Represent additional observations before spending space on long excerpts.
    for candidate in sorted(prepared, key=lambda x: (-x["rank"], x["index"])):
        index = candidate["index"]
        if index in selected_levels:
            continue
        size = len(_stable_json(render(candidate, 0)))
        if used + size <= budget:
            selected_levels[index] = 0
            used += size
    expanded = True
    while expanded:
        expanded = False
        for index in selected_levels:
            candidate = prepared[index]
            level = selected_levels[index]
            if level + 1 >= len(candidate["variants"]):
                continue
            delta = len(_stable_json(render(candidate, level + 1))) - len(_stable_json(render(candidate, level)))
            if used + delta <= budget:
                selected_levels[index] += 1
                used += delta
                expanded = True
    selected = [render(prepared[index], selected_levels[index]) for index in sorted(selected_levels)]
    omitted = [{"evidence_id": x["base"]["evidence_id"], "tool": x["base"]["tool"],
                "reason": "adaptive_evidence_budget", "raw_sha256": x["base"]["raw_sha256"]}
               for x in prepared if x["index"] not in selected_levels]
    return {
        "input_record_count": input_count,
        "selected_record_count": len(selected),
        "omitted_record_count": max(0, len(prepared) - len(selected)),
        "duplicate_record_count": input_count - len(prepared),
        "omitted_records": omitted,
        "records": selected,
        "raw_reference": raw_reference,
        "record_characters": sum(len(_stable_json(item)) for item in selected),
        "record_budget": budget,
    }


def build_evidence_handoff(
    initial_evidence: Any,
    kagent_investigation: Mapping[str, Any],
    *,
    initial_raw_reference: str = "brief_initial.json",
    raw_reference: str = "kagent_investigation.json",
    initial_budget: int = 4200,
    adaptive_budget: int = 4800,
) -> dict[str, Any]:
    """Build a generic compact handoff while leaving the raw audit file untouched."""
    records = kagent_investigation.get("successful_tool_evidence") or []
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes, bytearray)):
        records = []
    compact_initial = build_resource_preserving_initial_evidence(
        initial_evidence,
        remaining_budget=initial_budget,
    )
    seen = collect_semantic_fingerprints(compact_initial)
    compact_adaptive = compact_tool_evidence(
        records,
        seen=seen,
        raw_reference=raw_reference,
        budget=adaptive_budget,
    )
    limitations = _collection_limitations(initial_evidence) + list(kagent_investigation.get("limitations") or [])
    initial_events = compact_initial.get("remaining_evidence", {}).get("content", {}).get("kubernetes_api", {}).get("events", {})
    if initial_events.get("omitted_count", 0):
        limitations.append(f"Initial event transport omitted {initial_events['omitted_count']} observations; see {initial_raw_reference}.")
    for query in compact_initial.get("remaining_evidence", {}).get("content", {}).get("loki", {}).get("queries", []):
        if query.get("omitted_sample_lines") or query.get("truncated_sample_lines"):
            limitations.append(f"Loki transport retained a partial log sample for {query.get('query')}; see {initial_raw_reference}.")
    if compact_adaptive["omitted_record_count"]:
        limitations.append(f"Adaptive transport omitted {compact_adaptive['omitted_record_count']} tool records; see omitted_records and {raw_reference}.")
    for record in compact_adaptive["records"]:
        compacted = record["evidence"]
        content = compacted.get("content") or {}
        omitted_count = compacted.get("omitted_count", 0) or (content.get("omitted_count", 0) if isinstance(content, Mapping) else 0)
        if omitted_count or compacted.get("truncated") or compacted.get("partial"):
            limitations.append(f"Transport summary for {record['evidence_id']} ({record['tool']}) is partial; full output remains in {raw_reference}.")
    handoff = {
        "schema_version": 3,
        "transport_integrity": {
            "ok": True,
            "policy": "bounded_evidence_transport_with_raw_audit",
            "full_raw_preserved": True,
            "collection_limits_are_separate": True,
        },
        "initial_evidence": compact_initial,
        "adaptive_evidence": compact_adaptive,
        "limitations": _sanitize(list(dict.fromkeys(str(x) for x in limitations))),
        "audit": {
            "full_initial_evidence": initial_raw_reference,
            "full_adaptive_evidence": raw_reference,
            "full_raw_preserved": True,
            "raw_references_are_audit_only": True,
        },
    }
    handoff["compaction"] = {
        "handoff_characters": 0,
        "initial_budget": initial_budget,
        "adaptive_budget": adaptive_budget,
        "protected_resource_characters": len(_stable_json(compact_initial.get("related_kubernetes_resources", {}))),
        "budget_unit": "characters",
    }
    # Include the bookkeeping itself in the reported serialized character count.
    while handoff["compaction"]["handoff_characters"] != len(_stable_json(handoff)):
        handoff["compaction"]["handoff_characters"] = len(_stable_json(handoff))
    check_payload_size(handoff, "Final evidence handoff")
    return handoff
