from __future__ import annotations

import json
import math
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Callable

import requests
from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException

if __package__:
    from .evidence_normalizer import build_evidence_handoff, sanitize_evidence
    from .kagent_runner import run_kagent, build_kagent_task
    from .opensre_runner import run_opensre
else:
    from evidence_normalizer import build_evidence_handoff, sanitize_evidence
    from kagent_runner import run_kagent, build_kagent_task
    from opensre_runner import run_opensre


# =============================================================================
# Configuration
# =============================================================================

COORDINATOR_DIR = Path(__file__).resolve().parent
PROJECT_DIR = COORDINATOR_DIR.parent
OUTPUT_ROOT = PROJECT_DIR / "outputs"
OUTPUT_ROOT.mkdir(exist_ok=True)

PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090").rstrip("/")
LOKI_URL = os.getenv("LOKI_URL", "http://127.0.0.1:3100").rstrip("/")

def _csv_env(name: str) -> tuple[str, ...]:
    """Read a comma-separated environment variable as non-empty values."""
    return tuple(
        item.strip()
        for item in os.getenv(name, "").split(",")
        if item.strip()
    )


# Monitoring scope for the current OSCAR/Kubernetes cluster.
#
# Empty INCLUDE lists mean "include all".
# EXCLUDE lists always take precedence.
#
# Namespace examples:
#   RISK_INCLUDED_NAMESPACES="app-a,production,default"
#   RISK_EXCLUDED_NAMESPACES="monitoring,kube-system"
#
# Pod rules support shell-style patterns and may be scoped by namespace:
#   RISK_INCLUDED_PODS="app-a/*,production/api-*"
#   RISK_EXCLUDED_PODS="default/nfs-server-provisioner-*,*/debug-*"
#
# A pod-only pattern is also valid:
#   RISK_EXCLUDED_PODS="temporary-*,debug-*"
#
# Nothing is permanently hard-coded here; the user defines the monitored scope.
RISK_INCLUDED_NAMESPACES = _csv_env("RISK_INCLUDED_NAMESPACES")
RISK_EXCLUDED_NAMESPACES = _csv_env("RISK_EXCLUDED_NAMESPACES")
RISK_INCLUDED_PODS = _csv_env("RISK_INCLUDED_PODS")
RISK_EXCLUDED_PODS = _csv_env("RISK_EXCLUDED_PODS")

LOKI_LOOKBACK_MINUTES = int(os.getenv("LOKI_LOOKBACK_MINUTES", "10"))
AUTO_RUN_OPENSRE = os.getenv("AUTO_RUN_OPENSRE", "1").strip().lower() not in {"0", "false", "no", "off"}

CPU_LIMIT_USAGE_THRESHOLD = float(os.getenv("CPU_LIMIT_USAGE_THRESHOLD", "70"))
CPU_REQUEST_PRESSURE_THRESHOLD = float(os.getenv("CPU_REQUEST_PRESSURE_THRESHOLD", "150"))
MEMORY_LIMIT_USAGE_THRESHOLD = float(os.getenv("MEMORY_LIMIT_USAGE_THRESHOLD", "75"))
MEMORY_REQUEST_PRESSURE_THRESHOLD = float(os.getenv("MEMORY_REQUEST_PRESSURE_THRESHOLD", "120"))
CPU_THROTTLING_THRESHOLD = float(os.getenv("CPU_THROTTLING_THRESHOLD", "20"))
RESTART_INCREASE_THRESHOLD = float(os.getenv("RESTART_INCREASE_THRESHOLD", "0"))

_K8S_CORE: client.CoreV1Api | None = None
_K8S_APPS: client.AppsV1Api | None = None


# =============================================================================
# Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def safe_name(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "unknown"))[:120]


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    temporary.replace(path)


def as_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def serializable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        return [serializable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): serializable(item) for key, item in value.items()}
    if hasattr(value, "to_dict"):
        return serializable(value.to_dict())
    return str(value)


# =============================================================================
# Kubernetes API
# =============================================================================

def k8s_core() -> client.CoreV1Api:
    """Local execution uses kubeconfig; a future CronJob uses its ServiceAccount."""
    global _K8S_CORE
    if _K8S_CORE is None:
        try:
            config.load_incluster_config()
        except ConfigException:
            config.load_kube_config()
        _K8S_CORE = client.CoreV1Api()
    return _K8S_CORE


def k8s_apps() -> client.AppsV1Api:
    """Return the workload API after Kubernetes client configuration is loaded."""
    global _K8S_APPS
    if _K8S_APPS is None:
        k8s_core()
        _K8S_APPS = client.AppsV1Api()
    return _K8S_APPS


# =============================================================================
# Prometheus risk detection
# =============================================================================

@dataclass(frozen=True)
class RiskRule:
    risk_type: str
    reason: str
    query: str
    threshold: float | None
    unit: str = "%"
    compare: Callable[[float, float], bool] | None = None
    priority: str = "medium"


def prom_query(query: str) -> list[dict[str, Any]]:
    response = requests.get(
        f"{PROMETHEUS_URL}/api/v1/query",
        params={"query": query},
        timeout=25,
    )
    response.raise_for_status()
    body = response.json()
    if body.get("status") != "success":
        raise RuntimeError(str(body))
    return body.get("data", {}).get("result", []) or []


def prom_scalar(query: str) -> dict[str, Any]:
    try:
        result = prom_query(query)
    except Exception as exc:
        return {"ok": False, "query": query, "value": None, "timestamp": None, "error": str(exc)}

    if not result:
        return {"ok": False, "query": query, "value": None, "timestamp": None, "error": "no_result"}

    item = result[0]
    raw = item.get("value") or [None, None]
    number = as_float(raw[1])
    return {
        "ok": number is not None,
        "query": query,
        "value": number,
        "error": None if number is not None else "non_finite_or_invalid_value",
        "timestamp": raw[0],
        "metric": item.get("metric") or {},
    }


def namespace_is_eligible(namespace: str) -> bool:
    """Return whether a namespace belongs to the user-selected monitoring scope."""
    if RISK_INCLUDED_NAMESPACES and namespace not in RISK_INCLUDED_NAMESPACES:
        return False

    if namespace in RISK_EXCLUDED_NAMESPACES:
        return False

    return True


def namespace_selector() -> str:
    """
    Do not encode the user scope as a Prometheus regular expression.

    Prometheus scans Running Pods in the current cluster and the coordinator
    applies namespace and Pod include/exclude rules to the returned labels.
    This keeps the scope logic predictable and avoids regex compatibility
    problems between Python and PromQL/RE2.
    """
    return ""


def _pod_pattern_matches(pattern: str, namespace: str, pod: str) -> bool:
    """Match a Pod rule against either pod or namespace/pod."""
    if "/" in pattern:
        return fnmatchcase(f"{namespace}/{pod}", pattern)

    return fnmatchcase(pod, pattern)


def pod_is_eligible(namespace: str, pod: str) -> bool:
    """Return whether a Pod belongs to the user-selected monitoring scope."""
    if RISK_INCLUDED_PODS:
        included = any(
            _pod_pattern_matches(pattern, namespace, pod)
            for pattern in RISK_INCLUDED_PODS
        )
        if not included:
            return False

    if any(
        _pod_pattern_matches(pattern, namespace, pod)
        for pattern in RISK_EXCLUDED_PODS
    ):
        return False

    return True


def running_pod_filter(ns: str) -> str:
    """PromQL expression that keeps only containers belonging to Running pods."""
    return f'(kube_pod_status_phase{{{ns}phase="Running"}} == 1)'

def risk_rules() -> list[RiskRule]:
    ns = namespace_selector()
    running = running_pod_filter(ns)
    return [
        RiskRule(
            "HighCpuLimitUsageRisk",
            "ContainerCpuUsageNearLimit",
            f'''(
  100 * sum by (namespace,pod,container) (
    rate(container_cpu_usage_seconds_total{{{ns}container!="",container!="POD"}}[2m])
  ) / sum by (namespace,pod,container) (
    kube_pod_container_resource_limits{{{ns}resource="cpu",container!=""}}
  )
)
and on(namespace,pod)
{running}''',
            CPU_LIMIT_USAGE_THRESHOLD,
            priority="high",
        ),
        RiskRule(
            "CpuRequestPressureRisk",
            "ContainerCpuUsageAboveRequestedCpu",
            f'''(
  100 * sum by (namespace,pod,container) (
    rate(container_cpu_usage_seconds_total{{{ns}container!="",container!="POD"}}[2m])
  ) / sum by (namespace,pod,container) (
    kube_pod_container_resource_requests{{{ns}resource="cpu",container!=""}}
  )
)
and on(namespace,pod)
{running}''',
            CPU_REQUEST_PRESSURE_THRESHOLD,
            priority="medium",
        ),
        RiskRule(
            "HighMemoryLimitUsageRisk",
            "ContainerMemoryUsageNearLimit",
            f'''(
  100 * sum by (namespace,pod,container) (
    container_memory_working_set_bytes{{{ns}container!="",container!="POD"}}
  ) / sum by (namespace,pod,container) (
    kube_pod_container_resource_limits{{{ns}resource="memory",container!=""}}
  )
)
and on(namespace,pod)
{running}''',
            MEMORY_LIMIT_USAGE_THRESHOLD,
            priority="high",
        ),
        RiskRule(
            "MemoryRequestPressureRisk",
            "ContainerMemoryUsageAboveRequestedMemory",
            f'''(
  100 * sum by (namespace,pod,container) (
    container_memory_working_set_bytes{{{ns}container!="",container!="POD"}}
  ) / sum by (namespace,pod,container) (
    kube_pod_container_resource_requests{{{ns}resource="memory",container!=""}}
  )
)
and on(namespace,pod)
{running}''',
            MEMORY_REQUEST_PRESSURE_THRESHOLD,
            priority="medium",
        ),
        RiskRule(
            "CpuThrottlingRisk",
            "ContainerCpuThrottlingDetected",
            f'''(
  100 * sum by (namespace,pod,container) (
    rate(container_cpu_cfs_throttled_periods_total{{{ns}container!="",container!="POD"}}[5m])
  ) / sum by (namespace,pod,container) (
    rate(container_cpu_cfs_periods_total{{{ns}container!="",container!="POD"}}[5m])
  )
)
and on(namespace,pod)
{running}''',
            CPU_THROTTLING_THRESHOLD,
            priority="high",
        ),
        RiskRule(
            "RestartIncreaseRisk",
            "ContainerRestartCountIncreasedRecently",
            f'''(
  increase(kube_pod_container_status_restarts_total{{{ns}container!=""}}[10m])
)
and on(namespace,pod)
{running}''',
            RESTART_INCREASE_THRESHOLD,
            "restarts/10m",
            lambda value, threshold: value > threshold,
            "medium",
        ),
        RiskRule(
            "MissingCpuLimitRisk",
            "ContainerHasNoCpuLimit",
            f'''(
  kube_pod_container_info{{{ns}container!=""}}
  unless on(namespace,pod,container)
  kube_pod_container_resource_limits{{{ns}resource="cpu",container!=""}}
)
and on(namespace,pod)
{running}''',
            None,
            "",
            priority="low",
        ),
        RiskRule(
            "MissingMemoryLimitRisk",
            "ContainerHasNoMemoryLimit",
            f'''(
  kube_pod_container_info{{{ns}container!=""}}
  unless on(namespace,pod,container)
  kube_pod_container_resource_limits{{{ns}resource="memory",container!=""}}
)
and on(namespace,pod)
{running}''',
            None,
            "",
            priority="low",
        ),
    ]

def detect_risks(detection_status: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    risks: list[dict[str, Any]] = []
    status = detection_status if detection_status is not None else {}
    status.update({"started_at": now_iso(), "ok": True, "rules": []})

    for rule in risk_rules():
        try:
            items = prom_query(rule.query)
        except Exception as exc:
            print(f"Detection rule {rule.risk_type} failed: {exc}")
            status["ok"] = False
            status["rules"].append({"rule": rule.risk_type, "ok": False, "error": f"{type(exc).__name__}: {exc}"})
            continue
        status["rules"].append({"rule": rule.risk_type, "ok": True, "result_count": len(items)})

        for item in items:
            metric = item.get("metric") or {}
            value = as_float((item.get("value") or [None, None])[1])
            namespace = metric.get("namespace")
            pod = metric.get("pod")
            container_name = metric.get("container") or "app"

            if value is None or not namespace or not pod:
                continue

            if not namespace_is_eligible(namespace):
                continue

            if not pod_is_eligible(namespace, pod):
                continue

            if rule.threshold is not None:
                comparator = rule.compare or (lambda current, threshold: current >= threshold)
                if not comparator(value, rule.threshold):
                    continue

            risks.append({
                "risk_type": rule.risk_type,
                "risk_stage": "preventive",
                "detection_source": "prometheus",
                "namespace": namespace,
                "pod": pod,
                "container": container_name,
                "resource_type": "pod",
                "observed_reason": rule.reason,
                "observed_value": value,
                "observed_value_suffix": rule.unit,
                "threshold": rule.threshold,
                "priority": rule.priority,
                "prometheus_query": rule.query,
                "detected_at": now_iso(),
            })

    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for risk in risks:
        key = (risk["risk_type"], risk["namespace"], risk["pod"], risk["container"])
        unique.setdefault(key, risk)

    priority_order = {"high": 0, "medium": 1, "low": 2}
    status["finished_at"] = now_iso()
    return sorted(
        unique.values(),
        key=lambda risk: (
            priority_order.get(risk.get("priority", "medium"), 1),
            risk["namespace"],
            risk["pod"],
            risk["container"],
            risk["risk_type"],
        ),
    )


# =============================================================================
# Initial evidence
# =============================================================================

def selector(risk: dict[str, Any]) -> str:
    return f'namespace="{risk["namespace"]}",pod="{risk["pod"]}",container="{risk["container"]}"'


def collect_prometheus_evidence(risk: dict[str, Any]) -> dict[str, Any]:
    sel = selector(risk)
    risk_type = risk["risk_type"]
    measurements: list[dict[str, Any]] = []

    def add(role: str, metric: str, query: str, unit: str) -> None:
        observation = prom_scalar(query)
        labels = observation.pop("metric", {})
        measurements.append({"role": role, "metric": metric, "metric_labels": labels, "unit": unit, **observation})

    evidence_queries = {
        "HighMemoryLimitUsageRisk": [
            ("actual", "container_memory_working_set_bytes", f"sum(container_memory_working_set_bytes{{{sel}}})", "bytes"),
            ("limit", "kube_pod_container_resource_limits", f'sum(kube_pod_container_resource_limits{{{sel},resource="memory",unit="byte"}})', "bytes"),
        ],
        "MemoryRequestPressureRisk": [
            ("actual", "container_memory_working_set_bytes", f"sum(container_memory_working_set_bytes{{{sel}}})", "bytes"),
            ("request", "kube_pod_container_resource_requests", f'sum(kube_pod_container_resource_requests{{{sel},resource="memory",unit="byte"}})', "bytes"),
        ],
        "HighCpuLimitUsageRisk": [
            ("actual", "container_cpu_usage_seconds_total_rate", f"sum(rate(container_cpu_usage_seconds_total{{{sel}}}[2m]))", "cores"),
            ("limit", "kube_pod_container_resource_limits", f'sum(kube_pod_container_resource_limits{{{sel},resource="cpu",unit="core"}})', "cores"),
        ],
        "CpuRequestPressureRisk": [
            ("actual", "container_cpu_usage_seconds_total_rate", f"sum(rate(container_cpu_usage_seconds_total{{{sel}}}[2m]))", "cores"),
            ("request", "kube_pod_container_resource_requests", f'sum(kube_pod_container_resource_requests{{{sel},resource="cpu",unit="core"}})', "cores"),
        ],
        "CpuThrottlingRisk": [
            ("throttled_periods_rate", "container_cpu_cfs_throttled_periods_total", f"sum(rate(container_cpu_cfs_throttled_periods_total{{{sel}}}[5m]))", "periods/s"),
            ("total_periods_rate", "container_cpu_cfs_periods_total", f"sum(rate(container_cpu_cfs_periods_total{{{sel}}}[5m]))", "periods/s"),
        ],
        "RestartIncreaseRisk": [
            ("restart_increase", "kube_pod_container_status_restarts_total", f"increase(kube_pod_container_status_restarts_total{{{sel}}}[10m])", "restarts/10m"),
        ],
    }

    for args in evidence_queries.get(risk_type, []):
        add(*args)

    measurements.append({
        "role": "detected_value",
        "metric": risk["observed_reason"],
        "value": risk["observed_value"],
        "unit": risk["observed_value_suffix"],
        "ok": True,
    })
    if risk.get("threshold") is not None:
        measurements.append({
            "role": "threshold",
            "value": risk["threshold"],
            "unit": risk["observed_value_suffix"],
            "ok": True,
        })

    return {
        "source": "prometheus",
        "role": "detection_and_metric_evidence",
        "detection_query": risk["prometheus_query"],
        "measurements": measurements,
    }


def _k8s_evidence_id(kind: str, name: str, namespace: str | None = None) -> str:
    scope = namespace or "cluster"
    return f"kubernetes:{kind.lower()}:{scope}:{name}"


def _k8s_timestamp(value: Any) -> str | None:
    return str(value) if value is not None else None


def _k8s_conditions(values: Any) -> list[dict[str, Any]]:
    rows = []
    for condition in values or []:
        row = {
            "type": getattr(condition, "type", None),
            "status": getattr(condition, "status", None),
            "reason": getattr(condition, "reason", None),
            "message": getattr(condition, "message", None),
            "last_transition_time": _k8s_timestamp(
                getattr(condition, "last_transition_time", None)
            ),
        }
        rows.append({key: value for key, value in row.items() if value is not None})
    return rows


def _k8s_owner_reference(metadata: Any, kind: str | None = None) -> Any:
    references = list(getattr(metadata, "owner_references", None) or [])
    if kind is not None:
        references = [
            reference
            for reference in references
            if str(getattr(reference, "kind", "")).lower() == kind.lower()
        ]
    if not references:
        return None
    return next(
        (
            reference
            for reference in references
            if bool(getattr(reference, "controller", False))
        ),
        references[0],
    )


def _k8s_owner_row(reference: Any) -> dict[str, Any] | None:
    if reference is None:
        return None
    return {
        "kind": getattr(reference, "kind", None),
        "name": getattr(reference, "name", None),
        "controller": bool(getattr(reference, "controller", False)),
    }


def _k8s_limitation(
    limitations: list[dict[str, str]],
    *,
    operation: str,
    kind: str,
    name: str,
    error: Exception,
) -> None:
    limitations.append({
        "operation": operation,
        "resource_kind": kind,
        "resource_name": name,
        "error": str(error),
    })


def _k8s_container_templates(pod_spec: Any) -> list[dict[str, Any]]:
    templates = []
    for container_spec in getattr(pod_spec, "containers", None) or []:
        env_names = [
            item.name
            for item in (getattr(container_spec, "env", None) or [])
            if getattr(item, "name", None)
        ]
        templates.append({
            "name": container_spec.name,
            "image": container_spec.image,
            "image_pull_policy": getattr(container_spec, "image_pull_policy", None),
            "command": list(getattr(container_spec, "command", None) or []),
            "args": list(getattr(container_spec, "args", None) or []),
            "resources": serializable(getattr(container_spec, "resources", None)),
            "ports": serializable(getattr(container_spec, "ports", None) or []),
            "liveness_probe": serializable(
                getattr(container_spec, "liveness_probe", None)
            ),
            "readiness_probe": serializable(
                getattr(container_spec, "readiness_probe", None)
            ),
            "startup_probe": serializable(
                getattr(container_spec, "startup_probe", None)
            ),
            "environment_variable_names": env_names,
        })
    return templates


def _collect_workload_evidence(
    pod: Any,
    namespace: str,
    apps_api: client.AppsV1Api,
    limitations: list[dict[str, str]],
) -> dict[str, Any]:
    pod_owner = _k8s_owner_reference(pod.metadata)
    replica_set = None
    deployment = None
    deployment_reference = None

    if pod_owner and str(getattr(pod_owner, "kind", "")).lower() == "replicaset":
        replica_set_name = str(getattr(pod_owner, "name", ""))
        try:
            replica_set_object = apps_api.read_namespaced_replica_set(
                replica_set_name,
                namespace,
            )
            replica_set = {
                "evidence_id": _k8s_evidence_id(
                    "ReplicaSet", replica_set_name, namespace
                ),
                "kind": "ReplicaSet",
                "namespace": namespace,
                "name": replica_set_name,
                "generation": getattr(replica_set_object.metadata, "generation", None),
                "desired_replicas": getattr(replica_set_object.spec, "replicas", None),
                "current_replicas": getattr(replica_set_object.status, "replicas", None),
                "ready_replicas": getattr(
                    replica_set_object.status, "ready_replicas", None
                ),
                "available_replicas": getattr(
                    replica_set_object.status, "available_replicas", None
                ),
                "conditions": _k8s_conditions(
                    getattr(replica_set_object.status, "conditions", None)
                ),
            }
            deployment_reference = _k8s_owner_reference(
                replica_set_object.metadata,
                "Deployment",
            )
        except Exception as exc:
            _k8s_limitation(
                limitations,
                operation="read_namespaced_replica_set",
                kind="ReplicaSet",
                name=replica_set_name,
                error=exc,
            )
    elif pod_owner and str(getattr(pod_owner, "kind", "")).lower() == "deployment":
        deployment_reference = pod_owner

    if deployment_reference is not None:
        deployment_name = str(getattr(deployment_reference, "name", ""))
        try:
            deployment_object = apps_api.read_namespaced_deployment(
                deployment_name,
                namespace,
            )
            deployment_spec = deployment_object.spec
            deployment_status = deployment_object.status
            template = deployment_spec.template
            strategy = getattr(deployment_spec, "strategy", None)
            deployment = {
                "evidence_id": _k8s_evidence_id(
                    "Deployment", deployment_name, namespace
                ),
                "kind": "Deployment",
                "namespace": namespace,
                "name": deployment_name,
                "generation": getattr(deployment_object.metadata, "generation", None),
                "observed_generation": getattr(
                    deployment_status, "observed_generation", None
                ),
                "desired_replicas": getattr(deployment_spec, "replicas", None),
                "ready_replicas": getattr(deployment_status, "ready_replicas", None),
                "available_replicas": getattr(
                    deployment_status, "available_replicas", None
                ),
                "updated_replicas": getattr(
                    deployment_status, "updated_replicas", None
                ),
                "unavailable_replicas": getattr(
                    deployment_status, "unavailable_replicas", None
                ),
                "strategy": serializable(strategy),
                "selector": serializable(getattr(deployment_spec, "selector", None)),
                "conditions": _k8s_conditions(
                    getattr(deployment_status, "conditions", None)
                ),
                "pod_template": {
                    "labels": getattr(template.metadata, "labels", None) or {},
                    "service_account_name": getattr(
                        template.spec, "service_account_name", None
                    ),
                    "node_selector": getattr(template.spec, "node_selector", None) or {},
                    "containers": _k8s_container_templates(template.spec),
                },
            }
        except Exception as exc:
            _k8s_limitation(
                limitations,
                operation="read_namespaced_deployment",
                kind="Deployment",
                name=deployment_name,
                error=exc,
            )

    return {
        "pod_controller": _k8s_owner_row(pod_owner),
        "replica_set": replica_set,
        "deployment": deployment,
    }


def _relevant_node_labels(labels: Any) -> dict[str, str]:
    prefixes = (
        "kubernetes.io/",
        "node.kubernetes.io/",
        "node-role.kubernetes.io/",
        "topology.kubernetes.io/",
    )
    return {
        str(key): str(value)
        for key, value in (labels or {}).items()
        if str(key).startswith(prefixes)
    }


def _collect_node_evidence(
    core_api: client.CoreV1Api,
    node_name: str | None,
    limitations: list[dict[str, str]],
) -> dict[str, Any] | None:
    if not node_name:
        return None
    try:
        node = core_api.read_node(node_name)
    except Exception as exc:
        _k8s_limitation(
            limitations,
            operation="read_node",
            kind="Node",
            name=node_name,
            error=exc,
        )
        return None

    node_info = getattr(node.status, "node_info", None)
    return {
        "evidence_id": _k8s_evidence_id("Node", node_name),
        "kind": "Node",
        "name": node_name,
        "labels": _relevant_node_labels(getattr(node.metadata, "labels", None)),
        "unschedulable": bool(getattr(node.spec, "unschedulable", False)),
        "taints": serializable(getattr(node.spec, "taints", None) or []),
        "capacity": serializable(getattr(node.status, "capacity", None) or {}),
        "allocatable": serializable(
            getattr(node.status, "allocatable", None) or {}
        ),
        "conditions": _k8s_conditions(getattr(node.status, "conditions", None)),
        "addresses": serializable(getattr(node.status, "addresses", None) or []),
        "system": {
            "architecture": getattr(node_info, "architecture", None),
            "operating_system": getattr(node_info, "operating_system", None),
            "os_image": getattr(node_info, "os_image", None),
            "kernel_version": getattr(node_info, "kernel_version", None),
            "container_runtime_version": getattr(
                node_info, "container_runtime_version", None
            ),
            "kubelet_version": getattr(node_info, "kubelet_version", None),
        },
    }


def _persistent_volume_source(spec: Any) -> dict[str, Any]:
    source_attributes = (
        "csi",
        "nfs",
        "host_path",
        "local",
        "iscsi",
        "cephfs",
        "rbd",
        "azure_disk",
        "azure_file",
        "aws_elastic_block_store",
        "gce_persistent_disk",
    )
    for attribute in source_attributes:
        source = getattr(spec, attribute, None)
        if source is None:
            continue
        result = {"type": attribute}
        if attribute == "csi":
            result.update({
                "driver": getattr(source, "driver", None),
                "fs_type": getattr(source, "fs_type", None),
                "read_only": getattr(source, "read_only", None),
            })
        return {key: value for key, value in result.items() if value is not None}
    return {"type": "other_or_unspecified"}


def _persistent_volume_row(volume: Any) -> dict[str, Any]:
    claim_reference = getattr(volume.spec, "claim_ref", None)
    return {
        "evidence_id": _k8s_evidence_id(
            "PersistentVolume", volume.metadata.name
        ),
        "kind": "PersistentVolume",
        "name": volume.metadata.name,
        "phase": getattr(volume.status, "phase", None),
        "storage_class_name": getattr(volume.spec, "storage_class_name", None),
        "capacity": serializable(getattr(volume.spec, "capacity", None) or {}),
        "access_modes": list(getattr(volume.spec, "access_modes", None) or []),
        "volume_mode": getattr(volume.spec, "volume_mode", None),
        "reclaim_policy": getattr(
            volume.spec, "persistent_volume_reclaim_policy", None
        ),
        "mount_options": list(getattr(volume.spec, "mount_options", None) or []),
        "node_affinity": serializable(getattr(volume.spec, "node_affinity", None)),
        "claim_reference": {
            "namespace": getattr(claim_reference, "namespace", None),
            "name": getattr(claim_reference, "name", None),
        } if claim_reference is not None else None,
        "storage_source": _persistent_volume_source(volume.spec),
    }


def _collect_storage_evidence(
    core_api: client.CoreV1Api,
    pod: Any,
    namespace: str,
    limitations: list[dict[str, str]],
) -> list[dict[str, Any]]:
    claim_volumes: dict[str, list[dict[str, Any]]] = {}
    for volume in getattr(pod.spec, "volumes", None) or []:
        claim_source = getattr(volume, "persistent_volume_claim", None)
        claim_name = getattr(claim_source, "claim_name", None)
        if not claim_name:
            continue
        claim_volumes.setdefault(str(claim_name), []).append({
            "volume_name": volume.name,
            "read_only": bool(getattr(claim_source, "read_only", False)),
        })

    mounts_by_volume: dict[str, list[dict[str, Any]]] = {}
    for container_spec in getattr(pod.spec, "containers", None) or []:
        for mount in getattr(container_spec, "volume_mounts", None) or []:
            mounts_by_volume.setdefault(str(mount.name), []).append({
                "container": container_spec.name,
                "mount_path": getattr(mount, "mount_path", None),
                "read_only": bool(getattr(mount, "read_only", False)),
                "sub_path": getattr(mount, "sub_path", None),
            })

    output = []
    for claim_name, pod_volumes in sorted(claim_volumes.items()):
        mount_rows = [
            mount
            for pod_volume in pod_volumes
            for mount in mounts_by_volume.get(pod_volume["volume_name"], [])
        ]
        row: dict[str, Any] = {
            "evidence_id": _k8s_evidence_id(
                "PersistentVolumeClaim", claim_name, namespace
            ),
            "kind": "PersistentVolumeClaim",
            "namespace": namespace,
            "name": claim_name,
            "pod_volumes": pod_volumes,
            "container_mounts": mount_rows,
            "api_read_ok": False,
            "persistent_volume": None,
        }
        try:
            claim = core_api.read_namespaced_persistent_volume_claim(
                claim_name,
                namespace,
            )
            row.update({
                "api_read_ok": True,
                "phase": getattr(claim.status, "phase", None),
                "storage_class_name": getattr(
                    claim.spec, "storage_class_name", None
                ),
                "requested_storage": serializable(
                    (getattr(claim.spec, "resources", None).requests or {}).get(
                        "storage"
                    )
                    if getattr(claim.spec, "resources", None) is not None
                    else None
                ),
                "capacity": serializable(
                    getattr(claim.status, "capacity", None) or {}
                ),
                "access_modes": list(
                    getattr(claim.status, "access_modes", None)
                    or getattr(claim.spec, "access_modes", None)
                    or []
                ),
                "volume_mode": getattr(claim.spec, "volume_mode", None),
                "volume_name": getattr(claim.spec, "volume_name", None),
                "conditions": _k8s_conditions(
                    getattr(claim.status, "conditions", None)
                ),
                "usage": {
                    "available": False,
                    "reason": "not_exposed_by_kubernetes_api",
                },
            })
        except Exception as exc:
            _k8s_limitation(
                limitations,
                operation="read_namespaced_persistent_volume_claim",
                kind="PersistentVolumeClaim",
                name=claim_name,
                error=exc,
            )
            output.append(row)
            continue

        volume_name = row.get("volume_name")
        if volume_name:
            try:
                volume = core_api.read_persistent_volume(str(volume_name))
                row["persistent_volume"] = _persistent_volume_row(volume)
            except Exception as exc:
                _k8s_limitation(
                    limitations,
                    operation="read_persistent_volume",
                    kind="PersistentVolume",
                    name=str(volume_name),
                    error=exc,
                )
        output.append(row)
    return output


def _k8s_event_rows(events: Any) -> list[dict[str, Any]]:
    rows = []
    for event in getattr(events, "items", None) or []:
        involved_object = getattr(event, "involved_object", None)
        rows.append({
            "evidence_id": _k8s_evidence_id(
                "Event",
                str(getattr(event.metadata, "name", "unknown")),
                getattr(event.metadata, "namespace", None),
            ),
            "type": event.type,
            "namespace": getattr(involved_object, "namespace", None),
            "object_kind": getattr(involved_object, "kind", None),
            "object_name": getattr(involved_object, "name", None),
            "object_uid": getattr(involved_object, "uid", None),
            "field_path": getattr(involved_object, "field_path", None),
            "reason": event.reason,
            "message": event.message,
            "count": event.count,
            "count_semantics": "aggregated_occurrence_count",
            "first_timestamp": _k8s_timestamp(event.first_timestamp),
            "last_timestamp": _k8s_timestamp(event.last_timestamp),
            "event_time": _k8s_timestamp(getattr(event, "event_time", None)),
            "series": serializable(getattr(event, "series", None)),
        })
    rows.sort(
        key=lambda row: str(
            row.get("last_timestamp")
            or row.get("event_time")
            or row.get("first_timestamp")
            or ""
        )
    )
    return rows[-30:]


def collect_kubernetes_evidence(target: dict[str, str]) -> dict[str, Any]:
    namespace, pod_name = target["namespace"], target["pod"]
    limitations: list[dict[str, str]] = []
    try:
        core_api = k8s_core()
        pod = core_api.read_namespaced_pod(pod_name, namespace)
    except Exception as exc:
        return {
            "source": "kubernetes_api",
            "role": "preliminary_cluster_state_evidence",
            "ok": False,
            "error": str(exc),
            **target,
        }

    try:
        events = core_api.list_namespaced_event(
            namespace,
            field_selector=f"involvedObject.name={pod_name}",
        )
        event_rows = _k8s_event_rows(events)
    except Exception as exc:
        event_rows = []
        _k8s_limitation(
            limitations,
            operation="list_namespaced_event",
            kind="Event",
            name=pod_name,
            error=exc,
        )

    specs = {item.name: item for item in (pod.spec.containers or [])}
    containers = []
    for status in pod.status.container_statuses or []:
        spec = specs.get(status.name)
        containers.append({
            "evidence_id": _k8s_evidence_id(
                "Container", f"{pod_name}/{status.name}", namespace
            ),
            "name": status.name,
            "image": status.image,
            "image_id": getattr(status, "image_id", None),
            "ready": status.ready,
            "started": getattr(status, "started", None),
            "restart_count": status.restart_count,
            "restart_count_semantics": "cumulative_since_container_creation",
            "state": serializable(status.state),
            "last_state": serializable(status.last_state),
            "resources": serializable(spec.resources if spec else None),
        })

    try:
        workload = _collect_workload_evidence(
            pod,
            namespace,
            k8s_apps(),
            limitations,
        )
    except Exception as exc:
        pod_owner = _k8s_owner_reference(pod.metadata)
        workload = {
            "pod_controller": _k8s_owner_row(pod_owner),
            "replica_set": None,
            "deployment": None,
        }
        _k8s_limitation(
            limitations,
            operation="initialize_apps_api",
            kind="WorkloadController",
            name=pod_name,
            error=exc,
        )
    node_name = getattr(pod.spec, "node_name", None)
    node_details = _collect_node_evidence(core_api, node_name, limitations)
    storage = _collect_storage_evidence(core_api, pod, namespace, limitations)

    return {
        "source": "kubernetes_api",
        "role": "preliminary_cluster_state_evidence",
        "ok": True,
        "evidence_id": _k8s_evidence_id("Pod", pod_name, namespace),
        "namespace": namespace,
        "pod": pod_name,
        "labels": pod.metadata.labels or {},
        "pod_spec": sanitize_evidence(serializable(pod.spec)),
        "collected_at": now_iso(),
        "owner_references": serializable(pod.metadata.owner_references or []),
        "workload_controller": workload["pod_controller"],
        "replica_set": workload["replica_set"],
        "deployment": workload["deployment"],
        "node": node_name,
        "node_details": node_details,
        "persistent_volume_claims": storage,
        "phase": pod.status.phase,
        "pod_ip": pod.status.pod_ip,
        "start_time": _k8s_timestamp(pod.status.start_time),
        "conditions": _k8s_conditions(pod.status.conditions),
        "containers": containers,
        "events": event_rows,
        "event_sample_limit": 30,
        "collection_limitations": limitations,
    }


def loki_query(query: str) -> dict[str, Any]:
    end_ns = int(time.time() * 1_000_000_000)
    start_ns = int((time.time() - LOKI_LOOKBACK_MINUTES * 60) * 1_000_000_000)
    try:
        response = requests.get(
            f"{LOKI_URL}/loki/api/v1/query_range",
            params={
                "query": query,
                "start": str(start_ns),
                "end": str(end_ns),
                "limit": "50",
                "direction": "backward",
            },
            timeout=25,
        )
        response.raise_for_status()
        body = response.json()
        if body.get("status") != "success":
            raise RuntimeError(str(body))
        return {"ok": True, "streams": body.get("data", {}).get("result", []) or [], "error": None, "start_ns": str(start_ns), "end_ns": str(end_ns)}
    except Exception as exc:
        return {"ok": False, "streams": [], "error": str(exc), "start_ns": str(start_ns), "end_ns": str(end_ns)}


def collect_loki_evidence(target: dict[str, str]) -> dict[str, Any]:
    namespace, pod = target["namespace"], target["pod"]
    queries = [
        f'{{namespace="{namespace}", pod="{pod}"}}',
        f'{{namespace="{namespace}", pod="{pod}"}} |= "ERROR"',
        f'{{namespace="{namespace}", pod="{pod}"}} |= "WARNING"',
        f'{{namespace="{namespace}", pod="{pod}"}} |= "timeout"',
        f'{{namespace="{namespace}", pod="{pod}"}} |= "failed"',
    ]

    output = []
    for query in queries:
        result = loki_query(query)
        entries = []
        for stream in result["streams"]:
            labels = stream.get("stream") or {}
            container = labels.get("container") or labels.get("container_name")
            instance = str(labels.get("instance") or "")
            if not container and instance.startswith(f"{namespace}/{pod}:"):
                container = instance.rsplit(":", 1)[-1]
            for timestamp, line, *_ in stream.get("values", []) or []:
                entries.append({
                    "timestamp_ns": str(timestamp), "line": str(line), "labels": labels,
                    "container": container,
                    "target_container_match": container == target["container"] if container else None,
                })
        entries.sort(key=lambda x: int(x["timestamp_ns"]), reverse=True)
        returned_count = len(entries)
        entries = entries[:20]
        output.append({
            "query": query,
            "ok": result["ok"],
            "error": result["error"],
            "sample_count": len(entries),
            "sample_lines": [item["line"] for item in entries],
            "sample_entries": entries,
            "scope": "pod", "target_container": target["container"],
            "start_ns": result.get("start_ns"), "end_ns": result.get("end_ns"),
            "returned_count": returned_count,
            "omitted_before_normalization": max(0, returned_count - len(entries)),
            "unattributed_sample_count": sum(item["container"] is None for item in entries),
            "other_container_sample_count": sum(item["target_container_match"] is False for item in entries),
        })

    return {
        "source": "loki",
        "role": "preliminary_log_evidence",
        "lookback_minutes": LOKI_LOOKBACK_MINUTES,
        "queries": output,
    }

# =============================================================================
# Briefs and OpenSRE handoff
# =============================================================================

def build_initial_brief(
    case_id: str,
    target: dict[str, str],
    risks: list[dict[str, Any]],
    prom: list[dict[str, Any]],
    k8s: dict[str, Any],
    loki: dict[str, Any],
    coordinator_scope: dict[str, Any],
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "generated_at": now_iso(),
        "stage": "initial",
        "target": target,
        "coordinator_scope": coordinator_scope,
        "detected_risks": risks,
        "evidence": {"prometheus": prom, "kubernetes_api": k8s, "loki": loki},
    }


def build_final_brief(initial: dict[str, Any], kagent: dict[str, Any]) -> dict[str, Any]:
    target = initial["target"]
    risks = initial["detected_risks"]
    primary = risks[0] if risks else {}

    evidence_handoff = build_evidence_handoff(
        initial["evidence"],
        kagent,
        raw_reference="kagent_investigation.json",
    )

    return {
        "alertname": "ProactiveKubernetesRisk",
        "status": "firing",
        "labels": {
            "namespace": target["namespace"],
            "pod": target["pod"],
            "container": target["container"],
            "primary_risk_type": primary.get("risk_type"),
        },
        "annotations": {
            "summary": f"Potential Kubernetes risk detected for {target['namespace']}/{target['pod']}",
            "description": "Risk signals and operational evidence were collected before final SRE analysis.",
        },
        "incident_context": {
            "case_id": initial["case_id"],
            "generated_at": now_iso(),
            "target": target,
            "detected_risks": risks,
            "detection_status": initial.get("detection_status"),
            "evidence_handoff": evidence_handoff,
            "analysis_request": {
                "expected": ["possible causes", "impact", "recommendations", "uncertainty and limitations"],
                "rules": [
                    "Use the supplied evidence as the factual boundary.",
                    "Do not present unsupported hypotheses as confirmed root causes.",
                    "Failed or missing evidence is a limitation, not proof of absence.",
                ],
            },
        },
    }

# =============================================================================
# Main
# =============================================================================

def group_by_target(risks: list[dict[str, Any]]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for risk in risks:
        key = (risk["namespace"], risk["pod"], risk["container"])
        grouped.setdefault(key, []).append(risk)
    return grouped


def build_discovered_investigation_scope(
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]]
) -> dict[str, Any]:
    """Describe every target dynamically selected by the coordinator for this run."""
    targets: list[dict[str, Any]] = []
    namespaces: set[str] = set()
    pods: set[str] = set()

    for (namespace, pod, container_name), target_risks in grouped.items():
        namespaces.add(namespace)
        pods.add(f"{namespace}/{pod}")
        targets.append({
            "namespace": namespace,
            "pod": pod,
            "container": container_name,
            "risk_count": len(target_risks),
            "risk_types": [str(risk.get("risk_type")) for risk in target_risks],
        })

    return {
        "selection_mode": "dynamic_from_detected_risks",
        "selection_source": "prometheus_risk_detection",
        "running_pods_only": True,
        "target_count": len(targets),
        "namespaces": sorted(namespaces),
        "pods": sorted(pods),
        "targets": targets,
    }


def build_case_coordinator_scope(
    target: dict[str, str],
    case_risks: list[dict[str, Any]],
    run_scope: dict[str, Any],
) -> dict[str, Any]:
    """Give Kagent the exact current target plus the coordinator's dynamic run context."""
    return {
        "ownership": {
            "where": "coordinator",
            "how": "kagent",
            "final_analysis": "opensre",
        },
        "selection_mode": "dynamic_per_detected_target",
        "current_target": target,
        "current_target_risk_types": [
            str(risk.get("risk_type")) for risk in case_risks
        ],
        "all_detected_targets": run_scope.get("targets") or [],
        "instruction": (
            "Investigate only current_target. all_detected_targets is informational "
            "run context and must not be mixed into this case."
        ),
    }


def main() -> int:
    run_dir = OUTPUT_ROOT / f"run_{new_run_id()}"
    run_dir.mkdir(parents=True, exist_ok=False)
    summary_file = run_dir / "run_summary.json"
    started = time.monotonic()
    summary: dict[str, Any] = {
        "generated_at": now_iso(), "status": "running", "ok": None,
        "end_to_end_complete": False, "cases": [],
        "scan_scope": {
            "cluster": "current_oscar_kubernetes_cluster", "running_pods_only": True,
            "included_namespaces": list(RISK_INCLUDED_NAMESPACES),
            "excluded_namespaces": list(RISK_EXCLUDED_NAMESPACES),
            "included_pods": list(RISK_INCLUDED_PODS),
            "excluded_pods": list(RISK_EXCLUDED_PODS),
        },
    }
    write_json(summary_file, summary)
    print("Coordinator: detect -> initial evidence -> adaptive Kagent -> OpenSRE", flush=True)
    print(f"Run directory: {run_dir}", flush=True)
    print("Included namespaces: " + (", ".join(RISK_INCLUDED_NAMESPACES) or "all"), flush=True)
    print("Included pods: " + (", ".join(RISK_INCLUDED_PODS) or "all"), flush=True)
    print("Pod phase: Running only", flush=True)
    print(f"OpenSRE automatic execution: {AUTO_RUN_OPENSRE}", flush=True)

    detection_status: dict[str, Any] = {}
    risks = detect_risks(detection_status)
    grouped = group_by_target(risks)
    discovered_scope = build_discovered_investigation_scope(grouped)
    summary.update({"risks": risks, "detection_status": detection_status,
                    "discovered_investigation_scope": discovered_scope})
    write_json(run_dir / "discovered_investigation_scope.json", discovered_scope)
    write_json(summary_file, summary)
    print(f"Detected risk signals: {len(risks)} | cases: {len(grouped)}", flush=True)
    if not detection_status.get("ok"):
        print("Detection incomplete: one or more Prometheus queries failed; see run_summary.json.", flush=True)

    for number, ((namespace, pod, container_name), case_risks) in enumerate(grouped.items(), 1):
        case_id = f"{number:02d}_{safe_name(namespace)}_{safe_name(pod)}_{safe_name(container_name)}"
        case_dir = run_dir / "cases" / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        target = {"namespace": namespace, "pod": pod, "container": container_name}
        row: dict[str, Any] = {"case_id": case_id, "target": target, "risk_count": len(case_risks),
                               "ok": False, "status": "running", "started_at": now_iso()}
        summary["cases"].append(row)
        case_started = time.monotonic()

        def stage(name: str) -> None:
            row["stage"] = name
            write_json(case_dir / "case_status.json", row)
            write_json(summary_file, summary)
            print(f"Case {number}/{len(grouped)}: {namespace}/{pod}/{container_name} | {name}", flush=True)

        try:
            stage("initial_evidence")
            prom = [{"risk": risk, "evidence": collect_prometheus_evidence(risk)} for risk in case_risks]
            k8s = collect_kubernetes_evidence(target)
            loki = collect_loki_evidence(target)
            coordinator_scope = build_case_coordinator_scope(target, case_risks, discovered_scope)
            initial = build_initial_brief(case_id, target, case_risks, prom, k8s, loki, coordinator_scope)
            initial["detection_status"] = detection_status
            initial_path = case_dir / "brief_initial.json"
            write_json(initial_path, initial)
            row["brief_initial"] = str(initial_path)
            row["evidence_collection_ok"] = bool(
                k8s.get("ok") is True and not k8s.get("collection_limitations")
                and all(query.get("ok") is True for query in loki.get("queries", []))
                and all(m.get("ok") is True for record in prom for m in record["evidence"]["measurements"])
            )

            stage("kagent")
            kagent = run_kagent(initial, case_dir)
            write_json(case_dir / "kagent_investigation.json", kagent)
            row.update({
                "kagent_investigation_complete": kagent.get("investigation_complete", False),
                "kagent_final_target_scope_ok": kagent.get("final_target_scope_ok", False),
                "kagent_successful_tool_count": kagent.get("successful_tool_count", 0),
                "kagent_limitations": kagent.get("limitations", []),
            })
            print(f"Kagent validated tool evidence: {row['kagent_successful_tool_count']}", flush=True)

            stage("final_brief")
            final = build_final_brief(initial, kagent)
            final_path = case_dir / "brief_final.json"
            write_json(final_path, final)
            row["brief_final"] = str(final_path)
            row["handoff_limitations"] = final["incident_context"]["evidence_handoff"]["limitations"]
            row["evidence_transport_ok"] = final["incident_context"]["evidence_handoff"]["transport_integrity"]["ok"]

            if AUTO_RUN_OPENSRE:
                stage("opensre")
                opensre = run_opensre(final_path, case_dir)
            else:
                opensre = {"ran": False, "skipped": True, "reason": "AUTO_RUN_OPENSRE=0", "ok": None}
                write_json(case_dir / "opensre_status.json", opensre)
            row["opensre"] = opensre
            row["diagnosis_quality_status"] = opensre.get("diagnosis_quality_status", "unavailable")
            row["ok"] = bool(
                row["evidence_collection_ok"] and row["evidence_transport_ok"] and row["kagent_investigation_complete"]
                and row["kagent_final_target_scope_ok"]
                and (not AUTO_RUN_OPENSRE or opensre.get("ok") is True)
            )
            row["end_to_end_complete"] = row["ok"] and AUTO_RUN_OPENSRE
            row["status"] = "completed" if row["ok"] else "completed_with_errors"
            if opensre.get("ok") and opensre.get("report_file"):
                print(f"OpenSRE report: {opensre['report_file']}", flush=True)
        except KeyboardInterrupt:
            row.update({"status": "interrupted", "ok": False, "error": "KeyboardInterrupt"})
            summary.update({"status": "interrupted", "ok": False})
            raise
        except Exception as exc:
            row.update({"status": "failed", "ok": False, "error": f"{type(exc).__name__}: {exc}"})
            print(f"Case failed at {row.get('stage')}: {row['error']}", flush=True)
        finally:
            row["finished_at"] = now_iso()
            row["elapsed_seconds"] = round(time.monotonic() - case_started, 2)
            write_json(case_dir / "case_status.json", row)
            write_json(summary_file, summary)

    summary["ok"] = bool(detection_status.get("ok") and all(item["ok"] for item in summary["cases"]))
    summary["end_to_end_complete"] = bool(summary["cases"] and summary["ok"] and AUTO_RUN_OPENSRE)
    summary["diagnosis_quality_status"] = "requires_review" if summary["end_to_end_complete"] else "unavailable"
    summary["status"] = "completed" if summary["ok"] else "completed_with_errors"
    summary["finished_at"] = now_iso()
    summary["elapsed_seconds"] = round(time.monotonic() - started, 2)
    write_json(summary_file, summary)
    print(f"Run summary: {summary_file} | ok={summary['ok']}", flush=True)
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
