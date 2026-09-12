#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

if __package__:
    from .evidence_normalizer import check_payload_size, compact_value
else:
    from evidence_normalizer import check_payload_size, compact_value

PROJECT_DIR = Path(__file__).resolve().parent.parent

OPENSRE_CLUSTER_RUNNER = os.environ.get(
    "OPENSRE_CLUSTER_RUNNER", "scripts/run_opensre_cluster_investigation.sh"
)
OPENSRE_EVALUATE = os.environ.get("OPENSRE_EVALUATE", "0").strip().lower() in {
    "1", "true", "yes", "on"
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    temporary.replace(path)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def find_report_text(value: Any) -> str | None:
    """Accept explicit report fields; an arbitrary long error is not a report."""
    if not isinstance(value, dict):
        return None
    for key in ("report", "final_report"):
        text = value.get(key)
        if isinstance(text, str) and text.strip():
            return text.strip()
    return None


def _compact_opensre_handoff(value: Any) -> Any:
    """Compatibility name: forward the entire prepared handoff without projection."""
    if not isinstance(value, dict):
        raise ValueError("OpenSRE requires a structured evidence handoff")
    integrity = value.get("transport_integrity") or {}
    if integrity.get("ok") is not True:
        raise ValueError("Rebuild this brief with evidence preservation before inference")
    check_payload_size(value, "Complete OpenSRE evidence handoff")
    return json.loads(json.dumps(value, ensure_ascii=False))


def resolve_cluster_runner() -> Path:
    path = Path(OPENSRE_CLUSTER_RUNNER).expanduser()
    if not path.is_absolute():
        path = PROJECT_DIR / path
    return path.resolve()


def build_opensre_alert(brief: dict[str, Any]) -> dict[str, Any]:
    """
    Convert the Coordinator final brief to OpenSRE's generic alert payload.

    This is interface adaptation only. It does not diagnose, rank evidence,
    resolve contradictions, or invent missing facts.
    """
    ctx = brief.get("incident_context") or {}
    labels = brief.get("labels") or {}
    annotations = brief.get("annotations") or {}

    target = ctx.get("target") or {}
    risks = ctx.get("detected_risks") or []

    namespace = target.get("namespace") or labels.get("namespace") or "unknown"
    pod = target.get("pod") or labels.get("pod") or "unknown"
    container = target.get("container") or labels.get("container") or "unknown"

    first_risk = risks[0] if risks and isinstance(risks[0], dict) else {}
    risk_type = (
        labels.get("primary_risk_type")
        or first_risk.get("risk_type")
        or brief.get("alertname")
        or "KubernetesRisk"
    )
    severity = str(first_risk.get("priority") or "unknown")
    case_id = str(ctx.get("case_id") or f"{namespace}_{pod}_{container}")

    evidence_package = {
        "case_id": ctx.get("case_id"),
        "generated_at": ctx.get("generated_at"),
        "target": target,
        "detected_risks": risks,
        "detection_status": ctx.get("detection_status"),
        "evidence_handoff": _compact_opensre_handoff(ctx.get("evidence_handoff")),
        "analysis_request": ctx.get("analysis_request"),
    }

    message = (
        "Consolidated Kubernetes incident evidence produced by the incident coordinator.\n\n"
        f"Target namespace: {namespace}\n"
        f"Target pod: {pod}\n"
        f"Target container: {container}\n"
        f"Primary detected risk: {risk_type}\n\n"
        "Analysis boundary:\n"
        "Use only the supplied evidence as the factual boundary. "
        "Distinguish observed facts from hypotheses. "
        "Classify diagnostic conclusions as directly observed facts, supported inferences, hypotheses, or missing evidence. "
        "When several explanations are plausible, compare them against all supplied evidence and identify the explanation with the strongest factual support and fewest unsupported assumptions as the most likely explanation. "
        "A most-likely explanation is still an inference unless direct evidence specifically confirms the causal claim. "
        "Do not promote correlation, compatibility, plausibility, or a single ambiguous indicator into a confirmed root cause. "
        "Configuration values establish configured state only; they do not by themselves prove runtime behavior or that a configured threshold was actually reached. "
        "Preserve conflicting observations and observations from different timestamps, container attempts, or resource instances instead of silently merging them into one causal event. "
        "When evidence conflicts, explain which interpretation is better supported and why, while retaining credible alternatives when the evidence is not conclusive. "
        "Treat model-authored or explicitly non-authoritative summaries as investigative leads rather than primary factual evidence; prefer the underlying observed and validated evidence. "
        "If evidence was partial, truncated, omitted, unavailable, or outside the observation window, do not interpret the missing observation as proof that the condition did not occur. "
        "Use confirmed language only for claims directly supported by evidence; otherwise use calibrated terms such as likely, most consistent with, suggests, or possible. "
        "For the leading diagnosis, explain the supporting facts, remaining uncertainty, and what additional observation would confirm or refute it. "
        "Do not present unsupported hypotheses as confirmed root causes. "
        "If the evidence is insufficient to determine the internal application cause, "
        "state that limitation explicitly. "
        "Cumulative restart counts and event occurrence counts are not restarts per time window. "
        "Keep metric values, units, observation times and source identities together. "
        "CPU/memory requests and limits are configuration, not measurements of actual usage. "
        "Use a log's container identity; do not attribute another container's logs to the target. "
        "Report fields omitted during compaction as unavailable rather than absent. "
        "Explain the material observations and uncertainty without repeating raw JSON. "
        "For every confirmed finding, name its evidence source and observation time or evidence ID. "
        "Distinguish Kubernetes runtime startup failures, application exits and log-collection errors. "
        "A log-retrieval failure establishes an observation limitation, not an application root cause. "
        "Use the complete error reason, including its suffix, before proposing permissions or configuration problems. "
        "Do not label borrowed evidence as tools you personally tested; this mode uses precollected evidence. "
        "Do not state any causal mechanism or root cause as confirmed unless the supplied observations directly support that causal claim. "

        "Tie actions to the supported findings and keep unverified remedies conditional. "
        "Do not repeat the complete evidence package and do not perform additional tool calls; "
        "analyze only the supplied evidence.\n\n"
        "Consolidated evidence package:\n"
        + json.dumps(
            evidence_package,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    )

    check_payload_size(message, "OpenSRE alert message")

    summary = str(
        annotations.get("summary")
        or f"Kubernetes risk {risk_type} detected for {namespace}/{pod}/{container}"
    )
    summary += (
        ". Normalized Prometheus, Kubernetes API, Loki and validated agent evidence "
        "is included in the alert message; full raw records remain in the case artifacts."
    )

    return {
        "alert_name": str(risk_type),
        "pipeline_name": str(pod),
        "severity": severity,
        "alert_source": "kubernetes",
        "event_producer": "incident-coordinator",
        "investigation_mode": "precollected_evidence",
        "kube_namespace": str(namespace),
        "pod_name": str(pod),
        "container_name": str(container),
        "message": message,
        "commonAnnotations": {
            "summary": summary,
            "correlation_id": case_id,
        },
    }


def run_opensre(brief_path: Path, output_dir: Path) -> dict[str, Any]:
    brief_path, output_dir = Path(brief_path).resolve(), Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    status: dict[str, Any] = {
        "ok": False,
        "state": "preparing",
        "ran": False,
        "execution_mode": "cluster_pod_http",
        "brief_file": str(brief_path),
        "report_file": None,
        "started_at": utc_now(),
    }
    try:
        if shutil.which("kubectl") is None:
            raise RuntimeError("kubectl executable not found in PATH")
        cluster_runner = resolve_cluster_runner()
        if not cluster_runner.is_file():
            raise RuntimeError(f"OpenSRE cluster runner not found: {cluster_runner}")
        if OPENSRE_EVALUATE:
            raise RuntimeError("OPENSRE_EVALUATE is not supported by the cluster runner")
        brief = read_json(brief_path)
        if not isinstance(brief, dict) or not brief:
            raise ValueError("Final brief must be a non-empty JSON object")
        alert = build_opensre_alert(brief)
        alert_file = output_dir / "opensre_alert.json"
        output_file = output_dir / "opensre_output.json"
        stdout_log = output_dir / "opensre_stdout.log"
        report_file = output_dir / "opensre_report.md"
        # Preserve artifacts from a manual rerun of the same case directory.
        previous = [output_dir / name for name in (
            "opensre_output.json", "opensre_report.md", "opensre_status.json",
            "status.json", "client.log", "opensre_stdout.log", "opensre_alert.json",
        ) if (output_dir / name).exists()]
        if previous:
            archive = output_dir / "previous_opensre" / str(time.time_ns())
            archive.mkdir(parents=True)
            for path in previous:
                path.replace(archive / path.name)
        write_json(alert_file, alert)
        command = ["bash", str(cluster_runner), str(alert_file), str(output_dir)]
        status.update({"command": command, "ran": True,
                       "opensre_alert_file": str(alert_file), "opensre_output_file": str(output_file),
                       "stdout_log_file": str(stdout_log), "cluster_status_file": str(output_dir / "status.json"),
                       "report_target_file": str(report_file), "state": "running"})
        # Write before the blocking call. A live status file makes a long
        # model request observable and survives a disconnected local terminal.
        write_json(output_dir / "opensre_status.json", status)
        print(f"OpenSRE: calling cluster Pod | alert characters={len(alert['message'])}", flush=True)
        process = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, timeout=None, cwd=str(PROJECT_DIR))
        stdout_log.write_text(process.stdout or "", encoding="utf-8")
        status["return_code"] = process.returncode
        output_json = None
        parse_error = None
        try:
            output_json = read_json(output_file)
        except Exception as exc:
            parse_error = f"{type(exc).__name__}: {exc}"
        status["output_json_parse_error"] = parse_error
        report = find_report_text(output_json)
        application_ok = isinstance(output_json, dict) and not output_json.get("error") \
            and output_json.get("ok") is not False and output_json.get("success") is not False
        status["ok"] = bool(process.returncode == 0 and application_ok and report)
        status["state"] = "completed" if status["ok"] else "failed"
        if status["ok"]:
            report_file.write_text(report + "\n", encoding="utf-8")
            status["report_file"] = str(report_file)
        else:
            status["error"] = parse_error or "OpenSRE did not return a successful response with a non-empty report; inspect client.log and opensre_output.json."
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
        status["state"] = "failed"
    status["elapsed_seconds"] = round(time.monotonic() - started, 2)
    status["finished_at"] = utc_now() if status.get("state") == "completed" or status.get("state") == "failed" else None
    status["evaluation_enabled"] = OPENSRE_EVALUATE
    status["execution_ok"] = status["ok"]
    status["diagnosis_quality_status"] = "requires_review" if status["ok"] else "unavailable"
    status["diagnosis_quality_note"] = "A successful response is not an independent factuality evaluation."
    write_json(output_dir / "opensre_status.json", status)
    return status


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Adapt a consolidated incident brief to an OpenSRE generic alert and run "
            "the real OpenSRE CLI."
        )
    )
    parser.add_argument("--brief", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    try:
        status = run_opensre(args.brief.resolve(), args.output_dir.resolve())
    except Exception as exc:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        status = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "brief_file": str(args.brief),
        }
        write_json(args.output_dir / "opensre_status.json", status)
        print(json.dumps(status, ensure_ascii=False))
        raise SystemExit(1)

    print(json.dumps(status, ensure_ascii=False))
    raise SystemExit(0 if status.get("ok") else 1)


if __name__ == "__main__":
    main()
