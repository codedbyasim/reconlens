"""Stable JSON report. Field order is part of the 1.x schema."""

from __future__ import annotations

import json
from typing import Any, cast

from reconlens.errors import ReportError
from reconlens.models import (
    SCHEMA_VERSION,
    Finding,
    Report,
    SourceRun,
    Target,
    TargetType,
    finding_from_dict,
    finding_to_dict,
    parse_time,
    summarize,
)
from reconlens.version import __version__


def report_to_dict(report: Report) -> dict[str, Any]:
    """Serialize a report. Keys stay in this order so diffs are readable."""

    summary = summarize(report)
    return {
        "schema_version": report.schema_version,
        "tool": {"name": "reconlens", "version": report.tool_version},
        "target": {
            "value": report.target.value,
            "type": report.target.type.value,
            "original": report.target.original,
        },
        "started_at": _iso_field(report, "started_at"),
        "finished_at": _iso_field(report, "finished_at"),
        "elapsed_ms": summary.elapsed_ms,
        "summary": {
            "sources_ok": summary.ok,
            "sources_skipped": summary.skipped,
            "sources_error": summary.errors,
            "findings": summary.findings,
        },
        "notices": list(report.notices),
        "sources": [_source_to_dict(source) for source in report.sources],
    }


def render_json(report: Report) -> str:
    """Pretty JSON with a trailing newline."""

    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"


def report_from_dict(payload: object) -> Report:
    """Read a 1.x report. Unknown fields are rejected by the caller via the schema."""

    if not isinstance(payload, dict):
        raise ReportError("report must be a JSON object")
    version = payload.get("schema_version", "")
    if not isinstance(version, str) or not version.startswith("1."):
        raise ReportError(f"unsupported schema_version {version!r}; this release reads 1.x reports")
    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise ReportError("tool must be an object")
    tool_version = tool.get("version", __version__)
    if not isinstance(tool_version, str):
        raise ReportError("tool.version must be a string")
    target_raw = payload.get("target")
    if not isinstance(target_raw, dict):
        raise ReportError("target must be an object")
    try:
        target = Target(
            value=str(target_raw["value"]),
            type=TargetType(str(target_raw["type"])),
            original=str(target_raw.get("original", target_raw["value"])),
        )
        started = parse_time(str(payload["started_at"]))
        finished = parse_time(str(payload["finished_at"]))
    except ReportError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportError(f"invalid report header: {exc}") from exc
    notices = payload.get("notices", [])
    if not isinstance(notices, list) or not all(isinstance(item, str) for item in notices):
        raise ReportError("notices must be a list of strings")
    sources_raw = payload.get("sources")
    if not isinstance(sources_raw, list):
        raise ReportError("sources must be a list")
    return Report(
        target=target,
        started_at=started,
        finished_at=finished,
        sources=[_source_from_dict(item) for item in sources_raw],
        notices=list(cast(list[str], notices)),
        tool_version=tool_version,
        schema_version=version or SCHEMA_VERSION,
    )


def load_report(text: str) -> Report:
    """Parse a JSON report document."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReportError(f"report is not valid JSON: {exc}") from exc
    return report_from_dict(payload)


def _source_to_dict(source: SourceRun) -> dict[str, Any]:
    return {
        "name": source.name,
        "status": source.status,
        "duration_ms": source.duration_ms,
        "cached": source.cached,
        "error": source.error,
        "skip_reason": source.skip_reason,
        "findings": [finding_to_dict(item) for item in source.findings],
    }


def _source_from_dict(payload: object) -> SourceRun:
    if not isinstance(payload, dict):
        raise ReportError("source must be an object")
    status = payload.get("status")
    if status not in {"ok", "error", "skipped"}:
        raise ReportError(f"invalid source status {status!r}")
    findings_raw = payload.get("findings", [])
    if not isinstance(findings_raw, list):
        raise ReportError("source findings must be a list")
    duration = payload.get("duration_ms", 0)
    if isinstance(duration, bool) or not isinstance(duration, int):
        raise ReportError("duration_ms must be an integer")
    error = payload.get("error")
    skip = payload.get("skip_reason")
    return SourceRun(
        name=str(payload.get("name", "")),
        status=status,
        duration_ms=duration,
        cached=bool(payload.get("cached", False)),
        findings=[_finding(item) for item in findings_raw],
        error=None if error is None else str(error),
        skip_reason=None if skip is None else str(skip),
    )


def _finding(payload: object) -> Finding:
    return finding_from_dict(payload)


def _iso_field(report: Report, name: str) -> str:
    from reconlens.models import iso

    value = report.started_at if name == "started_at" else report.finished_at
    return iso(value)
