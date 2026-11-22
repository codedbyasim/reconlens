"""Shared value types for targets, findings, and reports."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from reconlens.errors import ReportError
from reconlens.version import __version__

SCHEMA_VERSION = "1.0.0"


class TargetType(str, Enum):
    """The four target kinds the CLI accepts."""

    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    USERNAME = "username"


class Severity(str, Enum):
    """How much attention a finding deserves. Observations default to info."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Category:
    """Recommended finding categories. Plugins may use another short label."""

    DNS = "dns"
    EMAIL = "email"
    REGISTRATION = "registration"
    CERTIFICATE = "certificate"
    HTTP = "http"
    POLICY = "policy"
    ARCHIVE = "archive"
    INFRASTRUCTURE = "infrastructure"
    REPUTATION = "reputation"
    IDENTITY = "identity"
    BREACH = "breach"


SourceStatus = Literal["ok", "error", "skipped"]


def iso(value: datetime) -> str:
    """Format a timestamp as UTC ``YYYY-MM-DDTHH:MM:SSZ``."""

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. A trailing ``Z`` is accepted on Python 3.10."""

    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ReportError(f"invalid timestamp {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def finding_id(source: str, category: str, title: str, value: str) -> str:
    """Stable short id for a finding. The timestamp is not part of the id."""

    raw = "\n".join((source, category, title, value))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Target:
    """A normalized target. ``value`` is what sources query; ``original`` is the input."""

    value: str
    type: TargetType
    original: str


@dataclass(frozen=True)
class Finding:
    """One normalized observation from a single source."""

    id: str
    source: str
    category: str
    title: str
    value: str
    severity: Severity
    timestamp: datetime
    detail: str | None = None
    source_url: str | None = None
    data: dict[str, str] = field(default_factory=dict)


def make_finding(
    *,
    source: str,
    category: str,
    title: str,
    value: str,
    severity: Severity = Severity.INFO,
    detail: str | None = None,
    source_url: str | None = None,
    data: Mapping[str, str] | None = None,
    timestamp: datetime | None = None,
) -> Finding:
    """Build a finding. The runner rewrites the id after it scrubs secrets."""

    title_text = title.strip()
    value_text = value.strip()
    if not title_text:
        raise ValueError("finding title must not be empty")
    if not value_text:
        raise ValueError("finding value must not be empty")
    if data is not None:
        for key, item in data.items():
            if not isinstance(key, str) or not isinstance(item, str):
                raise TypeError("finding data must be a mapping of strings")
    observed = timestamp or datetime.now(timezone.utc)
    return Finding(
        id=finding_id(source, category, title_text, value_text),
        source=source,
        category=category,
        title=title_text,
        value=value_text,
        severity=severity,
        timestamp=observed,
        detail=None if detail is None else detail.strip() or None,
        source_url=None if source_url is None else source_url.strip() or None,
        data={} if data is None else dict(data),
    )


def with_id(finding: Finding) -> Finding:
    """Recompute ``id`` from the current title and value."""

    return replace(
        finding,
        id=finding_id(finding.source, finding.category, finding.title, finding.value),
    )


def finding_to_dict(finding: Finding) -> dict[str, object]:
    """Serialize a finding with a stable field order."""

    return {
        "id": finding.id,
        "source": finding.source,
        "category": finding.category,
        "title": finding.title,
        "value": finding.value,
        "detail": finding.detail,
        "severity": finding.severity.value,
        "source_url": finding.source_url,
        "timestamp": iso(finding.timestamp),
        "data": dict(finding.data),
    }


def finding_from_dict(payload: object) -> Finding:
    """Read a finding produced by :func:`finding_to_dict`."""

    if not isinstance(payload, dict):
        raise ReportError("finding must be an object")
    try:
        data_raw = payload.get("data", {})
        if not isinstance(data_raw, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in data_raw.items()
        ):
            raise ReportError("finding data must be an object of strings")
        detail = payload.get("detail")
        source_url = payload.get("source_url")
        return Finding(
            id=str(payload["id"]),
            source=str(payload["source"]),
            category=str(payload["category"]),
            title=str(payload["title"]),
            value=str(payload["value"]),
            detail=None if detail is None else str(detail),
            severity=Severity(str(payload["severity"])),
            source_url=None if source_url is None else str(source_url),
            timestamp=parse_time(str(payload["timestamp"])),
            data={str(key): str(item) for key, item in data_raw.items()},
        )
    except ReportError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportError(f"invalid finding: {exc}") from exc


@dataclass
class SourceRun:
    """The outcome of one source, including an empty finding list on failure."""

    name: str
    status: SourceStatus
    duration_ms: int
    cached: bool
    findings: list[Finding]
    error: str | None = None
    skip_reason: str | None = None


@dataclass
class Report:
    """Everything a renderer needs. Machine-readable JSON uses the same fields."""

    target: Target
    started_at: datetime
    finished_at: datetime
    sources: list[SourceRun]
    notices: list[str] = field(default_factory=list)
    tool_version: str = __version__
    schema_version: str = SCHEMA_VERSION

    def all_findings(self) -> list[Finding]:
        items: list[Finding] = []
        for source in self.sources:
            items.extend(source.findings)
        return items

    @property
    def elapsed_ms(self) -> int:
        delta = (self.finished_at - self.started_at).total_seconds() * 1000
        return max(0, int(delta))


@dataclass(frozen=True)
class Summary:
    """Counts renderers show in the header."""

    ok: int
    skipped: int
    errors: int
    findings: int
    elapsed_ms: int


def summarize(report: Report) -> Summary:
    return Summary(
        ok=sum(1 for source in report.sources if source.status == "ok"),
        skipped=sum(1 for source in report.sources if source.status == "skipped"),
        errors=sum(1 for source in report.sources if source.status == "error"),
        findings=sum(len(source.findings) for source in report.sources),
        elapsed_ms=report.elapsed_ms,
    )
