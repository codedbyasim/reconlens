"""Optional on-disk cache. Files are mode 0600 and contain no API keys."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from reconlens.errors import ReportError
from reconlens.models import Finding, Target, finding_from_dict, finding_to_dict, iso
from reconlens.plugins.base import Source


class FileCache:
    """JSON cache keyed by source, cache version, and target."""

    def __init__(self, directory: Path, ttl_seconds: int) -> None:
        self.directory = directory
        self.ttl_seconds = ttl_seconds
        self.directory.mkdir(parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    def get(self, source: Source, target: Target) -> list[Finding] | None:
        path = self._path(source, target)
        if not path.is_file():
            return None
        if self.ttl_seconds <= 0:
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            cached_at = _parse_cached_at(payload)
            age = (datetime.now(timezone.utc) - cached_at).total_seconds()
            if age > self.ttl_seconds:
                return None
            raw_findings = payload.get("findings")
            if not isinstance(raw_findings, list):
                return None
            return [finding_from_dict(item) for item in raw_findings]
        except (OSError, json.JSONDecodeError, ReportError, TypeError, ValueError):
            return None

    def set(self, source: Source, target: Target, findings: list[Finding]) -> None:
        path = self._path(source, target)
        payload = {
            "cached_at": iso(datetime.now(timezone.utc)),
            "source": source.name,
            "target": target.value,
            "findings": [finding_to_dict(item) for item in findings],
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(path)

    def _path(self, source: Source, target: Target) -> Path:
        raw = f"{source.name}|{source.cache_version}|{target.type.value}|{target.value}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.directory / f"{digest}.json"


def _parse_cached_at(payload: object) -> datetime:
    if not isinstance(payload, dict) or "cached_at" not in payload:
        raise ReportError("cache entry is missing cached_at")
    from reconlens.models import parse_time

    return parse_time(str(payload["cached_at"]))
