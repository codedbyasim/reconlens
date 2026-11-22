"""Recent public snapshots from the Wayback Machine CDX API."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source

_LIMIT = 15


class WaybackSource(Source):
    """Search existing snapshots. This does not ask the Wayback Machine to archive a URL."""

    name = "wayback"
    description = "Recent public Wayback Machine snapshots (CDX search, capture is not requested)"
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 0.5
    display_order = 80
    homepage = "https://web.archive.org/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        response = await ctx.get_public(
            "https://web.archive.org/cdx/search/cdx",
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={
                "url": target.value,
                "output": "json",
                "fl": "timestamp,original,statuscode,mimetype",
                "filter": "statuscode:200",
                "limit": str(_LIMIT),
                "collapse": "digest",
            },
        )
        if response.status_code == 404 or not response.content.strip():
            return _empty(self.name, target.value)
        if response.status_code == 429:
            raise SourceError("Wayback Machine rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"Wayback Machine returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, list):
            raise SourceError("Wayback Machine returned an unexpected payload")
        return findings_from_cdx(self.name, target.value, payload)


def findings_from_cdx(source: str, domain: str, rows: list[Any]) -> list[Finding]:
    """Turn a CDX JSON table into snapshot findings."""

    snapshots = _snapshots(rows)
    if not snapshots:
        return _empty(source, domain)
    findings: list[Finding] = []
    for timestamp, original, status in snapshots[:_LIMIT]:
        link = f"https://web.archive.org/web/{timestamp}/{original}"
        findings.append(
            make_finding(
                source=source,
                category=Category.ARCHIVE,
                title="Snapshot",
                value=original,
                detail=f"{_format_ts(timestamp)} · HTTP {status}"
                if status
                else _format_ts(timestamp),
                source_url=link,
            )
        )
    return findings


def _snapshots(rows: list[Any]) -> list[tuple[str, str, str]]:
    if len(rows) < 2 or not isinstance(rows[0], list):
        return []
    header = [str(item) for item in rows[0]]
    index = {name: position for position, name in enumerate(header)}
    if "timestamp" not in index or "original" not in index:
        return []
    found: list[tuple[str, str, str]] = []
    for row in rows[1:]:
        if not isinstance(row, list):
            continue
        timestamp = _cell(row, index["timestamp"])
        original = _cell(row, index["original"])
        status = _cell(row, index["statuscode"]) if "statuscode" in index else ""
        if not timestamp.isdigit() or not _public_http_url(original):
            continue
        found.append((timestamp, original, status))
    return found


def _public_http_url(url: str) -> bool:
    """Ignore snapshot URLs that embed credentials or use another scheme."""

    if not url:
        return False
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return False
    return not (parts.username or parts.password)


def _cell(row: list[Any], position: int) -> str:
    if position >= len(row) or row[position] is None:
        return ""
    return str(row[position]).strip()


def _format_ts(timestamp: str) -> str:
    if len(timestamp) < 8:
        return timestamp
    return f"{timestamp[0:4]}-{timestamp[4:6]}-{timestamp[6:8]}"


def _empty(source: str, domain: str) -> list[Finding]:
    return [
        make_finding(
            source=source,
            category=Category.ARCHIVE,
            title="No snapshots",
            value=domain,
            detail="The CDX API returned no HTTP 200 snapshots for this host.",
            source_url=f"https://web.archive.org/web/*/{domain}",
        )
    ]
