"""Report schema, renderers, and the on-disk cache."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import pytest

from reconlens.cache import FileCache
from reconlens.errors import ReportError
from reconlens.models import (
    Finding,
    Report,
    Severity,
    SourceRun,
    Target,
    TargetType,
    make_finding,
)
from reconlens.plugins.base import Source
from reconlens.reports.html import render_html
from reconlens.reports.json_report import load_report, render_json, report_from_dict, report_to_dict
from reconlens.reports.markdown import render_markdown

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "docs" / "report.schema.json").read_text(encoding="utf-8"))


def _report() -> Report:
    started = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 11, 22, 12, 0, 2, tzinfo=timezone.utc)
    finding = make_finding(
        source="dns",
        category="dns",
        title="A",
        value="93.184.216.34",
        detail="example <script>alert(1)</script>",
        source_url="https://example.com/a",
        severity=Severity.INFO,
        timestamp=started,
        data={"kind": "address"},
    )
    return Report(
        target=Target(value="example.com", type=TargetType.DOMAIN, original="Example.com"),
        started_at=started,
        finished_at=finished,
        sources=[
            SourceRun(
                name="dns",
                status="ok",
                duration_ms=12,
                cached=False,
                findings=[finding],
            ),
            SourceRun(
                name="virustotal",
                status="skipped",
                duration_ms=0,
                cached=False,
                findings=[],
                skip_reason="VIRUSTOTAL_API_KEY is not set",
            ),
        ],
        notices=["plugin note"],
        tool_version="0.1.0",
    )


def test_json_matches_schema_and_roundtrips() -> None:
    report = _report()
    payload = report_to_dict(report)
    jsonschema.validate(payload, SCHEMA)
    again = report_from_dict(payload)
    assert report_to_dict(again) == payload
    text = render_json(report)
    assert text.endswith("\n")
    assert load_report(text).target.value == "example.com"


def test_renderers_escape_and_keep_the_target() -> None:
    report = _report()
    markdown = render_markdown(report)
    html = render_html(report)
    assert "example.com" in markdown
    assert "93.184.216.34" in markdown
    assert "VIRUSTOTAL_API_KEY is not set" in markdown
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert 'href="https://example.com/a"' in html
    hostile = Finding(
        id="abc",
        source="dns",
        category="dns",
        title="Title",
        value="javascript:alert(1)",
        severity=Severity.INFO,
        timestamp=datetime(2026, 11, 22, tzinfo=timezone.utc),
        source_url="javascript:alert(1)",
    )
    report.sources[0].findings.append(hostile)
    rendered = render_html(report)
    assert 'href="javascript:' not in rendered
    assert "javascript:alert(1)" in rendered


def test_bad_schema_version_is_rejected() -> None:
    payload = report_to_dict(_report())
    payload["schema_version"] = "2.0.0"
    with pytest.raises(ReportError):
        report_from_dict(payload)


def test_cache_roundtrip(tmp_path: Path) -> None:
    class Tiny(Source):
        name = "dns"
        description = "cache test"
        target_types = frozenset({TargetType.DOMAIN})
        cache_version = 3

        async def run(self, target: object, ctx: object) -> list[Finding]:
            del target, ctx
            return []

    cache = FileCache(tmp_path / "cache", ttl_seconds=3600)
    target = Target("example.com", TargetType.DOMAIN, "example.com")
    finding = make_finding(source="dns", category="dns", title="A", value="1.1.1.1")
    source = Tiny()
    assert cache.get(source, target) is None
    cache.set(source, target, [finding])
    stored = cache.get(source, target)
    assert stored is not None
    assert stored[0].value == "1.1.1.1"
    mode = (tmp_path / "cache").stat().st_mode & 0o777
    assert mode == 0o700
