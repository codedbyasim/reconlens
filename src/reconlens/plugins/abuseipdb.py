"""AbuseIPDB check endpoint. This reads their report; it does not file one."""

from __future__ import annotations

from typing import Any

from reconlens.coerce import as_dict
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class AbuseIpdbSource(Source):
    """Confidence score for one IP from AbuseIPDB's check API."""

    name = "abuseipdb"
    description = "AbuseIPDB confidence score for an IP (check only; no report is filed)"
    target_types = frozenset({TargetType.IP})
    requires_api_key = True
    api_key_env = "ABUSEIPDB_API_KEY"
    min_interval_seconds = 1.0
    display_order = 210
    homepage = "https://www.abuseipdb.com/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        key = ctx.require_api_key("ABUSEIPDB_API_KEY")
        page = f"https://www.abuseipdb.com/check/{target.value}"
        response = await ctx.get_public(
            "https://api.abuseipdb.com/api/v2/check",
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"ipAddress": target.value, "maxAgeInDays": "90"},
            headers={"Key": key, "Accept": "application/json"},
        )
        if response.status_code in {401, 403}:
            raise SourceError("AbuseIPDB rejected the API key")
        if response.status_code == 429:
            raise SourceError("AbuseIPDB rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"AbuseIPDB returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("AbuseIPDB returned an unexpected payload")
        return findings_from_abuseipdb(self.name, target.value, payload, page)


def findings_from_abuseipdb(
    source: str,
    ip: str,
    payload: dict[str, Any],
    page: str,
) -> list[Finding]:
    data = as_dict(payload.get("data"))
    score = data.get("abuseConfidenceScore")
    if isinstance(score, bool) or not isinstance(score, int):
        return [
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="AbuseIPDB",
                value=ip,
                detail="The response did not include a confidence score.",
                source_url=page,
            )
        ]
    if score >= 75:
        severity = Severity.HIGH
    elif score >= 25:
        severity = Severity.MEDIUM
    elif score > 0:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    reports = data.get("totalReports")
    report_text = f"{reports} reports in the last 90 days" if isinstance(reports, int) else None
    findings = [
        make_finding(
            source=source,
            category=Category.REPUTATION,
            title="Abuse confidence",
            value=str(score),
            detail=report_text,
            source_url=page,
            severity=severity,
        )
    ]
    for key, label in (
        ("isp", "ISP"),
        ("domain", "Domain"),
        ("usageType", "Usage"),
        ("countryCode", "Country"),
    ):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            findings.append(
                make_finding(
                    source=source,
                    category=Category.REPUTATION,
                    title=label,
                    value=value.strip(),
                    source_url=page,
                )
            )
    return findings
