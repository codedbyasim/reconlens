"""VirusTotal v3 lookup. The target is not submitted for a new analysis."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from reconlens.coerce import as_dict
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class VirusTotalSource(Source):
    """Read the current VirusTotal report for a domain or IP."""

    name = "virustotal"
    description = (
        "VirusTotal domain or IP reputation. Lookup only; nothing is submitted for scanning."
    )
    target_types = frozenset({TargetType.DOMAIN, TargetType.IP})
    requires_api_key = True
    api_key_env = "VIRUSTOTAL_API_KEY"
    min_interval_seconds = 1.0
    display_order = 200
    homepage = "https://www.virustotal.com/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        key = ctx.require_api_key("VIRUSTOTAL_API_KEY")
        if target.type is TargetType.DOMAIN:
            collection, gui = "domains", "domain"
        else:
            collection, gui = "ip_addresses", "ip-address"
        quoted = quote(target.value, safe=":.")
        api_url = f"https://www.virustotal.com/api/v3/{collection}/{quoted}"
        page = f"https://www.virustotal.com/gui/{gui}/{quoted}"
        response = await ctx.get_public(
            api_url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            headers={"x-apikey": key, "Accept": "application/json"},
        )
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.REPUTATION,
                    title="No VirusTotal record",
                    value=target.value,
                    source_url=page,
                )
            ]
        if response.status_code in {401, 403}:
            raise SourceError("VirusTotal rejected the API key")
        if response.status_code == 429:
            raise SourceError("VirusTotal rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"VirusTotal returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("VirusTotal returned an unexpected payload")
        return findings_from_virustotal(self.name, target.value, payload, page)


def findings_from_virustotal(
    source: str,
    target: str,
    payload: dict[str, Any],
    page: str,
) -> list[Finding]:
    attributes = as_dict(as_dict(payload.get("data")).get("attributes"))
    stats = as_dict(attributes.get("last_analysis_stats"))
    malicious = _count(stats.get("malicious"))
    suspicious = _count(stats.get("suspicious"))
    harmless = _count(stats.get("harmless"))
    if malicious >= 5:
        severity = Severity.HIGH
    elif malicious > 0:
        severity = Severity.MEDIUM
    elif suspicious > 0:
        severity = Severity.LOW
    else:
        severity = Severity.INFO
    findings = [
        make_finding(
            source=source,
            category=Category.REPUTATION,
            title="VirusTotal analysis",
            value=f"{malicious} malicious, {suspicious} suspicious, {harmless} harmless",
            detail="Counts are from VirusTotal's last analysis of existing data.",
            source_url=page,
            severity=severity,
        )
    ]
    reputation = attributes.get("reputation")
    if isinstance(reputation, int):
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="VirusTotal reputation",
                value=str(reputation),
                source_url=page,
            )
        )
    categories = as_dict(attributes.get("categories"))
    if categories:
        shown = ", ".join(f"{key}: {value}" for key, value in list(categories.items())[:8])
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="VirusTotal categories",
                value=shown,
                source_url=page,
            )
        )
    if len(findings) == 1 and malicious == 0 and suspicious == 0 and not attributes:
        findings[0] = make_finding(
            source=source,
            category=Category.REPUTATION,
            title="VirusTotal record",
            value=target,
            detail="The report did not include analysis stats.",
            source_url=page,
        )
    return findings


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)
