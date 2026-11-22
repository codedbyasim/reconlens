"""Shodan database lookup. ReconLens does not scan the host."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from reconlens.coerce import as_list
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class ShodanSource(Source):
    """Passive DNS for a domain, or the stored host record for an IP."""

    name = "shodan"
    description = (
        "Shodan passive DNS or stored host record. "
        "ReconLens does not scan ports; port numbers are Shodan's historical data."
    )
    target_types = frozenset({TargetType.DOMAIN, TargetType.IP})
    requires_api_key = True
    api_key_env = "SHODAN_API_KEY"
    min_interval_seconds = 1.0
    display_order = 230
    homepage = "https://www.shodan.io/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        key = ctx.require_api_key("SHODAN_API_KEY")
        if target.type is TargetType.DOMAIN:
            url = f"https://api.shodan.io/dns/domain/{quote(target.value, safe='.')}"
            page = f"https://www.shodan.io/domain/{target.value}"
        else:
            url = f"https://api.shodan.io/shodan/host/{quote(target.value, safe=':')}"
            page = f"https://www.shodan.io/host/{target.value}"
        response = await ctx.get_public(
            url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"key": key},
            headers={"Accept": "application/json"},
        )
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.REPUTATION,
                    title="No Shodan record",
                    value=target.value,
                    source_url=page,
                )
            ]
        if response.status_code in {401, 403}:
            raise SourceError("Shodan rejected the API key")
        if response.status_code == 429:
            raise SourceError("Shodan rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"Shodan returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("Shodan returned an unexpected payload")
        if target.type is TargetType.DOMAIN:
            return _domain_findings(self.name, target.value, payload, page)
        return _host_findings(self.name, target.value, payload, page)


def _domain_findings(
    source: str,
    domain: str,
    payload: dict[str, Any],
    page: str,
) -> list[Finding]:
    labels = [str(item).strip().lower() for item in as_list(payload.get("subdomains"))]
    names = []
    seen: set[str] = set()
    for label in labels:
        if not label or label in {".", "*"} or any(char in label for char in " /\\"):
            continue
        name = label if label.endswith("." + domain) or label == domain else f"{label}.{domain}"
        if name not in seen:
            seen.add(name)
            names.append(name)
        if len(names) >= 100:
            break
    if not names:
        return [
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="No passive DNS names",
                value=domain,
                detail="Shodan's DNS dataset had no names for this domain.",
                source_url=page,
            )
        ]
    return [
        make_finding(
            source=source,
            category=Category.REPUTATION,
            title="Passive DNS name",
            value=name,
            detail="From Shodan's passive DNS dataset. ReconLens did not resolve or scan it.",
            source_url=page,
        )
        for name in names
    ]


def _host_findings(source: str, ip: str, payload: dict[str, Any], page: str) -> list[Finding]:
    findings: list[Finding] = []
    org = payload.get("org")
    if isinstance(org, str) and org.strip():
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="Organization",
                value=org.strip(),
                source_url=page,
            )
        )
    asn = payload.get("asn")
    if isinstance(asn, str) and asn.strip():
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="ASN",
                value=asn.strip(),
                source_url=page,
            )
        )
    for hostname in [str(item) for item in as_list(payload.get("hostnames"))][:20]:
        if hostname.strip():
            findings.append(
                make_finding(
                    source=source,
                    category=Category.REPUTATION,
                    title="Hostname",
                    value=hostname.strip(),
                    source_url=page,
                )
            )
    ports = [item for item in as_list(payload.get("ports")) if isinstance(item, int)]
    if ports:
        shown = ", ".join(str(port) for port in ports[:30])
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="Observed ports",
                value=shown,
                detail=(
                    "Historical observations stored by Shodan. "
                    "ReconLens did not connect to these ports."
                ),
                source_url=page,
            )
        )
    if not findings:
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="Shodan host record",
                value=ip,
                detail="The record did not include organization, hostnames, or ports.",
                source_url=page,
            )
        )
    return findings
