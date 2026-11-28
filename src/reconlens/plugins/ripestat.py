"""Network prefix and origin ASN for a public IP, via the keyless RIPEstat Data API."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import quote

from reconlens.coerce import as_dict
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source
from reconlens.textutil import clip

_DATA_URL = "https://stat.ripe.net/data/network-info/data.json"
_MAX_ASNS = 5
_MAX_TEXT = 200


class RipeStatSource(Source):
    """One network-info lookup. Private addresses are not sent anywhere."""

    name = "ripestat"
    description = "Network prefix and ASN from the keyless RIPEstat network-info endpoint"
    target_types = frozenset({TargetType.IP})
    min_interval_seconds = 0.5
    display_order = 95
    homepage = "https://stat.ripe.net/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        address = ipaddress.ip_address(target.value)
        page = f"https://stat.ripe.net/{quote(target.value, safe=':')}"
        if not address.is_global:
            return [
                make_finding(
                    source=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="RIPEstat lookup skipped",
                    value=target.value,
                    detail=(
                        "The address is not a public global address, so it was not "
                        "sent to RIPEstat."
                    ),
                )
            ]
        response = await ctx.get_public(
            _DATA_URL,
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"resource": target.value},
            headers={"Accept": "application/json"},
        )
        if response.status_code == 429:
            raise SourceError("RIPEstat rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"RIPEstat returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("RIPEstat returned an unexpected payload")
        return findings_from_network_info(self.name, target.value, payload, page)


def findings_from_network_info(
    source: str,
    ip: str,
    payload: dict[str, Any],
    source_url: str,
) -> list[Finding]:
    """Map a RIPEstat network-info response onto prefix and ASN findings (network-info has no holder field)."""

    data = as_dict(payload.get("data"))
    findings: list[Finding] = []
    prefix = _text(data.get("prefix"))
    if prefix:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="Prefix",
                value=prefix,
                source_url=source_url,
            )
        )
    asns = data.get("asns")
    if isinstance(asns, list):
        for asn in asns[:_MAX_ASNS]:
            number = _text(asn).upper().removeprefix("AS")
            if number.isdigit():
                findings.append(
                    make_finding(
                        source=source,
                        category=Category.INFRASTRUCTURE,
                        title="ASN",
                        value=f"AS{number}",
                        source_url=source_url,
                    )
                )
    if not findings:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="No network info",
                value=ip,
                detail="RIPEstat returned no prefix or ASN for this address.",
                source_url=source_url,
            )
        )
    return findings


def _text(value: object) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    return clip(str(value).strip(), _MAX_TEXT)
