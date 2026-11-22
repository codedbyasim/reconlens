"""Country and ASN for a public IP, via the keyless ipwho.is HTTPS API."""

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


class IpGeoSource(Source):
    """Send a public IP to ipwho.is. Private addresses are not sent anywhere."""

    name = "ip-geo"
    description = "Country, network, and ASN from the keyless ipwho.is API"
    target_types = frozenset({TargetType.IP})
    min_interval_seconds = 0.5
    display_order = 90
    homepage = "https://ipwho.is/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        address = ipaddress.ip_address(target.value)
        if not address.is_global:
            return [
                make_finding(
                    source=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="Geolocation skipped",
                    value=target.value,
                    detail=(
                        "The address is not a public global address, so it was not "
                        "sent to ipwho.is."
                    ),
                )
            ]
        quoted = quote(target.value, safe=":")
        url = f"https://ipwho.is/{quoted}"
        response = await ctx.get_public(
            url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            headers={"Accept": "application/json"},
        )
        if response.status_code == 429:
            raise SourceError("ipwho.is rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"ipwho.is returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("ipwho.is returned an unexpected payload")
        if payload.get("success") is False:
            message = str(payload.get("message") or "lookup failed")
            raise SourceError(f"ipwho.is: {message}")
        return findings_from_ipwho(self.name, target.value, payload, url)


def findings_from_ipwho(
    source: str,
    ip: str,
    payload: dict[str, Any],
    source_url: str,
) -> list[Finding]:
    """Map an ipwho.is object onto a few findings."""

    findings: list[Finding] = []
    place = ", ".join(
        part
        for part in (
            _text(payload.get("city")),
            _text(payload.get("region")),
            _text(payload.get("country")),
        )
        if part
    )
    if place:
        country_code = _text(payload.get("country_code"))
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="Location",
                value=place,
                source_url=source_url,
                data={"country_code": country_code} if country_code else {},
            )
        )
    latitude = payload.get("latitude")
    longitude = payload.get("longitude")
    if isinstance(latitude, (int, float)) and isinstance(longitude, (int, float)):
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="Coordinates",
                value=f"{float(latitude):.4f}, {float(longitude):.4f}",
                source_url=source_url,
            )
        )
    connection = as_dict(payload.get("connection"))
    asn = connection.get("asn", payload.get("asn"))
    asn_text = _asn(asn)
    if asn_text:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="ASN",
                value=asn_text,
                source_url=source_url,
            )
        )
    org = _text(connection.get("org")) or _text(payload.get("org"))
    if org:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="Organization",
                value=org,
                source_url=source_url,
            )
        )
    isp = _text(connection.get("isp")) or _text(payload.get("isp"))
    if isp and isp != org:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="ISP",
                value=isp,
                source_url=source_url,
            )
        )
    timezone = payload.get("timezone")
    zone = ""
    if isinstance(timezone, dict):
        zone = _text(timezone.get("id"))
    elif isinstance(timezone, str):
        zone = timezone.strip()
    if zone:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="Timezone",
                value=zone,
                source_url=source_url,
            )
        )
    if not findings:
        findings.append(
            make_finding(
                source=source,
                category=Category.INFRASTRUCTURE,
                title="No geolocation details",
                value=ip,
                source_url=source_url,
            )
        )
    return findings


def _text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    return ""


def _asn(value: object) -> str:
    if isinstance(value, int):
        return f"AS{value}"
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return f"AS{text}"
        if text.upper().startswith("AS") and text[2:].isdigit():
            return text.upper()
        return text
    return ""
