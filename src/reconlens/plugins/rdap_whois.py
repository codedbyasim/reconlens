"""Registration data over RDAP, the structured successor to port-43 WHOIS."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from reconlens.coerce import as_dict, as_list
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source

_EVENT_TITLES = {
    "registration": "Registered",
    "expiration": "Expires",
    "last changed": "Last changed",
    "last update of rdap database": "RDAP database updated",
}


class RdapSource(Source):
    """One HTTPS lookup against the public RDAP bootstrap service."""

    name = "rdap"
    description = "Registration data via RDAP (the structured successor to WHOIS)"
    target_types = frozenset({TargetType.DOMAIN, TargetType.IP})
    min_interval_seconds = 0.3
    display_order = 30
    homepage = "https://www.rfc-editor.org/rfc/rfc9083"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        kind = "domain" if target.type is TargetType.DOMAIN else "ip"
        quoted = quote(target.value, safe=":.")
        url = f"https://rdap.org/{kind}/{quoted}"
        response = await ctx.get_public(
            url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            headers={"Accept": "application/rdap+json, application/json"},
        )
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.REGISTRATION,
                    title="No RDAP record",
                    value=target.value,
                    detail="The RDAP bootstrap service has no registration object for this target.",
                    source_url=url,
                )
            ]
        if response.status_code == 429:
            raise SourceError("RDAP rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"RDAP returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("RDAP returned an unexpected payload")
        return findings_from_rdap(self.name, target.value, payload, url)


def findings_from_rdap(
    source: str,
    target: str,
    payload: dict[str, Any],
    source_url: str,
) -> list[Finding]:
    """Pick the stable registration fields out of an RDAP object."""

    if "errorCode" in payload and "ldhName" not in payload and "handle" not in payload:
        title = str(payload.get("title") or payload.get("errorCode") or "error")
        raise SourceError(f"RDAP error: {title}")
    findings: list[Finding] = []
    name = str(payload.get("ldhName") or payload.get("name") or payload.get("handle") or target)
    findings.append(
        make_finding(
            source=source,
            category=Category.REGISTRATION,
            title="Name",
            value=name,
            source_url=source_url,
        )
    )
    handle = payload.get("handle")
    if isinstance(handle, str) and handle and handle != name:
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Handle",
                value=handle,
                source_url=source_url,
            )
        )
    status = [str(item) for item in as_list(payload.get("status")) if str(item).strip()]
    if status:
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Status",
                value=", ".join(status[:12]),
                source_url=source_url,
            )
        )
    network = _network(payload)
    if network:
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Network",
                value=network,
                source_url=source_url,
            )
        )
    country = payload.get("country")
    if isinstance(country, str) and country.strip():
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Country",
                value=country.strip(),
                source_url=source_url,
            )
        )
    registrar = _registrar(payload)
    if registrar:
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Registrar",
                value=registrar,
                source_url=source_url,
            )
        )
    for nameserver in _nameservers(payload)[:12]:
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title="Nameserver",
                value=nameserver,
                source_url=source_url,
            )
        )
    seen_events: set[str] = set()
    for event in as_list(payload.get("events")):
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction") or "").strip().lower()
        when = str(event.get("eventDate") or "").strip()
        if not action or not when or action in seen_events:
            continue
        seen_events.add(action)
        findings.append(
            make_finding(
                source=source,
                category=Category.REGISTRATION,
                title=_EVENT_TITLES.get(action, action.title()),
                value=when,
                source_url=source_url,
            )
        )
        if len(seen_events) >= 8:
            break
    return findings


def _network(payload: dict[str, Any]) -> str:
    cidrs: list[str] = []
    for item in as_list(payload.get("cidr0_cidrs")):
        if not isinstance(item, dict):
            continue
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if isinstance(prefix, str) and prefix:
            cidrs.append(f"{prefix}/{length}" if length is not None else prefix)
    if cidrs:
        return ", ".join(cidrs[:4])
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    if isinstance(start, str) and isinstance(end, str) and start and end:
        return f"{start} - {end}"
    return ""


def _nameservers(payload: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for item in as_list(payload.get("nameservers")):
        if isinstance(item, dict):
            name = item.get("ldhName") or item.get("unicodeName")
            if isinstance(name, str) and name.strip():
                found.append(name.strip().rstrip(".").lower())
    return found


def _registrar(payload: dict[str, Any]) -> str:
    for entity in as_list(payload.get("entities")):
        data = as_dict(entity)
        roles = {str(role).lower() for role in as_list(data.get("roles"))}
        if "registrar" not in roles:
            continue
        names = _vcard_fn(data)
        if names:
            return names[0]
    return ""


def _vcard_fn(entity: dict[str, Any]) -> list[str]:
    vcard = entity.get("vcardArray")
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return []
    names: list[str] = []
    for item in vcard[1]:
        if (
            isinstance(item, list)
            and len(item) >= 4
            and item[0] == "fn"
            and isinstance(item[3], str)
            and item[3].strip()
        ):
            names.append(item[3].strip())
    return names
