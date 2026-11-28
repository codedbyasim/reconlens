"""Certificate Transparency names from crt.sh. Expired certificates are excluded."""

from __future__ import annotations

from collections import Counter
from typing import Any

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source

_CAP = 200
_ISSUER_CAP = 10


class CrtShSource(Source):
    """Read-only query of https://crt.sh. ReconLens does not request new certificates."""

    name = "crtsh"
    description = (
        "Unexpired certificate names from the public crt.sh Certificate Transparency search"
    )
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 1.0
    display_order = 50
    homepage = "https://crt.sh/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        response = await ctx.get_public(
            "https://crt.sh/",
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"q": f"%.{target.value}", "output": "json", "exclude": "expired"},
            headers={"Accept": "application/json"},
        )
        if response.status_code == 404:
            return _empty(self.name, target.value)
        if response.status_code == 429:
            raise SourceError("crt.sh rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"crt.sh returned HTTP {response.status_code}")
        payload = json_body(response, limit=5_000_000)
        if isinstance(payload, dict):
            raise SourceError("crt.sh did not return a certificate list")
        if not isinstance(payload, list):
            raise SourceError("crt.sh returned an unexpected payload")
        return findings_from_ct(self.name, target.value, payload)


def names_from_ct(domain: str, rows: list[Any]) -> list[str]:
    """Unique hostnames from crt.sh rows that belong to ``domain``."""

    return _scan_ct(domain, rows)[0]


def _scan_ct(domain: str, rows: list[Any]) -> tuple[list[str], Counter[str]]:
    """Hostnames plus a count of new names per issuer."""

    issuers: Counter[str] = Counter()
    found: list[str] = []
    seen: set[str] = set()
    suffix = "." + domain.lower()
    apex = domain.lower()
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw = row.get("name_value")
        if not isinstance(raw, str):
            continue
        for part in raw.splitlines():
            name = part.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name != apex and not name.endswith(suffix):
                continue
            if not name or name in seen:
                continue
            seen.add(name)
            found.append(name)
            issuer = row.get("issuer_name")
            if isinstance(issuer, str) and issuer.strip():
                issuers[" ".join(issuer.split())] += 1
            if len(found) >= _CAP:
                return found, issuers
    return found, issuers


def findings_from_ct(source: str, domain: str, rows: list[Any]) -> list[Finding]:
    names, issuers = _scan_ct(domain, rows)
    if not names:
        return _empty(source, domain)
    reference = f"https://crt.sh/?q={domain}"
    findings = [
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="Certificate name",
            value=name,
            detail="Seen in an unexpired certificate logged by Certificate Transparency.",
            source_url=reference,
        )
        for name in names
    ]
    for issuer, count in issuers.most_common(_ISSUER_CAP):
        findings.append(
            make_finding(
                source=source,
                category=Category.CERTIFICATE,
                title="Issuer",
                value=issuer,
                detail=f"{count} names",
                source_url=reference,
            )
        )
    if len(names) >= _CAP:
        findings.append(
            make_finding(
                source=source,
                category=Category.CERTIFICATE,
                title="Certificate names truncated",
                value=str(_CAP),
                detail="crt.sh returned more names than this report keeps.",
                source_url=reference,
                severity=Severity.INFO,
            )
        )
    return findings


def _empty(source: str, domain: str) -> list[Finding]:
    return [
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="No certificate names",
            value=domain,
            detail="crt.sh has no unexpired certificate names for this domain.",
            source_url=f"https://crt.sh/?q={domain}",
        )
    ]
