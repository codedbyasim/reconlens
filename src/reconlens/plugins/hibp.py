"""Have I Been Pwned breach names for an email address.

Only query an address you are authorized to check. The response is the public
breach metadata HIBP returns. Password material is not requested.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from reconlens.coerce import as_list
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class HibpSource(Source):
    """GET /breachedaccount. A 404 is a normal "no public breach" answer."""

    name = "hibp"
    description = (
        "Public breach names from Have I Been Pwned. "
        "Only query addresses you are authorized to check."
    )
    target_types = frozenset({TargetType.EMAIL})
    requires_api_key = True
    api_key_env = "HIBP_API_KEY"
    min_interval_seconds = 1.5
    display_order = 240
    homepage = "https://haveibeenpwned.com/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        key = ctx.require_api_key("HIBP_API_KEY")
        url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(target.value, safe="")
        response = await ctx.get_public(
            url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": key, "Accept": "application/json"},
        )
        page = "https://haveibeenpwned.com/"
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.BREACH,
                    title="No HIBP breaches",
                    value=target.value,
                    detail="Have I Been Pwned has no public breach for this address.",
                    source_url=page,
                )
            ]
        if response.status_code in {401, 403}:
            raise SourceError("HIBP refused the request. Check the API key and User-Agent.")
        if response.status_code == 429:
            raise SourceError("HIBP rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"HIBP returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, list):
            raise SourceError("HIBP returned an unexpected payload")
        return findings_from_hibp(self.name, target.value, payload, page)


def findings_from_hibp(
    source: str,
    email: str,
    payload: list[Any],
    page: str,
) -> list[Finding]:
    breaches = [item for item in payload if isinstance(item, dict)]
    if not breaches:
        return [
            make_finding(
                source=source,
                category=Category.BREACH,
                title="No HIBP breaches",
                value=email,
                source_url=page,
            )
        ]
    findings: list[Finding] = []
    for breach in breaches[:20]:
        title = str(breach.get("Title") or breach.get("Name") or "Breach")
        when = str(breach.get("BreachDate") or title)
        classes = as_list(breach.get("DataClasses"))
        detail = ", ".join(str(item) for item in classes[:8] if str(item).strip()) or None
        findings.append(
            make_finding(
                source=source,
                category=Category.BREACH,
                title=title,
                value=when,
                detail=detail,
                source_url=page,
                severity=Severity.MEDIUM,
            )
        )
    if len(breaches) > 20:
        findings.append(
            make_finding(
                source=source,
                category=Category.BREACH,
                title="Additional breaches",
                value=str(len(breaches) - 20),
                detail="HIBP returned more breaches than this report lists.",
                source_url=page,
                severity=Severity.MEDIUM,
            )
        )
    return findings
