"""Search urlscan.io. ReconLens does not submit a URL for a new scan."""

from __future__ import annotations

from typing import Any

from reconlens.coerce import as_dict, as_list
from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class UrlscanSource(Source):
    """Search existing public urlscan results for a domain."""

    name = "urlscan"
    description = "Existing urlscan.io results for a domain. ReconLens does not submit new scans."
    target_types = frozenset({TargetType.DOMAIN})
    requires_api_key = True
    api_key_env = "URLSCAN_API_KEY"
    min_interval_seconds = 1.0
    display_order = 220
    homepage = "https://urlscan.io/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        key = ctx.require_api_key("URLSCAN_API_KEY")
        response = await ctx.get_public(
            "https://urlscan.io/api/v1/search/",
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"q": f"domain:{target.value}", "size": "10"},
            headers={"API-Key": key, "Accept": "application/json"},
        )
        if response.status_code in {401, 403}:
            raise SourceError("urlscan rejected the API key")
        if response.status_code == 429:
            raise SourceError("urlscan rate limit reached")
        if response.status_code >= 400:
            raise SourceError(f"urlscan returned HTTP {response.status_code}")
        payload = json_body(response)
        if not isinstance(payload, dict):
            raise SourceError("urlscan returned an unexpected payload")
        return findings_from_urlscan(self.name, target.value, payload)


def findings_from_urlscan(source: str, domain: str, payload: dict[str, Any]) -> list[Finding]:
    results = [item for item in as_list(payload.get("results")) if isinstance(item, dict)]
    if not results:
        return [
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="No public urlscan results",
                value=domain,
                detail="Search only. ReconLens did not submit a new scan.",
                source_url=f"https://urlscan.io/search/#domain:{domain}",
            )
        ]
    findings = [
        make_finding(
            source=source,
            category=Category.REPUTATION,
            title="urlscan search",
            value=f"{min(len(results), 10)} existing result(s)",
            detail="Search only. ReconLens did not submit a new scan.",
            source_url=f"https://urlscan.io/search/#domain:{domain}",
        )
    ]
    for item in results[:10]:
        page = as_dict(item.get("page"))
        task = as_dict(item.get("task"))
        scanned = str(page.get("url") or domain)
        when = str(task.get("time") or "")
        task_id = str(task.get("uuid") or "")
        link = f"https://urlscan.io/result/{task_id}/" if task_id else None
        findings.append(
            make_finding(
                source=source,
                category=Category.REPUTATION,
                title="Public scan",
                value=scanned,
                detail=when or None,
                source_url=link,
            )
        )
    return findings
