"""Copy this file when you add a source. It is not registered.

See CONTRIBUTING.md, section "Write your first plugin in 10 minutes".
"""

from __future__ import annotations

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source


class ExampleSource(Source):
    """Replace this docstring with what the source reads and which terms apply."""

    name = "example"
    description = "One-line description of the public data this source reads."
    target_types = frozenset({TargetType.DOMAIN})
    requires_api_key = False
    api_key_env = None  # set to "EXAMPLE_API_KEY" and requires_api_key = True if needed
    min_interval_seconds = 0.5
    display_order = 500
    homepage = "https://example.com"
    cache_version = 1

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        # Use ctx.get_public or ctx.request. Do not open your own client: the
        # shared client applies the User-Agent, rate limit, and public-host guard.
        # Do not scan ports, brute-force names, or submit the target for active scanning.
        response = await ctx.get_public(
            "https://example.com/api",
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"q": target.value},
        )
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.INFRASTRUCTURE,
                    title="Example result",
                    value="not found",
                    detail="Say what a negative result means.",
                    source_url="https://example.com",
                    severity=Severity.INFO,
                )
            ]
        if response.status_code >= 400:
            raise SourceError(f"example returned HTTP {response.status_code}")
        payload = json_body(response)
        result = payload.get("result", target.value) if isinstance(payload, dict) else target.value
        return [
            make_finding(
                source=self.name,
                category=Category.INFRASTRUCTURE,
                title="Example result",
                value=str(result),
                detail="Say what the value means, in one or two sentences.",
                source_url="https://example.com",
                severity=Severity.INFO,
                data={},
            )
        ]
