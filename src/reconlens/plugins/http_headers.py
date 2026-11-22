"""One GET of the site origin, then a reading of the response headers."""

from __future__ import annotations

from collections.abc import Mapping

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.plugins.base import Source
from reconlens.textutil import clip

_SECURITY_HEADERS = (
    ("strict-transport-security", "Strict-Transport-Security"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy"),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
    ("cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
)
_IDENTITY_HEADERS = (
    ("server", "Server"),
    ("x-powered-by", "X-Powered-By"),
)


class HttpHeadersSource(Source):
    """Fetch ``https://<domain>/`` and report security headers. This is not a crawl."""

    name = "http-headers"
    description = "Response headers from one HTTPS request to the site origin"
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 0.2
    display_order = 60
    homepage = "https://owasp.org/www-project-secure-headers/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        response = await ctx.get_public(
            f"https://{target.value}/",
            source=self.name,
            min_interval=self.min_interval_seconds,
            headers={"Accept": "text/html, */*"},
        )
        if response.status_code >= 500:
            raise SourceError(f"origin returned HTTP {response.status_code}")
        return findings_from_headers(
            self.name,
            response.status_code,
            str(response.url),
            {key.lower(): value for key, value in response.headers.items()},
        )


def findings_from_headers(
    source: str,
    status_code: int,
    final_url: str,
    headers: Mapping[str, str],
) -> list[Finding]:
    """Describe status, present security headers, and the set that is missing."""

    normalized = {key.lower(): value for key, value in headers.items()}
    findings = [
        make_finding(
            source=source,
            category=Category.HTTP,
            title="HTTP status",
            value=str(status_code),
            detail=f"Final URL: {final_url}",
            source_url=final_url,
        )
    ]
    missing: list[str] = []
    for header, label in _SECURITY_HEADERS:
        value = normalized.get(header, "").strip()
        if not value:
            missing.append(label)
            continue
        findings.append(
            make_finding(
                source=source,
                category=Category.HTTP,
                title=label,
                value=clip(value, 300),
                source_url=final_url,
            )
        )
    if missing:
        findings.append(
            make_finding(
                source=source,
                category=Category.HTTP,
                title="Security headers not set",
                value=", ".join(missing),
                detail="These headers were absent from this response. Absence is a signal, not proof of a flaw.",
                source_url=final_url,
                severity=Severity.LOW,
            )
        )
    for header, label in _IDENTITY_HEADERS:
        value = normalized.get(header, "").strip()
        if value:
            findings.append(
                make_finding(
                    source=source,
                    category=Category.HTTP,
                    title=label,
                    value=clip(value, 200),
                    detail="The server identified itself in the response.",
                    source_url=final_url,
                )
            )
    return findings
