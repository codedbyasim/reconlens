"""Read robots.txt and security.txt. Nothing those files point at is fetched."""

from __future__ import annotations

from datetime import datetime, timezone

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.net import text_body
from reconlens.plugins.base import Source


class RobotsSecuritySource(Source):
    """GET the two well-known policy files and summarize them."""

    name = "robots"
    description = "robots.txt and security.txt, summarized without following the links inside them"
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 0.2
    display_order = 70
    homepage = "https://www.rfc-editor.org/rfc/rfc9116"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self._robots(target.value, ctx))
        findings.extend(await self._security_txt(target.value, ctx))
        return findings

    async def _robots(self, domain: str, ctx: RunContext) -> list[Finding]:
        url = f"https://{domain}/robots.txt"
        status, body = await _get_text(ctx, url, self.name, self.min_interval_seconds)
        if status == 404 or _looks_like_html(body):
            return [
                make_finding(
                    source=self.name,
                    category=Category.POLICY,
                    title="robots.txt not found",
                    value=domain,
                    source_url=url,
                )
            ]
        return summarize_robots(self.name, url, body)

    async def _security_txt(self, domain: str, ctx: RunContext) -> list[Finding]:
        well_known = f"https://{domain}/.well-known/security.txt"
        root = f"https://{domain}/security.txt"
        status, body = await _get_text(ctx, well_known, self.name, self.min_interval_seconds)
        used = well_known
        if status == 404 or _looks_like_html(body):
            status, body = await _get_text(ctx, root, self.name, self.min_interval_seconds)
            used = root
        if status == 404 or _looks_like_html(body):
            return [
                make_finding(
                    source=self.name,
                    category=Category.POLICY,
                    title="security.txt not found",
                    value=domain,
                    detail="Looked at /.well-known/security.txt and /security.txt.",
                    source_url=well_known,
                )
            ]
        return summarize_security_txt(self.name, used, body)


def summarize_robots(source: str, url: str, body: str) -> list[Finding]:
    """Count rules. The disallow paths are not requested."""

    lines = [line.strip() for line in body.splitlines() if line.strip()]
    disallows = [line for line in lines if line.lower().startswith("disallow:")]
    sitemaps = []
    for line in lines:
        if line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    findings = [
        make_finding(
            source=source,
            category=Category.POLICY,
            title="robots.txt",
            value=f"{len(lines)} lines, {len(disallows)} Disallow rules",
            detail="The file was read and not used as a crawl map.",
            source_url=url,
        )
    ]
    for sitemap in sitemaps[:10]:
        findings.append(
            make_finding(
                source=source,
                category=Category.POLICY,
                title="Sitemap",
                value=sitemap,
                source_url=url,
            )
        )
    return findings


def summarize_security_txt(source: str, url: str, body: str) -> list[Finding]:
    """Pull the contact and expiry fields out of a security.txt file."""

    fields = _fields(body)
    findings: list[Finding] = [
        make_finding(
            source=source,
            category=Category.POLICY,
            title="security.txt",
            value="present",
            source_url=url,
        )
    ]
    for key, label in (
        ("contact", "Contact"),
        ("policy", "Policy"),
        ("preferred-languages", "Preferred languages"),
        ("canonical", "Canonical"),
    ):
        for value in fields.get(key, [])[:5]:
            findings.append(
                make_finding(
                    source=source,
                    category=Category.POLICY,
                    title=label,
                    value=value,
                    source_url=url,
                )
            )
    for value in fields.get("expires", [])[:1]:
        expires = _parse_expires(value)
        if expires is not None and expires < datetime.now(timezone.utc):
            severity = Severity.LOW
            detail = "The Expires field is in the past (RFC 9116)."
        else:
            severity = Severity.INFO
            detail = None
        findings.append(
            make_finding(
                source=source,
                category=Category.POLICY,
                title="Expires",
                value=value,
                detail=detail,
                severity=severity,
                source_url=url,
            )
        )
    return findings


def _fields(body: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for line in body.splitlines():
        text = line.strip()
        if not text or text.startswith("#") or ":" not in text:
            continue
        key, value = text.split(":", 1)
        cleaned = value.strip()
        if cleaned:
            found.setdefault(key.strip().lower(), []).append(cleaned)
    return found


def _parse_expires(value: str) -> datetime | None:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _looks_like_html(body: str) -> bool:
    sample = body.lstrip()[:200].lower()
    return sample.startswith("<!doctype html") or sample.startswith("<html")


async def _get_text(
    ctx: RunContext,
    url: str,
    source: str,
    interval: float,
) -> tuple[int, str]:
    response = await ctx.get_public(
        url,
        source=source,
        min_interval=interval,
        headers={"Accept": "text/plain, */*"},
    )
    if response.status_code == 404:
        return 404, ""
    if response.status_code >= 400:
        raise SourceError(f"HTTP {response.status_code} for {url}")
    return response.status_code, text_body(response, limit=100_000)
