"""Check a small, curated list of public profile URLs. No logins are attempted."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.net import text_body, validate_public_url
from reconlens.plugins.base import Source


@dataclass(frozen=True)
class Site:
    """One public profile URL template."""

    name: str
    url_template: str
    exists_status: tuple[int, ...]
    missing_status: tuple[int, ...]
    category: str = "identity"
    missing_body_contains: str | None = None
    exists_body_contains: str | None = None
    note: str = ""


class UsernameSource(Source):
    """GET each curated profile URL once, slowly, and record the HTTP result.

    A 200 is not proof that a person owns the account. Open the profile before
    you rely on it. The catalog is ``data/username_sites.json``.
    """

    name = "username"
    description = "Public profile URLs from a small curated list (no login, no guessing)"
    target_types = frozenset({TargetType.USERNAME})
    min_interval_seconds = 0.4
    display_order = 120
    homepage = (
        "https://github.com/codedbyasim/reconlens/blob/main/src/reconlens/data/username_sites.json"
    )

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        sites, skipped = load_sites()
        findings: list[Finding] = []
        if skipped:
            findings.append(
                make_finding(
                    source=self.name,
                    category=Category.IDENTITY,
                    title="Site catalog",
                    value=f"{skipped} invalid definition(s) skipped",
                    detail="Fix the username site JSON. Invalid entries are not requested.",
                )
            )
        rate_limited = False
        for site in sites:
            if rate_limited:
                findings.append(
                    _result(
                        self.name,
                        site,
                        "inconclusive",
                        detail="Not checked, because an earlier site returned HTTP 429.",
                    )
                )
                continue
            try:
                url = build_site_url(site.url_template, target.value)
            except SourceError as exc:
                findings.append(_result(self.name, site, "inconclusive", detail=str(exc), url=None))
                continue
            try:
                response = await ctx.get_public(
                    url,
                    source=self.name,
                    min_interval=self.min_interval_seconds,
                    headers={"Accept": "text/html, application/json;q=0.9, */*;q=0.8"},
                )
            except SourceError as exc:
                findings.append(_result(self.name, site, "inconclusive", detail=str(exc), url=url))
                continue
            if response.status_code == 429:
                rate_limited = True
                findings.append(
                    _result(
                        self.name,
                        site,
                        "inconclusive",
                        detail="The site returned HTTP 429, so later sites were not checked.",
                        url=url,
                    )
                )
                continue
            body = ""
            if site.missing_body_contains or site.exists_body_contains:
                try:
                    body = text_body(response, limit=200_000)
                except SourceError:
                    body = ""
            label = classify_site(site, response.status_code, body)
            detail = _detail(label, response.status_code, site.note)
            findings.append(_result(self.name, site, label, detail=detail, url=url))
        if not findings:
            findings.append(
                make_finding(
                    source=self.name,
                    category=Category.IDENTITY,
                    title="No sites configured",
                    value=target.value,
                    detail="The username catalog is empty.",
                )
            )
        return findings


def load_sites() -> tuple[list[Site], int]:
    """Read the packaged catalog. Invalid objects are counted and skipped."""

    payload = json.loads(_catalog_text())
    raw_sites = payload.get("sites") if isinstance(payload, dict) else None
    if not isinstance(raw_sites, list):
        raise SourceError("username site catalog is not a list")
    sites: list[Site] = []
    skipped = 0
    for item in raw_sites:
        parsed = _parse_site(item)
        if parsed is None:
            skipped += 1
        else:
            sites.append(parsed)
    return sites, skipped


def build_site_url(template: str, username: str) -> str:
    """Substitute the username into the path or query, never the host."""

    if template.count("{username}") != 1:
        raise SourceError("site template must contain {username} once")
    parts = urlsplit(template)
    if "{username}" in parts.scheme or "{username}" in parts.netloc:
        raise SourceError("the username placeholder is only allowed in the path or query")
    url = template.replace("{username}", quote(username, safe=""))
    validate_public_url(url)
    return url


def classify_site(site: Site, status: int, body: str) -> str:
    """Return ``found``, ``not_found``, or ``inconclusive``."""

    text = body.lower()
    if site.missing_body_contains and site.missing_body_contains.lower() in text:
        return "not_found"
    if site.exists_body_contains and site.exists_body_contains.lower() in text:
        return "found"
    if status in site.missing_status:
        return "not_found"
    if status in site.exists_status:
        return "found"
    return "inconclusive"


def _parse_site(item: Any) -> Site | None:
    if not isinstance(item, dict):
        return None
    name = item.get("name")
    url = item.get("url")
    exists = item.get("exists_status")
    missing = item.get("missing_status")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(url, str) or "{username}" not in url:
        return None
    if not _status_list(exists) or not _status_list(missing):
        return None
    category = item.get("category")
    missing_body = item.get("missing_body_contains")
    exists_body = item.get("exists_body_contains")
    note = item.get("note")
    return Site(
        name=name.strip(),
        url_template=url.strip(),
        exists_status=_status_list(exists),
        missing_status=_status_list(missing),
        category=category.strip() if isinstance(category, str) and category.strip() else "identity",
        missing_body_contains=missing_body
        if isinstance(missing_body, str) and missing_body
        else None,
        exists_body_contains=exists_body if isinstance(exists_body, str) and exists_body else None,
        note=note.strip() if isinstance(note, str) else "",
    )


def _status_list(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        return ()
    statuses: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int):
            return ()
        if item < 100 or item > 599:
            return ()
        statuses.append(item)
    return tuple(statuses)


def _catalog_text() -> str:
    try:
        return files("reconlens.data").joinpath("username_sites.json").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        path = Path(__file__).resolve().parents[1] / "data" / "username_sites.json"
        return path.read_text(encoding="utf-8")


def _result(
    source: str,
    site: Site,
    label: str,
    *,
    detail: str,
    url: str | None = None,
) -> Finding:
    return make_finding(
        source=source,
        category=Category.IDENTITY,
        title=site.name,
        value=label,
        detail=detail,
        source_url=url,
        data={"category": site.category},
    )


def _detail(label: str, status: int, note: str) -> str:
    base = f"HTTP {status} from the public profile URL."
    if label == "found":
        base += " Open the page before treating this as the same person."
    elif label == "not_found":
        base += " The site said this username is absent."
    else:
        base += " The result is not a clear yes or no."
    if note:
        return f"{base} {note}."
    return base
