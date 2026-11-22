"""Ask Gravatar whether a lowered, trimmed email has a profile image.

The request sends the MD5 of the address, which is how Gravatar's public
avatar URL works. It does not send a password.
"""

from __future__ import annotations

import hashlib

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Target, TargetType, make_finding
from reconlens.plugins.base import Source


class GravatarSource(Source):
    """One small image request with ``d=404`` so a miss is an HTTP 404."""

    name = "gravatar"
    description = "Whether Gravatar has an image for this email (MD5 avatar URL)"
    target_types = frozenset({TargetType.EMAIL})
    min_interval_seconds = 0.2
    display_order = 110
    homepage = "https://gravatar.com/"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        digest = gravatar_hash(target.value)
        url = f"https://www.gravatar.com/avatar/{digest}"
        response = await ctx.get_public(
            url,
            source=self.name,
            min_interval=self.min_interval_seconds,
            params={"d": "404", "s": "32"},
        )
        if response.status_code == 200:
            return [
                make_finding(
                    source=self.name,
                    category=Category.IDENTITY,
                    title="Gravatar",
                    value="present",
                    detail="Gravatar returned an image for this address.",
                    source_url=url,
                )
            ]
        if response.status_code == 404:
            return [
                make_finding(
                    source=self.name,
                    category=Category.IDENTITY,
                    title="Gravatar",
                    value="not present",
                    detail="Gravatar has no image for this address.",
                    source_url=url,
                )
            ]
        raise SourceError(f"Gravatar returned HTTP {response.status_code}")


def gravatar_hash(email: str) -> str:
    """MD5 of the trimmed, lowercased address, as Gravatar specifies."""

    normalized = email.strip().lower().encode("utf-8")
    return hashlib.md5(normalized, usedforsecurity=False).hexdigest()
