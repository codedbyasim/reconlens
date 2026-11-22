"""Per-run state handed to every source: HTTP, keys, cache, and rate limits."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from reconlens import net
from reconlens.config import Config
from reconlens.errors import SourceError
from reconlens.redact import safe_error_message

REDIRECTS = net.REDIRECTS


class RateLimiter:
    """Space out calls from one source. The first call does not wait."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            delay = self._next - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = time.monotonic()
            self._next = now + self.min_interval


@dataclass
class RunContext:
    """Everything a source is allowed to use for one target."""

    client: httpx.AsyncClient
    config: Config
    timeout: float
    cache: Any
    secrets: list[str]
    notices: list[str] = field(default_factory=list)
    _limiters: dict[str, RateLimiter] = field(default_factory=dict)

    def api_key(self, env_name: str | None) -> str | None:
        """Return a configured key, or None. The value is not logged here."""

        if not env_name:
            return None
        value = self.config.keys.get(env_name, "").strip()
        return value or None

    def require_api_key(self, env_name: str) -> str:
        key = self.api_key(env_name)
        if not key:
            raise SourceError(f"{env_name} is not set")
        return key

    def _limiter(self, source: str, min_interval: float) -> RateLimiter:
        limiter = self._limiters.get(source)
        if limiter is None:
            limiter = RateLimiter(min_interval)
            self._limiters[source] = limiter
        return limiter

    async def request(
        self,
        method: str,
        url: str,
        *,
        source: str,
        min_interval: float = 0.0,
        **kwargs: Any,
    ) -> httpx.Response:
        """Perform one HTTPS request after the public-host and rate-limit checks."""

        net.validate_public_url(url)
        host = urlsplit(url).hostname
        if host is None or not await net.host_is_public(host):
            raise SourceError("refusing to request a non-public host")
        await self._limiter(source, min_interval).wait()
        kwargs.pop("timeout", None)
        kwargs.pop("follow_redirects", None)
        try:
            return await self.client.request(
                method,
                url,
                follow_redirects=False,
                timeout=self.timeout,
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise SourceError(safe_error_message(exc, self.secrets)) from None

    async def get_public(
        self,
        url: str,
        *,
        source: str,
        min_interval: float = 0.0,
        max_redirects: int = 5,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        """GET a public HTTPS URL, following a few redirects that stay public."""

        current = url
        query = params
        for _ in range(max_redirects + 1):
            extra: dict[str, Any] = {}
            if headers:
                extra["headers"] = headers
            if query:
                extra["params"] = query
            response = await self.request(
                "GET",
                current,
                source=source,
                min_interval=min_interval,
                **extra,
            )
            query = None
            if response.status_code not in REDIRECTS:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            current = urljoin(str(response.url), location)
        raise SourceError("too many redirects")
