"""The shared HTTP client. It identifies itself and does not follow redirects."""

from __future__ import annotations

import httpx

from reconlens.config import Config
from reconlens.version import __version__


def default_user_agent() -> str:
    """A User-Agent that names the tool, the repo, and the passive-only policy."""

    return (
        f"ReconLens/{__version__} "
        "(+https://github.com/codedbyasim/reconlens; passive-osint; authorized-use-only)"
    )


def build_client(config: Config, *, trust_env: bool = True) -> httpx.AsyncClient:
    """Build the client used for one run. Redirects are followed manually."""

    connect = min(10.0, config.timeout)
    return httpx.AsyncClient(
        headers={
            "User-Agent": config.user_agent or default_user_agent(),
            "Accept": "application/json, text/plain, */*",
        },
        timeout=httpx.Timeout(config.timeout, connect=connect),
        trust_env=trust_env,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
    )
