"""Guards for outbound HTTP. Sources should not talk to loopback or link-local hosts."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

import httpx

from reconlens.errors import SourceError

REDIRECTS = frozenset({301, 302, 303, 307, 308})
_BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }
)
_BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".arpa")


def validate_public_url(url: str) -> str:
    """Reject non-HTTPS URLs, embedded credentials, and non-public literals."""

    parsed = urlsplit(url.strip())
    if parsed.scheme != "https":
        raise SourceError("only https URLs are requested")
    if parsed.username or parsed.password:
        raise SourceError("refusing a URL with embedded credentials")
    host = parsed.hostname
    if host is None:
        raise SourceError("URL is missing a host")
    normalized = host.rstrip(".").lower()
    if normalized in _BLOCKED_HOSTS or normalized.endswith(_BLOCKED_SUFFIXES):
        raise SourceError("refusing a non-public host")
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise SourceError("refusing a non-public address")
    return url


def addresses_are_public(addresses: Iterable[str]) -> bool:
    """True when every resolved address is a global unicast address."""

    saw = False
    for raw in addresses:
        saw = True
        text = raw.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        if not address.is_global:
            return False
    return saw


async def host_is_public(host: str) -> bool:
    """Resolve ``host`` and refuse it unless every answer is global."""

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return bool(literal.is_global)

    def lookup() -> list[str]:
        try:
            infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return []
        found: list[str] = []
        for info in infos:
            sockaddr = info[4]
            if sockaddr:
                found.append(str(sockaddr[0]))
        return found

    try:
        addresses = await asyncio.to_thread(lookup)
    except OSError:
        return False
    return addresses_are_public(addresses)


def body_bytes(response: httpx.Response, limit: int = 4_000_000) -> bytes:
    """Return the response body or raise if it is larger than ``limit``."""

    content = response.content
    if len(content) > limit:
        raise SourceError(f"response exceeded {limit} bytes")
    return content


def json_body(response: httpx.Response, limit: int = 4_000_000) -> object:
    """Parse a JSON body, with a size cap."""

    content = body_bytes(response, limit)
    try:
        return json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceError("response was not valid JSON") from exc


def text_body(response: httpx.Response, limit: int = 100_000) -> str:
    """Decode a text body, replacing bytes that are not valid UTF-8."""

    content = body_bytes(response, limit)
    return content.decode("utf-8", errors="replace")
