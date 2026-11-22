"""Blocking DNS lookups run in a worker thread. Search domains are disabled."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.resolver


@dataclass(frozen=True)
class DnsAnswer:
    """Records for one name and type, or a short error token."""

    name: str
    rtype: str
    values: list[str]
    error: str | None


def resolve_sync(name: str, rtype: str, timeout: float) -> DnsAnswer:
    """Query one record type. ``search`` is off so resolv.conf cannot rewrite the name."""

    bounded = min(max(timeout, 1.0), 10.0)
    resolver = dns.resolver.Resolver()
    resolver.timeout = bounded
    resolver.lifetime = bounded
    try:
        answer = resolver.resolve(name, rtype, lifetime=bounded, search=False)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer(name, rtype, [], "nxdomain")
    except dns.resolver.NoAnswer:
        return DnsAnswer(name, rtype, [], "noanswer")
    except (dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout, dns.exception.Timeout):
        return DnsAnswer(name, rtype, [], "timeout")
    except dns.exception.DNSException:
        return DnsAnswer(name, rtype, [], "error")
    values = [_rdata_text(rtype, rdata) for rdata in answer]
    return DnsAnswer(name, rtype, values, None)


async def resolve(name: str, rtype: str, timeout: float) -> DnsAnswer:
    """Run :func:`resolve_sync` off the event loop."""

    return await asyncio.to_thread(resolve_sync, name, rtype, timeout)


def _rdata_text(rtype: str, rdata: Any) -> str:
    strings = getattr(rdata, "strings", None)
    if rtype == "TXT" and strings is not None:
        parts: list[str] = []
        for item in strings:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", "replace"))
            else:
                parts.append(str(item))
        return "".join(parts)
    text = str(rdata).strip()
    if text.endswith("."):
        text = text[:-1]
    return text
