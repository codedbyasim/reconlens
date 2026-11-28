"""RIPEstat source. Tests use mocked HTTP only."""

from __future__ import annotations

import httpx
import pytest
import respx

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Target, TargetType
from reconlens.plugins.ripestat import RipeStatSource, findings_from_network_info

URL = "https://stat.ripe.net/data/network-info/data.json"


def _ip(value: str) -> Target:
    return Target(value, TargetType.IP, value)


async def test_public_ip_returns_prefix_and_asn(mocked: respx.MockRouter, ctx: RunContext) -> None:
    route = mocked.get(URL, params={"resource": "1.1.1.1"}).mock(
        return_value=httpx.Response(200, json={"data": {"asns": ["13335"], "prefix": "1.1.1.0/24"}})
    )
    findings = await RipeStatSource().run(_ip("1.1.1.1"), ctx)
    assert route.called
    pairs = {(item.title, item.value) for item in findings}
    assert ("Prefix", "1.1.1.0/24") in pairs
    assert ("ASN", "AS13335") in pairs
    assert all(item.source_url == "https://stat.ripe.net/1.1.1.1" for item in findings)


async def test_private_ip_is_not_sent(mocked: respx.MockRouter, ctx: RunContext) -> None:
    del mocked  # no routes: any outbound request would raise
    findings = await RipeStatSource().run(_ip("10.0.0.1"), ctx)
    assert findings[0].title == "RIPEstat lookup skipped"


async def test_http_errors_become_source_errors(mocked: respx.MockRouter, ctx: RunContext) -> None:
    mocked.get(url__startswith=URL).mock(return_value=httpx.Response(429))
    with pytest.raises(SourceError, match="rate limit"):
        await RipeStatSource().run(_ip("1.1.1.1"), ctx)
    mocked.get(url__startswith=URL).mock(return_value=httpx.Response(500))
    with pytest.raises(SourceError, match="HTTP 500"):
        await RipeStatSource().run(_ip("1.1.1.1"), ctx)


async def test_non_object_payload_is_an_error(mocked: respx.MockRouter, ctx: RunContext) -> None:
    mocked.get(url__startswith=URL).mock(return_value=httpx.Response(200, json=[1]))
    with pytest.raises(SourceError, match="unexpected"):
        await RipeStatSource().run(_ip("1.1.1.1"), ctx)


def test_mapping_handles_holder_cap_and_empty() -> None:
    long_name = "H" * 500
    findings = findings_from_network_info(
        "ripestat",
        "1.1.1.1",
        {"data": {"asns": ["AS1", 2, "x", None], "prefix": "1.1.1.0/24", "holder": long_name}},
        "https://stat.ripe.net/1.1.1.1",
    )
    values = [item.value for item in findings]
    assert "AS1" in values and "AS2" in values and "ASx" not in values
    holder = next(item for item in findings if item.title == "Holder")
    assert len(holder.value) <= 200
    empty = findings_from_network_info("ripestat", "1.1.1.1", {}, "https://stat.ripe.net/1.1.1.1")
    assert empty[0].title == "No network info"
