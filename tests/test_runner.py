"""The runner isolates failures and scrubs secrets before they reach a report."""

from __future__ import annotations

import httpx
import pytest

from reconlens.config import Config
from reconlens.context import RunContext
from reconlens.errors import UsageError
from reconlens.http import build_client
from reconlens.models import Finding, Target, TargetType, make_finding
from reconlens.plugins.base import Source
from reconlens.plugins.virustotal import VirusTotalSource
from reconlens.runner import choose_sources, execute
from reconlens.validate import domain_target, ip_target


class OkSource(Source):
    name = "ok-demo"
    description = "returns one finding"
    target_types = frozenset({TargetType.DOMAIN})

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        del ctx
        return [
            make_finding(
                source=self.name,
                category="dns",
                title="A",
                value=target.value,
            )
        ]


class BadSource(Source):
    name = "bad-demo"
    description = "raises"
    target_types = frozenset({TargetType.DOMAIN})

    def __init__(self, secret: str) -> None:
        self.secret = secret

    async def run(self, target: object, ctx: object) -> list[object]:
        del target, ctx
        raise RuntimeError(f"blew up with {self.secret}")


class SlowSource(Source):
    name = "slow-demo"
    description = "times out"
    target_types = frozenset({TargetType.DOMAIN})

    async def run(self, target: object, ctx: object) -> list[object]:
        del target, ctx
        import asyncio

        await asyncio.sleep(5)
        return []


def test_choose_sources_rejects_unknown_and_unsupported() -> None:
    sources = [OkSource(), VirusTotalSource()]
    chosen = choose_sources(sources, TargetType.DOMAIN, None, set())
    assert [item.name for item in chosen] == ["ok-demo", "virustotal"]
    with pytest.raises(UsageError):
        choose_sources(sources, TargetType.DOMAIN, {"missing"}, set())
    with pytest.raises(UsageError):
        choose_sources(sources, TargetType.USERNAME, {"ok-demo"}, set())


async def test_one_failure_does_not_drop_other_findings() -> None:
    secret = "super-secret-value"
    config = Config(timeout=2, keys={"VIRUSTOTAL_API_KEY": secret})
    async with build_client(config, trust_env=False) as client:
        ctx = RunContext(
            client=client,
            config=config,
            timeout=2,
            cache=None,
            secrets=[secret],
        )
        report = await execute(
            [OkSource(), BadSource(secret), SlowSource()],
            domain_target("example.com"),
            ctx,
        )
    by_name = {item.name: item for item in report.sources}
    assert by_name["ok-demo"].status == "ok"
    assert by_name["ok-demo"].findings[0].value == "example.com"
    assert by_name["bad-demo"].status == "error"
    assert secret not in (by_name["bad-demo"].error or "")
    assert by_name["slow-demo"].status == "error"
    assert "timed out" in (by_name["slow-demo"].error or "")
    blob = report.target.value + "".join(
        (source.error or "") + (source.skip_reason or "") for source in report.sources
    )
    assert secret not in blob


async def test_keyed_source_is_skipped_without_a_key() -> None:
    config = Config(timeout=5)
    async with httpx.AsyncClient(trust_env=False) as client:
        ctx = RunContext(client=client, config=config, timeout=5, cache=None, secrets=[])
        report = await execute([VirusTotalSource()], ip_target("1.1.1.1"), ctx)
    assert report.sources[0].status == "skipped"
    assert report.sources[0].skip_reason == "VIRUSTOTAL_API_KEY is not set"


async def test_finding_value_containing_a_key_is_scrubbed() -> None:
    secret = "super-secret-value"

    class Leaky(Source):
        name = "ok-demo"
        description = "leaks"
        target_types = frozenset({TargetType.DOMAIN})

        async def run(self, target: object, ctx: object) -> list[object]:
            del target, ctx
            return [
                make_finding(
                    source=self.name,
                    category="dns",
                    title="Token",
                    value=secret,
                    source_url=f"https://example.com/?key={secret}",
                )
            ]

    config = Config(timeout=5, keys={"VIRUSTOTAL_API_KEY": secret})
    async with httpx.AsyncClient(trust_env=False) as client:
        ctx = RunContext(
            client=client,
            config=config,
            timeout=5,
            cache=None,
            secrets=[secret],
        )
        report = await execute([Leaky()], domain_target("example.com"), ctx)
    finding = report.sources[0].findings[0]
    assert secret not in finding.value
    assert secret not in (finding.source_url or "")
    assert "key=***" in (finding.source_url or "")
