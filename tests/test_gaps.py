"""Extra branches: error paths, keyed payloads, config, and the terminal view."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from reconlens import dnsutil
from reconlens.cache import FileCache
from reconlens.cli import app
from reconlens.config import Config, ConfigError, load_config
from reconlens.context import RunContext
from reconlens.errors import ReportError, SourceError
from reconlens.http import build_client
from reconlens.models import Report as ReportModel
from reconlens.models import Severity, SourceRun, Target, TargetType, make_finding
from reconlens.net import json_body
from reconlens.plugins.base import Source
from reconlens.plugins.crtsh import CrtShSource
from reconlens.plugins.hibp import HibpSource, findings_from_hibp
from reconlens.plugins.ip_geo import findings_from_ipwho
from reconlens.plugins.rdap_whois import RdapSource, findings_from_rdap
from reconlens.plugins.registry import _load_dotted, _validate_class, load_sources
from reconlens.plugins.shodan import ShodanSource
from reconlens.plugins.urlscan import findings_from_urlscan
from reconlens.plugins.username_sites import UsernameSource, load_sites
from reconlens.plugins.virustotal import VirusTotalSource
from reconlens.plugins.wayback import WaybackSource
from reconlens.render import render_terminal
from reconlens.reports.html import render_html
from reconlens.reports.json_report import report_from_dict
from reconlens.runner import execute
from reconlens.textutil import clip
from reconlens.validate import domain_target, email_target
from tests.conftest import make_context
from tests.test_cli import _mock_domain, _patch_dns, _patch_tls

runner = CliRunner()


def test_clip_and_invalid_json() -> None:
    assert clip("a  b", 10) == "a b"
    assert clip("abcdef", 3) == "abc"
    assert clip("abcdef", 5) == "ab..."
    response = httpx.Response(200, content=b"not-json")
    with pytest.raises(SourceError):
        json_body(response)


def test_config_validation_and_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = tmp_path / "broken.toml"
    broken.write_text("this = [", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CONFIG": str(broken)})
    bad_section = tmp_path / "section.toml"
    bad_section.write_text("cache = true\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CONFIG": str(bad_section)})
    types = tmp_path / "types.toml"
    types.write_text(
        '[cache]\nenabled = "yes"\nttl_seconds = -1\n[http]\ntimeout = 0\nuser_agent = 1\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CONFIG": str(types)})
    home = tmp_path / "home"
    config_dir = home / ".config" / "reconlens"
    config_dir.mkdir(parents=True)
    (config_dir / "config.toml").write_text(
        '[http]\ntimeout = 15\nuser_agent = "LocalAgent/1"\n[keys]\nHIBP_API_KEY = ""\n',
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    loaded = load_config(
        {
            "HOME": str(home),
            "RECONLENS_CACHE": "false",
            "RECONLENS_CACHE_TTL": "30",
            "RECONLENS_CACHE_DIR": str(tmp_path / "cache"),
            "RECONLENS_TIMEOUT": "9",
            "RECONLENS_USER_AGENT": "Override/2",
        }
    )
    assert loaded.timeout == 9
    assert loaded.user_agent == "Override/2"
    assert loaded.cache_enabled is False
    assert loaded.cache_directory == tmp_path / "cache"
    assert "HIBP_API_KEY" not in loaded.keys
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CACHE": "maybe"})
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_TIMEOUT": "nope"})


def test_registry_rejects_bad_plugins() -> None:
    class Bad(Source):
        name = "Bad Name"
        description = "nope"
        target_types = frozenset({TargetType.DOMAIN})

        async def run(self, target: Target, ctx: RunContext) -> list[object]:
            del target, ctx
            return []

    with pytest.raises(TypeError):
        _validate_class(Bad, "bad-name")
    with pytest.raises(TypeError):
        _load_dotted("not a path")
    with pytest.raises(TypeError):
        _load_dotted("reconlens.version:__version__")

    class NeedsKey(Source):
        name = "needs-key"
        description = "keyed"
        target_types = frozenset()
        requires_api_key = True
        api_key_env = None

        async def run(self, target: Target, ctx: RunContext) -> list[object]:
            del target, ctx
            return []

    with pytest.raises(TypeError):
        _validate_class(NeedsKey, "needs-key")


def test_entry_point_errors_fall_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> list[tuple[str, str]]:
        raise RuntimeError("metadata down")

    monkeypatch.setattr("reconlens.plugins.registry._iter_entry_points", boom)
    sources, errors = load_sources()
    assert sources
    assert errors[0].name == "entry-points"


def test_payload_helpers() -> None:
    breaches = findings_from_hibp(
        "hibp",
        "user@example.com",
        [
            {
                "Title": "Example",
                "BreachDate": "2020-01-01",
                "DataClasses": ["Email addresses", "Passwords"],
            }
        ]
        * 21,
        "https://haveibeenpwned.com/",
    )
    assert breaches[0].severity is Severity.MEDIUM
    assert any(item.title == "Additional breaches" for item in breaches)
    scans = findings_from_urlscan(
        "urlscan",
        "example.com",
        {
            "results": [
                {
                    "page": {"url": "https://example.com/a"},
                    "task": {"time": "2024-01-01", "uuid": "abc"},
                }
            ]
        },
    )
    assert any(item.source_url == "https://urlscan.io/result/abc/" for item in scans)
    geo = findings_from_ipwho(
        "ip-geo", "192.0.2.1", {"success": True}, "https://ipwho.is/192.0.2.1"
    )
    assert geo[0].title == "No geolocation details"
    rdap = findings_from_rdap(
        "rdap",
        "192.0.2.1",
        {
            "handle": "NET",
            "name": "TEST",
            "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
            "country": "US",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
        },
        "https://rdap.org/ip/192.0.2.1",
    )
    assert any(item.title == "Network" and "192.0.2.0/24" in item.value for item in rdap)


async def test_http_error_paths(ctx: RunContext, mocked: object) -> None:
    domain = Target("example.com", TargetType.DOMAIN, "example.com")
    mocked.get(url__startswith="https://crt.sh/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, json={"error": "no"})
    )
    with pytest.raises(SourceError):
        await CrtShSource().run(domain, ctx)
    mocked.get(url__regex=r"https://rdap\.org/domain/missing\.example").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(404)
    )
    missing = await RdapSource().run(
        Target("missing.example", TargetType.DOMAIN, "missing.example"), ctx
    )
    assert missing[0].title == "No RDAP record"
    mocked.get(url__startswith="https://web.archive.org/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, content=b"")
    )
    empty = await WaybackSource().run(domain, ctx)
    assert empty[0].title == "No snapshots"

    secret = "test-key-value"
    async with httpx.AsyncClient(trust_env=False) as client:
        keyed = make_context(
            client,
            keys={"VIRUSTOTAL_API_KEY": secret, "SHODAN_API_KEY": secret, "HIBP_API_KEY": secret},
        )
        mocked.get(url__regex=r"https://www\.virustotal\.com/api/v3/ip_addresses/.*").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(404)
        )
        vt = await VirusTotalSource().run(Target("8.8.8.8", TargetType.IP, "8.8.8.8"), keyed)
        assert vt[0].title == "No VirusTotal record"
        mocked.get(url__regex=r"https://api\.shodan\.io/shodan/host/8\.8\.8\.8.*").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(
                200,
                json={"org": "Example", "asn": "AS1", "hostnames": ["dns.example"], "ports": [443]},
            )
        )
        host = await ShodanSource().run(Target("8.8.8.8", TargetType.IP, "8.8.8.8"), keyed)
        assert any(item.title == "Observed ports" and "443" in item.value for item in host)
        assert secret not in repr(host)
        mocked.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "Title": "Adobe",
                        "BreachDate": "2013-10-04",
                        "DataClasses": ["Email addresses"],
                    }
                ],
            )
        )
        breach = await HibpSource().run(email_target("user@example.com"), keyed)
        assert breach[0].title == "Adobe"
        assert secret not in repr(breach)


def test_dns_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    class Rdata:
        def __init__(self, text: str, strings: list[bytes] | None = None) -> None:
            self._text = text
            self.strings = strings

        def __str__(self) -> str:
            return self._text

    class Resolver:
        def __init__(self) -> None:
            self.timeout = 0.0
            self.lifetime = 0.0

        def resolve(
            self, name: str, rtype: str, lifetime: float | None = None, search: bool | None = None
        ) -> list[Rdata]:
            del name, lifetime, search
            if rtype == "TXT":
                return [Rdata("", strings=[b"hello", b" world"])]
            if rtype == "A":
                raise dnsutil.dns.resolver.NXDOMAIN()
            raise dnsutil.dns.exception.Timeout()

    monkeypatch.setattr(dnsutil.dns.resolver, "Resolver", Resolver)
    assert dnsutil.resolve_sync("example.com", "TXT", 1).values == ["hello world"]
    assert dnsutil.resolve_sync("example.com", "A", 1).error == "nxdomain"
    assert dnsutil.resolve_sync("example.com", "MX", 1).error == "timeout"


async def test_execute_uses_cache(tmp_path: Path) -> None:
    class Once(Source):
        name = "ok-demo"
        description = "cached"
        target_types = frozenset({TargetType.DOMAIN})
        cache_version = 1
        calls = 0

        async def run(self, target: Target, ctx: RunContext) -> list[object]:
            del target, ctx
            Once.calls += 1
            return [make_finding(source=self.name, category="dns", title="A", value="192.0.2.9")]

    cache = FileCache(tmp_path, ttl_seconds=3600)
    config = Config(timeout=5)
    target = domain_target("example.com")
    async with build_client(config, trust_env=False) as client:
        ctx = RunContext(client=client, config=config, timeout=5, cache=cache, secrets=[])
        await execute([Once()], target, ctx)
        second = await execute([Once()], target, ctx)
    assert Once.calls == 1
    assert second.sources[0].cached is True
    assert second.sources[0].findings[0].value == "192.0.2.9"


def test_terminal_and_html_cover_status_rows() -> None:
    from datetime import datetime, timezone

    now = datetime(2026, 11, 22, tzinfo=timezone.utc)
    findings = [
        make_finding(
            source="dns", category="dns", title=f"Item {index}", value=str(index), timestamp=now
        )
        for index in range(41)
    ]
    report = ReportModel(
        target=domain_target("example.com"),
        started_at=now,
        finished_at=now,
        sources=[
            SourceRun("dns", "ok", 1, False, findings),
            SourceRun("ssl", "error", 1, False, [], error=None),
            SourceRun("virustotal", "skipped", 0, False, [], skip_reason=None),
            SourceRun("wayback", "ok", 1, True, []),
        ],
        notices=[],
    )
    from rich.console import Console

    console = Console(record=True, highlight=False, width=80)
    render_terminal(report, console)
    text = console.export_text()
    assert "more findings" in text
    assert "skipped" in text
    assert "failed" in text
    html = render_html(report)
    assert "Failed." in html
    assert "Skipped." in html
    assert "No findings." in html


def test_username_catalog_skip_and_cli_paths(
    tmp_path: Path,
    mocked: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = json.loads(Path("src/reconlens/data/username_sites.json").read_text(encoding="utf-8"))
    raw["sites"].append({"name": "", "url": "ftp://nope"})
    path = tmp_path / "sites.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(
        "reconlens.plugins.username_sites._catalog_text",
        lambda: path.read_text(encoding="utf-8"),
    )
    sites, skipped = load_sites()
    assert sites
    assert skipped == 1

    _patch_dns(monkeypatch)
    _patch_tls(monkeypatch)
    _mock_domain(mocked)
    failed = runner.invoke(app, ["domain", "example.com", "--sources", "ssl", "--quiet"])
    assert failed.exit_code == 1
    unknown = runner.invoke(app, ["domain", "example.com", "--sources", "not-a-source"])
    assert unknown.exit_code == 2
    text = runner.invoke(app, ["domain", "example.com", "--fail-on-error"])
    assert text.exit_code == 1
    assert "example.com" in text.stdout
    bad_report = tmp_path / "bad.json"
    bad_report.write_text("{", encoding="utf-8")
    rendered = runner.invoke(app, ["report", "--input", str(bad_report), "--output", "html"])
    assert rendered.exit_code == 1
    with pytest.raises(ReportError):
        report_from_dict([])


async def test_username_found(
    ctx: RunContext, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reconlens.plugins.username_sites import Site

    monkeypatch.setattr(UsernameSource, "min_interval_seconds", 0.0)
    monkeypatch.setattr(
        "reconlens.plugins.username_sites.load_sites",
        lambda: ([Site("GitHub", "https://github.com/{username}", (200,), (404,))], 0),
    )
    mocked.get("https://github.com/octocat").mock(return_value=httpx.Response(200, text="hi"))  # type: ignore[attr-defined]
    findings = await UsernameSource().run(Target("octocat", TargetType.USERNAME, "octocat"), ctx)
    assert findings[0].value == "found"
