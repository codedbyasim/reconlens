"""Validation, redaction, config, networking, and the rate limiter."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from reconlens import context, net
from reconlens.config import ConfigError, load_config
from reconlens.context import RateLimiter
from reconlens.errors import SourceError, TargetError
from reconlens.redact import safe_error_message, scrub_text
from reconlens.validate import (
    domain_target,
    email_target,
    ip_target,
    normalize_domain,
    username_target,
)
from tests.conftest import ORIGINAL_HOST_IS_PUBLIC


def test_domain_normalization() -> None:
    target = domain_target("Example.COM.")
    assert target.value == "example.com"
    assert target.original == "Example.COM."
    with pytest.raises(TargetError):
        normalize_domain("https://example.com")
    with pytest.raises(TargetError):
        normalize_domain("1.1.1.1")
    with pytest.raises(TargetError):
        normalize_domain("not a domain")
    with pytest.raises(TargetError):
        normalize_domain("*.example.com")


def test_ip_email_and_username() -> None:
    assert ip_target("1.1.1.1").value == "1.1.1.1"
    assert ip_target("2001:db8::1").type.value == "ip"
    with pytest.raises(TargetError):
        ip_target("1.1.1.1/32")
    assert email_target("User@Example.com").value == "user@example.com"
    with pytest.raises(TargetError):
        email_target("not-an-email")
    assert username_target("octocat").value == "octocat"
    with pytest.raises(TargetError):
        username_target("../etc")
    with pytest.raises(TargetError):
        username_target("a..b")


def test_scrub_query_and_known_secret() -> None:
    secret = "super-secret-value"
    text = safe_error_message(
        RuntimeError(f"GET https://api.example.test/host?key={secret}"),
        [secret],
    )
    assert secret not in text
    assert "key=***" in text
    assert scrub_text("x-apikey: abcdefghijklmnop", []) == "x-apikey: ***"


def test_config_env_overrides_file_and_repr_hides_values(tmp_path: Path) -> None:
    path = tmp_path / "reconlens.toml"
    path.write_text(
        "\n".join(
            [
                "[cache]",
                "enabled = false",
                "ttl_seconds = 60",
                "[http]",
                "timeout = 12",
                "[keys]",
                'VIRUSTOTAL_API_KEY = "from-file-value"',
                "",
            ]
        ),
        encoding="utf-8",
    )
    config = load_config(
        {
            "RECONLENS_CONFIG": str(path),
            "VIRUSTOTAL_API_KEY": "from-env-value",
            "RECONLENS_CACHE": "true",
        }
    )
    assert config.keys["VIRUSTOTAL_API_KEY"] == "from-env-value"
    assert config.cache_enabled is True
    assert config.timeout == 12
    rendered = repr(config)
    assert "from-file-value" not in rendered
    assert "from-env-value" not in rendered
    assert "VIRUSTOTAL_API_KEY" in config.redacted()


def test_config_rejects_unknown_key_and_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.toml"
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CONFIG": str(missing)})
    bad = tmp_path / "bad.toml"
    bad.write_text('[keys]\nNOT_A_KEY = "x"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config({"RECONLENS_CONFIG": str(bad)})


def test_public_url_rules() -> None:
    assert net.validate_public_url("https://example.com/path") == "https://example.com/path"
    with pytest.raises(SourceError):
        net.validate_public_url("http://example.com")
    with pytest.raises(SourceError):
        net.validate_public_url("https://user:pass@example.com")
    with pytest.raises(SourceError):
        net.validate_public_url("https://127.0.0.1/")
    with pytest.raises(SourceError):
        net.validate_public_url("https://localhost/admin")
    assert net.addresses_are_public(["8.8.8.8", "1.1.1.1"]) is True
    assert net.addresses_are_public(["8.8.8.8", "10.0.0.1"]) is False
    assert net.addresses_are_public([]) is False


async def test_host_is_public_uses_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_private(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_private)
    assert await ORIGINAL_HOST_IS_PUBLIC("example.com") is False

    def fake_public(*_args: object, **_kwargs: object) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_public)
    assert await ORIGINAL_HOST_IS_PUBLIC("example.com") is True
    assert await ORIGINAL_HOST_IS_PUBLIC("8.8.8.8") is True
    assert await ORIGINAL_HOST_IS_PUBLIC("127.0.0.1") is False

    def explode(*_args: object, **_kwargs: object) -> list[object]:
        raise socket.gaierror("nope")

    monkeypatch.setattr(socket, "getaddrinfo", explode)
    assert await ORIGINAL_HOST_IS_PUBLIC("missing.example") is False


async def test_redirect_to_loopback_is_refused(ctx: context.RunContext, mocked: object) -> None:
    import httpx

    router = mocked
    assert hasattr(router, "get")
    router.get("https://example.com/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(302, headers={"location": "https://127.0.0.1/secret"})
    )
    with pytest.raises(SourceError):
        await ctx.get_public("https://example.com/", source="demo", min_interval=0)


async def test_public_redirect_is_followed(ctx: context.RunContext, mocked: object) -> None:
    import httpx

    router = mocked
    router.get("https://example.com/start").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(302, headers={"location": "https://example.org/landed"})
    )
    router.get("https://example.org/landed").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, text="ok")
    )
    response = await ctx.get_public("https://example.com/start", source="demo", min_interval=0)
    assert response.status_code == 200
    assert response.text == "ok"


async def test_rate_limiter_spaces_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = {"now": 10.0}
    sleeps: list[float] = []
    monkeypatch.setattr(context.time, "monotonic", lambda: clock["now"])

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)
        clock["now"] += delay

    monkeypatch.setattr(context.asyncio, "sleep", fake_sleep)
    limiter = RateLimiter(0.5)
    await limiter.wait()
    await limiter.wait()
    assert sleeps == [0.5]
