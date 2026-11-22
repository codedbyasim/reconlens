"""Shared fixtures. Tests do not use the network."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest
import respx

from reconlens import net
from reconlens.config import KEY_ENV_NAMES, Config
from reconlens.context import RunContext
from reconlens.http import build_client

ORIGINAL_HOST_IS_PUBLIC = net.host_is_public


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Point config at an empty file and drop any API keys from the environment."""

    path = tmp_path / "empty.toml"
    path.write_text("[keys]\n", encoding="utf-8")
    monkeypatch.setenv("RECONLENS_CONFIG", str(path))
    for name in KEY_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("RECONLENS_CACHE", raising=False)
    monkeypatch.delenv("RECONLENS_CACHE_DIR", raising=False)


@pytest.fixture(autouse=True)
def public_hosts(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip real DNS for the public-host guard. Tests opt into the real function."""

    async def _yes(host: str) -> bool:
        del host
        return True

    monkeypatch.setattr(net, "host_is_public", _yes)


@pytest.fixture
def mocked() -> Iterator[respx.MockRouter]:
    with respx.mock(assert_all_mocked=True, base_url=None) as router:
        yield router


@pytest.fixture
async def ctx(mocked: respx.MockRouter) -> AsyncIterator[RunContext]:
    del mocked
    config = Config(timeout=5)
    async with build_client(config, trust_env=False) as client:
        yield RunContext(
            client=client,
            config=config,
            timeout=5,
            cache=None,
            secrets=[],
        )


def make_context(client: httpx.AsyncClient, *, keys: dict[str, str] | None = None) -> RunContext:
    material = keys or {}
    return RunContext(
        client=client,
        config=Config(timeout=5, keys=dict(material)),
        timeout=5,
        cache=None,
        secrets=[value for value in material.values() if len(value) >= 8],
    )
