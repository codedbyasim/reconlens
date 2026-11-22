"""Load settings from a TOML file and the environment. Keys are never printed."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, cast

import tomli

from reconlens.errors import ConfigError

KEY_ENV_NAMES = (
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "URLSCAN_API_KEY",
    "SHODAN_API_KEY",
    "HIBP_API_KEY",
)
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


@dataclass
class Config:
    """Runtime settings. ``keys`` is omitted from ``repr`` so logs stay safe."""

    cache_enabled: bool = False
    cache_ttl_seconds: int = 3600
    cache_directory: Path | None = None
    timeout: float = 30.0
    user_agent: str | None = None
    keys: dict[str, str] = field(default_factory=dict, repr=False)

    def redacted(self) -> str:
        """A one-line description that names configured keys without their values."""

        present = ", ".join(sorted(name for name, value in self.keys.items() if value))
        return (
            f"Config(timeout={self.timeout}, cache_enabled={self.cache_enabled}, keys=[{present}])"
        )


def default_cache_dir() -> Path:
    """Return the XDG cache directory for ReconLens."""

    xdg = os.environ.get("XDG_CACHE_HOME", "").strip()
    base = Path(xdg).expanduser() if xdg else Path.home() / ".cache"
    return base / "reconlens"


def load_config(environ: Mapping[str, str] | None = None) -> Config:
    """Load config. Environment variables override the TOML file."""

    env = os.environ if environ is None else environ
    data = _read_file(env)
    config = Config(
        cache_enabled=_section_bool(data, "cache", "enabled", default=False),
        cache_ttl_seconds=_section_int(data, "cache", "ttl_seconds", default=3600),
        cache_directory=_cache_directory(data),
        timeout=_section_float(data, "http", "timeout", default=30.0),
        user_agent=_section_text(data, "http", "user_agent"),
        keys=_keys_from_file(data),
    )
    return _apply_env(config, env)


def _read_file(env: Mapping[str, str]) -> dict[str, Any]:
    explicit = env.get("RECONLENS_CONFIG", "").strip()
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise ConfigError(f"config file not found: {path}")
        return _read_toml(path)
    for candidate in _search_paths(env):
        if candidate.is_file():
            return _read_toml(candidate)
    return {}


def _search_paths(env: Mapping[str, str]) -> list[Path]:
    paths = [Path.cwd() / "reconlens.toml"]
    xdg = env.get("XDG_CONFIG_HOME", "").strip()
    if xdg:
        base = Path(xdg).expanduser()
    else:
        home = env.get("HOME", "").strip()
        base = Path(home).expanduser() if home else Path.home()
        base = base / ".config"
    paths.append(base / "reconlens" / "config.toml")
    return paths


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            loaded = tomli.load(handle)
    except (OSError, tomli.TOMLDecodeError) as exc:
        raise ConfigError(f"could not read {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise ConfigError(f"config file must be a table: {path}")
    return loaded


def _section(data: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    raw = data.get(name, {})
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"[{name}] must be a table")
    return cast(Mapping[str, Any], raw)


def _section_bool(data: Mapping[str, Any], section: str, key: str, *, default: bool) -> bool:
    table = _section(data, section)
    if key not in table:
        return default
    value = table[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{section}.{key} must be true or false")
    return value


def _section_int(data: Mapping[str, Any], section: str, key: str, *, default: int) -> int:
    table = _section(data, section)
    if key not in table:
        return default
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{section}.{key} must be an integer")
    if value < 0 or value > 30 * 24 * 3600:
        raise ConfigError(f"{section}.{key} is out of range")
    return value


def _section_float(data: Mapping[str, Any], section: str, key: str, *, default: float) -> float:
    table = _section(data, section)
    if key not in table:
        return default
    value = table[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{section}.{key} must be a number")
    number = float(value)
    if number < 1 or number > 120:
        raise ConfigError(f"{section}.{key} must be between 1 and 120 seconds")
    return number


def _section_text(data: Mapping[str, Any], section: str, key: str) -> str | None:
    table = _section(data, section)
    if key not in table:
        return None
    value = table[key]
    if not isinstance(value, str):
        raise ConfigError(f"{section}.{key} must be a string")
    stripped = value.strip()
    return stripped or None


def _cache_directory(data: Mapping[str, Any]) -> Path | None:
    text = _section_text(data, "cache", "directory")
    if text is None:
        return None
    return Path(text).expanduser()


def _keys_from_file(data: Mapping[str, Any]) -> dict[str, str]:
    table = _section(data, "keys")
    unknown = sorted(set(table) - set(KEY_ENV_NAMES))
    if unknown:
        raise ConfigError(
            "unknown key name(s) in [keys]: "
            + ", ".join(unknown)
            + ". Expected "
            + ", ".join(KEY_ENV_NAMES)
        )
    found: dict[str, str] = {}
    for name in KEY_ENV_NAMES:
        if name not in table:
            continue
        value = table[name]
        if not isinstance(value, str):
            raise ConfigError(f"keys.{name} must be a string")
        stripped = value.strip()
        if stripped:
            found[name] = stripped
    return found


def _apply_env(config: Config, env: Mapping[str, str]) -> Config:
    keys = dict(config.keys)
    for name in KEY_ENV_NAMES:
        value = env.get(name, "").strip()
        if value:
            keys[name] = value
    updates: dict[str, object] = {"keys": keys}
    cache_flag = env.get("RECONLENS_CACHE", "").strip().lower()
    if cache_flag:
        if cache_flag in _TRUE:
            updates["cache_enabled"] = True
        elif cache_flag in _FALSE:
            updates["cache_enabled"] = False
        else:
            raise ConfigError("RECONLENS_CACHE must be true or false")
    ttl = env.get("RECONLENS_CACHE_TTL", "").strip()
    if ttl:
        try:
            parsed = int(ttl)
        except ValueError as exc:
            raise ConfigError("RECONLENS_CACHE_TTL must be an integer") from exc
        if parsed < 0:
            raise ConfigError("RECONLENS_CACHE_TTL must be zero or greater")
        updates["cache_ttl_seconds"] = parsed
    directory = env.get("RECONLENS_CACHE_DIR", "").strip()
    if directory:
        updates["cache_directory"] = Path(directory).expanduser()
    timeout = env.get("RECONLENS_TIMEOUT", "").strip()
    if timeout:
        try:
            parsed_timeout = float(timeout)
        except ValueError as exc:
            raise ConfigError("RECONLENS_TIMEOUT must be a number") from exc
        if parsed_timeout < 1 or parsed_timeout > 120:
            raise ConfigError("RECONLENS_TIMEOUT must be between 1 and 120 seconds")
        updates["timeout"] = parsed_timeout
    user_agent = env.get("RECONLENS_USER_AGENT", "").strip()
    if user_agent:
        updates["user_agent"] = user_agent
    return replace(config, **updates)  # type: ignore[arg-type]
