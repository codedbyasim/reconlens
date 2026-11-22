"""Load built-in and third-party sources from entry points."""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Any

from reconlens.errors import ReconLensError
from reconlens.models import TargetType
from reconlens.plugins.base import Source
from reconlens.redact import safe_error_message

# Used when the package is not installed (for example PYTHONPATH=src).
# Installed environments, including third-party plugins, use entry points only.
# Keep this list identical to [project.entry-points."reconlens.sources"].
BUILTIN_PATHS: tuple[tuple[str, str], ...] = (
    ("dns", "reconlens.plugins.dns_records:DnsSource"),
    ("rdap", "reconlens.plugins.rdap_whois:RdapSource"),
    ("crtsh", "reconlens.plugins.crtsh:CrtShSource"),
    ("ssl", "reconlens.plugins.ssl_cert:SslCertSource"),
    ("http-headers", "reconlens.plugins.http_headers:HttpHeadersSource"),
    ("robots", "reconlens.plugins.robots_security:RobotsSecuritySource"),
    ("ip-geo", "reconlens.plugins.ip_geo:IpGeoSource"),
    ("wayback", "reconlens.plugins.wayback:WaybackSource"),
    ("username", "reconlens.plugins.username_sites:UsernameSource"),
    ("email-auth", "reconlens.plugins.email_auth:EmailAuthSource"),
    ("gravatar", "reconlens.plugins.gravatar:GravatarSource"),
    ("virustotal", "reconlens.plugins.virustotal:VirusTotalSource"),
    ("abuseipdb", "reconlens.plugins.abuseipdb:AbuseIpdbSource"),
    ("urlscan", "reconlens.plugins.urlscan:UrlscanSource"),
    ("shodan", "reconlens.plugins.shodan:ShodanSource"),
    ("hibp", "reconlens.plugins.hibp:HibpSource"),
)

_NAME = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


@dataclass(frozen=True)
class LoadError:
    """A plugin that could not be imported. The rest of the run still proceeds."""

    name: str
    message: str


def load_sources() -> tuple[list[Source], list[LoadError]]:
    """Import every source. One broken plugin does not drop the others."""

    errors: list[LoadError] = []
    try:
        specs = _iter_entry_points()
    except Exception as exc:
        specs = list(BUILTIN_PATHS)
        errors.append(LoadError("entry-points", safe_error_message(exc, [])))
    loaded: dict[str, Source] = {}
    for entry_name, path in specs:
        try:
            cls = _load_dotted(path)
            _validate_class(cls, entry_name)
            instance = cls()
        except (ReconLensError, Exception) as exc:
            errors.append(LoadError(entry_name, safe_error_message(exc, [])))
            continue
        if instance.name in loaded:
            errors.append(LoadError(entry_name, f"duplicate source name {instance.name}"))
            continue
        loaded[instance.name] = instance
    ordered = sorted(loaded.values(), key=lambda item: (item.display_order, item.name))
    return ordered, errors


def _iter_entry_points() -> list[tuple[str, str]]:
    discovered = list(entry_points(group="reconlens.sources"))
    if not discovered:
        return list(BUILTIN_PATHS)
    return [(item.name, item.value) for item in discovered]


def _load_dotted(path: str) -> type[Source]:
    module_name, separator, attr = path.partition(":")
    if not separator or not module_name or not attr:
        raise TypeError(f"invalid plugin path {path!r}")
    module = importlib.import_module(module_name)
    obj: Any = getattr(module, attr)
    if not isinstance(obj, type) or not issubclass(obj, Source):
        raise TypeError(f"{path} is not a Source subclass")
    return obj


def _validate_class(cls: type[Source], entry_name: str) -> None:
    if not isinstance(getattr(cls, "name", None), str):
        raise TypeError(f"{cls.__name__} is missing name")
    if cls.name != entry_name:
        raise TypeError(f"entry point name {entry_name!r} does not match class name {cls.name!r}")
    if _NAME.fullmatch(cls.name) is None:
        raise TypeError(f"source name {cls.name!r} must be lowercase words and hyphens")
    if not isinstance(cls.description, str) or not cls.description.strip():
        raise TypeError(f"{cls.name} is missing a description")
    targets = getattr(cls, "target_types", None)
    if not isinstance(targets, (set, frozenset)) or not targets:
        raise TypeError(f"{cls.name} must set target_types to a non-empty set")
    if not set(targets).issubset(set(TargetType)):
        raise TypeError(f"{cls.name} has an unknown target type")
    if cls.requires_api_key and not cls.api_key_env:
        raise TypeError(f"{cls.name} requires an API key but api_key_env is empty")
