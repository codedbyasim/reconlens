"""Normalize CLI targets before any source sees them."""

from __future__ import annotations

import ipaddress
import re

from reconlens.errors import TargetError
from reconlens.models import Target, TargetType

_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL = re.compile(r"^([^@\s]{1,64})@([^\s@]+)$")
_USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,30}[A-Za-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII hostname or raise :class:`TargetError`."""

    original = value.strip()
    if not original or any(character.isspace() for character in original):
        raise TargetError("domain must not contain spaces")
    lowered = original.lower().rstrip(".")
    if "://" in lowered or "/" in lowered or "\\" in lowered or "@" in lowered:
        raise TargetError("pass a bare domain, not a URL or an email address")
    if "_" in lowered or "*" in lowered:
        raise TargetError("domain must not contain a wildcard or an underscore")
    try:
        ascii_domain = lowered.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetError("domain is not valid internationalized text") from exc
    if not _DOMAIN.fullmatch(ascii_domain):
        raise TargetError("domain is not a valid hostname")
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        return ascii_domain
    raise TargetError("this looks like an IP address; use `reconlens ip`")


def normalize_ip(value: str) -> str:
    """Return a compressed IP address or raise :class:`TargetError`."""

    raw = value.strip()
    if not raw or "%" in raw or "/" in raw:
        raise TargetError("pass one IP address, without a zone id or a prefix length")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise TargetError("not an IP address") from exc


def normalize_email(value: str) -> str:
    """Return a lowercased address whose domain is a valid hostname."""

    raw = value.strip()
    match = _EMAIL.fullmatch(raw)
    if match is None:
        raise TargetError("email address is not valid")
    local, domain = match.group(1), match.group(2)
    try:
        normalized_domain = normalize_domain(domain)
    except TargetError as exc:
        raise TargetError(f"email domain is not valid: {exc}") from exc
    return f"{local.lower()}@{normalized_domain}"


def normalize_username(value: str) -> str:
    """Return a username that is safe to place in a profile path."""

    raw = value.strip()
    if not _USERNAME.fullmatch(raw) or ".." in raw:
        raise TargetError(
            "username must be 1-32 characters: letters, digits, dots, underscores, "
            "or hyphens, and it cannot contain '..'"
        )
    return raw


def domain_target(value: str) -> Target:
    normalized = normalize_domain(value)
    return Target(value=normalized, type=TargetType.DOMAIN, original=value.strip())


def ip_target(value: str) -> Target:
    normalized = normalize_ip(value)
    return Target(value=normalized, type=TargetType.IP, original=value.strip())


def email_target(value: str) -> Target:
    normalized = normalize_email(value)
    return Target(value=normalized, type=TargetType.EMAIL, original=value.strip())


def username_target(value: str) -> Target:
    normalized = normalize_username(value)
    return Target(value=normalized, type=TargetType.USERNAME, original=value.strip())
