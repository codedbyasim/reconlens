"""Remove API keys from text that might be printed or stored."""

from __future__ import annotations

import re
from collections.abc import Sequence

_QUERY = re.compile(r"(?i)([?&](?:key|api_key|apikey|token|access_token|api-key)=)([^&\s\"']+)")
_HEADER = re.compile(r"(?i)((?:x-apikey|api-key|hibp-api-key|authorization)\s*[:=]\s*)([^\s,;]+)")


def scrub_text(value: str, secrets: Sequence[str]) -> str:
    """Replace known secrets and common key query parameters."""

    text = _QUERY.sub(r"\1***", value)
    text = _HEADER.sub(r"\1***", text)
    for secret in secrets:
        if len(secret) >= 8 and secret in text:
            text = text.replace(secret, "***")
    return text


def safe_error_message(exc: BaseException, secrets: Sequence[str]) -> str:
    """A short, redacted description of an exception."""

    text = scrub_text(f"{exc.__class__.__name__}: {exc}", secrets)
    if len(text) > 400:
        return text[:397] + "..."
    return text
