"""Small string helpers shared by sources and renderers."""

from __future__ import annotations


def clip(value: str, limit: int) -> str:
    """Collapse whitespace and trim to ``limit`` characters."""

    compact = " ".join(value.split())
    if len(compact) <= limit:
        return compact
    if limit <= 3:
        return compact[:limit]
    return compact[: limit - 3] + "..."
