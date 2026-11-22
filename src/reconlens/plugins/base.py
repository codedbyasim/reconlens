"""The contract every ReconLens source implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from reconlens.models import Finding, Target, TargetType

if TYPE_CHECKING:
    from reconlens.context import RunContext


class Source(ABC):
    """One passive data source.

    Subclass this, set the class attributes, and register the class as an
    entry point in the ``reconlens.sources`` group. ``run`` must not scan
    ports, guess names, or attempt to log in. Raise ``SourceError`` when this
    source cannot complete; the runner will keep the other sources.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    target_types: ClassVar[frozenset[TargetType]]
    requires_api_key: ClassVar[bool] = False
    api_key_env: ClassVar[str | None] = None
    min_interval_seconds: ClassVar[float] = 0.0
    display_order: ClassVar[int] = 100
    homepage: ClassVar[str | None] = None
    cache_version: ClassVar[int] = 1

    @abstractmethod
    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        """Return normalized findings for ``target``."""
