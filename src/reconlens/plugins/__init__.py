"""Public plugin interface.

Third-party packages register a :class:`Source` on the ``reconlens.sources``
entry-point group. See ``CONTRIBUTING.md`` for the short version.
"""

from reconlens.models import (
    Category,
    Finding,
    Severity,
    Target,
    TargetType,
    make_finding,
)
from reconlens.plugins.base import Source

__all__ = [
    "Category",
    "Finding",
    "Severity",
    "Source",
    "Target",
    "TargetType",
    "make_finding",
]
