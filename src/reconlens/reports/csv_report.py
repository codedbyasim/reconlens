"""CSV report: one row per finding."""

from __future__ import annotations

import csv
import io

from reconlens.models import Report, iso

COLUMNS = (
    "source",
    "category",
    "severity",
    "title",
    "value",
    "detail",
    "source_url",
    "timestamp",
    "id",
)


_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe(cell: str) -> str:
    """Prefix a single quote so spreadsheets do not run a cell as a formula."""

    return f"'{cell}" if cell.startswith(_FORMULA_PREFIXES) else cell


def render_csv(report: Report) -> str:
    """Render findings as CSV. Every field is quoted, formula-like cells get a leading quote, and the file ends with a newline."""

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for source in report.sources:
        for finding in source.findings:
            cells = (
                finding.source,
                finding.category,
                finding.severity.value,
                finding.title,
                finding.value,
                finding.detail or "",
                finding.source_url or "",
                iso(finding.timestamp),
                finding.id,
            )
            writer.writerow(_safe(cell) for cell in cells)
    return buffer.getvalue()
