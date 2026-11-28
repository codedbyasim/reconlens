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


def render_csv(report: Report) -> str:
    """Render findings as CSV. Every field is quoted and the file ends with a newline."""

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(COLUMNS)
    for source in report.sources:
        for finding in source.findings:
            writer.writerow(
                (
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
            )
    return buffer.getvalue()
