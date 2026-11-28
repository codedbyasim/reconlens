"""JSON Lines report: one finding object per line."""

from __future__ import annotations

import json

from reconlens.models import Report, finding_to_dict


def render_jsonl(report: Report) -> str:
    """Render one compact JSON object per finding, each with the target fields."""

    lines: list[str] = []
    for source in report.sources:
        for finding in source.findings:
            row = {
                "target": report.target.value,
                "target_type": report.target.type.value,
                **finding_to_dict(finding),
            }
            line = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
            lines.append(line.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))
    return "".join(f"{line}\n" for line in lines)
