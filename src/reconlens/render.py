"""Rich terminal view. Machine-readable formats are written separately."""

from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from reconlens.models import Report, summarize

_SEVERITY = {
    "info": "cyan",
    "low": "yellow",
    "medium": "dark_orange",
    "high": "red",
}
_STATUS = {"ok": "green", "skipped": "yellow", "error": "red"}
_PER_SOURCE = 40


def render_terminal(report: Report, console: Console | None = None) -> None:
    """Print a readable summary. Long source lists are truncated on screen only."""

    out = console or Console(highlight=False, emoji=False)
    summary = summarize(report)
    header = Text()
    header.append(f"ReconLens {report.tool_version}", style="bold")
    header.append("  passive reconnaissance\n", style="dim")
    header.append("Target  ")
    header.append(report.target.value, style="bold")
    header.append(f"  ({report.target.type.value})\n", style="dim")
    header.append("Result  ")
    header.append(f"{summary.ok} ok", style="green")
    header.append("  ")
    header.append(f"{summary.skipped} skipped", style="yellow")
    header.append("  ")
    header.append(f"{summary.errors} failed", style="red")
    header.append(f"  {summary.findings} findings · {summary.elapsed_ms} ms\n", style="dim")
    header.append(
        "Authorized use only. No port scans, brute force, or login attempts.",
        style="dim",
    )
    out.print(Panel(header, border_style="cyan", title="reconlens"))
    for source in report.sources:
        if source.status != "ok":
            continue
        table = Table(
            title=source.name + ("  cached" if source.cached else ""),
            box=box.SIMPLE_HEAD,
            show_lines=False,
            pad_edge=False,
            title_style="bold",
        )
        table.add_column("Sev", width=8, no_wrap=True)
        table.add_column("Finding", overflow="fold")
        table.add_column("Value", overflow="fold")
        visible = source.findings[:_PER_SOURCE]
        if not visible:
            table.add_row(Text("info", style="cyan"), Text("Result"), Text("no findings"))
        for finding in visible:
            value = Text(finding.value)
            if finding.detail:
                value.append("\n")
                value.append(finding.detail, style="dim")
            table.add_row(
                Text(finding.severity.value, style=_SEVERITY.get(finding.severity.value, "cyan")),
                Text(finding.title),
                value,
            )
        out.print(table)
        hidden = len(source.findings) - len(visible)
        if hidden > 0:
            out.print(
                f"[dim]{source.name}: {hidden} more findings. "
                "Use --output json --out report.json for the full set.[/dim]"
            )
    skipped = [source for source in report.sources if source.status == "skipped"]
    failed = [source for source in report.sources if source.status == "error"]
    if skipped:
        out.print()
        for source in skipped:
            out.print(
                f"[{_STATUS['skipped']}]skipped[/{_STATUS['skipped']}] "
                f"{source.name}: {source.skip_reason or 'no reason recorded'}"
            )
    if failed:
        out.print()
        for source in failed:
            out.print(
                f"[{_STATUS['error']}]failed[/{_STATUS['error']}] "
                f"{source.name}: {source.error or 'no error recorded'}"
            )
    if report.notices:
        out.print()
        for notice in report.notices:
            out.print(f"[dim]notice:[/dim] {notice}")
    if summary.ok == 0 and summary.errors == 0 and summary.skipped:
        out.print("\n[yellow]Every selected source was skipped.[/yellow]")
