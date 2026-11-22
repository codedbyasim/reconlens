"""The ``reconlens`` command."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from reconlens.config import Config, load_config
from reconlens.errors import ConfigError, ReconLensError, ReportError, TargetError, UsageError
from reconlens.models import Report, Target
from reconlens.plugins.registry import load_sources
from reconlens.redact import scrub_text
from reconlens.render import render_terminal
from reconlens.reports.html import render_html
from reconlens.reports.json_report import load_report, render_json
from reconlens.reports.markdown import render_markdown
from reconlens.runner import collect
from reconlens.validate import domain_target, email_target, ip_target, username_target
from reconlens.version import __version__

app = typer.Typer(
    name="reconlens",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
    pretty_exceptions_enable=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"reconlens {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print the version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Passive reconnaissance for domains, IPs, emails, and usernames.

    ReconLens queries public records and read-only APIs. It does not scan ports,
    brute-force names, bypass authentication, or attempt logins.

    Use it only on targets you own or are authorized to assess. You are
    responsible for complying with the law and with each provider's terms.
    Requests are rate-limited and send an identifying User-Agent.
    """

    del version


@app.command()
def domain(
    target: str = typer.Argument(help="Domain name, such as example.com."),
    output: str = typer.Option("text", "--output", help="Report format: text, md, html, or json."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file."),
    timeout: float | None = typer.Option(
        None, "--timeout", min=1, max=120, help="Seconds to wait for each source."
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Use the on-disk cache."),
    sources: str | None = typer.Option(
        None, "--sources", help="Comma-separated source names to run."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated source names to skip."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print the terminal summary."),
    fail_on_error: bool = typer.Option(
        False, "--fail-on-error", help="Exit 1 if any source returns an error."
    ),
) -> None:
    """Look up public DNS, registration, certificate, and HTTP data for a domain."""

    _scan(
        _target(domain_target, target),
        output=output,
        out=out,
        timeout=timeout,
        cache=cache,
        sources=sources,
        exclude=exclude,
        quiet=quiet,
        fail_on_error=fail_on_error,
    )


@app.command()
def ip(
    target: str = typer.Argument(help="IP address, such as 1.1.1.1."),
    output: str = typer.Option("text", "--output", help="Report format: text, md, html, or json."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file."),
    timeout: float | None = typer.Option(
        None, "--timeout", min=1, max=120, help="Seconds to wait for each source."
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Use the on-disk cache."),
    sources: str | None = typer.Option(
        None, "--sources", help="Comma-separated source names to run."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated source names to skip."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print the terminal summary."),
    fail_on_error: bool = typer.Option(
        False, "--fail-on-error", help="Exit 1 if any source returns an error."
    ),
) -> None:
    """Look up registration and geolocation data for an IP address."""

    _scan(
        _target(ip_target, target),
        output=output,
        out=out,
        timeout=timeout,
        cache=cache,
        sources=sources,
        exclude=exclude,
        quiet=quiet,
        fail_on_error=fail_on_error,
    )


@app.command()
def email(
    target: str = typer.Argument(help="Email address, such as user@example.com."),
    output: str = typer.Option("text", "--output", help="Report format: text, md, html, or json."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file."),
    timeout: float | None = typer.Option(
        None, "--timeout", min=1, max=120, help="Seconds to wait for each source."
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Use the on-disk cache."),
    sources: str | None = typer.Option(
        None, "--sources", help="Comma-separated source names to run."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated source names to skip."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print the terminal summary."),
    fail_on_error: bool = typer.Option(
        False, "--fail-on-error", help="Exit 1 if any source returns an error."
    ),
) -> None:
    """Check MX, SPF, DMARC, and Gravatar for an email address.

    Have I Been Pwned runs only when HIBP_API_KEY is set. Query an address
    only when you are authorized to do so.
    """

    _scan(
        _target(email_target, target),
        output=output,
        out=out,
        timeout=timeout,
        cache=cache,
        sources=sources,
        exclude=exclude,
        quiet=quiet,
        fail_on_error=fail_on_error,
    )


@app.command()
def username(
    target: str = typer.Argument(help="Username, such as octocat."),
    output: str = typer.Option("text", "--output", help="Report format: text, md, html, or json."),
    out: Path | None = typer.Option(None, "--out", help="Write the report to this file."),
    timeout: float | None = typer.Option(
        None, "--timeout", min=1, max=120, help="Seconds to wait for each source."
    ),
    cache: bool | None = typer.Option(None, "--cache/--no-cache", help="Use the on-disk cache."),
    sources: str | None = typer.Option(
        None, "--sources", help="Comma-separated source names to run."
    ),
    exclude: str | None = typer.Option(
        None, "--exclude", help="Comma-separated source names to skip."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Do not print the terminal summary."),
    fail_on_error: bool = typer.Option(
        False, "--fail-on-error", help="Exit 1 if any source returns an error."
    ),
) -> None:
    """Check a small list of public profile pages for a username.

    Each site is requested once, over HTTPS, with no login. A hit means the
    public URL responded; open it before you treat it as the same person.
    """

    _scan(
        _target(username_target, target),
        output=output,
        out=out,
        timeout=timeout,
        cache=cache,
        sources=sources,
        exclude=exclude,
        quiet=quiet,
        fail_on_error=fail_on_error,
    )


@app.command("sources")
def sources_cmd() -> None:
    """List sources and whether they need an API key."""

    try:
        config = load_config()
        sources, errors = load_sources()
    except (ConfigError, ReconLensError) as exc:
        _fail(str(exc), code=2)
    console = Console(highlight=False, width=110)
    table = Table(title="ReconLens sources", show_lines=False)
    table.add_column("Name", style="bold", no_wrap=True)
    table.add_column("Targets", overflow="fold")
    table.add_column("Key", overflow="fold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Description", overflow="fold")
    for source in sources:
        env_name = source.api_key_env or ""
        if source.requires_api_key:
            key = env_name
            state = (
                "[green]key set[/green]"
                if config.keys.get(env_name)
                else "[yellow]needs key[/yellow]"
            )
        else:
            key = "none"
            state = "[green]ready[/green]"
        targets = ", ".join(sorted(item.value for item in source.target_types))
        table.add_row(source.name, targets, key, state, source.description)
    console.print(table)
    console.print(
        "[dim]Keyed sources stay disabled until the named variable is set in the "
        "environment or the config file. Values are never printed.[/dim]"
    )
    for error in errors:
        console.print(f"[red]load error:[/red] {escape(error.name)}: {escape(error.message)}")


@app.command("report")
def report_cmd(
    input_path: Path = typer.Option(
        ...,
        "--input",
        exists=True,
        dir_okay=False,
        readable=True,
        help="JSON report from a previous run.",
    ),
    output: str = typer.Option("md", "--output", help="Format to write: md, html, or json."),
    out: Path | None = typer.Option(None, "--out", help="Write the rendered report to this file."),
) -> None:
    """Render a saved JSON report as Markdown, HTML, or JSON."""

    try:
        fmt = _format(output)
        if fmt == "text":
            raise UsageError(
                "reconlens report writes md, html, or json. Omit --output for Markdown."
            )
        document = load_report(input_path.read_text(encoding="utf-8"))
        _emit(document, fmt, out, quiet=False, allow_text=False)
    except ReportError as exc:
        _fail(str(exc), code=1)
    except (UsageError, OSError) as exc:
        _fail(str(exc), code=2)


def _target(parser: Callable[[str], Target], value: str) -> Target:
    try:
        return parser(value)
    except TargetError as exc:
        _fail(str(exc), code=2)


def _scan(
    target: Target,
    *,
    output: str,
    out: Path | None,
    timeout: float | None,
    cache: bool | None,
    sources: str | None,
    exclude: str | None,
    quiet: bool,
    fail_on_error: bool,
) -> None:
    try:
        fmt = _format(output)
        only = None if sources is None else _names(sources)
        if sources is not None and not only:
            raise UsageError("--sources did not include any names")
        excluded = _names(exclude)
        config = _runtime_config(timeout=timeout, cache=cache)
        if not quiet and fmt == "text":
            Console(stderr=True, highlight=False).print(
                f"[dim]Querying passive sources for {target.value}[/dim]"
            )
        report = asyncio.run(collect(target, config=config, only=only, exclude=excluded))
        _emit(report, fmt, out, quiet=quiet, allow_text=True)
    except (TargetError, UsageError, ConfigError) as exc:
        _fail(str(exc), code=2)
    except ReconLensError as exc:
        _fail(str(exc), code=1)
    except OSError as exc:
        _fail(str(exc), code=1)
    else:
        if _should_fail(report, fail_on_error):
            raise typer.Exit(code=1)


def _runtime_config(*, timeout: float | None, cache: bool | None) -> Config:
    config = load_config()
    updates: dict[str, object] = {}
    if timeout is not None:
        updates["timeout"] = timeout
    if cache is not None:
        updates["cache_enabled"] = cache
    if not updates:
        return config
    return replace(config, **updates)  # type: ignore[arg-type]


def _emit(report: Report, fmt: str, out: Path | None, *, quiet: bool, allow_text: bool) -> None:
    if fmt == "text":
        if not allow_text:
            raise UsageError("this command does not write the text format")
        if out is not None:
            raise UsageError("pass --output md, html, or json when using --out")
        if not quiet:
            render_terminal(report, Console(highlight=False, emoji=False))
        return
    payload = {"md": render_markdown, "html": render_html, "json": render_json}[fmt](report)
    if out is not None:
        if out.exists() and out.is_dir():
            raise UsageError(f"--out is a directory: {out}")
        if not out.parent.exists():
            raise UsageError(f"directory does not exist: {out.parent}")
        out.write_text(payload, encoding="utf-8")
        if not quiet:
            err = Console(stderr=True, highlight=False, emoji=False)
            err.print(f"Wrote {fmt} report to {out}")
            render_terminal(report, err)
        return
    try:
        sys.stdout.write(payload)
    except BrokenPipeError:
        raise typer.Exit(code=0) from None


def _should_fail(report: Report, fail_on_error: bool) -> bool:
    if report.sources and all(source.status == "error" for source in report.sources):
        return True
    return fail_on_error and any(source.status == "error" for source in report.sources)


def _format(value: str) -> str:
    name = value.strip().lower()
    if name == "markdown":
        name = "md"
    if name not in {"text", "md", "html", "json"}:
        raise UsageError("--output must be text, md, html, or json")
    return name


def _names(value: str | None) -> set[str]:
    if not value:
        return set()
    return {part.strip().lower() for part in value.split(",") if part.strip()}


def _fail(message: str, *, code: int) -> NoReturn:
    safe = scrub_text(message, [])
    Console(stderr=True, highlight=False).print(f"[red]error:[/red] {escape(safe)}")
    raise typer.Exit(code=code)
