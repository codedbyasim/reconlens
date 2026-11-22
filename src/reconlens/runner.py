"""Run the sources that apply to one target. A failed source is a result, not a crash."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone

from reconlens.cache import FileCache
from reconlens.config import Config, default_cache_dir
from reconlens.context import RunContext
from reconlens.errors import SourceError, UsageError
from reconlens.http import build_client
from reconlens.models import (
    Finding,
    Report,
    SourceRun,
    Target,
    TargetType,
    with_id,
)
from reconlens.plugins.base import Source
from reconlens.plugins.registry import load_sources
from reconlens.redact import safe_error_message, scrub_text
from reconlens.textutil import clip


def choose_sources(
    sources: Sequence[Source],
    target_type: TargetType,
    only: set[str] | None,
    exclude: set[str],
) -> list[Source]:
    """Pick sources for this target. Unknown names are an error, not a silent skip."""

    by_name = {source.name: source for source in sources}
    unknown_exclude = sorted(exclude - set(by_name))
    if unknown_exclude:
        raise UsageError(
            "Unknown source(s): " + ", ".join(unknown_exclude) + ". Run `reconlens sources`."
        )
    if only is not None:
        unknown = sorted(only - set(by_name))
        if unknown:
            raise UsageError(
                "Unknown source(s): " + ", ".join(unknown) + ". Run `reconlens sources`."
            )
        unsupported = sorted(name for name in only if target_type not in by_name[name].target_types)
        if unsupported:
            raise UsageError(
                f"{', '.join(unsupported)} does not support {target_type.value} targets"
            )
    chosen = [
        source
        for source in sources
        if target_type in source.target_types
        and (only is None or source.name in only)
        and source.name not in exclude
    ]
    if not chosen:
        raise UsageError(f"No sources selected for {target_type.value} targets.")
    return chosen


async def collect(
    target: Target,
    *,
    config: Config,
    only: set[str] | None,
    exclude: set[str],
) -> Report:
    """Load plugins, query the ones that apply, and return a report."""

    sources, load_errors = load_sources()
    selected = choose_sources(sources, target.type, only, exclude)
    notices = [f"Could not load plugin {item.name}: {item.message}" for item in load_errors]
    cache: FileCache | None = None
    if config.cache_enabled:
        try:
            directory = config.cache_directory or default_cache_dir()
            cache = FileCache(directory, config.cache_ttl_seconds)
        except OSError as exc:
            notices.append(f"Cache disabled: {exc.strerror or exc.__class__.__name__}")
    secrets = [value for value in config.keys.values() if len(value) >= 8]
    async with build_client(config) as client:
        ctx = RunContext(
            client=client,
            config=config,
            timeout=config.timeout,
            cache=cache,
            secrets=secrets,
        )
        report = await execute(selected, target, ctx)
    report.notices = notices + report.notices
    return report


async def execute(sources: Sequence[Source], target: Target, ctx: RunContext) -> Report:
    """Query every source concurrently. Exceptions stay inside that source's result."""

    started = datetime.now(timezone.utc)
    runs = await asyncio.gather(*(_run_one(source, target, ctx) for source in sources))
    finished = datetime.now(timezone.utc)
    return Report(
        target=target,
        started_at=started,
        finished_at=finished,
        sources=list(runs),
        notices=list(ctx.notices),
    )


async def _run_one(source: Source, target: Target, ctx: RunContext) -> SourceRun:
    started = time.perf_counter()

    def finish(
        status: str,
        *,
        findings: list[Finding] | None = None,
        error: str | None = None,
        skip_reason: str | None = None,
        cached: bool = False,
    ) -> SourceRun:
        elapsed = int((time.perf_counter() - started) * 1000)
        if status not in {"ok", "error", "skipped"}:
            status = "error"
        return SourceRun(
            name=source.name,
            status=status,  # type: ignore[arg-type]
            duration_ms=elapsed,
            cached=cached,
            findings=findings or [],
            error=error,
            skip_reason=skip_reason,
        )

    if source.requires_api_key:
        env_name = source.api_key_env or ""
        if not ctx.api_key(env_name):
            reason = f"{env_name} is not set" if env_name else "API key is not set"
            return finish("skipped", skip_reason=reason)
    if ctx.cache is not None:
        try:
            cached = ctx.cache.get(source, target)
        except Exception as exc:
            cached = None
            ctx.notices.append(
                f"Cache read failed for {source.name}: {safe_error_message(exc, ctx.secrets)}"
            )
        if cached is not None:
            return finish(
                "ok", findings=[_finalize(item, source.name, ctx) for item in cached], cached=True
            )
    try:
        raw = await asyncio.wait_for(source.run(target, ctx), timeout=ctx.timeout)
    except TimeoutError:
        return finish("error", error=f"timed out after {ctx.timeout:.0f}s")
    except SourceError as exc:
        return finish("error", error=scrub_text(str(exc), ctx.secrets)[:400])
    except Exception as exc:
        return finish("error", error=safe_error_message(exc, ctx.secrets))
    if not isinstance(raw, list) or any(not isinstance(item, Finding) for item in raw):
        return finish("error", error="source returned an unexpected result")
    findings = [_finalize(item, source.name, ctx) for item in raw]
    if ctx.cache is not None:
        try:
            ctx.cache.set(source, target, findings)
        except Exception as exc:
            ctx.notices.append(
                f"Cache write failed for {source.name}: {safe_error_message(exc, ctx.secrets)}"
            )
    return finish("ok", findings=findings)


def _finalize(finding: Finding, source_name: str, ctx: RunContext) -> Finding:
    """Scrub secrets, clip long text, and force the finding to name its source."""

    scrubbed = replace(
        finding,
        source=source_name,
        title=scrub_text(finding.title, ctx.secrets),
        value=scrub_text(finding.value, ctx.secrets),
        detail=None if finding.detail is None else scrub_text(finding.detail, ctx.secrets),
        source_url=(
            None if finding.source_url is None else scrub_text(finding.source_url, ctx.secrets)
        ),
        data={key: scrub_text(item, ctx.secrets) for key, item in finding.data.items()},
    )
    value = clip(scrubbed.value, 1000) or "[redacted]"
    detail = None if scrubbed.detail is None else clip(scrubbed.detail, 1500) or None
    clipped = replace(
        scrubbed, title=clip(scrubbed.title, 180) or "Finding", value=value, detail=detail
    )
    return with_id(clipped)
