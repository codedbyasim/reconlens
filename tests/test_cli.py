"""CLI wiring. HTTP, DNS, and TLS are mocked."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from reconlens import dnsutil
from reconlens.cli import app
from reconlens.dnsutil import DnsAnswer
from reconlens.errors import SourceError
from reconlens.models import (
    Report,
    Severity,
    SourceRun,
    Target,
    TargetType,
    make_finding,
)
from reconlens.plugins.username_sites import Site, UsernameSource
from reconlens.reports.json_report import render_json

runner = CliRunner()


def test_help_states_the_passive_limit() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "does not scan ports" in result.stdout
    assert "authorized" in result.stdout.lower()
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0
    assert version.stdout.strip().startswith("reconlens ")


def test_sources_lists_keyless_and_keyed_plugins() -> None:
    result = runner.invoke(app, ["sources"])
    assert result.exit_code == 0
    assert "dns" in result.stdout
    assert "virustotal" in result.stdout
    assert "VIRUSTOTAL_API_KEY" in result.stdout
    assert "needs key" in result.stdout


def test_bad_target_exits_2() -> None:
    result = runner.invoke(app, ["domain", "https://example.com"])
    assert result.exit_code == 2
    assert "bare domain" in result.stderr.lower() or "bare domain" in result.stdout.lower()


def test_bad_output_format_exits_2() -> None:
    result = runner.invoke(app, ["domain", "example.com", "--output", "pdf"])
    assert result.exit_code == 2


def _patch_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_resolve(name: str, rtype: str, timeout: float) -> DnsAnswer:
        del timeout
        if rtype == "A":
            return DnsAnswer(name, rtype, ["93.184.216.34"], None)
        if rtype == "NS":
            return DnsAnswer(name, rtype, ["a.iana-servers.net."], None)
        if rtype == "MX":
            return DnsAnswer(name, rtype, ["0 ."], None)
        if rtype == "TXT" and name.startswith("_dmarc."):
            return DnsAnswer(name, rtype, ["v=DMARC1; p=reject"], None)
        if rtype == "TXT":
            return DnsAnswer(name, rtype, ["v=spf1 -all"], None)
        return DnsAnswer(name, rtype, [], "noanswer")

    monkeypatch.setattr(dnsutil, "resolve", fake_resolve)


def _patch_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch(host: str, timeout: float, *, port: int = 443) -> object:
        del host, timeout, port
        raise SourceError("tls disabled in this test")

    monkeypatch.setattr("reconlens.plugins.ssl_cert.fetch_peer_certificate", fake_fetch)


def _mock_domain(router: object) -> None:
    rdap = {
        "ldhName": "EXAMPLE.COM",
        "status": ["active"],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
    }
    router.get(url__regex=r"https://rdap\.org/domain/example\.com").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, json=rdap)
    )
    router.get(url__startswith="https://crt.sh/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200,
            json=[{"name_value": "example.com\nwww.example.com"}, {"name_value": "nope.test"}],
        )
    )
    router.get("https://example.com/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200,
            headers={"strict-transport-security": "max-age=31536000"},
            text="ok",
        )
    )
    router.get("https://example.com/robots.txt").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, text="User-agent: *\nDisallow: /private\n")
    )
    router.get("https://example.com/.well-known/security.txt").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, text="Contact: mailto:security@example.com\n")
    )
    router.get(url__startswith="https://web.archive.org/").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200,
            json=[
                ["timestamp", "original", "statuscode", "mimetype"],
                ["20240101000000", "http://example.com/", "200", "text/html"],
            ],
        )
    )


def test_domain_json_survives_one_failing_source(
    mocked: object,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_dns(monkeypatch)
    _patch_tls(monkeypatch)
    _mock_domain(mocked)
    out = tmp_path / "report.json"
    result = runner.invoke(
        app,
        ["domain", "example.com", "--output", "json", "--out", str(out), "--quiet"],
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(out.read_text(encoding="utf-8"))
    by_name = {item["name"]: item for item in payload["sources"]}
    assert by_name["dns"]["status"] == "ok"
    assert any(item["value"] == "93.184.216.34" for item in by_name["dns"]["findings"])
    assert by_name["ssl"]["status"] == "error"
    assert by_name["crtsh"]["status"] == "ok"
    assert by_name["virustotal"]["status"] == "skipped"
    assert "www.example.com" in {item["value"] for item in by_name["crtsh"]["findings"]}
    assert "nope.test" not in {item["value"] for item in by_name["crtsh"]["findings"]}


def test_ip_skips_geolocation_for_private_addresses(mocked: object) -> None:
    mocked.get(url__regex=r"https://rdap\.org/ip/10\.0\.0\.1").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, json={"handle": "NET-10", "name": "PRIVATE"})
    )
    result = runner.invoke(app, ["ip", "10.0.0.1", "--output", "json", "--quiet"])
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    geo = next(item for item in payload["sources"] if item["name"] == "ip-geo")
    assert geo["findings"][0]["title"] == "Geolocation skipped"


def test_email_and_username(
    mocked: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_dns(monkeypatch)
    mocked.get(url__regex=r"https://www\.gravatar\.com/avatar/.*").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, content=b"\x89PNG")
    )
    email = runner.invoke(app, ["email", "User@Example.com", "--output", "json", "--quiet"])
    assert email.exit_code == 0, email.stdout + email.stderr
    body = json.loads(email.stdout)
    assert body["target"]["value"] == "user@example.com"
    names = {item["name"]: item for item in body["sources"]}
    assert names["gravatar"]["findings"][0]["value"] == "present"
    assert names["hibp"]["status"] == "skipped"
    assert any(
        item["title"] == "DMARC policy is reject" for item in names["email-auth"]["findings"]
    )

    site = Site("GitHub", "https://github.com/{username}", (200,), (404,))
    monkeypatch.setattr("reconlens.plugins.username_sites.load_sites", lambda: ([site], 0))
    monkeypatch.setattr(UsernameSource, "min_interval_seconds", 0.0)
    mocked.get("https://github.com/octocat").mock(return_value=httpx.Response(404))  # type: ignore[attr-defined]
    username = runner.invoke(app, ["username", "octocat", "--output", "json", "--quiet"])
    assert username.exit_code == 0, username.stdout + username.stderr
    found = json.loads(username.stdout)
    assert found["sources"][0]["findings"][0]["value"] == "not_found"


def test_report_command_renders_markdown(
    tmp_path: Path, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dns(monkeypatch)
    _patch_tls(monkeypatch)
    _mock_domain(mocked)
    saved = tmp_path / "report.json"
    markdown = tmp_path / "report.md"
    first = runner.invoke(
        app,
        ["domain", "example.com", "--output", "json", "--out", str(saved), "--quiet"],
    )
    assert first.exit_code == 0, first.stdout + first.stderr
    second = runner.invoke(
        app,
        ["report", "--input", str(saved), "--output", "md", "--out", str(markdown)],
    )
    assert second.exit_code == 0, second.stdout + second.stderr
    text = markdown.read_text(encoding="utf-8")
    assert "example.com" in text
    assert "93.184.216.34" in text


def test_csv_and_jsonl_outputs_via_scan_and_report(
    tmp_path: Path, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_dns(monkeypatch)
    _patch_tls(monkeypatch)
    _mock_domain(mocked)
    saved = tmp_path / "report.json"
    first = runner.invoke(
        app, ["domain", "example.com", "--output", "json", "--out", str(saved), "--quiet"]
    )
    assert first.exit_code == 0, first.stdout + first.stderr
    csv_path = tmp_path / "report.csv"
    csv_result = runner.invoke(
        app, ["report", "--input", str(saved), "--output", "csv", "--out", str(csv_path)]
    )
    assert csv_result.exit_code == 0, csv_result.stdout + csv_result.stderr
    assert csv_path.read_text(encoding="utf-8").startswith('"source","category"')
    jsonl = runner.invoke(app, ["report", "--input", str(saved), "--output", "jsonl"])
    assert jsonl.exit_code == 0, jsonl.stdout + jsonl.stderr
    rows = [json.loads(line) for line in jsonl.stdout.splitlines()]
    assert rows and all(row["target"] == "example.com" for row in rows)


def test_scan_accepts_csv_output(mocked: object) -> None:
    mocked.get(url__regex=r"https://rdap\.org/ip/10\.0\.0\.1").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(200, json={"handle": "NET-10", "name": "PRIVATE"})
    )
    result = runner.invoke(app, ["ip", "10.0.0.1", "--output", "csv", "--quiet"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert result.stdout.startswith('"source","category","severity"')
    again = runner.invoke(app, ["ip", "10.0.0.1", "--output", "jsonl", "--quiet"])
    assert again.exit_code == 0
    assert json.loads(again.stdout.splitlines()[0])["target_type"] == "ip"


# --- batch, diff, doctor ---


def _report(target_value: str, findings: list[tuple[str, str, Severity]]) -> Report:
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    items = [
        make_finding(source="s", category="c", title=t, value=v, severity=sev, timestamp=now)
        for t, v, sev in findings
    ]
    run = SourceRun(name="s", status="ok", duration_ms=1, cached=False, findings=items)
    target = Target(value=target_value, type=TargetType.DOMAIN, original=target_value)
    return Report(target=target, started_at=now, finished_at=now, sources=[run])


def test_batch_skips_comments_and_reports_invalid_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def fake_collect(target: Target, **kwargs: object) -> Report:
        del kwargs
        return _report(target.value, [("T", "v", Severity.INFO)])

    monkeypatch.setattr("reconlens.cli.collect", fake_collect)
    path = tmp_path / "targets.txt"
    path.write_text("# comment\nexample.com\nhttps://bad.example\nexample.org\n")
    result = runner.invoke(
        app, ["batch", str(path), "--type", "domain", "--delay", "0", "--output", "json"]
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert [item["target"]["value"] for item in payload] == ["example.com", "example.org"]
    assert result.stderr.count("notice:") == 1
    assert "line 3" in result.stderr
    assert "Running 2 domain target(s)" in result.stderr


def test_batch_rejects_unknown_type_and_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "t.txt"
    path.write_text("example.com\n")
    assert runner.invoke(app, ["batch", str(path), "--type", "host"]).exit_code == 2
    assert (
        runner.invoke(app, ["batch", str(tmp_path / "no.txt"), "--type", "domain"]).exit_code == 2
    )


def test_batch_exits_nonzero_without_valid_targets(tmp_path: Path) -> None:
    path = tmp_path / "t.txt"
    path.write_text("# only a comment\nhttps://bad.example\n")
    result = runner.invoke(app, ["batch", str(path), "--type", "domain", "--delay", "0"])
    assert result.exit_code == 2
    assert "no valid targets" in result.stderr


def test_batch_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "t.txt"
    path.write_text("example.com\n" * 1001)
    result = runner.invoke(app, ["batch", str(path), "--type", "domain"])
    assert result.exit_code == 2
    assert "limited to" in result.stderr


def test_diff_detail_changed(tmp_path: Path) -> None:
    def one(detail: str) -> Report:
        rep = _report("example.com", [("Issuer", "CA", Severity.INFO)])
        old = rep.sources[0].findings[0]
        rep.sources[0].findings[0] = dataclasses.replace(old, detail=detail)
        return rep

    before = _write(tmp_path / "a.json", one("3 names"))
    after = _write(tmp_path / "b.json", one("300 names"))
    result = runner.invoke(app, ["diff", "--before", before, "--after", after, "--output", "json"])
    body = json.loads(result.stdout)
    assert [row["title"] for row in body["detail_changed"]] == ["Issuer"]
    assert body["severity_changed"] == []


def _write(path: Path, report: Report) -> str:
    path.write_text(render_json(report), encoding="utf-8")
    return str(path)


def test_diff_added_removed_and_severity_changed(tmp_path: Path) -> None:
    before = _write(
        tmp_path / "a.json",
        _report(
            "example.com",
            [("Gone", "x", Severity.INFO), ("Same", "y", Severity.INFO)],
        ),
    )
    after = _write(
        tmp_path / "b.json",
        _report("example.com", [("New", "z", Severity.LOW), ("Same", "y", Severity.INFO)]),
    )
    result = runner.invoke(app, ["diff", "--before", before, "--after", after, "--output", "json"])
    assert result.exit_code == 0, result.stdout + result.stderr
    body = json.loads(result.stdout)
    assert [row["title"] for row in body["added"]] == ["New"]
    assert [row["title"] for row in body["removed"]] == ["Gone"]
    assert body["severity_changed"] == []
    text = runner.invoke(app, ["diff", "--before", before, "--after", after])
    assert "Added (1)" in text.stdout
    assert "Removed (1)" in text.stdout
    assert "Severity changed (0)" in text.stdout


def test_diff_severity_changed(tmp_path: Path) -> None:
    before = _write(tmp_path / "a.json", _report("example.com", [("T", "v", Severity.INFO)]))
    after = _write(tmp_path / "b.json", _report("example.com", [("T", "v", Severity.HIGH)]))
    result = runner.invoke(app, ["diff", "--before", before, "--after", after, "--output", "json"])
    assert result.exit_code == 0
    row = json.loads(result.stdout)["severity_changed"][0]
    assert (row["before"], row["after"]) == ("info", "high")


def test_diff_target_mismatch_and_unreadable_exit_2(tmp_path: Path) -> None:
    one = _write(tmp_path / "a.json", _report("example.com", []))
    two = _write(tmp_path / "b.json", _report("example.org", []))
    assert runner.invoke(app, ["diff", "--before", one, "--after", two]).exit_code == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert runner.invoke(app, ["diff", "--before", one, "--after", str(bad)]).exit_code == 2
    missing = str(tmp_path / "missing.json")
    assert runner.invoke(app, ["diff", "--before", one, "--after", missing]).exit_code == 2


def test_doctor_never_prints_key_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = "dummy-secret-" + "x" * 40
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", secret)
    monkeypatch.delenv("RECONLENS_CONFIG", raising=False)
    monkeypatch.setenv("RECONLENS_CACHE_DIR", str(tmp_path / "cache"))
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0, result.stdout + result.stderr
    assert secret not in result.stdout
    assert secret not in result.stderr
    assert "VIRUSTOTAL_API_KEY: key set" in result.stdout
    assert "writable" in result.stdout


def test_doctor_exits_2_for_missing_or_invalid_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("RECONLENS_CONFIG", str(tmp_path / "missing.toml"))
    assert runner.invoke(app, ["doctor"]).exit_code == 2
    bad = tmp_path / "bad.toml"
    bad.write_text("not = [valid")
    monkeypatch.setenv("RECONLENS_CONFIG", str(bad))
    assert runner.invoke(app, ["doctor"]).exit_code == 2
