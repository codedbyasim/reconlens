"""Passive DNS records. Search domains from resolv.conf are not applied."""

from __future__ import annotations

import asyncio

from reconlens import dnsutil
from reconlens.context import RunContext
from reconlens.dnsutil import DnsAnswer
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.plugins.base import Source

RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")


class DnsSource(Source):
    """Authoritative-looking answers from the system resolver, one query per type."""

    name = "dns"
    description = "DNS records: A, AAAA, CNAME, MX, NS, TXT, SOA, and CAA"
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 0.0
    display_order = 10
    homepage = "https://www.rfc-editor.org/rfc/rfc1035"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        answers = await asyncio.gather(
            *(dnsutil.resolve(target.value, rtype, ctx.timeout) for rtype in RECORD_TYPES)
        )
        return findings_from_dns(self.name, target.value, list(answers))


def findings_from_dns(source: str, domain: str, answers: list[DnsAnswer]) -> list[Finding]:
    """Turn resolver answers into findings. Timeouts of every type raise."""

    if answers and all(item.error == "timeout" for item in answers):
        raise SourceError("DNS queries timed out")
    findings: list[Finding] = []
    missing_name = any(item.rtype == "A" and item.error == "nxdomain" for item in answers) and any(
        item.rtype == "NS" and item.error == "nxdomain" for item in answers
    )
    if missing_name:
        findings.append(
            make_finding(
                source=source,
                category=Category.DNS,
                title="Domain does not resolve",
                value=domain,
                detail="The resolver returned NXDOMAIN for both A and NS.",
                severity=Severity.LOW,
            )
        )
    timed_out = [item.rtype for item in answers if item.error == "timeout"]
    if timed_out and len(timed_out) != len(answers):
        findings.append(
            make_finding(
                source=source,
                category=Category.DNS,
                title="DNS timeout",
                value=", ".join(timed_out),
                detail="Those record types did not answer in time. Records that did are listed.",
                severity=Severity.LOW,
            )
        )
    for item in answers:
        if item.error is not None:
            continue
        for value in item.values:
            shown = _present(item.rtype, value)
            if not shown:
                continue
            findings.append(
                make_finding(
                    source=source,
                    category=Category.DNS,
                    title=item.rtype,
                    value=shown,
                )
            )
    if not findings:
        findings.append(
            make_finding(
                source=source,
                category=Category.DNS,
                title="No DNS records",
                value=domain,
                detail="The resolver returned no records for the queried types.",
            )
        )
    return findings


def _present(rtype: str, value: str) -> str:
    text = value.strip()
    if rtype == "MX" and text.replace(" ", "") in {"0.", "0"}:
        return "0 ."
    if rtype != "TXT" and text.endswith("."):
        return text[:-1].strip()
    return text
