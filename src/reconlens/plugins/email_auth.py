"""MX, SPF, and DMARC, plus optional BIMI, MTA-STS, and TLS-RPT records.

All of this is DNS, except the MTA-STS policy file at
https://mta-sts.<domain>/.well-known/mta-sts.txt. It is fetched only when a
``v=STSv1`` TXT record exists.
"""

from __future__ import annotations

import asyncio
import re

from reconlens import dnsutil
from reconlens.context import RunContext
from reconlens.dnsutil import DnsAnswer
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.plugins.base import Source
from reconlens.textutil import clip

_SPF_DNS_LIMIT = 10
_SPF_DNS_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})
_MTA_STS_BODY_LIMIT = 20_000
_ALL = re.compile(r"(?:^|\s)(\+|-|~|\?)all(?:$|\s)", re.IGNORECASE)


class EmailAuthSource(Source):
    """Mail-authentication records for the domain of an email address."""

    name = "email-auth"
    description = "MX, SPF, and DMARC, plus BIMI, MTA-STS, and TLS-RPT when published"
    target_types = frozenset({TargetType.EMAIL})
    min_interval_seconds = 0.0
    display_order = 20
    homepage = "https://www.rfc-editor.org/rfc/rfc7208"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        domain = target.value.split("@", 1)[1]
        queries = (
            (domain, "MX"),
            (domain, "TXT"),
            (f"_dmarc.{domain}", "TXT"),
            (f"default._bimi.{domain}", "TXT"),
            (f"_mta-sts.{domain}", "TXT"),
            (f"_smtp._tls.{domain}", "TXT"),
        )
        answers = await asyncio.gather(
            *(dnsutil.resolve(name, rtype, ctx.timeout) for name, rtype in queries)
        )
        findings = findings_from_mail(self.name, domain, list(answers))
        if any(value.lower().startswith("v=stsv1") for value in _values(answers[4])):
            try:
                findings.extend(await self._mta_sts_policy(domain, ctx))
            except SourceError as exc:
                findings.append(
                    make_finding(
                        source=self.name,
                        category=Category.EMAIL,
                        title="MTA-STS policy not available",
                        value=f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                        detail=clip(
                            f"A v=STSv1 TXT record exists but the fetch failed: {exc}", 300
                        ),
                        severity=Severity.LOW,
                    )
                )
        return findings

    async def _mta_sts_policy(self, domain: str, ctx: RunContext) -> list[Finding]:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        response = await ctx.get_public(url, source=self.name, min_interval=0.0)
        return findings_from_mta_sts(self.name, url, response.status_code, response.text)


def findings_from_mail(source: str, domain: str, answers: list[DnsAnswer]) -> list[Finding]:
    """Interpret a fixed set of mail DNS answers. ``answers`` follows the query order."""

    if len(answers) != 6:
        raise SourceError("internal mail lookup did not return every answer")
    mx, txt, dmarc, bimi, mta_sts, tls_rpt = answers
    if all(item.error == "timeout" for item in answers):
        raise SourceError("mail DNS queries timed out")
    findings: list[Finding] = []
    findings.extend(_mx_findings(source, domain, mx))
    findings.extend(_spf_findings(source, _values(txt)))
    findings.extend(_dmarc_findings(source, domain, dmarc))
    findings.extend(_optional_txt(source, "BIMI", bimi))
    findings.extend(_optional_txt(source, "MTA-STS", mta_sts))
    findings.extend(_optional_txt(source, "TLS-RPT", tls_rpt))
    return findings


def count_spf_dns_mechanisms(record: str) -> int:
    """Count terms that cost a DNS lookup (RFC 7208 section 4.6.4). Nothing is resolved."""

    count = 0
    for term in record.split()[1:]:
        text = term.lstrip("+-~?").lower()
        if "=" in text.split(":", 1)[0]:
            name = text.split("=", 1)[0]
        else:
            name = re.split(r"[:/=]", text, maxsplit=1)[0]
        if name in _SPF_DNS_TERMS:
            count += 1
    return count


def findings_from_mta_sts(source: str, url: str, status: int, body: str) -> list[Finding]:
    """Interpret an MTA-STS policy response. A missing file is a finding, not an error."""

    if status == 404:
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="MTA-STS policy not found",
                value=url,
                detail="A v=STSv1 TXT record exists but the policy file returned HTTP 404.",
                severity=Severity.LOW,
                source_url=url,
            )
        ]
    if status >= 400:
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="MTA-STS policy not available",
                value=url,
                detail=f"The policy file returned HTTP {status}.",
                severity=Severity.LOW,
                source_url=url,
            )
        ]
    fields: dict[str, list[str]] = {}
    for line in body[:_MTA_STS_BODY_LIMIT].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        if key in {"mode", "mx", "max_age"} and value.strip():
            fields.setdefault(key, []).append(value.strip())
    titles = {"mode": "MTA-STS mode", "mx": "MTA-STS mx", "max_age": "MTA-STS max_age"}
    findings = [
        make_finding(
            source=source,
            category=Category.EMAIL,
            title=titles[key],
            value=clip(value, 200),
            source_url=url,
        )
        for key in ("mode", "mx", "max_age")
        for value in fields.get(key, [])[:10]
    ]
    if not findings:
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="MTA-STS policy empty",
                value=url,
                detail="The policy file has no mode, mx, or max_age fields.",
                severity=Severity.LOW,
                source_url=url,
            )
        )
    return findings


def _values(answer: DnsAnswer) -> list[str]:
    if answer.error is not None:
        return []
    return [value.strip() for value in answer.values if value.strip()]


def _mx_findings(source: str, domain: str, answer: DnsAnswer) -> list[Finding]:
    if answer.error == "timeout":
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="MX query timed out",
                value=domain,
                severity=Severity.LOW,
            )
        ]
    if answer.error == "nxdomain":
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="Mail domain does not resolve",
                value=domain,
                severity=Severity.LOW,
            )
        ]
    values = _values(answer)
    if not values:
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="No MX records",
                value=domain,
                detail="There is no MX record. Delivery may fall back to an A or AAAA record.",
                severity=Severity.LOW,
            )
        ]
    findings: list[Finding] = []
    for value in values:
        if _is_null_mx(value):
            findings.append(
                make_finding(
                    source=source,
                    category=Category.EMAIL,
                    title="Null MX",
                    value="0 .",
                    detail="This domain announces that it does not accept mail (RFC 7505).",
                )
            )
            continue
        shown = value[:-1].strip() if value.endswith(".") else value
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="MX",
                value=shown,
            )
        )
    return findings


def _is_null_mx(value: str) -> bool:
    compact = value.replace(" ", "").lower()
    return compact in {"0.", "0"}


def _spf_findings(source: str, records: list[str]) -> list[Finding]:
    spf = [record for record in records if record.lower().startswith("v=spf1")]
    if not spf:
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="SPF record not found",
                value="none",
                detail="The domain publishes no v=spf1 TXT record.",
                severity=Severity.LOW,
            )
        ]
    findings: list[Finding] = []
    if len(spf) > 1:
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="Multiple SPF records",
                value=str(len(spf)),
                detail="A domain is expected to publish one SPF record. Extra records can be a permerror.",
                severity=Severity.MEDIUM,
            )
        )
    for record in spf:
        title, severity, detail = _describe_spf(record)
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title=title,
                value=record,
                detail=detail,
                severity=severity,
            )
        )
        lookups = count_spf_dns_mechanisms(record)
        if lookups > _SPF_DNS_LIMIT:
            findings.append(
                make_finding(
                    source=source,
                    category=Category.EMAIL,
                    title="SPF top-level DNS mechanisms exceed 10",
                    value=str(lookups),
                    detail=(
                        "RFC 7208 allows 10 DNS-based mechanisms. This counts only terms "
                        "written in the record itself. Includes were not resolved, so the "
                        "real total can be higher."
                    ),
                    severity=Severity.LOW,
                )
            )
    return findings


def _describe_spf(record: str) -> tuple[str, Severity, str]:
    match = None
    for candidate in _ALL.finditer(record):
        match = candidate
    if match is None:
        return (
            "SPF has no terminal all mechanism",
            Severity.LOW,
            "The record does not include an all mechanism.",
        )
    qualifier = match.group(1)
    if qualifier == "+":
        return (
            "SPF allows any sender",
            Severity.MEDIUM,
            "The record uses +all, so it does not restrict envelope senders.",
        )
    if qualifier == "-":
        return ("SPF rejects unmatched senders", Severity.INFO, "The record uses -all.")
    if qualifier == "~":
        return (
            "SPF soft-fails unmatched senders",
            Severity.INFO,
            "The record uses ~all.",
        )
    return (
        "SPF does not enforce a result",
        Severity.LOW,
        "The record uses ?all, which is a neutral result.",
    )


def _dmarc_findings(source: str, domain: str, answer: DnsAnswer) -> list[Finding]:
    if answer.error == "timeout":
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="DMARC query timed out",
                value=f"_dmarc.{domain}",
                severity=Severity.LOW,
            )
        ]
    records = [value for value in _values(answer) if value.lower().startswith("v=dmarc1")]
    if not records:
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="DMARC record not found",
                value=f"_dmarc.{domain}",
                detail="Receivers have no published DMARC policy for this domain.",
                severity=Severity.LOW,
            )
        ]
    findings: list[Finding] = []
    if len(records) > 1:
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title="Multiple DMARC records",
                value=str(len(records)),
                detail="A domain is expected to publish one DMARC record.",
                severity=Severity.MEDIUM,
            )
        )
    tags = _tags(records[0])
    policy = tags.get("p", "").lower()
    if policy == "reject":
        title, severity = "DMARC policy is reject", Severity.INFO
        detail = "Unaligned mail is rejected when receivers honor the record."
    elif policy == "quarantine":
        title, severity = "DMARC policy is quarantine", Severity.INFO
        detail = "Unaligned mail is quarantined when receivers honor the record."
    elif policy == "none":
        title, severity = "DMARC policy is none", Severity.LOW
        detail = "The domain asks for reports and does not ask receivers to reject mail."
    else:
        title, severity = "DMARC policy is missing", Severity.LOW
        detail = "The record does not include a p= tag."
    findings.append(
        make_finding(
            source=source,
            category=Category.EMAIL,
            title=title,
            value=records[0],
            detail=detail,
            severity=severity,
        )
    )
    return findings


def _optional_txt(source: str, title: str, answer: DnsAnswer) -> list[Finding]:
    if answer.error == "timeout":
        return [
            make_finding(
                source=source,
                category=Category.EMAIL,
                title=f"{title} query timed out",
                value=answer.name,
                severity=Severity.LOW,
            )
        ]
    findings: list[Finding] = []
    for value in _values(answer):
        findings.append(
            make_finding(
                source=source,
                category=Category.EMAIL,
                title=title,
                value=value,
                detail="Published as DNS TXT.",
            )
        )
    return findings


def _tags(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    return tags
