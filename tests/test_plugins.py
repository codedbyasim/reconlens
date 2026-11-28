"""Source behavior with mocked DNS and HTTP."""

from __future__ import annotations

import contextlib
import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from reconlens import dnsutil
from reconlens.dnsutil import DnsAnswer
from reconlens.errors import SourceError
from reconlens.models import Finding, Severity, Target, TargetType
from reconlens.plugins.abuseipdb import AbuseIpdbSource
from reconlens.plugins.crtsh import findings_from_ct, names_from_ct
from reconlens.plugins.dns_records import DnsSource, findings_from_dns
from reconlens.plugins.email_auth import (
    EmailAuthSource,
    count_spf_dns_mechanisms,
    findings_from_mail,
)
from reconlens.plugins.gravatar import GravatarSource, gravatar_hash
from reconlens.plugins.hibp import HibpSource
from reconlens.plugins.http_headers import findings_from_headers
from reconlens.plugins.ip_geo import IpGeoSource
from reconlens.plugins.rdap_whois import RdapSource
from reconlens.plugins.robots_security import summarize_robots, summarize_security_txt
from reconlens.plugins.shodan import ShodanSource
from reconlens.plugins.ssl_cert import fetch_peer_certificate, findings_from_cert
from reconlens.plugins.urlscan import UrlscanSource
from reconlens.plugins.username_sites import (
    Site,
    UsernameSource,
    build_site_url,
    classify_site,
    load_sites,
)
from reconlens.plugins.virustotal import VirusTotalSource
from reconlens.plugins.wayback import findings_from_cdx
from tests.conftest import make_context


def test_dns_findings_shape() -> None:
    answers = [
        DnsAnswer("example.com", "A", ["93.184.216.34"], None),
        DnsAnswer("example.com", "AAAA", [], "noanswer"),
        DnsAnswer("example.com", "CNAME", [], "noanswer"),
        DnsAnswer("example.com", "MX", ["0 ."], None),
        DnsAnswer("example.com", "NS", ["a.iana-servers.net."], None),
        DnsAnswer("example.com", "TXT", ["v=spf1 -all"], None),
        DnsAnswer("example.com", "SOA", [], "noanswer"),
        DnsAnswer("example.com", "CAA", [], "timeout"),
    ]
    findings = findings_from_dns("dns", "example.com", answers)
    values = {item.title: item.value for item in findings}
    assert values["A"] == "93.184.216.34"
    assert values["NS"] == "a.iana-servers.net"
    assert any(item.title == "DNS timeout" for item in findings)


def test_resolve_sync_reads_a_fake_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResolver:
        def __init__(self) -> None:
            self.timeout = 0.0
            self.lifetime = 0.0

        def resolve(
            self,
            name: str,
            rtype: str,
            lifetime: float | None = None,
            search: bool | None = None,
        ) -> list[object]:
            del name, lifetime, search
            if rtype == "A":

                class Rdata:
                    def __str__(self) -> str:
                        return "192.0.2.10"

                return [Rdata()]
            raise dnsutil.dns.resolver.NoAnswer()

    monkeypatch.setattr(dnsutil.dns.resolver, "Resolver", FakeResolver)
    found = dnsutil.resolve_sync("example.com", "A", 1)
    assert found.values == ["192.0.2.10"]
    empty = dnsutil.resolve_sync("example.com", "MX", 1)
    assert empty.error == "noanswer"


def test_mail_auth_interpretation() -> None:
    answers = [
        DnsAnswer("example.com", "MX", ["10 mail.example.com.", "0 ."], None),
        DnsAnswer("example.com", "TXT", ["v=spf1 include:_spf.example.com -all", "hello"], None),
        DnsAnswer(
            "_dmarc.example.com", "TXT", ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"], None
        ),
        DnsAnswer("default._bimi.example.com", "TXT", [], "noanswer"),
        DnsAnswer("_mta-sts.example.com", "TXT", ["v=STSv1; id=20261122"], None),
        DnsAnswer("_smtp._tls.example.com", "TXT", [], "noanswer"),
    ]
    findings = findings_from_mail("email-auth", "example.com", answers)
    titles = [item.title for item in findings]
    assert "MX" in titles
    assert "Null MX" in titles
    assert "SPF rejects unmatched senders" in titles
    assert "DMARC policy is none" in titles
    assert any(item.title == "MTA-STS" for item in findings)
    weak = findings_from_mail(
        "email-auth",
        "example.com",
        [
            DnsAnswer("example.com", "MX", [], "noanswer"),
            DnsAnswer("example.com", "TXT", ["v=spf1 +all"], None),
            DnsAnswer("_dmarc.example.com", "TXT", [], "noanswer"),
            DnsAnswer("bimi", "TXT", [], "noanswer"),
            DnsAnswer("mta", "TXT", [], "noanswer"),
            DnsAnswer("tls", "TXT", [], "noanswer"),
        ],
    )
    assert any(item.severity is Severity.MEDIUM and "any sender" in item.title for item in weak)
    assert any(item.title == "DMARC record not found" for item in weak)


def test_crtsh_filters_to_the_domain() -> None:
    rows = [
        {"name_value": "example.com\nwww.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "other.test"},
    ]
    assert names_from_ct("example.com", rows) == ["example.com", "www.example.com"]


def test_headers_and_policy_files() -> None:
    findings = findings_from_headers(
        "http-headers",
        200,
        "https://example.com/",
        {"strict-transport-security": "max-age=10", "server": "Example"},
    )
    assert any(
        item.title == "Security headers not set" and item.severity is Severity.LOW
        for item in findings
    )
    assert any(item.title == "Server" and item.value == "Example" for item in findings)
    robots = summarize_robots(
        "robots",
        "https://example.com/robots.txt",
        "User-agent: *\nDisallow: /private\nSitemap: https://example.com/sitemap.xml\n",
    )
    assert any(item.title == "Sitemap" for item in robots)
    expired = summarize_security_txt(
        "robots",
        "https://example.com/.well-known/security.txt",
        "Contact: mailto:security@example.com\nExpires: 2000-01-01T00:00:00Z\n",
    )
    assert any(item.title == "Expires" and item.severity is Severity.LOW for item in expired)


def test_wayback_rows() -> None:
    rows = [
        ["timestamp", "original", "statuscode", "mimetype"],
        ["20200102030405", "http://example.com/", "200", "text/html"],
        ["20200102030406", "http://user:pass@example.com/", "200", "text/html"],
    ]
    findings = findings_from_cdx("wayback", "example.com", rows)
    assert (
        findings[0].source_url == "https://web.archive.org/web/20200102030405/http://example.com/"
    )
    assert "2020-01-02" in (findings[0].detail or "")
    assert all("user:pass" not in item.value for item in findings)


def test_username_catalog_and_classification() -> None:
    sites, skipped = load_sites()
    assert skipped == 0
    assert len(sites) >= 8
    site = sites[0]
    url = build_site_url(site.url_template, "octocat")
    assert url.startswith("https://")
    assert "{username}" not in url
    with pytest.raises(SourceError):
        build_site_url("https://{username}.example.com/", "octocat")
    probe = Site(
        "Example",
        "https://example.com/{username}",
        (200,),
        (404,),
        missing_body_contains="no such user",
    )
    assert classify_site(probe, 200, "No Such User") == "not_found"
    assert classify_site(probe, 200, "profile") == "found"
    assert classify_site(probe, 500, "") == "inconclusive"


def test_gravatar_hash_is_md5_of_lowercased_email() -> None:
    assert gravatar_hash(" User@Example.com ") == gravatar_hash("user@example.com")
    assert len(gravatar_hash("user@example.com")) == 32


def _certificate() -> x509.Certificate:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0xABC)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.DNSName("www.example.com")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def test_certificate_findings_include_names() -> None:
    findings = findings_from_cert("ssl", "example.com", _certificate(), "hostname mismatch")
    titles = [item.title for item in findings]
    assert "Certificate verification failed" in titles
    assert "SAN" in titles
    assert any(item.value == "example.com" for item in findings)


def test_local_tls_server_can_be_read(tmp_path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=2))
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)
    port = listener.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                client, _addr = listener.accept()
            except OSError:
                return
            with (
                contextlib.suppress(ssl.SSLError, OSError),
                server_context.wrap_socket(client, server_side=True) as tls,
            ):
                tls.settimeout(2)
                with contextlib.suppress(TimeoutError, ssl.SSLError, OSError):
                    tls.recv(16)
            client.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        parsed, problem = fetch_peer_certificate("127.0.0.1", 5, port=port)
    finally:
        listener.close()
        thread.join(timeout=5)
    assert parsed.subject.rfc4514_string()
    assert problem


async def test_http_plugins(ctx: object, mocked: object) -> None:
    from reconlens.context import RunContext

    assert isinstance(ctx, RunContext)
    router = mocked
    router.get(url__regex=r"https://rdap\.org/domain/example\.com").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200,
            json={
                "ldhName": "EXAMPLE.COM",
                "status": ["active"],
                "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
                "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"}],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
            },
        )
    )
    rdap = await RdapSource().run(Target("example.com", TargetType.DOMAIN, "example.com"), ctx)
    assert any(item.title == "Registrar" and item.value == "Example Registrar" for item in rdap)

    router.get("https://ipwho.is/1.1.1.1").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "city": "Brisbane",
                "region": "Queensland",
                "country": "Australia",
                "country_code": "AU",
                "latitude": -27.4,
                "longitude": 153.0,
                "connection": {"asn": 13335, "org": "Cloudflare", "isp": "Cloudflare"},
                "timezone": {"id": "Australia/Brisbane"},
            },
        )
    )
    geo = await IpGeoSource().run(Target("1.1.1.1", TargetType.IP, "1.1.1.1"), ctx)
    assert any(item.title == "ASN" and item.value == "AS13335" for item in geo)
    private = await IpGeoSource().run(Target("10.0.0.1", TargetType.IP, "10.0.0.1"), ctx)
    assert private[0].title == "Geolocation skipped"

    digest = gravatar_hash("user@example.com")
    router.get(url__regex=rf"https://www\.gravatar\.com/avatar/{digest}.*").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(404)
    )
    avatar = await GravatarSource().run(
        Target("user@example.com", TargetType.EMAIL, "user@example.com"), ctx
    )
    assert avatar[0].value == "not present"


async def test_keyed_plugins_do_not_leak_the_key(mocked: object) -> None:
    secret = "test-key-value"
    keys = {
        "VIRUSTOTAL_API_KEY": secret,
        "ABUSEIPDB_API_KEY": secret,
        "URLSCAN_API_KEY": secret,
        "SHODAN_API_KEY": secret,
        "HIBP_API_KEY": secret,
    }
    async with httpx.AsyncClient(trust_env=False) as client:
        ctx = make_context(client, keys=keys)
        router = mocked
        router.get(url__regex=r"https://www\.virustotal\.com/api/v3/domains/example\.com").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 1,
                                "harmless": 10,
                            },
                            "reputation": 4,
                        }
                    }
                },
            )
        )
        vt = await VirusTotalSource().run(
            Target("example.com", TargetType.DOMAIN, "example.com"), ctx
        )
        router.get("https://api.abuseipdb.com/api/v2/check").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(
                200,
                json={"data": {"abuseConfidenceScore": 80, "totalReports": 3, "isp": "Example"}},
            )
        )
        abuse = await AbuseIpdbSource().run(Target("1.1.1.1", TargetType.IP, "1.1.1.1"), ctx)
        router.get(url__startswith="https://urlscan.io/api/v1/search/").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(200, json={"results": []})
        )
        scan = await UrlscanSource().run(
            Target("example.com", TargetType.DOMAIN, "example.com"), ctx
        )
        router.get(url__regex=r"https://api\.shodan\.io/dns/domain/example\.com.*").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(200, json={"subdomains": ["www", "mail"]})
        )
        passive = await ShodanSource().run(
            Target("example.com", TargetType.DOMAIN, "example.com"), ctx
        )
        router.get(url__regex=r"https://haveibeenpwned\.com/api/v3/breachedaccount/.*").mock(  # type: ignore[attr-defined]
            return_value=httpx.Response(404)
        )
        breach = await HibpSource().run(
            Target("user@example.com", TargetType.EMAIL, "user@example.com"), ctx
        )
    blob = repr((vt, abuse, scan, passive, breach))
    assert secret not in blob
    assert any(item.value == "AS13335" or item.title == "VirusTotal analysis" for item in vt)
    assert any(item.severity is Severity.HIGH for item in abuse)
    assert any("did not submit" in (item.detail or "") for item in scan)
    assert any(item.value == "www.example.com" for item in passive)
    assert breach[0].title == "No HIBP breaches"


async def test_dns_source_uses_resolver(ctx: object, monkeypatch: pytest.MonkeyPatch) -> None:
    from reconlens.context import RunContext

    assert isinstance(ctx, RunContext)

    async def fake_resolve(name: str, rtype: str, timeout: float) -> DnsAnswer:
        del timeout
        if rtype == "A":
            return DnsAnswer(name, rtype, ["192.0.2.1"], None)
        return DnsAnswer(name, rtype, [], "noanswer")

    monkeypatch.setattr(dnsutil, "resolve", fake_resolve)
    findings = await DnsSource().run(Target("example.com", TargetType.DOMAIN, "example.com"), ctx)
    assert any(item.title == "A" and item.value == "192.0.2.1" for item in findings)


async def test_username_source_stops_after_429(
    ctx: object, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reconlens.context import RunContext

    assert isinstance(ctx, RunContext)
    sites = [
        Site("One", "https://example.com/u/{username}", (200,), (404,)),
        Site("Two", "https://example.org/u/{username}", (200,), (404,)),
    ]
    monkeypatch.setattr(
        "reconlens.plugins.username_sites.load_sites",
        lambda: (sites, 0),
    )
    monkeypatch.setattr(UsernameSource, "min_interval_seconds", 0.0)
    router = mocked
    router.get("https://example.com/u/octocat").mock(return_value=httpx.Response(429))  # type: ignore[attr-defined]
    findings = await UsernameSource().run(Target("octocat", TargetType.USERNAME, "octocat"), ctx)
    assert findings[0].value == "inconclusive"
    assert findings[1].value == "inconclusive"
    assert "429" in (findings[1].detail or "")


def test_dnssec_records_present_and_absent() -> None:
    present = findings_from_dns(
        "dns",
        "example.com",
        [
            DnsAnswer("example.com", "DS", ["12345 13 2 ABCDEF"], None),
            DnsAnswer("example.com", "DNSKEY", ["257 3 13 KEY"], None),
        ],
    )
    assert {item.title for item in present} == {"DS", "DNSKEY"}
    absent = findings_from_dns(
        "dns",
        "example.com",
        [
            DnsAnswer("example.com", "A", ["192.0.2.1"], None),
            DnsAnswer("example.com", "DS", [], "noanswer"),
            DnsAnswer("example.com", "DNSKEY", [], "noanswer"),
        ],
    )
    dnssec = [item for item in absent if item.title == "No DNSSEC records"]
    assert len(dnssec) == 1
    assert dnssec[0].severity is Severity.INFO


def test_spf_mechanism_count() -> None:
    assert count_spf_dns_mechanisms("v=spf1 include:a.test include:b.test -all") == 2
    assert count_spf_dns_mechanisms("v=spf1 ip4:192.0.2.0/24 a mx:x.test ~all") == 2
    assert count_spf_dns_mechanisms("v=spf1 redirect=_spf.test") == 1
    many = "v=spf1 " + " ".join(f"include:s{n}.test" for n in range(11)) + " +all"
    assert count_spf_dns_mechanisms(many) == 11


def _mail_answers(spf: str) -> list[DnsAnswer]:
    return [
        DnsAnswer("example.com", "MX", [], "noanswer"),
        DnsAnswer("example.com", "TXT", [spf], None),
        DnsAnswer("_dmarc.example.com", "TXT", [], "noanswer"),
        DnsAnswer("bimi", "TXT", [], "noanswer"),
        DnsAnswer("mta", "TXT", [], "noanswer"),
        DnsAnswer("tls", "TXT", [], "noanswer"),
    ]


def test_spf_many_mechanisms_finding_is_additional() -> None:
    many = "v=spf1 " + " ".join(f"include:s{n}.test" for n in range(11)) + " +all"
    findings = findings_from_mail("email-auth", "example.com", _mail_answers(many))
    titles = [item.title for item in findings]
    assert "SPF allows any sender" in titles
    flagged = [item for item in findings if item.title == "SPF has many DNS mechanisms"]
    assert flagged[0].value == "11"
    assert flagged[0].severity is Severity.LOW
    few = findings_from_mail(
        "email-auth", "example.com", _mail_answers("v=spf1 include:a.test -all")
    )
    assert all(item.title != "SPF has many DNS mechanisms" for item in few)


async def _run_email(ctx: object, monkeypatch: pytest.MonkeyPatch, sts: bool) -> list[Finding]:
    from reconlens.context import RunContext

    assert isinstance(ctx, RunContext)

    async def fake_resolve(name: str, rtype: str, timeout: float) -> DnsAnswer:
        del timeout
        if sts and name.startswith("_mta-sts."):
            return DnsAnswer(name, rtype, ["v=STSv1; id=1"], None)
        return DnsAnswer(name, rtype, [], "noanswer")

    monkeypatch.setattr(dnsutil, "resolve", fake_resolve)
    target = Target("user@example.com", TargetType.EMAIL, "user@example.com")
    return await EmailAuthSource().run(target, ctx)


async def test_mta_sts_policy_fetched(
    ctx: object, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked.get("https://mta-sts.example.com/.well-known/mta-sts.txt").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(
            200, text="version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
        )
    )
    findings = await _run_email(ctx, monkeypatch, True)
    got = {item.title: item.value for item in findings if item.title.startswith("MTA-STS ")}
    assert got == {
        "MTA-STS mode": "enforce",
        "MTA-STS mx": "mail.example.com",
        "MTA-STS max_age": "86400",
    }


async def test_mta_sts_policy_404_is_a_finding(
    ctx: object, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    mocked.get("https://mta-sts.example.com/.well-known/mta-sts.txt").mock(  # type: ignore[attr-defined]
        return_value=httpx.Response(404)
    )
    findings = await _run_email(ctx, monkeypatch, True)
    assert any(item.title == "MTA-STS policy not found" for item in findings)


async def test_mta_sts_not_fetched_without_txt(
    ctx: object, mocked: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = await _run_email(ctx, monkeypatch, False)
    assert all("MTA-STS" not in item.title for item in findings)


def test_crtsh_issuer_summary() -> None:
    rows = [
        {"name_value": "a.example.com", "issuer_name": "C=US, O=Let's Encrypt, CN=R3"},
        {
            "name_value": "b.example.com\nc.example.com",
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
        },
        {"name_value": "d.example.com", "issuer_name": "C=US, O=Other CA, CN=X"},
        {"name_value": "elsewhere.test", "issuer_name": "C=US, O=Ignored, CN=Z"},
    ]
    findings = findings_from_ct("crtsh", "example.com", rows)
    issuers = {item.value: item.detail for item in findings if item.title == "Issuer"}
    assert issuers == {
        "C=US, O=Let's Encrypt, CN=R3": "3 names",
        "C=US, O=Other CA, CN=X": "1 names",
    }
    assert sum(1 for item in findings if item.title == "Certificate name") == 4
