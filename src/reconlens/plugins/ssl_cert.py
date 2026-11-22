"""Read the certificate a host presents on TCP port 443. No other ports are opened."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID

from reconlens.context import RunContext
from reconlens.errors import SourceError
from reconlens.models import Category, Finding, Severity, Target, TargetType, make_finding
from reconlens.plugins.base import Source


class SslCertSource(Source):
    """A single TLS handshake to port 443, used only to read the certificate."""

    name = "ssl"
    description = "Certificate presented by a single TLS handshake to port 443"
    target_types = frozenset({TargetType.DOMAIN})
    min_interval_seconds = 0.0
    display_order = 40
    homepage = "https://www.rfc-editor.org/rfc/rfc8446"

    async def run(self, target: Target, ctx: RunContext) -> list[Finding]:
        cert, problem = await asyncio.to_thread(
            fetch_peer_certificate,
            target.value,
            min(ctx.timeout, 20.0),
        )
        return findings_from_cert(self.name, target.value, cert, problem)


def fetch_peer_certificate(
    host: str,
    timeout: float,
    *,
    port: int = 443,
) -> tuple[x509.Certificate, str | None]:
    """Return the peer certificate and, when verification failed, a short reason.

    Verification is attempted first. If it fails, a second handshake reads the
    certificate without treating it as trusted. That second handshake still
    talks only to port 443 of ``host``.
    """

    bounded = min(max(timeout, 1.0), 20.0)
    try:
        der = _handshake(host, bounded, port=port, verify=True)
        return _load(der), None
    except ssl.SSLCertVerificationError as exc:
        reason = str(getattr(exc, "verify_message", "") or exc.__class__.__name__)
        try:
            der = _handshake(host, bounded, port=port, verify=False)
        except (TimeoutError, OSError, ssl.SSLError) as inner:
            raise SourceError(
                "TLS handshake failed after certificate verification failed"
            ) from inner
        return _load(der), reason[:300]
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        raise SourceError(f"TLS handshake failed: {exc.__class__.__name__}") from None


def findings_from_cert(
    source: str,
    host: str,
    cert: x509.Certificate,
    verification_error: str | None,
) -> list[Finding]:
    """Describe subject, issuer, dates, and DNS names."""

    findings: list[Finding] = []
    if verification_error:
        findings.append(
            make_finding(
                source=source,
                category=Category.CERTIFICATE,
                title="Certificate verification failed",
                value=host,
                detail=verification_error,
                severity=Severity.MEDIUM,
            )
        )
    subject = _attr(cert.subject, NameOID.COMMON_NAME) or host
    findings.append(
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="Subject",
            value=subject,
        )
    )
    issuer_parts = [
        part
        for part in (
            _attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            _attr(cert.issuer, NameOID.COMMON_NAME),
        )
        if part
    ]
    if issuer_parts:
        findings.append(
            make_finding(
                source=source,
                category=Category.CERTIFICATE,
                title="Issuer",
                value=" / ".join(issuer_parts),
            )
        )
    not_before = _when(cert, end=False)
    not_after = _when(cert, end=True)
    now = datetime.now(timezone.utc)
    findings.append(
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="Not valid before",
            value=not_before.strftime("%Y-%m-%d"),
        )
    )
    if not_after < now:
        expiry_severity = Severity.MEDIUM
        expiry_detail = "This certificate has expired."
    elif (not_after - now).days <= 14:
        expiry_severity = Severity.LOW
        expiry_detail = "This certificate expires within 14 days."
    else:
        expiry_severity = Severity.INFO
        expiry_detail = None
    findings.append(
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="Not valid after",
            value=not_after.strftime("%Y-%m-%d"),
            detail=expiry_detail,
            severity=expiry_severity,
        )
    )
    serial = f"{cert.serial_number:x}"
    findings.append(
        make_finding(
            source=source,
            category=Category.CERTIFICATE,
            title="Serial",
            value=serial,
        )
    )
    for name in _dns_names(cert)[:40]:
        findings.append(
            make_finding(
                source=source,
                category=Category.CERTIFICATE,
                title="SAN",
                value=name,
            )
        )
    return findings


def _handshake(host: str, timeout: float, *, port: int, verify: bool) -> bytes:
    if verify:
        context = ssl.create_default_context()
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as sock,
        context.wrap_socket(sock, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not isinstance(der, bytes) or not der:
        raise SourceError("server did not present a certificate")
    return der


def _load(der: bytes) -> x509.Certificate:
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise SourceError("certificate could not be parsed") from exc


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    attributes = name.get_attributes_for_oid(oid)
    if not attributes:
        return ""
    return str(attributes[0].value).strip()


def _when(cert: x509.Certificate, *, end: bool) -> datetime:
    attr = "not_valid_after_utc" if end else "not_valid_before_utc"
    value = getattr(cert, attr, None)
    if not isinstance(value, datetime):
        value = cert.not_valid_after if end else cert.not_valid_before
    if not isinstance(value, datetime):
        raise SourceError("certificate dates could not be read")
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _dns_names(cert: x509.Certificate) -> list[str]:
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names = extension.value.get_values_for_type(x509.DNSName)
    return [str(name) for name in names]
