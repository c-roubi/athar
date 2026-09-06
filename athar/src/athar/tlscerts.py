"""TLS certificate extraction from a handshake stream.

The server's certificate travels in the clear during the TLS handshake, even for
sessions athar can't decrypt. Reading it yields high-value facts: the subject and
issuer, the validity window, and whether the certificate is self-signed or
short-lived — both classic indicators of malware C2 infrastructure, which often
uses throwaway self-signed certs. This complements the JA3S fingerprint.

Parsing the X.509 structure uses the optional ``cryptography`` dependency when
present; without it, only the presence and size of the certificate are reported.
"""

from __future__ import annotations

import datetime as _dt
from typing import Any

try:
    from cryptography import x509
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def extract_certificates(stream: bytes) -> list[dict[str, Any]]:
    """Return parsed certificate records from a TLS handshake byte stream.

    Walks TLS records looking for a Certificate handshake message (type 11) and
    decodes the leaf certificate. Handles both TLS 1.2 and 1.3 message layouts.
    """
    der_list = _find_certificate_der(stream)
    return [_describe_cert(der) for der in der_list[:1]]  # leaf certificate only


def _find_certificate_der(stream: bytes) -> list[bytes]:
    """Locate the first DER certificate inside a Certificate handshake message."""
    pos, n = 0, len(stream)
    while pos + 5 <= n:
        ctype = stream[pos]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        body = stream[pos + 5:pos + 5 + length]
        pos += 5 + length
        if ctype != 0x16 or len(body) < 4:  # not a handshake record
            continue
        if body[0] != 0x0B:  # not a Certificate message
            continue
        return _parse_certificate_message(body)
    return []


def _parse_certificate_message(body: bytes) -> list[bytes]:
    """Extract DER blobs from a Certificate handshake message (TLS 1.2 or 1.3)."""
    # body: handshake type(1) + length(3) + payload
    p = 4
    # TLS 1.3 prepends a 1-byte certificate_request_context; skip it if present
    # by trying both offsets and taking whichever yields a sane list length.
    for ctx in (0, 1 + (body[4] if len(body) > 4 else 0)):
        q = p + ctx
        if q + 3 > len(body):
            continue
        list_len = int.from_bytes(body[q:q + 3], "big")
        q += 3
        if list_len == 0 or q + list_len > len(body) + 4:
            continue
        certs = []
        end = min(len(body), q + list_len)
        while q + 3 <= end:
            clen = int.from_bytes(body[q:q + 3], "big")
            q += 3
            if clen == 0 or q + clen > len(body):
                break
            certs.append(body[q:q + clen])
            q += clen + 0  # TLS 1.3 has per-cert extensions; leaf-only is enough
            if certs:
                return certs
        if certs:
            return certs
    return []


def _describe_cert(der: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"present": True, "der_bytes": len(der)}
    if not HAVE_CRYPTO:
        return info
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 - malformed cert, keep the size fact
        return info

    info["subject"] = _name(cert.subject)
    info["issuer"] = _name(cert.issuer)
    info["not_before"] = cert.not_valid_before_utc.isoformat()
    info["not_after"] = cert.not_valid_after_utc.isoformat()
    lifetime_days = (cert.not_valid_after_utc - cert.not_valid_before_utc).days
    info["lifetime_days"] = lifetime_days
    info["self_signed"] = cert.subject == cert.issuer
    now = _dt.datetime.now(_dt.timezone.utc)
    info["expired"] = cert.not_valid_after_utc < now
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["san"] = san.value.get_values_for_type(x509.DNSName)[:10]
    except x509.ExtensionNotFound:
        info["san"] = []
    return info


def _name(name: Any) -> str:
    try:
        from cryptography.x509.oid import NameOID
        cn = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            return str(cn[0].value)
    except Exception:  # noqa: BLE001
        pass
    return str(name.rfc4514_string())
