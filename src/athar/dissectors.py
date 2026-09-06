"""Application-layer dissectors.

Each dissector takes a transport payload and returns a small metadata dict, or
``None`` when the payload is not its protocol. They are intentionally shallow --
enough to answer "what was this host doing" (which name, which URL, which TLS
server) without a full protocol stack. All are tolerant of truncation.
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = ["dissect_dns", "dissect_http", "dissect_ftp",
           "dissect_tls_client_hello", "dissect_tls_server_hello", "ja3_from_client_hello"]


def dissect_dns(payload: bytes) -> dict[str, Any] | None:
    """Return the first question of a DNS message: ``{name, qtype}``."""
    if len(payload) < 12:
        return None
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount == 0:
        return None
    name, offset = _dns_name(payload, 12)
    if name is None or offset + 4 > len(payload):
        return None
    qtype = struct.unpack("!H", payload[offset:offset + 2])[0]
    qtypes = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
    flags = struct.unpack("!H", payload[2:4])[0]
    is_query = (flags & 0x8000) == 0  # QR bit: 0 = query, 1 = response
    return {"name": name, "qtype": qtypes.get(qtype, str(qtype)), "is_query": is_query}


def _dns_name(payload: bytes, offset: int) -> tuple[str | None, int]:
    labels: list[str] = []
    while offset < len(payload):
        length = payload[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0:  # compression pointer -- stop, we only need the name text
            return ".".join(labels) if labels else None, offset + 2
        offset += 1
        if offset + length > len(payload):
            return None, offset
        labels.append(payload[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return None, offset


_HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")


def dissect_http(payload: bytes) -> dict[str, Any] | None:
    """Return ``{method, host, path, credentials?}`` for an HTTP request."""
    if not payload.startswith(_HTTP_METHODS):
        return None
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except UnicodeDecodeError:
        return None
    lines = head.split("\r\n")
    request = lines[0].split(" ")
    if len(request) < 2:
        return None
    method, path = request[0], request[1]
    out: dict[str, Any] = {"method": method, "path": path, "host": ""}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        key, value = name.strip().lower(), value.strip()
        if key == "host":
            out["host"] = value
        elif key == "authorization" and value.lower().startswith("basic "):
            out["credentials"] = _decode_basic_auth(value[6:])
        elif key == "user-agent":
            out["user_agent"] = value
    return out


def _decode_basic_auth(token: str) -> str:
    import base64

    try:
        return base64.b64decode(token).decode("latin-1")
    except (ValueError, UnicodeDecodeError):
        return "(undecodable)"


def dissect_ftp(payload: bytes) -> dict[str, Any] | None:
    """Extract cleartext FTP credentials (``USER`` / ``PASS``) from a stream."""
    try:
        text = payload.decode("latin-1")
    except UnicodeDecodeError:
        return None
    user = password = None
    for line in text.split("\r\n"):
        upper = line[:5].upper()
        if upper == "USER ":
            user = line[5:].strip()
        elif upper == "PASS ":
            password = line[5:].strip()
    if user is None:
        return None
    return {"user": user, "password": password or ""}


def dissect_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    """Return ``{sni?, ja3, ja3_string}`` for a TLS ClientHello, if present."""
    hello = _parse_client_hello(payload)
    if hello is None:
        return None
    ja3_string, ja3 = _ja3(hello)
    out: dict[str, Any] = {"ja3": ja3, "ja3_string": ja3_string}
    if hello["sni"]:
        out["sni"] = hello["sni"]
    return out


def ja3_from_client_hello(payload: bytes) -> str | None:
    """Return just the JA3 MD5 fingerprint of a ClientHello, or ``None``."""
    hello = _parse_client_hello(payload)
    return _ja3(hello)[1] if hello else None


def dissect_tls_server_hello(payload: bytes) -> dict[str, Any] | None:
    """Return ``{ja3s, ja3s_string}`` for a TLS ServerHello, if present."""
    if len(payload) < 44 or payload[0] != 0x16 or payload[5] != 0x02:
        return None
    p, end = 9, len(payload)
    version = struct.unpack("!H", payload[p:p + 2])[0]
    p += 2 + 32  # server_version + random
    if p >= end:
        return None
    session_len = payload[p]
    p += 1 + session_len
    if p + 3 > end:
        return None
    cipher = struct.unpack("!H", payload[p:p + 2])[0]
    p += 3  # cipher (2) + compression method (1)

    extensions: list[int] = []
    if p + 2 <= end:
        ext_total = struct.unpack("!H", payload[p:p + 2])[0]
        p += 2
        ext_end = min(end, p + ext_total)
        while p + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4])
            extensions.append(etype)
            p += 4 + elen

    import hashlib
    exts = "-".join(str(e) for e in extensions if e not in _GREASE)
    ja3s_string = f"{version},{cipher},{exts}"
    return {"ja3s": hashlib.md5(ja3s_string.encode()).hexdigest(), "ja3s_string": ja3s_string}


# GREASE values (RFC 8701) are randomised placeholders and must be excluded
# from a JA3 so the fingerprint stays stable across connections.
_GREASE = {(v << 8) | v for v in (0x0A, 0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A,
                                  0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA)}


def _parse_client_hello(payload: bytes) -> dict[str, Any] | None:
    # TLS record: content_type(1)=22, version(2), length(2)
    if len(payload) < 9 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    p, end = 9, len(payload)  # skip record header (5) + handshake type/len (4)
    if p + 2 + 32 > end:
        return None
    version = struct.unpack("!H", payload[p:p + 2])[0]
    p += 2 + 32  # client_version + random

    if p >= end:
        return None
    session_len = payload[p]
    p += 1 + session_len

    if p + 2 > end:
        return None
    cipher_len = struct.unpack("!H", payload[p:p + 2])[0]
    p += 2
    if p + cipher_len > end:
        return None
    ciphers = [struct.unpack("!H", payload[p + i:p + i + 2])[0]
               for i in range(0, cipher_len, 2)]
    p += cipher_len

    if p >= end:
        return None
    comp_len = payload[p]
    p += 1 + comp_len

    extensions: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    sni: str | None = None
    if p + 2 <= end:
        ext_total = struct.unpack("!H", payload[p:p + 2])[0]
        p += 2
        ext_end = min(end, p + ext_total)
        while p + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[p:p + 4])
            p += 4
            edata = payload[p:p + elen]
            p += elen
            extensions.append(etype)
            if etype == 0x000A and len(edata) >= 2:      # supported_groups
                n = struct.unpack("!H", edata[:2])[0]
                curves = [struct.unpack("!H", edata[2 + i:4 + i])[0]
                          for i in range(0, min(n, len(edata) - 2), 2)]
            elif etype == 0x000B and len(edata) >= 1:    # ec_point_formats
                n = edata[0]
                point_formats = list(edata[1:1 + n])
            elif etype == 0x0000:                        # server_name
                sni = _tls_sni(edata)

    return {"version": version, "ciphers": ciphers, "extensions": extensions,
            "curves": curves, "point_formats": point_formats, "sni": sni}


def _ja3(hello: dict[str, Any]) -> tuple[str, str]:
    import hashlib

    def joined(values: list[int], drop_grease: bool = False) -> str:
        items = [v for v in values if not (drop_grease and v in _GREASE)]
        return "-".join(str(v) for v in items)

    ja3_string = ",".join((
        str(hello["version"]),
        joined(hello["ciphers"], drop_grease=True),
        joined(hello["extensions"], drop_grease=True),
        joined(hello["curves"], drop_grease=True),
        joined(hello["point_formats"]),
    ))
    return ja3_string, hashlib.md5(ja3_string.encode()).hexdigest()


def _tls_sni(ext: bytes) -> str | None:
    if len(ext) < 5:
        return None
    name_len = struct.unpack("!H", ext[3:5])[0]
    host = ext[5:5 + name_len]
    return host.decode("ascii", "replace") if host else None
