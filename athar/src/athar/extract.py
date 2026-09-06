"""Content extraction from cleartext HTTP streams.

For unencrypted HTTP, the reassembled byte stream contains the actual data that
moved: form fields, JSON payloads, and uploaded files. This reconstructs the
message body (honouring ``Content-Length`` and ``Transfer-Encoding: chunked``)
so an examiner can see *what* was sent, not just that a transfer happened. It
only ever applies to cleartext HTTP — TLS payloads are opaque and are never
touched.

Extracted bodies are capped and, for anything that isn't printable text, only a
hash, size and a short hex preview are kept: the point is evidentiary
attribution, not warehousing payloads.
"""

from __future__ import annotations

import hashlib
from typing import Any

_MAX_BODY = 8 << 20           # reconstruct up to 8 MiB of body per message
_TEXT_PREVIEW = 2048           # chars of text kept inline
_BIN_PREVIEW = 64             # bytes of a binary preview (shown as hex)

_HTTP_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH")
_RESPONSE = b"HTTP/"

# Public aliases for other modules that need to sniff HTTP framing.
HTTP_METHODS = _HTTP_METHODS
HTTP_RESPONSE = _RESPONSE


def extract_http_objects(stream: bytes) -> list[dict[str, Any]]:
    """Return the HTTP request/response messages carried by a cleartext stream.

    Each object is a dict with ``kind`` (``request``/``response``), start line
    fields, selected headers, and — when a body is present — its length, SHA-256,
    a content summary, and either a text or hex preview.
    """
    objects: list[dict[str, Any]] = []
    pos, n = 0, len(stream)
    while pos < n:
        head_end = stream.find(b"\r\n\r\n", pos)
        if head_end == -1:
            break
        header_blob = stream[pos:head_end]
        if not (header_blob.startswith(_HTTP_METHODS) or header_blob.startswith(_RESPONSE)):
            break
        try:
            header_text = header_blob.decode("latin-1")
        except UnicodeDecodeError:
            break

        lines = header_text.split("\r\n")
        headers = _parse_headers(lines[1:])
        body_start = head_end + 4
        body, consumed = _read_body(stream, body_start, headers)

        obj = _describe(lines[0], headers, body)
        if body:
            obj["body"] = body  # raw bytes, for carving (never serialised)
        objects.append(obj)

        if consumed <= 0:
            break
        pos = body_start + consumed
    return objects


def _safe_name(name: str, fallback: str) -> str:
    keep = "".join(c for c in name if c.isalnum() or c in "._- ").strip()
    return keep[:80] or fallback


def write_carved_files(carved: list[dict[str, Any]], outdir: str) -> list[dict[str, Any]]:
    """Write reconstructed bodies to *outdir* and return a hashed manifest.

    Each entry records the on-disk path, direction (upload/download), origin,
    content type, size and SHA-256 -- so carved artefacts join the chain of
    custody like any other output.
    """
    import pathlib

    base = pathlib.Path(outdir)
    base.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    for i, obj in enumerate(carved):
        body = obj.get("body")
        if not body:
            continue
        ext = ".txt" if obj.get("body_kind") == "text" else ".bin"
        stem = _safe_name(obj.get("filename", ""), f"object-{i:04d}")
        if "." not in stem:
            stem += ext
        path = base / f"{i:04d}_{stem}"
        path.write_bytes(body)
        manifest.append({
            "path": str(path),
            "filename": obj.get("filename", ""),
            "direction": obj.get("direction", ""),
            "origin": obj.get("origin", ""),
            "content_type": obj.get("content_type", ""),
            "bytes": len(body),
            "truncated": obj.get("truncated", False),
            "sha256": obj.get("body_sha256", ""),
        })
    return manifest


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return headers


def _read_body(stream: bytes, start: int, headers: dict[str, str]) -> tuple[bytes, int]:
    """Return ``(body, bytes_consumed_after_headers)`` for one message."""
    if headers.get("transfer-encoding", "").lower() == "chunked":
        return _read_chunked(stream, start)
    if "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError:
            return b"", 0
        length = max(0, min(length, _MAX_BODY))
        return stream[start:start + length], length
    return b"", 0  # no declared body (or connection-closed framing we don't guess)


def _read_chunked(stream: bytes, start: int) -> tuple[bytes, int]:
    body = bytearray()
    pos = start
    while pos < len(stream) and len(body) < _MAX_BODY:
        line_end = stream.find(b"\r\n", pos)
        if line_end == -1:
            break
        try:
            size = int(stream[pos:line_end].split(b";", 1)[0], 16)
        except ValueError:
            break
        pos = line_end + 2
        if size == 0:
            pos += 2  # trailing CRLF after the final chunk
            break
        body += stream[pos:pos + size]
        pos += size + 2  # chunk data + CRLF
    return bytes(body[:_MAX_BODY]), pos - start


def _describe(start_line: str, headers: dict[str, str], body: bytes) -> dict[str, Any]:
    is_response = start_line.startswith("HTTP/")
    obj: dict[str, Any] = {
        "kind": "response" if is_response else "request",
        "start_line": start_line,
        "content_type": headers.get("content-type", ""),
    }
    if not is_response:
        parts = start_line.split(" ")
        obj["method"] = parts[0] if parts else ""
        obj["path"] = parts[1] if len(parts) > 1 else ""
        obj["host"] = headers.get("host", "")
    if not body:
        return obj

    declared = _declared_length(headers)
    obj["body_bytes"] = len(body)
    obj["declared_bytes"] = declared if declared is not None else len(body)
    obj["truncated"] = declared is not None and declared > len(body)
    obj["body_sha256"] = hashlib.sha256(body).hexdigest()
    obj["filename"] = _filename(headers)
    text = _as_text(body)
    if text is not None:
        obj["body_kind"] = "text"
        obj["body_preview"] = text[:_TEXT_PREVIEW]
    else:
        obj["body_kind"] = "binary"
        obj["body_preview_hex"] = body[:_BIN_PREVIEW].hex()
    return obj


def _as_text(body: bytes) -> str | None:
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Reject bodies with control bytes (other than tab/newline/carriage return).
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text[:512]):
        return None
    return text


def _declared_length(headers: dict[str, str]) -> int | None:
    try:
        return int(headers["content-length"])
    except (KeyError, ValueError):
        return None


def _filename(headers: dict[str, str]) -> str:
    disp = headers.get("content-disposition", "")
    marker = "filename="
    if marker in disp:
        return disp.split(marker, 1)[1].strip().strip('"')
    return ""
