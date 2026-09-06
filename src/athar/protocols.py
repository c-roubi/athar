"""Cleartext application-protocol dissectors.

Line-oriented protocols carried in the clear expose session details and, often,
login credentials. This module reconstructs the useful parts of an FTP, SIP,
SMTP or POP3/IMAP conversation from its reassembled stream: who logged in, with
what username, and what they did (files transferred, calls placed, mail
envelopes). Each dissector returns a normalised session dict with an optional
``credentials`` list that feeds the plaintext-credentials detector.

Everything here is text protocol parsing on unencrypted streams; encrypted
variants (FTPS, SIPS, SMTPS, IMAPS) are opaque and are never handled.
"""

from __future__ import annotations

import base64
from typing import Any


def dissect_stream(data: bytes, sport: int, dport: int) -> dict[str, Any] | None:
    """Dispatch a reassembled stream to a protocol dissector by port/shape."""
    ports = {sport, dport}
    if 21 in ports:
        return dissect_ftp_session(data)
    if 5060 in ports:
        return dissect_sip(data)
    if ports & {25, 587}:
        return dissect_smtp(data)
    if 110 in ports:
        return dissect_pop3(data)
    if 143 in ports:
        return dissect_imap(data)
    if ports & {67, 68}:
        return dissect_dhcp(data)
    if 389 in ports:
        return dissect_ldap(data)
    if 22 in ports or data.startswith(b"SSH-"):
        return dissect_ssh(data)
    if 23 in ports:
        return dissect_telnet(data)
    if ports & {161, 162}:
        return dissect_snmp(data)
    # NTLM can appear on many ports (HTTP/SMB); detect by signature.
    if b"NTLMSSP\x00" in data:
        return dissect_ntlm(data)
    return None


def _lines(data: bytes, limit: int = 400) -> list[str]:
    try:
        text = data.decode("latin-1")
    except UnicodeDecodeError:
        return []
    return text.split("\r\n")[:limit]


def dissect_ftp_session(data: bytes) -> dict[str, Any] | None:
    """FTP control channel: login plus the commands issued (files, transfers)."""
    user = password = None
    commands: list[str] = []
    files: list[str] = []
    for line in _lines(data):
        verb = line[:5].upper()
        if verb == "USER ":
            user = line[5:].strip()
        elif verb == "PASS ":
            password = line[5:].strip()
        elif line[:5].upper() in ("RETR ", "STOR ", "DELE "):
            commands.append(line.strip())
            files.append(line[5:].strip())
        elif line[:4].upper() in ("CWD ", "MKD ", "LIST", "PWD "):
            commands.append(line.strip())
    if user is None and not commands:
        return None
    creds = [{"username": user, "password": password or ""}] if user is not None else []
    return {
        "protocol": "FTP", "service": "ftp",
        "details": {"username": user or "", "password": password or "",
                    "files": files[:50], "commands": commands[:50]},
        "credentials": creds,
    }


def dissect_sip(data: bytes) -> dict[str, Any] | None:
    """SIP signalling (VoIP): method, parties, user-agent, and auth username."""
    lines = _lines(data)
    if not lines or not any(x in (lines[0].split(" ", 1)[0])
                            for x in ("INVITE", "REGISTER", "SUBSCRIBE", "BYE", "ACK", "OPTIONS")):
        return None
    method = lines[0].split(" ", 1)[0]
    details: dict[str, Any] = {"method": method}
    creds: list[dict[str, str]] = []
    for line in lines[1:]:
        low = line.lower()
        if low.startswith("from:"):
            details["from"] = line[5:].strip()
        elif low.startswith("to:"):
            details["to"] = line[3:].strip()
        elif low.startswith("user-agent:"):
            details["user_agent"] = line[11:].strip()
        elif low.startswith(("authorization:", "proxy-authorization:")):
            username = _kv(line, "username")
            if username:
                creds.append({"username": username, "target": _kv(line, "realm")})
                details["auth_username"] = username
    return {"protocol": "SIP", "service": "sip", "details": details, "credentials": creds}


def dissect_smtp(data: bytes) -> dict[str, Any] | None:
    """SMTP: envelope (MAIL FROM / RCPT TO) and AUTH LOGIN/PLAIN credentials."""
    lines = _lines(data)
    joined = "\r\n".join(lines)
    if "MAIL FROM" not in joined.upper() and "AUTH " not in joined.upper() \
            and not joined.upper().startswith("EHLO") and not joined.upper().startswith("HELO"):
        return None
    details: dict[str, Any] = {"rcpt": []}
    creds: list[dict[str, str]] = []
    pending_login = False
    for line in lines:
        up = line.upper()
        if up.startswith("MAIL FROM"):
            details["from"] = line.split(":", 1)[-1].strip()
        elif up.startswith("RCPT TO"):
            details["rcpt"].append(line.split(":", 1)[-1].strip())
        elif up.startswith("AUTH LOGIN"):
            pending_login = True
        elif up.startswith("AUTH PLAIN"):
            user, pw = _decode_auth_plain(line[10:].strip())
            if user:
                creds.append({"username": user, "password": pw})
        elif pending_login and line.strip():
            decoded = _b64_text(line.strip())
            if not creds or "password" in creds[-1]:
                if decoded:
                    creds.append({"username": decoded})  # first line = username
            else:
                creds[-1]["password"] = decoded          # second line = password
                pending_login = False
    return {"protocol": "SMTP", "service": "smtp", "details": details, "credentials": creds}


def dissect_pop3(data: bytes) -> dict[str, Any] | None:
    return _user_pass(data, "POP3", "pop3")


def dissect_imap(data: bytes) -> dict[str, Any] | None:
    lines = _lines(data)
    for line in lines:
        parts = line.split()
        # e.g.  a1 LOGIN alice s3cret
        if len(parts) >= 4 and parts[1].upper() == "LOGIN":
            user, pw = parts[2].strip('"'), parts[3].strip('"')
            return {"protocol": "IMAP", "service": "imap",
                    "details": {"username": user, "password": pw},
                    "credentials": [{"username": user, "password": pw}]}
    return _user_pass(data, "IMAP", "imap")


def _user_pass(data: bytes, protocol: str, service: str) -> dict[str, Any] | None:
    user = password = None
    for line in _lines(data):
        parts = line.split(" ", 1)
        if len(parts) == 2 and parts[0].upper() == "USER":
            user = parts[1].strip()
        elif len(parts) == 2 and parts[0].upper() == "PASS":
            password = parts[1].strip()
    if user is None:
        return None
    return {"protocol": protocol, "service": service,
            "details": {"username": user, "password": password or ""},
            "credentials": [{"username": user, "password": password or ""}]}


def _kv(line: str, key: str) -> str:
    marker = f"{key}="
    if marker not in line:
        return ""
    rest = line.split(marker, 1)[1].lstrip()
    if rest.startswith('"'):
        return rest[1:].split('"', 1)[0]
    return rest.split(",", 1)[0].strip()


def _b64_text(token: str) -> str:
    try:
        return base64.b64decode(token, validate=True).decode("latin-1")
    except (ValueError, UnicodeDecodeError):
        return ""


def _decode_auth_plain(token: str) -> tuple[str, str]:
    # AUTH PLAIN is base64 of "\0username\0password".
    raw = _b64_text(token)
    parts = raw.split("\x00")
    if len(parts) >= 3:
        return parts[1], parts[2]
    return "", ""


def dissect_dhcp(payload: bytes) -> dict[str, Any] | None:
    """DHCP (UDP 67/68): recover hostname and requested/offered IP for inventory."""
    # BOOTP: op(1) htype(1) hlen(1) hops(1) xid(4) ... magic cookie 0x63825363
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    details: dict[str, Any] = {}
    mac = payload[28:34].hex(":")
    details["client_mac"] = mac
    # Walk options (code, len, value) after the magic cookie.
    i = 240
    msg_types = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK", 7: "RELEASE"}
    while i + 2 <= len(payload):
        code = payload[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        length = payload[i + 1]
        value = payload[i + 2:i + 2 + length]
        if code == 12:      # host name
            details["hostname"] = value.decode("latin-1", "replace")
        elif code == 50:    # requested IP
            details["requested_ip"] = ".".join(str(b) for b in value[:4])
        elif code == 53 and value:  # message type
            details["message_type"] = msg_types.get(value[0], str(value[0]))
        elif code == 60:    # vendor class
            details["vendor"] = value.decode("latin-1", "replace")
        i += 2 + length
    return {"protocol": "DHCP", "service": "dhcp", "details": details, "credentials": []}


def dissect_ntlm(data: bytes) -> dict[str, Any] | None:
    """NTLM: pull the domain/user/host from an NTLMSSP AUTHENTICATE message.

    NTLM is carried inside SMB and HTTP; the AUTHENTICATE (type 3) message
    reveals the account attempting to authenticate — high-value attribution.
    """
    idx = data.find(b"NTLMSSP\x00")
    if idx == -1:
        return None
    import struct
    msg = data[idx:]
    if len(msg) < 12:
        return None
    msg_type = struct.unpack("<I", msg[8:12])[0]
    details: dict[str, Any] = {"ntlmssp": {1: "NEGOTIATE", 2: "CHALLENGE",
                                           3: "AUTHENTICATE"}.get(msg_type, str(msg_type))}
    creds: list[dict[str, str]] = []
    if msg_type == 3 and len(msg) >= 64:
        def field(off: int) -> bytes:
            flen = struct.unpack("<H", msg[off:off + 2])[0]
            foff = struct.unpack("<I", msg[off + 4:off + 8])[0]
            return msg[foff:foff + flen] if foff + flen <= len(msg) else b""
        domain = field(28).decode("utf-16-le", "replace")
        user = field(36).decode("utf-16-le", "replace")
        host = field(44).decode("utf-16-le", "replace")
        if user:
            account = f"{domain}\\{user}" if domain else user
            details.update({"domain": domain, "user": user, "host": host})
            creds.append({"username": account})
    return {"protocol": "NTLM", "service": "ntlm", "details": details, "credentials": creds}


def dissect_ldap(data: bytes) -> dict[str, Any] | None:
    """LDAP (TCP 389): detect a bind request and recover the bind DN."""
    # LDAPMessage is a DER SEQUENCE (0x30); a bindRequest is application tag [0] (0x60).
    if len(data) < 8 or data[0] != 0x30:
        return None
    if data.find(b"\x60") == -1:  # no bindRequest application tag
        return None
    # Heuristically pull the printable bind DN (e.g. "cn=admin,dc=corp").
    import re
    text = data.decode("latin-1", "replace")
    m = re.search(r"(cn=|uid=|dc=)[\w.,=\- ]{2,120}", text, re.IGNORECASE)
    details: dict[str, Any] = {"operation": "bindRequest"}
    creds: list[dict[str, str]] = []
    if m:
        dn = m.group(0).strip()
        details["bind_dn"] = dn
        creds.append({"username": dn})
    return {"protocol": "LDAP", "service": "ldap", "details": details, "credentials": creds}


def dissect_ssh(data: bytes) -> dict[str, Any] | None:
    """SSH: capture the server/client version banner (product & version)."""
    if not data.startswith(b"SSH-"):
        return None
    banner = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")[:120]
    return {"protocol": "SSH", "service": "ssh",
            "details": {"banner": banner}, "credentials": []}


def dissect_telnet(data: bytes) -> dict[str, Any] | None:
    """Telnet: recover a typed login/password from the cleartext session."""
    # Strip Telnet IAC command bytes (0xFF ...) to get the readable text.
    text = bytes(b for b in data if b >= 0x20 or b in (0x0A, 0x0D)).decode("latin-1", "replace")
    low = text.lower()
    if "login:" not in low and "password:" not in low and "username:" not in low:
        return None
    creds: list[dict[str, str]] = []
    details: dict[str, Any] = {"protocol_detail": "telnet session"}
    import re
    m = re.search(r"(?:login|username):\s*([^\r\n]+)", text, re.IGNORECASE)
    if m:
        user = m.group(1).strip()
        details["username"] = user
        creds.append({"username": user})
    return {"protocol": "Telnet", "service": "telnet", "details": details, "credentials": creds}


def dissect_snmp(data: bytes) -> dict[str, Any] | None:
    """SNMP: recover the community string (v1/v2c) — often a weak secret."""
    # SNMP is a DER SEQUENCE; the community string is an OCTET STRING near the top.
    if len(data) < 8 or data[0] != 0x30:
        return None
    i = data.find(b"\x04")  # OCTET STRING tag
    if i == -1 or i + 2 >= len(data):
        return None
    length = data[i + 1]
    community = data[i + 2:i + 2 + length]
    if not community or any(b < 0x20 or b > 0x7E for b in community):
        return None
    return {"protocol": "SNMP", "service": "snmp",
            "details": {"community": community.decode("latin-1")},
            "credentials": [{"username": community.decode("latin-1")}]}
