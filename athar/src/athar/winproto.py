"""Windows/enterprise binary-protocol dissectors.

The east-west protocols attackers use to move laterally — RDP, SMB, Kerberos —
are where a compromise shows itself inside a network. These dissectors read just
enough of each protocol's opening exchange to record the session facts an
investigator needs: that an RDP session was negotiated (and any cookie/username),
that SMB mapped a share (especially the hidden admin shares C$/ADMIN$), or that a
Kerberos ticket was requested. They don't decrypt anything — they read the
cleartext negotiation that precedes encryption.

Each returns a normalised session dict compatible with :mod:`athar.protocols`.
"""

from __future__ import annotations

from typing import Any


def dissect_binary(data: bytes, sport: int, dport: int) -> dict[str, Any] | None:
    """Dispatch a reassembled stream to a binary-protocol dissector.

    Tries the port first, then falls back to content signatures so a service
    deliberately run on a non-standard port (an evasion tactic) is still
    recognised.
    """
    ports = {sport, dport}
    if 3389 in ports:
        return dissect_rdp(data)
    if ports & {445, 139}:
        return dissect_smb(data)
    if 88 in ports:
        return dissect_kerberos(data)
    # Content-based fallback: identify the protocol regardless of port.
    return dissect_rdp(data) or dissect_smb(data)


def dissect_rdp(data: bytes) -> dict[str, Any] | None:
    """RDP: the X.224 Connection Request that opens every session.

    The cookie ``mstshash=<user>`` in the connection request often carries the
    username the client last logged in as — a useful attribution artefact.
    """
    # TPKT header: version 3, reserved 0. RDP always starts with it.
    if len(data) < 11 or data[0] != 0x03 or data[1] != 0x00:
        return None
    details: dict[str, Any] = {"protocol_detail": "X.224 connection request"}
    marker = b"Cookie: mstshash="
    if marker in data:
        tail = data.split(marker, 1)[1]
        user = tail.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        details["cookie_user"] = user
    # Detect a negotiation request for TLS/CredSSP (security protocol byte).
    if b"\x01\x00\x08\x00" in data[:60]:
        details["negotiation"] = "requested"
    return {"protocol": "RDP", "service": "rdp", "details": details, "credentials": []}


def dissect_smb(data: bytes) -> dict[str, Any] | None:
    """SMB/SMB2: protocol version, and any tree connect to a share."""
    smb1 = b"\xffSMB"
    smb2 = b"\xfeSMB"
    idx1 = data.find(smb1)
    idx2 = data.find(smb2)
    if idx2 == -1 and idx1 == -1:
        return None
    version = "SMB2/3" if (idx2 != -1 and (idx1 == -1 or idx2 < idx1)) else "SMB1"
    details: dict[str, Any] = {"version": version}

    shares = _smb_shares(data)
    if shares:
        details["shares"] = shares
        admin = [s for s in shares if s.rstrip("\\").upper().endswith(("C$", "ADMIN$", "IPC$"))
                 or s.upper().rstrip("\\").split("\\")[-1] in ("C$", "ADMIN$")]
        if admin:
            details["admin_shares"] = admin
    return {"protocol": "SMB", "service": "smb", "details": details, "credentials": []}


def _smb_shares(data: bytes) -> list[str]:
    """Recover UNC share paths (\\\\host\\share) from tree-connect requests."""
    shares: list[str] = []
    needle = "\\\\".encode("utf-16-le")  # UNC paths are UTF-16LE in SMB2
    start = 0
    while True:
        i = data.find(needle, start)
        if i == -1:
            break
        # read UTF-16LE until a null-ish terminator or non-path byte run
        end = i
        while end + 1 < len(data) and data[end + 1] == 0x00 and data[end] not in (0x00,):
            end += 2
        try:
            path = data[i:end].decode("utf-16-le", "ignore")
        except ValueError:
            path = ""
        if path.startswith("\\\\") and len(path) > 3:
            shares.append(path.split("\x00", 1)[0])
        start = i + 2
    # de-dup, keep order
    seen: set[str] = set()
    out = []
    for s in shares:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out[:20]


def dissect_kerberos(data: bytes) -> dict[str, Any] | None:
    """Kerberos: distinguish AS-REQ / TGS-REQ by application tag.

    A burst of TGS-REQs (ticket requests) for service principals is the network
    signature of Kerberoasting; recording the message type lets a detector count
    them.
    """
    # Kerberos over TCP is length-prefixed (4 bytes) then a DER APPLICATION tag.
    if len(data) < 6:
        return None
    tag = data[4]
    kinds = {0x6A: "AS-REQ", 0x6B: "AS-REP", 0x6C: "TGS-REQ", 0x6D: "TGS-REP"}
    # Some stacks omit the length prefix; check both positions.
    kind = kinds.get(tag) or kinds.get(data[0])
    if kind is None:
        return None
    return {"protocol": "Kerberos", "service": "kerberos",
            "details": {"message_type": kind}, "credentials": []}
