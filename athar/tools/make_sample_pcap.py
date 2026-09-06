"""Craft a small synthetic pcap that exercises every detector.

No third-party packet library: frames are built byte by byte. The scenario is a
small office LAN with one clean workstation and three problems -- a plaintext
login, an internal port scan, a beaconing host, and a DNS tunnel. Run it, then
point ``athar`` at the output.
"""

from __future__ import annotations

import base64
import random
import struct
import sys
from collections.abc import Sequence

random.seed(7)

R_MAC = bytes.fromhex("001a2b000001")   # router / gateway
MACS = {
    "192.168.1.1": R_MAC,
    "192.168.1.20": bytes.fromhex("001a2b0000aa"),
    "192.168.1.50": bytes.fromhex("001a2b0000bb"),
    "192.168.1.66": bytes.fromhex("001a2b0000cc"),
    "192.168.1.77": bytes.fromhex("001a2b0000dd"),
    "192.168.1.88": bytes.fromhex("001a2b0000ee"),
}


def ip_bytes(ip: str) -> bytes:
    return bytes(int(o) for o in ip.split("."))


def mac_of(ip: str) -> bytes:
    return MACS.get(ip, bytes.fromhex("aabbccddeeff"))


def eth(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    return mac_of(dst_ip) + mac_of(src_ip) + struct.pack("!H", 0x0800) + payload


def ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0x4000, 64, proto, 0)
    hdr += ip_bytes(src) + ip_bytes(dst)
    return hdr + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"", seq: int = 0,
        window: int = 65535) -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, window, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str, qtype: int = 1) -> bytes:
    q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return q


def http_get(host: str, path: str, auth: str | None = None) -> bytes:
    lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "User-Agent: LegacyClient/1.0"]
    if auth:
        token = base64.b64encode(auth.encode()).decode()
        lines.append(f"Authorization: Basic {token}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


def build() -> bytes:
    pkts: list[tuple[float, bytes]] = []
    t = 1_726_000_000.0

    def send_tcp(dt, src, dst, sport, dport, flags, payload=b"", seq=0):
        nonlocal t
        t += dt
        frame = eth(src, dst, ipv4(src, dst, 6, tcp(sport, dport, flags, payload, seq)))
        pkts.append((t, frame))

    def send_udp(dt, src, dst, sport, dport, payload):
        nonlocal t
        t += dt
        frame = eth(src, dst, ipv4(src, dst, 17, udp(sport, dport, payload)))
        pkts.append((t, frame))

    # 1) Clean workstation: DNS + HTTPS browsing.
    for host in ["cdn.example.com", "api.example.com", "www.example.com"]:
        send_udp(0.4, "192.168.1.50", "192.168.1.1", 51000, 53, dns_query(host))
        send_udp(0.05, "192.168.1.1", "192.168.1.50", 53, 51000, dns_query(host))
        send_tcp(0.1, "192.168.1.50", "93.184.216.34", 44001, 443, 0x02,
                 tls_client_hello(host))
        send_tcp(0.1, "93.184.216.34", "192.168.1.50", 443, 44001, 0x12)
        send_tcp(0.05, "93.184.216.34", "192.168.1.50", 443, 44001, 0x18,
                 tls_server_hello())

    # 2) Plaintext credentials to a legacy internal box.
    send_tcp(1.0, "192.168.1.50", "192.168.1.20", 44100, 80, 0x02)
    send_tcp(0.05, "192.168.1.20", "192.168.1.50", 80, 44100, 0x12)
    send_tcp(0.05, "192.168.1.50", "192.168.1.20", 44100, 80, 0x18,
             http_get("nas.local", "/admin/config", auth="admin:password123"))

    # 2b) Cleartext FTP login (USER/PASS) to a legacy file server.
    send_tcp(0.4, "192.168.1.50", "192.168.1.30", 44200, 21, 0x02)
    send_tcp(0.05, "192.168.1.30", "192.168.1.50", 21, 44200, 0x12)
    send_tcp(0.05, "192.168.1.50", "192.168.1.30", 44200, 21, 0x18,
             b"USER ftpadmin\r\n", seq=1)
    send_tcp(0.05, "192.168.1.50", "192.168.1.30", 44200, 21, 0x18,
             b"PASS Sup3rSecret\r\n", seq=16)

    # 2c) A large file uploaded in the clear over HTTP POST (exfiltration).
    stolen = (b"CONFIDENTIAL,ssn,salary\r\n"
              b"employee-records," + b"9" * 11 + b",120000\r\n") * 40000
    body = stolen[:1_300_000]
    post = (b"POST /upload HTTP/1.1\r\nHost: filedrop.example\r\n"
            b"Content-Type: text/csv\r\n"
            b"Content-Disposition: form-data; name=\"file\"; filename=\"payroll.csv\"\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    send_tcp(0.4, "192.168.1.55", "203.0.113.9", 44300, 80, 0x02)
    send_tcp(0.05, "203.0.113.9", "192.168.1.55", 80, 44300, 0x12)
    seq = 1
    for i in range(0, len(post), 1400):  # split the upload across many segments
        chunk = post[i:i + 1400]
        send_tcp(0.001, "192.168.1.55", "203.0.113.9", 44300, 80, 0x18, chunk, seq=seq)
        seq += len(chunk)

    # 2d) A file DOWNLOAD over cleartext HTTP (server -> client response body).
    dl_body = b"MZ\x90\x00\x03" + b"\x00" * 500 + b"this program cannot be run in DOS mode"
    get = b"GET /tools/agent.exe HTTP/1.1\r\nHost: mirror.example\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"agent.exe\"\r\n"
            b"Content-Length: " + str(len(dl_body)).encode() + b"\r\n\r\n" + dl_body)
    send_tcp(0.3, "192.168.1.60", "198.51.100.7", 44400, 80, 0x02)
    send_tcp(0.05, "198.51.100.7", "192.168.1.60", 80, 44400, 0x12)
    send_tcp(0.02, "192.168.1.60", "198.51.100.7", 44400, 80, 0x18, get, seq=1)
    send_tcp(0.05, "198.51.100.7", "192.168.1.60", 80, 44400, 0x18, resp, seq=1)

    # 2e) SIP REGISTER (VoIP) with a cleartext auth username.
    sip = (b"REGISTER sip:pbx.example SIP/2.0\r\n"
           b"From: <sip:1001@pbx.example>\r\nTo: <sip:1001@pbx.example>\r\n"
           b"User-Agent: Grandstream GXP2170\r\n"
           b"Authorization: Digest username=\"1001\", realm=\"pbx.example\", "
           b"nonce=\"abc\", response=\"deadbeef\"\r\n\r\n")
    send_tcp(0.3, "192.168.1.61", "192.168.1.5", 45100, 5060, 0x02)
    send_tcp(0.05, "192.168.1.5", "192.168.1.61", 5060, 45100, 0x12)
    send_tcp(0.02, "192.168.1.61", "192.168.1.5", 45100, 5060, 0x18, sip, seq=1)

    # 2f) SMTP with AUTH LOGIN (base64 username) and an envelope.
    import base64 as _b64
    smtp = (b"EHLO ws\r\nAUTH LOGIN\r\n" + _b64.b64encode(b"[email protected]") + b"\r\n"
            + _b64.b64encode(b"hunter2") + b"\r\n"
            b"MAIL FROM:<[email protected]>\r\nRCPT TO:<[email protected]>\r\n")
    send_tcp(0.3, "192.168.1.62", "203.0.113.25", 45200, 587, 0x02)
    send_tcp(0.05, "203.0.113.25", "192.168.1.62", 587, 45200, 0x12)
    send_tcp(0.02, "192.168.1.62", "203.0.113.25", 45200, 587, 0x18, smtp, seq=1)

    # 2g) Lateral movement: a compromised host reaches out over RDP/SMB to
    #     several internal machines, hits hidden admin shares, and Kerberoasts.
    import struct as _st

    def utf16(s: str) -> bytes:
        return s.encode("utf-16-le")

    attacker = "192.168.1.66"
    for i, victim in enumerate(["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13"]):
        # RDP connection request (TPKT + X.224) carrying an mstshash cookie
        rdp = (b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00"
               b"Cookie: mstshash=administrator\r\n" + b"\x01\x00\x08\x00\x03\x00\x00\x00")
        send_tcp(0.2, attacker, victim, 46000 + i, 3389, 0x02)
        send_tcp(0.02, victim, attacker, 3389, 46000 + i, 0x12)
        send_tcp(0.02, attacker, victim, 46000 + i, 3389, 0x18, rdp, seq=1)
        # SMB2 tree connect to the hidden ADMIN$ share
        smb = b"\x00\x00\x00\x60\xfeSMB" + b"\x00" * 60 + utf16(f"\\\\{victim}\\ADMIN$")
        send_tcp(0.02, attacker, victim, 47000 + i, 445, 0x02)
        send_tcp(0.02, victim, attacker, 445, 47000 + i, 0x12)
        send_tcp(0.02, attacker, victim, 47000 + i, 445, 0x18, smb, seq=1)

    # Kerberoasting: a burst of TGS-REQ to the domain controller
    for i in range(12):
        tgs = _st.pack(">I", 40) + b"\x6c" + b"\x00" * 40  # length-prefixed TGS-REQ tag
        send_tcp(0.02, attacker, "192.168.1.5", 48000 + i, 88, 0x02)
        send_tcp(0.01, "192.168.1.5", attacker, 88, 48000 + i, 0x12)
        send_tcp(0.01, attacker, "192.168.1.5", 48000 + i, 88, 0x18, tgs)

    # 2h) Evasion: RDP on a non-standard port, and egress to Tor / a C2 port.
    rdp_ns = (b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00"
              b"Cookie: mstshash=svc-backup\r\n" + b"\x01\x00\x08\x00")
    send_tcp(0.2, "192.168.1.66", "192.168.1.14", 46500, 4444, 0x02)
    send_tcp(0.02, "192.168.1.14", "192.168.1.66", 4444, 46500, 0x12)
    send_tcp(0.02, "192.168.1.66", "192.168.1.14", 46500, 4444, 0x18, rdp_ns, seq=1)
    # Tor ORPort egress from the beaconing implant
    send_tcp(0.2, "192.168.1.77", "185.220.101.5", 49500, 9001, 0x02)
    send_tcp(0.02, "185.220.101.5", "192.168.1.77", 9001, 49500, 0x12)

    # 2i) The C2 serves a self-signed, short-lived TLS certificate (if we can
    #     generate one) — a strong malware-infrastructure indicator.
    _der = _self_signed_der()
    if _der is not None:
        send_tcp(0.2, "192.168.1.77", "185.220.101.5", 49600, 443, 0x02,
                 tls_client_hello("update.evil-c2.net"))
        send_tcp(0.02, "185.220.101.5", "192.168.1.77", 443, 49600, 0x12)
        send_tcp(0.02, "185.220.101.5", "192.168.1.77", 443, 49600, 0x18,
                 tls_server_hello() + tls_certificate_record(_der), seq=1)

    # 2j) TCP health: a data retransmission, a zero-window stall, and a reset.
    payload = b"GET /health HTTP/1.1\r\nHost: intranet.local\r\n\r\n"
    send_tcp(0.1, "192.168.1.90", "192.168.1.20", 47700, 80, 0x02)
    send_tcp(0.02, "192.168.1.20", "192.168.1.90", 80, 47700, 0x12)
    send_tcp(0.02, "192.168.1.90", "192.168.1.20", 47700, 80, 0x18, payload, seq=1)
    send_tcp(0.30, "192.168.1.90", "192.168.1.20", 47700, 80, 0x18, payload, seq=1)  # retransmit
    # server advertises a zero window (receiver stalled)
    t += 0.02
    pkts.append((t, eth("192.168.1.20", "192.168.1.90",
                        ipv4("192.168.1.20", "192.168.1.90", 6,
                             tcp(80, 47700, 0x10, b"", seq=100, window=0)))))
    send_tcp(0.02, "192.168.1.20", "192.168.1.90", 80, 47700, 0x04)  # RST

    # 2k) DHCP inventory, an NTLM logon, and an LDAP bind.
    def send_udp(dt, src, dst, sp, dp, payload):
        nonlocal t
        t += dt
        pkts.append((t, eth(src, dst, ipv4(src, dst, 17, udp(sp, dp, payload)))))

    # DHCP REQUEST with a hostname (device inventory)
    bootp = (b"\x01\x01\x06\x00" + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 16
             + b"\x00\x1a\x2b\x00\x00\x99" + b"\x00" * 10 + b"\x00" * 192
             + b"\x63\x82\x53\x63"                       # magic cookie
             + b"\x35\x01\x03"                           # option 53: REQUEST
             + b"\x0c\x08" + b"WKS-1234"                 # option 12: hostname
             + b"\x32\x04\xc0\xa8\x01\x64"               # option 50: requested 192.168.1.100
             + b"\xff")
    send_udp(0.2, "192.168.1.100", "192.168.1.1", 68, 67, bootp)

    # NTLM AUTHENTICATE (type 3) carrying DOMAIN\user — over an SMB-ish stream
    def ntlm_type3(domain: str, user: str, host: str) -> bytes:
        d = domain.encode("utf-16-le")
        u = user.encode("utf-16-le")
        h = host.encode("utf-16-le")
        base = 64
        def fld(val, off):
            return _st.pack("<HHI", len(val), len(val), off)
        hdr = b"NTLMSSP\x00" + _st.pack("<I", 3)
        hdr += fld(b"", base) + fld(b"", base)                 # LM, NT (empty)
        hdr += fld(d, base) + fld(u, base + len(d)) + fld(h, base + len(d) + len(u))
        hdr += _st.pack("<HHI", 0, 0, base)                    # session key
        hdr += _st.pack("<I", 0)                               # flags
        return hdr + d + u + h
    send_tcp(0.2, "192.168.1.101", "192.168.1.20", 47800, 445, 0x02)
    send_tcp(0.02, "192.168.1.20", "192.168.1.101", 445, 47800, 0x12)
    send_tcp(0.02, "192.168.1.101", "192.168.1.20", 47800, 445, 0x18,
             b"\x00\x00\x00\x40\xfeSMB" + ntlm_type3("CORP", "jdoe", "WKS-1234"), seq=1)

    # LDAP bind request with a bind DN
    ldap = (b"\x30\x20\x02\x01\x01\x60\x1b\x02\x01\x03\x04\x10"
            + b"cn=admin,dc=corp")
    send_tcp(0.2, "192.168.1.102", "192.168.1.5", 47900, 389, 0x02)
    send_tcp(0.02, "192.168.1.5", "192.168.1.102", 389, 47900, 0x12)
    send_tcp(0.02, "192.168.1.102", "192.168.1.5", 47900, 389, 0x18, ldap, seq=1)

    # 2l) SSH banner, a cleartext Telnet login, and an SNMP community string.
    send_tcp(0.2, "192.168.1.103", "192.168.1.40", 48100, 22, 0x02)
    send_tcp(0.02, "192.168.1.40", "192.168.1.103", 22, 48100, 0x12)
    send_tcp(0.02, "192.168.1.40", "192.168.1.103", 22, 48100, 0x18,
             b"SSH-2.0-OpenSSH_9.6\r\n", seq=1)
    send_tcp(0.2, "192.168.1.104", "192.168.1.41", 48200, 23, 0x02)
    send_tcp(0.02, "192.168.1.41", "192.168.1.104", 23, 48200, 0x12)
    send_tcp(0.02, "192.168.1.104", "192.168.1.41", 48200, 23, 0x18,
             b"login: operator\r\npassword: cisco123\r\n", seq=1)
    # SNMP GET with the "public" community string (UDP 161)
    snmp = (b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01"
            b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
    send_udp(0.2, "192.168.1.105", "192.168.1.42", 48300, 161, snmp)

    # 3) Internal port scan from a compromised host.
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443,
                              445, 993, 995, 1433, 3306, 3389, 5900, 8080, 8443]):
        send_tcp(0.02, "192.168.1.66", "192.168.1.1", 40000 + i, port, 0x02)

    # 4) Beaconing to an external host every ~30s, with a telltale TLS fingerprint.
    for i in range(8):
        sport = 45000 + i  # each beacon is a fresh connection (distinct source port)
        send_tcp(30.0 + random.uniform(-1.5, 1.5), "192.168.1.77",
                 "185.220.101.5", sport, 443, 0x02)
        send_tcp(0.05, "185.220.101.5", "192.168.1.77", 443, sport, 0x12)
        if i == 0:  # one ClientHello is enough to fingerprint the implant
            send_tcp(0.02, "192.168.1.77", "185.220.101.5", sport, 443, 0x18,
                     tls_client_hello("update.evil-c2.net", **BEACON_TLS), seq=1)

    # 5) DNS tunnelling: many long, high-entropy names under one domain.
    for _ in range(25):
        label = "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                         for _ in range(28))
        send_udp(0.3, "192.168.1.88", "192.168.1.1", 52000, 53,
                 dns_query(f"{label}.tunnel.evil-c2.net", qtype=16))

    pkts.sort(key=lambda p: p[0])
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # DLT_EN10MB
    for ts, frame in pkts:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return out


def tls_client_hello(
    sni: str,
    ciphers: Sequence[int] = (0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8),
    curves: Sequence[int] = (0x001D, 0x0017, 0x0018),
    point_formats: Sequence[int] = (0x00,),
    extra_exts: Sequence[int] = (0x0017, 0x0023, 0x000D, 0x0010),
) -> bytes:
    server_name = sni.encode()
    exts = b""

    # server_name (0x0000)
    sni_body = struct.pack("!H", len(server_name) + 3) + b"\x00"
    sni_body += struct.pack("!H", len(server_name)) + server_name
    exts += struct.pack("!HH", 0x0000, len(sni_body)) + sni_body

    # supported_groups / elliptic curves (0x000a)
    curve_bytes = b"".join(struct.pack("!H", c) for c in curves)
    groups = struct.pack("!H", len(curve_bytes)) + curve_bytes
    exts += struct.pack("!HH", 0x000A, len(groups)) + groups

    # ec_point_formats (0x000b)
    pf_bytes = bytes(point_formats)
    pf = bytes([len(pf_bytes)]) + pf_bytes
    exts += struct.pack("!HH", 0x000B, len(pf)) + pf

    for etype in extra_exts:  # empty extensions, present only to shape the JA3
        exts += struct.pack("!HH", etype, 0)

    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"          # version + random + session id
    body += struct.pack("!H", len(cipher_bytes)) + cipher_bytes
    body += b"\x01\x00"                                   # compression
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# A distinctive fingerprint for the beaconing implant; its JA3 is on the demo
# IOC feed, so intel matching flags the TLS connection to the C2.
BEACON_TLS = dict(
    ciphers=[0xC02F, 0xC030, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035],
    curves=[0x0017, 0x0018, 0x0019],
    point_formats=[0x00, 0x01, 0x02],
    extra_exts=[0x0005, 0x000D, 0x0023],
)


def build_pcapng() -> bytes:
    """Wrap the same frames as :func:`build` in a minimal pcapng container."""
    # Re-extract the frames from the classic capture we already know how to build.
    classic = build()
    frames: list[tuple[float, bytes]] = []
    off = 24
    while off + 16 <= len(classic):
        sec, usec, caplen, _orig = struct.unpack("<IIII", classic[off:off + 16])
        off += 16
        frames.append((sec + usec / 1_000_000, classic[off:off + caplen]))
        off += caplen

    def block(btype: int, body: bytes) -> bytes:
        total = 12 + len(body) + (-len(body) % 4)
        pad = b"\x00" * (-len(body) % 4)
        return struct.pack("<II", btype, total) + body + pad + struct.pack("<I", total)

    # Section Header Block: byte-order magic + version 1.0 + unspecified length.
    shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    # Interface Description Block: link type 1 (Ethernet), snaplen 65535.
    idb_body = struct.pack("<HHI", 1, 0, 65535)

    out = block(0x0A0D0D0A, shb_body) + block(0x00000001, idb_body)
    for ts, data in frames:
        ticks = int(round(ts * 1_000_000))
        epb_body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF,
                               len(data), len(data)) + data + b"\x00" * (-len(data) % 4)
        out += block(0x00000006, epb_body)
    return out


def tls_server_hello(cipher: int = 0xC02F, ext_types: Sequence[int] = (0x0000, 0x000B)) -> bytes:
    exts = b"".join(struct.pack("!HH", e, 0) for e in ext_types)
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"          # version + random + session id
    body += struct.pack("!H", cipher) + b"\x00"          # cipher suite + compression
    body += struct.pack("!H", len(exts)) + exts
    handshake = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def tls_certificate_record(der: bytes) -> bytes:
    """Wrap a DER certificate in a TLS Certificate handshake record (TLS 1.2)."""
    cert_entry = struct.pack("!I", len(der))[1:] + der            # 3-byte len + cert
    cert_list = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    handshake = b"\x0b" + struct.pack("!I", len(cert_list))[1:] + cert_list
    return b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake


def _self_signed_der() -> bytes | None:
    """Generate a short-lived self-signed certificate (C2-style), if possible."""
    try:
        import datetime as _dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "update.evil-c2.net")])
    now = _dt.datetime(2026, 8, 1, tzinfo=_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)  # self-signed
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + _dt.timedelta(days=14))  # short-lived
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    with open(path, "wb") as fh:
        fh.write(build())
    print(f"wrote {path}")
