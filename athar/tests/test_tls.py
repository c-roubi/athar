"""TLS decryption via NSS key-log (requires the optional cryptography dep)."""
from __future__ import annotations

import contextlib
import datetime
import ssl
import struct
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
pytest.importorskip("cryptography")


def _cert() -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.datetime(2020, 1, 1))
            .not_valid_after(datetime.datetime(2030, 1, 1)).sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = f"{d}/c.pem", f"{d}/k.pem"
    Path(cp).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(kp).write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cp, kp


def _handshake(tls_max: ssl.TLSVersion, request: bytes, response: bytes):
    """Drive a real in-memory TLS session; return (c2s, s2c, keylog_path)."""
    cp, kp = _cert()
    keylog = tempfile.mktemp()
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cp, kp)
    sctx.maximum_version = tls_max
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname = False
    cctx.verify_mode = ssl.CERT_NONE
    cctx.maximum_version = tls_max
    cctx.keylog_filename = keylog
    sin, sout, cin, cout = (ssl.MemoryBIO() for _ in range(4))
    srv = sctx.wrap_bio(sin, sout, server_side=True)
    cli = cctx.wrap_bio(cin, cout, server_hostname="localhost")
    c2s, s2c = bytearray(), bytearray()

    def pump() -> None:
        d = cout.read()
        if d:
            c2s.extend(d)
            sin.write(d)
        d = sout.read()
        if d:
            s2c.extend(d)
            cin.write(d)

    for _ in range(20):
        for side in (cli, srv):
            with contextlib.suppress(ssl.SSLWantReadError):
                side.do_handshake()
        pump()
    cli.write(request)
    pump()
    srv.write(response)
    pump()
    return bytes(c2s), bytes(s2c), keylog


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_2])
def test_decrypt_connection_recovers_plaintext(version: ssl.TLSVersion):
    from athar.tlsdecrypt import decrypt_connection, load_keylog
    req = b"POST /x HTTP/1.1\r\nHost: h\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    c2s, s2c, keylog = _handshake(version, req, resp)
    out = decrypt_connection(c2s, s2c, load_keylog(keylog))
    assert out is not None
    assert req in out["client"]
    assert resp in out["server"]


def test_analyze_decrypts_tls_and_extracts_credentials(tmp_path: Path):
    import make_sample_pcap as g

    from athar import analyze, load_keylog
    req = (b"GET /admin HTTP/1.1\r\nHost: bank.example\r\n"
           b"Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\r\n")
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\naccount data"
    c2s, s2c, keylog = _handshake(ssl.TLSVersion.TLSv1_3, req, resp)

    recs = []
    t = 1.0
    seq_c = seq_s = 1
    for chunk in [c2s[i:i + 1400] for i in range(0, len(c2s), 1400)]:
        t += 0.01
        recs.append((t, g.eth("10.0.0.5", "10.0.0.9", g.ipv4("10.0.0.5", "10.0.0.9", 6,
                     g.tcp(50000, 443, 0x18, chunk, seq=seq_c)))))
        seq_c += len(chunk)
    for chunk in [s2c[i:i + 1400] for i in range(0, len(s2c), 1400)]:
        t += 0.01
        recs.append((t, g.eth("10.0.0.9", "10.0.0.5", g.ipv4("10.0.0.9", "10.0.0.5", 6,
                     g.tcp(443, 50000, 0x18, chunk, seq=seq_s)))))
        seq_s += len(chunk)
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, fr in sorted(recs):
        sec = int(ts)
        blob += struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(fr), len(fr)) + fr
    p = tmp_path / "tls.pcap"
    p.write_bytes(blob)

    # opaque without keys
    assert not [e for e in analyze(p).events if e.detector == "plaintext_credentials"]
    # decrypted with keys
    case = analyze(p, keylog=load_keylog(keylog))
    creds = [e for e in case.events if e.detector == "plaintext_credentials"]
    assert creds and creds[0].evidence["username"] == "admin"
    assert creds[0].evidence["protocol"] == "HTTPS (decrypted)"
