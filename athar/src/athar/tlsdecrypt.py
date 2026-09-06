"""TLS decryption from an NSS key-log file.

athar does **not** break TLS. When an investigator supplies the per-session
secrets — the same ``SSLKEYLOGFILE`` Wireshark consumes, lawfully obtained from
an endpoint under their control — this module derives the record-protection keys
and decrypts the application data, after which the normal HTTP content/credential
extraction runs on the plaintext.

Supports the two key-log line types that matter:

* ``CLIENT_RANDOM <client_random> <master_secret>`` — TLS 1.2 (and earlier),
  any key exchange (RSA or DHE/ECDHE). Keys come from the TLS 1.2 PRF.
* ``SERVER_TRAFFIC_SECRET_0`` / ``CLIENT_TRAFFIC_SECRET_0`` — TLS 1.3, via the
  HKDF-Expand-Label schedule of RFC 8446.

Requires the optional ``cryptography`` dependency; if it is absent, TLS
decryption is simply unavailable and the rest of athar is unaffected.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

try:
    from cryptography.hazmat.primitives import hashes, hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:  # optional dependency
    HAVE_CRYPTO = False

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.hashes import HashAlgorithm


# --- key-log file ----------------------------------------------------------

_TLS12 = "CLIENT_RANDOM"
_TLS13_LABELS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0",
}


@dataclass
class KeyLog:
    """Secrets parsed from an NSS key-log file, indexed by client random."""

    # client_random(hex) -> master_secret(bytes)   [TLS 1.2]
    tls12: dict[str, bytes] = field(default_factory=dict)
    # client_random(hex) -> {label -> secret(bytes)}   [TLS 1.3]
    tls13: dict[str, dict[str, bytes]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.tls12 or self.tls13)


def load_keylog(path: str | Path) -> KeyLog:
    """Parse an NSS key-log file (``SSLKEYLOGFILE`` format)."""
    log = KeyLog()
    for line in Path(path).read_text(encoding="latin-1").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 3:
            continue
        label, client_random, secret_hex = parts
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError:
            continue
        if label == _TLS12:
            log.tls12[client_random.lower()] = secret
        elif label in _TLS13_LABELS:
            log.tls13.setdefault(client_random.lower(), {})[label] = secret
    return log


# --- HKDF / PRF primitives (RFC 5246 §5, RFC 8446 §7.1) --------------------

def _hmac(key: bytes, msg: bytes, alg: HashAlgorithm) -> bytes:
    h = hmac.HMAC(key, alg)
    h.update(msg)
    return h.finalize()


def _p_hash(secret: bytes, seed: bytes, size: int, alg: HashAlgorithm) -> bytes:
    """TLS 1.2 P_<hash> expansion function."""
    out = bytearray()
    a = seed
    while len(out) < size:
        a = _hmac(secret, a, alg)
        out += _hmac(secret, a + seed, alg)
    return bytes(out[:size])


def _hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int,
                       alg: HashAlgorithm) -> bytes:
    """HKDF-Expand-Label from RFC 8446 §7.1."""
    full_label = b"tls13 " + label.encode()
    hkdf_label = (length.to_bytes(2, "big")
                  + bytes([len(full_label)]) + full_label
                  + bytes([len(context)]) + context)
    # HKDF-Expand (RFC 5869) with a single-iteration-aware loop.
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = _hmac(secret, t + hkdf_label + bytes([counter]), alg)
        out += t
        counter += 1
    return bytes(out[:length])


# --- record layer & handshake parsing --------------------------------------

# cipher suite id -> (key length, hash name)
_SUITES = {
    0x009C: (16, "sha256"), 0x009D: (32, "sha384"),           # TLS_RSA_*_GCM
    0xC02F: (16, "sha256"), 0xC030: (32, "sha384"),           # ECDHE_RSA_*_GCM
    0xC02B: (16, "sha256"), 0xC02C: (32, "sha384"),           # ECDHE_ECDSA_*_GCM
    0x1301: (16, "sha256"), 0x1302: (32, "sha384"),           # TLS 1.3 AES-GCM
}


def _alg(name: str) -> HashAlgorithm:
    return hashes.SHA384() if name == "sha384" else hashes.SHA256()


def _records(stream: bytes) -> list[tuple[int, bytes, bytes, bytes]]:
    """Split a stream into TLS records: (type, version, header, fragment)."""
    out = []
    pos, n = 0, len(stream)
    while pos + 5 <= n:
        ctype = stream[pos]
        ver = stream[pos + 1:pos + 3]
        length = int.from_bytes(stream[pos + 3:pos + 5], "big")
        if pos + 5 + length > n:
            break
        out.append((ctype, ver, stream[pos:pos + 5], stream[pos + 5:pos + 5 + length]))
        pos += 5 + length
    return out


def _client_random(stream: bytes) -> str | None:
    for ctype, _ver, _hdr, frag in _records(stream):
        if ctype == 0x16 and len(frag) >= 38 and frag[0] == 0x01:  # ClientHello
            return frag[6:38].hex()
    return None


def _server_hello(stream: bytes) -> tuple[bytes, int] | None:
    for ctype, _ver, _hdr, frag in _records(stream):
        if ctype == 0x16 and len(frag) >= 40 and frag[0] == 0x02:  # ServerHello
            server_random = frag[6:38]
            sid_len = frag[38]
            p = 39 + sid_len
            if p + 2 > len(frag):
                return None
            cipher = int.from_bytes(frag[p:p + 2], "big")
            return server_random, cipher
    return None


# --- AEAD record decryption ------------------------------------------------

def _decrypt_tls12(records: list[tuple[int, bytes, bytes, bytes]], master: bytes,
                   client_random: bytes, server_random: bytes, key_len: int,
                   alg: HashAlgorithm, is_server: bool) -> bytes:
    block = _p_hash(master, b"key expansion" + server_random + client_random,
                    2 * key_len + 8, alg)
    cwk, swk = block[:key_len], block[key_len:2 * key_len]
    civ, siv = block[2 * key_len:2 * key_len + 4], block[2 * key_len + 4:2 * key_len + 8]
    key, salt = (swk, siv) if is_server else (cwk, civ)
    aead = AESGCM(key)

    out = bytearray()
    seq, active = 0, False
    for ctype, ver, _hdr, frag in records:
        if ctype == 0x14:      # ChangeCipherSpec: records after this are encrypted
            active, seq = True, 0
            continue
        if not active:
            continue
        if ctype == 0x17 and len(frag) > 24:
            explicit, ct = frag[:8], frag[8:]
            nonce = salt + explicit
            aad = seq.to_bytes(8, "big") + bytes([ctype]) + ver + (len(ct) - 16).to_bytes(2, "big")
            with contextlib.suppress(Exception):  # a bad key just yields no plaintext
                out += aead.decrypt(nonce, ct, aad)
        seq += 1
    return bytes(out)


def _decrypt_tls13(records: list[tuple[int, bytes, bytes, bytes]], secret: bytes,
                   key_len: int, alg: HashAlgorithm) -> bytes:
    key = _hkdf_expand_label(secret, "key", b"", key_len, alg)
    iv = _hkdf_expand_label(secret, "iv", b"", 12, alg)
    aead = AESGCM(key)

    out = bytearray()
    seq, started = 0, False
    for ctype, _ver, hdr, frag in records:
        if ctype != 0x17 or len(frag) < 17:
            continue
        nonce = bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big"), strict=True))
        try:
            inner = aead.decrypt(nonce, frag, hdr)
        except Exception:  # noqa: BLE001
            if started:
                seq += 1
            continue
        started = True
        seq += 1
        i = len(inner) - 1
        while i >= 0 and inner[i] == 0:  # strip zero padding
            i -= 1
        if i >= 0 and inner[i] == 0x17:  # inner content type == application_data
            out += inner[:i]
    return bytes(out)


def decrypt_connection(c2s: bytes, s2c: bytes, keylog: KeyLog) -> dict[str, bytes] | None:
    """Decrypt both directions of one TLS connection using logged secrets.

    Returns ``{"client": plaintext, "server": plaintext}`` for the application
    data, or ``None`` if the session can't be decrypted (unknown suite, no
    matching secret, or ``cryptography`` unavailable).
    """
    if not HAVE_CRYPTO:
        return None
    cr = _client_random(c2s)
    hello = _server_hello(s2c)
    if cr is None or hello is None:
        return None
    server_random, cipher = hello
    if cipher not in _SUITES:
        return None
    key_len, hashname = _SUITES[cipher]
    alg = _alg(hashname)

    if cr in keylog.tls13:
        secrets = keylog.tls13[cr]
        result = {}
        if "CLIENT_TRAFFIC_SECRET_0" in secrets:
            result["client"] = _decrypt_tls13(_records(c2s),
                                               secrets["CLIENT_TRAFFIC_SECRET_0"], key_len, alg)
        if "SERVER_TRAFFIC_SECRET_0" in secrets:
            result["server"] = _decrypt_tls13(_records(s2c),
                                               secrets["SERVER_TRAFFIC_SECRET_0"], key_len, alg)
        return result or None
    if cr in keylog.tls12:
        master = keylog.tls12[cr]
        cr_bytes = bytes.fromhex(cr)
        return {
            "client": _decrypt_tls12(_records(c2s), master, cr_bytes, server_random,
                                     key_len, alg, is_server=False),
            "server": _decrypt_tls12(_records(s2c), master, cr_bytes, server_random,
                                     key_len, alg, is_server=True),
        }
    return None
