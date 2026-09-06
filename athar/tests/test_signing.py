"""Digital-signature tests (require the optional cryptography dep)."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("cryptography")


def test_sign_and_verify_roundtrip(tmp_path: Path):
    from athar.signing import generate_keypair, sign_file, verify_file
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    target = tmp_path / "manifest.json"
    target.write_text('{"case":"CU-1"}', encoding="utf-8")

    record = sign_file(target, priv)
    assert record["algorithm"] == "ed25519"
    assert verify_file(target, record["signature"], pub) is True


def test_tampering_breaks_signature(tmp_path: Path):
    from athar.signing import generate_keypair, sign_file, verify_file
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    generate_keypair(priv, pub)
    target = tmp_path / "report.html"
    target.write_text("original evidence", encoding="utf-8")
    record = sign_file(target, priv)

    target.write_text("tampered evidence", encoding="utf-8")
    assert verify_file(target, record["signature"], pub) is False


def test_wrong_key_fails(tmp_path: Path):
    from athar.signing import generate_keypair, sign_file, verify_file
    priv, pub = tmp_path / "k.pem", tmp_path / "k.pub"
    other_priv, other_pub = tmp_path / "o.pem", tmp_path / "o.pub"
    generate_keypair(priv, pub)
    generate_keypair(other_priv, other_pub)
    target = tmp_path / "f.txt"
    target.write_text("data", encoding="utf-8")
    record = sign_file(target, priv)
    # signature is valid under pub, but not under an unrelated public key
    assert verify_file(target, record["signature"], other_pub) is False
