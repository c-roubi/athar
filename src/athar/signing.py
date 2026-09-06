"""Digital signatures for evidence artefacts.

The chain-of-custody manifest hashes every output; signing takes the next step —
binding those hashes to an examiner's key so a third party can verify both that
nothing changed *and* who attested to it. Uses Ed25519 (small, fast, modern) via
the optional ``cryptography`` dependency.

A signature covers the SHA-256 of the target file, so verification needs only the
file, the signature, and the public key. Keys and signatures are stored as
PEM/hex text for easy handling alongside a case.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    HAVE_CRYPTO = True
except ImportError:  # optional dependency
    HAVE_CRYPTO = False

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .evidence import sha256_file


class SigningError(RuntimeError):
    """Raised when signing/verification can't proceed."""


def _require_crypto() -> None:
    if not HAVE_CRYPTO:
        raise SigningError(
            "signing needs the 'cryptography' package (pip install athar[tls])")


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Create an Ed25519 keypair and write both halves as PEM."""
    _require_crypto()
    key = Ed25519PrivateKey.generate()
    Path(private_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    Path(public_path).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def _load_private(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SigningError("private key is not an Ed25519 key")
    return key


def _load_public(path: str | Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise SigningError("public key is not an Ed25519 key")
    return key


def sign_file(path: str | Path, private_key_path: str | Path) -> dict[str, str]:
    """Sign the SHA-256 of *path*; return a detached signature record."""
    _require_crypto()
    key = _load_private(private_key_path)
    digest = sha256_file(path)
    signature = key.sign(bytes.fromhex(digest))
    return {
        "file": str(Path(path).name),
        "algorithm": "ed25519",
        "sha256": digest,
        "signature": signature.hex(),
    }


def verify_file(path: str | Path, signature_hex: str, public_key_path: str | Path) -> bool:
    """Return True iff *signature_hex* matches *path* under the public key."""
    _require_crypto()
    key = _load_public(public_key_path)
    digest = sha256_file(path)
    try:
        key.verify(bytes.fromhex(signature_hex), bytes.fromhex(digest))
    except (InvalidSignature, ValueError):
        return False
    return True
