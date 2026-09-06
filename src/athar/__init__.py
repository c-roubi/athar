"""athar -- network capture forensics with a visual investigation report."""

from .analyze import analyze, classify_hosts
from .audit import AuditLog
from .backend import backend
from .evidence import Provenance, sha256_file
from .intel import Feed, load_feed
from .model import Case, Event, Flow, Host, Severity
from .signing import generate_keypair, sign_file, verify_file
from .store import load_case, save_case
from .tlsdecrypt import KeyLog, load_keylog

__version__ = "0.24.0"
__all__ = [
    "analyze", "classify_hosts", "backend", "save_case", "load_case",
    "load_feed", "Feed", "Provenance", "sha256_file", "AuditLog",
    "load_keylog", "KeyLog", "generate_keypair", "sign_file", "verify_file",
    "Case", "Host", "Flow", "Event", "Severity",
]
