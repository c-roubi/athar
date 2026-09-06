"""Network knowledge used by the evasion detectors.

Small, static reference data an analyst relies on: which port a service normally
lives on (so a service on the wrong port stands out), and how to recognise
anonymising infrastructure like Tor. This is deliberately lightweight and
offline; a deployment can extend the Tor set from the public exit-node list.
"""

from __future__ import annotations

# Canonical port for sensitive/adminservices. A match of the *service* on a
# different port is an evasion signal (e.g. RDP on 4444 instead of 3389).
# Sensitive services whose canonical port is singular, so a match of the service
# on a *different* port is a strong evasion signal (RDP on 4444, SSH on 2222...).
SERVICE_PORTS: dict[str, int] = {
    "rdp": 3389, "ssh": 22, "smb": 445, "kerberos": 88, "ldap": 389,
    "winrm": 5985, "vnc": 5900, "telnet": 23,
}

# A broader reference map (multi-standard-port apps included) for display only.
KNOWN_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    88: "kerberos", 110: "pop3", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 587: "smtp", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 5900: "vnc", 5985: "winrm",
    1433: "mssql", 6379: "redis", 27017: "mongodb",
}

# Ports strongly associated with Tor / common C2 defaults.
TOR_PORTS: frozenset[int] = frozenset({9001, 9030, 9040, 9050, 9051, 9150})
C2_DEFAULT_PORTS: frozenset[int] = frozenset(  # incl. Cobalt Strike, Metasploit, Meterpreter
    {4444, 4445, 1337, 31337, 8443, 50050, 6666, 6667, 12345, 54321, 2222})

# A seed set of known Tor relay addresses. Real deployments should refresh this
# from the published consensus; kept tiny here so the logic is testable offline.
_TOR_NODES: set[str] = set()


def load_tor_nodes(path: str) -> int:
    """Load newline-separated Tor relay IPs from a file; return the count."""
    from pathlib import Path
    count = 0
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        ip = line.strip()
        if ip and not ip.startswith("#"):
            _TOR_NODES.add(ip)
            count += 1
    return count


def is_tor_node(ip: str) -> bool:
    return ip in _TOR_NODES


def looks_like_tor(ip: str, port: int) -> bool:
    """Heuristic: a known relay, or a connection to a typical Tor ORPort."""
    return is_tor_node(ip) or port in TOR_PORTS
