"""Geolocation and ASN enrichment for external addresses.

Attribution context — what country and network an external IP belongs to — helps
an investigator reason about a conversation. Two tiers:

* If the investigator supplies a MaxMind GeoLite2/GeoIP2 database (``.mmdb``) and
  the optional ``geoip2`` reader is installed, athar returns precise
  country/city/ASN, exactly as Wireshark and other tools do.
* Otherwise a dependency-free fallback classifies each address by well-known
  reserved ranges (RFC 1918 private, loopback, link-local, CGNAT, multicast),
  which is enough to separate internal from external and flag special-use space.

Enrichment never leaves the machine — no network lookups — so it is safe on
sensitive evidence.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

try:
    import geoip2.database
    HAVE_GEOIP2 = True
except ImportError:
    HAVE_GEOIP2 = False


@dataclass
class GeoInfo:
    ip: str
    scope: str                 # private|loopback|link-local|cgnat|multicast|reserved|public
    country: str = ""
    country_code: str = ""
    city: str = ""
    asn: str = ""
    organization: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "ip": self.ip, "scope": self.scope, "country": self.country,
            "country_code": self.country_code, "city": self.city,
            "asn": self.asn, "organization": self.organization,
        }


def _scope(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "reserved"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    # 100.64.0.0/10 is carrier-grade NAT (RFC 6598) — check explicitly, as some
    # Python versions don't fold it into is_private.
    if addr.version == 4 and addr in ipaddress.ip_network("100.64.0.0/10"):
        return "cgnat"
    if addr.is_private:
        return "private"
    if addr.is_reserved or addr.is_unspecified:
        return "reserved"
    return "public"


class GeoEnricher:
    """Resolves addresses to :class:`GeoInfo`, using MaxMind when available."""

    def __init__(self, city_db: str | Path | None = None,
                 asn_db: str | Path | None = None) -> None:
        self._city = None
        self._asn = None
        if HAVE_GEOIP2:
            if city_db and Path(city_db).exists():
                self._city = geoip2.database.Reader(str(city_db))
            if asn_db and Path(asn_db).exists():
                self._asn = geoip2.database.Reader(str(asn_db))

    @property
    def has_database(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: str) -> GeoInfo:
        info = GeoInfo(ip=ip, scope=_scope(ip))
        if info.scope != "public":
            return info  # non-routable space is never geolocated
        if self._city is not None:
            try:
                r = self._city.city(ip)
                info.country = r.country.name or ""
                info.country_code = r.country.iso_code or ""
                info.city = r.city.name or ""
            except Exception:  # noqa: BLE001 - address simply not in the DB
                pass
        if self._asn is not None:
            try:
                a = self._asn.asn(ip)
                info.asn = f"AS{a.autonomous_system_number}" if a.autonomous_system_number else ""
                info.organization = a.autonomous_system_organization or ""
            except Exception:  # noqa: BLE001
                pass
        return info

    def close(self) -> None:
        for reader in (self._city, self._asn):
            if reader is not None:
                reader.close()
