"""
enrichment/threat_intel.py — Threat Intelligence Enrichment

Enriches alert source IPs with:
  - Geolocation (ip-api.com — free, no API key, 45 req/min)
  - Reputation (AbuseIPDB free tier — optional ABUSEIPDB_API_KEY, 1000 req/day)

Private IP detection uses explicit CIDR checks rather than Python's
is_private (which incorrectly marks RFC 5737 test-nets like 203.0.113.x
as private — those are documentation ranges but routable in demos).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,lat,lon,isp,org,as,proxy,hosting"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

_CACHE_TTL_SECONDS = 3600
_GEOIP_RATE_LIMIT = 40
_GEOIP_WINDOW = 60.0

# Private/reserved ranges to skip (explicit, no Python is_private)
_PRIVATE_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),
]

def _is_private(ip: str) -> bool:
    """Return True only for RFC1918 / loopback / link-local addresses."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


@dataclass
class EnrichmentResult:
    ip: str
    is_private: bool = False
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    isp: str | None = None
    org: str | None = None
    asn: str | None = None
    is_proxy: bool = False
    is_hosting: bool = False
    abuse_score: int | None = None
    abuse_reports: int | None = None
    abuse_categories: list[str] = field(default_factory=list)
    enriched_at: float = field(default_factory=time.time)
    sources: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def risk_level(self) -> str:
        if self.is_private:
            return "internal"
        if self.abuse_score is None:
            return "unknown"
        if self.abuse_score >= 75:
            return "high"
        if self.abuse_score >= 25:
            return "medium"
        return "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "is_private": self.is_private,
            "country": self.country,
            "country_code": self.country_code,
            "region": self.region,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "isp": self.isp,
            "org": self.org,
            "asn": self.asn,
            "is_proxy": self.is_proxy,
            "is_hosting": self.is_hosting,
            "abuse_score": self.abuse_score,
            "abuse_reports": self.abuse_reports,
            "abuse_categories": self.abuse_categories,
            "risk_level": self.risk_level,
            "enriched_at": self.enriched_at,
            "sources": self.sources,
            "error": self.error,
        }


_ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    7: "Phishing", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class ThreatIntelEnricher:
    """
    Async IP enrichment — geolocation + optional AbuseIPDB reputation.
    Uses explicit RFC1918 check instead of Python's is_private so that
    documentation-range IPs (203.0.113.x, 1.1.1.1, etc.) are enriched.
    """

    def __init__(self, abuseipdb_key: str | None = None) -> None:
        self._abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self._cache: dict[str, EnrichmentResult] = {}
        self._geoip_timestamps: list[float] = []

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self._abuseipdb_key)

    async def enrich(self, ip: str, use_cache: bool = True) -> EnrichmentResult:
        if use_cache and ip in self._cache:
            cached = self._cache[ip]
            if time.time() - cached.enriched_at < _CACHE_TTL_SECONDS:
                return cached

        if _is_private(ip):
            result = EnrichmentResult(ip=ip, is_private=True, sources=["local"])
            self._cache[ip] = result
            return result

        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return EnrichmentResult(ip=ip, error="Invalid IP address", sources=[])

        result = EnrichmentResult(ip=ip)
        sources = []

        geo_data = await self._fetch_geoip(ip)
        if geo_data:
            result.country = geo_data.get("country")
            result.country_code = geo_data.get("countryCode")
            result.region = geo_data.get("regionName")
            result.city = geo_data.get("city")
            result.latitude = geo_data.get("lat")
            result.longitude = geo_data.get("lon")
            result.isp = geo_data.get("isp")
            result.org = geo_data.get("org")
            result.asn = geo_data.get("as")
            result.is_proxy = geo_data.get("proxy", False)
            result.is_hosting = geo_data.get("hosting", False)
            sources.append("ip-api.com")

        if self.has_abuseipdb:
            abuse_data = await self._fetch_abuseipdb(ip)
            if abuse_data:
                result.abuse_score = abuse_data.get("abuseConfidenceScore")
                result.abuse_reports = abuse_data.get("totalReports")
                categories = set()
                for report in abuse_data.get("reports", [])[:10]:
                    for cat_id in report.get("categories", []):
                        if cat_id in _ABUSE_CATEGORIES:
                            categories.add(_ABUSE_CATEGORIES[cat_id])
                result.abuse_categories = sorted(categories)
                sources.append("abuseipdb.com")

        result.sources = sources
        if not sources:
            result.error = "No enrichment sources available or rate-limited"

        self._cache[ip] = result
        return result

    async def enrich_many(self, ips: list[str]) -> dict[str, EnrichmentResult]:
        unique_ips = list(dict.fromkeys(ips))
        results = {}
        for ip in unique_ips:
            results[ip] = await self.enrich(ip)
        return results

    async def _rate_limit_geoip(self) -> None:
        now = time.time()
        self._geoip_timestamps = [t for t in self._geoip_timestamps if now - t < _GEOIP_WINDOW]
        if len(self._geoip_timestamps) >= _GEOIP_RATE_LIMIT:
            wait = _GEOIP_WINDOW - (now - self._geoip_timestamps[0]) + 0.5
            if wait > 0:
                await asyncio.sleep(wait)
        self._geoip_timestamps.append(time.time())

    async def _fetch_geoip(self, ip: str) -> dict | None:
        import urllib.error
        import urllib.request
        await self._rate_limit_geoip()
        url = GEOIP_URL.format(ip=ip)

        def _call() -> dict | None:
            try:
                with urllib.request.urlopen(url, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data if data.get("status") == "success" else None
            except Exception as e:
                logger.debug("GeoIP lookup failed for %s: %s", ip, e)
                return None

        return await asyncio.get_running_loop().run_in_executor(None, _call)

    async def _fetch_abuseipdb(self, ip: str) -> dict | None:
        import urllib.error
        import urllib.request
        url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90&verbose"

        def _call() -> dict | None:
            req = urllib.request.Request(url, headers={"Key": self._abuseipdb_key, "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    return json.loads(resp.read().decode("utf-8")).get("data")
            except Exception as e:
                logger.debug("AbuseIPDB lookup failed for %s: %s", ip, e)
                return None

        return await asyncio.get_running_loop().run_in_executor(None, _call)

    def get_stats(self) -> dict:
        return {
            "cached_ips": len(self._cache),
            "abuseipdb_configured": self.has_abuseipdb,
            "geoip_calls_recent": len(self._geoip_timestamps),
        }
