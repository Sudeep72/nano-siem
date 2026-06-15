"""
enrichment/threat_intel.py — Threat Intelligence Enrichment

Enriches alert source IPs with:
  - Geolocation (ip-api.com — free, no API key required, 45 req/min)
  - IP reputation (AbuseIPDB free tier — requires API key, 1000 req/day)

DESIGN NOTE — this module is ENRICHMENT, not detection:
  Threat intel results are attached to alerts AFTER detection has already
  fired (Sigma/Correlation/ML). A "high abuse score" IP does NOT change
  whether an alert exists — it adds context for the analyst.

Caching: results are cached in-memory with a TTL to respect rate limits
and avoid re-querying the same IP repeatedly within a short window.

Private/reserved IPs (RFC1918, loopback, etc.) are never queried externally —
they're tagged locally as "private" with no external API call.
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

_CACHE_TTL_SECONDS = 3600  # 1 hour
_GEOIP_RATE_LIMIT = 40     # stay under 45/min free tier
_GEOIP_WINDOW = 60.0


@dataclass
class EnrichmentResult:
    ip: str
    is_private: bool = False
    # Geolocation
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
    # Reputation
    abuse_score: int | None = None       # 0-100, AbuseIPDB confidence score
    abuse_reports: int | None = None
    abuse_categories: list[str] = field(default_factory=list)
    # Metadata
    enriched_at: float = field(default_factory=time.time)
    sources: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def risk_level(self) -> str:
        """Derived risk level from abuse score, for display purposes only."""
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


# AbuseIPDB category code -> human-readable name (common subset)
_ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}


class ThreatIntelEnricher:
    """
    Async threat intelligence enrichment with caching and rate limiting.

    AbuseIPDB API key is optional — if not set, only geolocation is returned.
    Get a free key at: https://www.abuseipdb.com/account/api
    """

    def __init__(self, abuseipdb_key: str | None = None) -> None:
        self._abuseipdb_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
        self._cache: dict[str, EnrichmentResult] = {}
        self._geoip_timestamps: list[float] = []

    @property
    def has_abuseipdb(self) -> bool:
        return bool(self._abuseipdb_key)

    async def enrich(self, ip: str, use_cache: bool = True) -> EnrichmentResult:
        """
        Enrich a single IP address with geolocation and reputation data.
        Private/reserved IPs are tagged locally without external calls.
        """
        # Cache check
        if use_cache and ip in self._cache:
            cached = self._cache[ip]
            if time.time() - cached.enriched_at < _CACHE_TTL_SECONDS:
                return cached

        # Private IP check — no external call needed
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                result = EnrichmentResult(ip=ip, is_private=True, sources=["local"])
                self._cache[ip] = result
                return result
        except ValueError:
            return EnrichmentResult(ip=ip, error="Invalid IP address", sources=[])

        # External enrichment
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
        """Enrich multiple IPs, deduplicated, with shared cache and rate limiting."""
        unique_ips = list(dict.fromkeys(ips))  # preserve order, dedupe
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
                    if data.get("status") == "success":
                        return data
                    return None
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                logger.debug("GeoIP lookup failed for %s: %s", ip, e)
                return None

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _call)

    async def _fetch_abuseipdb(self, ip: str) -> dict | None:
        import urllib.error
        import urllib.request

        url = f"{ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90&verbose"

        def _call() -> dict | None:
            req = urllib.request.Request(
                url,
                headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("data")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                logger.debug("AbuseIPDB lookup failed for %s: %s", ip, e)
                return None

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _call)

    def get_stats(self) -> dict:
        return {
            "cached_ips": len(self._cache),
            "abuseipdb_configured": self.has_abuseipdb,
            "geoip_calls_recent": len(self._geoip_timestamps),
        }
