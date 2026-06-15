"""
test_enrichment.py — Tests for enrichment/threat_intel.py (Threat Intelligence)

Network calls are mocked — these tests verify logic, caching, private-IP
handling, and result structure without making real HTTP requests.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, patch

from nano_siem.enrichment.threat_intel import (
    ThreatIntelEnricher, EnrichmentResult, _ABUSE_CATEGORIES,
)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


GEOIP_RESPONSE = {
    "status": "success",
    "country": "United States",
    "countryCode": "US",
    "regionName": "California",
    "city": "Mountain View",
    "lat": 37.4056,
    "lon": -122.0775,
    "isp": "Example ISP",
    "org": "Example Org",
    "as": "AS15169 Example",
    "proxy": False,
    "hosting": True,
}

ABUSEIPDB_RESPONSE = {
    "ipAddress": "8.8.8.8",
    "abuseConfidenceScore": 85,
    "totalReports": 42,
    "reports": [
        {"categories": [18, 22]},
        {"categories": [14]},
    ],
}


class TestPrivateIPHandling:
    def test_rfc1918_10_is_private(self):
        enricher = ThreatIntelEnricher()
        result = run(enricher.enrich("10.0.0.5"))
        assert result.is_private is True
        assert result.sources == ["local"]

    def test_rfc1918_192_is_private(self):
        enricher = ThreatIntelEnricher()
        result = run(enricher.enrich("192.168.1.1"))
        assert result.is_private is True

    def test_loopback_is_private(self):
        enricher = ThreatIntelEnricher()
        result = run(enricher.enrich("127.0.0.1"))
        assert result.is_private is True

    def test_private_ip_no_external_call(self):
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock()) as mock_geo:
            run(enricher.enrich("10.0.0.1"))
            mock_geo.assert_not_called()

    def test_private_ip_risk_level(self):
        enricher = ThreatIntelEnricher()
        result = run(enricher.enrich("10.0.0.1"))
        assert result.risk_level == "internal"

    def test_invalid_ip_returns_error(self):
        enricher = ThreatIntelEnricher()
        result = run(enricher.enrich("not-an-ip"))
        assert result.error is not None


class TestPublicIPEnrichment:
    def test_geoip_enrichment(self):
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.country == "United States"
        assert result.city == "Mountain View"
        assert result.is_hosting is True
        assert "ip-api.com" in result.sources

    def test_geoip_failure_handled_gracefully(self):
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=None)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.country is None
        assert "ip-api.com" not in result.sources

    def test_no_abuseipdb_without_key(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="")
        assert enricher.has_abuseipdb is False
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.abuse_score is None

    def test_abuseipdb_enrichment_with_key(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="fake-key-for-test")
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)), \
             patch.object(enricher, "_fetch_abuseipdb", new=AsyncMock(return_value=ABUSEIPDB_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.abuse_score == 85
        assert result.abuse_reports == 42
        assert "abuseipdb.com" in result.sources

    def test_abuse_categories_mapped(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="fake-key")
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)), \
             patch.object(enricher, "_fetch_abuseipdb", new=AsyncMock(return_value=ABUSEIPDB_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert "SSH" in result.abuse_categories
        assert "Port Scan" in result.abuse_categories

    def test_risk_level_high(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="fake-key")
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)), \
             patch.object(enricher, "_fetch_abuseipdb", new=AsyncMock(return_value=ABUSEIPDB_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.risk_level == "high"

    def test_risk_level_low(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="fake-key")
        clean_response = {**ABUSEIPDB_RESPONSE, "abuseConfidenceScore": 5}
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)), \
             patch.object(enricher, "_fetch_abuseipdb", new=AsyncMock(return_value=clean_response)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.risk_level == "low"

    def test_risk_level_unknown_without_abuseipdb(self):
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        assert result.risk_level == "unknown"


class TestCaching:
    def test_result_cached(self):
        enricher = ThreatIntelEnricher()
        mock_geo = AsyncMock(return_value=GEOIP_RESPONSE)
        with patch.object(enricher, "_fetch_geoip", new=mock_geo):
            run(enricher.enrich("8.8.8.8"))
            run(enricher.enrich("8.8.8.8"))
        mock_geo.assert_called_once()

    def test_cache_bypass(self):
        enricher = ThreatIntelEnricher()
        mock_geo = AsyncMock(return_value=GEOIP_RESPONSE)
        with patch.object(enricher, "_fetch_geoip", new=mock_geo):
            run(enricher.enrich("8.8.8.8"))
            run(enricher.enrich("8.8.8.8", use_cache=False))
        assert mock_geo.call_count == 2


class TestEnrichMany:
    def test_enrich_many_dedupes(self):
        enricher = ThreatIntelEnricher()
        mock_geo = AsyncMock(return_value=GEOIP_RESPONSE)
        with patch.object(enricher, "_fetch_geoip", new=mock_geo):
            results = run(enricher.enrich_many(["8.8.8.8", "8.8.8.8", "10.0.0.1"]))
        assert len(results) == 2
        assert mock_geo.call_count == 1  # only called for the public IP, once

    def test_enrich_many_returns_dict(self):
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)):
            results = run(enricher.enrich_many(["8.8.8.8", "10.0.0.1"]))
        assert "8.8.8.8" in results
        assert "10.0.0.1" in results
        assert isinstance(results["8.8.8.8"], EnrichmentResult)


class TestToDict:
    def test_to_dict_serializable(self):
        import json
        enricher = ThreatIntelEnricher()
        with patch.object(enricher, "_fetch_geoip", new=AsyncMock(return_value=GEOIP_RESPONSE)):
            result = run(enricher.enrich("8.8.8.8"))
        d = result.to_dict()
        json.dumps(d)
        assert d["ip"] == "8.8.8.8"
        assert "risk_level" in d


class TestStats:
    def test_get_stats_structure(self):
        enricher = ThreatIntelEnricher()
        stats = enricher.get_stats()
        assert "cached_ips" in stats
        assert "abuseipdb_configured" in stats

    def test_abuseipdb_configured_reflects_key(self):
        enricher = ThreatIntelEnricher(abuseipdb_key="test-key")
        assert enricher.get_stats()["abuseipdb_configured"] is True
