"""Threat intelligence enrichment from external feeds."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelResult:
    indicator: str
    indicator_type: str
    malicious: bool = False
    confidence: float = 0.0
    sources: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)


class ThreatIntelligence:
    """Enriches IOCs against multiple threat intelligence feeds."""

    def __init__(self) -> None:
        self._cache: dict[str, tuple[ThreatIntelResult, datetime]] = {}
        self._cache_ttl = timedelta(hours=1)
        self._vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self._otx_key = os.getenv("OTX_API_KEY", "")

    async def enrich_ip(self, ip: str) -> ThreatIntelResult:
        """Enrich an IP address against all configured feeds."""
        cached = self._get_cached(f"ip:{ip}")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=ip, indicator_type="ip")
        enrichments = []

        if self._vt_key:
            enrichments.append(self._query_virustotal_ip(ip))
        if self._abuseipdb_key:
            enrichments.append(self._query_abuseipdb(ip))
        if self._otx_key:
            enrichments.append(self._query_otx_ip(ip))

        for coro in enrichments:
            try:
                partial = await coro
                result.sources.extend(partial.sources)
                result.tags.extend(partial.tags)
                if partial.malicious:
                    result.malicious = True
                result.confidence = max(result.confidence, partial.confidence)
            except Exception:
                logger.exception("Error querying threat intel feed")

        self._set_cached(f"ip:{ip}", result)
        return result

    async def enrich_domain(self, domain: str) -> ThreatIntelResult:
        """Enrich a domain against threat intel feeds."""
        cached = self._get_cached(f"domain:{domain}")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=domain, indicator_type="domain")

        if self._vt_key:
            try:
                partial = await self._query_virustotal_domain(domain)
                result.sources.extend(partial.sources)
                result.malicious = partial.malicious
                result.confidence = partial.confidence
            except Exception:
                logger.exception("Error querying VirusTotal for domain")

        self._set_cached(f"domain:{domain}", result)
        return result

    async def enrich_hash(self, file_hash: str) -> ThreatIntelResult:
        """Enrich a file hash against threat intel feeds."""
        cached = self._get_cached(f"hash:{file_hash}")
        if cached:
            return cached

        result = ThreatIntelResult(indicator=file_hash, indicator_type="hash")

        if self._vt_key:
            try:
                partial = await self._query_virustotal_hash(file_hash)
                result.sources.extend(partial.sources)
                result.malicious = partial.malicious
                result.confidence = partial.confidence
                result.tags = partial.tags
            except Exception:
                logger.exception("Error querying VirusTotal for hash")

        self._set_cached(f"hash:{file_hash}", result)
        return result

    async def _query_virustotal_ip(self, ip: str) -> ThreatIntelResult:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self._vt_key},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                malicious=malicious_count > 2,
                confidence=malicious_count / total,
                sources=["virustotal"],
                tags=list(data.get("tags", [])),
            )

    async def _query_virustotal_domain(self, domain: str) -> ThreatIntelResult:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": self._vt_key},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return ThreatIntelResult(
                indicator=domain,
                indicator_type="domain",
                malicious=malicious_count > 2,
                confidence=malicious_count / total,
                sources=["virustotal"],
            )

    async def _query_virustotal_hash(self, file_hash: str) -> ThreatIntelResult:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": self._vt_key},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            total = sum(stats.values()) or 1
            return ThreatIntelResult(
                indicator=file_hash,
                indicator_type="hash",
                malicious=malicious_count > 2,
                confidence=malicious_count / total,
                sources=["virustotal"],
                tags=data.get("tags", []),
            )

    async def _query_abuseipdb(self, ip: str) -> ThreatIntelResult:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                malicious=score > 50,
                confidence=score / 100,
                sources=["abuseipdb"],
                tags=data.get("usageType", "").split(",") if data.get("usageType") else [],
            )

    async def _query_otx_ip(self, ip: str) -> ThreatIntelResult:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": self._otx_key},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            return ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                malicious=pulse_count > 0,
                confidence=min(pulse_count / 10, 1.0),
                sources=["otx"],
                tags=[p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
            )

    def _get_cached(self, key: str) -> ThreatIntelResult | None:
        if key in self._cache:
            result, ts = self._cache[key]
            if datetime.now(timezone.utc) - ts < self._cache_ttl:
                return result
            del self._cache[key]
        return None

    def _set_cached(self, key: str, result: ThreatIntelResult) -> None:
        self._cache[key] = (result, datetime.now(timezone.utc))
