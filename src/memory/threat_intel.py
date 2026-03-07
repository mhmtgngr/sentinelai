"""Threat intelligence enrichment for Sentinel-AI.

Provides IOC reputation lookup, threat intel caching,
and feed ingestion.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from src.core.models import IOC
from src.memory.vector_store import VectorStore

logger = logging.getLogger(__name__)


class ThreatIntelCache:
    """Threat intelligence cache backed by ChromaDB.

    Maintains an in-memory cache layer with TTL for fast lookups,
    with ChromaDB as the persistent backing store.
    """

    COLLECTION_NAME = "threat_intel"

    def __init__(self, vector_store: VectorStore, cache_ttl_seconds: int = 3600) -> None:
        self._vector_store = vector_store
        self._cache_ttl = cache_ttl_seconds
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_timestamps: dict[str, float] = {}

    def _is_cache_valid(self, key: str) -> bool:
        """Check if a cache entry is still valid."""
        if key not in self._cache_timestamps:
            return False
        return (time.monotonic() - self._cache_timestamps[key]) < self._cache_ttl

    async def enrich_ioc(self, ioc: IOC) -> dict[str, Any]:
        """Enrich an IOC with threat intelligence data.

        Returns reputation info, associated campaigns, and MITRE techniques.
        """
        cache_key = f"{ioc.type}:{ioc.value}"

        if self._is_cache_valid(cache_key):
            return self._cache[cache_key]

        results = await self._vector_store.search_similar(
            query=f"{ioc.type} {ioc.value}",
            n_results=3,
        )

        enrichment: dict[str, Any] = {
            "ioc_type": ioc.type,
            "ioc_value": ioc.value,
            "reputation": "unknown",
            "confidence": 0.0,
            "associated_campaigns": [],
            "mitre_techniques": [],
            "first_seen": None,
            "last_seen": None,
            "related_iocs": [],
        }

        if results:
            enrichment["reputation"] = "suspicious"
            enrichment["confidence"] = 0.5
            enrichment["related_iocs"] = [
                r.get("metadata", {}) for r in results[:3]
            ]

        self._cache[cache_key] = enrichment
        self._cache_timestamps[cache_key] = time.monotonic()

        return enrichment

    async def add_ioc(self, ioc: IOC, intel: dict[str, Any]) -> bool:
        """Add or update an IOC in the threat intel store."""
        doc_text = (
            f"type={ioc.type} value={ioc.value} "
            f"reputation={intel.get('reputation', 'unknown')} "
            f"campaigns={','.join(intel.get('associated_campaigns', []))} "
            f"techniques={','.join(intel.get('mitre_techniques', []))}"
        )

        metadata = {
            "ioc_type": ioc.type,
            "ioc_value": ioc.value,
            "reputation": intel.get("reputation", "unknown"),
            "confidence": intel.get("confidence", 0.0),
            "source": ioc.source,
        }

        success = await self._vector_store.store_pattern(
            pattern_id=f"intel:{ioc.type}:{ioc.value}",
            embedding_text=doc_text,
            metadata=metadata,
        )

        if success:
            cache_key = f"{ioc.type}:{ioc.value}"
            self._cache[cache_key] = {**intel, "ioc_type": ioc.type, "ioc_value": ioc.value}
            self._cache_timestamps[cache_key] = time.monotonic()

        return success

    async def search_related(self, ioc_value: str) -> list[dict[str, Any]]:
        """Search for IOCs related to a given value."""
        return await self._vector_store.search_similar(
            query=ioc_value,
            n_results=10,
        )

    async def update_from_feed(self, feed_data: list[dict[str, Any]]) -> int:
        """Ingest IOCs from a threat intel feed. Returns count of IOCs added."""
        added = 0
        for entry in feed_data:
            ioc = IOC(
                type=entry.get("type", "unknown"),
                value=entry.get("value", ""),
                confidence=entry.get("confidence", 0.5),
                source=entry.get("source", "feed"),
            )
            intel = {
                "reputation": entry.get("reputation", "malicious"),
                "associated_campaigns": entry.get("campaigns", []),
                "mitre_techniques": entry.get("techniques", []),
            }
            if await self.add_ioc(ioc, intel):
                added += 1
        logger.info("Ingested %d/%d IOCs from feed", added, len(feed_data))
        return added

    def clear_cache(self) -> None:
        """Clear the in-memory cache."""
        self._cache.clear()
        self._cache_timestamps.clear()
