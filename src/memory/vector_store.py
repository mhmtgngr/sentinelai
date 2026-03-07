"""ChromaDB-based vector memory for Sentinel-AI.

Stores security events, threat patterns, and incident history
as vector embeddings for similarity search.
"""

from __future__ import annotations

import logging
from typing import Any

from src.core.models import SecurityEvent

logger = logging.getLogger(__name__)

COLLECTION_EVENTS = "security_events"
COLLECTION_PATTERNS = "threat_patterns"
COLLECTION_INCIDENTS = "incident_history"


class VectorStore:
    """ChromaDB vector store for security event memory and similarity search.

    Gracefully degrades if ChromaDB is unavailable — returns empty results
    rather than crashing the pipeline.
    """

    def __init__(self, host: str = "localhost", port: int = 8100) -> None:
        self._host = host
        self._port = port
        self._client: Any = None
        self._collections: dict[str, Any] = {}

    def _get_client(self) -> Any:
        """Lazy-initialize ChromaDB client."""
        if self._client is None:
            try:
                import chromadb

                self._client = chromadb.HttpClient(host=self._host, port=self._port)
                logger.info("Connected to ChromaDB at %s:%d", self._host, self._port)
            except Exception:
                logger.warning("ChromaDB unavailable at %s:%d — operating in degraded mode", self._host, self._port)
                return None
        return self._client

    def _get_collection(self, name: str) -> Any:
        """Get or create a collection."""
        if name not in self._collections:
            client = self._get_client()
            if client is None:
                return None
            try:
                self._collections[name] = client.get_or_create_collection(name=name)
            except Exception:
                logger.exception("Failed to access collection '%s'", name)
                return None
        return self._collections[name]

    async def store_event(self, event: SecurityEvent) -> bool:
        """Store a security event as a vector embedding."""
        collection = self._get_collection(COLLECTION_EVENTS)
        if collection is None:
            return False

        doc_text = (
            f"source={event.source_adapter} type={event.event_type} "
            f"severity={event.severity.value} "
            f"mitre={','.join(event.mitre_attack)} "
            f"assets={','.join(event.affected_assets)} "
            f"iocs={','.join(ioc.value for ioc in event.iocs)}"
        )

        try:
            collection.add(
                documents=[doc_text],
                ids=[event.id],
                metadatas=[{
                    "source_adapter": event.source_adapter,
                    "event_type": event.event_type,
                    "severity": event.severity.value,
                    "timestamp": event.timestamp.isoformat(),
                }],
            )
            return True
        except Exception:
            logger.exception("Failed to store event '%s'", event.id)
            return False

    async def search_similar(self, query: str, n_results: int = 5) -> list[dict[str, Any]]:
        """Search for similar events by text query."""
        collection = self._get_collection(COLLECTION_EVENTS)
        if collection is None:
            return []

        try:
            results = collection.query(query_texts=[query], n_results=n_results)
            return [
                {
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                    "distance": results["distances"][0][i] if results.get("distances") else None,
                }
                for i in range(len(results["ids"][0]))
            ]
        except Exception:
            logger.exception("Similarity search failed")
            return []

    async def store_pattern(self, pattern_id: str, embedding_text: str, metadata: dict[str, Any]) -> bool:
        """Store a threat pattern for future matching."""
        collection = self._get_collection(COLLECTION_PATTERNS)
        if collection is None:
            return False

        try:
            collection.upsert(
                documents=[embedding_text],
                ids=[pattern_id],
                metadatas=[metadata],
            )
            return True
        except Exception:
            logger.exception("Failed to store pattern '%s'", pattern_id)
            return False

    async def get_collection_stats(self) -> dict[str, Any]:
        """Get statistics for all collections."""
        stats: dict[str, Any] = {}
        for name in [COLLECTION_EVENTS, COLLECTION_PATTERNS, COLLECTION_INCIDENTS]:
            collection = self._get_collection(name)
            if collection is not None:
                try:
                    stats[name] = {"count": collection.count()}
                except Exception:
                    stats[name] = {"count": -1, "error": "unavailable"}
            else:
                stats[name] = {"count": -1, "error": "unavailable"}
        return stats
