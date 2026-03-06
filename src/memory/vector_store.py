"""ChromaDB-based vector memory for threat pattern similarity matching."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class VectorStore:
    """Vector memory store backed by ChromaDB for storing and querying security events by similarity."""

    def __init__(self, host: str = "localhost", port: int = 8000, collection_name: str = "sentinel_memory") -> None:
        self._host = host
        self._port = port
        self._collection_name = collection_name
        self._client: Any = None
        self._collection: Any = None
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize ChromaDB connection."""
        try:
            import chromadb
            self._client = chromadb.HttpClient(host=self._host, port=self._port)
            self._collection = self._client.get_or_create_collection(
                name=self._collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            self._initialized = True
            logger.info("VectorStore initialized with collection: %s", self._collection_name)
        except ImportError:
            logger.warning("chromadb not installed — using in-memory fallback")
            self._init_fallback()
        except Exception:
            logger.warning("ChromaDB not reachable — using in-memory fallback")
            self._init_fallback()

    def _init_fallback(self) -> None:
        """Initialize in-memory fallback when ChromaDB is unavailable."""
        self._documents: list[dict[str, Any]] = []
        self._initialized = True
        logger.info("VectorStore using in-memory fallback")

    async def store_event(self, event_data: dict[str, Any], metadata: dict[str, str] | None = None) -> str:
        """Store a security event in the vector store."""
        doc_text = self._event_to_text(event_data)
        doc_id = hashlib.sha256(doc_text.encode()).hexdigest()[:16]
        meta = {
            "event_type": str(event_data.get("event_type", "")),
            "severity": str(event_data.get("severity", "")),
            "source": str(event_data.get("source", "")),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        }

        if self._collection is not None:
            self._collection.upsert(
                documents=[doc_text],
                metadatas=[meta],
                ids=[doc_id],
            )
        else:
            self._documents.append({"id": doc_id, "text": doc_text, "metadata": meta})

        return doc_id

    async def query_similar(self, event_data: dict[str, Any], top_k: int = 5) -> list[dict[str, Any]]:
        """Find similar past events."""
        query_text = self._event_to_text(event_data)

        if self._collection is not None:
            results = self._collection.query(
                query_texts=[query_text],
                n_results=top_k,
            )
            return [
                {
                    "id": results["ids"][0][i],
                    "document": results["documents"][0][i],
                    "metadata": results["metadatas"][0][i] if results.get("metadatas") else {},
                    "distance": results["distances"][0][i] if results.get("distances") else 0,
                }
                for i in range(len(results["ids"][0]))
            ]
        else:
            # Simple text-overlap fallback
            scored = []
            query_words = set(query_text.lower().split())
            for doc in self._documents:
                doc_words = set(doc["text"].lower().split())
                overlap = len(query_words & doc_words) / max(len(query_words | doc_words), 1)
                scored.append({**doc, "distance": 1 - overlap})
            scored.sort(key=lambda x: x["distance"])
            return scored[:top_k]

    async def store_threat_pattern(self, pattern: dict[str, Any]) -> str:
        """Store a detected threat pattern for future similarity matching."""
        return await self.store_event(pattern, metadata={"type": "threat_pattern"})

    async def find_similar_threats(self, event_data: dict[str, Any], top_k: int = 5) -> list[dict[str, Any]]:
        """Find similar historical threat patterns."""
        return await self.query_similar(event_data, top_k=top_k)

    def get_stats(self) -> dict[str, Any]:
        if self._collection is not None:
            return {"backend": "chromadb", "count": self._collection.count()}
        return {"backend": "in_memory", "count": len(self._documents)}

    @staticmethod
    def _event_to_text(event_data: dict[str, Any]) -> str:
        """Convert an event dict to a text representation for embedding."""
        parts = []
        for key in ("event_type", "severity", "description", "rule_name", "attack_type",
                     "source_ip", "destination_ip", "mitre_tactic", "mitre_technique"):
            val = event_data.get(key)
            if val:
                parts.append(f"{key}: {val}")
        return " | ".join(parts) if parts else json.dumps(event_data, default=str)
