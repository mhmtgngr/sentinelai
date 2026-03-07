"""Tests for memory layer components."""

from __future__ import annotations

import pytest

from src.core.models import IOC, SecurityEvent, Severity, Verdict


class TestVectorStore:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.memory.vector_store import VectorStore
        assert VectorStore is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.memory.vector_store import VectorStore
        store = VectorStore(host="localhost", port=8100)
        assert store is not None

    @pytest.mark.asyncio
    async def test_store_event_graceful_degradation(self):
        from src.memory.vector_store import VectorStore
        store = VectorStore(host="localhost", port=9999)
        event = SecurityEvent(
            source_adapter="test",
            event_type="test",
            severity=Severity.HIGH,
            raw_payload={"key": "value"},
        )
        result = await store.store_event(event)
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_search_similar_graceful_degradation(self):
        from src.memory.vector_store import VectorStore
        store = VectorStore(host="localhost", port=9999)
        results = await store.search_similar("test query")
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_collection_stats_graceful_degradation(self):
        from src.memory.vector_store import VectorStore
        store = VectorStore(host="localhost", port=9999)
        stats = await store.get_collection_stats()
        assert isinstance(stats, dict)


class TestThreatIntelCache:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.memory.threat_intel import ThreatIntelCache
        assert ThreatIntelCache is not None

    @pytest.mark.asyncio
    async def test_creation(self):
        from src.memory.vector_store import VectorStore
        from src.memory.threat_intel import ThreatIntelCache
        store = VectorStore()
        cache = ThreatIntelCache(vector_store=store)
        assert cache is not None

    @pytest.mark.asyncio
    async def test_add_and_enrich_ioc(self):
        from src.memory.vector_store import VectorStore
        from src.memory.threat_intel import ThreatIntelCache
        store = VectorStore()
        cache = ThreatIntelCache(vector_store=store)
        ioc = IOC(type="ip", value="10.0.0.1", confidence=0.9)
        await cache.add_ioc(ioc, {"reputation": "malicious"})
        result = await cache.enrich_ioc(ioc)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_search_related(self):
        from src.memory.vector_store import VectorStore
        from src.memory.threat_intel import ThreatIntelCache
        store = VectorStore()
        cache = ThreatIntelCache(vector_store=store)
        results = await cache.search_related("10.0.0.1")
        assert isinstance(results, list)

    @pytest.mark.asyncio
    async def test_update_from_feed(self):
        from src.memory.vector_store import VectorStore
        from src.memory.threat_intel import ThreatIntelCache
        store = VectorStore()
        cache = ThreatIntelCache(vector_store=store)
        feed = [
            {"type": "ip", "value": "1.2.3.4", "reputation": "malicious"},
            {"type": "domain", "value": "evil.com", "reputation": "malicious"},
        ]
        count = await cache.update_from_feed(feed)
        assert isinstance(count, int)

    @pytest.mark.asyncio
    async def test_clear_cache(self):
        from src.memory.vector_store import VectorStore
        from src.memory.threat_intel import ThreatIntelCache
        store = VectorStore()
        cache = ThreatIntelCache(vector_store=store)
        ioc = IOC(type="ip", value="10.0.0.1", confidence=0.9)
        await cache.add_ioc(ioc, {"reputation": "malicious"})
        cache.clear_cache()


class TestLearningEngine:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.memory.learning_engine import LearningEngine
        assert LearningEngine is not None

    @pytest.mark.asyncio
    async def test_record_verdict(self):
        from src.memory.vector_store import VectorStore
        from src.memory.learning_engine import LearningEngine
        store = VectorStore()
        engine = LearningEngine(vector_store=store)
        await engine.record_verdict(
            alert_id="alert-1",
            verdict=Verdict.TRUE_POSITIVE,
            analyst_notes="confirmed",
            original_verdict=Verdict.UNDETERMINED,
        )

    @pytest.mark.asyncio
    async def test_false_positive_rate(self):
        from src.memory.vector_store import VectorStore
        from src.memory.learning_engine import LearningEngine
        store = VectorStore()
        engine = LearningEngine(vector_store=store)
        rate = engine.get_false_positive_rate()
        assert isinstance(rate, float)
        assert 0.0 <= rate <= 1.0

    @pytest.mark.asyncio
    async def test_record_action_outcome(self):
        from src.memory.vector_store import VectorStore
        from src.memory.learning_engine import LearningEngine
        store = VectorStore()
        engine = LearningEngine(vector_store=store)
        await engine.record_action_outcome(
            action_id="act-1",
            success=True,
            side_effects=None,
        )

    @pytest.mark.asyncio
    async def test_action_success_rate(self):
        from src.memory.vector_store import VectorStore
        from src.memory.learning_engine import LearningEngine
        store = VectorStore()
        engine = LearningEngine(vector_store=store)
        rate = engine.get_action_success_rate()
        assert isinstance(rate, dict)
        assert "success_rate" in rate

    @pytest.mark.asyncio
    async def test_baseline_management(self):
        from src.memory.vector_store import VectorStore
        from src.memory.learning_engine import LearningEngine
        store = VectorStore()
        engine = LearningEngine(vector_store=store)
        await engine.update_baseline("host-1", {"cpu": 45.0, "memory": 60.0})
        baseline = engine.get_baseline("host-1")
        assert baseline is not None
        assert len(baseline["metrics_history"]) == 1


class TestKnowledgeGraph:
    @pytest.mark.asyncio
    async def test_import(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        assert KnowledgeGraph is not None

    @pytest.mark.asyncio
    async def test_add_node(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("ip-1", "ip_address", {"value": "10.0.0.1"})
        assert kg.node_count == 1

    @pytest.mark.asyncio
    async def test_add_relationship(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("ip-1", "ip_address", {"value": "10.0.0.1"})
        kg.add_node("host-1", "host", {"hostname": "ws-042"})
        kg.add_relationship("ip-1", "communicates_with", "host-1", {})
        assert kg.edge_count == 1

    @pytest.mark.asyncio
    async def test_query_neighbors(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("ip-1", "ip_address", {})
        kg.add_node("host-1", "host", {})
        kg.add_relationship("ip-1", "communicates_with", "host-1", {})
        neighbors = kg.query_neighbors("ip-1")
        assert len(neighbors) >= 1

    @pytest.mark.asyncio
    async def test_get_attack_chain(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("ioc-1", "ioc", {"type": "ip"})
        kg.add_node("host-1", "host", {})
        kg.add_relationship("ioc-1", "targets", "host-1", {})
        chain = kg.get_attack_chain("ioc-1")
        assert isinstance(chain, list)

    @pytest.mark.asyncio
    async def test_asset_risk_score(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("asset-1", "host", {"risk_base": 3.0})
        score = kg.get_asset_risk_score("asset-1")
        assert isinstance(score, float)

    @pytest.mark.asyncio
    async def test_get_nodes_by_type(self):
        from src.memory.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        kg.add_node("ip-1", "ip_address", {})
        kg.add_node("ip-2", "ip_address", {})
        kg.add_node("host-1", "host", {})
        ips = kg.get_nodes_by_type("ip_address")
        assert len(ips) == 2
