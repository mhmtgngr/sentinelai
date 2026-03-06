"""Tests for memory system components."""

import pytest
from src.core.event_bus import EventBus, EventType
from src.memory.vector_store import VectorStore
from src.memory.learning_engine import LearningEngine, FeedbackEntry, FeedbackVerdict
from src.memory.knowledge_graph import KnowledgeGraph


# --- Vector Store ---

@pytest.mark.asyncio
async def test_vector_store_fallback():
    store = VectorStore()
    await store.initialize()  # Should use in-memory fallback

    stats = store.get_stats()
    assert stats["backend"] == "in_memory"
    assert stats["count"] == 0


@pytest.mark.asyncio
async def test_vector_store_store_and_query():
    store = VectorStore()
    await store.initialize()

    event1 = {"event_type": "alert", "severity": "high", "description": "SQL injection attempt", "source_ip": "10.0.0.1"}
    event2 = {"event_type": "alert", "severity": "medium", "description": "Port scan detected", "source_ip": "10.0.0.2"}
    event3 = {"event_type": "alert", "severity": "high", "description": "SQL injection from external IP", "source_ip": "10.0.0.3"}

    await store.store_event(event1)
    await store.store_event(event2)
    await store.store_event(event3)

    results = await store.query_similar({"description": "SQL injection", "severity": "high"}, top_k=2)
    assert len(results) == 2


# --- Learning Engine ---

@pytest.mark.asyncio
async def test_learning_feedback():
    event_bus = EventBus()
    engine = LearningEngine(event_bus)

    await engine.record_feedback(FeedbackEntry(
        alert_id="A001", verdict=FeedbackVerdict.TRUE_POSITIVE, rule_id="R001",
    ))
    await engine.record_feedback(FeedbackEntry(
        alert_id="A002", verdict=FeedbackVerdict.FALSE_POSITIVE, rule_id="R001",
        analyst_notes="Monitoring probe",
    ))

    stats = engine.get_overall_stats()
    assert stats["total_feedback"] == 2
    assert stats["true_positives"] == 1
    assert stats["false_positives"] == 1


@pytest.mark.asyncio
async def test_learning_rule_accuracy():
    event_bus = EventBus()
    engine = LearningEngine(event_bus)

    for _ in range(8):
        await engine.record_feedback(FeedbackEntry(
            alert_id="A", verdict=FeedbackVerdict.FALSE_POSITIVE, rule_id="R100",
        ))
    for _ in range(2):
        await engine.record_feedback(FeedbackEntry(
            alert_id="A", verdict=FeedbackVerdict.TRUE_POSITIVE, rule_id="R100",
        ))

    accuracy = engine.get_rule_accuracy("R100")
    assert accuracy["fp_rate"] == 0.8
    assert accuracy["precision"] == 0.2

    # High FP rule should have reduced confidence
    adj = engine.get_confidence_adjustment("R100")
    assert adj < 1.0


@pytest.mark.asyncio
async def test_learning_fp_patterns():
    event_bus = EventBus()
    engine = LearningEngine(event_bus)

    await engine.record_feedback(FeedbackEntry(
        alert_id="A001", verdict=FeedbackVerdict.FALSE_POSITIVE,
        rule_id="R001", analyst_notes="Health check from monitoring",
    ))

    patterns = engine.get_false_positive_patterns()
    assert "Health check from monitoring" in patterns


# --- Knowledge Graph ---

def test_knowledge_graph_add_nodes():
    kg = KnowledgeGraph()
    node = kg.add_node("ip:10.0.0.1", "ip", {"ip": "10.0.0.1"})
    assert node.node_id == "ip:10.0.0.1"
    assert node.node_type == "ip"

    stats = kg.get_stats()
    assert stats["total_nodes"] == 1


def test_knowledge_graph_edges():
    kg = KnowledgeGraph()
    kg.add_node("ip:10.0.0.1", "ip")
    kg.add_node("ip:10.0.0.2", "ip")
    kg.add_edge("ip:10.0.0.1", "ip:10.0.0.2", "communicates_with")

    neighbors = kg.get_neighbors("ip:10.0.0.1")
    assert len(neighbors["neighbors"]) == 1
    assert neighbors["neighbors"][0]["node_id"] == "ip:10.0.0.2"


def test_knowledge_graph_ingest_event():
    kg = KnowledgeGraph()
    kg.ingest_event({
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.5",
        "hostname": "workstation-01",
        "user": "admin",
    })

    stats = kg.get_stats()
    assert stats["total_nodes"] == 4  # 2 IPs, 1 host, 1 user
    assert stats["total_edges"] >= 3


def test_knowledge_graph_attack_paths():
    kg = KnowledgeGraph()
    kg.add_node("A", "ip")
    kg.add_node("B", "host")
    kg.add_node("C", "ip")
    kg.add_edge("A", "B", "communicates_with")
    kg.add_edge("B", "C", "communicates_with")

    paths = kg.find_attack_paths("A", "C")
    assert len(paths) >= 1
    assert paths[0] == ["A", "B", "C"]


def test_knowledge_graph_high_connectivity():
    kg = KnowledgeGraph()
    kg.add_node("hub", "ip")
    for i in range(10):
        kg.add_node(f"node_{i}", "ip")
        kg.add_edge("hub", f"node_{i}", "communicates_with")

    high_conn = kg.get_high_connectivity_nodes(min_connections=5)
    assert len(high_conn) >= 1
    assert high_conn[0]["node_id"] == "hub"
