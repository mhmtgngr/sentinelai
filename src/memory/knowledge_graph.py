"""Security knowledge graph for relationship mapping between entities."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    node_id: str
    node_type: str  # ip, domain, user, host, process, file, alert, incident
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    relationship: str  # communicates_with, executed_on, triggered_by, owns, part_of
    properties: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class KnowledgeGraph:
    """In-memory knowledge graph for mapping relationships between security entities."""

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []
        self._adjacency: dict[str, list[str]] = {}  # node_id -> [connected_node_ids]

    def add_node(self, node_id: str, node_type: str, properties: dict[str, Any] | None = None) -> GraphNode:
        """Add or update a node in the graph."""
        if node_id in self._nodes:
            existing = self._nodes[node_id]
            if properties:
                existing.properties.update(properties)
            return existing
        node = GraphNode(node_id=node_id, node_type=node_type, properties=properties or {})
        self._nodes[node_id] = node
        if node_id not in self._adjacency:
            self._adjacency[node_id] = []
        return node

    def add_edge(self, source_id: str, target_id: str, relationship: str, properties: dict[str, Any] | None = None) -> GraphEdge:
        """Add a relationship between two nodes."""
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            relationship=relationship,
            properties=properties or {},
        )
        self._edges.append(edge)

        if source_id not in self._adjacency:
            self._adjacency[source_id] = []
        if target_id not in self._adjacency:
            self._adjacency[target_id] = []
        self._adjacency[source_id].append(target_id)
        self._adjacency[target_id].append(source_id)

        return edge

    def ingest_event(self, event_data: dict[str, Any]) -> None:
        """Automatically extract entities and relationships from a security event."""
        source_ip = event_data.get("source_ip")
        dest_ip = event_data.get("destination_ip")
        hostname = event_data.get("hostname")
        user = event_data.get("user")
        domain = event_data.get("domain")
        process = event_data.get("process_name")
        file_path = event_data.get("file_path")

        if source_ip:
            self.add_node(f"ip:{source_ip}", "ip", {"ip": source_ip})
        if dest_ip:
            self.add_node(f"ip:{dest_ip}", "ip", {"ip": dest_ip})
        if hostname:
            self.add_node(f"host:{hostname}", "host", {"hostname": hostname})
        if user:
            self.add_node(f"user:{user}", "user", {"username": user})
        if domain:
            self.add_node(f"domain:{domain}", "domain", {"domain": domain})
        if process:
            self.add_node(f"process:{process}", "process", {"name": process})
        if file_path:
            self.add_node(f"file:{file_path}", "file", {"path": file_path})

        # Create relationships
        if source_ip and dest_ip:
            self.add_edge(f"ip:{source_ip}", f"ip:{dest_ip}", "communicates_with")
        if source_ip and hostname:
            self.add_edge(f"ip:{source_ip}", f"host:{hostname}", "associated_with")
        if user and hostname:
            self.add_edge(f"user:{user}", f"host:{hostname}", "logged_into")
        if process and hostname:
            self.add_edge(f"process:{process}", f"host:{hostname}", "executed_on")
        if source_ip and domain:
            self.add_edge(f"ip:{source_ip}", f"domain:{domain}", "resolved_to")

    def get_neighbors(self, node_id: str, depth: int = 1) -> dict[str, Any]:
        """Get all connected nodes up to a given depth (BFS)."""
        if node_id not in self._nodes:
            return {"node": None, "neighbors": []}

        visited = {node_id}
        current_level = [node_id]
        all_neighbors = []

        for _ in range(depth):
            next_level = []
            for nid in current_level:
                for connected in self._adjacency.get(nid, []):
                    if connected not in visited:
                        visited.add(connected)
                        next_level.append(connected)
                        node = self._nodes.get(connected)
                        if node:
                            all_neighbors.append({
                                "node_id": node.node_id,
                                "node_type": node.node_type,
                                "properties": node.properties,
                            })
            current_level = next_level

        return {
            "node": {
                "node_id": node_id,
                "node_type": self._nodes[node_id].node_type,
                "properties": self._nodes[node_id].properties,
            },
            "neighbors": all_neighbors,
        }

    def find_attack_paths(self, source_id: str, target_id: str, max_depth: int = 5) -> list[list[str]]:
        """Find all paths between two nodes (attack path analysis)."""
        if source_id not in self._nodes or target_id not in self._nodes:
            return []

        paths: list[list[str]] = []
        self._dfs_paths(source_id, target_id, set(), [source_id], paths, max_depth)
        return paths

    def _dfs_paths(
        self,
        current: str,
        target: str,
        visited: set[str],
        path: list[str],
        results: list[list[str]],
        max_depth: int,
    ) -> None:
        if len(path) > max_depth:
            return
        if current == target:
            results.append(path.copy())
            return
        visited.add(current)
        for neighbor in self._adjacency.get(current, []):
            if neighbor not in visited:
                path.append(neighbor)
                self._dfs_paths(neighbor, target, visited, path, results, max_depth)
                path.pop()
        visited.discard(current)

    def get_high_connectivity_nodes(self, min_connections: int = 5) -> list[dict[str, Any]]:
        """Find nodes with many connections (potential pivots or C2 servers)."""
        high_conn = []
        for node_id, connections in self._adjacency.items():
            if len(connections) >= min_connections:
                node = self._nodes.get(node_id)
                if node:
                    high_conn.append({
                        "node_id": node.node_id,
                        "node_type": node.node_type,
                        "connection_count": len(connections),
                        "properties": node.properties,
                    })
        return sorted(high_conn, key=lambda x: x["connection_count"], reverse=True)

    def get_stats(self) -> dict[str, Any]:
        type_counts: dict[str, int] = {}
        for node in self._nodes.values():
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "node_types": type_counts,
        }
