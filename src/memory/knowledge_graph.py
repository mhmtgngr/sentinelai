"""Security knowledge graph for Sentinel-AI.

In-memory graph of relationships between assets, vulnerabilities,
IOCs, campaigns, and MITRE ATT&CK techniques.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class KnowledgeGraph:
    """In-memory knowledge graph for security context.

    Tracks relationships like:
    - asset -> vulnerability
    - ioc -> campaign
    - technique -> tactic
    - asset -> asset (lateral movement paths)
    """

    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[str, list[dict[str, Any]]] = defaultdict(list)

    def add_node(self, node_id: str, node_type: str, metadata: dict[str, Any] | None = None) -> None:
        """Add or update a node in the graph."""
        self._nodes[node_id] = {
            "type": node_type,
            "metadata": metadata or {},
        }

    def add_relationship(
        self,
        source: str,
        relation: str,
        target: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Add a directed relationship between two nodes."""
        if source not in self._nodes:
            self.add_node(source, "unknown")
        if target not in self._nodes:
            self.add_node(target, "unknown")

        self._edges[source].append({
            "relation": relation,
            "target": target,
            "metadata": metadata or {},
        })

    def query_neighbors(
        self,
        node_id: str,
        relation_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get all neighbors of a node, optionally filtered by relation type."""
        edges = self._edges.get(node_id, [])
        if relation_type:
            edges = [e for e in edges if e["relation"] == relation_type]

        return [
            {
                "node_id": e["target"],
                "relation": e["relation"],
                "node_data": self._nodes.get(e["target"], {}),
                "edge_metadata": e["metadata"],
            }
            for e in edges
        ]

    def get_attack_chain(self, starting_ioc: str, max_depth: int = 5) -> list[dict[str, Any]]:
        """Trace an attack chain from a starting IOC through related nodes.

        Uses BFS to find connected nodes up to max_depth.
        """
        chain: list[dict[str, Any]] = []
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(starting_ioc, 0)]

        while queue:
            node_id, depth = queue.pop(0)
            if node_id in visited or depth > max_depth:
                continue
            visited.add(node_id)

            node_data = self._nodes.get(node_id, {})
            chain.append({
                "node_id": node_id,
                "depth": depth,
                "type": node_data.get("type", "unknown"),
                "metadata": node_data.get("metadata", {}),
                "connections": len(self._edges.get(node_id, [])),
            })

            for edge in self._edges.get(node_id, []):
                if edge["target"] not in visited:
                    queue.append((edge["target"], depth + 1))

        return chain

    def get_asset_risk_score(self, asset_id: str) -> float:
        """Calculate a risk score for an asset based on graph relationships.

        Score is based on:
        - Number of connected vulnerabilities (weight: 0.3)
        - Number of associated IOCs (weight: 0.4)
        - Proximity to known attack chains (weight: 0.3)
        """
        if asset_id not in self._nodes:
            return 0.0

        neighbors = self._edges.get(asset_id, [])
        vuln_count = sum(1 for e in neighbors if e["relation"] == "has_vulnerability")
        ioc_count = sum(1 for e in neighbors if e["relation"] == "associated_ioc")
        attack_count = sum(1 for e in neighbors if e["relation"] in ("lateral_movement", "compromised_by"))

        # Normalize to 0-1 range with diminishing returns
        vuln_score = min(vuln_count / 10.0, 1.0)
        ioc_score = min(ioc_count / 5.0, 1.0)
        attack_score = min(attack_count / 3.0, 1.0)

        return 0.3 * vuln_score + 0.4 * ioc_score + 0.3 * attack_score

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self._edges.values())

    def get_nodes_by_type(self, node_type: str) -> list[str]:
        """Get all node IDs of a given type."""
        return [nid for nid, data in self._nodes.items() if data["type"] == node_type]
