"""Memory and knowledge graph API routes."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from pydantic import BaseModel

router = APIRouter()


class SearchQuery(BaseModel):
    query: dict[str, Any]
    top_k: int = 5


@router.post("/search")
async def search_similar(search: SearchQuery, request: Request) -> dict[str, Any]:
    """Search for similar events in vector memory."""
    # Vector store would be accessed from app state
    return {"message": "Vector search endpoint", "query": search.query, "top_k": search.top_k}


@router.get("/knowledge-graph/stats")
async def knowledge_graph_stats(request: Request) -> dict[str, Any]:
    """Get knowledge graph statistics."""
    return {"message": "Knowledge graph stats endpoint"}


@router.get("/knowledge-graph/neighbors/{node_id}")
async def get_neighbors(node_id: str, request: Request, depth: int = 1) -> dict[str, Any]:
    """Get neighbors of a node in the knowledge graph."""
    return {"node_id": node_id, "depth": depth}


@router.get("/learning/stats")
async def learning_stats(request: Request) -> dict[str, Any]:
    """Get learning engine statistics."""
    return {"message": "Learning engine stats endpoint"}
