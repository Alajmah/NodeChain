"""Node Manifest — describes a node's identity and capabilities."""

from __future__ import annotations

from pydantic import BaseModel, Field

from nodechain.core.contract import NodeContract


class NodeManifest(BaseModel):
    """
    A node's identity card. Registered with the runtime.
    Contains the contract and metadata about the node.
    """

    node_id: str
    node_type: str  # e.g., "model", "deterministic", "hybrid"
    name: str
    description: str
    version: str = "1.0.0"
    contract: NodeContract
    tags: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid"}
