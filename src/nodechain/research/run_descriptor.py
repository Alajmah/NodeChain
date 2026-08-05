"""Persisted operational run descriptor.

Records the inputs, paths, and metadata needed to resume a paused run or
finalize a terminal bundle — without requiring the operator to resupply
``--corpus``, ``--brief``, or ``--db``.

The descriptor is written as a JSON file in the operational workspace
directory alongside the runtime database and trace files.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RunDescriptor(BaseModel):
    """Persisted metadata for a research workspace run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    chain_id: str
    question: str
    focus_areas: tuple[str, ...] = ()
    corpus_path: str
    corpus_digest: str
    corpus_version: str
    scenario_id: str
    db_path: str
    trace_dir: str
    workspace_dir: str
    blueprint_version: str = "1.0.0"
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    kek_path: str = ""


def descriptor_path(workspace_dir: str | Path, run_id: str) -> Path:
    """Return the path to a run's descriptor file."""
    return Path(workspace_dir) / f"{run_id}.descriptor.json"


def save_descriptor(
    workspace_dir: str | Path, desc: RunDescriptor
) -> Path:
    """Write a run descriptor to the workspace directory."""
    p = descriptor_path(workspace_dir, desc.run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        desc.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return p


def load_descriptor(
    workspace_dir: str | Path, run_id: str
) -> RunDescriptor:
    """Load a run descriptor by run ID. Raises FileNotFoundError if absent."""
    p = descriptor_path(workspace_dir, run_id)
    if not p.exists():
        raise FileNotFoundError(f"no descriptor for run {run_id} in {workspace_dir}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return RunDescriptor(**data)
