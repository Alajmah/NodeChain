"""Persisted operational run descriptor.

Records the inputs, paths, and metadata needed to resume a paused run or
finalize a terminal bundle — without requiring the operator to resupply
``--corpus``, ``--brief``, or ``--db``.

The descriptor is written atomically (staging + fsync + rename) so a crash
cannot leave a partially readable file. It includes its own canonical digest
for identity verification on reload.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


# --------------------------------------------------------------------------- #
# Atomic write helper
# --------------------------------------------------------------------------- #


def _atomic_write(path: Path, content: str) -> Path:
    """Write ``content`` to ``path`` atomically: staging file → fsync → rename.

    The staging file is a sibling of the target so the rename is atomic on
    the same filesystem. Overwrites are rejected (no silent replacement of
    an existing finalized file).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    staging = path.with_suffix(path.suffix + ".staging")
    with open(staging, "w", encoding="utf-8") as fh:
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(staging, path)
    return path


# --------------------------------------------------------------------------- #
# Descriptor model
# --------------------------------------------------------------------------- #


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
    descriptor_digest: str = ""

    @model_validator(mode="after")
    def _compute_digest(self) -> "RunDescriptor":
        """Compute canonical digest over all fields except descriptor_digest."""
        data = self.model_dump(mode="json")
        data.pop("descriptor_digest", None)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        # Use object.__setattr__ to bypass frozen if needed; RunDescriptor
        # is not frozen so direct assignment works.
        if self.descriptor_digest != digest:
            self.descriptor_digest = digest
        return self


def descriptor_path(workspace_dir: str | Path, run_id: str) -> Path:
    """Return the path to a run's descriptor file."""
    return Path(workspace_dir) / f"{run_id}.descriptor.json"


def save_descriptor(
    workspace_dir: str | Path, desc: RunDescriptor
) -> Path:
    """Write a run descriptor atomically to the workspace directory."""
    p = descriptor_path(workspace_dir, desc.run_id)
    # Recompute digest before writing.
    data = desc.model_dump(mode="json")
    data.pop("descriptor_digest", None)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    data["descriptor_digest"] = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    content = json.dumps(data, indent=2, sort_keys=True)
    return _atomic_write(p, content)


def load_descriptor(
    workspace_dir: str | Path, run_id: str
) -> RunDescriptor:
    """Load a run descriptor by run ID. Raises FileNotFoundError if absent.

    Verifies the descriptor digest on reload.
    """
    p = descriptor_path(workspace_dir, run_id)
    if not p.exists():
        raise FileNotFoundError(f"no descriptor for run {run_id} in {workspace_dir}")
    data = json.loads(p.read_text(encoding="utf-8"))
    # Verify digest.
    stored_digest = data.pop("descriptor_digest", "")
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    expected_digest = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()
    if stored_digest != expected_digest:
        raise ValueError(
            f"descriptor digest mismatch for run {run_id}: "
            f"expected {expected_digest}, got {stored_digest}"
        )
    data["descriptor_digest"] = stored_digest
    return RunDescriptor(**data)


# --------------------------------------------------------------------------- #
# Review / Outcome records (atomic)
# --------------------------------------------------------------------------- #


def save_review_record(
    workspace_dir: str | Path, run_id: str, record: dict[str, Any]
) -> Path:
    """Write a review record atomically."""
    p = Path(workspace_dir) / f"{run_id}.review.{record.get('review_id', 'unknown')[:8]}.json"
    return _atomic_write(p, json.dumps(record, indent=2, sort_keys=True))


def save_outcome_record(
    workspace_dir: str | Path, run_id: str, review_id: str, record: dict[str, Any]
) -> Path:
    """Write a resume outcome record atomically."""
    p = Path(workspace_dir) / f"{run_id}.outcome.{review_id[:8]}.json"
    return _atomic_write(p, json.dumps(record, indent=2, sort_keys=True))
