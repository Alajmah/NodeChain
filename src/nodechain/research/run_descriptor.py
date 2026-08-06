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
    """Write ``content`` to ``path`` atomically with write-once semantics.

    Sequence:
    1. Create a unique sibling staging file (exclusive creation — fails if
       it already exists).
    2. Write content + flush + fsync the staging file.
    3. Reject if the target already exists (no-overwrite publication).
    4. Atomic rename (os.replace).
    5. Fsync the parent directory where supported.

    Staging file is cleaned up on any failure path.
    """
    import uuid

    path.parent.mkdir(parents=True, exist_ok=True)

    # Unique staging file (prevents collision with concurrent writes).
    staging = path.with_suffix(f".{uuid.uuid4().hex[:8]}.staging")

    try:
        # Exclusive creation — fails if the staging file already exists.
        fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())

        # Reject if target already exists (write-once / no-overwrite).
        if path.exists():
            raise FileExistsError(
                f"target already exists (write-once violated): {path}"
            )

        # Atomic publication.
        os.replace(staging, path)

        # Fsync parent directory where supported (Linux/macOS, not Windows).
        dir_fd = None
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            os.fsync(dir_fd)
        except (OSError, AttributeError):
            pass  # Windows or unsupported — fsync of dir is best-effort
        finally:
            if dir_fd is not None:
                os.close(dir_fd)
    except Exception:
        # Clean up staging on any failure path.
        try:
            if staging.exists():
                staging.unlink()
        except OSError:
            pass
        raise

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
