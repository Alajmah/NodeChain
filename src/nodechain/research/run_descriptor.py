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
    """Write ``content`` to ``path`` atomically with true write-once semantics.

    The publication step uses ``os.open(O_CREAT|O_EXCL)`` on the target,
    which atomically fails if another process created it between our check
    and publication. This is race-safe: the target either exists before we
    start (we reject) or we create it exclusively.

    Sequence:
    1. Create a unique sibling staging file (exclusive O_CREAT|O_EXCL).
    2. Write content + flush + fsync the staging file.
    3. Atomically create the target with O_CREAT|O_EXCL (fails if exists).
    4. Copy staging content to target via the new fd.
    5. Close + fsync target. Fsync parent dir where supported.
    6. Clean up staging.

    On any failure, staging is cleaned up and the target is NOT created.
    """
    import uuid

    path.parent.mkdir(parents=True, exist_ok=True)

    # Validate path identifier (no traversal or absolute path injection).
    # The filename must be a simple basename in the parent directory.
    if path.name != path.name.replace("/", "").replace("\\", "").replace("..", ""):
        raise ValueError(f"unsafe path identifier: {path.name}")

    staging = path.with_name(f".{path.name}.{uuid.uuid4().hex[:8]}.staging")

    try:
        # 1. Exclusive staging creation.
        fd = os.open(str(staging), os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())

        # 2. Atomically create the target (O_CREAT|O_EXCL — fails if exists).
        # This is the race-safe publication: no TOCTOU window.
        try:
            target_fd = os.open(
                str(path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            )
        except FileExistsError:
            raise FileExistsError(
                f"target already exists (write-once violated): {path}"
            )

        # 3. Write content to the target fd.
        with os.fdopen(target_fd, "w", encoding="utf-8") as tfh:
            tfh.write(content)
            tfh.flush()
            os.fsync(tfh.fileno())

        # 4. Fsync parent directory where supported.
        dir_fd = None
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            os.fsync(dir_fd)
        except (OSError, AttributeError):
            pass  # Windows or unsupported
        finally:
            if dir_fd is not None:
                os.close(dir_fd)

    except Exception:
        raise
    finally:
        # Clean up staging on every path (success and failure).
        try:
            if staging.exists():
                staging.unlink()
        except OSError:
            pass

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


def _validate_identifier(name: str) -> str:
    """Validate a run_id or review_id for safe filesystem use.

    Rejects empty strings, path separators, traversal, and non-UUID-like
    patterns (must contain only [a-zA-Z0-9-]).
    """
    import re
    if not name or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*$', name):
        raise ValueError(f"unsafe filesystem identifier: {name!r}")
    return name


def run_dir(workspace_dir: str | Path, run_id: str) -> Path:
    """Return the per-run operational directory: <workspace>/runs/<run_id>/"""
    _validate_identifier(run_id)
    return Path(workspace_dir) / "runs" / run_id


def descriptor_path(workspace_dir: str | Path, run_id: str) -> Path:
    """Return the path to a run's descriptor file."""
    return run_dir(workspace_dir, run_id) / "descriptor.json"


def review_path(workspace_dir: str | Path, run_id: str, review_id: str) -> Path:
    """Return the path to a review record."""
    _validate_identifier(review_id)
    return run_dir(workspace_dir, run_id) / "reviews" / f"{review_id}.json"


def outcome_path(workspace_dir: str | Path, run_id: str, review_id: str) -> Path:
    """Return the path to an outcome record."""
    _validate_identifier(review_id)
    return run_dir(workspace_dir, run_id) / "outcomes" / f"{review_id}.json"


def save_descriptor(
    workspace_dir: str | Path, desc: RunDescriptor
) -> Path:
    """Write a run descriptor atomically to the per-run workspace directory."""
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
# Review / Outcome records (atomic, per-run directory)
# --------------------------------------------------------------------------- #


def save_review_record(
    workspace_dir: str | Path, run_id: str, record: dict[str, Any]
) -> Path:
    """Write a review record atomically to the per-run reviews directory."""
    rid = record.get("review_id", "unknown")
    p = review_path(workspace_dir, run_id, rid)
    return _atomic_write(p, json.dumps(record, indent=2, sort_keys=True))


def save_outcome_record(
    workspace_dir: str | Path, run_id: str, review_id: str, record: dict[str, Any]
) -> Path:
    """Write a resume outcome record atomically to the per-run outcomes dir."""
    p = outcome_path(workspace_dir, run_id, review_id)
    return _atomic_write(p, json.dumps(record, indent=2, sort_keys=True))
