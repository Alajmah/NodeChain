"""Canonical JSON serialization and digest helpers for ResearchWorkspaceBundleV1.

The canonical form is defined as:

* UTF-8 encoded
* ``json.dumps`` with ``sort_keys=True``
* Compact separators ``(",", ":")`` (no insignificant whitespace)
* Exactly one terminal newline (``\\n``)
* ``allow_nan=False`` — NaN/Infinity are rejected (raises ``ValueError``)
* Stable enum serialization: ``str`` enums serialize to their ``.value``

The same input data always produces byte-identical output.
"""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel


def _to_serializable(obj: Any) -> Any:
    """Recursively convert ``obj`` into a structure composed only of
    JSON-native types, with stable enum and datetime serialization."""
    if isinstance(obj, BaseModel):
        return _to_serializable(
            obj.model_dump(mode="json", by_alias=True)
        )
    if isinstance(obj, Enum):
        return obj.value if isinstance(obj, str) else _to_serializable(obj.value)
    if isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_serializable(v) for v in obj]
    return obj


def canonical_json(data: Any) -> str:
    """Serialize ``data`` to a canonical JSON string.

    See module docstring for the exact canonical form.
    """
    serializable = _to_serializable(data)
    payload = json.dumps(
        serializable,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return payload + "\n"


def canonical_json_bytes(data: Any) -> bytes:
    """Serialize ``data`` to canonical JSON and encode as UTF-8."""
    return canonical_json(data).encode("utf-8")


def compute_sha256(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def compute_file_hash(path: Path) -> str:
    """Return the lowercase hex SHA-256 digest of the file at ``path``."""
    hasher = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# --------------------------------------------------------------------------- #
# Set-like array canonicalization
# --------------------------------------------------------------------------- #

#: Set-like array fields whose element order carries no semantic meaning. These
#: hold opaque IDs (evidence/source/citation/claim ids, adapter names, etc.)
#: and are therefore canonicalized by sorting their elements prior to
#: serialization, so two bundles that differ only in ID ordering produce
#: byte-identical canonical output. Semantically ordered arrays (trace events,
#: policy decisions, plan steps, steps_completed) are deliberately NOT listed
#: here and retain their order. Only arrays of scalar strings/IDs are listed;
#: arrays of objects are intentionally excluded to keep ordering faithful.
DEFAULT_SET_LIKE_PATHS: tuple[str, ...] = (
    # Top-level document-level arrays of scalars.
    "checks_run",            # ResearchValidations
    "adapters_required",     # ResearchPlan
    "adapters_used",         # ResearchWorkspaceReport
    # Per-record arrays (applied to every element of the enclosing collection).
    "evidence.source_ids",
    "claims.supporting_evidence_ids",
    "claims.contradicting_evidence_ids",
    "claims.citation_ids",
    "citations.evidence_ids",
    "uncertainties.affected_claim_ids",
    "failures.affected_claim_ids",
    # Nested under a containing object/collection (not top-level).
    "sources.authors",                       # SourceRecord inside sources.sources[]
    "scope.domains",                         # BriefScope inside brief.scope
    "constraints.required_adapters",         # BriefConstraints inside brief.constraints
    "constraints.excluded_adapters",         # BriefConstraints inside brief.constraints
    # Per-record nested ID arrays.
    "claims.uncertainty_markers.affected_claim_ids",
)


def _split_path(path: str) -> tuple[str, ...]:
    return tuple(p for p in path.split(".") if p)


def _normalize_set_like(
    data: Any, paths: tuple[tuple[str, ...], ...]
) -> Any:
    """Return a deep-copied structure where every designated set-like array
    field is replaced by its sorted-elements version.

    ``paths`` is a tuple of key-tuples. A path traverses dicts and, when it
    meets a list mid-path, descends into every element. The final path segment
    names the array to sort. Arrays whose values are not directly sortable as
    scalars (e.g. arrays of objects) are sorted by their canonical-JSON
    representation, which is deterministic.
    """
    if isinstance(data, dict):
        out = {k: v for k, v in data.items()}
        for path in paths:
            _apply_path(out, path)
        return out
    return data


def _apply_path(container: dict[str, Any], path: tuple[str, ...]) -> None:
    """Apply one set-like normalization path to ``container`` (a dict),
    mutating it in place."""
    if not path:
        return
    head, rest = path[0], path[1:]
    if head not in container:
        return
    value = container[head]
    if not rest:
        # Final segment: sort the array if present.
        if isinstance(value, list):
            container[head] = _sort_array(value)
        return
    # Descend: dicts recurse; lists fan out over every element.
    if isinstance(value, dict):
        _apply_path(value, rest)
    elif isinstance(value, list):
        new_list: list[Any] = []
        for item in value:
            if isinstance(item, dict):
                _apply_path(item, rest)
            new_list.append(item)
        container[head] = new_list


def _sort_array(arr: list[Any]) -> list[Any]:
    """Return a sorted copy of ``arr``. Scalars sort directly; objects sort by
    their canonical-JSON text so the result is deterministic and stable."""
    if not arr:
        return []
    first = arr[0]
    if isinstance(first, (dict, list)):
        return sorted(arr, key=lambda v: canonical_json(v))
    try:
        return sorted(arr)
    except TypeError:
        # Mixed/unorderable fallback: sort by canonical-JSON text.
        return sorted(arr, key=lambda v: canonical_json(v))


def canonical_json_with_set_normalization(
    data: Any,
    set_like_paths: "Sequence[str] | None" = None,
) -> str:
    """Serialize ``data`` to canonical JSON after normalizing designated
    set-like array fields by sorting their elements.

    For set-like arrays (arrays of IDs where order is not semantically
    meaningful — e.g. ``evidence_ids``, ``source_ids``, ``citation_ids``) the
    elements are sorted before serialization, so two payloads that differ only
    in the order of those arrays produce byte-identical output. Semantically
    ordered arrays (trace ``events``, ``policy_decisions``, ``steps``,
    ``steps_completed``) are preserved as-is because they are NOT in the
    designated set-like set.

    ``set_like_paths`` defaults to :data:`DEFAULT_SET_LIKE_PATHS`. Each entry is
    a dotted path; a path may cross arrays (it then fans out over every element
    of the array).
    """
    from typing import Sequence  # local to avoid top-level typing churn

    paths = (
        tuple(_split_path(p) for p in set_like_paths)
        if set_like_paths is not None
        else tuple(_split_path(p) for p in DEFAULT_SET_LIKE_PATHS)
    )
    serializable = _to_serializable(data)
    normalized = _normalize_set_like(serializable, paths)
    payload = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return payload + "\n"
