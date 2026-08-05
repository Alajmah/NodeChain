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
from typing import Any

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
