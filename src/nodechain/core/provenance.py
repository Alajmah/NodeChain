"""Flat-result provenance versioning v1.

Provides strict version classification and compatibility gating for the
existing transient search-result and source-ingestion boundary.

Classification is performed on **raw dictionaries** before any Pydantic
defaults are applied, so that a pre-version record cannot be silently
upgraded to current.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Any


# ── RFC 3339 date-time validator ─────────────────────────────────

# Two-stage validation: a strict bounded regex pre-check (component ranges
# AND the presence of a timezone — RFC 3339 date-time requires one), followed
# by semantic calendar validation via the standard library.
#
# Strict subset note (leap seconds): RFC 3339 permits a second value of 60
# for positive leap seconds. NodeChain intentionally REJECTS :60 — the
# downstream clock/epoch math does not implement leap-second tables, and
# accepting a value that cannot be faithfully represented downstream would
# be a silent integrity gap. This is a deliberate strict subset of RFC 3339,
# not a claim of complete leap-second support. Provenance timestamps are
# UTC civil-time only; leap seconds never legitimately appear.
#
# Mechanism note: R6 authorized jsonschema.FormatChecker for the semantic
# stage. Empirically the installed jsonschema does not register a
# `date-time` checker without the optional `rfc3339-validator` package, so
# FormatChecker silently ACCEPTS impossible dates such as 2026-02-30.
# datetime.fromisoformat performs the calendar check in the standard library.
# However, fromisoformat NORMALIZES overflowing offset minutes
# (e.g. +14:60 -> +15:00), so the regex below is the authority for all
# component-range bounds (time-hour 00-23, time-minute 00-59, time-second
# 00-59, offset-hour 00-23, offset-minute 00-59) and fromisoformat is the
# authority for calendar validity (month/day ranges, leap years).

_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}"
    r"[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?"
    r"(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$"
)


def is_valid_timestamp(ts: str) -> bool:
    """Check that a timestamp is a valid RFC 3339 date-time with timezone.

    Two stages: (1) a strict structural check enforcing component ranges
    (time-hour 00-23, time-minute/second 00-59, offset-hour 00-23,
    offset-minute 00-59) and required timezone; (2) semantic calendar
    validation via ``datetime.fromisoformat`` (month/day ranges, leap years).

    Rejects impossible dates (2026-02-30, 2025-02-29 non-leap, month 13),
    out-of-range clock fields (hour 24, minute/second 60), and overflowing
    offset minutes (+14:60). Accepts trailing ``Z`` and ``+/-HH:MM`` offsets.

    Leap seconds (:60) are rejected as a deliberate NodeChain strict subset
    of RFC 3339 (see module notes above).
    """
    if not isinstance(ts, str):
        return False
    # Strict structural pre-check: component ranges + required timezone.
    if not _RFC3339_RE.match(ts):
        return False
    # Semantic calendar validation via the standard library.
    try:
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00").replace("z", "+00:00"))
        return True
    except ValueError:
        return False

# ── Version constants ─────────────────────────────────────────────

CURRENT_PROVENANCE_VERSION = 1
LEGACY_PROVENANCE_VERSION = 0

REQUIRED_FIELDS = ("adapter", "query", "retrieval_timestamp")


# ── Classification ────────────────────────────────────────────────

class ProvenanceMode(str, enum.Enum):
    CURRENT = "current"
    LEGACY = "legacy"
    PRE_VERSION = "pre_version"


class ProvenanceClassification(str, enum.Enum):
    """Result of inspecting a raw provenance record."""
    CURRENT_COMPLETE = "current_complete"
    CURRENT_INCOMPLETE = "current_incomplete"
    LEGACY_COMPLETE = "legacy_complete"
    LEGACY_INCOMPLETE = "legacy_incomplete"
    PRE_VERSION_COMPLETE = "pre_version_complete"
    PRE_VERSION_INCOMPLETE = "pre_version_incomplete"
    UNKNOWN_VERSION = "unknown_version"
    MALFORMED_VERSION = "malformed_version"


# ── Stable failure codes ──────────────────────────────────────────

class ProvenanceFailureCode(str, enum.Enum):
    PROVENANCE_VERSION_MISSING_LIVE = "PROVENANCE_VERSION_MISSING_LIVE"
    PROVENANCE_CURRENT_INCOMPLETE = "PROVENANCE_CURRENT_INCOMPLETE"
    PROVENANCE_LEGACY_INCOMPLETE = "PROVENANCE_LEGACY_INCOMPLETE"
    PROVENANCE_PRE_VERSION_INCOMPLETE = "PROVENANCE_PRE_VERSION_INCOMPLETE"
    PROVENANCE_VERSION_MALFORMED = "PROVENANCE_VERSION_MALFORMED"
    PROVENANCE_VERSION_UNKNOWN = "PROVENANCE_VERSION_UNKNOWN"
    PROVENANCE_MODE_MIXED = "PROVENANCE_MODE_MIXED"
    PROVENANCE_VERSION_CONFLICT = "PROVENANCE_VERSION_CONFLICT"


class ProvenanceError(Exception):
    """Typed exception for provenance-integrity violations."""

    def __init__(self, code: ProvenanceFailureCode, context: str = "") -> None:
        self.code = code
        self.context = context
        super().__init__(f"{code.value}: {context}" if context else code.value)


# ── Helpers ───────────────────────────────────────────────────────

def _is_strict_int(value: Any) -> bool:
    """True only for genuine int, excluding bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _is_complete(record: dict[str, Any]) -> bool:
    """Check that all required fields are present as non-blank strings.

    Accepts both the raw-result field names (origin_api, query_used,
    retrieved_at) and the normalized provenance field names (adapter,
    query, retrieval_timestamp). Non-string values are NOT accepted.
    """
    field_aliases = {
        "adapter": ["adapter", "origin_api"],
        "query": ["query", "query_used"],
        "retrieval_timestamp": ["retrieval_timestamp", "retrieved_at"],
    }
    for canonical, aliases in field_aliases.items():
        found = False
        for alias in aliases:
            val = record.get(alias)
            if val is not None:
                if isinstance(val, str) and val.strip() != "":
                    found = True
                    break
        if not found:
            return False
    return True


# ── Classifier ────────────────────────────────────────────────────

def classify_provenance(record: dict[str, Any]) -> ProvenanceClassification:
    """Classify a raw provenance record by version and completeness.

    Inspects the raw dictionary **before** any model defaults.
    """
    has_version = "provenance_version" in record

    if not has_version:
        complete = _is_complete(record)
        return (
            ProvenanceClassification.PRE_VERSION_COMPLETE
            if complete
            else ProvenanceClassification.PRE_VERSION_INCOMPLETE
        )

    version = record["provenance_version"]

    # Reject booleans before int check
    if isinstance(version, bool):
        return ProvenanceClassification.MALFORMED_VERSION

    if not _is_strict_int(version):
        return ProvenanceClassification.MALFORMED_VERSION

    if version < 0:
        return ProvenanceClassification.MALFORMED_VERSION

    complete = _is_complete(record)

    if version == CURRENT_PROVENANCE_VERSION:
        return (
            ProvenanceClassification.CURRENT_COMPLETE
            if complete
            else ProvenanceClassification.CURRENT_INCOMPLETE
        )

    if version == LEGACY_PROVENANCE_VERSION:
        return (
            ProvenanceClassification.LEGACY_COMPLETE
            if complete
            else ProvenanceClassification.LEGACY_INCOMPLETE
        )

    return ProvenanceClassification.UNKNOWN_VERSION


def classification_to_mode(c: ProvenanceClassification) -> ProvenanceMode:
    """Map a classification to its mode."""
    if c in (ProvenanceClassification.CURRENT_COMPLETE, ProvenanceClassification.CURRENT_INCOMPLETE):
        return ProvenanceMode.CURRENT
    if c in (ProvenanceClassification.LEGACY_COMPLETE, ProvenanceClassification.LEGACY_INCOMPLETE):
        return ProvenanceMode.LEGACY
    if c in (ProvenanceClassification.PRE_VERSION_COMPLETE, ProvenanceClassification.PRE_VERSION_INCOMPLETE):
        return ProvenanceMode.PRE_VERSION
    # MALFORMED and UNKNOWN have no mode
    raise ValueError(f"Classification {c} has no mode")


# ── Provenance entry ──────────────────────────────────────────────

@dataclass
class ProvenanceEntry:
    """A single origin's provenance record."""
    version: int | None
    adapter: str
    query: str
    retrieval_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "adapter": self.adapter,
            "query": self.query,
            "retrieval_timestamp": self.retrieval_timestamp,
        }

    @classmethod
    def from_raw_result(cls, raw: dict[str, Any]) -> ProvenanceEntry:
        """Build an entry from a raw search result dict.

        Missing version stays None. Explicit 0 stays 0.
        Malformed versions raise.
        """
        version = raw.get("provenance_version")
        if version is not None:
            if not _is_strict_int(version):
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
                    f"from_raw_result: malformed version {version!r}",
                )
            if version < 0:
                raise ProvenanceError(
                    ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
                    f"from_raw_result: negative version {version}",
                )
        return cls(
            version=version,
            adapter=raw.get("origin_api", ""),
            query=raw.get("query_used", ""),
            retrieval_timestamp=raw.get("retrieved_at", ""),
        )


# ── Deduplication helpers ─────────────────────────────────────────

def _version_rank(v: Any) -> int:
    """Stable sort rank for version values (avoids None vs int TypeError)."""
    if v is None:
        return 0
    if _is_strict_int(v):
        return v + 1  # shift so 0→1, 1→2, avoiding collision with None→0
    return -1  # malformed sorts first but will be rejected later


def _entry_sort_key(e: dict[str, Any]) -> tuple:
    """Canonical sort key for provenance entries."""
    return (
        _version_rank(e.get("version")),
        e.get("adapter", ""),
        e.get("query", ""),
        e.get("retrieval_timestamp", ""),
    )


def merge_provenance_entries(
    existing: list[dict[str, Any]],
    new_entry: dict[str, Any],
) -> list[dict[str, Any]]:
    """Merge a new entry into an existing list, deduplicating and sorting.

    Uses a tuple identity key to avoid delimiter collisions.
    """
    combined = list(existing) + [new_entry]
    seen: set[tuple] = set()
    deduped: list[dict[str, Any]] = []
    for e in combined:
        key = (
            e.get("version"),
            e.get("adapter"),
            e.get("query"),
            e.get("retrieval_timestamp"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(e)
    return sorted(deduped, key=_entry_sort_key)


def check_mode_consistency(entries: list[dict[str, Any]]) -> None:
    """Reject mixed current/legacy/pre-version modes in deduplicated entries."""
    if not entries:
        return
    modes: set[str] = set()
    for e in entries:
        v = e.get("version")
        if v == CURRENT_PROVENANCE_VERSION:
            modes.add("current")
        elif v == LEGACY_PROVENANCE_VERSION:
            modes.add("legacy")
        elif v is None:
            modes.add("pre_version")
        else:
            modes.add("other")
    if len(modes) > 1:
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_MODE_MIXED,
            f"Found modes: {sorted(modes)}",
        )


def derive_dedup_origins(entries: list[dict[str, Any]]) -> list[str]:
    """Derive _dedup_origins from authoritative entries (backward compat)."""
    origins: list[str] = []
    for e in entries:
        adapter = e.get("adapter", "")
        if adapter and adapter not in origins:
            origins.append(adapter)
    return origins


# ── Live-result gate ──────────────────────────────────────────────

def validate_live_result(raw: dict[str, Any], index: int) -> None:
    """Validate that a live search result has current complete provenance.

    Raises ProvenanceError on any violation.
    """
    has_version = "provenance_version" in raw
    if not has_version:
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE,
            f"result index {index}: no provenance_version on live result",
        )

    c = classify_provenance(raw)
    if c == ProvenanceClassification.CURRENT_COMPLETE:
        # Also validate timestamp format on live results
        ts = raw.get("retrieved_at", raw.get("retrieval_timestamp", ""))
        if not is_valid_timestamp(ts):
            raise ProvenanceError(
                ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE,
                f"result index {index}: invalid retrieval timestamp {ts!r}",
            )
        return
    if c == ProvenanceClassification.CURRENT_INCOMPLETE:
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_CURRENT_INCOMPLETE,
            f"result index {index}: current version with incomplete fields",
        )
    if c in (ProvenanceClassification.LEGACY_COMPLETE, ProvenanceClassification.LEGACY_INCOMPLETE):
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_VERSION_CONFLICT,
            f"result index {index}: legacy version on live result",
        )
    if c in (ProvenanceClassification.PRE_VERSION_COMPLETE, ProvenanceClassification.PRE_VERSION_INCOMPLETE):
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE,
            f"result index {index}: pre-version record on live result",
        )
    if c == ProvenanceClassification.MALFORMED_VERSION:
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_VERSION_MALFORMED,
            f"result index {index}: malformed version value",
        )
    if c == ProvenanceClassification.UNKNOWN_VERSION:
        raise ProvenanceError(
            ProvenanceFailureCode.PROVENANCE_VERSION_UNKNOWN,
            f"result index {index}: unknown version",
        )


# ── Historical ingestion gate ─────────────────────────────────────

def classify_for_ingestion(raw: dict[str, Any]) -> ProvenanceClassification:
    """Classify a historical record for source ingestion compatibility."""
    return classify_provenance(raw)


def is_ingestible(c: ProvenanceClassification) -> bool:
    """Whether a classification permits historical ingestion."""
    return c in (
        ProvenanceClassification.CURRENT_COMPLETE,
        ProvenanceClassification.LEGACY_COMPLETE,
        ProvenanceClassification.PRE_VERSION_COMPLETE,
    )
