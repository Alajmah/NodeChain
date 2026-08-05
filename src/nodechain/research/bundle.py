"""Bundle reader/writer with atomic finalization for ResearchWorkspaceBundleV1.

Finalization contract
---------------------
1. The caller writes all non-manifest documents into a *staging* directory
   (``<target>.staging/``) via :class:`BundleWriter`.
2. ``BundleWriter.finalize`` computes per-file hashes, computes the
   ``bundle_digest``, writes ``manifest.json`` last, validates every document
   against its JSON schema, validates cross-references, then atomically renames
   the staging directory onto the final destination via :func:`os.replace`.
3. On any failure the staging directory is removed; no partial bundle is left.
4. A finalized bundle is never overwritten — :func:`os.replace` is only reached
   if the destination does not already exist.

Path safety: file basenames written into the bundle are validated to reject
absolute paths, parent traversal (``..``), and symlink escape.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Sequence

import jsonschema
from pydantic import BaseModel

from nodechain.validation.schema_validator import SCHEMA_ROOT

from .exceptions import (
    BundleError,
    BundleFinalizationError,
    BundleIntegrityError,
    BundleValidationError,
)
from .models import (
    BundleVersion,
    FileHash,
    ResearchWorkspaceManifest,
    TargetType,
)
from .serialization import (
    canonical_json,
    canonical_json_bytes,
    canonical_json_with_set_normalization,
    compute_file_hash,
    compute_sha256,
)

# --------------------------------------------------------------------------- #
# Schema loading and $ref resolution
# --------------------------------------------------------------------------- #

# Schema-root resolution is shared with the rest of NodeChain via
# ``nodechain.validation.schema_validator.SCHEMA_ROOT``. Do not duplicate the
# package-vs-source layout probe here.
_DEFINITIONS_REF = "nodechain://schemas/semantic_types/research_workspace_definitions"

_SCHEMA_REGISTRY: Any | None = None


def _registry() -> Any:
    """Build (and cache) a ``referencing`` Registry that resolves the shared
    definitions document so per-document schemas can dereference their ``$ref``
    pointers."""
    global _SCHEMA_REGISTRY
    if _SCHEMA_REGISTRY is not None:
        return _SCHEMA_REGISTRY
    try:
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012
    except ImportError as exc:  # pragma: no cover
        raise BundleError(
            "The 'referencing' library is required for $ref resolution"
        ) from exc

    def _retrieve(uri: str) -> Resource:
        if uri.startswith("nodechain://schemas/"):
            rel = uri[len("nodechain://schemas/"):]
            path = SCHEMA_ROOT / f"{rel}.json"
            if not path.exists():
                raise FileNotFoundError(f"Schema not found: {uri} ({path})")
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
            return Resource(contents=doc, specification=DRAFT202012)
        raise FileNotFoundError(f"Unsupported schema URI: {uri}")

    _SCHEMA_REGISTRY = Registry(retrieve=_retrieve)
    return _SCHEMA_REGISTRY


def _schema_ref_for(filename: str) -> str:
    """Map a bundle filename to its nodechain schema_ref URI.

    Bundle filenames and schema filenames differ (e.g. ``brief.json`` vs
    ``research_brief.json``), so an explicit mapping is required.
    """
    stem = filename[:-5] if filename.endswith(".json") else filename
    return _FILENAME_TO_SCHEMA_REF[stem]


_FILENAME_TO_SCHEMA_REF: dict[str, str] = {
    "manifest": "nodechain://schemas/semantic_types/research_workspace_manifest",
    "brief": "nodechain://schemas/semantic_types/research_brief",
    "run": "nodechain://schemas/semantic_types/research_run",
    "plan": "nodechain://schemas/semantic_types/research_plan",
    "sources": "nodechain://schemas/semantic_types/research_sources",
    "evidence": "nodechain://schemas/semantic_types/research_evidence",
    "claims": "nodechain://schemas/semantic_types/research_claims",
    "citations": "nodechain://schemas/semantic_types/research_citations",
    "uncertainties": "nodechain://schemas/semantic_types/research_uncertainties",
    "validations": "nodechain://schemas/semantic_types/research_validations",
    "policy-decisions": "nodechain://schemas/semantic_types/research_policy_decisions",
    "review-decisions": "nodechain://schemas/semantic_types/research_review_decisions",
    "failures": "nodechain://schemas/semantic_types/research_failures",
    "report": "nodechain://schemas/semantic_types/research_workspace_report",
    "trace": "nodechain://schemas/semantic_types/research_trace",
}


# --------------------------------------------------------------------------- #
# Canonical bundle layout
# --------------------------------------------------------------------------- #

#: Ordered list of the 15 canonical bundle filenames. The manifest is written
#: LAST during finalization (it digests everything else), so it appears at the
#: end of the inventory but is listed first for discoverability.
BUNDLE_FILES: tuple[str, ...] = (
    "manifest.json",
    "brief.json",
    "run.json",
    "plan.json",
    "sources.json",
    "evidence.json",
    "claims.json",
    "citations.json",
    "uncertainties.json",
    "validations.json",
    "policy-decisions.json",
    "review-decisions.json",
    "failures.json",
    "trace.json",
    "report.json",
)

#: Filenames that must be present and digested (every file except the manifest,
#: whose own digest is the bundle_digest).
_NON_MANIFEST_FILES: tuple[str, ...] = tuple(f for f in BUNDLE_FILES if f != "manifest.json")

SUPPORTED_BUNDLE_VERSION = "1.0"


# --------------------------------------------------------------------------- #
# Filename-aware set-like normalization policy
# --------------------------------------------------------------------------- #
#
# Bundle files are persisted through ``canonical_json_with_set_normalization``
# (NOT plain ``canonical_json_bytes``) so that the on-disk bytes, per-file
# hashes, and ``bundle_digest`` are all invariant under reordering of set-like
# ID arrays. Each bundle filename declares the dotted set-like paths that apply
# to its document shape. Paths are scoped to the document root of that file
# (e.g. ``"sources.authors"`` resolves ``root["sources"][*]["authors"]``).
#
# Semantically ordered arrays (trace ``events``, plan ``steps``, report
# ``steps_completed``, policy-decisions, review-decisions, evidence ordering)
# are deliberately NOT listed and retain their input order.
_NORMALIZATION_PATHS_BY_FILE: dict[str, tuple[str, ...]] = {
    "brief.json": (
        "scope.domains",
        "constraints.required_adapters",
        "constraints.excluded_adapters",
    ),
    "plan.json": (
        "adapters_required",
    ),
    "sources.json": (
        "sources.authors",
    ),
    "evidence.json": (
        "evidence.source_ids",
    ),
    "claims.json": (
        "claims.supporting_evidence_ids",
        "claims.contradicting_evidence_ids",
        "claims.citation_ids",
        "claims.uncertainty_markers.affected_claim_ids",
    ),
    "citations.json": (
        "citations.evidence_ids",
    ),
    "uncertainties.json": (
        "uncertainties.affected_claim_ids",
    ),
    "failures.json": (
        "failures.affected_claim_ids",
    ),
    "validations.json": (
        "checks_run",
    ),
    "report.json": (
        "adapters_used",
    ),
    # Documents with no set-like scalar arrays use an empty tuple and serialize
    # through the same normalized path for uniformity (it is a no-op there).
    "run.json": (),
    "policy-decisions.json": (),
    "review-decisions.json": (),
    "trace.json": (),
}


def _set_like_paths_for(filename: str) -> tuple[str, ...]:
    """Return the set-like normalization paths declared for ``filename``.

    Every canonical non-manifest filename has an entry (possibly empty).
    Unknown filenames raise so the policy cannot silently regress.
    """
    try:
        return _NORMALIZATION_PATHS_BY_FILE[filename]
    except KeyError as exc:
        raise BundleError(
            f"no normalization policy for bundle file: {filename!r}"
        ) from exc


def _canonical_bundle_bytes(filename: str, data: Any) -> bytes:
    """Serialize a bundle document using the filename-aware canonicalization
    policy (set-like arrays sorted; ordered arrays preserved)."""
    paths = _set_like_paths_for(filename)
    return canonical_json_with_set_normalization(
        data, set_like_paths=paths
    ).encode("utf-8")


# --------------------------------------------------------------------------- #
# Digest computation
# --------------------------------------------------------------------------- #


def compute_bundle_digest(
    file_hashes: Sequence[FileHash | dict[str, Any]],
    manifest_without_digest: dict[str, Any] | BaseModel,
) -> str:
    """Compute the bundle digest.

    Algorithm:

    1. Sort ``file_hashes`` by ``path`` (lexicographic, ascending).
    2. For each entry, append ``"<path>:<sha256>\\n"`` to a buffer.
    3. Append the canonical JSON (sorted keys, compact) of the manifest fields
       *excluding* ``bundle_digest``.
    4. Return the lowercase hex SHA-256 of the UTF-8 buffer.
    """
    normalized: list[tuple[str, str]] = []
    for entry in file_hashes:
        if isinstance(entry, BaseModel):
            entry = entry.model_dump(mode="json")
        normalized.append((entry["path"], entry["sha256"]))
    normalized.sort(key=lambda pair: pair[0])

    parts: list[str] = [f"{p}:{s}\n" for p, s in normalized]

    if isinstance(manifest_without_digest, BaseModel):
        manifest_dict = manifest_without_digest.model_dump(mode="json")
    else:
        manifest_dict = dict(manifest_without_digest)
    manifest_dict.pop("bundle_digest", None)
    parts.append(canonical_json(manifest_dict))

    buffer = "".join(parts).encode("utf-8")
    return compute_sha256(buffer)


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


def _validate_filename(filename: str) -> str:
    """Reject absolute paths, parent traversal, and any path separator.

    Returns the filename if it is a plain, safe basename.
    """
    if not filename:
        raise BundleValidationError("filename must be non-empty")
    if os.path.isabs(filename):
        raise BundleValidationError(
            f"absolute paths are not allowed: {filename!r}"
        )
    # Reject any separator or drive letter or traversal.
    if "/" in filename or "\\" in filename:
        raise BundleValidationError(
            f"path separators are not allowed in filename: {filename!r}"
        )
    if filename in (".", ".."):
        raise BundleValidationError(f"reserved name rejected: {filename!r}")
    parts = filename.split(".")
    if any(p in ("", "..") for p in parts):
        raise BundleValidationError(f"traversal/empty segment rejected: {filename!r}")
    return filename


def _validate_within_bundle(path: Path, bundle_root: Path) -> None:
    """Ensure ``path`` resolves inside ``bundle_root`` and is not a symlink
    pointing outside the bundle."""
    bundle_root_resolved = bundle_root.resolve()
    try:
        real = path.resolve(strict=False)
    except OSError as exc:
        raise BundleValidationError(f"cannot resolve path {path}: {exc}") from exc
    try:
        real.relative_to(bundle_root_resolved)
    except ValueError as exc:
        raise BundleValidationError(
            f"path escapes bundle root: {path}"
        ) from exc
    # Symlink escape check: if the file is a symlink, its target must remain
    # inside the bundle root.
    if path.is_symlink():
        target = Path(os.readlink(path))
        if not target.is_absolute():
            target = (path.parent / target)
        try:
            target_resolved = target.resolve(strict=False)
            target_resolved.relative_to(bundle_root_resolved)
        except (ValueError, OSError) as exc:
            raise BundleValidationError(
                f"symlink escapes bundle root: {path} -> {target}"
            ) from exc


# --------------------------------------------------------------------------- #
# Cross-reference validation
# --------------------------------------------------------------------------- #


def _validate_cross_references(bundle: dict[str, dict[str, Any]]) -> None:
    """Validate referential integrity across bundle documents.

    ``bundle`` maps each filename to its parsed JSON document.

    Raises :class:`BundleValidationError` on the first broken reference.
    """
    def _ids(doc_key: str, list_key: str, id_key: str) -> set[str]:
        doc = bundle.get(doc_key, {})
        return {
            item[id_key]
            for item in doc.get(list_key, [])
            if isinstance(item, dict) and id_key in item
        }

    def _require(doc_key: str) -> dict[str, Any]:
        if doc_key not in bundle:
            raise BundleValidationError(
                f"missing document required for cross-reference check: {doc_key}"
            )
        return bundle[doc_key]

    sources_doc = _require("sources.json")
    evidence_doc = _require("evidence.json")
    claims_doc = _require("claims.json")
    citations_doc = _require("citations.json")

    source_ids = {s["source_id"] for s in sources_doc.get("sources", [])}
    evidence_ids = {e["evidence_id"] for e in evidence_doc.get("evidence", [])}
    claim_ids = {c["claim_id"] for c in claims_doc.get("claims", [])}
    citation_ids = {c["citation_id"] for c in citations_doc.get("citations", [])}

    errors: list[str] = []

    # evidence.source_ids -> sources
    for ev in evidence_doc.get("evidence", []):
        for sid in ev.get("source_ids", []):
            if sid not in source_ids:
                errors.append(
                    f"evidence {ev['evidence_id']} references unknown source_id {sid!r}"
                )

    # citations.source_id -> sources
    for cit in citations_doc.get("citations", []):
        if cit.get("source_id") not in source_ids:
            errors.append(
                f"citation {cit['citation_id']} references unknown source_id {cit.get('source_id')!r}"
            )

    # claims: supporting/contradicting evidence, citations
    for claim in claims_doc.get("claims", []):
        cid = claim["claim_id"]
        for eid in claim.get("supporting_evidence_ids", []):
            if eid not in evidence_ids:
                errors.append(
                    f"claim {cid} supporting_evidence_id {eid!r} not in evidence"
                )
        for eid in claim.get("contradicting_evidence_ids", []):
            if eid not in evidence_ids:
                errors.append(
                    f"claim {cid} contradicting_evidence_id {eid!r} not in evidence"
                )
        for cit_id in claim.get("citation_ids", []):
            if cit_id not in citation_ids:
                errors.append(
                    f"claim {cid} citation_id {cit_id!r} not in citations"
                )

    # uncertainties -> claims
    unc_doc = bundle.get("uncertainties.json", {})
    for marker in unc_doc.get("uncertainties", []):
        for cid in marker.get("affected_claim_ids", []):
            if cid not in claim_ids:
                errors.append(
                    f"uncertainty {marker['marker_id']} references unknown claim_id {cid!r}"
                )

    # failures -> claims
    fail_doc = bundle.get("failures.json", {})
    for fail in fail_doc.get("failures", []):
        for cid in fail.get("affected_claim_ids", []):
            if cid not in claim_ids:
                errors.append(
                    f"failure {fail['failure_id']} references unknown claim_id {cid!r}"
                )

    # validations -> target document by target_type
    val_doc = bundle.get("validations.json", {})
    target_sets = {
        TargetType.SOURCE.value: source_ids,
        TargetType.EVIDENCE.value: evidence_ids,
        TargetType.CLAIM.value: claim_ids,
        TargetType.CITATION.value: citation_ids,
    }
    for vr in val_doc.get("validation_results", []):
        ttype = vr.get("target_type")
        tid = vr.get("target_id")
        valid = target_sets.get(ttype)
        if valid is None:
            errors.append(
                f"validation {vr.get('validation_id')} has unknown target_type {ttype!r}"
            )
            continue
        if tid not in valid:
            errors.append(
                f"validation {vr.get('validation_id')} target_id {tid!r} not in {ttype} ids"
            )

    if errors:
        raise BundleValidationError(
            "cross-reference validation failed: " + "; ".join(errors)
        )


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def _validate_document_schema(filename: str, payload: dict[str, Any]) -> None:
    """Validate ``payload`` against the JSON schema for ``filename``."""
    ref = _schema_ref_for(filename)
    rel = ref[len("nodechain://schemas/"):]
    path = SCHEMA_ROOT / f"{rel}.json"
    if not path.exists():
        raise BundleValidationError(f"schema not found for {filename}: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(
        schema, registry=_registry()
    )
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if errors:
        msgs = []
        for err in errors:
            loc = ".".join(str(p) for p in err.absolute_path) or "(root)"
            msgs.append(f"{loc}: {err.message}")
        raise BundleValidationError(
            f"schema validation failed for {filename}: " + "; ".join(msgs)
        )


# --------------------------------------------------------------------------- #
# BundleWriter
# --------------------------------------------------------------------------- #


class BundleWriter:
    """Write a ResearchWorkspaceBundleV1 to a staging directory and finalize it
    atomically onto a destination directory.

    Usage::

        w = BundleWriter(Path("/out/run-123"))
        w.write_document("brief.json", brief_model)
        w.write_document("run.json", run_dict)
        ...
        w.finalize(source_commit="abc...", ...)

    The destination must NOT already exist as a finalized bundle.
    """

    def __init__(self, bundle_dir: Path) -> None:
        self.bundle_dir = Path(bundle_dir)
        if self.bundle_dir.exists() and any(self.bundle_dir.iterdir()):
            # An empty placeholder dir is tolerated; a non-empty one is not.
            if (self.bundle_dir / "manifest.json").exists():
                raise BundleFinalizationError(
                    f"bundle already finalized: {self.bundle_dir}"
                )
            raise BundleFinalizationError(
                f"destination is not empty: {self.bundle_dir}"
            )
        self.staging_dir = self.bundle_dir.with_name(
            self.bundle_dir.name + ".staging"
        )
        # The staging directory must be a sibling on the same filesystem so
        # that os.replace is atomic. Refuse if a staging dir already exists
        # with content (it would imply a crashed prior attempt).
        if self.staging_dir.exists() and any(self.staging_dir.iterdir()):
            raise BundleFinalizationError(
                f"staging directory already exists and is not empty: {self.staging_dir}"
            )
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self._written: set[str] = set()

    # ------------------------------------------------------------------ #
    # Writing
    # ------------------------------------------------------------------ #

    def write_document(self, filename: str, data: BaseModel | dict[str, Any]) -> None:
        """Serialize ``data`` canonically and write it atomically into staging."""
        safe = _validate_filename(filename)
        if safe == "manifest.json":
            raise BundleError(
                "manifest.json is written by finalize(); do not write it directly"
            )
        if safe not in BUNDLE_FILES:
            raise BundleError(f"unsupported bundle file: {filename!r}")
        if safe in self._written:
            raise BundleError(f"duplicate document write: {filename!r}")

        payload_bytes = _canonical_bundle_bytes(safe, data)
        target = self.staging_dir / safe
        # Atomic write: write to temp file in same dir, then os.replace.
        tmp = target.with_suffix(target.suffix + ".tmp")
        with open(tmp, "wb") as fh:
            fh.write(payload_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        self._written.add(safe)

    # ------------------------------------------------------------------ #
    # Manifest
    # ------------------------------------------------------------------ #

    def compute_manifest(
        self,
        source_commit: str,
        run_id: str,
        chain_id: str,
        blueprint_version: str,
        created_at: Any,
        finalized_at: Any,
        run_status: Any,
        input_digest: str,
        provider_mode: str,
        fixture_corpus_version: str,
        trace_reference: str = "trace.json",
        replay_eligible: bool = True,
    ) -> ResearchWorkspaceManifest:
        """Compute the manifest (including ``bundle_digest``) from the files
        already written into staging. Does not write the manifest to disk."""
        from .models import RunStatus  # local import avoids cycle at module load

        missing = [f for f in _NON_MANIFEST_FILES if f not in self._written]
        if missing:
            raise BundleFinalizationError(
                f"cannot compute manifest; missing documents: {missing}"
            )

        inventory: list[FileHash] = []
        for fname in _NON_MANIFEST_FILES:
            path = self.staging_dir / fname
            inventory.append(
                FileHash(path=fname, sha256=compute_file_hash(path))
            )

        manifest_fields: dict[str, Any] = {
            "bundle_version": BundleVersion.V1_0.value,
            "run_id": run_id,
            "chain_id": chain_id,
            "blueprint_version": blueprint_version,
            "created_at": created_at,
            "finalized_at": finalized_at,
            "run_status": run_status.value
            if isinstance(run_status, RunStatus)
            else run_status,
            "source_commit": source_commit,
            "input_digest": input_digest,
            "artifact_inventory": [
                {"path": fh.path, "sha256": fh.sha256} for fh in inventory
            ],
            "provider_mode": provider_mode,
            "fixture_corpus_version": fixture_corpus_version,
            "trace_reference": trace_reference,
            "replay_eligible": replay_eligible,
        }

        bundle_digest = compute_bundle_digest(inventory, manifest_fields)
        manifest_fields["bundle_digest"] = bundle_digest
        return ResearchWorkspaceManifest(**manifest_fields)

    # ------------------------------------------------------------------ #
    # Finalization
    # ------------------------------------------------------------------ #

    def finalize(self, manifest: ResearchWorkspaceManifest) -> Path:
        """Validate, write the manifest last, and atomically swap staging into
        place. Returns the finalized bundle directory path.

        Raises :class:`BundleFinalizationError` on any write/swap failure (this
        includes a stale-hash / stale-digest mismatch detected between the
        staging files and the supplied manifest) and
        :class:`BundleValidationError` on schema or cross-reference failure.
        The staging directory is cleaned up on failure.
        """
        if self.bundle_dir.exists() and (self.bundle_dir / "manifest.json").exists():
            self._cleanup()
            raise BundleFinalizationError(
                f"bundle already finalized, will not overwrite: {self.bundle_dir}"
            )

        try:
            # 1. BEFORE writing the manifest, recompute every non-manifest file
            #    hash from the current staging contents and reject any drift
            #    from the manifest's recorded artifact_inventory. This catches
            #    stale manifests that were computed against different bytes
            #    (e.g. a file mutated on disk after compute_manifest ran).
            self._assert_staging_matches_manifest(manifest)

            # 2. Write manifest into staging LAST (it digests everything else).
            self._write_manifest(manifest)

            # 3. Load every document and run schema validation.
            bundle = self._load_all_documents()
            for fname, payload in bundle.items():
                _validate_document_schema(fname, payload)

            # 4. Reject unsupported bundle versions on any document.
            for fname, payload in bundle.items():
                if isinstance(payload, dict) and "bundle_version" in payload:
                    if payload["bundle_version"] != SUPPORTED_BUNDLE_VERSION:
                        raise BundleValidationError(
                            f"unsupported bundle_version in {fname}: "
                            f"{payload['bundle_version']!r}"
                        )

            # 5. Cross-document truth + terminal-status enforcement.
            _validate_cross_document_truth(bundle)
            _assert_terminal_status(manifest.run_status.value, "manifest.run_status")

            # 6. Cross-reference integrity.
            _validate_cross_references(bundle)

            # 7. Reject duplicate IDs within each collection.
            _validate_unique_ids(bundle)

            # 8. Atomic rename. os.replace on the same filesystem is atomic.
            if self.bundle_dir.exists():
                # Destination exists but without manifest (shouldn't normally
                # happen because of __init__ guard, but double-check).
                shutil.rmtree(self.bundle_dir)
            os.replace(self.staging_dir, self.bundle_dir)
            return self.bundle_dir
        except (BundleValidationError, BundleFinalizationError):
            self._cleanup()
            raise
        except Exception as exc:
            self._cleanup()
            raise BundleFinalizationError(
                f"finalization failed: {exc}"
            ) from exc

    def _assert_staging_matches_manifest(
        self, manifest: ResearchWorkspaceManifest
    ) -> None:
        """Recompute hashes of every non-manifest file currently in staging and
        compare them (and the recomputed ``bundle_digest``) against the values
        recorded on ``manifest``. Raise :class:`BundleFinalizationError` on any
        mismatch — the caller must not have altered files between
        :meth:`compute_manifest` and :meth:`finalize`.
        """
        recorded_by_path: dict[str, str] = {
            entry.path: entry.sha256 for entry in manifest.artifact_inventory
        }

        actual_inventory: list[FileHash] = []
        for fname in _NON_MANIFEST_FILES:
            path = self.staging_dir / fname
            if not path.exists():
                raise BundleFinalizationError(
                    f"staging missing required file before finalization: {fname}"
                )
            actual = compute_file_hash(path)
            actual_inventory.append(FileHash(path=fname, sha256=actual))
            recorded = recorded_by_path.get(fname)
            if recorded is None:
                raise BundleFinalizationError(
                    f"manifest artifact_inventory missing entry for {fname}"
                )
            if actual != recorded:
                raise BundleFinalizationError(
                    f"stale hash for {fname}: manifest recorded {recorded}, "
                    f"staging now contains {actual}"
                )

        # The manifest inventory must cover exactly the non-manifest file set.
        recorded_paths = set(recorded_by_path)
        expected_paths = set(_NON_MANIFEST_FILES)
        if recorded_paths != expected_paths:
            missing = expected_paths - recorded_paths
            extra = recorded_paths - expected_paths
            raise BundleFinalizationError(
                "manifest artifact_inventory does not match canonical file set: "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )

        # Recompute the bundle_digest and compare with the manifest's value.
        recomputed_digest = compute_bundle_digest(
            actual_inventory, manifest.model_dump(mode="json")
        )
        if recomputed_digest != manifest.bundle_digest:
            raise BundleFinalizationError(
                f"stale bundle_digest: manifest recorded {manifest.bundle_digest}, "
                f"recomputed {recomputed_digest}"
            )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    def _write_manifest(self, manifest: ResearchWorkspaceManifest) -> None:
        target = self.staging_dir / "manifest.json"
        tmp = target.with_suffix(target.suffix + ".tmp")
        payload_bytes = canonical_json_bytes(manifest)
        with open(tmp, "wb") as fh:
            fh.write(payload_bytes)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)

    def _load_all_documents(self) -> dict[str, dict[str, Any]]:
        bundle: dict[str, dict[str, Any]] = {}
        for fname in BUNDLE_FILES:
            path = self.staging_dir / fname
            _validate_within_bundle(path, self.staging_dir)
            if not path.exists():
                raise BundleValidationError(f"missing required file: {fname}")
            with open(path, "r", encoding="utf-8") as fh:
                bundle[fname] = json.load(fh)
        return bundle

    def _cleanup(self) -> None:
        try:
            if self.staging_dir.exists():
                shutil.rmtree(self.staging_dir, ignore_errors=True)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Cross-cutting checks
# --------------------------------------------------------------------------- #


def _validate_unique_ids(bundle: dict[str, dict[str, Any]]) -> None:
    """Reject duplicate IDs within each collection document."""
    checks: list[tuple[str, str, str]] = [
        # (filename, list_key, id_key)
        ("sources.json", "sources", "source_id"),
        ("evidence.json", "evidence", "evidence_id"),
        ("claims.json", "claims", "claim_id"),
        ("citations.json", "citations", "citation_id"),
        ("policy-decisions.json", "policy_decisions", "decision_id"),
        ("review-decisions.json", "review_decisions", "review_id"),
        ("failures.json", "failures", "failure_id"),
        ("uncertainties.json", "uncertainties", "marker_id"),
        ("validations.json", "validation_results", "validation_id"),
    ]
    errors: list[str] = []
    for fname, list_key, id_key in checks:
        doc = bundle.get(fname, {})
        seen: set[str] = set()
        for item in doc.get(list_key, []):
            value = item.get(id_key)
            if value in seen:
                errors.append(f"duplicate {id_key} in {fname}: {value!r}")
            seen.add(value)
    if errors:
        raise BundleValidationError("; ".join(errors))


# --------------------------------------------------------------------------- #
# Cross-document truth + terminal-status enforcement
# --------------------------------------------------------------------------- #

#: Run statuses that may legitimately appear on a finalized bundle. Anything
#: else (e.g. ``running``, ``paused_for_review``) means the run is still in
#: flight and MUST NOT be finalized.
TERMINAL_RUN_STATUSES: frozenset[str] = frozenset(
    {
        "completed",
        "completed_degraded",
        "failed",
        "blocked",
        "cancelled",
    }
)


def _assert_terminal_status(run_status: str, where: str) -> None:
    """Reject non-terminal run statuses. ``where`` decorates the error."""
    if run_status not in TERMINAL_RUN_STATUSES:
        raise BundleValidationError(
            f"non-terminal run_status {run_status!r} rejected at {where}; "
            f"only {sorted(TERMINAL_RUN_STATUSES)} may finalize"
        )


def _validate_cross_document_truth(bundle_data: dict[str, dict[str, Any]]) -> None:
    """Enforce that every document agrees with the manifest on shared fields.

    ``bundle_data`` maps each canonical filename (including ``manifest.json``)
    to its parsed JSON document. The manifest is the single source of truth;
    every other document must agree with it on ``run_id`` and any other field
    they hold in common. The trace reference on the manifest must resolve to
    the canonical trace file present in the bundle.

    Raises :class:`BundleValidationError` on the first disagreement.
    """
    manifest = bundle_data.get("manifest.json")
    if manifest is None:
        raise BundleValidationError(
            "cross-document truth check requires manifest.json"
        )

    m_run_id = manifest.get("run_id")
    m_chain_id = manifest.get("chain_id")
    m_run_status = manifest.get("run_status")
    m_input_digest = manifest.get("input_digest")
    m_provider_mode = manifest.get("provider_mode")
    m_replay_eligible = manifest.get("replay_eligible")
    m_trace_reference = manifest.get("trace_reference")

    errors: list[str] = []

    def _eq(label: str, doc_field: str, expected: Any, actual: Any) -> None:
        if actual != expected:
            errors.append(
                f"{label}: expected {doc_field}={expected!r}, got {actual!r}"
            )

    # 1. Every document's run_id == manifest.run_id.
    for fname, doc in bundle_data.items():
        if fname == "manifest.json" or not isinstance(doc, dict):
            continue
        if "run_id" in doc:
            _eq(fname, "run_id", m_run_id, doc.get("run_id"))

    # 2. review record run_id == manifest.run_id (per-record, in case the
    #    document-level run_id is absent on a malformed bundle).
    review_doc = bundle_data.get("review-decisions.json", {})
    for rec in review_doc.get("review_decisions", []):
        _eq(
            f"review-decisions.json[{rec.get('review_id')}]",
            "run_id",
            m_run_id,
            rec.get("run_id"),
        )

    # 3. run.json agreement with manifest.
    run_doc = bundle_data.get("run.json", {})
    _eq("run.json", "chain_id", m_chain_id, run_doc.get("chain_id"))
    _eq("run.json", "status", m_run_status, run_doc.get("status"))
    _eq("run.json", "input_digest", m_input_digest, run_doc.get("input_digest"))
    _eq("run.json", "provider_mode", m_provider_mode, run_doc.get("provider_mode"))
    _eq("run.json", "replay_eligible", m_replay_eligible, run_doc.get("replay_eligible"))

    # 4. report.json agreement with manifest.
    report_doc = bundle_data.get("report.json", {})
    _eq("report.json", "run_id", m_run_id, report_doc.get("run_id"))
    _eq("report.json", "run_status", m_run_status, report_doc.get("run_status"))
    _eq("report.json", "replay_eligible", m_replay_eligible, report_doc.get("replay_eligible"))

    # 5. trace run_id AND chain_id agreement with manifest. The trace carries
    #    its own chain_id; a trace from another chain that happens to share a
    #    run_id must not pass truth check.
    trace_doc = bundle_data.get("trace.json", {})
    _eq("trace.json", "run_id", m_run_id, trace_doc.get("run_id"))
    _eq("trace.json", "chain_id", m_chain_id, trace_doc.get("chain_id"))

    # 6. trace_reference must resolve to the canonical trace file in the bundle.
    if m_trace_reference != "trace.json":
        errors.append(
            f"manifest.trace_reference must be 'trace.json' (canonical trace "
            f"file), got {m_trace_reference!r}"
        )
    if "trace.json" not in bundle_data:
        errors.append("canonical trace.json is missing from the bundle")

    if errors:
        raise BundleValidationError(
            "cross-document truth check failed: " + "; ".join(errors)
        )


# --------------------------------------------------------------------------- #
# BundleReader
# --------------------------------------------------------------------------- #


class BundleReader:
    """Read and verify a finalized ResearchWorkspaceBundleV1 from disk."""

    def __init__(self, bundle_dir: Path) -> None:
        self.bundle_dir = Path(bundle_dir)
        manifest_path = self.bundle_dir / "manifest.json"
        if not manifest_path.exists():
            raise BundleIntegrityError(
                f"not a finalized bundle (no manifest): {self.bundle_dir}"
            )
        _validate_within_bundle(manifest_path, self.bundle_dir)
        with open(manifest_path, "r", encoding="utf-8") as fh:
            self._manifest_doc = json.load(fh)
        try:
            self._manifest = ResearchWorkspaceManifest(**self._manifest_doc)
        except Exception as exc:
            raise BundleIntegrityError(
                f"manifest is not valid: {exc}"
            ) from exc

    def get_manifest(self) -> ResearchWorkspaceManifest:
        return self._manifest

    def get_document(self, filename: str) -> dict[str, Any]:
        safe = _validate_filename(filename)
        if safe not in BUNDLE_FILES:
            raise BundleIntegrityError(
                f"{safe!r} is not a canonical bundle file"
            )
        path = self.bundle_dir / safe
        _validate_within_bundle(path, self.bundle_dir)
        if not path.exists():
            raise BundleIntegrityError(f"missing file: {safe}")
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def verify_integrity(self) -> bool:
        """Verify the complete on-disk contract of a finalized bundle.

        Checks, in order:

        1. The bundle directory's physical member set equals the canonical
           ``BUNDLE_FILES`` exactly (no extra files, directories, or symlinks;
           no missing canonical file).
        2. Every required file is present and contained within the bundle root.
        3. The manifest inventory equals the exact canonical non-manifest set
           (no duplicate / missing / extra inventory entries).
        4. Every recorded per-file hash matches the file now on disk.
        5. The ``bundle_digest`` matches a recomputation.
        6. Every non-manifest document validates against its JSON schema.
        7. No document declares an unsupported ``bundle_version``.
        8. Cross-document truth holds (run_id / chain_id / status / ... agree
           with the manifest, including ``trace.chain_id``).
        9. The manifest ``run_status`` is terminal (``running`` /
           ``paused_for_review`` are rejected even if internally consistent).
        10. Cross-reference integrity + duplicate-ID checks.

        Returns ``True`` if everything is consistent. Raises
        :class:`BundleIntegrityError` (or
        :class:`BundleValidationError` for schema / cross-reference / truth
        failures, which are surfaced unchanged so callers can distinguish
        integrity drift from contract violations) on the first problem.
        """
        # 1. Physical directory member set must equal the canonical file set
        #    exactly. This makes the manifest a COMPLETE artifact inventory:
        #    no unlisted file, directory, or symlink may ride along inside a
        #    finalized bundle. We check this before per-file hash recomputation
        #    so an extra member cannot hide behind a passing hash check.
        actual_members = set()
        for entry in self.bundle_dir.iterdir():
            actual_members.add(entry.name)
        expected_members = set(BUNDLE_FILES)
        extra_members = actual_members - expected_members
        missing_members = expected_members - actual_members
        if extra_members:
            raise BundleIntegrityError(
                f"bundle directory contains non-canonical members: "
                f"{sorted(extra_members)}; expected exactly {sorted(expected_members)}"
            )
        if missing_members:
            raise BundleIntegrityError(
                f"bundle directory missing canonical members: "
                f"{sorted(missing_members)}"
            )
        # Reject any symlink among the canonical members — a finalized bundle is
        # a flat directory of real files.
        for fname in BUNDLE_FILES:
            if (self.bundle_dir / fname).is_symlink():
                raise BundleIntegrityError(
                    f"bundle member must be a real file, not a symlink: {fname}"
                )

        # 2. Every required file present and within-bundle.
        for fname in BUNDLE_FILES:
            path = self.bundle_dir / fname
            _validate_within_bundle(path, self.bundle_dir)
            if not path.exists():
                raise BundleIntegrityError(f"missing required file: {fname}")

        # 3. Inventory must equal the exact canonical file set: no duplicates,
        #    no missing canonical paths, no extra/noncanonical paths.
        inventory_entries: list[dict[str, Any]] = list(
            self._manifest_doc.get("artifact_inventory", [])
        )
        inventory_paths: list[str] = [e.get("path") for e in inventory_entries]
        seen: set[str] = set()
        for p in inventory_paths:
            if p in seen:
                raise BundleIntegrityError(
                    f"duplicate inventory path in manifest: {p!r}"
                )
            seen.add(p)
        canonical_non_manifest = set(_NON_MANIFEST_FILES)
        inventory_set = set(inventory_paths)
        missing = canonical_non_manifest - inventory_set
        extra = inventory_set - canonical_non_manifest
        if missing:
            raise BundleIntegrityError(
                f"manifest inventory missing canonical paths: {sorted(missing)}"
            )
        if extra:
            raise BundleIntegrityError(
                f"manifest inventory contains noncanonical paths: {sorted(extra)}"
            )

        # 4. Recompute per-file hashes; compare against inventory.
        inventory_by_path: dict[str, str] = {
            entry["path"]: entry["sha256"] for entry in inventory_entries
        }
        for fname in _NON_MANIFEST_FILES:
            actual = compute_file_hash(self.bundle_dir / fname)
            recorded = inventory_by_path.get(fname)
            if recorded is None:
                raise BundleIntegrityError(
                    f"manifest inventory missing entry for {fname}"
                )
            if actual != recorded:
                raise BundleIntegrityError(
                    f"hash mismatch for {fname}: expected {recorded}, got {actual}"
                )

        # 5. Recompute bundle_digest and compare.
        inventory: list[FileHash] = [
            FileHash(path=p, sha256=s)
            for p, s in inventory_by_path.items()
        ]
        recomputed = compute_bundle_digest(inventory, self._manifest_doc)
        if recomputed != self._manifest.bundle_digest:
            raise BundleIntegrityError(
                f"bundle_digest mismatch: manifest has "
                f"{self._manifest.bundle_digest}, recomputed {recomputed}"
            )

        # 6. Schema-validate every non-manifest document (not just hash check).
        bundle: dict[str, dict[str, Any]] = {}
        for fname in _NON_MANIFEST_FILES:
            with open(self.bundle_dir / fname, "r", encoding="utf-8") as fh:
                bundle[fname] = json.load(fh)
            _validate_document_schema(fname, bundle[fname])

        # 7. Reject unsupported bundle versions on any document.
        for fname, payload in bundle.items():
            if isinstance(payload, dict) and "bundle_version" in payload:
                if payload["bundle_version"] != SUPPORTED_BUNDLE_VERSION:
                    raise BundleValidationError(
                        f"unsupported bundle_version in {fname}: "
                        f"{payload['bundle_version']!r}"
                    )

        # 8. Cross-document truth (run_id / chain_id / status / ... agree with
        #    the manifest).
        bundle_with_manifest = dict(bundle)
        bundle_with_manifest["manifest.json"] = self._manifest_doc
        _validate_cross_document_truth(bundle_with_manifest)

        # 9. Terminal-status enforcement. A bundle whose documents all agree on
        #    a non-terminal status (running / paused_for_review) would pass the
        #    truth check above; this gate independently rejects it so a
        #    half-finished run cannot be read as a finalized bundle even if its
        #    hashes and cross-document values are internally consistent.
        _assert_terminal_status(
            self._manifest.run_status.value, "manifest.run_status"
        )

        # 10. Cross-reference integrity + duplicate-ID checks.
        _validate_cross_references(bundle)
        _validate_unique_ids(bundle)

        return True
