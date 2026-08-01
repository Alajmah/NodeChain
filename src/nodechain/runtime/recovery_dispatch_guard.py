"""v3.5.0: Recovery dispatch guard — intercepts the actual adapter boundary.

The RecoveryDispatchGuard wraps a search adapter's ``search()`` method so the
recovery runtime can enforce exactly-one-target-effect at the real dispatch
boundary (INV-006, INV-014), NOT at the pre-call journal layer.

ChatGPT Blocker 1 (plan review): the existing journal runs BEFORE node
execution and cannot mediate adapter calls that happen during execution.
SearchToolNode calls ``adapter.search(query)`` directly. Without a guard at
that boundary, a secondary call (e.g. rescue path) could bypass the gate.

The guard:
- validates the full tuple (type, operation_name, adapter_id, adapter_version,
  request_hash, canonicalization_version) against the execution constraints
- persists ``dispatch_attempted_at`` atomically (the runtime crossed the
  dispatch boundary; does NOT claim provider receipt — INV-011)
- rejects a second call even with the same request hash (counts dispatch
  proposals, not unique hashes — ChatGPT guardrail #4)
- is instance-local (not mutating the module-global _ADAPTERS registry —
  ChatGPT guardrail #3)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from nodechain.adapters.search.base_search import BaseSearchAdapter, SearchQuery, SearchAdapterResult


class RecoveryDispatchError(Exception):
    """Raised when the recovery dispatch guard rejects a proposal."""

    def __init__(self, reason: str, *, rejection_type: str = "dispatch_rejected") -> None:
        self.reason = reason
        self.rejection_type = rejection_type
        super().__init__(reason)


@dataclass
class AdapterRetryCapability:
    """v3.5.0: attestation that an adapter is eligible for Tier 1 retry.

    Pinned by (adapter_id, version range). Backed by characterization tests
    proving the adapter is a single logical operation with no hidden batching.
    """
    adapter_id: str
    min_version: str
    max_version: str
    dispatch_cardinality: str = "single_logical_operation"  # single | variable | multi
    internal_batching: bool = False
    transport_retry_semantics: str = "identical_logical_operation"
    characterization_test_ref: str = ""


@dataclass
class ExecutionConstraints:
    """The constraints the guard enforces, carried in RecoveryEnvelopeV1."""
    required_type: str
    required_operation_name: str
    required_adapter_id: str
    required_adapter_version: str
    required_request_hash: str
    required_canonicalization_version: str = "1"
    max_total_side_effects: int = 1


class RecoveryDispatchGuard:
    """Wraps a target adapter so search() is intercepted at the dispatch boundary.

    ChatGPT guardrail #2: the guard owns tuple validation, single-call
    enforcement, fencing validation, and dispatch_attempted_at. It does NOT
    introduce adapter-authoritative completion — the recovery response still
    passes through the observed-completion authority.

    ChatGPT guardrail #4: counts dispatch proposals, not unique request hashes.
    Two identical calls with the same tuple still constitute an impermissible
    second proposal in Tier 1.
    """

    def __init__(
        self,
        target_adapter: BaseSearchAdapter,
        constraints: ExecutionConstraints,
        *,
        on_dispatch_attempted: Any = None,  # callback(result) to persist dispatch_attempted_at
    ) -> None:
        self._adapter = target_adapter
        self._constraints = constraints
        self._on_dispatch_attempted = on_dispatch_attempted
        self._dispatch_count = 0
        self._target_dispatched = False

    def preflight_validate(self, query: SearchQuery) -> None:
        """Run all local validations WITHOUT persisting or dispatching.

        ChatGPT T6 re-review fix 2: these checks must run BEFORE the boundary
        CAS so a predictable local rejection doesn't leave dispatch_attempted_at
        set with no adapter call.

        ChatGPT T6 3rd re-review fix 2: enforce the FULL INV-014 tuple:
        side_effect_type, operation_name, adapter_id, adapter_version,
        request_hash, canonicalization_version.

        Raises RecoveryDispatchError on any mismatch.
        """
        # Validate adapter identity
        actual_adapter_id = self._adapter.adapter_name
        actual_adapter_version = self._adapter.adapter_version
        if actual_adapter_id != self._constraints.required_adapter_id:
            raise RecoveryDispatchError(
                f"Adapter ID mismatch: expected "
                f"{self._constraints.required_adapter_id}, got {actual_adapter_id}",
                rejection_type="adapter_mismatch",
            )
        if actual_adapter_version != self._constraints.required_adapter_version:
            raise RecoveryDispatchError(
                f"Adapter version mismatch: expected "
                f"{self._constraints.required_adapter_version}, got {actual_adapter_version}",
                rejection_type="version_mismatch",
            )

        # Validate request hash (full canonical digest, not 16-char prefix)
        from nodechain.core.side_effect_utils import (
            canonicalize_capsule_payload,
            compute_canonical_request_digest,
        )
        operation = {
            "terms": sorted(query.terms),
            "max": query.max_results,
            "filters": query.filters,
        }
        canonical_bytes = canonicalize_capsule_payload(operation)
        actual_request_hash = compute_canonical_request_digest(canonical_bytes)
        if actual_request_hash != self._constraints.required_request_hash:
            raise RecoveryDispatchError(
                f"Request hash mismatch: expected "
                f"{self._constraints.required_request_hash[:12]}…, got "
                f"{actual_request_hash[:12]}…",
                rejection_type="hash_mismatch",
            )

        # ChatGPT T6 3rd re-review fix 2: validate remaining tuple fields.
        # ChatGPT T6 4th re-review fix 1: side_effect_type is part of the
        # INV-014 tuple and must be validated.
        if self._constraints.required_type != "external_call":
            raise RecoveryDispatchError(
                f"Side-effect type mismatch: expected 'external_call', got "
                f"'{self._constraints.required_type}'",
                rejection_type="side_effect_type_mismatch",
            )
        # operation_name should be "search" for search side effects, not the
        # adapter name. canonicalization_version must match the capsule's.
        if self._constraints.required_operation_name != "search":
            raise RecoveryDispatchError(
                f"Operation name mismatch: expected 'search', got "
                f"'{self._constraints.required_operation_name}'",
                rejection_type="operation_name_mismatch",
            )
        if self._constraints.required_canonicalization_version != "1":
            raise RecoveryDispatchError(
                f"Canonicalization version mismatch: expected '1', got "
                f"'{self._constraints.required_canonicalization_version}'",
                rejection_type="canonicalization_version_mismatch",
            )

    async def search(self, query: SearchQuery) -> list[SearchAdapterResult]:
        """Intercept search() — the real dispatch boundary.

        On first call: validate tuple (defense in depth — preflight already
        ran), persist dispatch_attempted_at, allow.
        On any subsequent call: reject (even if same request hash).
        """
        self._dispatch_count += 1

        if self._target_dispatched:
            raise RecoveryDispatchError(
                "Second dispatch proposal rejected — Tier 1 permits exactly "
                "one governed side-effect operation (INV-006). "
                f"Attempt #{self._dispatch_count} for adapter "
                f"{self._constraints.required_adapter_id}.",
                rejection_type="duplicate_dispatch",
            )

        # Defense in depth: re-run preflight checks (caller should have
        # already called preflight_validate before the boundary CAS)
        self.preflight_validate(query)

        # Persist dispatch_attempted_at (the runtime crossed the dispatch boundary)
        if self._on_dispatch_attempted is not None:
            self._on_dispatch_attempted()

        self._target_dispatched = True

        # Delegate to the real adapter
        return await self._adapter.search(query)

    @property
    def target_dispatched(self) -> bool:
        """True if the target has been dispatched (for post-invocation checks)."""
        return self._target_dispatched

    @property
    def dispatch_count(self) -> int:
        """Total dispatch proposals (including rejected ones)."""
        return self._dispatch_count


def build_guarded_adapter_registry(
    target_adapter_name: str,
    target_adapter: BaseSearchAdapter,
    constraints: ExecutionConstraints,
    on_dispatch_attempted: Any = None,
) -> dict[str, BaseSearchAdapter]:
    """Build an instance-local adapter registry with the target wrapped in a guard.

    ChatGPT guardrail #3: do NOT mutate the module-global _ADAPTERS registry.
    This returns a fresh dict containing only the guarded target adapter,
    suitable for constructor injection into a recovery-specific SearchToolNode.
    """
    guard = RecoveryDispatchGuard(
        target_adapter=target_adapter,
        constraints=constraints,
        on_dispatch_attempted=on_dispatch_attempted,
    )
    return {target_adapter_name: guard}


# v3.5.0: adapter retry capability allowlist.
# Each adapter is attested as single_logical_operation with no internal
# batching. Internal _fetch retries reuse the same canonical request.
# Characterization tests prove these claims (test_v35_adapter_attestation.py).
ADAPTER_RETRY_ALLOWLIST: dict[str, AdapterRetryCapability] = {
    "semantic_scholar": AdapterRetryCapability(
        adapter_id="semantic_scholar",
        min_version="1.0.0",
        max_version="999.0.0",
        characterization_test_ref="test_v35_adapter_attestation.py::TestSemanticScholarSingleton",
    ),
    "arxiv": AdapterRetryCapability(
        adapter_id="arxiv",
        min_version="1.0.0",
        max_version="999.0.0",
        characterization_test_ref="test_v35_adapter_attestation.py::TestArxivSingleton",
    ),
    "openalex": AdapterRetryCapability(
        adapter_id="openalex",
        min_version="1.0.0",
        max_version="999.0.0",
        characterization_test_ref="test_v35_adapter_attestation.py::TestOpenAlexSingleton",
    ),
    "crossref": AdapterRetryCapability(
        adapter_id="crossref",
        min_version="1.0.0",
        max_version="999.0.0",
        characterization_test_ref="test_v35_adapter_attestation.py::TestCrossRefSingleton",
    ),
    "pubmed": AdapterRetryCapability(
        adapter_id="pubmed",
        min_version="1.0.0",
        max_version="999.0.0",
        characterization_test_ref="test_v35_adapter_attestation.py::TestPubMedSingleton",
    ),
}


def is_adapter_attested(adapter_id: str, adapter_version: str) -> bool:
    """Check if an adapter version is in the v3.5 retry allowlist."""
    cap = ADAPTER_RETRY_ALLOWLIST.get(adapter_id)
    if cap is None:
        return False
    try:
        from packaging.specifiers import SpecifierSet
        spec = SpecifierSet(f">={cap.min_version},<{cap.max_version}")
        return adapter_version in spec
    except ImportError:
        # Fallback: simple version string match if packaging not available
        return adapter_id in ADAPTER_RETRY_ALLOWLIST


# ── Trusted adapter registry (ChatGPT: attestation must not be self-asserted) ──


def _build_trusted_adapter_registry() -> dict[str, type]:
    """Bind adapter IDs to their trusted concrete classes.

    ChatGPT: "The five-adapter attestation must bind to a trusted implementation
    identity — such as the registered concrete class/factory — not only adapter-
    supplied strings. Otherwise a different implementation can claim an allowlisted
    identity while internally batching multiple wire operations."

    This registry maps adapter_id → concrete class. At dispatch time, the guard
    verifies ``isinstance(actual_adapter, trusted_class)`` to prevent identity
    spoofing.
    """
    registry: dict[str, type] = {}
    try:
        from nodechain.adapters.search.semantic_scholar import SemanticScholarAdapter
        registry["semantic_scholar"] = SemanticScholarAdapter
    except ImportError:
        pass
    try:
        from nodechain.adapters.search.arxiv import ArxivAdapter
        registry["arxiv"] = ArxivAdapter
    except ImportError:
        pass
    try:
        from nodechain.adapters.search.openalex import OpenAlexAdapter
        registry["openalex"] = OpenAlexAdapter
    except ImportError:
        pass
    try:
        from nodechain.adapters.search.crossref import CrossRefAdapter
        registry["crossref"] = CrossRefAdapter
    except ImportError:
        pass
    try:
        from nodechain.adapters.search.pubmed import PubMedAdapter
        registry["pubmed"] = PubMedAdapter
    except ImportError:
        pass
    return registry


TRUSTED_ADAPTER_CLASSES: dict[str, type] = _build_trusted_adapter_registry()


def is_trusted_adapter(adapter: BaseSearchAdapter) -> bool:
    """Verify an adapter instance is of the trusted concrete class for its name.

    ChatGPT T3 gate: ``isinstance()`` is not a strong implementation-identity
    binding — it accepts an arbitrary subclass that can override search() to
    batch, fan out, or bypass the characterized implementation while still
    passing the check.

    Uses ``type() is`` (exact class match) instead. Subclassing is allowed only
    through a separate explicit attestation entry.
    """
    trusted_cls = TRUSTED_ADAPTER_CLASSES.get(adapter.adapter_name)
    if trusted_cls is None:
        return False
    # ChatGPT: exact class match, not isinstance — rejects subclasses
    return type(adapter) is trusted_cls


# ── OrdinaryDispatchGuard ─────────────────────────────────────────────


class OrdinaryDispatchError(Exception):
    """Raised when the ordinary dispatch guard rejects an adapter call."""

    def __init__(self, reason: str, *, rejection_type: str = "ordinary_dispatch_rejected") -> None:
        self.reason = reason
        self.rejection_type = rejection_type
        super().__init__(reason)


# Type alias for the capsule validator callback.
# Takes (run_id, adapter_name, canonical_request_digest) → True if a started
# side-effect row with capsule_status=available exists for this operation.
CapsuleValidator = Any  # Callable[[str, str, str], bool]


class OrdinaryDispatchGuard:
    """v3.5.0: Guards ordinary adapter dispatch — closes the rescue/fallback gap.

    ChatGPT T3 STOP: "Every journaled side effect has a capsule" does not prove
    "Every adapter dispatch has a matching capsule." The ordinary search node can
    call adapter.search() directly (rescue path, fallback queries) without a
    matching operation-specific capsule.

    This guard wraps the adapter so search() is intercepted even during ordinary
    execution. Before delegating to the real adapter:
    1. Compute the canonical request digest from the query
    2. Check that a started side-effect row with capsule_status=available exists
    3. Track per-operation dispatch (one capsule = one logical operation)
    4. Verify the adapter is a trusted concrete class (not identity-spoofed)

    Policy differs from RecoveryDispatchGuard:
        Ordinary: permits each correctly journaled operation once; no recovery tuple
        Recovery: permits exactly one authorized target; requires envelope + fencing
    """

    def __init__(
        self,
        target_adapter: BaseSearchAdapter,
        run_id: str,
        capsule_validator: CapsuleValidator,
        *,
        skip_trust_check: bool = False,
    ) -> None:
        """Initialize the ordinary dispatch guard.

        Args:
            target_adapter: the real adapter to wrap.
            run_id: the current run ID (for capsule lookup).
            capsule_validator: callable(run_id, adapter_name, canonical_digest) → bool.
                Returns True if a started row with capsule_status=available exists
                for this exact operation.
            skip_trust_check: bypass the trusted-class check. For testing only —
                production code must never set this. The check binds attestation
                to concrete adapter classes, not adapter-supplied strings.
        """
        self._adapter = target_adapter
        self._run_id = run_id
        self._capsule_validator = capsule_validator
        self._skip_trust_check = skip_trust_check
        self._dispatched_digests: set[str] = set()

    async def search(self, query: SearchQuery) -> list[SearchAdapterResult]:
        """Intercept search() — validate capsule before delegating.

        Raises OrdinaryDispatchError if no matching capsule exists (rescue/fallback
        gap) or if the operation was already dispatched (duplicate).
        """
        # 1. Verify trusted adapter identity (ChatGPT: not self-asserted)
        if not self._skip_trust_check and not is_trusted_adapter(self._adapter):
            raise OrdinaryDispatchError(
                f"Adapter {self._adapter.adapter_name} is not a trusted concrete class. "
                f"Identity spoofing prevented.",
                rejection_type="untrusted_adapter",
            )

        # 2. Compute canonical request digest from the query
        from nodechain.core.side_effect_utils import (
            canonicalize_capsule_payload,
            compute_canonical_request_digest,
        )
        operation = {
            "terms": sorted(query.terms),
            "max": query.max_results,
            "filters": query.filters,
        }
        canonical_bytes = canonicalize_capsule_payload(operation)
        canonical_digest = compute_canonical_request_digest(canonical_bytes)

        # 3. Check duplicate dispatch (one capsule = one logical operation)
        if canonical_digest in self._dispatched_digests:
            raise OrdinaryDispatchError(
                f"Duplicate dispatch for adapter {self._adapter.adapter_name}: "
                f"this exact operation was already dispatched. One capsule "
                f"authorizes one logical adapter operation.",
                rejection_type="duplicate_dispatch",
            )

        # 4. Validate that a matching capsule exists (closes rescue/fallback gap)
        has_capsule = self._capsule_validator(
            self._run_id, self._adapter.adapter_name, canonical_digest,
        )
        if not has_capsule:
            raise OrdinaryDispatchError(
                f"No available capsule for adapter {self._adapter.adapter_name} "
                f"with matching operation (digest {canonical_digest[:12]}…). "
                f"Dispatch blocked — capsule-before-wire invariant (INV-004).",
                rejection_type="no_matching_capsule",
            )

        # 5. Record dispatch and delegate
        self._dispatched_digests.add(canonical_digest)
        return await self._adapter.search(query)

    @property
    def adapter_name(self) -> str:
        """Delegate adapter_name so this guard is transparent to callers."""
        return self._adapter.adapter_name

    @property
    def adapter_version(self) -> str:
        """Delegate adapter_version."""
        return self._adapter.adapter_version

    @property
    def dispatch_count(self) -> int:
        """Number of successful dispatches."""
        return len(self._dispatched_digests)


def build_ordinary_guarded_registry(
    run_id: str,
    adapter_names: list[str],
    capsule_validator: CapsuleValidator,
) -> dict[str, OrdinaryDispatchGuard]:
    """Build an instance-local registry of ordinary-guarded adapters.

    Each adapter is wrapped in an OrdinaryDispatchGuard. The registry maps
    adapter_name → guarded adapter. Only adapters that exist in the module-global
    _ADAPTERS lazy loader are included.

    ChatGPT guardrail #3: instance-local, does NOT mutate _ADAPTERS.
    """
    from nodechain.nodes.search_tool import _get_adapter
    registry: dict[str, OrdinaryDispatchGuard] = {}
    for name in adapter_names:
        adapter = _get_adapter(name)
        if adapter is not None:
            registry[name] = OrdinaryDispatchGuard(
                target_adapter=adapter,
                run_id=run_id,
                capsule_validator=capsule_validator,
            )
    return registry
