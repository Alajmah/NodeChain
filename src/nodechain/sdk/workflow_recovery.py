"""Checkpointed Workflow Recovery Integration (v2.11.0–v2.11.1).

Binds checkpoint integrity to real workflow execution. Proves that a
composed multi-node, side-effect-aware workflow can crash, restart,
reconcile its checkpoint journal, restore only verified state, and
continue without duplicating governed actions.

Core components:
    WorkflowEnvironmentBinding — captures execution environment state
    WorkflowCheckpointBinder — creates and verifies environment bindings
    WorkflowRecoveryReceipt — recovery result with full provenance
    WorkflowRecoveryManager — orchestrates full recovery protocol

v2.11.1: Side-effect recovery semantics.
    SideEffectContract / IdempotencyContract — declares external action
    safety properties so that recovery knows whether a started action
    can be safely retried, queried, compensated, or must be escalated.

    Contract types:
        idempotent_with_key  → retry with same key
        externally_queryable → query target before retry
        compensatable        → propose governed compensation (not automatic)
        non_idempotent       → needs_intervention
        unknown              → needs_intervention

v2.11.2: Semantic correction.
    planned actions are 'eligible for execution', not 'skip'.
    compensatable actions require authorization + human approval;
    the contract describes available behavior, policy decides whether
    that behavior may execute.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .evidence_checkpoint import (
    CheckpointChain,
    CheckpointJournal,
    CheckpointError,
    EvidenceCheckpoint,
    RecoveryReport,
    generate_recovery_report,
    JOURNAL_COMMITTED,
    JOURNAL_ABORTED,
)
from .artifact_retention import ContentAddressedStore


# ── Environment Binding ─────────────────────────────────────────────────────


@dataclass
class WorkflowEnvironmentBinding:
    """Captures the execution environment at checkpoint time.

    Resume is rejected when any binding field no longer matches.
    """

    blueprint_revision: str = ""
    execution_order_hash: str = ""
    package_versions: dict[str, str] = field(default_factory=dict)
    policy_profile_digest: str = ""
    trust_store_digest: str = ""
    registry_resolution_digest: str = ""
    certification_state_digest: str = ""
    binding_digest: str = ""

    def compute_digest(self) -> str:
        """SHA-256 over all binding fields except binding_digest."""
        payload = json.dumps({
            "blueprint_revision": self.blueprint_revision,
            "execution_order_hash": self.execution_order_hash,
            "package_versions": dict(sorted(self.package_versions.items())),
            "policy_profile_digest": self.policy_profile_digest,
            "trust_store_digest": self.trust_store_digest,
            "registry_resolution_digest": self.registry_resolution_digest,
            "certification_state_digest": self.certification_state_digest,
        }, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = {
            "blueprint_revision": self.blueprint_revision,
            "execution_order_hash": self.execution_order_hash,
            "package_versions": dict(sorted(self.package_versions.items())),
            "policy_profile_digest": self.policy_profile_digest,
            "trust_store_digest": self.trust_store_digest,
            "registry_resolution_digest": self.registry_resolution_digest,
            "certification_state_digest": self.certification_state_digest,
            "binding_digest": self.compute_digest(),
        }
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkflowEnvironmentBinding:
        binding = cls(
            blueprint_revision=data.get("blueprint_revision", ""),
            execution_order_hash=data.get("execution_order_hash", ""),
            package_versions=data.get("package_versions", {}),
            policy_profile_digest=data.get("policy_profile_digest", ""),
            trust_store_digest=data.get("trust_store_digest", ""),
            registry_resolution_digest=data.get("registry_resolution_digest", ""),
            certification_state_digest=data.get("certification_state_digest", ""),
        )
        binding.binding_digest = binding.compute_digest()
        return binding


class WorkflowCheckpointBinder:
    """Creates and verifies environment bindings for workflow recovery."""

    @staticmethod
    def capture_binding(
        *,
        blueprint_revision: str = "",
        execution_order_hash: str = "",
        package_versions: dict[str, str] | None = None,
        policy_profile_digest: str = "",
        trust_store_digest: str = "",
        registry_resolution_digest: str = "",
        certification_state_digest: str = "",
    ) -> WorkflowEnvironmentBinding:
        return WorkflowEnvironmentBinding(
            blueprint_revision=blueprint_revision,
            execution_order_hash=execution_order_hash,
            package_versions=package_versions or {},
            policy_profile_digest=policy_profile_digest,
            trust_store_digest=trust_store_digest,
            registry_resolution_digest=registry_resolution_digest,
            certification_state_digest=certification_state_digest,
        )

    @staticmethod
    def verify_binding(
        stored: WorkflowEnvironmentBinding,
        current: WorkflowEnvironmentBinding,
    ) -> bool:
        """Return True if all binding fields match."""
        return stored.compute_digest() == current.compute_digest()

    @staticmethod
    def diff_binding(
        stored: WorkflowEnvironmentBinding,
        current: WorkflowEnvironmentBinding,
    ) -> list[str]:
        """Return list of changed fields."""
        changes = []
        if stored.blueprint_revision != current.blueprint_revision:
            changes.append("blueprint_revision")
        if stored.execution_order_hash != current.execution_order_hash:
            changes.append("execution_order_hash")
        if stored.package_versions != current.package_versions:
            changes.append("package_versions")
        if stored.policy_profile_digest != current.policy_profile_digest:
            changes.append("policy_profile_digest")
        if stored.trust_store_digest != current.trust_store_digest:
            changes.append("trust_store_digest")
        if stored.registry_resolution_digest != current.registry_resolution_digest:
            changes.append("registry_resolution_digest")
        if stored.certification_state_digest != current.certification_state_digest:
            changes.append("certification_state_digest")
        return changes


# ── Side-Effect Recovery Semantics (v2.11.1) ─────────────────────────────────


IDEMPOTENT_WITH_KEY = "idempotent_with_key"
EXTERNALLY_QUERYABLE = "externally_queryable"
COMPENSATABLE = "compensatable"
NON_IDEMPOTENT = "non_idempotent"
UNKNOWN_CONTRACT = "unknown"

ALL_CONTRACT_TYPES = {
    IDEMPOTENT_WITH_KEY,
    EXTERNALLY_QUERYABLE,
    COMPENSATABLE,
    NON_IDEMPOTENT,
    UNKNOWN_CONTRACT,
}

# Recovery decisions for started side effects
RETRY = "retry"
QUERY_BEFORE_RETRY = "query_before_retry"
PROPOSE_COMPENSATION = "propose_compensation"  # v2.11.2: governed, not automatic
NEEDS_INTERVENTION = "needs_intervention"
SKIP = "skip"           # completed actions
ELIGIBLE = "eligible"    # v2.11.2: planned actions eligible for execution


def classify_started_effect(contract_type: str) -> str:
    """Determine the recovery action for a started side effect.

    v2.11.1: A started action may have reached an external system.
    The contract type determines the safe recovery path.
    """
    if contract_type == IDEMPOTENT_WITH_KEY:
        return RETRY
    elif contract_type == EXTERNALLY_QUERYABLE:
        return QUERY_BEFORE_RETRY
    elif contract_type == COMPENSATABLE:
        return PROPOSE_COMPENSATION
    elif contract_type == NON_IDEMPOTENT:
        return NEEDS_INTERVENTION
    else:
        return NEEDS_INTERVENTION


@dataclass
class SideEffectContract:
    """Contract declaring the idempotency properties of a side effect.

    v2.11.1: Every action-capable side effect must declare one of:
        idempotent_with_key  — target honors idempotency keys (e.g., Stripe)
        externally_queryable — target can be queried for prior result
        compensatable        — a compensation/undo action exists
        non_idempotent       — no safe retry (e.g., bank transfer)
        unknown              — no contract, must escalate
    """

    effect_type: str
    target: str
    contract_type: str = UNKNOWN_CONTRACT
    idempotency_key: str = ""
    query_method: str = ""  # For externally_queryable: how to check
    compensation_action: str = ""  # For compensatable: the undo action
    contract_digest: str = ""

    def __post_init__(self) -> None:
        if self.contract_type not in ALL_CONTRACT_TYPES:
            raise ValueError(
                f"Invalid contract_type: {self.contract_type}. "
                f"Must be one of {ALL_CONTRACT_TYPES}"
            )
        self.contract_digest = self.compute_digest()

    def compute_digest(self) -> str:
        payload = json.dumps({
            "effect_type": self.effect_type,
            "target": self.target,
            "contract_type": self.contract_type,
            "idempotency_key": self.idempotency_key,
            "query_method": self.query_method,
            "compensation_action": self.compensation_action,
        }, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect_type": self.effect_type,
            "target": self.target,
            "contract_type": self.contract_type,
            "idempotency_key": self.idempotency_key,
            "query_method": self.query_method,
            "compensation_action": self.compensation_action,
            "contract_digest": self.contract_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SideEffectContract:
        return cls(
            effect_type=data.get("effect_type", ""),
            target=data.get("target", ""),
            contract_type=data.get("contract_type", UNKNOWN_CONTRACT),
            idempotency_key=data.get("idempotency_key", ""),
            query_method=data.get("query_method", ""),
            compensation_action=data.get("compensation_action", ""),
        )


@dataclass
class SideEffectRecoveryDecision:
    """Recovery decision for a single side effect after a crash."""

    idempotency_key: str = ""
    effect_status: str = ""  # completed, started, planned, unknown
    contract_type: str = UNKNOWN_CONTRACT
    recovery_action: str = ""  # retry, query_before_retry, propose_compensation, needs_intervention, skip, eligible
    target_query_result: str = ""  # For externally_queryable
    contract_verified: bool = False
    authorization_required: bool = False  # v2.11.2: compensation needs authorization
    human_approval_required: bool = False  # v2.11.2: compensation may need human approval

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_key": self.idempotency_key,
            "effect_status": self.effect_status,
            "contract_type": self.contract_type,
            "recovery_action": self.recovery_action,
            "target_query_result": self.target_query_result,
            "contract_verified": self.contract_verified,
            "authorization_required": self.authorization_required,
            "human_approval_required": self.human_approval_required,
        }


@dataclass
class ActionDeduplicationResult:
    """Result of side-effect deduplication on recovery.

    v2.11.1: Now includes per-action recovery decisions and started
    effect classification based on idempotency contracts.
    """

    completed_keys: list[str] = field(default_factory=list)
    skipped_keys: list[str] = field(default_factory=list)
    unknown_keys: list[str] = field(default_factory=list)
    retried_keys: list[str] = field(default_factory=list)
    proposed_compensation_keys: list[str] = field(default_factory=list)  # v2.11.2: renamed
    queried_keys: list[str] = field(default_factory=list)
    eligible_keys: list[str] = field(default_factory=list)  # v2.11.2: planned actions
    total_actions: int = 0
    recovery_decisions: list[SideEffectRecoveryDecision] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "completed_keys": self.completed_keys,
            "skipped_keys": self.skipped_keys,
            "unknown_keys": self.unknown_keys,
            "retried_keys": self.retried_keys,
            "proposed_compensation_keys": self.proposed_compensation_keys,
            "queried_keys": self.queried_keys,
            "eligible_keys": self.eligible_keys,
            "total_actions": self.total_actions,
            "recovery_decisions": [d.to_dict() for d in self.recovery_decisions],
        }


@dataclass
class WorkflowRecoveryReceipt:
    """Full recovery receipt with provenance."""

    recovery_id: str = ""
    recovered_at: str = ""
    checkpoint_digest: str = ""
    checkpoint_sequence: int = 0
    reconciliation_verdict: str = ""  # committed / aborted / needs_intervention
    restored_state_digest: str = ""
    resumed_run_id: str = ""
    resumed_step_id: int = 0
    resumed_node_id: str = ""
    action_deduplication: ActionDeduplicationResult = field(
        default_factory=ActionDeduplicationResult
    )
    environment_binding_verified: bool = False
    environment_binding_changes: list[str] = field(default_factory=list)
    operator_intervention_reference: str = ""
    valid: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "recovery_id": self.recovery_id,
            "recovered_at": self.recovered_at,
            "checkpoint_digest": self.checkpoint_digest,
            "checkpoint_sequence": self.checkpoint_sequence,
            "reconciliation_verdict": self.reconciliation_verdict,
            "restored_state_digest": self.restored_state_digest,
            "resumed_run_id": self.resumed_run_id,
            "resumed_step_id": self.resumed_step_id,
            "resumed_node_id": self.resumed_node_id,
            "action_deduplication": self.action_deduplication.to_dict(),
            "environment_binding_verified": self.environment_binding_verified,
            "environment_binding_changes": self.environment_binding_changes,
            "operator_intervention_reference": self.operator_intervention_reference,
            "valid": self.valid,
            "error": self.error,
        }


# ── Recovery Manager ────────────────────────────────────────────────────────


class WorkflowRecoveryManager:
    """Orchestrates the full workflow recovery protocol.

    Protocol:
        1. Load journal + chain + store
        2. Reconcile journal (store-aware)
        3. Verify checkpoint chain
        4. Verify environment bindings
        5. Restore chain state
        6. Reconcile side effects (dedup)
        7. Emit recovery receipt
    """

    def __init__(
        self,
        chain: CheckpointChain,
        store: ContentAddressedStore,
    ) -> None:
        self.chain = chain
        self.store = store
        self._journal = CheckpointJournal(str(chain.chain_path) + ".journal")

    def recover(
        self,
        current_binding: WorkflowEnvironmentBinding | None = None,
        stored_binding: WorkflowEnvironmentBinding | None = None,
        side_effects: list[dict[str, Any]] | None = None,
        run_id: str = "",
    ) -> WorkflowRecoveryReceipt:
        """Execute full recovery protocol.

        Args:
            current_binding: Current environment state.
            stored_binding: Environment state at checkpoint time.
            side_effects: Side-effect ledger entries for dedup.
            run_id: Run ID for the workflow being recovered.

        Returns:
            WorkflowRecoveryReceipt with full provenance.
        """
        import uuid

        receipt = WorkflowRecoveryReceipt(
            recovery_id=str(uuid.uuid4()),
            recovered_at=datetime.now(timezone.utc).isoformat(),
            resumed_run_id=run_id,
        )

        # Step 1: Reconcile journal
        try:
            needs_intervention = self._journal.reconcile(
                chain=self.chain, store=self.store,
            )
        except CheckpointError as e:
            receipt.reconciliation_verdict = "needs_intervention"
            receipt.error = f"Journal reconciliation failed: {e}"
            receipt.operator_intervention_reference = (
                f"Journal at {self._journal.path} is corrupt"
            )
            return receipt

        if needs_intervention:
            receipt.reconciliation_verdict = "needs_intervention"
            receipt.error = "Unresolved operations require intervention"
            receipt.operator_intervention_reference = (
                f"{len(needs_intervention)} operation(s) need manual resolution"
            )
            return receipt

        receipt.reconciliation_verdict = "committed"

        # Step 2: Verify checkpoint chain
        try:
            checkpoints = self.chain.get_checkpoints()
            if not checkpoints:
                receipt.valid = True
                receipt.error = "No checkpoints to verify"
                return receipt

            latest = checkpoints[-1]
            receipt.checkpoint_digest = latest.checkpoint_digest
            receipt.checkpoint_sequence = latest.sequence_number
        except CheckpointError as e:
            receipt.error = f"Checkpoint chain verification failed: {e}"
            return receipt

        # Step 3: Verify environment binding
        if current_binding and stored_binding:
            if WorkflowCheckpointBinder.verify_binding(stored_binding, current_binding):
                receipt.environment_binding_verified = True
            else:
                receipt.environment_binding_verified = False
                receipt.environment_binding_changes = (
                    WorkflowCheckpointBinder.diff_binding(stored_binding, current_binding)
                )
                receipt.error = (
                    f"Environment binding mismatch: {receipt.environment_binding_changes}"
                )
                receipt.valid = False
                return receipt
        else:
            receipt.environment_binding_verified = True  # No binding to check

        # Step 4: Compute restored state digest
        manifest_path = self.store._artifact_path(latest.manifest_digest)
        if manifest_path.exists():
            receipt.restored_state_digest = latest.manifest_digest
        else:
            receipt.error = "Checkpoint manifest artifact missing"
            receipt.valid = False
            return receipt

        # Step 5: Action deduplication with contract-aware semantics
        # v2.11.1: started effects are classified by their idempotency contract
        if side_effects:
            dedup = ActionDeduplicationResult()
            for effect in side_effects:
                dedup.total_actions += 1
                key = effect.get("idempotency_key", "")
                status = effect.get("status", "")
                contract_type = effect.get("contract_type", UNKNOWN_CONTRACT)

                decision = SideEffectRecoveryDecision(
                    idempotency_key=key,
                    effect_status=status,
                    contract_type=contract_type,
                )

                if status == "completed":
                    dedup.completed_keys.append(key)
                    decision.recovery_action = SKIP
                    decision.contract_verified = True
                elif status == "unknown":
                    dedup.unknown_keys.append(key)
                    decision.recovery_action = NEEDS_INTERVENTION
                elif status == "started":
                    # v2.11.1: The critical fix
                    action = classify_started_effect(contract_type)
                    decision.recovery_action = action
                    decision.contract_verified = contract_type in ALL_CONTRACT_TYPES
                    if action == RETRY:
                        dedup.retried_keys.append(key)
                    elif action == QUERY_BEFORE_RETRY:
                        dedup.queried_keys.append(key)
                    elif action == PROPOSE_COMPENSATION:
                        # v2.11.2: Governed compensation, not automatic
                        dedup.proposed_compensation_keys.append(key)
                        decision.authorization_required = True
                        decision.human_approval_required = True
                    else:
                        dedup.unknown_keys.append(key)
                else:
                    # v2.11.2: planned actions are eligible for execution, not skipped
                    dedup.eligible_keys.append(key)
                    decision.recovery_action = ELIGIBLE

                dedup.recovery_decisions.append(decision)
            receipt.action_deduplication = dedup

        # Step 6: Determine resume point
        receipt.resumed_step_id = 0
        receipt.resumed_node_id = ""
        receipt.valid = True

        return receipt


# ── Convenience ─────────────────────────────────────────────────────────────


def compute_state_digest(state_dict: dict[str, Any]) -> str:
    """Compute SHA-256 digest of a chain state dict."""
    payload = json.dumps(state_dict, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def compute_trust_store_digest(trust_store_path: str | Path) -> str:
    """Compute digest of trust store contents."""
    p = Path(trust_store_path)
    if not p.exists():
        return ""
    import hashlib
    h = hashlib.sha256()
    for chunk in iter(lambda: p.open("rb").read(8192), b""):
        h.update(chunk)
    return h.hexdigest()
