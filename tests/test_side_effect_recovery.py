"""Side-Effect Recovery Semantics Tests (v2.21.3).

Proves that recovery handles started side effects correctly based on
their idempotency contract. A started action may have reached an
external system before crash — retrying it is safe only when the
contract guarantees idempotency.

Contract types and recovery actions:
    idempotent_with_key  → retry with same key
    externally_queryable → query target before retry
    compensatable        → operator-approved compensation path
    non_idempotent       → needs_intervention
    unknown              → needs_intervention
"""

from __future__ import annotations

import json
import pytest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from nodechain.sdk.artifact_retention import ContentAddressedStore
from nodechain.sdk.evidence_checkpoint import (
    CheckpointChain,
    create_checkpoint,
)
from nodechain.sdk.workflow_recovery import (
    WorkflowRecoveryManager,
    WorkflowCheckpointBinder,
    WorkflowEnvironmentBinding,
    SideEffectContract,
    SideEffectRecoveryDecision,
    ActionDeduplicationResult,
    classify_started_effect,
    IDEMPOTENT_WITH_KEY,
    EXTERNALLY_QUERYABLE,
    COMPENSATABLE,
    NON_IDEMPOTENT,
    UNKNOWN_CONTRACT,
    RETRY,
    QUERY_BEFORE_RETRY,
    PROPOSE_COMPENSATION,
    NEEDS_INTERVENTION,
    SKIP,
    ALL_CONTRACT_TYPES,
)


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


@pytest.fixture
def store(tmp_path):
    return ContentAddressedStore(tmp_path / "store")


@pytest.fixture
def chain(tmp_path):
    return CheckpointChain(tmp_path / "chain.json")


@pytest.fixture
def populated_store(store):
    store.retain(b"artifact-1")
    store.retain(b"artifact-2")
    return store


@pytest.fixture
def base_binding():
    return WorkflowCheckpointBinder.capture_binding(
        blueprint_revision="test#v1",
        execution_order_hash="abc123",
    )


# ── AC-1: SideEffectContract / IdempotencyContract ──────────────────────────

class TestAC1SideEffectContract:
    """1. SideEffectContract metadata on action-capable nodes."""

    def test_contract_types(self):
        """All 5 contract types exist."""
        assert IDEMPOTENT_WITH_KEY == "idempotent_with_key"
        assert EXTERNALLY_QUERYABLE == "externally_queryable"
        assert COMPENSATABLE == "compensatable"
        assert NON_IDEMPOTENT == "non_idempotent"
        assert UNKNOWN_CONTRACT == "unknown"
        assert len(ALL_CONTRACT_TYPES) == 5

    def test_contract_creation(self):
        contract = SideEffectContract(
            effect_type="external_call",
            target="api.stripe.com/charges",
            contract_type=IDEMPOTENT_WITH_KEY,
            idempotency_key="charge-001",
        )
        assert contract.contract_digest != ""
        assert contract.contract_type == IDEMPOTENT_WITH_KEY

    def test_contract_invalid_type_rejected(self):
        with pytest.raises(ValueError):
            SideEffectContract(
                effect_type="external_call",
                target="x",
                contract_type="invalid_type",
            )

    def test_contract_digest_changes_on_fields(self):
        c1 = SideEffectContract(
            effect_type="external_call",
            target="api.example.com",
            contract_type=IDEMPOTENT_WITH_KEY,
        )
        c2 = SideEffectContract(
            effect_type="external_call",
            target="api.example.com",
            contract_type=NON_IDEMPOTENT,
        )
        assert c1.contract_digest != c2.contract_digest

    def test_contract_roundtrip(self):
        contract = SideEffectContract(
            effect_type="tool_invocation",
            target="deployment",
            contract_type=COMPENSATABLE,
            compensation_action="rollback_deployment",
        )
        d = contract.to_dict()
        restored = SideEffectContract.from_dict(d)
        assert restored.contract_digest == contract.contract_digest
        assert restored.compensation_action == "rollback_deployment"


# ── AC-2: classify_started_effect ───────────────────────────────────────────

class TestAC2ClassifyStartedEffect:
    """2. Recovery decision for started effects by contract type."""

    def test_idempotent_with_key_returns_retry(self):
        assert classify_started_effect(IDEMPOTENT_WITH_KEY) == RETRY

    def test_externally_queryable_returns_query(self):
        assert classify_started_effect(EXTERNALLY_QUERYABLE) == QUERY_BEFORE_RETRY

    def test_compensatable_returns_compensate(self):
        assert classify_started_effect(COMPENSATABLE) == PROPOSE_COMPENSATION

    def test_non_idempotent_returns_intervention(self):
        assert classify_started_effect(NON_IDEMPOTENT) == NEEDS_INTERVENTION

    def test_unknown_returns_intervention(self):
        assert classify_started_effect(UNKNOWN_CONTRACT) == NEEDS_INTERVENTION


# ── AC-3: Recovery with started effects ─────────────────────────────────────

class TestAC3StartedEffectRecovery:
    """3. Started effect recovery by contract type."""

    def test_started_idempotent_with_key_safely_retried(
        self, populated_store, chain, key_pair
    ):
        """started + idempotent_with_key → retry (safe with same key)."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "payment-001",
            "status": "started",
            "contract_type": IDEMPOTENT_WITH_KEY,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-idem")

        assert receipt.valid
        assert "payment-001" in receipt.action_deduplication.retried_keys
        assert "payment-001" not in receipt.action_deduplication.unknown_keys

    def test_started_externally_queryable_queried(
        self, populated_store, chain, key_pair
    ):
        """started + externally_queryable → query_before_retry."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "deploy-001",
            "status": "started",
            "contract_type": EXTERNALLY_QUERYABLE,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-query")

        assert receipt.valid
        assert "deploy-001" in receipt.action_deduplication.queried_keys

    def test_started_compensatable_compensated(
        self, populated_store, chain, key_pair
    ):
        """started + compensatable → compensate."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "migration-001",
            "status": "started",
            "contract_type": COMPENSATABLE,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-compensate")

        assert receipt.valid
        assert "migration-001" in receipt.action_deduplication.proposed_compensation_keys

    def test_started_non_idempotent_needs_intervention(
        self, populated_store, chain, key_pair
    ):
        """started + non_idempotent → needs_intervention."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "bank-transfer-001",
            "status": "started",
            "contract_type": NON_IDEMPOTENT,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-nonidem")

        assert "bank-transfer-001" in receipt.action_deduplication.unknown_keys
        # Check recovery decision details
        decisions = {d.idempotency_key: d for d in receipt.action_deduplication.recovery_decisions}
        assert decisions["bank-transfer-001"].recovery_action == NEEDS_INTERVENTION

    def test_started_unknown_contract_needs_intervention(
        self, populated_store, chain, key_pair
    ):
        """started + unknown → needs_intervention."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "action-001",
            "status": "started",
            "contract_type": UNKNOWN_CONTRACT,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-unknown")

        assert "action-001" in receipt.action_deduplication.unknown_keys


# ── AC-4: Completed and planned effects ─────────────────────────────────────

class TestAC4CompletedAndPlannedEffects:
    """Completed effects are skipped; planned effects are safe to execute."""

    def test_completed_always_skipped(self, populated_store, chain, key_pair):
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [
            {"idempotency_key": "k1", "status": "completed", "contract_type": NON_IDEMPOTENT},
            {"idempotency_key": "k2", "status": "completed", "contract_type": UNKNOWN_CONTRACT},
        ]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-completed")

        assert "k1" in receipt.action_deduplication.completed_keys
        assert "k2" in receipt.action_deduplication.completed_keys

    def test_planned_safe_to_execute(self, populated_store, chain, key_pair):
        """Planned effects haven't started, so they're safe to re-execute."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-planned",
            "status": "planned",
            "contract_type": NON_IDEMPOTENT,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-planned")

        # Planned is safe because it never started
        assert "k-planned" in receipt.action_deduplication.eligible_keys


# ── AC-5: Recovery receipt records contract decisions ───────────────────────

class TestAC5ReceiptContractRecords:
    """5. Recovery receipt records contract and decision details."""

    def test_receipt_has_recovery_decisions(
        self, populated_store, chain, key_pair
    ):
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [
            {"idempotency_key": "k1", "status": "completed", "contract_type": IDEMPOTENT_WITH_KEY},
            {"idempotency_key": "k2", "status": "started", "contract_type": NON_IDEMPOTENT},
            {"idempotency_key": "k3", "status": "planned", "contract_type": UNKNOWN_CONTRACT},
        ]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-decisions")

        decisions = receipt.action_deduplication.recovery_decisions
        assert len(decisions) == 3

        d1 = next(d for d in decisions if d.idempotency_key == "k1")
        assert d1.recovery_action == SKIP
        assert d1.contract_verified

        d2 = next(d for d in decisions if d.idempotency_key == "k2")
        assert d2.recovery_action == NEEDS_INTERVENTION
        assert d2.contract_type == NON_IDEMPOTENT

    def test_receipt_to_dict_includes_decisions(
        self, populated_store, chain, key_pair
    ):
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-test",
            "status": "started",
            "contract_type": IDEMPOTENT_WITH_KEY,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-dict")
        d = receipt.to_dict()

        assert "recovery_decisions" in d["action_deduplication"]
        assert len(d["action_deduplication"]["recovery_decisions"]) == 1
        assert d["action_deduplication"]["recovery_decisions"][0]["recovery_action"] == RETRY


# ── AC-6: Realistic external-action simulator crash tests ───────────────────

class TestAC6ExternalActionSimulator:
    """6. Crash tests against a realistic external-action simulator."""

    def test_payment_scenario_idempotent_retry(
        self, populated_store, chain, key_pair
    ):
        """Simulate: payment API call started, process crashed.

        With idempotent_with_key contract, retry is safe.
        """
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "stripe-charge-abc123",
            "status": "started",
            "contract_type": IDEMPOTENT_WITH_KEY,
            "side_effect_type": "external_call",
            "node_id": "payment_processor",
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-payment")

        # Safe to retry — Stripe deduplicates by key
        assert receipt.valid
        assert "stripe-charge-abc123" in receipt.action_deduplication.retried_keys

    def test_bank_transfer_non_idempotent_blocked(
        self, populated_store, chain, key_pair
    ):
        """Simulate: bank transfer started, process crashed.

        With non_idempotent contract, must escalate to human.
        """
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "wire-transfer-001",
            "status": "started",
            "contract_type": NON_IDEMPOTENT,
            "side_effect_type": "external_call",
            "node_id": "bank_connector",
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-bank")

        # Cannot safely retry a bank transfer
        assert "wire-transfer-001" in receipt.action_deduplication.unknown_keys

    def test_deployment_externally_queryable(
        self, populated_store, chain, key_pair
    ):
        """Simulate: deployment started, process crashed.

        With externally_queryable contract, query target first.
        """
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "deploy-k8s-001",
            "status": "started",
            "contract_type": EXTERNALLY_QUERYABLE,
            "side_effect_type": "tool_invocation",
            "node_id": "deployment_manager",
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-deploy")

        assert "deploy-k8s-001" in receipt.action_deduplication.queried_keys

    def test_database_migration_compensatable(
        self, populated_store, chain, key_pair
    ):
        """Simulate: DB migration started, process crashed.

        With compensatable contract, compensation path is available.
        """
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "db-migration-001",
            "status": "started",
            "contract_type": COMPENSATABLE,
            "side_effect_type": "tool_invocation",
            "node_id": "migration_runner",
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-migration")

        assert "db-migration-001" in receipt.action_deduplication.proposed_compensation_keys

    def test_mixed_side_effects_correct_classification(
        self, populated_store, chain, key_pair
    ):
        """Mixed side effects with different contracts all classified correctly."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [
            {"idempotency_key": "k-completed", "status": "completed", "contract_type": IDEMPOTENT_WITH_KEY},
            {"idempotency_key": "k-retry", "status": "started", "contract_type": IDEMPOTENT_WITH_KEY},
            {"idempotency_key": "k-query", "status": "started", "contract_type": EXTERNALLY_QUERYABLE},
            {"idempotency_key": "k-compensate", "status": "started", "contract_type": COMPENSATABLE},
            {"idempotency_key": "k-block", "status": "started", "contract_type": NON_IDEMPOTENT},
            {"idempotency_key": "k-unknown", "status": "started", "contract_type": UNKNOWN_CONTRACT},
            {"idempotency_key": "k-planned", "status": "planned", "contract_type": NON_IDEMPOTENT},
        ]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-mixed")

        dedup = receipt.action_deduplication
        assert dedup.total_actions == 7
        assert "k-completed" in dedup.completed_keys
        assert "k-retry" in dedup.retried_keys
        assert "k-query" in dedup.queried_keys
        assert "k-compensate" in dedup.proposed_compensation_keys
        assert "k-block" in dedup.unknown_keys
        assert "k-unknown" in dedup.unknown_keys
        assert "k-planned" in dedup.eligible_keys

        # Verify no key appears in multiple lists
        all_keys = (
            dedup.completed_keys + dedup.retried_keys + dedup.queried_keys +
            dedup.proposed_compensation_keys + dedup.unknown_keys + dedup.eligible_keys
        )
        assert len(all_keys) == len(set(all_keys)), "Duplicate keys across categories"


# ── AC-7: Dashboard health rule ─────────────────────────────────────────────

class TestAC7DashboardHealthRule:
    """7. Dashboard health rule for unresolved side-effect ambiguity."""

    def test_hr025_exists(self):
        from nodechain.cli.dashboard_health import RULES_BY_ID
        assert "HR-025" in RULES_BY_ID

    def test_hr025_triggers_on_unknown_side_effects(self):
        from nodechain.cli.dashboard_health import HR025UnresolvedSideEffectAmbiguity
        rule = HR025UnresolvedSideEffectAmbiguity()
        result = rule.evaluate({
            "workflow_recovery": {
                "enabled": True,
                "unknown_side_effect_count": 3,
            }
        })
        assert result is not None
        assert "3 side effect(s)" in result["description"]

    def test_hr025_does_not_trigger_when_clean(self):
        from nodechain.cli.dashboard_health import HR025UnresolvedSideEffectAmbiguity
        rule = HR025UnresolvedSideEffectAmbiguity()
        result = rule.evaluate({
            "workflow_recovery": {
                "enabled": True,
                "unknown_side_effect_count": 0,
            }
        })
        assert result is None

    def test_all_rules_count_39(self):
        from nodechain.cli.dashboard_health import ALL_RULES
        assert len(ALL_RULES) == 65  # 49 HR + 5 MEM + 6 SE + 5 MR (v2.41.0)


# ── Critical regression: v2.21.3 behavior ───────────────────────────────────

class TestV2110BackwardsCompat:
    """Verify v2.21.3 tests still pass with v2.21.3 changes."""

    def test_completed_effects_still_skipped(
        self, populated_store, chain, key_pair
    ):
        """v2.21.3 behavior: completed → skip."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [
            {"idempotency_key": "k1", "status": "completed"},
            {"idempotency_key": "k2", "status": "completed"},
        ]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-compat")

        assert len(receipt.action_deduplication.completed_keys) == 2

    def test_planned_effects_still_safe_to_execute(
        self, populated_store, chain, key_pair
    ):
        """v2.21.3 behavior: planned → safe to execute (skipped in dedup)."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-planned",
            "status": "planned",
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-planned-compat")

        assert "k-planned" in receipt.action_deduplication.eligible_keys

    def test_no_contract_started_treated_as_intervention(
        self, populated_store, chain, key_pair
    ):
        """v2.21.3 behavior: started without contract_type → needs_intervention.

        This is the critical fix — previously started effects were
        silently re-executed. Now they default to unknown contract → intervention.
        """
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-started-no-contract",
            "status": "started",
            # No contract_type specified — defaults to unknown
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-no-contract")

        # Without a contract, started → needs_intervention (NOT retry)
        assert "k-started-no-contract" in receipt.action_deduplication.unknown_keys
        assert "k-started-no-contract" not in receipt.action_deduplication.retried_keys


# ── v2.21.3: Semantic corrections ───────────────────────────────────────────

class TestV2112PlannedIsEligible:
    """v2.21.3: planned actions are 'eligible for execution', not 'skip'."""

    def test_planned_in_eligible_keys(
        self, populated_store, chain, key_pair
    ):
        """Planned actions should be in eligible_keys, not skipped_keys."""
        from nodechain.sdk.workflow_recovery import ELIGIBLE
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-future",
            "status": "planned",
            "contract_type": NON_IDEMPOTENT,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-v2112-planned")

        dedup = receipt.action_deduplication
        assert "k-future" in dedup.eligible_keys
        assert "k-future" not in dedup.skipped_keys  # v2.21.3: NOT skipped

        # Recovery decision should say eligible
        decisions = {d.idempotency_key: d for d in dedup.recovery_decisions}
        assert decisions["k-future"].recovery_action == ELIGIBLE


class TestV2112CompensationIsGoverned:
    """v2.21.3: compensatable actions require authorization, not automatic."""

    def test_compensation_requires_authorization(
        self, populated_store, chain, key_pair
    ):
        """started + compensatable → propose_compensation + authorization_required."""
        from nodechain.sdk.workflow_recovery import PROPOSE_COMPENSATION
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "db-migration-001",
            "status": "started",
            "contract_type": COMPENSATABLE,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-v2112-comp")

        decisions = {d.idempotency_key: d for d in receipt.action_deduplication.recovery_decisions}
        d = decisions["db-migration-001"]
        assert d.recovery_action == PROPOSE_COMPENSATION
        assert d.authorization_required is True
        assert d.human_approval_required is True

    def test_compensation_key_in_proposed_list(
        self, populated_store, chain, key_pair
    ):
        """Compensatable action key appears in proposed_compensation_keys."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "undo-001",
            "status": "started",
            "contract_type": COMPENSATABLE,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-v2112-keys")

        assert "undo-001" in receipt.action_deduplication.proposed_compensation_keys

    def test_compensation_decision_dict_has_auth_fields(
        self, populated_store, chain, key_pair
    ):
        """Decision to_dict includes authorization fields."""
        priv_pem, pub_pem = key_pair
        create_checkpoint(populated_store, chain, priv_pem, pub_pem)

        side_effects = [{
            "idempotency_key": "k-comp",
            "status": "started",
            "contract_type": COMPENSATABLE,
        }]

        manager = WorkflowRecoveryManager(chain, populated_store)
        receipt = manager.recover(side_effects=side_effects, run_id="run-v2112-dict")

        d = receipt.to_dict()
        decisions = d["action_deduplication"]["recovery_decisions"]
        comp_decision = [dec for dec in decisions if dec["idempotency_key"] == "k-comp"][0]
        assert "authorization_required" in comp_decision
        assert comp_decision["authorization_required"] is True
        assert "human_approval_required" in comp_decision
        assert comp_decision["human_approval_required"] is True
