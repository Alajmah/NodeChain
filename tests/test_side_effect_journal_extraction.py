"""v3.4.0 — Side-Effect Journaling Extraction (structural characterization).

These tests guard the v2.75 decomposition boundary: the six side-effect
journaling methods were physically moved from orchestrator.py into
SideEffectJournalMixin (src/nodechain/runtime/side_effect_journal.py).

They are intentionally source-based and structural — they verify the
extraction boundary without depending on runtime behavior, so they cannot
mask behavioral regressions (those are covered by the existing side-effect,
recovery, resume, and trace characterization suites).

Zero behavioral change is the contract; these tests assert the shape of
that contract, not its execution.
"""
from __future__ import annotations

from pathlib import Path

from nodechain.runtime.orchestrator import Orchestrator
from nodechain.runtime.side_effect_journal import SideEffectJournalMixin
from nodechain.runtime.node_event_emitter import NodeEventEmitterMixin


# The six methods extracted in v3.4.0.
EXTRACTED_METHODS = (
    "_journal_planned_side_effects",
    "_journal_search_operations",
    "_assert_declared_side_effect",
    "_journal_one",
    "_reconcile_side_effects_on_resume",
    "_get_declared_se_types",
)

# _node_has_contract sits inside the same source region but was intentionally
# NOT extracted — it is a general helper used beyond side-effect journaling.
KEPT_ON_ORCHESTRATOR = ("_node_has_contract",)

ORCHESTRATOR_PATH = (
    Path(__file__).resolve().parent.parent
    / "src" / "nodechain" / "runtime" / "orchestrator.py"
)


def test_orchestrator_inherits_side_effect_journal_mixin():
    """Orchestrator must subclass SideEffectJournalMixin (extraction wiring)."""
    assert issubclass(Orchestrator, SideEffectJournalMixin), (
        "Orchestrator must inherit SideEffectJournalMixin after v2.75 extraction"
    )
    # NodeEventEmitterMixin (v2.74) must still be present — this release does
    # not regress the prior decomposition.
    assert issubclass(Orchestrator, NodeEventEmitterMixin), (
        "NodeEventEmitterMixin inheritance (v2.74) must remain intact"
    )


def test_mro_orders_mixins_before_object():
    """Both mixins must appear in the MRO; order keeps NodeEventEmitterMixin first."""
    mro_names = [cls.__name__ for cls in Orchestrator.__mro__]
    assert "SideEffectJournalMixin" in mro_names
    assert "NodeEventEmitterMixin" in mro_names
    # NodeEventEmitterMixin was declared first in the class bases; it should
    # precede SideEffectJournalMixin in the linearization.
    assert mro_names.index("NodeEventEmitterMixin") < mro_names.index(
        "SideEffectJournalMixin"
    ), "inheritance order should keep NodeEventEmitterMixin before SideEffectJournalMixin"


def test_side_effect_journal_mixin_exposes_expected_methods():
    """The mixin class itself must define all six extracted methods."""
    missing = [m for m in EXTRACTED_METHODS if m not in SideEffectJournalMixin.__dict__]
    assert not missing, f"SideEffectJournalMixin is missing: {missing}"


def test_extracted_methods_resolve_on_orchestrator_via_mixin():
    """Each extracted method must still be callable on Orchestrator instances.

    Resolution must come from SideEffectJournalMixin (not Orchestrator itself),
    proving the methods are inherited rather than redefined.
    """
    for method_name in EXTRACTED_METHODS:
        assert hasattr(Orchestrator, method_name), (
            f"{method_name} must be resolvable on Orchestrator after extraction"
        )
        defining_cls = None
        for cls in Orchestrator.__mro__:
            if method_name in cls.__dict__:
                defining_cls = cls
                break
        assert defining_cls is SideEffectJournalMixin, (
            f"{method_name} should be defined on SideEffectJournalMixin, "
            f"found on {defining_cls}"
        )


def test_no_side_effect_journal_methods_left_on_orchestrator_source():
    """Conservative source-level guard: the method defs must be gone from
    orchestrator.py. Checks physical presence of `def <name>` in source, not
    runtime availability — this protects the decomposition boundary.
    """
    source = ORCHESTRATOR_PATH.read_text(encoding="utf-8")
    leftovers = [
        f"def {name}"
        for name in EXTRACTED_METHODS
        if f"def {name}" in source
    ]
    assert not leftovers, (
        f"extracted method definitions still present in orchestrator.py: {leftovers}"
    )


def test_node_has_contract_remains_on_orchestrator():
    """_node_has_contract was intentionally NOT extracted (general helper).

    _assert_declared_side_effect calls it via self.; it must stay on
    Orchestrator and resolve there directly (not via a mixin).
    """
    for name in KEPT_ON_ORCHESTRATOR:
        assert "_node_has_contract" in Orchestrator.__dict__, (
            "_node_has_contract must remain defined directly on Orchestrator"
        )


def test_no_method_name_collisions_between_mixins():
    """The two mixins must not define the same method name.

    A collision would make inheritance order silently change behavior.
    This guards the (NodeEventEmitterMixin, SideEffectJournalMixin) ordering.
    """
    node_emitter_methods = set(NodeEventEmitterMixin.__dict__.keys())
    side_effect_methods = set(SideEffectJournalMixin.__dict__.keys())
    # Filter out dunder/non-method attributes.
    ne_real = {
        n for n in node_emitter_methods
        if not n.startswith("__") and callable(getattr(NodeEventEmitterMixin, n, None))
    }
    se_real = {
        n for n in side_effect_methods
        if not n.startswith("__") and callable(getattr(SideEffectJournalMixin, n, None))
    }
    collisions = ne_real & se_real
    assert not collisions, (
        f"method-name collisions between mixins: {sorted(collisions)}; "
        "inheritance order would silently change behavior"
    )
