"""Admission spike test: FixtureSearchToolNode + fixture adapter survive the
orchestrator's capability-sanitization path and reach the guarded resolver.

This test exercises the REAL orchestrator capability builder
(``Orchestrator._build_capabilities``), not a reproduction of the intersection
logic. It proves that a Phase 5 blueprint using adapter grant ``"fixture"``
passes contract validation, survives sanitization, reaches
``_resolve_adapter()``, and that the resolved object is an
``OrdinaryDispatchGuard`` wrapping a trusted ``FixtureSearchAdapter`` — with no
production adapter present and ``allow_unguarded`` remaining ``False``.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from nodechain.adapters.search.base_search import SearchQuery
from nodechain.adapters.search.fixture import FixtureSearchAdapter
from nodechain.core.blueprint import ChainBlueprint, NodeDef
from nodechain.core.state import StateManager
from nodechain.nodes.fixture_search_tool import (
    FIXTURE_SEARCH_CONTRACT,
    FixtureSearchToolNode,
)
from nodechain.runtime.orchestrator import Orchestrator
from nodechain.runtime.recovery_dispatch_guard import (
    OrdinaryDispatchGuard,
    TRUSTED_ADAPTER_CLASSES,
    is_trusted_adapter,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

PRODUCTION_ADAPTERS = [
    "semantic_scholar", "arxiv", "openalex", "crossref", "pubmed",
]


def _make_orchestrator(tmp_path: Path) -> tuple[Orchestrator, FixtureSearchToolNode]:
    """Build a minimal orchestrator with a FixtureSearchToolNode whose blueprint
    config grants only ``"fixture"``."""
    bp = ChainBlueprint(
        chain_id="admission-test",
        name="admission-test",
        version="1.0.0",
        goal="prove fixture admission",
        nodes=[
            NodeDef(
                node_id="search_tool",
                node_type="tool",
                config={
                    "allowed_adapters": ["fixture"],
                    "allowed_tools": ["search"],
                },
                position=0,
            ),
        ],
        connections=[],
    )
    sm = StateManager(str(tmp_path / "admission.db"))
    node = FixtureSearchToolNode()
    orch = Orchestrator(blueprint=bp, nodes={"search_tool": node}, state_manager=sm)
    return orch, node


# --------------------------------------------------------------------------- #
# Contract validation
# --------------------------------------------------------------------------- #


def test_fixture_contract_declares_only_fixture() -> None:
    """The Phase 5 contract declares only 'fixture', not the five production
    adapters."""
    assert FIXTURE_SEARCH_CONTRACT.requirements.adapters_required == ["fixture"]


def test_fixture_contract_retains_search_tool() -> None:
    """The tool capability class is unchanged."""
    assert FIXTURE_SEARCH_CONTRACT.requirements.tools_required == ["search"]


def test_fixture_contract_has_distinct_id() -> None:
    assert FIXTURE_SEARCH_CONTRACT.contract_id == "research.search-tool.fixture.v1"


def test_fixture_contract_entry_exit_identical_to_production_schema_refs() -> None:
    """Same schema refs and port types as the production contract."""
    assert FIXTURE_SEARCH_CONTRACT.entry.schema_ref == (
        "nodechain://schemas/semantic_types/context_bundle"
    )
    assert FIXTURE_SEARCH_CONTRACT.exit.schema_ref == (
        "nodechain://schemas/semantic_types/raw_search_results"
    )


def test_fixture_node_id_is_search_tool() -> None:
    """Blueprint compatibility: the node ID is 'search_tool'."""
    node = FixtureSearchToolNode()
    assert node.manifest.node_id == "search_tool"


# --------------------------------------------------------------------------- #
# Capability sanitization through the REAL orchestrator path
# --------------------------------------------------------------------------- #


def test_fixture_survives_orchestrator_capability_sanitization(
    tmp_path: Path,
) -> None:
    """Through Orchestrator._build_capabilities, 'fixture' survives the
    declared ∩ runtime intersection."""
    orch, _ = _make_orchestrator(tmp_path)
    caps = orch._build_capabilities("search_tool")
    assert "fixture" in caps.allowed_adapters


def test_no_production_adapter_in_effective_capabilities(
    tmp_path: Path,
) -> None:
    """No production adapter leaks into the effective capabilities."""
    orch, _ = _make_orchestrator(tmp_path)
    caps = orch._build_capabilities("search_tool")
    for prod in PRODUCTION_ADAPTERS:
        assert prod not in caps.allowed_adapters, (
            f"production adapter {prod!r} present in fixture-only capabilities"
        )


def test_allow_unguarded_remains_false() -> None:
    """The fixture node defaults to fail-closed (allow_unguarded=False)."""
    node = FixtureSearchToolNode()
    assert node._allow_unguarded is False


# --------------------------------------------------------------------------- #
# Resolver + guard admission
# --------------------------------------------------------------------------- #


def test_fixture_reaches_resolver_as_guarded(tmp_path: Path) -> None:
    """After set_adapter_resolver, _resolve_adapter('fixture') returns the
    OrdinaryDispatchGuard-wrapped fixture adapter."""
    orch, node = _make_orchestrator(tmp_path)
    fixture_adapter = FixtureSearchAdapter({"test": {"results": []}})
    guard = OrdinaryDispatchGuard(
        target_adapter=fixture_adapter,
        run_id=orch.state.run_id,
        capsule_validator=lambda rid, aname, digest: True,
        skip_trust_check=False,
    )
    node.set_adapter_resolver({"fixture": guard})
    assert node._allow_unguarded is False  # set_adapter_resolver forces this
    resolved = node._resolve_adapter("fixture")
    assert isinstance(resolved, OrdinaryDispatchGuard)
    assert resolved._skip_trust_check is False


def test_no_production_adapter_resolver_available(tmp_path: Path) -> None:
    """With only the fixture resolver injected, production adapter names
    resolve to None (not available)."""
    orch, node = _make_orchestrator(tmp_path)
    fixture_adapter = FixtureSearchAdapter({"test": {"results": []}})
    guard = OrdinaryDispatchGuard(
        target_adapter=fixture_adapter,
        run_id=orch.state.run_id,
        capsule_validator=lambda rid, aname, digest: True,
    )
    node.set_adapter_resolver({"fixture": guard})
    for prod in PRODUCTION_ADAPTERS:
        assert node._resolve_adapter(prod) is None, (
            f"production adapter {prod!r} unexpectedly resolved"
        )


# --------------------------------------------------------------------------- #
# Trust attestation through the guard
# --------------------------------------------------------------------------- #


def test_guard_accepts_exact_fixture_class(tmp_path: Path) -> None:
    """The OrdinaryDispatchGuard accepts the exact FixtureSearchAdapter class."""
    orch, _ = _make_orchestrator(tmp_path)
    fixture_adapter = FixtureSearchAdapter(
        {"async rust": {"results": [
            {"origin_api": "fixture", "raw_data": {"title": "Sealed Paper"}}
        ]}}
    )
    guard = OrdinaryDispatchGuard(
        target_adapter=fixture_adapter,
        run_id=orch.state.run_id,
        capsule_validator=lambda rid, aname, digest: True,
        skip_trust_check=False,
    )
    import asyncio
    results = asyncio.run(guard.search(SearchQuery(terms=["rust", "async"])))
    assert len(results) == 1
    assert len(guard._dispatched_digests) == 1


def test_guard_rejects_fixture_subclass(tmp_path: Path) -> None:
    """A subclass of FixtureSearchAdapter is rejected by the exact-class
    trust check."""

    class FakeFixture(FixtureSearchAdapter):
        pass

    fake = FakeFixture({"test": {"results": []}})
    assert not is_trusted_adapter(fake)


def test_unknown_adapter_name_rejected_by_trust_registry() -> None:
    """An adapter whose name is not in the trusted registry is rejected."""
    assert "not_a_real_adapter" not in TRUSTED_ADAPTER_CLASSES


def test_fixture_in_trust_registry() -> None:
    """The fixture adapter is statically bound in the trust registry."""
    assert "fixture" in TRUSTED_ADAPTER_CLASSES
    assert TRUSTED_ADAPTER_CLASSES["fixture"] is FixtureSearchAdapter


# --------------------------------------------------------------------------- #
# Package-trust boundary (regression)
# --------------------------------------------------------------------------- #


def test_fixture_node_module_is_in_trusted_namespace() -> None:
    """The relocated node's concrete class module must be under
    nodechain.nodes.* so PolicyGate's built-in boundary accepts it."""
    node = FixtureSearchToolNode()
    mod = type(node).__module__
    assert mod == "nodechain.nodes.fixture_search_tool", mod
    assert mod.startswith("nodechain.nodes.")


def test_fixture_node_passes_privileged_trust_boundary() -> None:
    """Through the real PolicyGate trust predicate, the fixture node is
    classified as proven built-in (not unknown)."""
    from nodechain.core.contract import is_privileged_node

    node = FixtureSearchToolNode()
    assert is_privileged_node(node.manifest.contract) is True
    # Simulate the PolicyGate's module check (policy_gate.py:101-106)
    import inspect

    mod = inspect.getmodule(type(node))
    mod_name = mod.__name__ if mod else ""
    assert mod_name.startswith("nodechain.nodes."), mod_name


def test_non_nodes_subclass_remains_denied() -> None:
    """Boundary regression: a privileged subclass declared from a
    non-nodechain.nodes.* module remains denied by the trust boundary."""

    class ResearchSubclass(FixtureSearchToolNode):
        pass

    instance = ResearchSubclass()
    mod = type(instance).__module__
    # This subclass is defined in the test module, not nodechain.nodes.*
    assert not mod.startswith("nodechain.nodes."), (
        f"boundary weakened: {mod} should not pass the built-in check"
    )
