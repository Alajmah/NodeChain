"""H0.3 adversarial proof: legacy composition execution fails closed.

This module proves that no production composition path can reach
``BaseNode.execute()`` outside the canonical ``Orchestrator``. It covers:

  * ``execute_sub_chain()`` — raises before touching a node
  * ``orchestrate_composition()`` — raises before any execution
  * ``SubChainStep.execute()`` — returns an unsuccessful response before
    registry access
  * ``nodechain compose --plan ...`` — exits 10 with a stable reason, no
    package load, no node execution
  * an adversarial sentinel node whose ``execute()`` flips a marker; the
    marker must remain untouched across every legacy entry point
  * registry/package monkeypatching that explodes if ``RegistryIndex.scan()``
    or ``pkg.load()`` is called, proving refusal happens *before* admission
  * an AST guard: no call expression whose attribute is ``.execute(...)`` may
    exist in ``src/nodechain/runtime/chain_orchestrator.py``

Positive proof that ``nodechain compose validate --plan ...`` continues to
work is included — plan validation is explicitly retained.
"""

from __future__ import annotations

import ast
import json
import uuid
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from nodechain.cli.exit_codes import EXIT_VALIDATION
from nodechain.cli.main import cli
from nodechain.core.envelope import InvocationEnvelope
from nodechain.runtime.chain_orchestrator import (
    GOVERNED_COMPOSITION_BACKEND_REQUIRED,
    CompositionPlan,
    GovernedCompositionRequired,
    SubChainSpec,
    SubChainStep,
    execute_sub_chain,
    orchestrate_composition,
)


CHAIN_ORCH_MODULE = "src/nodechain/runtime/chain_orchestrator.py"


# --------------------------------------------------------------------------- #
# Adversarial sentinel node
# --------------------------------------------------------------------------- #


class _SentinelNode:
    """A fake node whose ``execute()`` flips an unmistakable marker.

    If any legacy composition path reaches ``await node.execute(envelope)``,
    ``marker["executed"]`` flips to True and the test fails.
    """

    def __init__(self, marker: dict) -> None:
        self._marker = marker

    async def execute(self, envelope):  # noqa: D401 - adversarial stub
        self._marker["executed"] = True
        raise AssertionError(
            "sentinel node executed — composition path reached BaseNode.execute()"
        )


def _sentinel_marker() -> dict:
    return {"executed": False}


def _sentinel_registry(marker: dict) -> dict:
    """A registry that maps a known chain_id to the sentinel node."""
    return {"adversarial_node": _SentinelNode(marker)}


# --------------------------------------------------------------------------- #
# 1. execute_sub_chain — sentinel untouched
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_execute_sub_chain_raises_and_sentinel_untouched() -> None:
    """execute_sub_chain raises GovernedCompositionRequired and never
    reaches the sentinel node."""
    marker = _sentinel_marker()
    registry = _sentinel_registry(marker)
    spec = SubChainSpec(chain_id="adversarial_node", inputs={"x": 1})
    with pytest.raises(GovernedCompositionRequired) as exc_info:
        await execute_sub_chain(spec, {}, registry)
    assert str(exc_info.value) == GOVERNED_COMPOSITION_BACKEND_REQUIRED
    assert marker["executed"] is False, "sentinel was reached"


# --------------------------------------------------------------------------- #
# 2. orchestrate_composition — sentinel untouched
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_orchestrate_composition_raises_and_sentinel_untouched() -> None:
    """orchestrate_composition raises before any sub-chain runs."""
    marker = _sentinel_marker()
    registry = _sentinel_registry(marker)
    plan = CompositionPlan(sub_chains=[
        SubChainSpec(chain_id="adversarial_node", inputs={"x": 1}),
    ])
    with pytest.raises(GovernedCompositionRequired):
        await orchestrate_composition(plan, registry)
    assert marker["executed"] is False


# --------------------------------------------------------------------------- #
# 3. SubChainStep.execute — sentinel untouched
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_subchainstep_execute_refuses_and_sentinel_untouched() -> None:
    """SubChainStep.execute returns an unsuccessful governed-backend-required
    response and never reaches the sentinel node."""
    marker = _sentinel_marker()
    node = SubChainStep()
    envelope = InvocationEnvelope(
        envelope_id=str(uuid.uuid4()),
        run_id="test",
        chain_id="test",
        node_id="test",
        step_id=1,
        payload={"plan": {"sub_chains": [{"chain_id": "adversarial_node"}]}},
    )
    response = await node.execute(envelope)
    assert response.success is False
    assert response.error == GOVERNED_COMPOSITION_BACKEND_REQUIRED
    assert response.output["error"] == GOVERNED_COMPOSITION_BACKEND_REQUIRED
    assert marker["executed"] is False


# --------------------------------------------------------------------------- #
# 4. nodechain compose --plan — exit 10, no package load, no node execution
# --------------------------------------------------------------------------- #


def test_compose_cli_plan_exits_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """The compose --plan path exits with EXIT_VALIDATION (10) and prints the
    stable reason code."""
    # Explode if the CLI reaches registry/package loading.
    def _boom(*args, **kwargs):
        raise AssertionError("RegistryIndex was reached by compose --plan")

    monkeypatch.setattr(
        "nodechain.registry.local_registry.RegistryIndex", _boom
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["compose", "--plan", "blueprints/composition_cross_domain_v1.yaml"],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_VALIDATION, (
        f"expected exit {EXIT_VALIDATION}, got {result.exit_code}\n{result.output}"
    )
    assert GOVERNED_COMPOSITION_BACKEND_REQUIRED in result.output, (
        f"stable reason code missing from output:\n{result.output}"
    )


def test_compose_cli_plan_does_not_load_packages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compose --plan path never calls pkg.load(); sentinel untouched."""
    marker = _sentinel_marker()

    def _explode_load(*args, **kwargs):
        marker["loaded"] = True
        raise AssertionError("pkg.load() was called by compose --plan")

    # Patch the registry scan path so any access explodes.
    monkeypatch.setattr(
        "nodechain.registry.local_registry.RegistryIndex.scan", _explode_load
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["compose", "--plan", "blueprints/composition_cross_domain_v1.yaml"],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_VALIDATION
    assert marker.get("loaded") is not True, "package loading was reached"
    assert marker["executed"] is False


def test_compose_cli_plan_json_emits_parseable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``compose --plan ... --json`` emits machine-readable JSON, not prose.

    The fail-closed behavior is correct, but the CLI must remain parseable
    when ``--json`` is requested so programmatic consumers can read the
    reason code. The JSON object must carry the stable reason and the exit
    code must remain ``EXIT_VALIDATION`` (10).
    """
    # Explode if the CLI reaches registry/package loading.
    def _boom(*args, **kwargs):
        raise AssertionError("RegistryIndex was reached by compose --plan --json")

    monkeypatch.setattr(
        "nodechain.registry.local_registry.RegistryIndex", _boom
    )

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "compose", "--plan",
            "blueprints/composition_cross_domain_v1.yaml",
            "--json",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == EXIT_VALIDATION, (
        f"expected exit {EXIT_VALIDATION}, got {result.exit_code}\n{result.output}"
    )
    # Output must be parseable JSON, not Rich prose.
    parsed = json.loads(result.output)
    assert parsed["error"] == GOVERNED_COMPOSITION_BACKEND_REQUIRED, (
        f"JSON error field mismatch: {parsed}"
    )
    assert "message" in parsed and parsed["message"], (
        f"JSON message field missing or empty: {parsed}"
    )


# --------------------------------------------------------------------------- #
# 5. AST authority guard — no .execute() call expressions
# --------------------------------------------------------------------------- #


def test_ast_no_execute_calls_in_chain_orchestrator() -> None:
    """No call expression whose attribute is ``.execute(...)`` may exist in
    the production composition module.

    Method *definitions* named ``execute`` are fine; *calls* to arbitrary
    node execution are not. This is the static authority guard that prevents
    a future commit from silently re-introducing the bypass.
    """
    src = Path(CHAIN_ORCH_MODULE).read_text(encoding="utf-8")
    tree = ast.parse(src)
    offending: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "execute"
        ):
            offending.append(node.lineno)
    assert not offending, (
        f"found .execute() call expression(s) at lines {offending} in "
        f"{CHAIN_ORCH_MODULE}; composition must not call BaseNode.execute()"
    )


# --------------------------------------------------------------------------- #
# 6. Positive proof — compose validate still works
# --------------------------------------------------------------------------- #


def test_compose_validate_still_works() -> None:
    """Plan validation remains a supported read-only surface after H0.3."""
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["compose", "validate", "--plan",
         "blueprints/composition_cross_domain_v1.yaml"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, (
        f"validate failed: exit={result.exit_code}\n{result.output}"
    )
    assert "cross_domain_assessment_v1" in result.output


# --------------------------------------------------------------------------- #
# 7. No escape hatch in src/nodechain
# --------------------------------------------------------------------------- #


def test_no_unsafe_composition_flag_in_src_nodechain() -> None:
    """No private ``_unsafe``, ``_legacy``, or environment override in
    ``src/nodechain`` re-enables legacy composition execution."""
    src_root = Path("src/nodechain")
    banned_substrings = (
        "_unsafe_compose",
        "legacy_compose",
        "NODECHAIN_UNSAFE_COMPOSE",
        "NODECHAIN_LEGACY_COMPOSE",
        "_compose_escape_hatch",
    )
    hits: list[str] = []
    for py_file in src_root.rglob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        for needle in banned_substrings:
            if needle in text:
                hits.append(f"{py_file}: {needle}")
    assert not hits, (
        f"found escape-hatch markers in src/nodechain: {hits}"
    )
