"""Phase 5 specialized search node for sealed fixture-corpus runs.

``FixtureSearchToolNode`` is a product-local specialization of the production
``SearchToolNode``. It inherits all execution behavior — ``execute()``,
``_resolve_adapter()``, side-effect gating, FPV1 validation, deduplication,
and result handling — unchanged. The **only** override is the
manifest/contract declaration: the Phase 5 contract declares
``adapters_required=["fixture"]`` (not the five production adapters), which
makes the sealed research workspace fail closed against accidental
live-provider dispatch.

Why a subclass instead of mutating the global contract
------------------------------------------------------
The orchestrator sanitizes effective adapter capabilities as the intersection
of the node contract's declared ``adapters_required`` and the run
configuration's ``allowed_adapters``. The global ``SEARCH_TOOL_CONTRACT``
declares only the five production adapters, so a ``"fixture"`` grant is
sanitized out before it can reach the adapter resolver. Broadening the global
contract would expose every NodeChain deployment to a fixture grant; the
specialization confines it to the Phase 5 research workspace.

Invariants
----------
* ``manifest.node_id == "search_tool"`` (same node ID — blueprint compatibility).
* ``contract.adapters_required == ["fixture"]`` (only the sealed adapter).
* ``contract.tools_required == ["search"]`` (same tool capability class).
* ``contract.entry / exit / side_effects`` identical to ``SEARCH_TOOL_CONTRACT``
  (same schema refs, port types, side-effect declaration).
* ``contract.contract_id == "research.search-tool.fixture.v1"`` (distinct).
* ``execute()``, ``_resolve_adapter()``, side-effect behavior, FPV1
  validation, and deduplication are inherited untouched.
"""

from __future__ import annotations

from nodechain.core.contract import (
    EntryContract,
    ExitContract,
    NodeContract,
    Requirements,
    SideEffect,
)
from nodechain.core.manifest import NodeManifest
from nodechain.nodes.search_tool import PortType, SearchToolNode

#: Phase 5 sealed-fixture contract. Identical to ``SEARCH_TOOL_CONTRACT``
#: except: (1) ``contract_id`` is distinct, (2) ``adapters_required`` declares
#: only ``"fixture"``. This makes the sealed workspace fail closed against
#: accidental live-provider dispatch.
FIXTURE_SEARCH_CONTRACT = NodeContract(
    contract_id="research.search-tool.fixture.v1",
    node_id="search_tool",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CONTEXT_BUNDLE,
        schema_ref="nodechain://schemas/semantic_types/context_bundle",
        required_fields=["search_queries", "adapter_grants"],
    ),
    exit=ExitContract(
        output_type=PortType.RAW_SEARCH_RESULTS,
        schema_ref="nodechain://schemas/semantic_types/raw_search_results",
        guaranteed_fields=["results"],
    ),
    side_effects=[
        SideEffect(effect_type="external_call", target="search_apis"),
    ],
    requirements=Requirements(
        model_required=False,
        tools_required=["search"],
        adapters_required=["fixture"],
    ),
)


class FixtureSearchToolNode(SearchToolNode):
    """Sealed-fixture search node for the Phase 5 research workspace.

    Inherits all behavior from :class:`SearchToolNode`. Overrides only the
    ``manifest`` property to return the fixture-specialized contract. The node
    ID remains ``"search_tool"`` for blueprint compatibility.
    """

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="search_tool",
            node_type="tool",
            name="Fixture Search Tool",
            description=(
                "Sealed fixture-corpus search node for governed research "
                "workspace runs. Inherits all execution behavior from "
                "SearchToolNode; declares only the 'fixture' adapter."
            ),
            contract=FIXTURE_SEARCH_CONTRACT,
        )
