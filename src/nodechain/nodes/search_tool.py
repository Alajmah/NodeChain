"""Node 4: Search Tool — multi-source domain-routed academic search."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
    SideEffect,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.adapters.search.base_search import SearchQuery, SearchAdapterError
from nodechain.core.provenance import (
    ProvenanceError,
    ProvenanceFailureCode,
    ProvenanceEntry,
    validate_live_result,
    merge_provenance_entries,
    check_mode_consistency,
    derive_dedup_origins,
)
from nodechain.nodes.base_node import BaseNode
# v3.5.0: dispatch-integrity exceptions must escape the node (ChatGPT T3 gate)
from nodechain.runtime.recovery_dispatch_guard import (
    OrdinaryDispatchError,
    RecoveryDispatchError,
)


SEARCH_TOOL_CONTRACT = NodeContract(
    contract_id="research.search-tool.v1",
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
        # v2.43.0: tool capability class (not adapter names)
        tools_required=["search"],
        # v2.43.0: specific backend/adapter grants
        adapters_required=[
            "semantic_scholar", "arxiv", "openalex", "crossref", "pubmed",
        ],
    ),
)


def _normalize_doi(doi: str) -> str:
    """Normalize a DOI for deduplication."""
    doi = doi.strip().lower()
    # Strip common prefixes
    for prefix in ("https://doi.org/", "http://doi.org/", "doi:"):
        if doi.startswith(prefix):
            doi = doi[len(prefix):]
            break
    return doi


def _normalize_title(title: str) -> str:
    """Normalize a title for deduplication (lowercase, collapse whitespace)."""
    import re
    title = re.sub(r"\s+", " ", title.strip().lower())
    return title


def _get_dedup_key(result: dict[str, Any]) -> str | None:
    """Compute a deduplication key for a search result.

    Priority: DOI → external stable ID → normalized title → source_id.
    Returns None if no key can be computed.
    """
    raw = result.get("raw_data", {})

    # 1. DOI (most reliable)
    doi = raw.get("doi", "")
    if doi:
        ndoi = _normalize_doi(doi)
        if ndoi:
            return f"doi:{ndoi}"

    # 2. External stable IDs
    for id_field in ("paperId", "arxiv_id", "openalex_id", "pmid"):
        ext_id = raw.get(id_field, "")
        if ext_id:
            return f"ext:{id_field}:{ext_id}"

    # 3. Normalized title
    title = raw.get("title", "")
    if title:
        ntitle = _normalize_title(title)
        if ntitle and len(ntitle) > 5:
            return f"title:{ntitle}"

    # 4. Source ID fallback
    source_id = raw.get("source_id", "")
    if source_id:
        return f"sid:{source_id}"

    return None


def _deduplicate_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate search results by DOI, stable ID, or normalized title.

    Preserves complete provenance entries: when duplicates merge, each
    contributing adapter's version/query/timestamp is retained.
    Rejects mixed current/legacy/pre-version modes in deduplicated results.
    """
    seen: dict[str, dict[str, Any]] = {}
    no_key: list[dict[str, Any]] = []

    for result in results:
        # FPV1: every result gets a provenance entry before dedup key check
        entry = ProvenanceEntry.from_raw_result(result).to_dict()
        if "provenance_entries" not in result.get("raw_data", {}):
            result["raw_data"]["provenance_entries"] = [entry]
            result["raw_data"]["_dedup_origins"] = derive_dedup_origins([entry])

        key = _get_dedup_key(result)
        if key is None:
            no_key.append(result)
            continue

        entry = ProvenanceEntry.from_raw_result(result).to_dict()

        if key in seen:
            existing = seen[key]
            existing_entries = existing.get("raw_data", {}).get("provenance_entries", [])
            merged = merge_provenance_entries(existing_entries, entry)
            check_mode_consistency(merged)
            existing["raw_data"]["provenance_entries"] = merged
            existing["raw_data"]["_dedup_origins"] = derive_dedup_origins(merged)
        else:
            seen[key] = result

    return list(seen.values()) + no_key


# Lazy-loaded adapter registry
_ADAPTERS: dict[str, Any] = {}


def _get_adapter(name: str) -> Any:
    """Lazy-load search adapters to avoid import errors when API unavailable."""
    if name in _ADAPTERS:
        return _ADAPTERS[name]

    if name == "semantic_scholar":
        from nodechain.adapters.search.semantic_scholar import SemanticScholarAdapter
        _ADAPTERS[name] = SemanticScholarAdapter()
    elif name == "arxiv":
        from nodechain.adapters.search.arxiv import ArxivAdapter
        _ADAPTERS[name] = ArxivAdapter()
    elif name == "openalex":
        from nodechain.adapters.search.openalex import OpenAlexAdapter
        _ADAPTERS[name] = OpenAlexAdapter()
    elif name == "crossref":
        from nodechain.adapters.search.crossref import CrossRefAdapter
        _ADAPTERS[name] = CrossRefAdapter()
    elif name == "pubmed":
        from nodechain.adapters.search.pubmed import PubMedAdapter
        _ADAPTERS[name] = PubMedAdapter()
    else:
        return None

    return _ADAPTERS[name]


class SearchToolNode(BaseNode):
    """
    Node 4: Multi-source domain-routed academic search.
    First external side effect. Uses adapter grants from context bundle.

    v3.5.0: supports an injected ``adapter_resolver`` for dispatch guarding.
    When provided, adapter calls route through the resolver (which may wrap
    them in OrdinaryDispatchGuard) instead of the module-global _get_adapter.
    This closes the rescue/fallback gap (ChatGPT T3 STOP).
    """

    def __init__(
        self,
        adapters: dict[str, Any] | None = None,
        *,
        adapter_resolver: dict[str, Any] | None = None,
        allow_unguarded: bool = False  # v3.5.0: fail-closed by default. Tests opt in explicitly.
    ) -> None:
        if adapters:
            _ADAPTERS.update(adapters)
        # v3.5.0: instance-local guarded adapter resolver. When set, all
        # adapter lookups use this dict instead of _get_adapter(). The
        # resolver may contain OrdinaryDispatchGuard-wrapped adapters.
        self._adapter_resolver = adapter_resolver
        # v3.5.0 (ChatGPT T3 gate): allow_unguarded enables the legacy
        # _get_adapter fallback. Currently True for backward compatibility
        # (tests + mock runs). T4 will wire the production composition root
        # (cli/run.py _create_nodes) to inject OrdinaryDispatchGuard-wrapped
        # adapters and flip this to False for production.
        self._allow_unguarded = allow_unguarded

    def set_adapter_resolver(self, resolver: dict[str, Any]) -> None:
        """v3.5.0: Inject a guarded adapter resolver post-construction.

        Called by the composition root (cli/run.py) after the orchestrator
        exists and the run_id is known. The resolver contains
        OrdinaryDispatchGuard-wrapped adapters bound to the run's capsule
        validator.
        """
        self._adapter_resolver = resolver
        self._allow_unguarded = False

    def _resolve_adapter(self, name: str) -> Any:
        """Resolve an adapter by name, using injected resolver if available.

        v3.5.0 (ChatGPT T3 gate): in production, the adapter_resolver MUST be
        injected. Without it, there is no dispatch guard and no capsule-before-wire
        enforcement. Fail closed rather than falling back to the module-global
        _ADAPTERS registry.

        For backward compatibility with tests and mock runs, set
        ``allow_unguarded=True`` to use the legacy _get_adapter path. Production
        composition roots must NEVER set this.
        """
        if self._adapter_resolver is not None:
            return self._adapter_resolver.get(name)
        if self._allow_unguarded:
            return _get_adapter(name)
        raise RuntimeError(
            f"SearchToolNode._resolve_adapter('{name}'): no adapter_resolver "
            f"injected. Production composition must inject OrdinaryDispatchGuard-"
            f"wrapped adapters. Set allow_unguarded=True only for tests/mocks."
        )

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="search_tool",
            node_type="tool",
            name="Search Tool",
            description="Multi-source domain-routed academic search.",
            contract=SEARCH_TOOL_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        context_bundle = envelope.payload
        search_queries = context_bundle.get("search_queries", [])
        adapter_grants = context_bundle.get("adapter_grants", [])

        all_results: list[dict[str, Any]] = []
        adapters_called: list[str] = []
        adapters_failed: list[dict[str, str]] = []
        # v2.69: per-adapter result counts — prevents silent empty-adapter success
        adapter_result_counts: dict[str, int] = {}

        # If no search queries or grants, try a fallback with the research goal
        if not search_queries or not adapter_grants:
            # Extract query from the payload chain — look for research goal or original query
            fallback_terms = []
            goal = context_bundle.get("research_goal", "")
            if isinstance(goal, dict):
                fallback_terms = [goal.get("primary_question", "")]
            elif isinstance(goal, str) and goal:
                fallback_terms = [goal]
            
            # Walk up the payload for a query
            if not fallback_terms:
                for key in ("query", "primary_question", "research_query"):
                    val = context_bundle.get(key, "")
                    if val:
                        fallback_terms = [str(val)]
                        break
            
            if fallback_terms and adapter_grants:
                search_queries = [{"terms": fallback_terms, "target_adapters": adapter_grants, "max_results": 10, "filters": {}}]
            elif fallback_terms:
                # v2.67.3: no hardcoded adapter fallback — adapters must be
                # explicitly granted via capabilities. Fallback terms are fine,
                # but adapter selection comes from allowed_adapters only.
                # Use ALL granted adapters, not just first 2.
                cap_adapters = getattr(envelope.capabilities, 'allowed_adapters', [])
                if cap_adapters:
                    search_queries = [{"terms": fallback_terms, "target_adapters": list(cap_adapters), "max_results": 10, "filters": {}}]

        # Fallback: if queries have empty terms, generate generic terms from focus_areas
        for sq in search_queries:
            terms = sq.get("terms", [])
            if not terms or all(not t.strip() for t in terms if isinstance(t, str)):
                focus = context_bundle.get("focus_areas", [])
                if focus:
                    sq["terms"] = [str(f) for f in focus[:3] if f]

        for sq in search_queries:
            query = SearchQuery(
                terms=sq.get("terms", []),
                max_results=sq.get("max_results", 10),
                filters=sq.get("filters", {}),
            )

            # Determine which adapters to call for this query
            target_adapters = sq.get("target_adapters", adapter_grants)
            # Only call adapters that are granted in payload
            target_adapters = [a for a in target_adapters if a in adapter_grants]
            # v2.43.0: hard upper bound from capabilities.allowed_adapters
            # (NOT allowed_tools — adapter grants are separate from tool grants).
            # Unconditional: empty allowed_adapters = no adapters callable.
            cap_adapters = getattr(envelope.capabilities, 'allowed_adapters', [])
            target_adapters = [a for a in target_adapters if a in cap_adapters]

            # Side-effect gating: check ledger state before each adapter call
            se_completed = list(envelope.capabilities.side_effect_completed_keys or [])
            se_all = dict(envelope.capabilities.side_effect_status_map or {})

            for adapter_name in target_adapters:
                # Build idempotency key from pre-call normalized request payload
                import hashlib as _hl
                import json as _json
                request_payload = _json.dumps(
                    {"terms": sorted(query.terms), "max": query.max_results, "filters": query.filters},
                    sort_keys=True,
                )
                request_hash = _hl.sha256(request_payload.encode()).hexdigest()[:16]
                ikey = f"{adapter_name}:{request_hash}"

                # Execution gating: check side-effect ledger status
                if ikey in se_completed:
                    # Completed — skip duplicate call
                    adapters_called.append(adapter_name)
                    continue

                # Check if a non-completed side effect exists (started/unknown/failed)
                # These block automatic retry — require reconciliation
                if ikey in se_all:
                    se_status = se_all[ikey]
                    if se_status in ("started", "unknown"):
                        # Block — needs reconciliation
                        adapters_failed.append({
                            "adapter": adapter_name,
                            "error": f"side_effect_{se_status}: requires reconciliation",
                        })
                        continue
                    if se_status == "failed":
                        retryable = se_all.get(f"{ikey}__retryable", "True") != "False"
                        if not retryable:
                            # Non-retryable failure — escalate
                            adapters_failed.append({
                                "adapter": adapter_name,
                                "error": "side_effect_failed: non-retryable, requires escalation",
                            })
                            continue
                        # Retryable — fall through to retry

                adapter = self._resolve_adapter(adapter_name)
                if adapter is None:
                    adapters_failed.append({
                        "adapter": adapter_name,
                        "error": f"Unknown adapter: {adapter_name}",
                        "failure_type": "unknown",
                        "retryable": False,
                    })
                    continue

                try:
                    results = await adapter.search(query)
                    for r in results:
                        d = r.model_dump()
                        # FPV1: detect unstamped before serialization
                        if r.provenance_version is None:
                            raise ProvenanceError(
                                ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE,
                                f"result index {len(all_results)}: unstamped live result "
                                f"(adapter did not route through _finalize_results)",
                            )
                        validate_live_result(d, len(all_results))
                        all_results.append(d)
                    adapters_called.append(adapter_name)
                    # v2.69: track per-adapter result count for visibility
                    adapter_result_counts[adapter_name] = (
                        adapter_result_counts.get(adapter_name, 0) + len(results)
                    )
                except (OrdinaryDispatchError, RecoveryDispatchError):
                    # v3.5.0 (ChatGPT T3 gate): dispatch-integrity violations
                    # must NOT be swallowed as adapter failures. They must
                    # propagate so the coordinator/classifier can handle them.
                    raise
                except ProvenanceError:
                    # FPV1: provenance-integrity violations must propagate,
                    # not be swallowed as adapter failures.
                    raise
                except SearchAdapterError as e:
                    # Structured failure from the adapter layer (v2.57.0)
                    f = e.failure
                    adapters_failed.append({
                        "adapter": adapter_name,
                        "error": f.message,
                        "failure_type": f.failure_type.value,
                        "retryable": f.retryable,
                        "attempts": f.attempts,
                        "status_code": f.status_code,
                        "latency_ms": f.latency_ms,
                        "reason_code": getattr(f, "reason_code", "") or "",
                    })
                except Exception as e:
                    adapters_failed.append({
                        "adapter": adapter_name,
                        "error": str(e),
                        "failure_type": "unknown",
                        "retryable": False,
                    })

        # v2.57.0: Deduplicate results by DOI → stable ID → title → source_id
        all_results = _deduplicate_results(all_results)

        # v2.67.3: Zero-results rescue — if no results found, try all granted
        # adapters that weren't already attempted. This handles the case where
        # the planner routed to specific adapters that all failed, but other
        # granted adapters were available.
        rescue_attempted: list[str] = []
        if len(all_results) == 0:
            already_tried = set(adapters_called + [af["adapter"] for af in adapters_failed])
            cap_adapters = getattr(envelope.capabilities, 'allowed_adapters', [])
            rescue_adapters = [a for a in cap_adapters if a not in already_tried]

            if rescue_adapters:
                # Build a fallback query from whatever terms we have
                rescue_terms = []
                for sq in search_queries:
                    rescue_terms.extend(sq.get("terms", []))
                if not rescue_terms:
                    rescue_terms = [context_bundle.get("query", "research")]

                rescue_query = SearchQuery(
                    terms=rescue_terms[:3],
                    max_results=10,
                    filters={},
                )

                for adapter_name in rescue_adapters:
                    adapter = self._resolve_adapter(adapter_name)
                    if adapter is None:
                        continue
                    try:
                        results = await adapter.search(rescue_query)
                        for r in results:
                            d = r.model_dump()
                            if r.provenance_version is None:
                                raise ProvenanceError(
                                    ProvenanceFailureCode.PROVENANCE_VERSION_MISSING_LIVE,
                                    f"result index {len(all_results)}: unstamped live result "
                                    f"(adapter did not route through _finalize_results)",
                                )
                            validate_live_result(d, len(all_results))
                            all_results.append(d)
                        adapters_called.append(adapter_name)
                        rescue_attempted.append(adapter_name)
                        # v2.69: track rescue per-adapter result count
                        adapter_result_counts[adapter_name] = (
                            adapter_result_counts.get(adapter_name, 0) + len(results)
                        )
                    except (OrdinaryDispatchError, RecoveryDispatchError):
                        # v3.5.0 (ChatGPT T3 gate): must propagate, not swallowed
                        raise
                    except ProvenanceError:
                        # FPV1: provenance-integrity violations must propagate
                        raise
                    except (SearchAdapterError, Exception) as e:
                        err_msg = e.failure.message if isinstance(e, SearchAdapterError) else str(e)
                        adapters_failed.append({
                            "adapter": adapter_name,
                            "error": f"rescue: {err_msg}",
                            "failure_type": e.failure.failure_type.value if isinstance(e, SearchAdapterError) else "unknown",
                            "retryable": e.failure.retryable if isinstance(e, SearchAdapterError) else False,
                        })

                # Re-deduplicate after rescue
                all_results = _deduplicate_results(all_results)

        # v2.57.0: Aggregate failure counters
        failures_by_type: dict[str, int] = {}
        retry_attempts_total = 0
        adapters_circuit_open: list[str] = []
        for af in adapters_failed:
            ft = af.get("failure_type", "unknown")
            failures_by_type[ft] = failures_by_type.get(ft, 0) + 1
            retry_attempts_total += af.get("attempts", 1) - 1
            if ft == "circuit_open":
                adapters_circuit_open.append(af.get("adapter", ""))

        # v2.69: Identify adapters that were called but returned zero results.
        # These are not failures (the adapter responded successfully), but they
        # are "silent zeros" that the chain should surface — not hide. Per
        # agreement with strategic reviewer: "silent zero" is the real defect
        # to eliminate. The source-quality corroboration rule and the operator
        # both need to see this to make informed decisions.
        silent_zero_adapters = sorted([
            name for name, count in adapter_result_counts.items()
            if count == 0 and name not in [af["adapter"] for af in adapters_failed]
        ])

        output = {
            "results": all_results,
            "total_found": len(all_results),
            "adapters_called": list(set(adapters_called)),
            "adapters_failed": adapters_failed,
            # v2.57.0: structured failure telemetry
            "failures_by_type": failures_by_type,
            "retry_attempts_total": retry_attempts_total,
            "adapters_circuit_open": list(set(adapters_circuit_open)),
            # v2.67.3: rescue pass metadata
            "rescue_attempted": list(set(rescue_attempted)) if rescue_attempted else [],
            # v2.69: per-adapter result counts + silent-zero surfacing
            "adapter_result_counts": dict(sorted(adapter_result_counts.items())),
            "silent_zero_adapters": silent_zero_adapters,
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="search_tool",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.RAW_SEARCH_RESULTS,
        )
