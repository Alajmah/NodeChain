"""H1.3 — Live source acquisition profile focused tests.

Qualification matrix (frozen plan §13):
  A — Legacy fixture invocation unchanged
  B — Explicit live composition (ordinary SearchTool + guarded adapters)
  C — Current provenance through ingestion
  D — Artifact identity (NodeChain-computed hash + exact ref)
  E — Content vs time (same content/new time → same hash)
  F — Qualified linkage (bound live sources reach synthesis)
  G — Failure truth (no configuration-derived fake faults)
  H — Descriptor compatibility (V1 identity preserved; V2 reconstructs)
  I — Live terminal bundle (verified, provider_mode=live, replay false)
  J — Workspace/operator path on live runs
  K — No-network qualification (deterministic local adapters only)

Every live test dispatches through the REAL adapter/SearchTool/provenance
seam — the OrdinaryDispatchGuard, capsule-before-wire lifecycle, and the
central BaseSearchAdapter stamping boundary — using deterministic
zero-network adapters seeded into the module adapter registry. No test
here contacts Semantic Scholar, arXiv, OpenAlex, CrossRef, or PubMed.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodechain.cli.research import research
from nodechain.research.corpus import (
    FixtureCorpus,
    compute_corpus_canonical_digest,
)

CORPUS_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"
    / "corpus_basic.yaml"
)

LIVE_ADAPTERS = (
    "semantic_scholar", "arxiv", "openalex", "crossref", "pubmed",
)

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Deterministic zero-network live adapter control (case K)
# --------------------------------------------------------------------------- #
#
# The OrdinaryDispatchGuard binds adapter identities to their exact real
# concrete classes (type() is, subclasses rejected) — so deterministic live
# tests cannot substitute fake adapter classes. Instead, each test attaches
# an instance-level ``_fetch`` stub to the REAL cached adapter instance.
# The full real seam runs: real adapter class, real search(), real
# normalize_response, real central provenance stamping, real guard and
# capsule lifecycle. No HTTP is performed.


def _ss_paper(title: str, doi: str) -> dict:
    """A Semantic-Scholar-API-shaped paper payload."""
    return {
        "paperId": f"ss-{abs(hash(title)) % 10**10}",
        "title": title,
        "abstract": f"Deterministic abstract for {title}.",
        "authors": [{"name": "Alice Author"}, {"name": "Bob Researcher"}],
        "year": 2025,
        "publicationDate": "2025-01-15",
        "venue": "Journal of Deterministic Acquisition",
        "citationCount": 7,
        "referenceCount": 20,
        "influentialCitationCount": 2,
        "isOpenAccess": True,
        "openAccessPdf": {"url": "https://example.org/pdf"},
        "publicationTypes": ["JournalArticle"],
        "fieldsOfStudy": ["Computer Science"],
        "externalIds": {"DOI": doi},
        "journal": {"name": "JDAC", "volume": "1"},
    }


def _stub_fetch(papers: list[dict] | None = None, failure=None):
    from nodechain.adapters.search.failure_types import SearchFetchResult

    async def _fetch(url, params=None, *, headers=None,
                     response_format="json", query_hash=""):
        if failure is not None:
            return SearchFetchResult(failure=failure)
        return SearchFetchResult(
            data={"data": list(papers or [])}, latency_ms=1,
        )

    return _fetch


def _patch_live_adapters(monkeypatch, *, fail: tuple[str, ...] = ()) -> None:
    """Attach zero-network _fetch stubs to the REAL cached live adapters.

    Each healthy adapter returns enough distinct papers for the risk
    classifier's evidence thresholds to be honestly satisfied (multiple
    sources → multiple claims with evidence) — the run must complete on
    evidence quality, not on a weakened gate.
    """
    from nodechain.adapters.search.failure_types import (
        AdapterFailure,
        SearchFailureType,
    )
    from nodechain.nodes.search_tool import _get_adapter

    for name in LIVE_ADAPTERS:
        adapter = _get_adapter(name)
        if adapter is None:
            pytest.skip(f"real adapter {name} unavailable in this environment")
        if name in fail:
            monkeypatch.setattr(adapter, "_fetch", _stub_fetch(failure=AdapterFailure(
                adapter=name,
                failure_type=SearchFailureType.UNKNOWN,
                retryable=False,
                message=f"deterministic {name} failure (test)",
                query_hash="test",
            )))
        else:
            papers = [
                _ss_paper(f"Deterministic Live Source {name} {i}",
                          f"10.1000/{name}.{i}")
                for i in range(1, 4)
            ]
            monkeypatch.setattr(adapter, "_fetch", _stub_fetch(papers))


class _LiveTestModelAdapter:
    """Bounded deterministic model adapter for live-profile qualification.

    Delegates every completion to the sealed FixtureModelAdapter's
    deterministic responses, rewriting only the task plan's source routing
    to the routed live adapters (the sealed adapter routes 'fixture' alone).
    External LLM availability is not a qualification gate (frozen plan §8).
    """

    def __init__(self, adapters: list[str]) -> None:
        from nodechain.research.fixture_model_adapter import FixtureModelAdapter
        self._inner = FixtureModelAdapter(
            latency_ms=0,
            search_terms=["deterministic live acquisition"],
            claim_confidence=0.75,
        )
        self._adapters = list(adapters)
        self.model = "live-test-mock"
        self.default_max_tokens = 4096

    def _reroute(self, doc: dict) -> dict:
        doc = dict(doc)
        doc["source_routing"] = {
            "primary": list(self._adapters),
            "secondary": [],
            "domain_specific": {},
        }
        return doc

    def complete(self, system_prompt, user_message, max_tokens=None,
                 temperature=0.3, output_schema=None, task_type="auto"):
        resp = self._inner.complete(
            system_prompt, user_message, max_tokens=max_tokens,
            temperature=temperature, output_schema=output_schema,
            task_type=task_type,
        )
        update: dict = {}
        if isinstance(resp.structured_output, dict) and \
                "source_routing" in resp.structured_output:
            update["structured_output"] = self._reroute(resp.structured_output)
        if isinstance(resp.content, str):
            try:
                parsed = json.loads(resp.content)
            except (json.JSONDecodeError, TypeError):
                parsed = None
            if isinstance(parsed, dict) and "source_routing" in parsed:
                update["content"] = json.dumps(self._reroute(parsed))
        if update:
            resp = resp.model_copy(update=update)
        return resp


#: Default live routing for full runs: the real Semantic Scholar pipeline.
_DEFAULT_LIVE_ROUTE = ["semantic_scholar"]


def _run_live(workspace: Path, *, route: list[str] | None = None,
              fail: tuple[str, ...] = ()) -> object:
    from nodechain.research.runner import WorkspaceRunner
    r = WorkspaceRunner(
        brief="Is deterministic live acquisition governable?",
        profile="live",
        workspace_dir=workspace,
        model_adapter=_LiveTestModelAdapter(route or _DEFAULT_LIVE_ROUTE),
    )
    return r.run()


def _ingested_sources(ws: Path, run_id: str) -> list[dict]:
    import sqlite3
    db = next(ws.glob("*.db"))
    conn = sqlite3.connect(str(db))
    row = conn.execute(
        "SELECT state_json FROM chain_states WHERE run_id = ?", (run_id,)
    ).fetchone()
    conn.close()
    state = json.loads(row[0])
    out = state.get("outputs", {}).get("source_ingestion", {})
    if isinstance(out, str):
        out = json.loads(out)
    return out.get("sources", [])


# --------------------------------------------------------------------------- #
# A — Legacy fixture profile unchanged (fail-closed combinations)
# --------------------------------------------------------------------------- #


class TestFixtureProfileUnchanged:
    def test_fixture_without_corpus_fails_closed(self, tmp_path: Path):
        r = runner.invoke(research, ["run", "q?", "--profile", "fixture",
                                     "--workspace", str(tmp_path / "ws")])
        assert r.exit_code != 0
        assert "requires" in r.output and "--corpus" in r.output

    def test_live_with_corpus_fails_closed(self, tmp_path: Path):
        r = runner.invoke(research, ["run", "q?", "--profile", "live",
                                     "--corpus", str(CORPUS_PATH),
                                     "--workspace", str(tmp_path / "ws")])
        assert r.exit_code != 0
        assert "does not accept" in r.output

    def test_fixture_run_writes_v2_descriptor_with_corpus_fields(
            self, tmp_path: Path):
        from nodechain.research.runner import WorkspaceRunner
        from nodechain.research.run_descriptor import load_descriptor
        ws = tmp_path / "ws"
        r = WorkspaceRunner("Fixture profile question?",
                            corpus_path=CORPUS_PATH, workspace_dir=ws)
        result = r.run()
        desc = load_descriptor(ws, result.run_id)
        assert desc.descriptor_version == 2
        assert desc.acquisition_profile == "fixture"
        assert desc.corpus_path == str(CORPUS_PATH)
        assert desc.corpus_digest == r.corpus_digest
        assert desc.input_digest and len(desc.input_digest) == 64


# --------------------------------------------------------------------------- #
# B — Explicit live composition
# --------------------------------------------------------------------------- #


class TestLiveComposition:
    def test_live_uses_ordinary_search_tool_and_guarded_registry(
            self, tmp_path: Path, monkeypatch):
        _patch_live_adapters(monkeypatch)
        from nodechain.nodes.search_tool import SearchToolNode
        from nodechain.nodes.fixture_search_tool import FixtureSearchToolNode
        from nodechain.runtime.recovery_dispatch_guard import (
            OrdinaryDispatchGuard,
        )
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            brief="live composition", profile="live", workspace_dir=tmp_path,
            model_adapter=_LiveTestModelAdapter(list(LIVE_ADAPTERS)),
        )
        with monkeypatch.context() as m:
            _patch_live_adapters(m)
            orch = r._compose()
        assert isinstance(r._search_node, SearchToolNode)
        assert not isinstance(r._search_node, FixtureSearchToolNode)
        resolver = r._search_node._adapter_resolver
        assert set(resolver) == set(LIVE_ADAPTERS)
        assert all(isinstance(g, OrdinaryDispatchGuard) for g in resolver.values())
        # Guarded dispatch only — the unguarded fallback is disabled once a
        # resolver is injected.
        assert r._search_node._allow_unguarded is False
        # The runner itself holds no direct adapter reference (no CLI/runner
        # network path).
        assert r._fixture_adapter is None

    def test_live_run_completes(self, tmp_path: Path, monkeypatch):
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        assert result.completed, (
            f"live run did not complete: {result.trace.final_status}"
        )


# --------------------------------------------------------------------------- #
# C/D/E — Provenance, artifact identity, content-vs-time
# --------------------------------------------------------------------------- #


class TestLiveSourceIdentity:
    def test_current_provenance_and_artifact_identity(
            self, tmp_path: Path, monkeypatch):
        from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        sources = _ingested_sources(tmp_path, result.run_id)
        assert sources, "no live sources ingested"
        for s in sources:
            # C: current provenance stamped through the central boundary.
            prov = s.get("provenance", {})
            assert prov.get("version") == CURRENT_PROVENANCE_VERSION
            assert prov.get("mode") == "current"
            assert prov.get("entries"), "no provenance entries"
            for e in prov["entries"]:
                assert e["version"] == CURRENT_PROVENANCE_VERSION
                assert e["adapter"] in LIVE_ADAPTERS
            # Authoritative acquisition provenance propagated (not invented
            # at finalization time).
            assert s.get("query_used")
            assert s.get("retrieved_at")
            # D: NodeChain-computed content hash + exact artifact ref.
            self._assert_identity(s)

    @staticmethod
    def _assert_identity(s: dict) -> None:
        """Exact identity equality: recompute the expected hash directly
        from the PERSISTED substantive fields and require equality."""
        import hashlib
        from nodechain.nodes.source_ingestion import (
            _LIVE_CONTENT_FIELDS, _canonical_live_content,
        )
        normalized = {k: s[k] for k in _LIVE_CONTENT_FIELDS if k in s}
        canonical = _canonical_live_content(s["origin_api"], normalized)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert s["source_hash"] == expected, (
            f"persisted source_hash {s['source_hash']} != hash of persisted "
            f"content {expected}"
        )
        assert s["artifact_ref"] == f"ingested:{s['source_id']}:{s['source_hash']}"

    def test_content_vs_time_identity(self):
        """Case E: same content fetched later → same content hash; changed
        content → changed hash. Exercised directly at the ingestion seam
        with adapter-normalized (snake_case) semantic scholar raw_data, the
        exact shape the real adapter's normalize_response produces."""
        import hashlib
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.nodes.source_ingestion import (
            SourceIngestionNode, _canonical_live_content,
        )

        def _norm_doc(title: str) -> dict:
            return {
                "paper_id": "ss-stable",
                "title": title,
                "abstract": f"Deterministic abstract for {title}.",
                "authors": ["Alice Author", "Bob Researcher"],
                "year": 2025,
                "publication_date": "2025-01-15",
                "venue": "Journal of Deterministic Acquisition",
                "citation_count": 7,
                "reference_count": 20,
                "influential_citation_count": 2,
                "open_access": True,
                "pdf_url": "https://example.org/pdf",
                "publication_types": ["JournalArticle"],
                "fields_of_study": ["Computer Science"],
                "external_ids": {"DOI": "10.1000/stable"},
                "journal": {"name": "JDAC", "volume": "1"},
            }

        def _raw(retrieved_at: str, title: str = "Stable Content") -> dict:
            # The exact post-adapter shape SearchToolNode hands to
            # ingestion: centrally-stamped current version plus merged
            # provenance entries.
            from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION
            return {
                "origin_api": "semantic_scholar",
                "raw_data": {
                    **_norm_doc(title),
                    "provenance_entries": [{
                        "version": CURRENT_PROVENANCE_VERSION,
                        "adapter": "semantic_scholar",
                        "query": "stable content query",
                        "retrieval_timestamp": retrieved_at,
                    }],
                },
                "query_used": "stable content query",
                "retrieved_at": retrieved_at,
                "provenance_version": CURRENT_PROVENANCE_VERSION,
            }

        node = SourceIngestionNode()

        async def _ingest(raws):
            env = InvocationEnvelope(
                run_id="r", chain_id="c", node_id="source_ingestion",
                step_id=1, payload={"results": raws},
            )
            resp = await node.execute(env)
            return resp.output["sources"]

        t1 = "2026-01-01T00:00:00Z"
        t2 = "2026-06-01T12:00:00Z"
        s1 = asyncio.run(_ingest([_raw(t1)]))[0]
        s2 = asyncio.run(_ingest([_raw(t2)]))[0]
        # Same content, different retrieval time → same content hash,
        # different acquisition provenance timestamp.
        assert s1["source_hash"] == s2["source_hash"]
        assert s1["retrieved_at"] == t1
        assert s2["retrieved_at"] == t2
        # Changed content → changed hash.
        s3 = asyncio.run(_ingest([_raw(t1, "Stable Content (Updated)")]))[0]
        assert s3["source_hash"] != s1["source_hash"]

    def test_null_abstract_identity(self):
        """A live record with abstract=None: the nullable→default
        transformation happens BEFORE hashing, so the hash is always over
        exactly the persisted content (abstract "")."""
        import hashlib
        from nodechain.core.envelope import InvocationEnvelope
        from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION
        from nodechain.nodes.source_ingestion import (
            _LIVE_CONTENT_FIELDS, SourceIngestionNode, _canonical_live_content,
        )

        raw_data = {
            "paper_id": "ss-nullabs",
            "title": "Null Abstract Source",
            "abstract": None,
            "authors": ["Carol Author"],
            "year": 2025,
            "publication_date": "2025-02-02",
            "venue": "Journal of Null Handling",
            "citation_count": 1,
            "reference_count": 2,
            "influential_citation_count": 0,
            "open_access": False,
            "pdf_url": "",
            "publication_types": ["JournalArticle"],
            "fields_of_study": ["Computer Science"],
            "external_ids": {"DOI": "10.1000/nullabs"},
            "journal": {},
            "provenance_entries": [{
                "version": CURRENT_PROVENANCE_VERSION,
                "adapter": "semantic_scholar",
                "query": "null abstract query",
                "retrieval_timestamp": "2026-01-01T00:00:00Z",
            }],
        }
        raw = {
            "origin_api": "semantic_scholar",
            "raw_data": raw_data,
            "query_used": "null abstract query",
            "retrieved_at": "2026-01-01T00:00:00Z",
            "provenance_version": CURRENT_PROVENANCE_VERSION,
        }
        node = SourceIngestionNode()

        async def _ingest():
            env = InvocationEnvelope(
                run_id="r", chain_id="c", node_id="source_ingestion",
                step_id=1, payload={"results": [raw]},
            )
            resp = await node.execute(env)
            return resp.output["sources"][0]

        s = asyncio.run(_ingest())
        # The persisted representation carries the schema-level default.
        assert s["abstract"] == ""
        assert s["abstract_available"] is False
        # The hash is over exactly that persisted representation.
        normalized = {k: s[k] for k in _LIVE_CONTENT_FIELDS if k in s}
        canonical = _canonical_live_content("semantic_scholar", normalized)
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert s["source_hash"] == expected


# --------------------------------------------------------------------------- #
# F — Qualified linkage
# --------------------------------------------------------------------------- #


class TestQualifiedLinkage:
    def test_bound_live_sources_reach_synthesis(self, tmp_path: Path,
                                                monkeypatch):
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        import sqlite3
        db = next(tmp_path.glob("*.db"))
        conn = sqlite3.connect(str(db))
        row = conn.execute(
            "SELECT state_json FROM chain_states WHERE run_id = ?",
            (result.run_id,),
        ).fetchone()
        conn.close()
        outputs = json.loads(row[0]).get("outputs", {})

        def _out(nid):
            o = outputs.get(nid, {})
            return json.loads(o) if isinstance(o, str) else o

        linked = _out("qualified_source_linker").get("linked_sources", [])
        assert linked, "no linked qualified sources"
        for ls in linked:
            assert ls.get("source_hash")
            assert ls.get("artifact_ref") == (
                f"ingested:{ls['source_id']}:{ls['source_hash']}"
            )
        # The qualified set actually reaches synthesis.
        synth = _out("evidence_synthesizer")
        assert synth.get("claims") or synth.get("evidence"), (
            "qualified live sources did not reach evidence synthesis"
        )


# --------------------------------------------------------------------------- #
# G — Failure truth
# --------------------------------------------------------------------------- #


class TestFailureTruth:
    def test_adapter_failure_is_evidence_not_a_fake_fault(
            self, tmp_path: Path, monkeypatch):
        # Route to a healthy adapter AND a deterministically failing one.
        # The failing adapter's error is real execution evidence; the run
        # must survive on the healthy lane.
        _patch_live_adapters(monkeypatch, fail=("arxiv",))
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            brief="live failure truth", profile="live",
            workspace_dir=tmp_path,
            model_adapter=_LiveTestModelAdapter(
                ["semantic_scholar", "arxiv"]),
        )
        result = r.run()
        assert result.completed, (
            f"live run with one failing lane did not complete: "
            f"{result.trace.final_status}"
        )
        # ...but NO fault record is created merely because an adapter was
        # configured to fail (faults are trace-event projections only).
        from nodechain.research.run_descriptor import list_fault_records
        faults = list_fault_records(tmp_path, result.run_id)
        lane_or_provenance = [
            f for f in faults
            if f.get("failure_type") in (
                "fail_before_dispatch", "malformed_provenance")
        ]
        assert not lane_or_provenance, (
            "configuration-derived fault fabricated: "
            f"{[f.get('failure_type') for f in faults]}"
        )

    def test_invoked_and_failed_adapter_is_reported_as_used(
            self, tmp_path: Path, monkeypatch):
        """C2: an adapter that WAS invoked through the guard and then
        failed is execution truth — the terminal bundle must report it in
        adapters_used alongside the healthy adapter."""
        _patch_live_adapters(monkeypatch, fail=("arxiv",))
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            brief="invoked and failed", profile="live",
            workspace_dir=tmp_path,
            model_adapter=_LiveTestModelAdapter(
                ["semantic_scholar", "arxiv"]),
        )
        result = r.run()
        assert result.completed, result.trace.final_status
        from nodechain.research.bundle import BundleReader
        reader = BundleReader(tmp_path / "runs" / result.run_id / "bundle")
        assert reader.verify_integrity()
        report = reader.get_document("report.json")
        used = set(report["adapters_used"])
        assert "semantic_scholar" in used, used  # invoked, succeeded
        assert "arxiv" in used, (  # invoked, failed — still invoked
            f"invoked-but-failed adapter omitted from adapters_used: {used}"
        )
        # Pre-dispatch/non-dispatched adapters remain excluded.
        assert not (used - {"semantic_scholar", "arxiv"}), used


# --------------------------------------------------------------------------- #
# H — Descriptor compatibility
# --------------------------------------------------------------------------- #


class TestDescriptorCompatibility:
    def _write_v1_descriptor(self, ws: Path, run_id: str) -> dict:
        """Write a legacy V1 descriptor exactly as pre-H1.3 code did."""
        import hashlib
        corpus = FixtureCorpus(
            corpus_version="basic-1", scenario_id="basic",
        )
        digest = compute_corpus_canonical_digest(corpus)
        doc = {
            "run_id": run_id,
            "chain_id": "research-workspace-v1",
            "question": "legacy question",
            "focus_areas": [],
            "corpus_path": str(CORPUS_PATH),
            "corpus_digest": digest,
            "corpus_version": corpus.corpus_version,
            "scenario_id": corpus.scenario_id,
            "db_path": str(ws / "run.db"),
            "trace_dir": str(ws / "traces"),
            "workspace_dir": str(ws),
            "blueprint_version": "1.0.0",
            "created_at": "2026-01-01T00:00:00+00:00",
            "kek_path": "",
        }
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        doc["descriptor_digest"] = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        target = ws / "runs" / run_id / "descriptor.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc, indent=2, sort_keys=True),
                          encoding="utf-8")
        return doc

    def test_v1_descriptor_loads_with_original_digest_identity(
            self, tmp_path: Path):
        from nodechain.research.run_descriptor import load_descriptor
        doc = self._write_v1_descriptor(tmp_path, "legacy-run-1")
        desc = load_descriptor(tmp_path, "legacy-run-1")
        # The V1 identity rule: the stored raw-document digest survives
        # loading unchanged — never recomputed under V2 defaults.
        assert desc.descriptor_digest == doc["descriptor_digest"]
        assert desc.descriptor_version == 1
        assert desc.profile == "fixture"
        assert desc.acquisition_profile is None

    def test_live_descriptor_reconstructs_live_profile(
            self, tmp_path: Path, monkeypatch):
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        from nodechain.research.run_descriptor import load_descriptor
        from nodechain.research.runner import WorkspaceRunner
        desc = load_descriptor(tmp_path, result.run_id)
        assert desc.descriptor_version == 2
        assert desc.profile == "live"
        assert desc.corpus_path is None
        assert desc.allowed_adapters == tuple(LIVE_ADAPTERS)
        assert desc.input_digest and len(desc.input_digest) == 64
        # This run used an injected process-local model adapter: a fresh
        # process cannot reconstruct that configuration, so reconstruction
        # fails closed instead of substituting current defaults.
        with pytest.raises(ValueError, match="injected"):
            WorkspaceRunner.from_descriptor(desc)

    def test_live_reconstruction_restores_or_rejects_configuration(
            self, tmp_path: Path, monkeypatch):
        """Adversarial (H1.3 correction): a run created under acquisition
        configuration A must never resume under configuration B. Either the
        persisted configuration is restored or reconstruction fails closed."""
        _patch_live_adapters(monkeypatch)
        import nodechain.cli.run as cli_run_mod
        from nodechain.research.run_descriptor import load_descriptor
        from nodechain.research.runner import WorkspaceRunner

        resolver_calls = {"identity": ("provA", "modelA")}

        def _resolver(model_name=None):
            return (_LiveTestModelAdapter(_DEFAULT_LIVE_ROUTE),
                    *resolver_calls["identity"])

        monkeypatch.setattr(
            cli_run_mod, "resolve_production_model_adapter", _resolver)
        # Create through the resolver path (no explicit model_adapter) so
        # the descriptor records the resolved identity (provA/modelA).
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            brief="reconstruction adversarial", profile="live",
            workspace_dir=tmp_path,
        )
        result = r.run()
        assert result.completed or result.paused
        desc = load_descriptor(tmp_path, result.run_id)
        assert (desc.model_provider, desc.model_name) == ("provA", "modelA")

        # Current environment now resolves configuration B → reject.
        resolver_calls["identity"] = ("provB", "modelB")
        with pytest.raises(ValueError, match="refusing to resume"):
            WorkspaceRunner.from_descriptor(desc)

        # Current environment satisfies configuration A → restore it,
        # including the descriptor-authoritative granted adapter set (the
        # launch-time capability grant, recorded in the descriptor).
        resolver_calls["identity"] = ("provA", "modelA")
        runner = WorkspaceRunner.from_descriptor(desc)
        assert (runner.model_provider, runner.model_name) == ("provA", "modelA")
        assert runner.profile == "live"
        assert runner.corpus is None
        assert runner.allowed_adapters == list(LIVE_ADAPTERS)

    def test_live_reconstruction_honors_descriptor_adapter_subset(
            self, tmp_path: Path, monkeypatch):
        """The persisted adapter set is authoritative: a subset granted at
        launch is restored as that subset, not reset to the full five."""
        import hashlib
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = {
            "run_id": "subset-run-1",
            "chain_id": "research-workspace-v1",
            "question": "subset question",
            "db_path": str(tmp_path / "run.db"),
            "trace_dir": str(tmp_path / "traces"),
            "workspace_dir": str(tmp_path),
            "descriptor_version": 2,
            "acquisition_profile": "live",
            "input_digest": "a" * 64,
            "allowed_adapters": ["semantic_scholar"],
            "provenance_version": 1,
            "model_provider": "mock",
            "model_name": "mock-model",
        }
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        doc["descriptor_digest"] = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        target = tmp_path / "runs" / "subset-run-1" / "descriptor.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(doc, indent=2, sort_keys=True),
                          encoding="utf-8")
        desc = RunDescriptor(**doc)
        runner = WorkspaceRunner.from_descriptor(desc)
        assert runner.allowed_adapters == ["semantic_scholar"]
        assert (runner.model_provider, runner.model_name) == (
            "mock", "mock-model")

    def test_live_reconstruction_rejects_unknown_adapter_set(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        import hashlib
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = {
            "run_id": "badset-run-1",
            "chain_id": "research-workspace-v1",
            "question": "q",
            "db_path": str(tmp_path / "run.db"),
            "trace_dir": str(tmp_path / "traces"),
            "workspace_dir": str(tmp_path),
            "descriptor_version": 2,
            "acquisition_profile": "live",
            "input_digest": "a" * 64,
            "allowed_adapters": ["not_a_real_adapter"],
            "provenance_version": 1,
            "model_provider": "mock",
            "model_name": "mock-model",
        }
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        doc["descriptor_digest"] = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        with pytest.raises(ValueError, match="unsatisfiable"):
            WorkspaceRunner.from_descriptor(RunDescriptor(**doc))

    @staticmethod
    def _live_v2_doc(tmp_path: Path, run_id: str, **overrides) -> dict:
        """Hand-build a valid V2 live descriptor document (digest-correct)."""
        import hashlib
        from nodechain.core.provenance import CURRENT_PROVENANCE_VERSION
        from nodechain.nodes.search_tool import _get_adapter
        current_versions = {
            name: str(getattr(_get_adapter(name), "adapter_version", ""))
            for name in LIVE_ADAPTERS
        }
        doc = {
            "run_id": run_id,
            "chain_id": "research-workspace-v1",
            "question": "version enforcement question",
            "db_path": str(tmp_path / "run.db"),
            "trace_dir": str(tmp_path / "traces"),
            "workspace_dir": str(tmp_path),
            "descriptor_version": 2,
            "acquisition_profile": "live",
            "input_digest": "a" * 64,
            "allowed_adapters": list(LIVE_ADAPTERS),
            "adapter_versions": current_versions,
            "provenance_version": CURRENT_PROVENANCE_VERSION,
            "model_provider": "mock",
            "model_name": "mock-model",
        }
        doc.update(overrides)
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        doc["descriptor_digest"] = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        return doc

    def test_live_resume_rejects_provenance_version_mismatch(
            self, tmp_path: Path, monkeypatch):
        """C1: a descriptor recorded under an older/newer provenance
        contract must never resume under the current one."""
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = self._live_v2_doc(tmp_path, "prov-mismatch-run",
                                provenance_version=99)
        runner = WorkspaceRunner.from_descriptor(RunDescriptor(**doc))
        with pytest.raises(ValueError, match="provenance contract"):
            runner.compose_for_resume("prov-mismatch-run")

    def test_live_resume_rejects_adapter_version_mismatch(
            self, tmp_path: Path, monkeypatch):
        """C1: an adapter implementation version that drifted since launch
        must fail closed before resume."""
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = self._live_v2_doc(tmp_path, "adapter-mismatch-run")
        drifted = dict(doc["adapter_versions"])
        drifted["semantic_scholar"] = "999.999.999"
        doc = self._live_v2_doc(tmp_path, "adapter-mismatch-run",
                                adapter_versions=drifted)
        runner = WorkspaceRunner.from_descriptor(RunDescriptor(**doc))
        with pytest.raises(ValueError, match="version changed"):
            runner.compose_for_resume("adapter-mismatch-run")

    def test_live_resume_rejects_missing_adapter_versions(
            self, tmp_path: Path, monkeypatch):
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = self._live_v2_doc(tmp_path, "no-versions-run")
        del doc["adapter_versions"]
        # Recompute the digest over the reduced field set.
        import hashlib
        body = {k: v for k, v in doc.items() if k != "descriptor_digest"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        doc["descriptor_digest"] = hashlib.sha256(
            canonical.encode("utf-8")).hexdigest()
        runner = WorkspaceRunner.from_descriptor(RunDescriptor(**doc))
        with pytest.raises(ValueError, match="missing"):
            runner.compose_for_resume("no-versions-run")

    def test_live_resume_accepts_matching_versions(
            self, tmp_path: Path, monkeypatch):
        """The matching-configuration case still composes: enforcement
        rejects drift, not resume itself."""
        monkeypatch.setenv("NODECHAIN_PROVIDER", "mock")
        monkeypatch.setenv("NODECHAIN_MODEL", "mock-model")
        from nodechain.research.run_descriptor import RunDescriptor
        from nodechain.research.runner import WorkspaceRunner
        doc = self._live_v2_doc(tmp_path, "matching-versions-run")
        runner = WorkspaceRunner.from_descriptor(RunDescriptor(**doc))
        orchestrator = runner.compose_for_resume("matching-versions-run")
        assert orchestrator is not None


# --------------------------------------------------------------------------- #
# I — Live terminal bundle
# --------------------------------------------------------------------------- #


class TestLiveTerminalBundle:
    def test_verified_live_bundle_truth(self, tmp_path: Path, monkeypatch):
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        bundle_dir = tmp_path / "runs" / result.run_id / "bundle"
        from nodechain.research.bundle import BundleReader
        reader = BundleReader(bundle_dir)
        assert reader.verify_integrity()
        manifest = reader.get_manifest()
        assert manifest.provider_mode == "live"
        assert manifest.fixture_corpus_version is None
        assert manifest.replay_eligible is False

        run_doc = reader.get_document("run.json")
        assert run_doc["provider_mode"] == "live"
        assert run_doc["replay_eligible"] is False
        assert run_doc["input_digest"] == manifest.input_digest

        sources_doc = reader.get_document("sources.json")
        assert sources_doc["sources"]
        for s in sources_doc["sources"]:
            assert s.get("artifact_ref") == (
                f"ingested:{s['source_id']}:{s['source_hash']}"
            )
            # Real acquisition timestamps, not finalization-time inventions.
            assert s["retrieved_at"] != "2026-01-01T00:00:00Z"
        # Adapter coverage derived from actual origins — no fixture claim.
        assert set(sources_doc["adapter_coverage"]) <= set(LIVE_ADAPTERS)
        assert "fixture" not in sources_doc["adapter_coverage"]

        report = reader.get_document("report.json")
        assert report["adapters_used"]
        assert set(report["adapters_used"]) <= set(LIVE_ADAPTERS)

        # Model labels are never 'fixture-mock' on a live bundle.
        evidence_doc = reader.get_document("evidence.json")
        assert evidence_doc["extraction_model"] != "fixture-mock"

        brief_doc = reader.get_document("brief.json")
        assert "fixture" not in brief_doc["constraints"]["required_adapters"]


# --------------------------------------------------------------------------- #
# Correction 2 — adapters_used is execution evidence, never permission
# --------------------------------------------------------------------------- #


class TestAdaptersUsedExecutionEvidence:
    def test_zero_source_run_reports_no_undispatched_adapters(
            self, tmp_path: Path, monkeypatch):
        """A terminal live run with zero ingested sources must not claim
        the permission set as used. Only actually dispatched adapters may
        appear in report.json (permission is not execution evidence)."""
        from nodechain.nodes.search_tool import _get_adapter
        for name in LIVE_ADAPTERS:
            adapter = _get_adapter(name)
            if adapter is None:
                pytest.skip(f"real adapter {name} unavailable")
            monkeypatch.setattr(adapter, "_fetch", _stub_fetch([]))

        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            brief="zero source run", profile="live", workspace_dir=tmp_path,
            model_adapter=_LiveTestModelAdapter(_DEFAULT_LIVE_ROUTE),
        )
        result = r.run()
        # Zero sources → high risk → the run pauses for review; approve to
        # reach a terminal state and a finalized bundle.
        assert result.paused, (
            f"expected review pause on zero sources, got "
            f"{result.trace.final_status}"
        )
        r.apply_review("approve", "zero-source qualification", "h1.3-test")
        r.compose_for_resume(result.run_id)
        resumed = r.resume(run_id=result.run_id)
        assert resumed.completed or resumed.failed, (
            f"resumed run not terminal: {resumed.trace.final_status}"
        )

        from nodechain.research.bundle import BundleReader
        reader = BundleReader(tmp_path / "runs" / result.run_id / "bundle")
        assert reader.verify_integrity()
        report = reader.get_document("report.json")
        never_dispatched = {"arxiv", "openalex", "crossref", "pubmed"}
        assert not (set(report["adapters_used"]) & never_dispatched), (
            f"never-dispatched adapters reported as used: "
            f"{report['adapters_used']}"
        )
        assert set(report["adapters_used"]) <= {"semantic_scholar"}
        assert reader.get_document("sources.json")["sources"] == []


# --------------------------------------------------------------------------- #
# Correction 4 — published schema enforces fixture/live exclusivity
# --------------------------------------------------------------------------- #


class TestManifestSchemaExclusivity:
    """Schema-only consumers must see the same fixture/live exclusivity the
    Pydantic model enforces: fixture ⇒ non-empty corpus version, non-fixture
    ⇒ null."""

    @staticmethod
    def _validate(provider_mode: str, corpus_version) -> None:
        from nodechain.research.bundle import _validate_document_schema
        payload = {
            "bundle_version": "1.0",
            "run_id": "schema-run-1",
            "chain_id": "research-workspace-v1",
            "blueprint_version": "1.0.0",
            "created_at": "2026-01-01T00:00:00Z",
            "finalized_at": "2026-01-01T00:00:00Z",
            "run_status": "completed",
            "source_commit": "sc",
            "input_digest": "a" * 64,
            "artifact_inventory": [],
            "bundle_digest": "b" * 64,
            "provider_mode": provider_mode,
            "fixture_corpus_version": corpus_version,
            "trace_reference": "trace.json",
            "replay_eligible": True,
        }
        _validate_document_schema("manifest.json", payload)

    def test_fixture_with_corpus_version_is_valid(self):
        self._validate("fixture", "fixture-1")

    def test_fixture_with_null_corpus_version_is_rejected(self):
        from nodechain.research.exceptions import BundleValidationError
        with pytest.raises(BundleValidationError):
            self._validate("fixture", None)

    def test_fixture_with_empty_corpus_version_is_rejected(self):
        from nodechain.research.exceptions import BundleValidationError
        with pytest.raises(BundleValidationError):
            self._validate("fixture", "")

    def test_live_with_null_corpus_version_is_valid(self):
        self._validate("live", None)

    def test_live_with_corpus_version_is_rejected(self):
        """The reviewer's exact counterexample: schema-only validation must
        reject live + a fixture corpus version."""
        from nodechain.research.exceptions import BundleValidationError
        with pytest.raises(BundleValidationError):
            self._validate("live", "fixture-1")


# --------------------------------------------------------------------------- #
# J — Workspace/operator path
# --------------------------------------------------------------------------- #


class TestWorkspaceOperatorPath:
    def test_operator_surfaces_on_live_run(self, tmp_path: Path, monkeypatch):
        _patch_live_adapters(monkeypatch)
        result = _run_live(tmp_path)
        rid = result.run_id

        r = runner.invoke(research, ["open", "--workspace", str(tmp_path),
                                     "--json"])
        assert r.exit_code == 0
        snap = json.loads(r.output)
        assert snap["acquisition_profile"] == "live"
        assert snap["reproducibility_mode"] == "artifact_bounded_live"
        listed = next(x for x in snap["runs"] if x["run_id"] == rid)
        assert listed["acquisition_profile"] == "live"

        r = runner.invoke(research, ["runs", "--workspace", str(tmp_path)])
        assert r.exit_code == 0
        assert "live" in r.output

        r = runner.invoke(research, ["verify", rid, "--workspace",
                                     str(tmp_path), "--json"])
        assert r.exit_code == 0
        assert json.loads(r.output)["bundle_status"] == "verified"

        out = tmp_path / "exported-live"
        r = runner.invoke(research, ["export", rid, "--workspace",
                                     str(tmp_path), "--output", str(out)])
        assert r.exit_code == 0
        assert (out / "manifest.json").exists()

    def test_cli_live_run_end_to_end(self, tmp_path: Path, monkeypatch):
        """The real CLI live path: profile resolution through the shared
        production helper (patched to a bounded deterministic adapter —
        external LLM availability is not a qualification gate)."""
        _patch_live_adapters(monkeypatch)
        import nodechain.cli.run as cli_run_mod
        monkeypatch.setattr(
            cli_run_mod, "resolve_production_model_adapter",
            lambda model_name=None: (
                _LiveTestModelAdapter(_DEFAULT_LIVE_ROUTE),
                "live-test", "deterministic",
            ),
        )
        ws = tmp_path / "cli-ws"
        r = runner.invoke(research, ["run", "CLI live question?",
                                     "--profile", "live",
                                     "--workspace", str(ws),
                                     "--json-output", str(tmp_path / "m.json")])
        assert r.exit_code == 0, r.output[-500:]
        meta = json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))
        assert meta["acquisition_profile"] == "live"
