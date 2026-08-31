"""H1.4 — Human-readable final research artifact focused tests.

Qualification matrix (frozen plan §13):
  A — Fixture memo            G — Review (real pause/approve/resume)
  B — Live memo               H — No-review run
  C — Invalid bundle          I — Failure truth
  D — Determinism             J — Uncertainty absent/unavailable
  E — Final response          K — Governance appendix
  F — Citation chain          L — Read-only
  M — Legacy V1 bundle        N — Regression (suites, run separately)

The memo is a deterministic projection of one verified BundleV1 — no
model call, no network, no state mutation (AC3). All fixtures run through
the real governed WorkspaceRunner.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodechain.cli.research import research

FIXTURES = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"
CORPUS_BASIC = FIXTURES / "corpus_basic.yaml"
CORPUS_CONFLICTING = FIXTURES / "corpus_conflicting_evidence.yaml"
CORPUS_FAIL_BEFORE_DISPATCH = FIXTURES / "corpus_fail_before_dispatch.yaml"

runner = CliRunner()


def _run_fixture(workspace: Path, corpus: Path = CORPUS_BASIC,
                 question: str = "Is async Rust memory-safe?") -> str:
    from nodechain.research.runner import WorkspaceRunner
    result = WorkspaceRunner(
        question, corpus_path=corpus, workspace_dir=workspace,
    ).run()
    return result.run_id


def _bundle_dir(ws: Path, run_id: str) -> Path:
    return ws / "runs" / run_id / "bundle"


def _hash_tree(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(
                p.read_bytes()).hexdigest()
    return out


# --------------------------------------------------------------------------- #
# A / D / E / F / K / L — fixture memo, determinism, evidence, governance,
# read-only
# --------------------------------------------------------------------------- #


class TestFixtureMemo:
    def test_report_command_rich_and_json_and_output(
            self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        bundle = _bundle_dir(ws, rid)

        # Rich terminal view.
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws)])
        assert r.exit_code == 0, r.output[-400:]
        assert "Research Memo" in r.output

        # Structured memo JSON.
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code == 0
        memo = json.loads(r.output)
        assert memo["memo_version"] == 1
        assert memo["run_id"] == rid
        assert memo["acquisition_profile"] == "fixture"
        assert memo["reproducibility_mode"] == "deterministic_fixture"
        assert memo["bundle_digest"]
        assert memo["trace_event_count"] > 0

        # Markdown artifact.
        out = tmp_path / "memo.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert text.startswith("# Research Memo")
        assert rid in text
        # Governance appendix matches canonical documents (case K).
        from nodechain.research.bundle import BundleReader
        reader = BundleReader(bundle)
        manifest = reader.get_manifest()
        report_doc = reader.get_document("report.json")
        assert f"`{manifest.bundle_digest}`" in text
        assert manifest.run_status.value in text
        assert str(len(reader.get_document("trace.json")["events"])) in text
        for adapter in report_doc["adapters_used"]:
            assert adapter in text

    def test_deterministic_markdown_bytes(self, tmp_path: Path):
        """Case D: the same verified bundle renders identically twice."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        out1 = tmp_path / "memo1.md"
        out2 = tmp_path / "memo2.md"
        for out in (out1, out2):
            r = runner.invoke(research, ["report", rid, "--workspace",
                                         str(ws), "--output", str(out)])
            assert r.exit_code == 0
        assert out1.read_bytes() == out2.read_bytes()

        # Structurally identical JSON too.
        r1 = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                      "--json"])
        r2 = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                      "--json"])
        assert json.loads(r1.output) == json.loads(r2.output)

    def test_final_response_preserved_exactly(self, tmp_path: Path):
        """Case E: the Response Generator's recorded output appears in the
        bundle and memo exactly as produced — no replacement prose."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        import sqlite3
        db = next(ws.glob("*.db"))
        conn = sqlite3.connect(str(db))
        row = conn.execute(
            "SELECT state_json FROM chain_states WHERE run_id = ?", (rid,)
        ).fetchone()
        conn.close()
        outputs = json.loads(row[0]).get("outputs", {})
        resp = outputs.get("response_generator", {})
        if isinstance(resp, str):
            resp = json.loads(resp)

        from nodechain.research.bundle import BundleReader
        report_doc = BundleReader(_bundle_dir(ws, rid)).get_document(
            "report.json")
        assert report_doc["recommendation"] == resp["recommendation"]
        assert report_doc["executive_summary"] == resp["executive_summary"]
        assert report_doc["key_findings"] == resp["key_findings"]
        assert report_doc["executive_answer"] == resp["recommendation"]

        out = tmp_path / "memo.md"
        runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                 "--output", str(out)])
        text = out.read_text(encoding="utf-8")
        assert resp["recommendation"] in text
        for finding in resp["key_findings"]:
            assert finding in text

    def test_citation_chain_resolves(self, tmp_path: Path):
        """Case F: claim → evidence → citation → source all resolve inside
        the verified bundle."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        from nodechain.research.bundle import BundleReader
        reader = BundleReader(_bundle_dir(ws, rid))
        claims = reader.get_document("claims.json")["claims"]
        evidence = reader.get_document("evidence.json")["evidence"]
        citations = reader.get_document("citations.json")["citations"]
        sources = reader.get_document("sources.json")["sources"]

        evidence_by_id = {e["evidence_id"]: e for e in evidence}
        citation_by_id = {c["citation_id"]: c for c in citations}
        source_by_id = {s["source_id"]: s for s in sources}

        linked_claims = [c for c in claims if c["citation_ids"]]
        assert linked_claims, "no claim carries a citation link"
        for claim in linked_claims:
            for cit_id in claim["citation_ids"]:
                citation = citation_by_id[cit_id]
                # Citation links to evidence that belongs to the claim.
                assert set(citation["evidence_ids"]) & (
                    set(claim["supporting_evidence_ids"])
                    | set(claim["contradicting_evidence_ids"]))
                # And every linked evidence references the cited source.
                for ev_id in citation["evidence_ids"]:
                    assert citation["source_id"] in evidence_by_id[
                        ev_id]["source_ids"]
                assert citation["source_id"] in source_by_id

    def test_report_is_read_only(self, tmp_path: Path):
        """Case L: DB and canonical bundle bytes are unchanged by report
        generation; --output writes only the requested artifact."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        db_file = next(ws.glob("*.db"))
        db_before = hashlib.sha256(db_file.read_bytes()).hexdigest()
        bundle_before = _hash_tree(_bundle_dir(ws, rid))

        out = tmp_path / "memo.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out), "--json"])
        assert r.exit_code == 0
        assert out.exists()

        assert hashlib.sha256(
            db_file.read_bytes()).hexdigest() == db_before
        assert _hash_tree(_bundle_dir(ws, rid)) == bundle_before


# --------------------------------------------------------------------------- #
# B — Live memo
# --------------------------------------------------------------------------- #


class TestLiveMemo:
    def test_live_memo_artifact_bounded_language(self, tmp_path: Path,
                                                 monkeypatch):
        from research import test_live_acquisition as live
        live._patch_live_adapters(monkeypatch)
        result = live._run_live(tmp_path)
        assert result.completed, result.trace.final_status

        r = runner.invoke(research, ["report", result.run_id,
                                     "--workspace", str(tmp_path), "--json"])
        assert r.exit_code == 0
        memo = json.loads(r.output)
        assert memo["acquisition_profile"] == "live"
        assert memo["reproducibility_mode"] == "artifact_bounded_live"
        assert memo["replay_eligible"] is False

        out = tmp_path / "live-memo.md"
        r = runner.invoke(research, ["report", result.run_id,
                                     "--workspace", str(tmp_path),
                                     "--output", str(out)])
        assert r.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "artifact-bounded" in text
        # Never claims deterministic replay for a live run.
        assert "expected to produce the same results" not in text


# --------------------------------------------------------------------------- #
# C — Invalid bundle
# --------------------------------------------------------------------------- #


class TestInvalidBundle:
    def test_tampered_bundle_rejected_no_artifact(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        doc = _bundle_dir(ws, rid) / "claims.json"
        data = json.loads(doc.read_text(encoding="utf-8"))
        data["tampered"] = True
        doc.write_text(json.dumps(data), encoding="utf-8")

        out = tmp_path / "should-not-exist.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code != 0
        assert not out.exists()

    def test_absent_bundle_rejected(self, tmp_path: Path):
        r = runner.invoke(research, ["report", "no-such-run",
                                     "--workspace", str(tmp_path / "ws")])
        assert r.exit_code != 0

    def test_existing_output_not_overwritten(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        out = tmp_path / "memo.md"
        out.write_text("PRECIOUS", encoding="utf-8")
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code != 0
        assert out.read_text(encoding="utf-8") == "PRECIOUS"

    def test_output_inside_canonical_bundle_rejected(self, tmp_path: Path):
        """Codex P2: a report artifact inside the bundle would add a
        sixteenth member and invalidate the source bundle's verification."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        bundle = _bundle_dir(ws, rid)
        before = _hash_tree(bundle)
        out = bundle / "memo.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code != 0
        assert not out.exists()
        assert _hash_tree(bundle) == before
        # The bundle still verifies afterwards.
        from nodechain.research.bundle import BundleReader
        assert BundleReader(bundle).verify_integrity()


# --------------------------------------------------------------------------- #
# G / H — Review truth
# --------------------------------------------------------------------------- #


class TestReviewTruth:
    def _reviewed_run(self, ws: Path) -> str:
        """Real pause → approve → resume through the governed seams."""
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            "Is the evidence conflicting?", corpus_path=CORPUS_CONFLICTING,
            workspace_dir=ws,
        )
        result = r.run()
        assert result.paused, (
            f"conflicting-evidence run did not pause: "
            f"{result.trace.final_status}"
        )
        r.apply_review("approve", "conflicting evidence resolved by operator",
                       "operator-a")
        r.compose_for_resume(result.run_id)
        resumed = r.resume(run_id=result.run_id)
        assert resumed.completed or resumed.failed, (
            f"resumed run not terminal: {resumed.trace.final_status}"
        )
        return result.run_id

    def test_admitted_review_appears_completed(self, tmp_path: Path):
        """Case G: a real approve produces decision/reviewer/time in the
        bundle and memo, with review_completed=true."""
        ws = tmp_path / "ws"
        rid = self._reviewed_run(ws)

        from nodechain.research.bundle import BundleReader
        reader = BundleReader(_bundle_dir(ws, rid))
        review_doc = reader.get_document("review-decisions.json")
        assert review_doc["review_decisions"], "no admitted decision recorded"
        decision = review_doc["review_decisions"][0]
        assert decision["decision"] == "approve"
        assert decision["reviewer_identity"] == "operator-a"
        assert decision["decided_at"]
        assert review_doc["review_completed"] is True

        report_doc = reader.get_document("report.json")
        assert report_doc["review_required"] is True
        assert report_doc["review_completed"] is True

        out = tmp_path / "memo.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert "approve" in text
        assert "operator-a" in text
        assert "Review was required" in text

    def test_review_required_reflects_runtime_gate(self, tmp_path: Path):
        """Codex P2: a paused run whose risk flag says review_required=false
        must still report review as required — the runtime gate fired (the
        trace requested human review and a decision was admitted)."""
        ws = tmp_path / "ws"
        rid = self._reviewed_run(ws)
        from nodechain.research.bundle import BundleReader
        report_doc = BundleReader(_bundle_dir(ws, rid)).get_document(
            "report.json")
        assert report_doc["review_required"] is True
        assert report_doc["review_completed"] is True

    @staticmethod
    def _refinalize(ws: Path, rid: str):
        """Prepare a finalization call for an already-terminal run with its
        run-time bundle removed. Returns a zero-arg callable that invokes
        finalize_bundle with reconstructed trace/state stand-ins (only the
        step-projection fields are read)."""
        import shutil
        import sqlite3
        from types import SimpleNamespace
        from nodechain.research.bundle_finalizer import finalize_bundle
        from nodechain.research.run_descriptor import load_descriptor
        from nodechain.research.runner import WorkspaceRunner

        bundle = _bundle_dir(ws, rid)
        if bundle.exists():
            shutil.rmtree(bundle)
        desc = load_descriptor(ws, rid)
        runner = WorkspaceRunner.from_descriptor(desc)

        db = next(ws.glob("*.db"))
        conn = sqlite3.connect(str(db))
        row = conn.execute(
            "SELECT state_json FROM chain_states WHERE run_id = ?",
            (rid,)).fetchone()
        conn.close()
        state_payload = json.loads(row[0])
        completed_steps = state_payload.get("completed_steps", {})

        state = SimpleNamespace(
            completed_steps=completed_steps,
            current_node=state_payload.get("current_node", ""),
        )
        trace = SimpleNamespace(
            final_status="completed",
            events=[
                SimpleNamespace(
                    node_id=node_id,
                    event_type=SimpleNamespace(value="node_succeeded"),
                )
                for node_id in completed_steps.values()
            ],
        )

        def _call():
            finalize_bundle(
                workspace_dir=ws, run_id=rid, desc=desc, trace=trace,
                state=state, corpus=runner.corpus,
                source_commit=desc.chain_id,
            )

        return _call

    def test_authoritative_review_read_failure_fails_finalization(
            self, tmp_path: Path, monkeypatch):
        """GitWire blocker proof: an unreadable authoritative review store
        must FAIL finalization — never read as 'no admitted decisions' —
        so a false review_completed=false cannot be sealed into a bundle."""
        ws = tmp_path / "ws"
        rid = self._reviewed_run(ws)
        _call = self._refinalize(ws, rid)

        import nodechain.core.state as state_mod

        def _unreadable(*args, **kwargs):
            raise RuntimeError("authoritative store unreadable")

        monkeypatch.setattr(
            state_mod.StateManager, "get_review_attempts", _unreadable)
        with pytest.raises(RuntimeError, match="unreadable"):
            _call()
        # No verified bundle was published.
        assert not (_bundle_dir(ws, rid) / "manifest.json").exists()

    def test_corrupt_review_record_fails_finalization(self, tmp_path: Path):
        """An unexpected failure reading SUPPORTING review records also
        fails closed — a corrupt submission file must not silently
        discard a recorded reviewer reason."""
        ws = tmp_path / "ws"
        rid = self._reviewed_run(ws)
        _call = self._refinalize(ws, rid)
        reviews_dir = ws / "runs" / rid / "reviews"
        reviews_dir.mkdir(parents=True, exist_ok=True)
        (reviews_dir / "corrupt-review.json").write_text(
            "{not valid json", encoding="utf-8")
        with pytest.raises(Exception):
            _call()
        assert not (_bundle_dir(ws, rid) / "manifest.json").exists()

    def test_rejected_run_is_modern_not_legacy(self, tmp_path: Path):
        """Final correction proof: a modern run rejected at the risk review
        gate truthfully produces no Response Generator output. Its verified
        failed bundle must render as MODERN — no 'legacy bundle' wording,
        no fabricated recommendation — while the admitted rejection is
        still represented."""
        from nodechain.research.runner import WorkspaceRunner
        ws = tmp_path / "ws"
        r = WorkspaceRunner(
            "Should this be rejected?", corpus_path=CORPUS_CONFLICTING,
            workspace_dir=ws,
        )
        result = r.run()
        assert result.paused, result.trace.final_status
        r.apply_review("reject", "evidence rejected by operator",
                       "operator-r")
        r.compose_for_resume(result.run_id)
        resumed = r.resume(run_id=result.run_id)
        rid = result.run_id
        assert resumed.failed, (
            f"rejected run not failed: {resumed.trace.final_status}"
        )

        from nodechain.research.bundle import BundleReader
        bundle = _bundle_dir(ws, rid)
        reader = BundleReader(bundle)
        assert reader.verify_integrity(), (
            "rejected run must still produce a verified terminal bundle"
        )

        out = tmp_path / "rejected-memo.md"
        run_res = runner.invoke(research, ["report", rid, "--workspace",
                                           str(ws), "--output", str(out),
                                           "--json"])
        assert run_res.exit_code == 0
        memo = json.loads(run_res.output)
        text = out.read_text(encoding="utf-8")

        # Modern failed bundle: run status failed, no false legacy claims.
        assert memo["run_status"] == "failed"
        assert memo["unavailable_fields"] == []
        assert "legacy bundle" not in text
        # No fabricated recommendation — the absence is stated plainly.
        assert memo["recommendation"] == ""
        assert ("No recommendation was recorded in this verified bundle."
                in text)
        # The admitted rejection is represented.
        assert memo["review_required"] is True
        assert memo["review_completed"] is True
        decisions = memo["review_decisions"]
        assert decisions and decisions[0]["decision"] == "reject"
        assert decisions[0]["reviewer_identity"] == "operator-r"

    def test_no_review_run_not_falsely_approved(self, tmp_path: Path):
        """Case H: a run where review was not required shows exactly
        that — never an invented approval."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        from nodechain.research.bundle import BundleReader
        review_doc = BundleReader(_bundle_dir(ws, rid)).get_document(
            "review-decisions.json")
        assert review_doc["review_decisions"] == []
        assert review_doc["review_required"] is False
        assert review_doc["review_completed"] is False

        out = tmp_path / "memo.md"
        runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                 "--output", str(out)])
        text = out.read_text(encoding="utf-8")
        assert "Review was not required" in text
        assert "approve" not in text.lower()


# --------------------------------------------------------------------------- #
# I — Failure truth
# --------------------------------------------------------------------------- #


class TestFailureTruth:
    def test_recorded_fault_appears_in_memo(self, tmp_path: Path):
        ws = tmp_path / "ws"
        from nodechain.research.runner import WorkspaceRunner
        r = WorkspaceRunner(
            "Does the lane fail?", corpus_path=CORPUS_FAIL_BEFORE_DISPATCH,
            workspace_dir=ws,
        )
        result = r.run()
        rid = result.run_id
        from nodechain.research.run_descriptor import list_fault_records
        faults = list_fault_records(ws, rid)
        assert faults, "fault corpus produced no fault record"
        # The fault run pauses for review; approve to reach a terminal
        # bundle carrying the fault evidence.
        assert result.paused, result.trace.final_status
        r.apply_review("approve", "fault-lane run accepted by operator",
                       "operator-f")
        r.compose_for_resume(rid)
        resumed = r.resume(run_id=rid)
        assert resumed.completed or resumed.failed, (
            resumed.trace.final_status)

        from nodechain.research.bundle import BundleReader
        reader = BundleReader(_bundle_dir(ws, rid))
        failures_doc = reader.get_document("failures.json")
        assert failures_doc["failures"], "no failure in bundle"
        record = failures_doc["failures"][0]
        assert record["failure_id"] == faults[0]["fault_id"]
        assert record["fault_type"] in (
            "fail_before_dispatch", "timeout_after_dispatch",
            "malformed_provenance", "partial_result_set")
        # fail_before_dispatch never reached the wire.
        assert record["dispatch_occurred"] is False
        # Downstream evidence availability derives from fault semantics:
        # an operation that never dispatched left no evidence for
        # downstream synthesis.
        assert record["evidence_unavailable"] is True
        assert record["affected_claim_ids"] == []

        out = tmp_path / "memo.md"
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code == 0
        text = out.read_text(encoding="utf-8")
        assert record["fault_type"] in text
        assert "blocked before dispatch" in text
        # Claim impact comes from affected_claim_ids, not evidence
        # availability — the two are unrelated concepts.
        assert "no claim impact was established" in text
        assert "downstream evidence from this operation was unavailable" in text


# --------------------------------------------------------------------------- #
# J — Uncertainty absent vs unavailable
# --------------------------------------------------------------------------- #


class TestUncertaintyTruth:
    def test_no_uncertainty_language_distinguished(self, tmp_path: Path):
        """Recorded-empty and legacy-unavailable are different statements."""
        from nodechain.research.report import (
            ResearchMemoV1, render_markdown,
        )
        base = dict(
            run_id="r", bundle_digest="d" * 64, run_status="completed",
            acquisition_profile="fixture",
            reproducibility_mode="deterministic_fixture", question="q?",
        )
        modern = render_markdown(ResearchMemoV1(**base))
        assert ("No uncertainty was recorded in this verified bundle."
                in modern)
        legacy = render_markdown(ResearchMemoV1(
            unavailable_fields=["risk_level"], **base))
        assert "Risk level is not available in this legacy bundle." in legacy

    def test_recorded_uncertainty_projected(self):
        from nodechain.research.bundle_finalizer import _uncertainty_markers
        risk_out = {
            "uncertainty_disclosures": [
                {"area": "evidence_coverage", "nature": "thin", "impact":
                 "high"},
            ],
        }
        markers = _uncertainty_markers(risk_out)
        assert markers == [{
            "marker_id": "unc-1",
            "description": "evidence_coverage: thin (impact: high)",
            "affected_claim_ids": [],
        }]

    def test_alternative_perspectives_preserved(self, tmp_path: Path):
        """Codex P2: recorded final-response alternatives must survive into
        the memo — never silently discarded."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws),
                                     "--json"])
        memo = json.loads(r.output)
        assert isinstance(memo["alternative_perspectives"], list)

        # A bundle that recorded alternatives renders them verbatim.
        from nodechain.research.report import (
            ResearchMemoV1, build_memo, render_markdown,
        )
        base_memo = build_memo(_bundle_dir(ws, rid))
        enriched = base_memo.model_copy(update={
            "alternative_perspectives": [
                "Contradicting literature may temper this conclusion."],
        })
        text = render_markdown(enriched)
        assert "Contradicting literature may temper this conclusion." in text
        assert "Alternative Perspectives" in text


# --------------------------------------------------------------------------- #
# M — Legacy V1 bundle
# --------------------------------------------------------------------------- #


def _legacy_bundle(ws: Path, run_id: str, target: Path) -> Path:
    """Rebuild a verified bundle in its PRE-H1.4 document shape.

    Uses the existing BundleWriter so the legacy artifact is genuinely
    verified — only the document payloads are legacy-shaped.
    """
    from nodechain.research.bundle import BundleReader, BundleWriter
    source = BundleReader(_bundle_dir(ws, run_id))

    legacy_report = source.get_document("report.json")
    for field in ("recommendation", "executive_summary", "key_findings",
                  "confidence_statement", "alternative_perspectives",
                  "methodology_notes", "risk_level", "overall_confidence",
                  "risk_factors", "review_reason"):
        legacy_report.pop(field, None)

    legacy_review = source.get_document("review-decisions.json")
    legacy_review.pop("review_required", None)
    legacy_review.pop("review_completed", None)
    legacy_review["review_decisions"] = []

    legacy_uncertainties = source.get_document("uncertainties.json")
    legacy_uncertainties["uncertainties"] = []

    writer = BundleWriter(target)
    writer.write_document("brief.json", source.get_document("brief.json"))
    writer.write_document("run.json", source.get_document("run.json"))
    writer.write_document("plan.json", source.get_document("plan.json"))
    writer.write_document("sources.json",
                          source.get_document("sources.json"))
    writer.write_document("evidence.json",
                          source.get_document("evidence.json"))
    writer.write_document("claims.json", source.get_document("claims.json"))
    writer.write_document("citations.json",
                          source.get_document("citations.json"))
    writer.write_document("uncertainties.json", legacy_uncertainties)
    writer.write_document("validations.json",
                          source.get_document("validations.json"))
    writer.write_document("policy-decisions.json",
                          source.get_document("policy-decisions.json"))
    writer.write_document("review-decisions.json", legacy_review)
    writer.write_document("failures.json",
                          source.get_document("failures.json"))
    writer.write_document("trace.json", source.get_document("trace.json"))
    writer.write_document("report.json", legacy_report)

    manifest = source.get_manifest().model_dump(mode="json")
    new_manifest = writer.compute_manifest(
        source_commit=manifest["source_commit"],
        run_id=manifest["run_id"],
        chain_id=manifest["chain_id"],
        blueprint_version=manifest["blueprint_version"],
        created_at=manifest["created_at"],
        finalized_at=manifest["finalized_at"],
        run_status=manifest["run_status"],
        input_digest=manifest["input_digest"],
        provider_mode=manifest["provider_mode"],
        fixture_corpus_version=manifest["fixture_corpus_version"],
        trace_reference=manifest["trace_reference"],
        replay_eligible=manifest["replay_eligible"],
    )
    writer.finalize(new_manifest)
    return target


class TestLegacyBundle:
    def test_pre_h14_bundle_renders_with_explicit_limits(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        legacy_dir = tmp_path / "legacy-bundle"
        _legacy_bundle(ws, rid, legacy_dir)

        from nodechain.research.bundle import BundleReader
        assert BundleReader(legacy_dir).verify_integrity(), (
            "legacy-shaped bundle must still verify"
        )

        from nodechain.research.report import build_memo, render_markdown
        memo = build_memo(legacy_dir)
        assert "recommendation" in memo.unavailable_fields
        assert "uncertainties" in memo.unavailable_fields
        text = render_markdown(memo)
        assert "not available in this legacy bundle" in text
        # A legacy empty uncertainty document proves nothing about whether
        # uncertainty existed — never rendered as 'no uncertainty was
        # recorded'.
        assert ("Uncertainty information is not available in this legacy "
                "bundle.") in text
        assert ("No uncertainty was recorded in this verified bundle."
                not in text)
        # The recorded executive answer is labeled as exactly that — never
        # silently upgraded to a first-class Recommendation.
        assert ("A final recommendation is not available in this legacy "
                "bundle.") in text
        assert "recorded legacy executive answer was:" in text
        assert memo.recommendation == ""

    def test_legacy_rich_view_states_unavailable_uncertainty(
            self, tmp_path: Path):
        """The default Rich experience carries the same legacy-availability
        truth as the Markdown artifact."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        legacy_dir = tmp_path / "legacy-bundle"
        _legacy_bundle(ws, rid, legacy_dir)
        from nodechain.research.report import build_memo, render_rich
        from rich.console import Console
        import io
        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        render_rich(build_memo(legacy_dir), console)
        output = buf.getvalue()
        assert "not available in this legacy bundle" in output
        assert ("No uncertainty was recorded in this verified bundle."
                not in output)


class TestRichParity:
    def test_rich_view_carries_recorded_findings_and_methodology(
            self, tmp_path: Path):
        """The default Rich memo renders the recorded final-response
        content (key findings, methodology) — not only the structured and
        Markdown views."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        from nodechain.research.report import build_memo, render_rich
        from rich.console import Console
        import io
        memo = build_memo(_bundle_dir(ws, rid))
        assert memo.key_findings and memo.methodology
        buf = io.StringIO()
        console = Console(file=buf, width=200, force_terminal=False)
        render_rich(memo, console)
        output = buf.getvalue()
        for finding in memo.key_findings:
            assert finding in output
        assert memo.methodology in output

    def test_cli_rich_output_carries_recorded_content(self, tmp_path: Path):
        """CLI-level proof: the default terminal report shows a known
        recorded key finding and methodology value verbatim."""
        ws = tmp_path / "ws"
        rid = _run_fixture(ws)
        r = runner.invoke(research, ["report", rid, "--workspace", str(ws)])
        assert r.exit_code == 0
        assert "Sealed corpus run completed with deterministic evidence." \
            in r.output
        assert "Governed execution over the sealed fixture corpus" \
            in r.output
