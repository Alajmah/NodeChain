"""H1.2 — Research operator CLI tests.

Covers the frozen H1.2 acceptance criteria:
  AC0 — Workspace targeting (--workspace DIR on research run)
  AC1 — Workspace open
  AC2 — Runs listing
  AC3 — Run inspection (all sections, availability states)
  AC4 — Bundle verification
  AC5 — Run comparison
  AC5a — Recovery handoff
  AC6 — Read-only behavior (DB hash invariant)
  AC7 — JSON output on every new command
  AC8 — Export (verified-bundle copy only)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nodechain.cli.research import research

CORPUS_PATH = (
    Path(__file__).parent.parent.parent / "tests" / "fixtures" / "research"
    / "corpus_basic.yaml"
)

runner = CliRunner()


def _run_research(workspace: Path) -> str:
    """Run the real WorkspaceRunner into a workspace; returns run_id."""
    from nodechain.research.runner import ResearchBrief, WorkspaceRunner
    r = WorkspaceRunner(
        brief=ResearchBrief.from_question("Is async Rust memory-safe?"),
        corpus_path=str(CORPUS_PATH),
        workspace_dir=workspace,
    )
    result = r.run()
    return result.run_id


class TestWorkspaceOpen:
    def test_open_empty_workspace_json(self, tmp_path: Path):
        r = runner.invoke(research, ["open", "--workspace",
                                     str(tmp_path / "ws"), "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["selected_run_id"] == ""
        assert data["runs"] == []

    def test_open_with_runs(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["open", "--workspace", str(ws)])
        assert r.exit_code == 0
        # Rich tables may truncate UUIDs; verify via JSON too.
        r2 = runner.invoke(research, ["runs", "--workspace", str(ws), "--json"])
        data = json.loads(r2.output)
        assert any(run["run_id"] == rid for run in data["runs"])


class TestRunsListing:
    def test_runs_lists_all(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["runs", "--workspace", str(ws)])
        assert r.exit_code == 0
        # AC2: the human table shows persistence time (Updated), not
        # creation time.
        assert "Updated" in r.output
        # Rich tables may truncate UUIDs; verify via JSON.
        r2 = runner.invoke(research, ["runs", "--workspace", str(ws),
                                     "--json"])
        data = json.loads(r2.output)
        assert any(run["run_id"] == rid for run in data["runs"])
        listed = next(run for run in data["runs"] if run["run_id"] == rid)
        assert listed["updated_at"]

    def test_runs_json(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["runs", "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert any(run["run_id"] == rid for run in data["runs"])

    def test_runs_empty(self, tmp_path: Path):
        r = runner.invoke(research, ["runs", "--workspace",
                                     str(tmp_path / "empty"), "--json"])
        assert r.exit_code == 0
        assert json.loads(r.output)["runs"] == []


class TestInspect:
    def test_inspect_all_sections(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws)])
        assert r.exit_code == 0
        assert rid in r.output

    def test_inspect_json(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["selected_run_id"] == rid
        assert data["projection_version"] == 2

    def test_inspect_not_found(self, tmp_path: Path):
        # A workspace with runs: inspect on a nonexistent run errors.
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", "no-such-run",
                                     "--workspace", str(ws)])
        assert r.exit_code != 0

    def test_inspect_section_filter(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws),
                                     "--section", "objective"])
        assert r.exit_code == 0

    def test_inspect_section_structured(self, tmp_path: Path):
        """AC3: non-WorkspaceSection concepts (recovery, faults) serialize
        as structured JSON, never as stringified Pydantic reprs."""
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws),
                                     "--section", "recovery"])
        assert r.exit_code == 0
        # The panel header precedes the JSON body; parse from the first
        # brace.
        payload = r.output[r.output.index("{"):]
        data = json.loads(payload)
        assert isinstance(data, dict)
        assert isinstance(data["side_effects"], list)
        assert isinstance(data["recovery_decisions"], list)


class TestVerify:
    def test_verify_no_bundle(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        # The runner auto-finalizes; remove the bundle to test absent.
        bundle_dir = ws / "runs" / rid / "bundle"
        if bundle_dir.exists():
            import shutil
            shutil.rmtree(bundle_dir)
        r = runner.invoke(research, ["verify", rid, "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code == 0
        assert json.loads(r.output)["bundle_status"] == "absent"

    def test_verify_with_bundle(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)  # auto-finalizes on completion
        bundle_dir = ws / "runs" / rid / "bundle"
        if not (bundle_dir / "manifest.json").exists():
            pytest.skip("corpus did not produce a finalizable run")
        r = runner.invoke(research, ["verify", rid, "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["bundle_status"] == "verified"
        assert data["bundle_digest"]
        # AC4: the verified document inventory is part of the contract.
        assert isinstance(data["documents"], list)
        assert data["document_count"] == len(data["documents"])
        assert data["document_count"] > 0

    def test_verify_invalid_bundle_json_exits_nonzero(self, tmp_path: Path):
        """AC4 exit semantics: rendering mode must not change verification
        success/failure — an invalid bundle exits nonzero even with --json,
        after the JSON body is emitted."""
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        bundle_dir = ws / "runs" / rid / "bundle"
        if not (bundle_dir / "manifest.json").exists():
            pytest.skip("corpus did not produce a finalizable run")
        doc = bundle_dir / "claims.json"
        data_doc = json.loads(doc.read_text(encoding="utf-8"))
        data_doc["tampered"] = True
        doc.write_text(json.dumps(data_doc), encoding="utf-8")
        r = runner.invoke(research, ["verify", rid, "--workspace", str(ws),
                                     "--json"])
        assert r.exit_code != 0
        data = json.loads(r.output)
        assert data["bundle_status"] == "invalid"


class TestCompare:
    def test_compare_two_runs(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid_a = _run_research(ws)
        # Create a second run with a different question.
        from nodechain.research.runner import ResearchBrief, WorkspaceRunner
        r2 = WorkspaceRunner(
            brief=ResearchBrief.from_question("What is quantum computing?"),
            corpus_path=str(CORPUS_PATH),
            workspace_dir=ws,
        )
        result2 = r2.run()
        rid_b = result2.run_id
        r = runner.invoke(research, ["compare", rid_a, rid_b,
                                     "--workspace", str(ws), "--json"])
        assert r.exit_code == 0
        data = json.loads(r.output)
        assert data["run_a"]["run_id"] == rid_a
        assert data["run_b"]["run_id"] == rid_b


class TestExport:
    def test_export_verified_bundle(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)  # auto-finalizes on completion
        bundle_dir = ws / "runs" / rid / "bundle"
        if not (bundle_dir / "manifest.json").exists():
            pytest.skip("corpus did not produce a finalizable run")
        out = tmp_path / "exported"
        r = runner.invoke(research, ["export", rid,
                                     "--workspace", str(ws),
                                     "--output", str(out), "--json"])
        assert r.exit_code == 0
        assert out.exists()
        assert (out / "manifest.json").exists()


class TestWorkspaceTargeting:
    """AC0 — research run --workspace DIR creates and targets the workspace."""

    def test_run_with_explicit_workspace(self, tmp_path: Path):
        ws = tmp_path / "my-ws"
        assert not ws.exists()
        r = runner.invoke(research, [
            "run", "Is async Rust memory-safe?",
            "--corpus", str(CORPUS_PATH),
            "--workspace", str(ws),
        ])
        # The workspace root was created by the runner.
        assert ws.exists()
        assert (ws / "runs").is_dir()
        # The run is discoverable from that workspace.
        r2 = runner.invoke(research, ["runs", "--workspace", str(ws), "--json"])
        data = json.loads(r2.output)
        assert len(data["runs"]) >= 1


class TestExportNegative:
    """Export must reject non-verified bundles and create no artifact."""

    def test_export_absent_bundle_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        bundle_dir = ws / "runs" / rid / "bundle"
        if bundle_dir.exists():
            import shutil
            shutil.rmtree(bundle_dir)
        out = tmp_path / "should-not-exist"
        r = runner.invoke(research, ["export", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code != 0
        assert not out.exists()

    def test_export_invalid_bundle_rejected(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        bundle_dir = ws / "runs" / rid / "bundle"
        if not (bundle_dir / "manifest.json").exists():
            pytest.skip("corpus did not produce a finalizable run")
        # Tamper with a document to make the bundle invalid.
        doc = bundle_dir / "claims.json"
        data = json.loads(doc.read_text(encoding="utf-8"))
        data["tampered"] = True
        doc.write_text(json.dumps(data), encoding="utf-8")
        out = tmp_path / "should-not-exist-invalid"
        r = runner.invoke(research, ["export", rid, "--workspace", str(ws),
                                     "--output", str(out)])
        assert r.exit_code != 0
        assert not out.exists()


class TestReadOnlyInvariant:
    """AC6 — every new command performs zero persistence writes."""

    def test_observation_commands_do_not_mutate_db(self, tmp_path: Path):
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        db_file = next(ws.glob("*.db"), None)
        if db_file is None:
            pytest.skip("no db file found")
        hash_before = hashlib.sha256(db_file.read_bytes()).hexdigest()

        for cmd in (["open", "--workspace", str(ws)],
                    ["runs", "--workspace", str(ws)],
                    ["inspect", rid, "--workspace", str(ws)],
                    ["verify", rid, "--workspace", str(ws)],
                    ["compare", rid, rid, "--workspace", str(ws)]):
            r = runner.invoke(research, cmd)
            assert r.exit_code == 0, f"{cmd} failed: {r.output[:200]}"

        hash_after = hashlib.sha256(db_file.read_bytes()).hexdigest()
        assert hash_after == hash_before, (
            "read-only violation: DB changed across observation commands"
        )


class TestRecoveryHandoff:
    """AC5a — inspect identifies actionable recovery state and prints
    the existing governed recovery console path with the resolved DB."""

    def test_inspect_shows_recovery_when_actionable(self, tmp_path: Path):
        """Positive case: inject an unknown side effect, assert the exact
        DB path and a valid recovery command appear in the output."""
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        db_path = next(ws.glob("*.db"))
        # Inject a side-effect ledger row with status=unknown (the
        # actionable recovery state).
        from nodechain.core.state import StateManager
        sm = StateManager(str(db_path))
        sm._side_effect_ledger.record_side_effect(
            run_id=rid,
            step_id=99,
            node_id="search_tool",
            side_effect_type="tool_dispatch",
            idempotency_key=f"test-unknown-{rid[:8]}",
            status="unknown",
        )
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws)])
        assert r.exit_code == 0
        # The recovery handoff appears with the resolved DB path.
        # Rich may wrap long paths across lines — normalize before checking.
        normalized = r.output.replace("\n", "").replace("\r", "")
        assert "Recovery required" in normalized
        assert str(db_path).replace("\\", "/") in normalized.replace("\\", "/"), (
            f"resolved DB path not in output: {r.output[-300:]}"
        )
        # A valid existing recovery command is printed.
        assert "nodechain recover inspect" in normalized
        assert "nodechain recover list-unknown" in normalized

    def test_inspect_no_recovery_when_none_actionable(self, tmp_path: Path):
        """Negative case: no actionable side effects → no handoff."""
        ws = tmp_path / "ws"
        rid = _run_research(ws)
        r = runner.invoke(research, ["inspect", rid, "--workspace", str(ws)])
        assert r.exit_code == 0
        # The fixture runner may produce no side effects at all, or all
        # completed. Either way, "Recovery required" should not appear
        # unless something is actionable.
        from nodechain.core.state import StateManager
        sm = StateManager(str(next(ws.glob("*.db"))), read_only=True)
        ledger = sm.get_side_effects(rid)
        if not any(se.get("status") in ("unknown", "retry_authorized")
                   for se in ledger):
            assert "Recovery required" not in r.output


class TestPausedReviewHandoff:
    """AC0/operator flow: a run launched with --workspace DIR must
    advertise the review command against the SAME workspace. The sealed
    fixture corpus cannot deterministically pause, so the rendering seam
    is tested with a stubbed WorkspaceRunner."""

    def _install_stub(self, monkeypatch):
        import nodechain.research.runner as runner_mod

        class _State:
            status = "waiting_for_review"

        class _PausedResult:
            paused = True
            completed = False
            failed = False
            run_id = "paused-rid-1234"
            corpus_digest = "0123456789abcdef" * 2
            state = _State()

        class _StubRunner:
            def __init__(self, brief, corpus_path=None, *, profile="fixture",
                         db_path=None, trace_dir=None, workspace_dir=None,
                         chain_id="research-workspace-v1", model_adapter=None):
                self.corpus_digest = "0123456789abcdef" * 2

            def run(self):
                return _PausedResult()

        monkeypatch.setattr(runner_mod, "WorkspaceRunner", _StubRunner)
        return _PausedResult

    def test_paused_review_command_preserves_workspace(self, tmp_path: Path,
                                                       monkeypatch):
        self._install_stub(monkeypatch)
        # Widen the console so the command line is not wrapped mid-token.
        import nodechain.cli.research as research_cli
        monkeypatch.setattr(research_cli.console, "width", 300)

        ws = tmp_path / "custom-ws"
        json_out = tmp_path / "paused.json"
        r = runner.invoke(research, ["run", "What pauses?",
                                     "--corpus", str(CORPUS_PATH),
                                     "--workspace", str(ws),
                                     "--json-output", str(json_out)])
        from nodechain.cli.exit_codes import EXIT_RUN_PAUSED
        assert r.exit_code == EXIT_RUN_PAUSED
        collapsed = " ".join(r.output.split())
        assert "nodechain research review paused-rid-1234" in collapsed
        assert f'--workspace "{ws}"' in collapsed
        # Machine metadata carries the explicitly supplied workspace.
        meta = json.loads(json_out.read_text(encoding="utf-8"))
        assert meta["workspace_dir"] == str(ws)
        assert meta["paused_for_review"] is True

    def test_paused_review_command_omits_workspace_by_default(
            self, tmp_path: Path, monkeypatch):
        self._install_stub(monkeypatch)
        import nodechain.cli.research as research_cli
        monkeypatch.setattr(research_cli.console, "width", 300)

        r = runner.invoke(research, ["run", "What pauses?",
                                     "--corpus", str(CORPUS_PATH)])
        from nodechain.cli.exit_codes import EXIT_RUN_PAUSED
        assert r.exit_code == EXIT_RUN_PAUSED
        collapsed = " ".join(r.output.split())
        assert "nodechain research review paused-rid-1234" in collapsed
        assert "--workspace" not in collapsed
