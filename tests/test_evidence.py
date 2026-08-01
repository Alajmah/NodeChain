"""Tests for v1.18.2 Trace Replay and Evidence Query.

Tests cover all 12 acceptance criteria.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write_json(tmp_path, name, data):
    path = str(tmp_path / name)
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _generate_key_pair(tmp_path, suffix=""):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = str(tmp_path / f"priv_ev{suffix}.pem")
    pub_path = str(tmp_path / f"pub_ev{suffix}.pem")
    Path(priv_path).write_bytes(priv_pem)
    Path(pub_path).write_bytes(pub_pem)
    return priv_path, pub_path


# ── AC1+AC2: Evidence Index ────────────────────────────────────────────────

class TestEvidenceIndex:
    """AC1: evidence index command. AC2: supports 11 artifact types."""

    def test_index_single_file(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification",
            "certification_id": "c1",
            "target_digest": "a" * 64,
            "certification_status": "certified",
            "issued_at": "2026-06-17T00:00:00+00:00",
        })
        index = build_evidence_index(artifact)
        assert index["entry_count"] == 1
        assert index["entries"][0]["artifact_type"] == "certification"

    def test_index_directory(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "certification_status": "certified",
            "issued_at": "2026-06-17T00:00:00+00:00",
        })
        _write_json(tmp_path, "report.json", {
            "type": "evaluation_report", "eval_id": "e1",
            "suite_digest": "b" * 64, "passed": True,
            "target_digest": "a" * 64, "report_digest": "c" * 64,
            "finished_at": "2026-06-17T00:00:00+00:00",
        })
        index = build_evidence_index(str(tmp_path))
        assert index["entry_count"] == 2
        assert "certification" in index["artifact_types"]
        assert "evaluation_report" in index["artifact_types"]

    def test_index_has_digest(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "certification_status": "certified",
        })
        index = build_evidence_index(artifact)
        assert index["evidence_index_digest"]
        assert len(index["evidence_index_digest"]) == 64

    def test_index_writes_file(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        out = str(tmp_path / "index.json")
        build_evidence_index(artifact, output_path=out)
        data = json.loads(Path(out).read_text(encoding="utf-8"))
        assert data["entry_count"] == 1

    def test_evidence_types_constant(self):
        from nodechain.cli.evidence import EVIDENCE_TYPES
        assert len(EVIDENCE_TYPES) >= 11
        for t in ["trace", "audit_bundle", "attestation", "verifier_profile",
                   "gate_receipt", "deployment_receipt", "release_history_snapshot",
                   "drift_report", "remediation_receipt", "evaluation_report",
                   "certification"]:
            assert t in EVIDENCE_TYPES


# ── AC3+AC4: Evidence Query ────────────────────────────────────────────────

class TestEvidenceQuery:
    """AC3: evidence query command. AC4: 12 filter types."""

    def _build_index(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "target_type": "node", "target_ref": "echo_node",
            "certification_status": "certified", "issued_at": "2026-06-17T00:00:00+00:00",
        })
        _write_json(tmp_path, "report.json", {
            "type": "evaluation_report", "eval_id": "e1",
            "suite_digest": "b" * 64, "passed": True,
            "target_digest": "a" * 64, "report_digest": "c" * 64,
            "finished_at": "2026-06-16T00:00:00+00:00",
        })
        return build_evidence_index(str(tmp_path))

    def test_query_by_target_digest(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, filters={"target_digest": "a" * 64})
        assert len(results) == 2

    def test_query_by_artifact_type(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, filters={"artifact_type": "certification"})
        assert len(results) == 1
        assert results[0]["artifact_type"] == "certification"

    def test_query_by_certification_status(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, filters={"certification_status": "certified"})
        assert len(results) == 1

    def test_query_partial_string(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, filters={"target_ref": "echo"})
        assert len(results) == 1

    def test_query_time_range(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, time_from="2026-06-17T00:00:00+00:00")
        assert len(results) == 1  # only cert, not report

    def test_query_no_matches(self, tmp_path):
        from nodechain.cli.evidence import query_evidence
        index = self._build_index(tmp_path)
        results = query_evidence(index, filters={"target_digest": "z" * 64})
        assert len(results) == 0

    def test_query_filters_constant(self):
        from nodechain.cli.evidence import QUERY_FILTERS
        assert len(QUERY_FILTERS) >= 12


# ── AC5+AC6: Timeline ──────────────────────────────────────────────────────

class TestTimeline:
    """AC5: evidence timeline command. AC6: reconstructs operational phases."""

    def test_timeline_built(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, build_timeline
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "target_ref": "echo_node",
            "certification_status": "certified", "issued_at": "2026-06-17T00:00:00+00:00",
        })
        _write_json(tmp_path, "report.json", {
            "type": "evaluation_report", "eval_id": "e1",
            "suite_digest": "b" * 64, "passed": True,
            "target_digest": "a" * 64, "report_digest": "c" * 64,
            "finished_at": "2026-06-16T00:00:00+00:00",
        })
        index = build_evidence_index(str(tmp_path))
        timeline = build_timeline(index)
        assert timeline["event_count"] == 2
        assert timeline["timeline_digest"]
        assert len(timeline["timeline_digest"]) == 64

    def test_timeline_filtered_by_target(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, build_timeline
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "target_ref": "echo_node",
        })
        _write_json(tmp_path, "cert2.json", {
            "type": "evaluation_certification", "certification_id": "c2",
            "target_digest": "b" * 64, "target_ref": "other_node",
        })
        index = build_evidence_index(str(tmp_path))
        timeline = build_timeline(index, target="echo")
        assert timeline["event_count"] == 1

    def test_timeline_events_have_summaries(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, build_timeline
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "certification_status": "certified",
        })
        index = build_evidence_index(str(tmp_path))
        timeline = build_timeline(index)
        assert timeline["events"][0]["summary"]


# ── AC7+AC8: Trace Replay ──────────────────────────────────────────────────

class TestTraceReplay:
    """AC7: trace replay command. AC8: verifies 7 checks."""

    def _make_trace(self, events=None):
        if events is None:
            events = [
                {"step": 1, "node_id": "n1", "state": "completed",
                 "contract": {"input_port": "raw_text", "output_port": "normalized"}},
                {"step": 2, "node_id": "n2", "state": "completed",
                 "contract": {"input_port": "normalized", "output_port": "enriched"}},
            ]
        return {"chain_id": "test-chain", "run_id": "r1", "events": events}

    def test_replay_valid_trace(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace()
        report = replay_trace(trace)
        assert report["passed"] is True
        assert len(report["checks"]) == 7

    def test_replay_step_order_violation(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace([
            {"step": 3, "node_id": "n2", "state": "completed"},
            {"step": 1, "node_id": "n1", "state": "completed"},
        ])
        report = replay_trace(trace)
        step_check = [c for c in report["checks"] if c["check"] == "step_order"][0]
        assert step_check["passed"] is False

    def test_replay_policy_denied(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace([
            {"step": 1, "node_id": "n1", "state": "completed", "policy_verdict": "denied"},
        ])
        report = replay_trace(trace, strict=True)
        assert report["passed"] is False

    def test_replay_invalid_state_transition(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace([
            {"step": 1, "node_id": "n1", "state": "completed"},
            {"step": 2, "node_id": "n2", "state": "running"},
        ])
        report = replay_trace(trace)
        state_check = [c for c in report["checks"] if c["check"] == "state_transitions"][0]
        assert state_check["passed"] is False

    def test_replay_strict_vs_non_strict(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace([
            {"step": 1, "node_id": "n1", "state": "completed",
             "policy_verdict": "denied"},
        ])
        non_strict = replay_trace(trace, strict=False)
        strict = replay_trace(trace, strict=True)
        # Non-strict still records errors but may pass
        assert strict["strict_mode"] is True
        assert strict["passed"] is False

    def test_replay_has_digest(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace()
        report = replay_trace(trace)
        assert report["replay_report_digest"]
        assert len(report["replay_report_digest"]) == 64

    def test_replay_from_file(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = self._make_trace()
        path = _write_json(tmp_path, "trace.json", trace)
        report = replay_trace(path)
        assert report["passed"] is True


# ── AC9: Evidence Report Signing ───────────────────────────────────────────

class TestEvidenceSigning:
    """AC9: Evidence reports can be signed with RSA-PSS-SHA256."""

    def test_sign_index(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, sign_evidence_report
        priv_path, _ = _generate_key_pair(tmp_path)
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        index = build_evidence_index(artifact)
        signed = sign_evidence_report(index, priv_path)
        assert signed["evidence_signature"]
        assert signed["evidence_signature_algorithm"] == "RSA-PSS-SHA256"
        assert signed["evidence_signer_fingerprint"]

    def test_verify_signed_index(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, sign_evidence_report, verify_evidence_report
        priv_path, pub_path = _generate_key_pair(tmp_path)
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        index = build_evidence_index(artifact)
        signed = sign_evidence_report(index, priv_path)
        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_evidence_report(signed, public_key_pem=pubkey)
        assert result["valid"] is True

    def test_verify_unsigned_fails(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, verify_evidence_report
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        index = build_evidence_index(artifact)
        result = verify_evidence_report(index)
        assert result["valid"] is False

    def test_verify_bad_signature_fails(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, sign_evidence_report, verify_evidence_report
        priv_path, _ = _generate_key_pair(tmp_path)
        _, pub_path2 = _generate_key_pair(tmp_path, suffix="2")
        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        index = build_evidence_index(artifact)
        signed = sign_evidence_report(index, priv_path)
        wrong_pub = Path(pub_path2).read_text(encoding="utf-8")
        result = verify_evidence_report(signed, public_key_pem=wrong_pub)
        assert result["valid"] is False


# ── AC10: Trust Store Purpose ──────────────────────────────────────────────

class TestTrustStorePurpose:
    """AC10: evidence_report_signing trust store purpose."""

    def test_purpose_in_valid(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert "evidence_report_signing" in VALID_PURPOSES

    def test_purpose_count(self):
        from nodechain.cli.trust_store import VALID_PURPOSES
        assert len(VALID_PURPOSES) == 13

    def test_trust_store_verification(self, tmp_path):
        from nodechain.cli.evidence import build_evidence_index, sign_evidence_report, verify_evidence_report
        from nodechain.cli.trust_store import add_key
        import os

        priv_path, pub_path = _generate_key_pair(tmp_path)
        ts_path = str(tmp_path / "ts.json")
        os.environ["NODECHAIN_TRUST_STORE"] = ts_path
        add_key(public_key_path=pub_path, name="ev-signer",
                purposes=["evidence_report_signing"])
        del os.environ["NODECHAIN_TRUST_STORE"]

        artifact = _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64,
        })
        index = build_evidence_index(artifact)
        signed = sign_evidence_report(index, priv_path)

        result = verify_evidence_report(signed, trust_store_path=ts_path)
        assert result["valid"] is True
        assert result["details"]["signer_trusted"] is True


# ── AC11: Strict Mode ──────────────────────────────────────────────────────

class TestStrictMode:
    """AC11: Strict mode fails on various error conditions."""

    def test_strict_replay_fails_on_policy(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = {
            "chain_id": "c", "run_id": "r",
            "events": [{"step": 1, "node_id": "n1", "state": "completed",
                        "policy_verdict": "denied"}],
        }
        report = replay_trace(trace, strict=True)
        assert report["passed"] is False
        assert report["strict_mode"] is True

    def test_strict_replay_fails_on_port_mismatch(self, tmp_path):
        from nodechain.cli.trace_replay import replay_trace
        trace = {
            "chain_id": "c", "run_id": "r",
            "events": [
                {"step": 1, "node_id": "n1", "state": "completed",
                 "contract": {"input_port": "a", "output_port": "b"}},
                {"step": 2, "node_id": "n2", "state": "completed",
                 "contract": {"input_port": "x", "output_port": "y"}},
            ],
        }
        report = replay_trace(trace, strict=True)
        assert report["passed"] is False

    def test_unsupported_artifact_type_in_index(self, tmp_path):
        from nodechain.cli.evidence import index_artifact
        entry = index_artifact("dummy", data={"unknown_field": "value"})
        assert entry["artifact_type"] == "unknown"


# ── Full Flow Integration ──────────────────────────────────────────────────

class TestFullEvidenceFlow:
    """End-to-end: index → query → timeline → sign → verify."""

    def test_full_flow(self, tmp_path):
        from nodechain.cli.evidence import (
            build_evidence_index, query_evidence, build_timeline,
            sign_evidence_report, verify_evidence_report,
        )

        # Create artifacts
        _write_json(tmp_path, "cert.json", {
            "type": "evaluation_certification", "certification_id": "c1",
            "target_digest": "a" * 64, "target_type": "node", "target_ref": "echo_node",
            "certification_status": "certified", "issued_at": "2026-06-17T00:00:00+00:00",
        })
        _write_json(tmp_path, "report.json", {
            "type": "evaluation_report", "eval_id": "e1",
            "suite_digest": "b" * 64, "passed": True,
            "target_digest": "a" * 64, "report_digest": "c" * 64,
            "finished_at": "2026-06-16T00:00:00+00:00",
        })

        # 1. Index
        index = build_evidence_index(str(tmp_path))
        assert index["entry_count"] == 2

        # 2. Query
        results = query_evidence(index, filters={"artifact_type": "certification"})
        assert len(results) == 1

        # 3. Timeline
        timeline = build_timeline(index)
        assert timeline["event_count"] == 2

        # 4. Sign
        priv_path, pub_path = _generate_key_pair(tmp_path)
        signed = sign_evidence_report(index, priv_path)
        assert signed["evidence_signature"]

        # 5. Verify
        pubkey = Path(pub_path).read_text(encoding="utf-8")
        result = verify_evidence_report(signed, public_key_pem=pubkey)
        assert result["valid"] is True
