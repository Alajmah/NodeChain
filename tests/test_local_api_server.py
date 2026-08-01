"""Local API Server tests (v2.67.3).

Deterministic tests using FastAPI TestClient — no real network.
Covers auth, health, runs, evidence, profiles, dashboard, preview, and error model.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from nodechain.api.app import create_app
from nodechain.core.state import StateManager, ChainState


TEST_TOKEN = "test-token-1234567890abcdef"
AUTH_HEADER = {"Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Create a test client with a temp DB and set token."""
    db = str(tmp_path / "test_api.db")
    monkeypatch.setenv("NODECHAIN_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("NODECHAIN_API_EXPOSE_DOCS", "1")
    app = create_app(db_path=db, trace_dir=str(tmp_path / "traces"))
    return TestClient(app)


@pytest.fixture
def client_with_run(tmp_path, monkeypatch):
    """Create a test client with a pre-existing failed run."""
    db = str(tmp_path / "test_api_run.db")
    monkeypatch.setenv("NODECHAIN_API_TOKEN", TEST_TOKEN)
    monkeypatch.setenv("NODECHAIN_API_EXPOSE_DOCS", "1")

    sm = StateManager(db_path=db)
    state = ChainState(run_id="test-run-001", chain_id="research_decision_v1")
    state.status = "failed"
    state.step = 5
    state.current_node = "risk_classifier"
    sm.save(state)

    app = create_app(db_path=db, trace_dir=str(tmp_path / "traces"))
    return TestClient(app)


# ── Auth tests ────────────────────────────────────────────────────────────

class TestAuth:
    def test_no_auth_returns_401(self, client):
        resp = client.get("/api/v1/health")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "unauthorized"

    def test_wrong_token_returns_403(self, client):
        resp = client.get("/api/v1/health", headers={"Authorization": "Bearer wrong-token"})
        assert resp.status_code == 403
        assert resp.json()["error"]["code"] == "forbidden"

    def test_correct_token_succeeds(self, client):
        resp = client.get("/api/v1/health", headers=AUTH_HEADER)
        assert resp.status_code == 200


# ── Health ────────────────────────────────────────────────────────────────

class TestHealth:
    def test_returns_version(self, client):
        resp = client.get("/api/v1/health", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert data["api_version"] == "v1"


# ── Runs ──────────────────────────────────────────────────────────────────

class TestRuns:
    def test_list_empty(self, client):
        resp = client.get("/api/v1/runs", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["runs"] == []

    def test_list_with_run(self, client_with_run):
        resp = client_with_run.get("/api/v1/runs", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["runs"][0]["run_id"] == "test-run-001"

    def test_get_run_snapshot(self, client_with_run):
        resp = client_with_run.get("/api/v1/runs/test-run-001", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["run_id"] == "test-run-001"
        assert data["status"] == "failed"

    def test_get_run_not_found(self, client):
        resp = client.get("/api/v1/runs/nonexistent", headers=AUTH_HEADER)
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "run_not_found"

    def test_get_evidence(self, client_with_run):
        resp = client_with_run.get("/api/v1/runs/test-run-001/evidence", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["run_id"] == "test-run-001"

    def test_get_report(self, client_with_run):
        resp = client_with_run.get("/api/v1/runs/test-run-001/report", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["run_id"] == "test-run-001"


# ── Profiles ──────────────────────────────────────────────────────────────

class TestProfiles:
    def test_list_profiles(self, client):
        resp = client.get("/api/v1/profiles", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 4  # solo-dev, team-default, regulated, break-glass
        ids = [p["id"] for p in data["profiles"]]
        assert "team-default" in ids

    def test_get_profile_detail(self, client):
        resp = client.get("/api/v1/profiles/team-default", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "team-default"
        assert "action_matrix" in data
        assert "resume" in data["action_matrix"]
        assert data["action_matrix"]["resume"]["operator"] is True

    def test_get_break_glass_admin_only(self, client):
        resp = client.get("/api/v1/profiles/break-glass", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["action_matrix"]["resume"]["operator"] is False
        assert data["action_matrix"]["resume"]["admin"] is True

    def test_profile_not_found(self, client):
        resp = client.get("/api/v1/profiles/nonexistent", headers=AUTH_HEADER)
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "profile_not_found"


# ── Dashboard ─────────────────────────────────────────────────────────────

class TestDashboard:
    def test_dashboard_empty(self, client):
        resp = client.get("/api/v1/dashboard", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_runs"] == 0
        assert data["recovery_backlog"] == 0

    def test_dashboard_with_run(self, client_with_run):
        resp = client_with_run.get("/api/v1/dashboard", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_runs"] >= 1


# ── Preview ───────────────────────────────────────────────────────────────

class TestPreview:
    def test_preview_resume(self, client_with_run):
        resp = client_with_run.post(
            "/api/v1/runs/test-run-001/preview",
            headers=AUTH_HEADER,
            json={"action": "resume", "role": "operator"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "resume"
        assert data["mutated"] is False
        assert "admitted" in data

    def test_preview_budget_denied_for_operator(self, client_with_run):
        resp = client_with_run.post(
            "/api/v1/runs/test-run-001/preview",
            headers=AUTH_HEADER,
            json={"action": "approve_budget_increase", "role": "operator", "new_budget": 100},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["admitted"] is False
        assert data["mutated"] is False

    def test_preview_invalid_action(self, client_with_run):
        resp = client_with_run.post(
            "/api/v1/runs/test-run-001/preview",
            headers=AUTH_HEADER,
            json={"action": "not_real"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_action"

    def test_preview_run_not_found(self, client):
        resp = client.post(
            "/api/v1/runs/nonexistent/preview",
            headers=AUTH_HEADER,
            json={"action": "resume"},
        )
        assert resp.status_code == 404
        assert resp.json()["error"]["code"] == "run_not_found"

    def test_preview_no_mutation(self, client_with_run):
        """Verify preview does not change state revision."""
        from nodechain.core.state import StateManager
        # Get initial revision
        app = client_with_run.app
        sm = StateManager(db_path=app.state.db_path)
        state_before = sm.load("test-run-001")
        rev_before = state_before.revision if state_before else 0

        # Run preview
        resp = client_with_run.post(
            "/api/v1/runs/test-run-001/preview",
            headers=AUTH_HEADER,
            json={"action": "resume", "role": "operator"},
        )
        assert resp.status_code == 200

        # Verify revision unchanged
        state_after = sm.load("test-run-001")
        rev_after = state_after.revision if state_after else 0
        assert rev_after == rev_before


# ── OpenAPI ───────────────────────────────────────────────────────────────

class TestOpenAPI:
    def test_openapi_schema_available(self, client):
        """When docs are exposed, /openapi.json should be available."""
        resp = client.get("/openapi.json", headers=AUTH_HEADER)
        assert resp.status_code == 200
        data = resp.json()
        assert data["info"]["title"] == "NodeChain Operator API"
        # Verify key paths are in schema
        paths = data.get("paths", {})
        assert "/api/v1/health" in paths
        assert "/api/v1/runs" in paths
        assert "/api/v1/profiles" in paths

    def test_docs_ui_available(self, client):
        """When docs are exposed, /docs should serve Swagger UI."""
        resp = client.get("/docs", headers=AUTH_HEADER)
        assert resp.status_code == 200
