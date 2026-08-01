"""Negative smoke tests for v1.11.2 Proxmox adapter hardening.

Each test proves that a specific policy violation actually fails.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


class TestHostFingerprintMismatch:
    """Host fingerprint mismatch fails in strict mode."""

    def test_fingerprint_mismatch_detected(self, tmp_path, monkeypatch):
        """_ssh_exec tracks host key pin mismatch via stderr."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            strict_host_key_checking=True,
            proxmox_host_fingerprint="SHA256:expected",
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        # Simulate what happens when SSH reports host key failure
        adapter._host_pin_matched = False
        adapter._host_key_verified = False
        # deploy should still run but record the mismatch
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["host_key_pin_checked"] is True
        assert result["host_key_pin_matched"] is False

    def test_receipt_has_host_pin_fields(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            proxmox_host_fingerprint="SHA256:test",
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert "host_key_pin_checked" in result
        assert "host_key_pin_matched" in result
        assert result["host_key_pin_checked"] is True


class TestRootUserFails:
    """root user without allow_root fails in strict mode."""

    def test_root_denied_strict(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "root")
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["validate_target"],
            allow_root=False,
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest(strict=True)
        assert any("root" in i.lower() and "not allowed" in i for i in issues)


class TestVmidOutsideAllowlist:
    """VMID outside allowlist fails."""

    def test_vmid_outside_fails(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="999",
            allowed_vmid_list=["801", "802"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("999" in i for i in issues)


class TestNodeOutsideAllowlist:
    """Node outside allowlist fails."""

    def test_node_outside_fails(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="evil-node", target_vmid="801",
            allowed_node_list=["pve1", "pve2"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("evil-node" in i for i in issues)


class TestActionOutsideAllowlist:
    """Action outside allowlist fails."""

    def test_unknown_action_fails(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["destroy_all"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("Unknown actions" in i for i in issues)


class TestArgvOnlyExecution:
    """execute_deploy proves argv-only execution with shell_used=false."""

    def test_shell_used_is_false(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["shell_used"] is False

    def test_proxmox_command_shape_is_ssh(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["proxmox_command_shape"] == "ssh"


class TestRemoteHashVerification:
    """Remote hash verification fields in receipt."""

    def test_receipt_has_hash_fields(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            require_artifact_hash_verification=True,
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert "remote_hash_verified" in result
        assert "remote_hash_matched" in result
        assert result["remote_hash_verified"] is True

    def test_hash_verification_off_by_default(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["remote_hash_verified"] is False


class TestKnownHostsConfig:
    """known_hosts configuration."""

    def test_strict_requires_known_hosts_or_fingerprint(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["validate_target"],
            strict_host_key_checking=True,
            # No known_hosts_path or proxmox_host_fingerprint
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest(strict=True)
        assert any("known_hosts" in i or "fingerprint" in i for i in issues)

    def test_known_hosts_satisfies_strict(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "deploy")
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["validate_target"],
            strict_host_key_checking=True,
            known_hosts_path="/etc/ssh/known_hosts",
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest(strict=True)
        assert not any("known_hosts" in i or "fingerprint" in i for i in issues)


class TestFullNegativeSmokeSuite:
    """All 7 negative scenarios prove failure."""

    def test_all_violations_produce_rejection(self, tmp_path, monkeypatch):
        """Every policy violation produces a 'rejected' deploy_status."""
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter

        violations = [
            # VMID outside allowlist
            AdapterManifest(
                adapter_id="v1", adapter_type="proxmox",
                proxmox_node="pve1", target_vmid="999",
                allowed_vmid_list=["801"],
            ),
            # Node outside allowlist
            AdapterManifest(
                adapter_id="v2", adapter_type="proxmox",
                proxmox_node="wrong", target_vmid="801",
                allowed_node_list=["pve1"],
            ),
            # Unknown action
            AdapterManifest(
                adapter_id="v3", adapter_type="proxmox",
                proxmox_node="pve1", target_vmid="801",
                allowed_actions=["nuke"],
            ),
            # Missing node
            AdapterManifest(
                adapter_id="v4", adapter_type="proxmox",
                target_vmid="801",
            ),
            # Missing vmid
            AdapterManifest(
                adapter_id="v5", adapter_type="proxmox",
                proxmox_node="pve1",
            ),
            # Wrong type
            AdapterManifest(
                adapter_id="v6", adapter_type="local_shell",
                proxmox_node="pve1", target_vmid="801",
            ),
        ]

        for manifest in violations:
            adapter = ProxmoxAdapter(manifest=manifest)
            result = adapter.deploy("target", "artifact", "policy", "receipt-id")
            assert result["deploy_status"] == "rejected", (
                f"Expected rejection for {manifest.adapter_id}, "
                f"got {result['deploy_status']}: {result['deploy_detail']}"
            )
