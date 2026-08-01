"""Tests for v1.11.1 Proxmox adapter hardening."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


class TestProxmoxHostKeyPinning:
    """SSH host key verification and pinning."""

    def test_manifest_host_key_fields(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            strict_host_key_checking=True,
            known_hosts_path="/etc/ssh/ssh_known_hosts",
            proxmox_host_fingerprint="SHA256:abc123",
        )
        d = m.to_dict()
        assert d["strict_host_key_checking"] is True
        assert d["known_hosts_path"] == "/etc/ssh/ssh_known_hosts"
        assert d["proxmox_host_fingerprint"] == "SHA256:abc123"

    def test_manifest_host_key_roundtrip(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            strict_host_key_checking=False,
            known_hosts_path="",
        )
        m2 = AdapterManifest.from_dict(m.to_dict())
        assert m2.strict_host_key_checking is False
        assert m2.known_hosts_path == ""

    def test_ssh_args_strict_host_key(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            strict_host_key_checking=True,
            known_hosts_path="/tmp/known_hosts",
        )
        adapter = ProxmoxAdapter(manifest=m)
        args = adapter._build_ssh_args()
        assert "StrictHostKeyChecking=yes" in args
        assert "UserKnownHostsFile=/tmp/known_hosts" in args

    def test_ssh_args_no_strict(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            strict_host_key_checking=False,
        )
        adapter = ProxmoxAdapter(manifest=m)
        args = adapter._build_ssh_args()
        assert "StrictHostKeyChecking=no" in args

    def test_strict_mode_requires_host_key_config(self, tmp_path, monkeypatch):
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
        assert any("known_hosts_path" in i or "host_fingerprint" in i for i in issues)


class TestProxmoxDeployIdentity:
    """Dedicated deploy identity enforcement."""

    def test_root_user_rejected_in_strict(self, tmp_path, monkeypatch):
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
        assert any("root" in i.lower() for i in issues)

    def test_root_user_allowed_with_flag(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "root")
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["validate_target"],
            allow_root=True,
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest(strict=True)
        assert not any("root" in i.lower() and "not allowed" in i for i in issues)

    def test_nonroot_user_accepted(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "deploy")
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["validate_target"],
            allow_root=False,
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest(strict=True)
        assert not any("root" in i.lower() and "not allowed" in i for i in issues)


class TestProxmoxAllowlists:
    """VMID and node allowlist enforcement."""

    def test_vmid_outside_allowlist_rejected(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="999",
            allowed_vmid_list=["801", "802"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("999" in i and "allowed_vmid_list" in i for i in issues)

    def test_vmid_in_allowlist_accepted(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_vmid_list=["801", "802"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert not any("allowed_vmid_list" in i for i in issues)

    def test_node_outside_allowlist_rejected(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="wrong-node", target_vmid="801",
            allowed_node_list=["pve1", "pve2"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert any("wrong-node" in i and "allowed_node_list" in i for i in issues)

    def test_node_in_allowlist_accepted(self):
        from nodechain.cli.deployment_adapter import AdapterManifest, ProxmoxAdapter
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_node_list=["pve1", "pve2"],
        )
        adapter = ProxmoxAdapter(manifest=m)
        issues = adapter._validate_proxmox_manifest()
        assert not any("allowed_node_list" in i for i in issues)


class TestProxmoxReceiptFields:
    """Receipt records v1.11.1 SSH hardening fields."""

    def test_receipt_has_ssh_fields(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import ProxmoxAdapter, AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            proxmox_host_fingerprint="SHA256:test",
            allow_root=True,
        )
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "deploy")
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert "ssh_user" in result
        assert "host_key_verified" in result
        assert "root_user_used" in result
        assert "sudo_used" in result
        assert "ssh_host_fingerprint" in result
        assert result["ssh_user"] == "deploy"
        assert result["root_user_used"] is False
        assert result["ssh_host_fingerprint"] == "SHA256:test"

    def test_receipt_root_user_flagged(self, tmp_path, monkeypatch):
        from nodechain.cli.deployment_adapter import ProxmoxAdapter, AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            allowed_actions=["upload_artifact"],
            execution_mode="argv", argv_template=["echo"],
            allow_root=True,
        )
        monkeypatch.setenv("NODECHAIN_PROXMOX_USER", "root")
        adapter = ProxmoxAdapter(manifest=m)
        result = adapter.deploy("target", "artifact", "policy", "receipt-id")
        assert result["root_user_used"] is True


class TestProxmoxArtifactHash:
    """Artifact hash verification configuration."""

    def test_manifest_has_artifact_hash_field(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            require_artifact_hash_verification=True,
        )
        assert m.require_artifact_hash_verification is True
        d = m.to_dict()
        assert d["require_artifact_hash_verification"] is True

    def test_deploy_timeout_override(self):
        from nodechain.cli.deployment_adapter import AdapterManifest
        m = AdapterManifest(
            adapter_id="px-1", adapter_type="proxmox",
            proxmox_node="pve1", target_vmid="801",
            timeout_seconds=30,
            deploy_timeout_seconds=120,
        )
        assert m.deploy_timeout_seconds == 120
        d = m.to_dict()
        assert d["deploy_timeout_seconds"] == 120
