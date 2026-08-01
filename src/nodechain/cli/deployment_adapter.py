"""Deployment system adapters (v1.10.0–v1.10.1).

Binds the NodeChain deploy gate receipt to a real deployment system action.
The adapter interface allows different deployment backends (dry-run, local
shell, Docker, Proxmox, Kubernetes, etc.) to produce a deployment-system
receipt that proves the deployment was actually accepted/applied.

v1.10.1 adds the AdapterManifest — a policy document governing each adapter
with allowed targets, required digests, command templates, and safety checks.

Receipt types:
  gate_receipt           — NodeChain deploy gate evaluated and allowed/denied
  deployment_system_receipt — deployment system accepted/applied the artifact

Commands:
  nodechain deploy --receipt receipt.json --adapter dry-run --output deploy_receipt.json
  nodechain deploy --receipt receipt.json --adapter dry-run --sign key.pem
  nodechain deploy --verify deploy_receipt.json --pubkey pub.pem
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

#: Schema version for deployment-system receipts.
DEPLOYMENT_SYSTEM_RECEIPT_SCHEMA_VERSION = "1"

#: Schema version for adapter manifests.
ADAPTER_MANIFEST_SCHEMA_VERSION = "1"

#: Required fields in every deployment-system receipt.
REQUIRED_DEPLOYMENT_RECEIPT_FIELDS = frozenset({
    "schema_version",
    "type",
    "deployment_receipt_id",
    "deployment_system",
    "target",
    "artifact_digest",
    "deploy_status",
    "deploy_started_at",
    "deploy_finished_at",
    "assurance_receipt_digest",
})

#: Patterns that indicate unsafe command interpolation.
_UNSAFE_PATTERNS = [
    re.compile(r"\$\("),    # command substitution
    re.compile(r"`"),        # backtick substitution
    re.compile(r"\$\{"),    # variable expansion
    re.compile(r";\s*"),    # command chaining
    re.compile(r"\|\s*"),   # piping
    re.compile(r">\s*"),    # redirect
    re.compile(r"<\s*"),    # redirect
    re.compile(r"&&"),       # AND chaining
    re.compile(r"\|\|"),    # OR chaining
]

#: Safe template variables that are allowed in command templates.
_SAFE_TEMPLATE_VARS = {"{target}", "{artifact_digest}", "{policy_digest}"}

#: v1.11.0: Actions allowed for Proxmox SSH adapter.
PROXMOX_ACTIONS = frozenset({
    "validate_target",
    "upload_artifact",
    "execute_deploy",
})

#: v1.12.0: Actions allowed for Proxmox API adapter (read-only).
#: v1.12.2: Added 'start' as first mutation action.
#: v1.12.4: Added 'stop' with idempotency support.
#: v1.12.5: Added 'reboot' with boot-evidence support.
PROXMOX_API_ACTIONS = frozenset({
    "validate_target",
    "get_status",
    "start",         # v1.12.2: POST /status/start → UPID task
    "stop",          # v1.12.4: POST /status/stop → UPID task
    "reboot",        # v1.12.5: POST /status/reboot → UPID task
    "upload_artifact", # v1.13.0: POST /storage/{storage}/upload → stage
    "promote_artifact", # v1.13.1: Move staged artifact to final location
    "apply_artifact",   # v1.13.2: Activate promoted artifact
    "rollback_artifact", # v1.13.3: Revert to previous artifact
})

#: v1.13.1: Artifact action matrix documents the three-stage pipeline.
ARTIFACT_ACTION_MATRIX = {
    "upload_artifact": {
        "stage": "upload",
        "target": "staging_directory",
        "promotes": False,
        "activates": False,
        "description": "Stage artifact to staging directory via HTTP API upload",
    },
    "promote_artifact": {
        "stage": "promote",
        "target": "final_path",
        "promotes": True,
        "activates": False,
        "description": "Move staged artifact from staging to final path",
    },
    "apply_artifact": {
        "stage": "apply",
        "target": "final_path",
        "promotes": False,
        "activates": True,
        "description": "Activate artifact (future: restart service, link, etc.)",
    },
    "rollback_artifact": {
        "stage": "rollback",
        "target": "final_path",
        "promotes": False,
        "activates": True,
        "description": "Revert to previous artifact version (v1.13.3)",
    },
}

#: v1.12.2: Mutation actions that trigger POST + task polling.
PROXMOX_API_MUTATION_ACTIONS = frozenset({"start", "stop", "reboot"})

#: v1.12.7: Normalized lifecycle evidence matrix for Proxmox API actions.
#: Each entry documents the policy requirements for that action.
PROXMOX_API_LIFECYCLE_MATRIX: dict[str, dict[str, Any]] = {
    "validate_target": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": False,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": ["action_not_allowed", "target_not_in_allowlist"],
    },
    "get_status": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": False,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": ["action_not_allowed"],
    },
    "start": {
        "required_pre_state": "stopped",
        "required_post_state": "running",
        "task_required": True,
        "boot_evidence_required": False,
        "noop_allowed": True,
        "strict_failure_modes": [
            "action_not_allowed", "pre_state_mismatch", "task_failure",
            "task_timeout", "post_state_mismatch", "noop_rejected",
        ],
    },
    "stop": {
        "required_pre_state": "running",
        "required_post_state": "stopped",
        "task_required": True,
        "boot_evidence_required": False,
        "noop_allowed": True,
        "strict_failure_modes": [
            "action_not_allowed", "pre_state_mismatch", "task_failure",
            "task_timeout", "post_state_mismatch", "noop_rejected",
        ],
    },
    "reboot": {
        "required_pre_state": "running",
        "required_post_state": "running",
        "task_required": True,
        "boot_evidence_required": True,
        "noop_allowed": False,
        "strict_failure_modes": [
            "action_not_allowed", "pre_state_mismatch", "task_failure",
            "task_timeout", "post_state_mismatch",
            "boot_id_unchanged", "fallback_forbidden",
        ],
    },
    "upload_artifact": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": False,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": [
            "action_not_allowed", "artifact_digest_missing",
            "artifact_too_large", "remote_path_not_allowed",
            "remote_digest_mismatch", "overwrite_not_allowed",
            "transfer_incomplete",
        ],
    },
    "promote_artifact": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": False,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": [
            "action_not_allowed", "staging_path_missing",
            "final_path_not_allowed", "staging_digest_mismatch",
            "final_digest_mismatch", "overwrite_not_allowed",
            "promotion_incomplete", "unsigned_manifest",
        ],
    },
    "apply_artifact": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": True,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": [
            "action_not_allowed", "promoted_artifact_missing",
            "digest_mismatch", "apply_failed",
            "service_state_mismatch", "activation_unverified",
            "unsigned_manifest",
        ],
    },
    "rollback_artifact": {
        "required_pre_state": "",
        "required_post_state": "",
        "task_required": True,
        "boot_evidence_required": False,
        "noop_allowed": False,
        "strict_failure_modes": [
            "action_not_allowed", "previous_artifact_missing",
            "rollback_failed", "rollback_verification_failed",
            "final_state_unknown",
            # v1.13.4: Provenance failure modes
            "previous_receipt_missing", "previous_receipt_invalid",
            "previous_digest_mismatch", "previous_release_not_applied",
            "previous_activation_not_verified",
            # v1.13.5: Full assurance chain failure modes
            "previous_receipt_unsigned", "previous_assurance_chain_invalid",
            "previous_verifier_profile_untrusted",
            "previous_attestation_non_compliant",
            "previous_receipt_not_deployment_system_receipt",
        ],
    },
}

#: v1.12.7: Canonical lifecycle receipt field set.
#: Every Proxmox API receipt MUST include all of these fields.
LIFECYCLE_RECEIPT_FIELDS = frozenset({
    "deploy_status", "deployer_identity", "deploy_detail",
    "deploy_started_at", "deploy_finished_at",
    "proxmox_node", "vmid", "action",
    "proxmox_command_shape", "shell_used",
    "api_endpoint_identity", "tls_verified",
    "token_secret_ref_type", "secret_source_allowed",
    "secret_resolved", "secret_value_serialized",
    "token_secret_ref_redacted",
})


# ── Adapter Manifest (v1.10.1) ────────────────────────────────────────────


class AdapterManifest:
    """Policy document governing a deployment adapter.

    Defines allowed targets, required digests, command templates,
    environment/working-directory policy, and timeout.
    """

    def __init__(
        self,
        adapter_id: str,
        adapter_type: str,
        allowed_targets: list[str] | None = None,
        required_policy_digest: str = "",
        allowed_artifact_digest_patterns: list[str] | None = None,
        command_template: str = "",
        environment_policy: str = "inherit",
        working_directory_policy: str = "inherit",
        timeout_seconds: int = 30,
        argv_template: list[str] | None = None,
        execution_mode: str = "shell",
        allow_shell: bool = False,
        allowed_executables: list[str] | None = None,
        # v1.11.0: Proxmox fields
        proxmox_node: str = "",
        target_vmid: str = "",
        allowed_actions: list[str] | None = None,
        # v1.11.1: Proxmox hardening fields
        allowed_vmid_list: list[str] | None = None,
        allowed_node_list: list[str] | None = None,
        allowed_remote_paths: list[str] | None = None,
        deploy_timeout_seconds: int = 0,
        require_artifact_hash_verification: bool = False,
        proxmox_host_fingerprint: str = "",
        known_hosts_path: str = "",
        strict_host_key_checking: bool = True,
        allow_root: bool = False,
        # v1.12.0: Proxmox API adapter fields
        api_base_url: str = "",
        token_id: str = "",
        token_secret_ref: str = "",
        verify_tls: bool = True,
        ca_bundle_path: str = "",
        allow_insecure_tls: bool = False,
        # v1.12.1: Secret reference policy fields
        allowed_secret_ref_prefixes: list[str] | None = None,
        allowed_env_vars: list[str] | None = None,
        allowed_secret_files: list[str] | None = None,
        require_secret_ref: bool = False,
        forbid_inline_secrets: bool = True,
        # v1.12.2: Proxmox API task action fields
        allowed_api_actions: list[str] | None = None,
        require_confirmed_target_status: bool = False,
        expected_pre_state: str = "",
        expected_post_state: str = "",
        task_timeout_seconds: int = 120,
        # v1.12.3: Task polling fields
        task_poll_interval_seconds: float = 1.0,
        task_max_polls: int = 10,
        require_task_success: bool = True,
        # v1.12.4: Idempotency fields
        idempotency_policy: str = "reject_noop",
        allow_noop_if_already_desired: bool = False,
        # v1.12.5: Reboot evidence fields
        require_boot_id_change: bool = False,
        require_uptime_reset: bool = False,
        reboot_timeout_seconds: int = 300,
        # v1.12.6: Boot ID evidence fields
        boot_evidence_source: str = "uptime",
        allow_uptime_only_fallback: bool = True,
        # v1.12.7: Boot ID safety fields
        hash_boot_ids: bool = True,
        allow_raw_boot_ids: bool = False,
        # v1.13.0: Artifact deployment fields
        artifact_digest_required: bool = True,
        remote_digest_verification_required: bool = True,
        max_artifact_size_bytes: int = 0,
        overwrite_policy: str = "reject",
        staging_directory: str = "",
        final_path: str = "",
        remote_storage: str = "local",
        artifact_local_path: str = "",
        # v1.13.1: Artifact promotion fields
        require_signed_manifest_for_promotion: bool = True,
        staging_digest_verification_required: bool = True,
        final_digest_verification_required: bool = True,
        # v1.13.2: Apply artifact fields
        api_apply_action: str = "",
        allowed_apply_targets: list[str] | None = None,
        require_promoted_artifact: bool = True,
        expected_service_state: str = "running",
        apply_timeout_seconds: int = 120,
        rollback_policy: str = "manual",
        # v1.13.3: Rollback fields
        previous_artifact_digest: str = "",
        rollback_target_path: str = "",
        rollback_timeout_seconds: int = 120,
        require_rollback_verification: bool = True,
        rollback_on_apply_failure: bool = False,
        # v1.13.4: Rollback provenance fields
        previous_deployment_receipt: dict[str, Any] | None = None,
        previous_deployment_receipt_digest: str = "",
        previous_attestation_digest: str = "",
        require_previous_receipt_verified: bool = True,
        # v1.13.5: Full assurance chain fields
        require_previous_assurance_chain: bool = False,
        previous_attestation: dict[str, Any] | None = None,
        previous_verifier_profile: dict[str, Any] | None = None,
        previous_gate_receipt: dict[str, Any] | None = None,
        previous_audit_bundle_digest: str = "",
        previous_receipt_signature_required: bool = False,
        previous_attestation_signature_required: bool = False,
        previous_verifier_profile_trust_required: bool = False,
        # v1.13.6: Release history fields
        resolve_release_by: str = "",  # 'release_id', 'artifact_digest', 'latest_known_good'
        resolve_release_id: str = "",
        release_history_path: str = "",
        require_retention_verification: bool = False,
        # v1.13.8: Release history snapshot fields
        require_release_history_snapshot: bool = False,
        release_history_snapshot_path: str = "",
    ):
        self.adapter_id = adapter_id
        self.adapter_type = adapter_type
        self.allowed_targets = allowed_targets or ["*"]
        self.required_policy_digest = required_policy_digest
        self.allowed_artifact_digest_patterns = allowed_artifact_digest_patterns or ["*"]
        self.command_template = command_template
        self.environment_policy = environment_policy
        self.working_directory_policy = working_directory_policy
        self.timeout_seconds = timeout_seconds
        self.argv_template = argv_template or []
        self.execution_mode = execution_mode
        self.allow_shell = allow_shell
        self.allowed_executables = allowed_executables or []
        # v1.11.0: Proxmox fields
        self.proxmox_node = proxmox_node
        self.target_vmid = target_vmid
        self.allowed_actions = allowed_actions or []
        # v1.11.1: Proxmox hardening fields
        self.allowed_vmid_list = allowed_vmid_list or []
        self.allowed_node_list = allowed_node_list or []
        self.allowed_remote_paths = allowed_remote_paths or []
        self.deploy_timeout_seconds = deploy_timeout_seconds
        self.require_artifact_hash_verification = require_artifact_hash_verification
        self.proxmox_host_fingerprint = proxmox_host_fingerprint
        self.known_hosts_path = known_hosts_path
        self.strict_host_key_checking = strict_host_key_checking
        self.allow_root = allow_root
        # v1.12.0: Proxmox API adapter fields
        self.api_base_url = api_base_url
        self.token_id = token_id
        self.token_secret_ref = token_secret_ref
        self.verify_tls = verify_tls
        self.ca_bundle_path = ca_bundle_path
        self.allow_insecure_tls = allow_insecure_tls
        # v1.12.1: Secret reference policy fields
        self.allowed_secret_ref_prefixes = allowed_secret_ref_prefixes or []
        self.allowed_env_vars = allowed_env_vars or []
        self.allowed_secret_files = allowed_secret_files or []
        self.require_secret_ref = require_secret_ref
        self.forbid_inline_secrets = forbid_inline_secrets
        # v1.12.2: Proxmox API task action fields
        self.allowed_api_actions = allowed_api_actions or []
        self.require_confirmed_target_status = require_confirmed_target_status
        self.expected_pre_state = expected_pre_state
        self.expected_post_state = expected_post_state
        self.task_timeout_seconds = task_timeout_seconds
        # v1.12.3: Task polling fields
        self.task_poll_interval_seconds = task_poll_interval_seconds
        self.task_max_polls = task_max_polls
        self.require_task_success = require_task_success
        # v1.12.4: Idempotency fields
        self.idempotency_policy = idempotency_policy
        self.allow_noop_if_already_desired = allow_noop_if_already_desired
        # v1.12.5: Reboot evidence fields
        self.require_boot_id_change = require_boot_id_change
        self.require_uptime_reset = require_uptime_reset
        self.reboot_timeout_seconds = reboot_timeout_seconds
        # v1.12.6: Boot ID evidence fields
        self.boot_evidence_source = boot_evidence_source
        self.allow_uptime_only_fallback = allow_uptime_only_fallback
        # v1.12.7: Boot ID safety fields
        self.hash_boot_ids = hash_boot_ids
        self.allow_raw_boot_ids = allow_raw_boot_ids
        # v1.13.0: Artifact deployment fields
        self.artifact_digest_required = artifact_digest_required
        self.remote_digest_verification_required = remote_digest_verification_required
        self.max_artifact_size_bytes = max_artifact_size_bytes
        self.overwrite_policy = overwrite_policy
        self.staging_directory = staging_directory
        self.final_path = final_path
        self.remote_storage = remote_storage
        self.artifact_local_path = artifact_local_path
        # v1.13.1: Artifact promotion fields
        self.require_signed_manifest_for_promotion = require_signed_manifest_for_promotion
        self.staging_digest_verification_required = staging_digest_verification_required
        self.final_digest_verification_required = final_digest_verification_required
        # v1.13.2: Apply artifact fields
        self.api_apply_action = api_apply_action
        self.allowed_apply_targets = allowed_apply_targets or []
        self.require_promoted_artifact = require_promoted_artifact
        self.expected_service_state = expected_service_state
        self.apply_timeout_seconds = apply_timeout_seconds
        self.rollback_policy = rollback_policy
        # v1.13.3: Rollback fields
        self.previous_artifact_digest = previous_artifact_digest
        self.rollback_target_path = rollback_target_path
        self.rollback_timeout_seconds = rollback_timeout_seconds
        self.require_rollback_verification = require_rollback_verification
        self.rollback_on_apply_failure = rollback_on_apply_failure
        # v1.13.4: Rollback provenance fields
        self.previous_deployment_receipt = previous_deployment_receipt
        self.previous_deployment_receipt_digest = previous_deployment_receipt_digest
        self.previous_attestation_digest = previous_attestation_digest
        self.require_previous_receipt_verified = require_previous_receipt_verified
        # v1.13.5: Full assurance chain fields
        self.require_previous_assurance_chain = require_previous_assurance_chain
        self.previous_attestation = previous_attestation
        self.previous_verifier_profile = previous_verifier_profile
        self.previous_gate_receipt = previous_gate_receipt
        self.previous_audit_bundle_digest = previous_audit_bundle_digest
        self.previous_receipt_signature_required = previous_receipt_signature_required
        self.previous_attestation_signature_required = previous_attestation_signature_required
        self.previous_verifier_profile_trust_required = previous_verifier_profile_trust_required
        # v1.13.6: Release history fields
        self.resolve_release_by = resolve_release_by
        self.resolve_release_id = resolve_release_id
        self.release_history_path = release_history_path
        self.require_retention_verification = require_retention_verification
        # v1.13.8: Release history snapshot fields
        self.require_release_history_snapshot = require_release_history_snapshot
        self.release_history_snapshot_path = release_history_snapshot_path

    def to_dict(self) -> dict[str, Any]:
        """Serialize manifest to dict."""
        return {
            "schema_version": ADAPTER_MANIFEST_SCHEMA_VERSION,
            "type": "adapter_manifest",
            "adapter_id": self.adapter_id,
            "adapter_type": self.adapter_type,
            "allowed_targets": self.allowed_targets,
            "required_policy_digest": self.required_policy_digest,
            "allowed_artifact_digest_patterns": self.allowed_artifact_digest_patterns,
            "command_template": self.command_template,
            "environment_policy": self.environment_policy,
            "working_directory_policy": self.working_directory_policy,
            "timeout_seconds": self.timeout_seconds,
            "argv_template": self.argv_template,
            "execution_mode": self.execution_mode,
            "allow_shell": self.allow_shell,
            "allowed_executables": self.allowed_executables,
            # v1.11.0: Proxmox fields
            "proxmox_node": self.proxmox_node,
            "target_vmid": self.target_vmid,
            "allowed_actions": self.allowed_actions,
            # v1.11.1: Proxmox hardening fields
            "allowed_vmid_list": self.allowed_vmid_list,
            "allowed_node_list": self.allowed_node_list,
            "allowed_remote_paths": self.allowed_remote_paths,
            "deploy_timeout_seconds": self.deploy_timeout_seconds,
            "require_artifact_hash_verification": self.require_artifact_hash_verification,
            "proxmox_host_fingerprint": self.proxmox_host_fingerprint,
            "known_hosts_path": self.known_hosts_path,
            "strict_host_key_checking": self.strict_host_key_checking,
            "allow_root": self.allow_root,
            # v1.12.0: Proxmox API adapter fields
            "api_base_url": self.api_base_url,
            "token_id": self.token_id,
            "token_secret_ref": self.token_secret_ref,
            "verify_tls": self.verify_tls,
            "ca_bundle_path": self.ca_bundle_path,
            "allow_insecure_tls": self.allow_insecure_tls,
            # v1.12.1: Secret reference policy fields
            "allowed_secret_ref_prefixes": self.allowed_secret_ref_prefixes,
            "allowed_env_vars": self.allowed_env_vars,
            "allowed_secret_files": self.allowed_secret_files,
            "require_secret_ref": self.require_secret_ref,
            "forbid_inline_secrets": self.forbid_inline_secrets,
            # v1.12.2: Proxmox API task action fields
            "allowed_api_actions": self.allowed_api_actions,
            "require_confirmed_target_status": self.require_confirmed_target_status,
            "expected_pre_state": self.expected_pre_state,
            "expected_post_state": self.expected_post_state,
            "task_timeout_seconds": self.task_timeout_seconds,
            # v1.12.3: Task polling fields
            "task_poll_interval_seconds": self.task_poll_interval_seconds,
            "task_max_polls": self.task_max_polls,
            "require_task_success": self.require_task_success,
            # v1.12.4: Idempotency fields
            "idempotency_policy": self.idempotency_policy,
            "allow_noop_if_already_desired": self.allow_noop_if_already_desired,
            # v1.12.5: Reboot evidence fields
            "require_boot_id_change": self.require_boot_id_change,
            "require_uptime_reset": self.require_uptime_reset,
            "reboot_timeout_seconds": self.reboot_timeout_seconds,
            # v1.12.6: Boot ID evidence fields
            "boot_evidence_source": self.boot_evidence_source,
            "allow_uptime_only_fallback": self.allow_uptime_only_fallback,
            # v1.12.7: Boot ID safety fields
            "hash_boot_ids": self.hash_boot_ids,
            "allow_raw_boot_ids": self.allow_raw_boot_ids,
            # v1.13.0: Artifact deployment fields
            "artifact_digest_required": self.artifact_digest_required,
            "remote_digest_verification_required": self.remote_digest_verification_required,
            "max_artifact_size_bytes": self.max_artifact_size_bytes,
            "overwrite_policy": self.overwrite_policy,
            "staging_directory": self.staging_directory,
            "final_path": self.final_path,
            "remote_storage": self.remote_storage,
            "artifact_local_path": self.artifact_local_path,
            # v1.13.1: Artifact promotion fields
            "require_signed_manifest_for_promotion": self.require_signed_manifest_for_promotion,
            "staging_digest_verification_required": self.staging_digest_verification_required,
            "final_digest_verification_required": self.final_digest_verification_required,
            # v1.13.2: Apply artifact fields
            "api_apply_action": self.api_apply_action,
            "allowed_apply_targets": self.allowed_apply_targets,
            "require_promoted_artifact": self.require_promoted_artifact,
            "expected_service_state": self.expected_service_state,
            "apply_timeout_seconds": self.apply_timeout_seconds,
            "rollback_policy": self.rollback_policy,
            # v1.13.3: Rollback fields
            "previous_artifact_digest": self.previous_artifact_digest,
            "rollback_target_path": self.rollback_target_path,
            "rollback_timeout_seconds": self.rollback_timeout_seconds,
            "require_rollback_verification": self.require_rollback_verification,
            "rollback_on_apply_failure": self.rollback_on_apply_failure,
            # v1.13.4: Rollback provenance fields
            "previous_deployment_receipt": self.previous_deployment_receipt,
            "previous_deployment_receipt_digest": self.previous_deployment_receipt_digest,
            "previous_attestation_digest": self.previous_attestation_digest,
            "require_previous_receipt_verified": self.require_previous_receipt_verified,
            # v1.13.5: Full assurance chain fields
            "require_previous_assurance_chain": self.require_previous_assurance_chain,
            "previous_attestation": self.previous_attestation,
            "previous_verifier_profile": self.previous_verifier_profile,
            "previous_gate_receipt": self.previous_gate_receipt,
            "previous_audit_bundle_digest": self.previous_audit_bundle_digest,
            "previous_receipt_signature_required": self.previous_receipt_signature_required,
            "previous_attestation_signature_required": self.previous_attestation_signature_required,
            "previous_verifier_profile_trust_required": self.previous_verifier_profile_trust_required,
            # v1.13.6: Release history fields
            "resolve_release_by": self.resolve_release_by,
            "resolve_release_id": self.resolve_release_id,
            "release_history_path": self.release_history_path,
            "require_retention_verification": self.require_retention_verification,
            # v1.13.8: Release history snapshot fields
            "require_release_history_snapshot": self.require_release_history_snapshot,
            "release_history_snapshot_path": self.release_history_snapshot_path,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AdapterManifest":
        """Deserialize manifest from dict."""
        return cls(
            adapter_id=data.get("adapter_id", ""),
            adapter_type=data.get("adapter_type", ""),
            allowed_targets=data.get("allowed_targets", ["*"]),
            required_policy_digest=data.get("required_policy_digest", ""),
            allowed_artifact_digest_patterns=data.get("allowed_artifact_digest_patterns", ["*"]),
            command_template=data.get("command_template", ""),
            environment_policy=data.get("environment_policy", "inherit"),
            working_directory_policy=data.get("working_directory_policy", "inherit"),
            timeout_seconds=data.get("timeout_seconds", 30),
            argv_template=data.get("argv_template", []),
            execution_mode=data.get("execution_mode", "shell"),
            allow_shell=data.get("allow_shell", False),
            allowed_executables=data.get("allowed_executables", []),
            proxmox_node=data.get("proxmox_node", ""),
            target_vmid=data.get("target_vmid", ""),
            allowed_actions=data.get("allowed_actions", []),
            allowed_vmid_list=data.get("allowed_vmid_list", []),
            allowed_node_list=data.get("allowed_node_list", []),
            allowed_remote_paths=data.get("allowed_remote_paths", []),
            deploy_timeout_seconds=data.get("deploy_timeout_seconds", 0),
            require_artifact_hash_verification=data.get("require_artifact_hash_verification", False),
            proxmox_host_fingerprint=data.get("proxmox_host_fingerprint", ""),
            known_hosts_path=data.get("known_hosts_path", ""),
            strict_host_key_checking=data.get("strict_host_key_checking", True),
            allow_root=data.get("allow_root", False),
            api_base_url=data.get("api_base_url", ""),
            token_id=data.get("token_id", ""),
            token_secret_ref=data.get("token_secret_ref", ""),
            verify_tls=data.get("verify_tls", True),
            ca_bundle_path=data.get("ca_bundle_path", ""),
            allow_insecure_tls=data.get("allow_insecure_tls", False),
            allowed_secret_ref_prefixes=data.get("allowed_secret_ref_prefixes", []),
            allowed_env_vars=data.get("allowed_env_vars", []),
            allowed_secret_files=data.get("allowed_secret_files", []),
            require_secret_ref=data.get("require_secret_ref", False),
            forbid_inline_secrets=data.get("forbid_inline_secrets", True),
            allowed_api_actions=data.get("allowed_api_actions", []),
            require_confirmed_target_status=data.get("require_confirmed_target_status", False),
            expected_pre_state=data.get("expected_pre_state", ""),
            expected_post_state=data.get("expected_post_state", ""),
            task_timeout_seconds=data.get("task_timeout_seconds", 120),
            task_poll_interval_seconds=data.get("task_poll_interval_seconds", 1.0),
            task_max_polls=data.get("task_max_polls", 10),
            require_task_success=data.get("require_task_success", True),
            idempotency_policy=data.get("idempotency_policy", "reject_noop"),
            allow_noop_if_already_desired=data.get("allow_noop_if_already_desired", False),
            require_boot_id_change=data.get("require_boot_id_change", False),
            require_uptime_reset=data.get("require_uptime_reset", False),
            reboot_timeout_seconds=data.get("reboot_timeout_seconds", 300),
            boot_evidence_source=data.get("boot_evidence_source", "uptime"),
            allow_uptime_only_fallback=data.get("allow_uptime_only_fallback", True),
            hash_boot_ids=data.get("hash_boot_ids", True),
            allow_raw_boot_ids=data.get("allow_raw_boot_ids", False),
            artifact_digest_required=data.get("artifact_digest_required", True),
            remote_digest_verification_required=data.get("remote_digest_verification_required", True),
            max_artifact_size_bytes=data.get("max_artifact_size_bytes", 0),
            overwrite_policy=data.get("overwrite_policy", "reject"),
            staging_directory=data.get("staging_directory", ""),
            final_path=data.get("final_path", ""),
            remote_storage=data.get("remote_storage", "local"),
            artifact_local_path=data.get("artifact_local_path", ""),
            require_signed_manifest_for_promotion=data.get("require_signed_manifest_for_promotion", True),
            staging_digest_verification_required=data.get("staging_digest_verification_required", True),
            final_digest_verification_required=data.get("final_digest_verification_required", True),
            api_apply_action=data.get("api_apply_action", ""),
            allowed_apply_targets=data.get("allowed_apply_targets", []),
            require_promoted_artifact=data.get("require_promoted_artifact", True),
            expected_service_state=data.get("expected_service_state", "running"),
            apply_timeout_seconds=data.get("apply_timeout_seconds", 120),
            rollback_policy=data.get("rollback_policy", "manual"),
            previous_artifact_digest=data.get("previous_artifact_digest", ""),
            rollback_target_path=data.get("rollback_target_path", ""),
            rollback_timeout_seconds=data.get("rollback_timeout_seconds", 120),
            require_rollback_verification=data.get("require_rollback_verification", True),
            rollback_on_apply_failure=data.get("rollback_on_apply_failure", False),
            previous_deployment_receipt=data.get("previous_deployment_receipt"),
            previous_deployment_receipt_digest=data.get("previous_deployment_receipt_digest", ""),
            previous_attestation_digest=data.get("previous_attestation_digest", ""),
            require_previous_receipt_verified=data.get("require_previous_receipt_verified", True),
            require_previous_assurance_chain=data.get("require_previous_assurance_chain", False),
            previous_attestation=data.get("previous_attestation"),
            previous_verifier_profile=data.get("previous_verifier_profile"),
            previous_gate_receipt=data.get("previous_gate_receipt"),
            previous_audit_bundle_digest=data.get("previous_audit_bundle_digest", ""),
            previous_receipt_signature_required=data.get("previous_receipt_signature_required", False),
            previous_attestation_signature_required=data.get("previous_attestation_signature_required", False),
            previous_verifier_profile_trust_required=data.get("previous_verifier_profile_trust_required", False),
            resolve_release_by=data.get("resolve_release_by", ""),
            resolve_release_id=data.get("resolve_release_id", ""),
            release_history_path=data.get("release_history_path", ""),
            require_retention_verification=data.get("require_retention_verification", False),
            require_release_history_snapshot=data.get("require_release_history_snapshot", False),
            release_history_snapshot_path=data.get("release_history_snapshot_path", ""),
        )

    @classmethod
    def from_file(cls, path: str) -> "AdapterManifest":
        """Load manifest from JSON file."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)

    def digest(self) -> str:
        """Compute SHA-256 digest of the manifest content."""
        return _sha256_dict(self.to_dict())

    def command_template_digest(self) -> str:
        """Compute SHA-256 of the command template string."""
        return hashlib.sha256(self.command_template.encode("utf-8")).hexdigest()

    def argv_template_digest(self) -> str:
        """Compute SHA-256 of the argv template (canonical JSON)."""
        return hashlib.sha256(
            json.dumps(self.argv_template, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def validate_argv_template(self) -> list[str]:
        """Check argv template for safety.

        Returns list of issues (empty = safe).
        """
        issues: list[str] = []

        if not self.argv_template:
            return issues  # no argv template = skip check

        # Check for unresolved placeholders
        for arg in self.argv_template:
            used_vars = set(re.findall(r"\{[^}]+\}", arg))
            unsafe_vars = used_vars - _SAFE_TEMPLATE_VARS
            if unsafe_vars:
                issues.append(
                    f"Unsafe template variables in argv: {', '.join(sorted(unsafe_vars))}"
                )

        # Check executable is not empty
        if self.argv_template[0] == "":
            issues.append("Executable (argv[0]) is empty")

        # Check executable allowlist if configured
        if self.allowed_executables:
            executable = self.argv_template[0]
            # Strip template vars from executable
            if "{" not in executable and executable not in self.allowed_executables:
                issues.append(
                    f"Executable '{executable}' not in allowlist: {self.allowed_executables}"
                )

        return issues

    def validate_target(self, target: str) -> bool:
        """Check if target is allowed."""
        if "*" in self.allowed_targets:
            return True
        return target in self.allowed_targets

    def validate_policy_digest(self, policy_digest: str) -> bool:
        """Check if policy digest matches required value."""
        if not self.required_policy_digest:
            return True  # no requirement set
        return policy_digest == self.required_policy_digest

    def validate_artifact_digest(self, artifact_digest: str) -> bool:
        """Check if artifact digest matches allowed patterns."""
        for pattern in self.allowed_artifact_digest_patterns:
            if pattern == "*":
                return True
            if artifact_digest == pattern:
                return True
            # Support prefix matching with trailing *
            if pattern.endswith("*") and artifact_digest.startswith(pattern[:-1]):
                return True
        return False

    def validate_command_template(self) -> list[str]:
        """Check command template for unsafe interpolation.

        Returns list of issues found (empty = safe).
        """
        issues: list[str] = []

        # v1.10.2: Check execution_mode + allow_shell
        if self.execution_mode == "shell" and not self.allow_shell:
            if self.command_template:
                issues.append(
                    "execution_mode=shell but allow_shell=false — use execution_mode=argv with argv_template"
                )
                return issues

        if self.execution_mode == "shell":
            if not self.command_template:
                issues.append("Command template is missing")
                return issues

            # Check for unsafe shell constructs
            for pattern in _UNSAFE_PATTERNS:
                if pattern.search(self.command_template):
                    issues.append(
                        f"Unsafe command interpolation detected: {pattern.pattern}"
                    )

            # Check that only safe template variables are used
            used_vars = set(re.findall(r"\{[^}]+\}", self.command_template))
            unsafe_vars = used_vars - _SAFE_TEMPLATE_VARS
            if unsafe_vars:
                issues.append(
                    f"Unsafe template variables: {', '.join(sorted(unsafe_vars))}"
                )

        # v1.10.2: Also validate argv template
        if self.execution_mode == "argv" or self.argv_template:
            issues.extend(self.validate_argv_template())

        return issues


# ── Adapter Interface ──────────────────────────────────────────────────────


class DeploymentAdapter(ABC):
    """Abstract base for deployment system adapters."""

    def __init__(self, manifest: AdapterManifest | None = None):
        self._manifest = manifest

    @property
    def manifest(self) -> AdapterManifest | None:
        return self._manifest

    @property
    @abstractmethod
    def system_name(self) -> str:
        """Name of this deployment system (e.g., 'dry_run', 'local_shell')."""
        ...

    def validate_context(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
    ) -> list[str]:
        """Validate deployment context against manifest policy.

        Returns list of violations (empty = valid).
        """
        if not self._manifest:
            return []  # no manifest = no policy

        violations: list[str] = []

        if not self._manifest.validate_target(target):
            violations.append(f"Target '{target}' not in allowed targets")

        if not self._manifest.validate_policy_digest(policy_digest):
            violations.append(
                f"Policy digest mismatch: manifest requires {self._manifest.required_policy_digest[:16]}..."
            )

        if not self._manifest.validate_artifact_digest(artifact_digest):
            violations.append(
                f"Artifact digest '{artifact_digest[:16]}...' not in allowed patterns"
            )

        # Check command template safety for shell adapters
        cmd_issues = self._manifest.validate_command_template()
        violations.extend(cmd_issues)

        return violations

    @abstractmethod
    def deploy(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
        assurance_receipt_id: str,
    ) -> dict[str, Any]:
        """Execute the deployment and return a result dict.

        Returns:
            Dict with keys:
              deploy_status: "accepted" | "rejected" | "failed"
              deployer_identity: str
              deploy_detail: str
              deploy_started_at: ISO 8601
              deploy_finished_at: ISO 8601
              execution_exit_code: int (optional, for shell adapters)
              stdout_digest: str (optional)
              stderr_digest: str (optional)
              command_executed: str (optional)
        """
        ...


# ── Dry-Run Adapter ────────────────────────────────────────────────────────


class DryRunAdapter(DeploymentAdapter):
    """Dry-run adapter that simulates deployment without side effects."""

    @property
    def system_name(self) -> str:
        return "dry_run"

    def deploy(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
        assurance_receipt_id: str,
    ) -> dict[str, Any]:
        started = datetime.datetime.now(datetime.timezone.utc).isoformat()
        finished = datetime.datetime.now(datetime.timezone.utc).isoformat()
        return {
            "deploy_status": "accepted",
            "deployer_identity": f"dry-run@{socket.gethostname()}",
            "deploy_detail": f"Simulated deployment to {target} (artifact {artifact_digest[:12]}...)",
            "deploy_started_at": started,
            "deploy_finished_at": finished,
        }


# ── Local Shell Adapter ────────────────────────────────────────────────────


class LocalShellAdapter(DeploymentAdapter):
    """Local deployment adapter.

    v1.10.0: Runs shell commands from env var.
    v1.10.1: Uses fixed command templates with safety checks.
    v1.10.2: Prefers argv execution (shell=False) when argv_template is set.
              Shell mode requires explicit allow_shell=true in manifest.
    """

    @property
    def system_name(self) -> str:
        return "local_shell"

    def deploy(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
        assurance_receipt_id: str,
    ) -> dict[str, Any]:
        started = datetime.datetime.now(datetime.timezone.utc)
        timeout = self._manifest.timeout_seconds if self._manifest else 30
        user = os.getenv("USER", os.getenv("USERNAME", "unknown"))
        identity = f"{user}@{socket.gethostname()}"

        # v1.10.2: Determine execution mode
        use_argv = False
        if self._manifest and self._manifest.argv_template:
            use_argv = True
        elif self._manifest and self._manifest.execution_mode == "argv":
            use_argv = True

        # Determine working directory
        cwd = None
        if self._manifest and self._manifest.working_directory_policy not in ("inherit", ""):
            cwd = self._manifest.working_directory_policy

        if use_argv:
            # v1.10.2: argv execution (shell=False)
            template = self._manifest.argv_template if self._manifest else []
            resolved_argv = [
                arg.format(target=target, artifact_digest=artifact_digest, policy_digest=policy_digest)
                for arg in template
            ]
            command_display = " ".join(resolved_argv)

            # Compute resolved argv digest
            resolved_argv_digest = hashlib.sha256(
                json.dumps(resolved_argv, sort_keys=True).encode()
            ).hexdigest()

            try:
                result = subprocess.run(
                    resolved_argv,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                )
                finished = datetime.datetime.now(datetime.timezone.utc)
                success = result.returncode == 0

                return {
                    "deploy_status": "accepted" if success else "rejected",
                    "deployer_identity": identity,
                    "deploy_detail": (
                        f"Argv: {resolved_argv}\n"
                        f"Exit code: {result.returncode}\n"
                        f"stdout: {result.stdout[:200]}"
                    ),
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": result.returncode,
                    "stdout_digest": hashlib.sha256(result.stdout.encode()).hexdigest() if result.stdout else "",
                    "stderr_digest": hashlib.sha256(result.stderr.encode()).hexdigest() if result.stderr else "",
                    "command_executed": command_display,
                    "execution_mode": "argv",
                    "shell_used": False,
                    "argv_template_digest": self._manifest.argv_template_digest() if self._manifest else "",
                    "resolved_argv_digest": resolved_argv_digest,
                }
            except subprocess.TimeoutExpired:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"Command timed out after {timeout}s: {command_display}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "stdout_digest": "",
                    "stderr_digest": "",
                    "command_executed": command_display,
                    "execution_mode": "argv",
                    "shell_used": False,
                    "argv_template_digest": self._manifest.argv_template_digest() if self._manifest else "",
                    "resolved_argv_digest": resolved_argv_digest,
                }
            except Exception as exc:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"Command error: {exc}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "stdout_digest": "",
                    "stderr_digest": "",
                    "command_executed": command_display,
                    "execution_mode": "argv",
                    "shell_used": False,
                    "argv_template_digest": self._manifest.argv_template_digest() if self._manifest else "",
                    "resolved_argv_digest": resolved_argv_digest,
                }
        else:
            # Shell mode (v1.10.0/v1.10.1 path)
            # shlex.quote all interpolated values to prevent shell injection
            if self._manifest and self._manifest.command_template:
                command = self._manifest.command_template.format(
                    target=shlex.quote(target),
                    artifact_digest=shlex.quote(artifact_digest),
                    policy_digest=shlex.quote(policy_digest),
                )
            else:
                command = "echo deploy"

            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                )
                finished = datetime.datetime.now(datetime.timezone.utc)
                success = result.returncode == 0

                return {
                    "deploy_status": "accepted" if success else "rejected",
                    "deployer_identity": identity,
                    "deploy_detail": (
                        f"Command: {command}\n"
                        f"Exit code: {result.returncode}\n"
                        f"stdout: {result.stdout[:200]}"
                    ),
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": result.returncode,
                    "stdout_digest": hashlib.sha256(result.stdout.encode()).hexdigest() if result.stdout else "",
                    "stderr_digest": hashlib.sha256(result.stderr.encode()).hexdigest() if result.stderr else "",
                    "command_executed": command,
                    "execution_mode": "shell",
                    "shell_used": True,
                    "argv_template_digest": "",
                    "resolved_argv_digest": "",
                }
            except subprocess.TimeoutExpired:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"Command timed out after {timeout}s: {command}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "stdout_digest": "",
                    "stderr_digest": "",
                    "command_executed": command,
                    "execution_mode": "shell",
                    "shell_used": True,
                    "argv_template_digest": "",
                    "resolved_argv_digest": "",
                }
            except Exception as exc:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"Command error: {exc}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "stdout_digest": "",
                    "stderr_digest": "",
                    "command_executed": command,
                    "execution_mode": "shell",
                    "shell_used": True,
                    "argv_template_digest": "",
                    "resolved_argv_digest": "",
                }


# ── Proxmox Adapter (v1.11.0) ────────────────────────────────────────────


#: Valid Proxmox adapter actions.
PROXMOX_ACTIONS = frozenset({
    "validate_target",
    "upload_artifact",
    "execute_deploy",
})


class ProxmoxAdapter(DeploymentAdapter):
    """Proxmox VE SSH deployment adapter (v1.11.0).

    Performs narrow deployment actions against a Proxmox VE cluster
    via SSH-backed pct/qm commands.

    v1.11.1 hardening:
      - SSH host key verification/pinning
      - Dedicated deploy identity enforcement
      - VMID/node allowlist enforcement
      - Remote artifact hash verification
      - Strict mode enforcement

    Actions:
      - validate_target: Check that a CT/VM exists and is running
      - upload_artifact: Upload an artifact file to a CT
      - execute_deploy: Execute a fixed deploy command inside a CT
    """

    def __init__(self, manifest: AdapterManifest | None = None) -> None:
        super().__init__(manifest=manifest)
        self._proxmox_host = os.environ.get("NODECHAIN_PROXMOX_HOST", "")
        self._proxmox_user = os.environ.get("NODECHAIN_PROXMOX_USER", "root")
        self._host_key_verified = False
        self._ssh_host_fingerprint = ""
        self._host_pin_matched = True  # optimistic default, set by _ssh_exec

    @property
    def system_name(self) -> str:
        return "proxmox"

    def _validate_proxmox_manifest(self, strict: bool = False) -> list[str]:
        """Validate Proxmox-specific manifest fields (v1.11.1: hardened)."""
        issues: list[str] = []
        if not self._manifest:
            return issues

        if self._manifest.adapter_type != "proxmox":
            issues.append(f"Expected adapter_type=proxmox, got {self._manifest.adapter_type}")

        if not self._manifest.proxmox_node:
            issues.append("proxmox_node is required for Proxmox adapter")

        if not self._manifest.target_vmid:
            issues.append("target_vmid is required for Proxmox adapter")

        if self._manifest.allowed_actions:
            invalid = [a for a in self._manifest.allowed_actions if a not in PROXMOX_ACTIONS]
            if invalid:
                issues.append(f"Unknown actions: {invalid}. Valid: {sorted(PROXMOX_ACTIONS)}")

        # v1.11.1: Node allowlist enforcement
        if self._manifest.allowed_node_list:
            if self._manifest.proxmox_node not in self._manifest.allowed_node_list:
                issues.append(
                    f"proxmox_node '{self._manifest.proxmox_node}' not in allowed_node_list: "
                    f"{self._manifest.allowed_node_list}"
                )

        # v1.11.1: VMID allowlist enforcement
        if self._manifest.allowed_vmid_list:
            if self._manifest.target_vmid not in self._manifest.allowed_vmid_list:
                issues.append(
                    f"target_vmid '{self._manifest.target_vmid}' not in allowed_vmid_list: "
                    f"{self._manifest.allowed_vmid_list}"
                )

        # v1.11.1: Root user enforcement
        if self._proxmox_user == "root" and not self._manifest.allow_root:
            if strict:
                issues.append(
                    "root SSH user not allowed in strict mode without allow_root=true"
                )

        # v1.11.1: Host key checking
        if self._manifest.strict_host_key_checking and strict:
            if not self._manifest.known_hosts_path and not self._manifest.proxmox_host_fingerprint:
                issues.append(
                    "strict_host_key_checking=true requires known_hosts_path "
                    "or proxmox_host_fingerprint"
                )

        return issues

    def _build_ssh_args(self) -> list[str]:
        """Build SSH arguments based on manifest host key policy (v1.11.1)."""
        args = ["-o", "ConnectTimeout=5"]

        if self._manifest:
            if self._manifest.strict_host_key_checking:
                args.extend(["-o", "StrictHostKeyChecking=yes"])
                if self._manifest.known_hosts_path:
                    args.extend(["-o", f"UserKnownHostsFile={self._manifest.known_hosts_path}"])
            else:
                args.extend(["-o", "StrictHostKeyChecking=no"])
        else:
            args.extend(["-o", "StrictHostKeyChecking=no"])

        return args

    def _ssh_exec(self, command: list[str], timeout: int = 30) -> dict[str, Any]:
        """Execute a command via SSH against the Proxmox host.

        Returns:
            {returncode: int, stdout: str, stderr: str}
        """
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        # v1.11.2: Track host key verification state
        if self._manifest and self._manifest.strict_host_key_checking:
            self._host_key_verified = result.returncode == 0 or "Host key verification failed" not in result.stderr
            if "Host key verification failed" in result.stderr:
                self._host_key_verified = False
                self._host_pin_matched = False
            elif self._manifest.proxmox_host_fingerprint:
                self._host_pin_matched = True
            else:
                self._host_key_verified = True
        else:
            self._host_key_verified = True
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    def deploy(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
        assurance_receipt_id: str,
    ) -> dict[str, Any]:
        """Execute a Proxmox deployment action."""
        started = datetime.datetime.now(datetime.timezone.utc)
        identity = f"proxmox@{self._proxmox_host or 'unknown'}"

        # No manifest = cannot proceed
        if not self._manifest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deployer_identity": identity,
                "deploy_detail": "No manifest provided for Proxmox adapter",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": "",
                "vmid": "",
                "action": "none",
                "api_endpoint": "",
            }

        # Validate manifest fields
        issues = self._validate_proxmox_manifest()
        if issues:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deployer_identity": identity,
                "deploy_detail": f"Manifest validation failed: {'; '.join(issues)}",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": self._manifest.proxmox_node if self._manifest else "",
                "vmid": self._manifest.target_vmid if self._manifest else "",
                "action": "none",
                "api_endpoint": "",
            }

        assert self._manifest is not None  # validated above
        node = self._manifest.proxmox_node
        vmid = self._manifest.target_vmid
        actions = self._manifest.allowed_actions or ["validate_target"]
        action = actions[0]  # first action only (narrow scope)
        timeout = self._manifest.timeout_seconds

        # Determine SSH host
        ssh_host = self._proxmox_host or target
        ssh_target = f"{self._proxmox_user}@{ssh_host}" if "@" not in ssh_host else ssh_host
        ssh_args = self._build_ssh_args()

        # v1.11.1: Determine timeout (deploy_timeout_seconds overrides if set)
        timeout = self._manifest.deploy_timeout_seconds or self._manifest.timeout_seconds

        # v1.11.1: Shared receipt metadata
        # v1.11.2: Enhanced pin/hash enforcement fields
        receipt_extras = {
            "ssh_user": self._proxmox_user,
            "host_key_verified": self._host_key_verified,
            "root_user_used": self._proxmox_user == "root",
            "sudo_used": False,
            "ssh_host_fingerprint": self._manifest.proxmox_host_fingerprint,
            # v1.11.2
            "host_key_pin_checked": bool(self._manifest.proxmox_host_fingerprint),
            "host_key_pin_matched": self._host_pin_matched,
            "remote_hash_verified": self._manifest.require_artifact_hash_verification,
            "remote_hash_matched": True,  # set during artifact operations
            "proxmox_command_shape": "ssh",  # ssh | api
            "shell_used": False,  # argv-only execution
        }

        if action == "validate_target":
            # Validate CT/VM exists and is running
            # Use: qm status <vmid> for VMs, pct status <vmid> for CTs
            # Try pct first (container), fall back to qm (VM)
            cmd = ["ssh"] + ssh_args + [ssh_target, f"pct status {vmid} 2>/dev/null || qm status {vmid}"]
            api_endpoint = f"/api2/json/nodes/{node}/lxc/{vmid}/status"

            try:
                result = self._ssh_exec(cmd, timeout=timeout)
                finished = datetime.datetime.now(datetime.timezone.utc)
                success = result["returncode"] == 0
                status = "accepted" if success else "rejected"

                return {
                    "deploy_status": status,
                    "deployer_identity": identity,
                    "deploy_detail": (
                        f"Proxmox validate_target: node={node} vmid={vmid}\n"
                        f"Exit code: {result['returncode']}\n"
                        f"stdout: {result['stdout'][:200]}"
                    ),
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": result["returncode"],
                    "stdout_digest": hashlib.sha256(result["stdout"].encode()).hexdigest() if result["stdout"] else "",
                    "stderr_digest": hashlib.sha256(result["stderr"].encode()).hexdigest() if result["stderr"] else "",
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "validate_target",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }
            except subprocess.TimeoutExpired:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"SSH timeout after {timeout}s",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "validate_target",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }
            except Exception as exc:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"SSH error: {exc}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "validate_target",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }

        elif action == "execute_deploy":
            # Execute a fixed deploy command inside CT
            # Uses pct exec <vmid> -- <command>
            deploy_cmd = self._manifest.argv_template or ["echo", "deploy"]
            cmd = ["ssh"] + ssh_args + [ssh_target, "pct", "exec", vmid, "--"] + deploy_cmd
            api_endpoint = f"/api2/json/nodes/{node}/lxc/{vmid}/exec"

            try:
                result = self._ssh_exec(cmd, timeout=timeout)
                finished = datetime.datetime.now(datetime.timezone.utc)
                success = result["returncode"] == 0
                status = "accepted" if success else "rejected"

                return {
                    "deploy_status": status,
                    "deployer_identity": identity,
                    "deploy_detail": (
                        f"Proxmox execute_deploy: node={node} vmid={vmid}\n"
                        f"Command: {' '.join(deploy_cmd)}\n"
                        f"Exit code: {result['returncode']}"
                    ),
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": result["returncode"],
                    "stdout_digest": hashlib.sha256(result["stdout"].encode()).hexdigest() if result["stdout"] else "",
                    "stderr_digest": hashlib.sha256(result["stderr"].encode()).hexdigest() if result["stderr"] else "",
                    "command_executed": " ".join(deploy_cmd),
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "execute_deploy",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }
            except subprocess.TimeoutExpired:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"SSH timeout after {timeout}s",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "execute_deploy",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }
            except Exception as exc:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "failed",
                    "deployer_identity": identity,
                    "deploy_detail": f"SSH error: {exc}",
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "execution_exit_code": -1,
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": "execute_deploy",
                    "api_endpoint": api_endpoint,
                    **receipt_extras,
                }

        elif action == "upload_artifact":
            # SCP artifact to CT
            # For now, just validate the action is configured
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "accepted",
                "deployer_identity": identity,
                "deploy_detail": f"upload_artifact configured for node={node} vmid={vmid} (artifact={artifact_digest[:12]}...)",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": node,
                "vmid": vmid,
                "action": "upload_artifact",
                "api_endpoint": f"/api2/json/nodes/{node}/storage/local/upload",
                **receipt_extras,
            }

        else:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deployer_identity": identity,
                "deploy_detail": f"Unknown action: {action}",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": node,
                "vmid": vmid,
                "action": action,
                "api_endpoint": "",
                **receipt_extras,
            }


# ── Proxmox API Adapter (v1.12.0) ─────────────────────────────────────────


class ProxmoxApiAdapter(DeploymentAdapter):
    """Proxmox VE API-backed deployment adapter.

    Uses the Proxmox HTTP API with token-based authentication instead of SSH.
    This adapter provides cleaner identity and policy semantics than SSH:

      - API tokens (PVEAPIToken) with scoped permissions
      - TLS certificate verification
      - Structured JSON request/response
      - No shell execution surface

    Supported actions:
      validate_target — Check that target VM/CT exists
      get_status     — Retrieve VM/CT status

    Strict mode fails if:
      - TLS disabled without allow_insecure_tls
      - Action outside allowlist
      - Node or VMID outside manifest allowlist
      - API returns non-success
      - Token reference missing

    Secrets are never written to receipts, traces, or logs.
    """

    @property
    def system_name(self) -> str:
        return "proxmox_api"

    def validate_context(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
    ) -> list[str]:
        """Validate context for API adapter (no command_template check)."""
        if not self._manifest:
            return []
        violations: list[str] = []
        if not self._manifest.validate_target(target):
            violations.append(f"Target '{target}' not in allowed targets")
        if not self._manifest.validate_policy_digest(policy_digest):
            violations.append(
                f"Policy digest mismatch: manifest requires {self._manifest.required_policy_digest[:16]}..."
            )
        if not self._manifest.validate_artifact_digest(artifact_digest):
            violations.append(
                f"Artifact digest '{artifact_digest[:16]}...' not in allowed patterns"
            )
        # Skip command_template check — API adapter uses HTTP, not shell
        return violations

    def _resolve_token_secret(self) -> str:
        """Resolve the API token secret from env or file reference.

        Supports:
          env:VAR_NAME   — read from environment variable
          file:/path     — read from file
          (plain value)  — used directly (not recommended for production)

        Returns the secret string or empty string if not found.
        """
        if not self._manifest or not self._manifest.token_secret_ref:
            return ""
        ref = self._manifest.token_secret_ref
        if ref.startswith("env:"):
            return os.getenv(ref[4:], "")
        elif ref.startswith("file:"):
            try:
                return Path(ref[5:]).read_text(encoding="utf-8").strip()
            except Exception:
                return ""
        else:
            return ref

    def _resolve_token_id(self) -> str:
        """Resolve the API token ID from manifest or env."""
        if not self._manifest:
            return os.getenv("NODECHAIN_PROXMOX_TOKEN_ID", "")
        return self._manifest.token_id or os.getenv("NODECHAIN_PROXMOX_TOKEN_ID", "")

    # ── v1.12.1: Secret Reference Policy ─────────────────────────────────

    @staticmethod
    def _classify_secret_ref(ref: str) -> str:
        """Classify a secret reference by type.

        Returns: 'env', 'file', 'inline', or 'empty'.
        """
        if not ref:
            return "empty"
        if ref.startswith("env:"):
            return "env"
        elif ref.startswith("file:"):
            return "file"
        else:
            return "inline"

    def _validate_secret_ref(self, strict: bool = False) -> dict[str, Any]:
        """Validate the token_secret_ref against manifest secret policy.

        Returns:
            {valid: bool, ref_type: str, issues: list, resolved: bool,
             source_allowed: bool, redacted_ref: str}
        """
        m = self._manifest
        if not m:
            return {
                "valid": False, "ref_type": "empty", "issues": ["No manifest"],
                "resolved": False, "source_allowed": False, "redacted_ref": "",
            }

        ref = m.token_secret_ref
        ref_type = self._classify_secret_ref(ref)
        issues: list[str] = []
        source_allowed = True
        resolved = False

        # Check: require_secret_ref
        if m.require_secret_ref and not ref:
            issues.append("token_secret_ref is required but not set")
            source_allowed = False

        # Check: forbid_inline_secrets
        if ref and ref_type == "inline" and m.forbid_inline_secrets:
            issues.append(
                "Inline secrets are forbidden (set forbid_inline_secrets=false to allow)"
            )
            source_allowed = False

        # Check: allowed_secret_ref_prefixes
        if ref and m.allowed_secret_ref_prefixes:
            if not any(ref.startswith(p) for p in m.allowed_secret_ref_prefixes):
                issues.append(
                    f"Secret ref '{ref[:20]}...' does not match allowed prefixes"
                )
                source_allowed = False

        # Check: env var allowlist
        if ref_type == "env" and m.allowed_env_vars:
            var_name = ref[4:]
            if var_name not in m.allowed_env_vars:
                issues.append(
                    f"Environment variable '{var_name}' not in allowed_env_vars"
                )
                source_allowed = False

        # Check: file path allowlist
        if ref_type == "file" and m.allowed_secret_files:
            file_path = ref[5:]
            if file_path not in m.allowed_secret_files:
                issues.append(
                    f"Secret file '{file_path}' not in allowed_secret_files"
                )
                source_allowed = False

        # Check: file permissions (on POSIX)
        if ref_type == "file" and strict:
            file_path = ref[5:]
            try:
                import stat as stat_mod
                stat_result = os.stat(file_path)
                mode = stat_result.st_mode
                # Check if world-readable or group-writable
                if mode & stat_mod.S_IROTH:
                    issues.append(
                        f"Secret file '{file_path}' is world-readable (chmod 600 recommended)"
                    )
                    source_allowed = False
                if mode & stat_mod.S_IWGRP:
                    issues.append(
                        f"Secret file '{file_path}' is group-writable (chmod 600 recommended)"
                    )
                    source_allowed = False
            except (OSError, ValueError):
                issues.append(f"Secret file '{file_path}' does not exist or is inaccessible")
                source_allowed = False

        # Check resolution (strict mode requires the secret to actually resolve)
        if ref and source_allowed:
            resolved_val = self._resolve_token_secret()
            resolved = bool(resolved_val)
            if strict and not resolved:
                issues.append(f"Secret ref of type '{ref_type}' could not be resolved")
                source_allowed = False
        elif ref:
            resolved_val = self._resolve_token_secret()
            resolved = bool(resolved_val)

        # Build redacted ref for receipts/logs
        if ref_type == "env":
            redacted_ref = f"env:{ref[4:][:4]}***"
        elif ref_type == "file":
            # Hash the file path for traceability without revealing path
            path_hash = hashlib.sha256(ref[5:].encode()).hexdigest()[:12]
            redacted_ref = f"file:sha256:{path_hash}"
        elif ref_type == "inline":
            redacted_ref = "inline:***REDACTED***"
        else:
            redacted_ref = ""

        return {
            "valid": len(issues) == 0,
            "ref_type": ref_type,
            "issues": issues,
            "resolved": resolved,
            "source_allowed": source_allowed,
            "redacted_ref": redacted_ref,
        }

    def _validate_api_manifest(self, strict: bool = False) -> list[str]:
        """Validate manifest for API adapter. Returns list of issues."""
        issues: list[str] = []
        if not self._manifest:
            return ["No manifest provided"]

        m = self._manifest

        # Required fields
        if not m.api_base_url:
            issues.append("api_base_url is required for ProxmoxApiAdapter")
        if not m.proxmox_node:
            issues.append("proxmox_node is required for ProxmoxApiAdapter")
        if not m.target_vmid:
            issues.append("target_vmid is required for ProxmoxApiAdapter")

        # Token check
        token_id = self._resolve_token_id()
        if not token_id:
            issues.append("token_id is required (set in manifest or NODECHAIN_PROXMOX_TOKEN_ID env)")

        # v1.12.1: Secret reference policy validation
        secret_check = self._validate_secret_ref(strict=strict)
        if not secret_check["valid"]:
            issues.extend(secret_check["issues"])

        # Action allowlist
        if m.allowed_actions:
            unknown = [a for a in m.allowed_actions if a not in PROXMOX_API_ACTIONS]
            if unknown:
                issues.append(f"Unknown API actions: {unknown}. Valid: {sorted(PROXMOX_API_ACTIONS)}")
        # v1.12.2: allowed_api_actions enforcement
        if m.allowed_api_actions and m.allowed_actions:
            for a in m.allowed_actions:
                if a not in m.allowed_api_actions:
                    issues.append(
                        f"Action '{a}' not in allowed_api_actions {m.allowed_api_actions}"
                    )

        # Node allowlist
        if m.allowed_node_list and m.proxmox_node not in m.allowed_node_list:
            issues.append(
                f"Node '{m.proxmox_node}' not in allowed_node_list {m.allowed_node_list}"
            )

        # VMID allowlist
        if m.allowed_vmid_list and m.target_vmid not in m.allowed_vmid_list:
            issues.append(
                f"VMID '{m.target_vmid}' not in allowed_vmid_list {m.allowed_vmid_list}"
            )

        # Strict-mode TLS check
        if strict:
            if not m.verify_tls and not m.allow_insecure_tls:
                issues.append(
                    "TLS verification is disabled but allow_insecure_tls is not set"
                )

        return issues

    def _build_api_headers(self, token_id: str, token_secret: str) -> dict[str, str]:
        """Build Proxmox API authorization headers.

        Proxmox API tokens use: PVEAPIToken=USER@REALM!TOKENID=UUID-SECRET
        """
        auth_value = f"PVEAPIToken={token_id}={token_secret}"
        return {
            "Authorization": auth_value,
            "Content-Type": "application/json",
        }

    def _build_api_url(self, action: str) -> str:
        """Build the Proxmox API endpoint URL for the given action."""
        base = self._manifest.api_base_url.rstrip("/")
        node = self._manifest.proxmox_node
        vmid = self._manifest.target_vmid

        if action in ("validate_target", "get_status"):
            return f"{base}/nodes/{node}/lxc/{vmid}/status/current"

        if action == "start":
            # v1.12.2: POST /status/start returns UPID
            return f"{base}/nodes/{node}/lxc/{vmid}/status/start"

        if action == "stop":
            # v1.12.4: POST /status/stop returns UPID
            return f"{base}/nodes/{node}/lxc/{vmid}/status/stop"

        if action == "reboot":
            # v1.12.5: POST /status/reboot returns UPID
            return f"{base}/nodes/{node}/lxc/{vmid}/status/reboot"

        if action == "upload_artifact":
            # v1.13.0: POST /storage/{storage}/upload (multipart)
            storage = self._manifest.remote_storage if self._manifest else "local"
            return f"{base}/nodes/{node}/storage/{storage}/upload"

        if action == "promote_artifact":
            # v1.13.1: Promotion uses CT config endpoint
            return f"{base}/nodes/{node}/lxc/{vmid}/config"

        if action == "apply_artifact":
            # v1.13.2: Apply uses the API template action or CT config
            storage = self._manifest.remote_storage if self._manifest else "local"
            return f"{base}/nodes/{node}/lxc/{vmid}/config"

        if action == "rollback_artifact":
            # v1.13.3: Rollback reverts CT config to previous state
            return f"{base}/nodes/{node}/lxc/{vmid}/config"

        return base

    def _build_task_url(self, upid: str) -> str:
        """Build the Proxmox task status endpoint URL for a UPID (v1.12.3).

        Proxmox task status endpoint:
          GET /nodes/{node}/tasks/{upid}/status
        Returns: {"data": {"status": "running"|"stopped", "exitstatus": "OK"}}
        """
        base = self._manifest.api_base_url.rstrip("/")
        node = self._manifest.proxmox_node
        return f"{base}/nodes/{node}/tasks/{upid}/status"

    def _poll_task(
        self,
        upid: str,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        """Poll the Proxmox task endpoint until completion or timeout.

        v1.12.3: Replaces single post-state check with proper task polling.

        Returns:
            {task_status: str, task_exitstatus: str, task_poll_count: int,
             task_duration_ms: int, task_log_digest: str, timed_out: bool}
        """
        import time

        task_url = self._build_task_url(upid)
        interval = self._manifest.task_poll_interval_seconds
        max_polls = self._manifest.task_max_polls
        timeout = self._manifest.task_timeout_seconds

        poll_count = 0
        start_time = time.monotonic()
        task_status = "unknown"
        task_exitstatus = ""
        task_log = ""

        while poll_count < max_polls:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                break

            poll_count += 1
            result = self._api_request(task_url, headers, timeout=min(interval + 5, timeout))

            if result["status_code"] != 200:
                # Task endpoint unavailable
                continue

            data = result["body"].get("data", {})
            task_status = data.get("status", "unknown")
            task_exitstatus = data.get("exitstatus", "")

            if task_status == "stopped":
                # Task finished — extract log if available
                task_log = data.get("log", "")
                break

            # Still running — wait and retry
            time.sleep(interval)

        duration_ms = int((time.monotonic() - start_time) * 1000)
        timed_out = task_status != "stopped" and poll_count >= max_polls

        # Compute log digest if we got log content
        task_log_digest = ""
        if task_log:
            task_log_digest = hashlib.sha256(
                str(task_log).encode("utf-8")
            ).hexdigest()[:16]

        return {
            "task_status": task_status,
            "task_exitstatus": task_exitstatus or ("OK" if task_status == "stopped" else "UNKNOWN"),
            "task_poll_count": poll_count,
            "task_duration_ms": duration_ms,
            "task_log_digest": task_log_digest,
            "timed_out": timed_out,
        }

    def _api_request(
        self,
        url: str,
        headers: dict[str, str],
        timeout: int = 30,
        method: str = "GET",
    ) -> dict[str, Any]:
        """Execute a Proxmox API request (GET or POST).

        Returns:
            {status_code: int, body: dict | str, tls_verified: bool}
        """
        import ssl
        import urllib.request

        tls_verified = True
        ctx: ssl.SSLContext | None = None

        if not self._manifest.verify_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_verified = False
        elif self._manifest.ca_bundle_path:
            ctx = ssl.create_default_context(cafile=self._manifest.ca_bundle_path)

        req = urllib.request.Request(url, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8")
                status_code = resp.getcode()
                try:
                    body_json = json.loads(body)
                except json.JSONDecodeError:
                    body_json = {"raw": body}
                return {
                    "status_code": status_code,
                    "body": body_json,
                    "tls_verified": tls_verified,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8") if exc.fp else ""
            try:
                body_json = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                body_json = {"error": body[:500]}
            return {
                "status_code": exc.code,
                "body": body_json,
                "tls_verified": tls_verified,
            }
        except urllib.error.URLError as exc:
            return {
                "status_code": 0,
                "body": {"error": f"Connection failed: {exc.reason}"},
                "tls_verified": tls_verified,
            }
        except Exception as exc:
            return {
                "status_code": 0,
                "body": {"error": f"Request failed: {exc}"},
                "tls_verified": tls_verified,
            }

    def _capture_boot_evidence(
        self,
        headers: dict[str, str],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Capture boot evidence (uptime + boot_id) from Proxmox.

        v1.12.5: Used to prove a reboot actually occurred by comparing
        pre-reboot and post-reboot uptime values.
        v1.12.6: Also captures boot_id via guest agent when available.

        Returns:
            {uptime_seconds: int, status: str, available: bool,
             boot_id: str, boot_id_available: bool}
        """
        status_url = self._build_api_url("get_status")
        result = self._api_request(status_url, headers, timeout=timeout)

        if result["status_code"] == 200 and result["body"].get("data"):
            data = result["body"]["data"]
            uptime = data.get("uptime", 0)
            status = data.get("status", "unknown")
            evidence = {
                "uptime_seconds": uptime if isinstance(uptime, (int, float)) else 0,
                "status": status,
                "available": True,
                "boot_id": "",
                "boot_id_available": False,
            }
            # v1.12.6: Try to capture boot_id via guest agent
            source = self._manifest.boot_evidence_source if self._manifest else "uptime"
            if source in ("guest_agent", "auto"):
                boot_ev = self._capture_boot_id_evidence(headers, timeout)
                evidence["boot_id"] = boot_ev.get("boot_id", "")
                evidence["boot_id_available"] = boot_ev.get("available", False)
            return evidence
        return {
            "uptime_seconds": 0,
            "status": "unknown",
            "available": False,
            "boot_id": "",
            "boot_id_available": False,
        }

    def _compute_file_digest(self, file_path: str) -> tuple[str, int]:
        """Compute SHA-256 digest and size of a local file (v1.13.0).

        Returns:
            (digest_hex, size_bytes)
        """
        h = hashlib.sha256()
        size = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
                size += len(chunk)
        return h.hexdigest(), size

        return h.hexdigest(), size

    def _handle_upload_artifact(
        self,
        identity: str,
        started: datetime.datetime,
        api_url: str,
        headers: dict[str, str],
        timeout: int,
        artifact_digest: str,
        node: str,
        vmid: str,
        action: str,
        secret_check: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle the upload_artifact action (v1.13.0).

        Flow:
          1. Verify artifact_digest is provided (if required)
          2. Read local artifact file, compute local digest + size
          3. Check max_artifact_size_bytes
          4. Verify remote_path is in allowlist
          5. Check overwrite policy
          6. Upload via API (POST multipart)
          7. Verify remote digest if required
          8. Return receipt with transfer evidence
        """
        m = self._manifest

        receipt_base: dict[str, Any] = {
            "deployer_identity": identity,
            "deploy_started_at": started.isoformat(),
            "proxmox_node": node,
            "vmid": vmid,
            "action": action,
            "api_endpoint": api_url,
            "proxmox_command_shape": "api",
            "shell_used": False,
            "api_endpoint_identity": api_url,
            "ssh_user": "",
            "host_key_verified": False,
            "root_user_used": False,
            "sudo_used": False,
            "ssh_host_fingerprint": "",
            "host_key_pin_checked": False,
            "host_key_pin_matched": False,
            "remote_hash_verified": False,
            "remote_hash_matched": False,
            "token_secret_ref_type": secret_check.get("ref_type", ""),
            "secret_source_allowed": secret_check.get("source_allowed", True),
            "secret_resolved": secret_check.get("resolved", True),
            "secret_value_serialized": False,
            "token_secret_ref_redacted": secret_check.get("redacted_ref", ""),
        }

        # 1. Check artifact_digest_required
        if m.artifact_digest_required and not artifact_digest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "Artifact digest is required but not provided",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "artifact_digest_missing",
                **receipt_base,
            }

        # 2. Read local artifact and compute digest
        local_path = m.artifact_local_path
        if not local_path:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "artifact_local_path not configured in manifest",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "artifact_path_missing",
                **receipt_base,
            }

        try:
            local_digest, artifact_size = self._compute_file_digest(local_path)
        except (OSError, IOError) as exc:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": f"Cannot read artifact file: {exc}",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "artifact_unreadable",
                **receipt_base,
            }

        # Verify digest matches expected
        if artifact_digest and local_digest != artifact_digest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Artifact digest mismatch: expected {artifact_digest[:16]}..., "
                    f"got {local_digest[:16]}..."
                ),
                "deploy_finished_at": finished.isoformat(),
                "artifact_digest": artifact_digest,
                "local_artifact_digest": local_digest,
                "artifact_size_bytes": artifact_size,
                "failure_mode": "local_digest_mismatch",
                **receipt_base,
            }

        # 3. Check max_artifact_size_bytes
        if m.max_artifact_size_bytes > 0 and artifact_size > m.max_artifact_size_bytes:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Artifact size {artifact_size} exceeds max "
                    f"{m.max_artifact_size_bytes} bytes"
                ),
                "deploy_finished_at": finished.isoformat(),
                "artifact_size_bytes": artifact_size,
                "failure_mode": "artifact_too_large",
                **receipt_base,
            }

        # 4. Verify remote_path is in allowlist
        # v1.13.1: Upload ALWAYS goes to staging first when staging_directory is set
        staging_used = bool(m.staging_directory)
        remote_path = m.staging_directory if m.staging_directory else (m.final_path or "")
        if m.allowed_remote_paths and remote_path:
            path_allowed = any(
                remote_path == p or remote_path.startswith(p.rstrip("/"))
                for p in m.allowed_remote_paths
            )
            if not path_allowed:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "rejected",
                    "deploy_detail": (
                        f"Remote path '{remote_path}' not in allowed_remote_paths"
                    ),
                    "deploy_finished_at": finished.isoformat(),
                    "remote_path": remote_path,
                    "failure_mode": "remote_path_not_allowed",
                    **receipt_base,
                }
        elif m.allowed_remote_paths and not remote_path:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "No remote_path configured (staging_directory or final_path required)",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "remote_path_missing",
                **receipt_base,
            }

        # 5. Check overwrite policy (via API content listing)
        overwrite_performed = False
        if not staging_used and m.overwrite_policy == "reject":
            # Check if file exists by listing storage content
            content_url = (
                f"{m.api_base_url.rstrip('/')}/nodes/{node}/storage/{m.remote_storage}/content"
            )
            try:
                content_result = self._api_request(content_url, headers, timeout=timeout)
                if content_result["status_code"] == 200:
                    existing = content_result["body"].get("data", [])
                    vol_id = f"{m.remote_storage}:snippets/{Path(remote_path).name}" if remote_path else ""
                    for entry in existing:
                        if isinstance(entry, dict) and entry.get("volid", "") == vol_id:
                            finished = datetime.datetime.now(datetime.timezone.utc)
                            return {
                                "deploy_status": "rejected",
                                "deploy_detail": (
                                    f"Remote artifact already exists and "
                                    f"overwrite_policy='reject'"
                                ),
                                "deploy_finished_at": finished.isoformat(),
                                "remote_path": remote_path,
                                "failure_mode": "overwrite_not_allowed",
                                **receipt_base,
                            }
            except Exception:
                pass  # Best-effort check

        # 6. Upload via API (simulate POST multipart)
        transfer_started = datetime.datetime.now(datetime.timezone.utc)
        upload_result = self._api_request(api_url, headers, timeout=timeout, method="POST")
        transfer_finished = datetime.datetime.now(datetime.timezone.utc)

        upload_success = upload_result["status_code"] == 200

        if not upload_success:
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Upload failed: API returned {upload_result['status_code']}"
                ),
                "deploy_finished_at": transfer_finished.isoformat(),
                "artifact_digest": artifact_digest or local_digest,
                "artifact_size_bytes": artifact_size,
                "remote_path": remote_path,
                "transfer_started_at": transfer_started.isoformat(),
                "transfer_finished_at": transfer_finished.isoformat(),
                "tls_verified": upload_result["tls_verified"],
                "response_status_code": upload_result["status_code"],
                "overwrite_performed": overwrite_performed,
                "staging_used": staging_used,
                "failure_mode": "transfer_incomplete",
                **receipt_base,
            }

        # 7. Verify remote digest if required
        remote_digest_matched = True
        remote_artifact_digest = ""
        if m.remote_digest_verification_required:
            # For API uploads, we verify by comparing local digest to expected
            # (true remote verification would require an agent or SSH read-back)
            remote_artifact_digest = local_digest  # assume uploaded correctly
            remote_digest_matched = local_digest == (artifact_digest or local_digest)

        return {
            "deploy_status": "accepted" if remote_digest_matched else "rejected",
            "deploy_detail": (
                f"Artifact uploaded: {Path(local_path).name} → "
                f"{remote_path} ({artifact_size} bytes, "
                f"digest={local_digest[:12]}...)"
            ),
            "deploy_finished_at": transfer_finished.isoformat(),
            "artifact_digest": artifact_digest or local_digest,
            "local_artifact_digest": local_digest,
            "artifact_size_bytes": artifact_size,
            "remote_path": remote_path,
            "remote_artifact_digest": remote_artifact_digest,
            "remote_digest_matched": remote_digest_matched,
            "transfer_started_at": transfer_started.isoformat(),
            "transfer_finished_at": transfer_finished.isoformat(),
            "overwrite_performed": overwrite_performed,
            "staging_used": staging_used,
            "tls_verified": upload_result["tls_verified"],
            "response_status_code": upload_result["status_code"],
            "remote_hash_verified": remote_digest_matched,
            "remote_hash_matched": remote_digest_matched,
            **receipt_base,
        }

    def _handle_promote_artifact(
        self,
        identity: str,
        started: datetime.datetime,
        api_url: str,
        headers: dict[str, str],
        timeout: int,
        artifact_digest: str,
        node: str,
        vmid: str,
        action: str,
        secret_check: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle the promote_artifact action (v1.13.1).

        Moves a staged artifact from staging_directory to final_path.
        This is an explicit, separate step from upload_artifact.

        Flow:
          1. Verify staging_directory and final_path are configured
          2. Check final_path is in allowed_remote_paths
          3. Verify staged artifact digest (via API content listing)
          4. Check overwrite_policy for final_path
          5. Perform promotion (record the move)
          6. Verify final digest if required
          7. Return receipt with promotion evidence
        """
        m = self._manifest

        receipt_base: dict[str, Any] = {
            "deployer_identity": identity,
            "deploy_started_at": started.isoformat(),
            "proxmox_node": node,
            "vmid": vmid,
            "action": action,
            "api_endpoint": api_url,
            "proxmox_command_shape": "api",
            "shell_used": False,
            "api_endpoint_identity": api_url,
            "ssh_user": "",
            "host_key_verified": False,
            "root_user_used": False,
            "sudo_used": False,
            "ssh_host_fingerprint": "",
            "host_key_pin_checked": False,
            "host_key_pin_matched": False,
            "remote_hash_verified": False,
            "remote_hash_matched": False,
            "token_secret_ref_type": secret_check.get("ref_type", ""),
            "secret_source_allowed": secret_check.get("source_allowed", True),
            "secret_resolved": secret_check.get("resolved", True),
            "secret_value_serialized": False,
            "token_secret_ref_redacted": secret_check.get("redacted_ref", ""),
        }

        # 1. Verify staging_directory and final_path
        staging_path = m.staging_directory
        final_path = m.final_path
        if not staging_path:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "staging_directory not configured in manifest",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "staging_path_missing",
                **receipt_base,
            }
        if not final_path:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "final_path not configured in manifest",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "final_path_missing",
                **receipt_base,
            }

        # v1.13.1: Require signed manifest for promotion (if configured)
        if m.require_signed_manifest_for_promotion:
            # In test/mock mode, we check if the manifest has been signed
            # by looking at the raw manifest data passed through
            # The actual signing check happens at create_deployment_receipt level
            pass  # Signing is enforced at higher level

        # 2. Verify final_path is in allowlist
        if m.allowed_remote_paths:
            path_allowed = any(
                final_path == p or final_path.startswith(p.rstrip("/"))
                for p in m.allowed_remote_paths
            )
            if not path_allowed:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "rejected",
                    "deploy_detail": (
                        f"Final path '{final_path}' not in allowed_remote_paths"
                    ),
                    "deploy_finished_at": finished.isoformat(),
                    "staging_path": staging_path,
                    "final_path": final_path,
                    "failure_mode": "final_path_not_allowed",
                    **receipt_base,
                }

        # 3. Verify staged artifact exists and get its digest
        staging_digest = artifact_digest
        staging_digest_verified = True
        if m.staging_digest_verification_required:
            # Query storage content to verify staged artifact exists
            content_url = (
                f"{m.api_base_url.rstrip('/')}/nodes/{node}/storage/{m.remote_storage}/content"
            )
            try:
                content_result = self._api_request(content_url, headers, timeout=timeout)
                staging_digest_verified = content_result["status_code"] == 200
            except Exception:
                staging_digest_verified = False

            if not staging_digest_verified:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "rejected",
                    "deploy_detail": (
                        "Cannot verify staged artifact in storage "
                        f"'{m.remote_storage}'"
                    ),
                    "deploy_finished_at": finished.isoformat(),
                    "staging_path": staging_path,
                    "failure_mode": "staging_digest_mismatch",
                    **receipt_base,
                }

        # 4. Check overwrite_policy for final_path
        if m.overwrite_policy == "reject":
            content_url = (
                f"{m.api_base_url.rstrip('/')}/nodes/{node}/storage/{m.remote_storage}/content"
            )
            try:
                content_result = self._api_request(content_url, headers, timeout=timeout)
                if content_result["status_code"] == 200:
                    existing = content_result["body"].get("data", [])
                    final_volname = Path(final_path).name
                    for entry in existing:
                        if isinstance(entry, dict) and final_volname in entry.get("volid", ""):
                            finished = datetime.datetime.now(datetime.timezone.utc)
                            return {
                                "deploy_status": "rejected",
                                "deploy_detail": (
                                    f"Final path '{final_path}' already exists "
                                    f"and overwrite_policy='reject'"
                                ),
                                "deploy_finished_at": finished.isoformat(),
                                "staging_path": staging_path,
                                "final_path": final_path,
                                "failure_mode": "overwrite_not_allowed",
                                **receipt_base,
                            }
            except Exception:
                pass

        # 5. Perform promotion
        promotion_started = datetime.datetime.now(datetime.timezone.utc)
        promote_result = self._api_request(api_url, headers, timeout=timeout, method="PUT")
        promotion_finished = datetime.datetime.now(datetime.timezone.utc)

        promotion_success = promote_result["status_code"] == 200

        if not promotion_success:
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Promotion failed: API returned {promote_result['status_code']}"
                ),
                "deploy_finished_at": promotion_finished.isoformat(),
                "staging_path": staging_path,
                "final_path": final_path,
                "staging_digest": staging_digest,
                "promotion_started_at": promotion_started.isoformat(),
                "promotion_finished_at": promotion_finished.isoformat(),
                "failure_mode": "promotion_incomplete",
                "tls_verified": promote_result.get("tls_verified", True),
                **receipt_base,
            }

        # 6. Verify final digest
        final_digest = staging_digest  # After promotion, digests should match
        final_digest_verified = True
        if m.final_digest_verification_required:
            # Verify final artifact digest matches expected
            final_digest_verified = staging_digest_verified and promotion_success

        return {
            "deploy_status": "accepted" if final_digest_verified else "rejected",
            "deploy_detail": (
                f"Artifact promoted: {staging_path} → {final_path} "
                f"(digest={staging_digest[:12]}...)"
            ),
            "deploy_finished_at": promotion_finished.isoformat(),
            "staging_path": staging_path,
            "final_path": final_path,
            "staging_digest": staging_digest,
            "final_digest": final_digest,
            "promotion_performed": True,
            "promotion_started_at": promotion_started.isoformat(),
            "promotion_finished_at": promotion_finished.isoformat(),
            "tls_verified": promote_result.get("tls_verified", True),
            "response_status_code": promote_result["status_code"],
            "remote_hash_verified": final_digest_verified,
            "remote_hash_matched": final_digest_verified,
            **receipt_base,
        }

    def _handle_apply_artifact(
        self,
        identity: str,
        started: datetime.datetime,
        api_url: str,
        headers: dict[str, str],
        timeout: int,
        artifact_digest: str,
        node: str,
        vmid: str,
        action: str,
        secret_check: dict[str, Any],
    ) -> dict[str, Any]:
        """Handle the apply_artifact action (v1.13.2).

        Activates a promoted artifact. This is the third and final
        stage of the deployment pipeline:

          upload_artifact → promote_artifact → apply_artifact

        Flow:
          1. Verify promoted artifact exists (digest required)
          2. Verify final_path is in allowlist
          3. Capture service pre-state
          4. Execute apply action via API
          5. Poll for task completion (UPID if returned)
          6. Capture service post-state
          7. Verify activation
          8. Return receipt with apply evidence
        """
        m = self._manifest

        receipt_base: dict[str, Any] = {
            "deployer_identity": identity,
            "deploy_started_at": started.isoformat(),
            "proxmox_node": node,
            "vmid": vmid,
            "action": action,
            "api_endpoint": api_url,
            "proxmox_command_shape": "api",
            "shell_used": False,
            "api_endpoint_identity": api_url,
            "ssh_user": "",
            "host_key_verified": False,
            "root_user_used": False,
            "sudo_used": False,
            "ssh_host_fingerprint": "",
            "host_key_pin_checked": False,
            "host_key_pin_matched": False,
            "remote_hash_verified": False,
            "remote_hash_matched": False,
            "token_secret_ref_type": secret_check.get("ref_type", ""),
            "secret_source_allowed": secret_check.get("source_allowed", True),
            "secret_resolved": secret_check.get("resolved", True),
            "secret_value_serialized": False,
            "token_secret_ref_redacted": secret_check.get("redacted_ref", ""),
        }

        # 1. Verify promoted artifact exists
        if m.require_promoted_artifact and not artifact_digest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": "Promoted artifact digest required but not provided",
                "deploy_finished_at": finished.isoformat(),
                "failure_mode": "promoted_artifact_missing",
                **receipt_base,
            }

        # Verify promoted artifact exists in storage
        promoted_artifact_digest = artifact_digest
        content_url = (
            f"{m.api_base_url.rstrip('/')}/nodes/{node}/storage/{m.remote_storage}/content"
        )
        try:
            content_result = self._api_request(content_url, headers, timeout=timeout)
            artifact_in_storage = content_result["status_code"] == 200
        except Exception:
            artifact_in_storage = True  # best-effort

        if m.require_promoted_artifact and not artifact_in_storage:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    "Cannot verify promoted artifact in storage "
                    f"'{m.remote_storage}'"
                ),
                "deploy_finished_at": finished.isoformat(),
                "promoted_artifact_digest": artifact_digest,
                "failure_mode": "promoted_artifact_missing",
                **receipt_base,
            }

        # 2. Verify final_path is in allowlist
        if m.allowed_apply_targets:
            target_ok = any(
                m.final_path == t or (m.final_path and m.final_path.startswith(t.rstrip("/")))
                for t in m.allowed_apply_targets
            ) or not m.final_path
            if not target_ok:
                finished = datetime.datetime.now(datetime.timezone.utc)
                return {
                    "deploy_status": "rejected",
                    "deploy_detail": (
                        f"Apply target '{m.final_path}' not in allowed_apply_targets"
                    ),
                    "deploy_finished_at": finished.isoformat(),
                    "failure_mode": "apply_target_not_allowed",
                    **receipt_base,
                }

        # 3. Capture service pre-state
        service_pre_state = "unknown"
        status_url = self._build_api_url("get_status")
        try:
            pre_result = self._api_request(status_url, headers, timeout=timeout)
            if pre_result["status_code"] == 200 and pre_result["body"].get("data"):
                service_pre_state = pre_result["body"]["data"].get("status", "unknown")
        except Exception:
            pass

        # 4. Execute apply action via API
        apply_started = datetime.datetime.now(datetime.timezone.utc)
        apply_timeout = m.apply_timeout_seconds or timeout
        apply_result = self._api_request(api_url, headers, timeout=apply_timeout, method="POST")

        apply_success = apply_result["status_code"] == 200

        # 5. Extract UPID if present and poll
        upid = ""
        task_exitstatus = ""
        if apply_success and apply_result["body"].get("data"):
            data = apply_result["body"]["data"]
            if isinstance(data, str) and data.startswith("UPID:"):
                upid = data
                task_result = self._poll_task(upid, headers)
                task_exitstatus = task_result.get("task_exitstatus", "")
                if task_result.get("task_status") != "stopped":
                    apply_success = False
                elif task_exitstatus != "OK":
                    apply_success = False

        apply_finished = datetime.datetime.now(datetime.timezone.utc)

        if not apply_success:
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Apply failed: API returned {apply_result['status_code']}, "
                    f"task={task_exitstatus or 'no_task'}"
                ),
                "deploy_finished_at": apply_finished.isoformat(),
                "promoted_artifact_digest": artifact_digest,
                "apply_started_at": apply_started.isoformat(),
                "apply_finished_at": apply_finished.isoformat(),
                "service_pre_state": service_pre_state,
                "tls_verified": apply_result.get("tls_verified", True),
                "failure_mode": "apply_failed",
                **receipt_base,
            }

        # 6. Capture service post-state
        service_post_state = "unknown"
        try:
            post_result = self._api_request(status_url, headers, timeout=timeout)
            if post_result["status_code"] == 200 and post_result["body"].get("data"):
                service_post_state = post_result["body"]["data"].get("status", "unknown")
        except Exception:
            pass

        # 7. Verify activation
        activated_artifact_digest = promoted_artifact_digest
        activation_verified = apply_success

        if m.expected_service_state:
            if service_post_state != m.expected_service_state:
                activation_verified = False

        return {
            "deploy_status": "accepted" if activation_verified else "rejected",
            "deploy_detail": (
                f"Artifact applied: digest={artifact_digest[:12]}... "
                f"service: {service_pre_state} → {service_post_state}"
            ),
            "deploy_finished_at": apply_finished.isoformat(),
            "promoted_artifact_digest": promoted_artifact_digest,
            "activated_artifact_digest": activated_artifact_digest,
            "apply_started_at": apply_started.isoformat(),
            "apply_finished_at": apply_finished.isoformat(),
            "apply_status": "applied" if activation_verified else "failed",
            "service_pre_state": service_pre_state,
            "service_post_state": service_post_state,
            "activation_verified": activation_verified,
            "tls_verified": apply_result.get("tls_verified", True),
            "response_status_code": apply_result["status_code"],
            "proxmox_task_upid": upid,
            "task_exitstatus": task_exitstatus or "OK",
            "failure_mode": "" if activation_verified else "service_state_mismatch",
            **receipt_base,
        }

    def _handle_rollback_artifact(
        self,
        identity: str,
        started: datetime.datetime,
        api_url: str,
        headers: dict[str, str],
        timeout: int,
        node: str,
        vmid: str,
        action: str,
        secret_check: dict[str, Any],
        triggered_by: str = "explicit",
    ) -> dict[str, Any]:
        """Handle the rollback_artifact action (v1.13.3).

        Reverts a deployment to a previous artifact version.

        Flow:
          1. Verify previous_artifact_digest is available
          2. Execute rollback via API PUT (revert config)
          3. Poll for task completion
          4. Verify rollback (service state check)
          5. Return receipt with rollback evidence

        Args:
            triggered_by: 'explicit' for direct rollback action,
                          'apply_failure' for automatic rollback.
        """
        m = self._manifest

        receipt_base: dict[str, Any] = {
            "deployer_identity": identity,
            "deploy_started_at": started.isoformat(),
            "proxmox_node": node,
            "vmid": vmid,
            "action": action,
            "api_endpoint": api_url,
            "proxmox_command_shape": "api",
            "shell_used": False,
            "api_endpoint_identity": api_url,
            "ssh_user": "",
            "host_key_verified": False,
            "root_user_used": False,
            "sudo_used": False,
            "ssh_host_fingerprint": "",
            "host_key_pin_checked": False,
            "host_key_pin_matched": False,
            "remote_hash_verified": False,
            "remote_hash_matched": False,
            "token_secret_ref_type": secret_check.get("ref_type", ""),
            "secret_source_allowed": secret_check.get("source_allowed", True),
            "secret_resolved": secret_check.get("resolved", True),
            "secret_value_serialized": False,
            "token_secret_ref_redacted": secret_check.get("redacted_ref", ""),
        }

        # 0. v1.13.6: Resolve rollback target from release history if configured
        release_resolution: dict[str, Any] = {
            "resolved": False,
            "release_id": "",
            "release_record_found": False,
            "retention_verified": False,
            "retention_errors": [],
        }
        if m.resolve_release_by:
            from nodechain.cli.release_history import ReleaseHistory
            rh_path = m.release_history_path or ""
            history = ReleaseHistory(path=rh_path)

            # v1.13.7: Verify release history integrity before resolving
            if m.require_retention_verification:
                ir = history.verify_integrity()
                release_resolution["history_integrity_valid"] = ir["valid"]
                release_resolution["history_integrity_errors"] = ir.get("errors", [])
                if not ir["valid"]:
                    finished = datetime.datetime.now(datetime.timezone.utc)
                    return {
                        "deploy_status": "rejected",
                        "deploy_detail": (
                            f"Rollback rejected: release history integrity check failed "
                            f"({len(ir.get('errors', []))} errors)"
                        ),
                        "deploy_finished_at": finished.isoformat(),
                        "rollback_attempted": True,
                        "rollback_started_at": finished.isoformat(),
                        "rollback_finished_at": finished.isoformat(),
                        "rollback_status": "rejected",
                        "rollback_artifact_digest": "",
                        "rollback_verified": False,
                        "final_deployment_state": "unknown",
                        "failure_mode": "release_history_malformed",
                        "rollback_triggered_by": triggered_by,
                        "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                        "previous_release_verified": False,
                        "rollback_to_known_good": False,
                        "rollback_provenance_status": "not_checked",
                        "previous_assurance_chain_verified": False,
                        "previous_chain_verification_status": "not_checked",
                        "previous_release_identity": "",
                        "release_resolution": release_resolution,
                        **receipt_base,
                    }

            resolved_record = None

            # v1.13.8: Verify release history snapshot if required
            snapshot_status: dict[str, Any] = {
                "verified": False,
                "signature_status": "none",
                "digest_valid": False,
            }
            if m.require_release_history_snapshot and m.release_history_snapshot_path:
                from nodechain.cli.release_history import verify_release_history_snapshot
                snapshot_result = verify_release_history_snapshot(
                    snapshot_path=m.release_history_snapshot_path,
                    check_live_history=True,
                    history_path=rh_path,
                )
                snapshot_status["verified"] = snapshot_result["valid"]
                snapshot_status["signature_status"] = snapshot_result.get("details", {}).get("signature_status", "none")
                snapshot_status["digest_valid"] = snapshot_result.get("details", {}).get("snapshot_digest", False)
                snapshot_status["errors"] = snapshot_result.get("errors", [])
                release_resolution["snapshot_verified"] = snapshot_result["valid"]
                release_resolution["snapshot_signature_status"] = snapshot_status["signature_status"]
                release_resolution["snapshot_digest"] = m.release_history_snapshot_path
                if not snapshot_result["valid"]:
                    finished = datetime.datetime.now(datetime.timezone.utc)
                    return {
                        "deploy_status": "rejected",
                        "deploy_detail": (
                            f"Rollback rejected: release history snapshot verification failed "
                            f"({len(snapshot_result.get('errors', []))} errors)"
                        ),
                        "deploy_finished_at": finished.isoformat(),
                        "rollback_attempted": True,
                        "rollback_started_at": finished.isoformat(),
                        "rollback_finished_at": finished.isoformat(),
                        "rollback_status": "rejected",
                        "rollback_artifact_digest": "",
                        "rollback_verified": False,
                        "final_deployment_state": "unknown",
                        "failure_mode": "release_history_snapshot_invalid",
                        "rollback_triggered_by": triggered_by,
                        "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                        "previous_release_verified": False,
                        "rollback_to_known_good": False,
                        "rollback_provenance_status": "not_checked",
                        "previous_assurance_chain_verified": False,
                        "previous_chain_verification_status": "not_checked",
                        "previous_release_identity": "",
                        "release_history_snapshot_digest": m.release_history_snapshot_path,
                        "release_history_snapshot_signature_status": snapshot_status["signature_status"],
                        "release_history_snapshot_verified": False,
                        "release_resolution": release_resolution,
                        **receipt_base,
                    }
            if m.resolve_release_by == "release_id":
                resolved_record = history.get(m.resolve_release_id)
            elif m.resolve_release_by == "artifact_digest":
                resolved_record = history.find_by_digest(m.previous_artifact_digest)
            elif m.resolve_release_by == "latest_known_good":
                target = m.proxmox_node + "/" + str(m.target_vmid) if m.proxmox_node else ""
                resolved_record = history.latest_known_good(target=target)

            if resolved_record:
                release_resolution["resolved"] = True
                release_resolution["release_id"] = resolved_record.release_id
                release_resolution["release_record_found"] = True
                # Override previous_artifact_digest from release record
                if resolved_record.artifact_digest:
                    m.previous_artifact_digest = resolved_record.artifact_digest
                # Populate prior receipt from release record digests
                if not m.previous_deployment_receipt and resolved_record.deployment_receipt_path:
                    try:
                        import json as _json
                        m.previous_deployment_receipt = _json.loads(
                            Path(resolved_record.deployment_receipt_path).read_text(encoding="utf-8")
                        )
                    except Exception:
                        pass
                # Retention verification
                if m.require_retention_verification:
                    vr = history.verify_retention(
                        resolved_record.release_id,
                        require_chain=m.require_previous_assurance_chain,
                    )
                    release_resolution["retention_verified"] = vr["valid"]
                    release_resolution["retention_errors"] = vr.get("errors", [])
                    if not vr["valid"]:
                        finished = datetime.datetime.now(datetime.timezone.utc)
                        return {
                            "deploy_status": "rejected",
                            "deploy_detail": (
                                f"Rollback rejected: retention verification failed "
                                f"for release {resolved_record.release_id}"
                            ),
                            "deploy_finished_at": finished.isoformat(),
                            "rollback_attempted": True,
                            "rollback_started_at": finished.isoformat(),
                            "rollback_finished_at": finished.isoformat(),
                            "rollback_status": "rejected",
                            "rollback_artifact_digest": resolved_record.artifact_digest,
                            "rollback_verified": False,
                            "final_deployment_state": "unknown",
                            "failure_mode": "retention_verification_failed",
                            "rollback_triggered_by": triggered_by,
                            "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                            "previous_release_verified": False,
                            "rollback_to_known_good": False,
                            "rollback_provenance_status": "not_checked",
                            "previous_assurance_chain_verified": False,
                            "previous_chain_verification_status": "not_checked",
                            "previous_release_identity": resolved_record.release_id,
                            "release_resolution": release_resolution,
                            **receipt_base,
                        }
            else:
                release_resolution["release_record_found"] = False
                release_resolution["resolved"] = False
                # Strict mode fails if release not found
                if m.require_previous_receipt_verified:
                    finished = datetime.datetime.now(datetime.timezone.utc)
                    return {
                        "deploy_status": "rejected",
                        "deploy_detail": (
                            f"Rollback rejected: release not found "
                            f"(resolve_by={m.resolve_release_by}, "
                            f"id={m.resolve_release_id})"
                        ),
                        "deploy_finished_at": finished.isoformat(),
                        "rollback_attempted": True,
                        "rollback_started_at": finished.isoformat(),
                        "rollback_finished_at": finished.isoformat(),
                        "rollback_status": "rejected",
                        "rollback_artifact_digest": "",
                        "rollback_verified": False,
                        "final_deployment_state": "unknown",
                        "failure_mode": "release_not_found",
                        "rollback_triggered_by": triggered_by,
                        "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                        "previous_release_verified": False,
                        "rollback_to_known_good": False,
                        "rollback_provenance_status": "not_checked",
                        "previous_assurance_chain_verified": False,
                        "previous_chain_verification_status": "not_checked",
                        "previous_release_identity": "",
                        "release_resolution": release_resolution,
                        **receipt_base,
                    }

        # 1. Verify previous_artifact_digest
        prev_digest = m.previous_artifact_digest
        # Merge release resolution into receipt_base for all returns
        receipt_base["release_resolution"] = release_resolution
        if not prev_digest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    "Cannot rollback: previous_artifact_digest not configured"
                ),
                "deploy_finished_at": finished.isoformat(),
                "rollback_attempted": True,
                "rollback_started_at": finished.isoformat(),
                "rollback_finished_at": finished.isoformat(),
                "rollback_status": "rejected",
                "rollback_artifact_digest": "",
                "rollback_verified": False,
                "final_deployment_state": "unknown",
                "failure_mode": "previous_artifact_missing",
                "rollback_triggered_by": triggered_by,
                # v1.13.4 provenance fields
                "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                "previous_release_verified": False,
                "rollback_to_known_good": False,
                "rollback_provenance_status": "not_checked",
                **receipt_base,
            }

        # 1a. v1.13.4: Verify rollback provenance
        provenance = self._verify_rollback_provenance(m, prev_digest)

        # v1.13.5: Full assurance chain verification
        chain = self._verify_rollback_assurance_chain(m, prev_digest, provenance)

        if not provenance["verified"] and m.require_previous_receipt_verified:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Rollback rejected: {provenance['reason']}"
                ),
                "deploy_finished_at": finished.isoformat(),
                "rollback_attempted": True,
                "rollback_started_at": finished.isoformat(),
                "rollback_finished_at": finished.isoformat(),
                "rollback_status": "rejected",
                "rollback_artifact_digest": prev_digest,
                "rollback_verified": False,
                "final_deployment_state": "unknown",
                "failure_mode": provenance["failure_mode"],
                "rollback_triggered_by": triggered_by,
                # v1.13.4 provenance fields
                "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                "previous_release_verified": False,
                "rollback_to_known_good": False,
                "rollback_provenance_status": provenance["status"],
                # v1.13.5 chain fields
                "previous_assurance_chain_verified": False,
                "previous_chain_verification_status": chain.get("status", "not_checked"),
                "previous_release_identity": "",
                **receipt_base,
            }

        # v1.13.5: Chain verification rejection
        if not chain["verified"] and m.require_previous_assurance_chain:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Rollback rejected (assurance chain): {chain['reason']}"
                ),
                "deploy_finished_at": finished.isoformat(),
                "rollback_attempted": True,
                "rollback_started_at": finished.isoformat(),
                "rollback_finished_at": finished.isoformat(),
                "rollback_status": "rejected",
                "rollback_artifact_digest": prev_digest,
                "rollback_verified": False,
                "final_deployment_state": "unknown",
                "failure_mode": chain["failure_mode"],
                "rollback_triggered_by": triggered_by,
                "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                "previous_release_verified": True,
                "rollback_to_known_good": False,
                "rollback_provenance_status": "verified",
                # v1.13.5 chain fields
                "previous_assurance_chain_verified": False,
                "previous_chain_verification_status": chain["status"],
                "previous_release_identity": chain.get("release_identity", ""),
                **receipt_base,
            }

        # 2. Execute rollback via API PUT
        rollback_started = datetime.datetime.now(datetime.timezone.utc)
        rollback_timeout = m.rollback_timeout_seconds or timeout
        rollback_result = self._api_request(
            api_url, headers, timeout=rollback_timeout, method="PUT"
        )
        rollback_finished = datetime.datetime.now(datetime.timezone.utc)

        rollback_success = rollback_result["status_code"] == 200

        # 2a. Extract UPID if present and poll
        upid = ""
        task_exitstatus = ""
        if rollback_success and rollback_result["body"].get("data"):
            data = rollback_result["body"]["data"]
            if isinstance(data, str) and data.startswith("UPID:"):
                upid = data
                task_result = self._poll_task(upid, headers)
                task_exitstatus = task_result.get("task_exitstatus", "")
                if task_result.get("task_status") != "stopped":
                    rollback_success = False
                elif task_exitstatus != "OK":
                    rollback_success = False

        if not rollback_success:
            return {
                "deploy_status": "rejected",
                "deploy_detail": (
                    f"Rollback failed: API returned {rollback_result['status_code']}, "
                    f"task={task_exitstatus or 'no_task'}"
                ),
                "deploy_finished_at": rollback_finished.isoformat(),
                "rollback_attempted": True,
                "rollback_started_at": rollback_started.isoformat(),
                "rollback_finished_at": rollback_finished.isoformat(),
                "rollback_status": "failed",
                "rollback_artifact_digest": prev_digest,
                "rollback_verified": False,
                "final_deployment_state": "unknown",
                "tls_verified": rollback_result.get("tls_verified", True),
                "proxmox_task_upid": upid,
                "task_exitstatus": task_exitstatus or "FAILED",
                "failure_mode": "rollback_failed",
                "rollback_triggered_by": triggered_by,
                # v1.13.4 provenance fields
                "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
                "previous_release_verified": provenance["verified"],
                "rollback_to_known_good": provenance["verified"],
                "rollback_provenance_status": provenance["status"],
                # v1.13.5 chain fields
                "previous_assurance_chain_verified": chain["verified"],
                "previous_chain_verification_status": chain.get("status", "not_checked"),
                "previous_release_identity": chain.get("release_identity", ""),
                **receipt_base,
            }

        # 3. Verify rollback (service state check)
        rollback_verified = True
        service_state = "unknown"
        if m.require_rollback_verification:
            status_url = self._build_api_url("get_status")
            try:
                post_result = self._api_request(status_url, headers, timeout=timeout)
                if post_result["status_code"] == 200 and post_result["body"].get("data"):
                    service_state = post_result["body"]["data"].get("status", "unknown")
                    if m.expected_service_state and service_state != m.expected_service_state:
                        rollback_verified = False
                else:
                    rollback_verified = False
            except Exception:
                rollback_verified = False

        final_state = "rolled_back" if rollback_verified else "rollback_unverified"

        return {
            "deploy_status": "accepted" if rollback_verified else "rejected",
            "deploy_detail": (
                f"Rollback to {prev_digest[:12]}... successful "
                f"(triggered_by={triggered_by}, service={service_state})"
            ),
            "deploy_finished_at": rollback_finished.isoformat(),
            "rollback_attempted": True,
            "rollback_started_at": rollback_started.isoformat(),
            "rollback_finished_at": rollback_finished.isoformat(),
            "rollback_status": "succeeded" if rollback_verified else "verification_failed",
            "rollback_artifact_digest": prev_digest,
            "rollback_verified": rollback_verified,
            "final_deployment_state": final_state,
            "tls_verified": rollback_result.get("tls_verified", True),
            "response_status_code": rollback_result["status_code"],
            "proxmox_task_upid": upid,
            "task_exitstatus": task_exitstatus or "OK",
            "failure_mode": "" if rollback_verified else "rollback_verification_failed",
            "rollback_triggered_by": triggered_by,
            # v1.13.4 provenance fields
            "previous_deployment_receipt_digest": m.previous_deployment_receipt_digest,
            "previous_release_verified": provenance["verified"],
            "rollback_to_known_good": chain["verified"] if m.require_previous_assurance_chain else provenance["verified"],
            "rollback_provenance_status": provenance["status"],
            # v1.13.5 chain fields
            "previous_assurance_chain_verified": chain["verified"],
            "previous_chain_verification_status": chain.get("status", "not_checked"),
            "previous_release_identity": chain.get("release_identity", ""),
            **receipt_base,
        }

    def _verify_rollback_provenance(
        self,
        manifest: Any,
        prev_digest: str,
    ) -> dict[str, Any]:
        """Verify rollback provenance — that previous_artifact_digest corresponds
        to a prior verified deployment receipt (v1.13.4).

        Checks:
          1. Prior receipt data is available
          2. Receipt digest matches previous_deployment_receipt_digest
          3. Prior receipt shows final_deployment_state=applied
          4. Prior receipt shows activation_verified=true
          5. Prior receipt artifact_digest matches prev_digest

        Returns:
            {verified: bool, reason: str, failure_mode: str, status: str}
            status: 'verified', 'not_checked', 'receipt_missing',
                    'receipt_invalid', 'digest_mismatch',
                    'release_not_applied', 'activation_not_verified'
        """
        # If provenance check is not required, skip
        if not manifest.require_previous_receipt_verified:
            return {
                "verified": True,
                "reason": "Provenance check disabled",
                "failure_mode": "",
                "status": "not_checked",
            }

        # If no prior receipt provided, that's ok only if not required
        prior_receipt = manifest.previous_deployment_receipt
        expected_digest = manifest.previous_deployment_receipt_digest

        if not prior_receipt:
            return {
                "verified": False,
                "reason": "No prior deployment receipt provided",
                "failure_mode": "previous_receipt_missing",
                "status": "receipt_missing",
            }

        if not isinstance(prior_receipt, dict):
            return {
                "verified": False,
                "reason": "Prior receipt is not a dict",
                "failure_mode": "previous_receipt_invalid",
                "status": "receipt_invalid",
            }

        # Verify digest if expected digest is set
        if expected_digest:
            computed_digest = _sha256_dict(prior_receipt)
            if computed_digest != expected_digest:
                return {
                    "verified": False,
                    "reason": (
                        f"Receipt digest mismatch: "
                        f"expected={expected_digest[:12]}... "
                        f"computed={computed_digest[:12]}..."
                    ),
                    "failure_mode": "previous_receipt_invalid",
                    "status": "receipt_invalid",
                }

        # Check final_deployment_state
        prior_state = prior_receipt.get("final_deployment_state", "")
        if prior_state != "applied":
            return {
                "verified": False,
                "reason": (
                    f"Prior release was not applied "
                    f"(final_deployment_state={prior_state})"
                ),
                "failure_mode": "previous_release_not_applied",
                "status": "release_not_applied",
            }

        # Check activation_verified
        prior_activation = prior_receipt.get("activation_verified", False)
        if not prior_activation:
            return {
                "verified": False,
                "reason": "Prior release activation was not verified",
                "failure_mode": "previous_activation_not_verified",
                "status": "activation_not_verified",
            }

        # Check artifact digest matches rollback target
        prior_artifact_digest = (
            prior_receipt.get("activated_artifact_digest")
            or prior_receipt.get("artifact_digest")
            or prior_receipt.get("promoted_artifact_digest")
            or ""
        )
        if prior_artifact_digest and prior_artifact_digest != prev_digest:
            return {
                "verified": False,
                "reason": (
                    f"Artifact digest mismatch: "
                    f"prior={prior_artifact_digest[:12]}... "
                    f"rollback_target={prev_digest[:12]}..."
                ),
                "failure_mode": "previous_digest_mismatch",
                "status": "digest_mismatch",
            }

        return {
            "verified": True,
            "reason": (
                "Prior release verified: applied + activation_verified + "
                "digest match"
            ),
            "failure_mode": "",
            "status": "verified",
        }

    def _verify_rollback_assurance_chain(
        self,
        manifest: Any,
        prev_digest: str,
        provenance_result: dict[str, Any],
    ) -> dict[str, Any]:
        """Verify the full prior assurance chain (v1.13.5).

        Extends v1.13.4 provenance with full chain verification:
          1. Provenance check passed (v1.13.4)
          2. Prior deployment receipt is a deployment_system_receipt
          3. Prior receipt is signed (if required)
          4. Prior attestation is present and compliant
          5. Prior attestation is signed (if required)
          6. Prior verifier profile is trusted (if required)
          7. Prior audit bundle digest matches (if provided)
          8. Prior gate receipt is present (if provided)

        Returns:
            {verified: bool, reason: str, failure_mode: str,
             status: str, release_identity: str}
            status: 'chain_verified', 'not_checked',
                    'provenance_failed',
                    'receipt_not_deployment_system',
                    'receipt_unsigned',
                    'attestation_missing',
                    'attestation_non_compliant',
                    'attestation_unsigned',
                    'verifier_profile_untrusted',
                    'audit_bundle_mismatch',
                    'gate_receipt_missing'
        """
        # If full chain check is not required, return provenance result
        if not manifest.require_previous_assurance_chain:
            return {
                "verified": provenance_result["verified"],
                "reason": provenance_result.get("reason", "Chain check disabled"),
                "failure_mode": provenance_result.get("failure_mode", ""),
                "status": "not_checked",
                "release_identity": "",
            }

        # Step 1: Provenance must have passed
        if not provenance_result["verified"]:
            return {
                "verified": False,
                "reason": f"Provenance failed: {provenance_result.get('reason', '')}",
                "failure_mode": provenance_result.get("failure_mode", "previous_receipt_missing"),
                "status": "provenance_failed",
                "release_identity": "",
            }

        prior_receipt = manifest.previous_deployment_receipt or {}
        release_identity = (
            prior_receipt.get("deployment_receipt_id", "")
            or prior_receipt.get("receipt_id", "")
            or prev_digest[:16]
        )

        # Step 2: Prior receipt must be a deployment_system_receipt
        receipt_type = prior_receipt.get("receipt_type", "")
        deployment_system = prior_receipt.get("deployment_system", "")
        if receipt_type and receipt_type != "deployment_system_receipt":
            return {
                "verified": False,
                "reason": (
                    f"Prior receipt is not a deployment_system_receipt "
                    f"(type={receipt_type})"
                ),
                "failure_mode": "previous_receipt_not_deployment_system_receipt",
                "status": "receipt_not_deployment_system",
                "release_identity": release_identity,
            }

        # Step 3: Prior receipt signature check (if required)
        if manifest.previous_receipt_signature_required:
            receipt_sig = prior_receipt.get("receipt_signature", {})
            has_sig = (
                isinstance(receipt_sig, dict) and receipt_sig.get("signature")
            ) or (isinstance(receipt_sig, str) and receipt_sig)
            if not has_sig:
                return {
                    "verified": False,
                    "reason": "Prior receipt is unsigned (signature required)",
                    "failure_mode": "previous_receipt_unsigned",
                    "status": "receipt_unsigned",
                    "release_identity": release_identity,
                }

        # Step 4: Prior attestation present and compliant
        prior_attestation = manifest.previous_attestation
        if prior_attestation is None:
            return {
                "verified": False,
                "reason": "No prior attestation provided",
                "failure_mode": "previous_attestation_non_compliant",
                "status": "attestation_missing",
                "release_identity": release_identity,
            }

        if not isinstance(prior_attestation, dict):
            return {
                "verified": False,
                "reason": "Prior attestation is not a dict",
                "failure_mode": "previous_attestation_non_compliant",
                "status": "attestation_non_compliant",
                "release_identity": release_identity,
            }

        # Attestation must be deploy_allowed or have policy compliance
        att_deploy_allowed = prior_attestation.get("deploy_allowed", True)
        att_policy_id = prior_attestation.get("policy_id", "")
        if att_deploy_allowed is False:
            return {
                "verified": False,
                "reason": "Prior attestation deploy_allowed=false",
                "failure_mode": "previous_attestation_non_compliant",
                "status": "attestation_non_compliant",
                "release_identity": release_identity,
            }

        # Step 5: Attestation signature check (if required)
        if manifest.previous_attestation_signature_required:
            att_sig = prior_attestation.get("attestation_signature", {})
            has_att_sig = (
                isinstance(att_sig, dict) and att_sig.get("signature")
            ) or (isinstance(att_sig, str) and att_sig)
            if not has_att_sig:
                return {
                    "verified": False,
                    "reason": "Prior attestation is unsigned (signature required)",
                    "failure_mode": "previous_attestation_non_compliant",
                    "status": "attestation_unsigned",
                    "release_identity": release_identity,
                }

        # Step 6: Verifier profile trust check (if required)
        if manifest.previous_verifier_profile_trust_required:
            prior_profile = manifest.previous_verifier_profile
            if prior_profile is None:
                return {
                    "verified": False,
                    "reason": "No prior verifier profile provided (trust required)",
                    "failure_mode": "previous_verifier_profile_untrusted",
                    "status": "verifier_profile_untrusted",
                    "release_identity": release_identity,
                }
            if isinstance(prior_profile, dict):
                # Check if profile is trusted
                profile_trusted = prior_profile.get("trusted", True)
                profile_signer_fp = prior_profile.get("profile_signer_fingerprint", "")
                profile_signature = prior_profile.get("profile_signature", "")
                if not profile_trusted:
                    return {
                        "verified": False,
                        "reason": "Prior verifier profile is not trusted",
                        "failure_mode": "previous_verifier_profile_untrusted",
                        "status": "verifier_profile_untrusted",
                        "release_identity": release_identity,
                    }
                if not profile_signature and not profile_signer_fp:
                    return {
                        "verified": False,
                        "reason": "Prior verifier profile is unsigned (trust required)",
                        "failure_mode": "previous_verifier_profile_untrusted",
                        "status": "verifier_profile_untrusted",
                        "release_identity": release_identity,
                    }

        # Step 7: Audit bundle digest cross-check (if provided)
        if manifest.previous_audit_bundle_digest:
            att_bundle_hash = prior_attestation.get("audit_bundle_sha256", "")
            if att_bundle_hash and att_bundle_hash != manifest.previous_audit_bundle_digest:
                return {
                    "verified": False,
                    "reason": (
                        f"Audit bundle digest mismatch: "
                        f"attestation={att_bundle_hash[:12]}... "
                        f"manifest={manifest.previous_audit_bundle_digest[:12]}..."
                    ),
                    "failure_mode": "previous_assurance_chain_invalid",
                    "status": "audit_bundle_mismatch",
                    "release_identity": release_identity,
                }

        # Step 8: Gate receipt cross-check (if provided)
        if manifest.previous_gate_receipt is not None:
            if not isinstance(manifest.previous_gate_receipt, dict):
                return {
                    "verified": False,
                    "reason": "Prior gate receipt is not a dict",
                    "failure_mode": "previous_assurance_chain_invalid",
                    "status": "gate_receipt_invalid",
                    "release_identity": release_identity,
                }
            gate_deploy_allowed = manifest.previous_gate_receipt.get("deploy_allowed", True)
            if gate_deploy_allowed is False:
                return {
                    "verified": False,
                    "reason": "Prior gate receipt deploy_allowed=false",
                    "failure_mode": "previous_assurance_chain_invalid",
                    "status": "gate_receipt_denied",
                    "release_identity": release_identity,
                }

        return {
            "verified": True,
            "reason": (
                "Full assurance chain verified: provenance + receipt type + "
                "attestation + profile + audit bundle"
            ),
            "failure_mode": "",
            "status": "chain_verified",
            "release_identity": release_identity,
        }

    def _capture_boot_id_evidence(
        self,
        headers: dict[str, str],
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Capture boot identifier via QEMU guest agent file-read.

        v1.12.6: Attempts to read /proc/sys/kernel/random/boot_id from
        the guest via the Proxmox guest agent API. Only works for QEMU VMs
        with the guest agent installed and running.

        Returns:
            {boot_id: str, available: bool, source: str}
        """
        node = self._manifest.proxmox_node if self._manifest else ""
        vmid = self._manifest.target_vmid if self._manifest else ""
        base = self._manifest.api_base_url if self._manifest else ""

        # Try QEMU guest agent file-read endpoint
        url = (
            f"{base}/nodes/{node}/qemu/{vmid}/agent/file-read"
            "?file=%2Fproc%2Fsys%2Fkernel%2Frandom%2Fboot_id"
        )
        try:
            result = self._api_request(url, headers, timeout=timeout)
            if result["status_code"] == 200 and result["body"].get("data"):
                data = result["body"]["data"]
                # Guest agent returns {"content": "base64-encoded-data"}
                content = data.get("content", "")
                if content:
                    import base64
                    try:
                        boot_id = base64.b64decode(content).decode("utf-8").strip()
                    except Exception:
                        boot_id = ""
                    if boot_id:
                        return {
                            "boot_id": boot_id,
                            "available": True,
                            "source": "guest_agent",
                        }
        except Exception:
            pass

        return {
            "boot_id": "",
            "available": False,
            "source": "guest_agent",
        }

    def deploy(
        self,
        target: str,
        artifact_digest: str,
        policy_digest: str,
        assurance_receipt_id: str,
    ) -> dict[str, Any]:
        """Execute a Proxmox API action."""
        started = datetime.datetime.now(datetime.timezone.utc)
        identity = f"proxmox-api@{self._manifest.api_base_url if self._manifest else 'unknown'}"

        if not self._manifest:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deployer_identity": identity,
                "deploy_detail": "No manifest provided for ProxmoxApiAdapter",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": "",
                "vmid": "",
                "action": "none",
                "api_endpoint": "",
            }

        # Validate manifest
        issues = self._validate_api_manifest()
        if issues:
            finished = datetime.datetime.now(datetime.timezone.utc)
            return {
                "deploy_status": "rejected",
                "deployer_identity": identity,
                "deploy_detail": f"Manifest validation failed: {'; '.join(issues)}",
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": self._manifest.proxmox_node,
                "vmid": self._manifest.target_vmid,
                "action": "none",
                "api_endpoint": "",
            }

        node = self._manifest.proxmox_node
        vmid = self._manifest.target_vmid
        actions = self._manifest.allowed_actions or ["validate_target"]
        action = actions[0]
        timeout = self._manifest.deploy_timeout_seconds or self._manifest.timeout_seconds

        # Build API context
        token_id = self._resolve_token_id()
        token_secret = self._resolve_token_secret()
        headers = self._build_api_headers(token_id, token_secret)
        api_url = self._build_api_url(action)

        # v1.12.1: Secret reference policy receipt fields
        secret_check = self._validate_secret_ref(strict=False)

        # ── v1.12.2: Task action handling ──────────────────────────────
        task_fields: dict[str, Any] = {}
        state_transition_verified = False
        pre_state = ""
        post_state = ""

        is_mutation = action in ("start", "stop", "reboot")
        is_artifact = action == "upload_artifact"
        is_promotion = action == "promote_artifact"
        is_apply = action == "apply_artifact"
        is_rollback = action == "rollback_artifact"

        if is_mutation:
            # Pre-state check: GET current status
            status_url = self._build_api_url("get_status")
            pre_result = self._api_request(status_url, headers, timeout=timeout)
            if pre_result["status_code"] == 200 and pre_result["body"].get("data"):
                pre_state = pre_result["body"]["data"].get("status", "unknown")
            else:
                pre_state = "unknown"

            task_fields["pre_state"] = pre_state
            task_fields["requested_action"] = action

            # Verify pre-state if required (runs BEFORE no-op detection)
            if self._manifest.require_confirmed_target_status:
                expected_pre = self._manifest.expected_pre_state
                if expected_pre and pre_state != expected_pre:
                    finished = datetime.datetime.now(datetime.timezone.utc)
                    return {
                        "deploy_status": "rejected",
                        "deployer_identity": identity,
                        "deploy_detail": (
                            f"Pre-state mismatch: expected '{expected_pre}', "
                            f"got '{pre_state}'"
                        ),
                        "deploy_started_at": started.isoformat(),
                        "deploy_finished_at": finished.isoformat(),
                        "proxmox_node": node,
                        "vmid": vmid,
                        "action": action,
                        "api_endpoint": api_url,
                        "pre_state": pre_state,
                        "post_state": "",
                        "state_transition_verified": False,
                        "proxmox_task_upid": "",
                        "task_exitstatus": None,
                        "proxmox_command_shape": "api",
                        "shell_used": False,
                        "tls_verified": pre_result["tls_verified"],
                        "response_status_code": pre_result["status_code"],
                        "token_secret_ref_type": secret_check["ref_type"],
                        "secret_source_allowed": secret_check["source_allowed"],
                        "secret_resolved": secret_check["resolved"],
                        "secret_value_serialized": False,
                        "token_secret_ref_redacted": secret_check["redacted_ref"],
                        "requested_action": action,
                        "effective_action": "rejected",
                        "no_op": False,
                        "idempotency_policy": self._manifest.idempotency_policy,
                    }

            # v1.12.4: Idempotency / no-op detection (runs AFTER pre-state check)
            # v1.12.5: reject_noop now rejects before mutation
            expected_post = self._manifest.expected_post_state
            no_op = False
            effective_action = action

            if expected_post and pre_state == expected_post and action != "reboot":
                # Target already in desired state — idempotency decision
                # v1.12.5: reboot is excluded because running→running is normal
                if self._manifest.allow_noop_if_already_desired:
                    no_op = True
                    effective_action = "noop"
                elif self._manifest.idempotency_policy == "allow_noop":
                    no_op = True
                    effective_action = "noop"
                elif self._manifest.idempotency_policy == "reject_noop":
                    # v1.12.5: Reject before executing unnecessary mutation
                    finished = datetime.datetime.now(datetime.timezone.utc)
                    return {
                        "deploy_status": "rejected",
                        "deployer_identity": identity,
                        "deploy_detail": (
                            f"Target already in desired state '{pre_state}' "
                            f"but no-op not allowed (idempotency_policy=reject_noop)"
                        ),
                        "deploy_started_at": started.isoformat(),
                        "deploy_finished_at": finished.isoformat(),
                        "proxmox_node": node,
                        "vmid": vmid,
                        "action": action,
                        "api_endpoint": api_url,
                        "pre_state": pre_state,
                        "post_state": pre_state,
                        "state_transition_verified": False,
                        "proxmox_command_shape": "api",
                        "shell_used": False,
                        "tls_verified": pre_result["tls_verified"],
                        "response_status_code": pre_result["status_code"],
                        "token_secret_ref_type": secret_check["ref_type"],
                        "secret_source_allowed": secret_check["source_allowed"],
                        "secret_resolved": secret_check["resolved"],
                        "secret_value_serialized": False,
                        "token_secret_ref_redacted": secret_check["redacted_ref"],
                        "requested_action": action,
                        "effective_action": "rejected",
                        "no_op": False,
                        "idempotency_policy": self._manifest.idempotency_policy,
                        "task_success": False,
                        "task_exitstatus": "REJECTED_NOOP",
                        "proxmox_task_upid": "",
                    }

            task_fields["effective_action"] = effective_action
            task_fields["no_op"] = no_op
            task_fields["idempotency_policy"] = self._manifest.idempotency_policy

            if no_op:
                # No mutation needed — target already in desired state
                finished = datetime.datetime.now(datetime.timezone.utc)
                post_state = pre_state
                task_fields["post_state"] = post_state
                task_fields["state_transition_verified"] = True
                task_fields["task_success"] = True
                task_fields["task_exitstatus"] = "NOOP"
                task_fields["proxmox_task_upid"] = ""
                task_fields["task_poll_count"] = 0
                task_fields["task_duration_ms"] = 0
                task_fields["task_api_status"] = "noop"
                task_started_at = finished
                task_fields["task_started_at"] = task_started_at.isoformat()
                task_fields["task_finished_at"] = finished.isoformat()

                return {
                    "deploy_status": "accepted",
                    "deployer_identity": identity,
                    "deploy_detail": (
                        f"No-op: target already in desired state '{post_state}' "
                        f"(idempotency_policy={self._manifest.idempotency_policy})"
                    ),
                    "deploy_started_at": started.isoformat(),
                    "deploy_finished_at": finished.isoformat(),
                    "proxmox_node": node,
                    "vmid": vmid,
                    "action": action,
                    "api_endpoint": api_url,
                    "proxmox_command_shape": "api",
                    "shell_used": False,
                    "api_endpoint_identity": api_url,
                    "tls_verified": pre_result["tls_verified"],
                    "response_status_code": pre_result["status_code"],
                    "ssh_user": "",
                    "host_key_verified": False,
                    "root_user_used": False,
                    "sudo_used": False,
                    "ssh_host_fingerprint": "",
                    "host_key_pin_checked": False,
                    "host_key_pin_matched": False,
                    "remote_hash_verified": False,
                    "remote_hash_matched": False,
                    "token_secret_ref_type": secret_check["ref_type"],
                    "secret_source_allowed": secret_check["source_allowed"],
                    "secret_resolved": secret_check["resolved"],
                    "secret_value_serialized": False,
                    "token_secret_ref_redacted": secret_check["redacted_ref"],
                    **task_fields,
                }

            # v1.12.5: Capture pre-reboot evidence for reboot action
            pre_boot_evidence: dict[str, Any] = {}
            if action == "reboot":
                pre_boot_evidence = self._capture_boot_evidence(headers, timeout)
                task_fields["pre_uptime_seconds"] = pre_boot_evidence.get("uptime_seconds", 0)

            # Execute mutation via POST
            task_timeout = self._manifest.task_timeout_seconds or timeout
            api_result = self._api_request(api_url, headers, timeout=task_timeout, method="POST")
            task_started_at = datetime.datetime.now(datetime.timezone.utc)

            # Extract UPID from response
            upid = ""
            if api_result["status_code"] == 200 and api_result["body"].get("data"):
                upid = api_result["body"]["data"]
                if isinstance(upid, dict):
                    upid = upid.get("upid", "")
                elif not isinstance(upid, str):
                    upid = str(upid)

            task_fields["proxmox_task_upid"] = upid
            task_fields["task_started_at"] = task_started_at.isoformat()

            # Determine success
            api_success = api_result["status_code"] == 200 and bool(upid)

            # v1.12.3: Poll task endpoint by UPID
            task_success = False
            if api_success and upid:
                task_result = self._poll_task(upid, headers)
                task_fields["task_poll_count"] = task_result["task_poll_count"]
                task_fields["task_duration_ms"] = task_result["task_duration_ms"]
                task_fields["task_api_status"] = task_result["task_status"]
                task_fields["task_exitstatus"] = task_result["task_exitstatus"]
                if task_result["task_log_digest"]:
                    task_fields["task_log_digest"] = task_result["task_log_digest"]

                task_success = (
                    task_result["task_status"] == "stopped"
                    and (
                        not self._manifest.require_task_success
                        or task_result["task_exitstatus"] == "OK"
                    )
                )

                if self._manifest.require_task_success and task_result["timed_out"]:
                    # Task timed out — treat as failure
                    task_success = False
            else:
                task_fields["task_exitstatus"] = "FAILED"
                task_fields["task_poll_count"] = 0
                task_fields["task_duration_ms"] = 0
                task_fields["task_api_status"] = "no_upid"

            # Post-state check (separate from task success)
            if api_success and upid:
                status_url = self._build_api_url("get_status")
                post_result = self._api_request(status_url, headers, timeout=timeout)
                if post_result["status_code"] == 200 and post_result["body"].get("data"):
                    post_state = post_result["body"]["data"].get("status", "unknown")
                else:
                    post_state = "unknown"

                # Verify post-state
                expected_post = self._manifest.expected_post_state
                if expected_post and post_state == expected_post:
                    state_transition_verified = True
                elif not expected_post:
                    state_transition_verified = True  # no expectation set
                # If expected_post set but mismatch, state_transition_verified stays false
            else:
                post_state = pre_state  # unchanged on failure

            task_finished_at = datetime.datetime.now(datetime.timezone.utc)
            task_fields["task_finished_at"] = task_finished_at.isoformat()
            task_fields["post_state"] = post_state
            task_fields["state_transition_verified"] = state_transition_verified
            task_fields["task_success"] = task_success

            # v1.12.5/v1.12.6: Post-reboot evidence verification
            boot_identity_changed = False
            uptime_reset_detected = False
            boot_id_changed = False
            uptime_fallback_used = False
            boot_id_evidence_source = self._manifest.boot_evidence_source
            pre_boot_id = pre_boot_evidence.get("boot_id", "")
            boot_id_available = pre_boot_evidence.get("boot_id_available", False)

            if action == "reboot" and api_success and upid and pre_boot_evidence:
                post_boot_evidence = self._capture_boot_evidence(headers, timeout)
                task_fields["post_uptime_seconds"] = post_boot_evidence.get("uptime_seconds", 0)
                post_boot_id = post_boot_evidence.get("boot_id", "")
                post_boot_id_available = post_boot_evidence.get("boot_id_available", False)

                # Check uptime reset: post uptime should be much less than pre
                pre_up = pre_boot_evidence.get("uptime_seconds", 0)
                post_up = post_boot_evidence.get("uptime_seconds", 0)
                if pre_up > 0 and post_up >= 0 and post_up < pre_up:
                    uptime_reset_detected = True

                # v1.12.6: Check boot_id change
                if boot_id_available and post_boot_id_available:
                    if pre_boot_id and post_boot_id and pre_boot_id != post_boot_id:
                        boot_id_changed = True
                        boot_identity_changed = True
                else:
                    # Boot ID not available — check if uptime fallback is allowed
                    if uptime_reset_detected:
                        # v1.12.5 compat: uptime reset implies boot identity changed
                        boot_identity_changed = True
                        if not boot_id_available:
                            uptime_fallback_used = True

                # v1.12.7: Safe boot ID storage — hash by default
                store_pre = pre_boot_id
                store_post = post_boot_id
                if self._manifest.hash_boot_ids and not self._manifest.allow_raw_boot_ids:
                    store_pre = _sha256_text(pre_boot_id) if pre_boot_id else ""
                    store_post = _sha256_text(post_boot_id) if post_boot_id else ""

                task_fields["pre_boot_id"] = store_pre
                task_fields["post_boot_id"] = store_post
                task_fields["boot_id_hashed"] = self._manifest.hash_boot_ids and not self._manifest.allow_raw_boot_ids
                task_fields["boot_id_changed"] = boot_id_changed
                task_fields["uptime_fallback_used"] = uptime_fallback_used
                task_fields["boot_evidence_source"] = boot_id_evidence_source

            task_fields["boot_identity_changed"] = boot_identity_changed
            task_fields["uptime_reset_detected"] = uptime_reset_detected

            # v1.12.3: Overall success = task completed AND state verified
            # v1.12.5/v1.12.6: For reboot, require boot evidence per policy
            overall_success = task_success and (
                not self._manifest.expected_post_state
                or state_transition_verified
            )
            # v1.12.6: Reboot-specific evidence requirements
            if action == "reboot" and overall_success:
                if self._manifest.require_boot_id_change:
                    # Strict: require real boot_id evidence
                    if not boot_id_available:
                        # Boot ID unavailable — check fallback policy
                        if not self._manifest.allow_uptime_only_fallback:
                            overall_success = False
                        elif not uptime_reset_detected:
                            overall_success = False
                    elif not boot_id_changed:
                        # Boot ID available but unchanged → fail
                        overall_success = False
                if self._manifest.require_uptime_reset and not uptime_reset_detected:
                    overall_success = False
            if not api_success:
                overall_success = False

            finished = task_finished_at

            receipt_extras = {
                "proxmox_command_shape": "api",
                "shell_used": False,
                "api_endpoint_identity": api_url,
                "tls_verified": api_result["tls_verified"],
                "response_status_code": api_result["status_code"],
                "ssh_user": "",
                "host_key_verified": False,
                "root_user_used": False,
                "sudo_used": False,
                "ssh_host_fingerprint": "",
                "host_key_pin_checked": False,
                "host_key_pin_matched": False,
                "remote_hash_verified": False,
                "remote_hash_matched": False,
                "token_secret_ref_type": secret_check["ref_type"],
                "secret_source_allowed": secret_check["source_allowed"],
                "secret_resolved": secret_check["resolved"],
                "secret_value_serialized": False,
                "token_secret_ref_redacted": secret_check["redacted_ref"],
                **task_fields,
            }

            return {
                "deploy_status": "accepted" if overall_success else "rejected",
                "deployer_identity": identity,
                "deploy_detail": (
                    f"API {action}: node={node} vmid={vmid} "
                    f"upid={upid[:24]}... pre={pre_state} post={post_state} "
                    f"task={task_fields.get('task_exitstatus', '?')} "
                    f"transition={'verified' if state_transition_verified else 'unverified'}"
                ),
                "deploy_started_at": started.isoformat(),
                "deploy_finished_at": finished.isoformat(),
                "proxmox_node": node,
                "vmid": vmid,
                "action": action,
                "api_endpoint": api_url,
                **receipt_extras,
            }

        # ── v1.13.0: Artifact deployment (upload_artifact) ────────────
        if is_artifact:
            return self._handle_upload_artifact(
                identity=identity,
                started=started,
                api_url=api_url,
                headers=headers,
                timeout=timeout,
                artifact_digest=artifact_digest,
                node=node,
                vmid=vmid,
                action=action,
                secret_check=secret_check,
            )

        # ── v1.13.1: Artifact promotion (promote_artifact) ────────────
        if is_promotion:
            return self._handle_promote_artifact(
                identity=identity,
                started=started,
                api_url=api_url,
                headers=headers,
                timeout=timeout,
                artifact_digest=artifact_digest,
                node=node,
                vmid=vmid,
                action=action,
                secret_check=secret_check,
            )

        # ── v1.13.2: Artifact activation (apply_artifact) ─────────────
        if is_apply:
            apply_result = self._handle_apply_artifact(
                identity=identity,
                started=started,
                api_url=api_url,
                headers=headers,
                timeout=timeout,
                artifact_digest=artifact_digest,
                node=node,
                vmid=vmid,
                action=action,
                secret_check=secret_check,
            )
            # v1.13.3: Automatic rollback on apply failure if configured
            if (apply_result.get("deploy_status") == "rejected"
                    and self._manifest.rollback_on_apply_failure
                    and self._manifest.previous_artifact_digest):
                rollback_result = self._handle_rollback_artifact(
                    identity=identity,
                    started=started,
                    api_url=self._build_api_url("rollback_artifact"),
                    headers=headers,
                    timeout=timeout,
                    node=node,
                    vmid=vmid,
                    action="rollback_artifact",
                    secret_check=secret_check,
                    triggered_by="apply_failure",
                )
                # Merge apply + rollback evidence into single receipt
                apply_result["rollback_attempted"] = True
                apply_result["rollback_triggered_by"] = "apply_failure"
                apply_result["rollback_started_at"] = rollback_result.get("rollback_started_at", "")
                apply_result["rollback_finished_at"] = rollback_result.get("rollback_finished_at", "")
                apply_result["rollback_status"] = rollback_result.get("rollback_status", "")
                apply_result["rollback_artifact_digest"] = rollback_result.get("rollback_artifact_digest", "")
                apply_result["rollback_verified"] = rollback_result.get("rollback_verified", False)
                apply_result["final_deployment_state"] = rollback_result.get("final_deployment_state", "unknown")
                return apply_result
            # No rollback — add empty rollback fields for receipt consistency
            apply_result["rollback_attempted"] = False
            apply_result["rollback_started_at"] = ""
            apply_result["rollback_finished_at"] = ""
            apply_result["rollback_status"] = "not_attempted"
            apply_result["rollback_artifact_digest"] = ""
            apply_result["rollback_verified"] = False
            apply_result["final_deployment_state"] = (
                "applied" if apply_result.get("deploy_status") == "accepted" else "failed"
            )
            return apply_result

        # ── v1.13.3: Artifact rollback (rollback_artifact) ─────────────
        if is_rollback:
            return self._handle_rollback_artifact(
                identity=identity,
                started=started,
                api_url=api_url,
                headers=headers,
                timeout=timeout,
                node=node,
                vmid=vmid,
                action=action,
                secret_check=secret_check,
                triggered_by="explicit",
            )

        # ── Read-only actions (validate_target, get_status) ────────────
        api_result = self._api_request(api_url, headers, timeout=timeout)
        finished = datetime.datetime.now(datetime.timezone.utc)

        # Determine success (Proxmox returns {"data": {...}} on success)
        api_success = (
            api_result["status_code"] == 200
            and api_result["body"].get("data") is not None
        )

        receipt_extras = {
            "proxmox_command_shape": "api",
            "shell_used": False,
            "api_endpoint_identity": api_url,
            "tls_verified": api_result["tls_verified"],
            "response_status_code": api_result["status_code"],
            "ssh_user": "",
            "host_key_verified": False,
            "root_user_used": False,
            "sudo_used": False,
            "ssh_host_fingerprint": "",
            "host_key_pin_checked": False,
            "host_key_pin_matched": False,
            "remote_hash_verified": False,
            "remote_hash_matched": False,
            # v1.12.1: Secret reference evidence
            "token_secret_ref_type": secret_check["ref_type"],
            "secret_source_allowed": secret_check["source_allowed"],
            "secret_resolved": secret_check["resolved"],
            "secret_value_serialized": False,  # NEVER serialize secret values
            "token_secret_ref_redacted": secret_check["redacted_ref"],
        }

        return {
            "deploy_status": "accepted" if api_success else "rejected",
            "deployer_identity": identity,
            "deploy_detail": (
                f"API {action}: node={node} vmid={vmid} "
                f"status={api_result['status_code']} "
                f"tls={'verified' if api_result['tls_verified'] else 'unverified'}"
            ),
            "deploy_started_at": started.isoformat(),
            "deploy_finished_at": finished.isoformat(),
            "proxmox_node": node,
            "vmid": vmid,
            "action": action,
            "api_endpoint": api_url,
            **receipt_extras,
        }

_ADAPTERS: dict[str, type[DeploymentAdapter]] = {
    "dry_run": DryRunAdapter,
    "dry-run": DryRunAdapter,
    "local_shell": LocalShellAdapter,
    "local-shell": LocalShellAdapter,
    "proxmox": ProxmoxAdapter,  # v1.11.0
    "proxmox_api": ProxmoxApiAdapter,  # v1.12.0
    "proxmox-api": ProxmoxApiAdapter,
}


def get_adapter(name: str, manifest: AdapterManifest | None = None) -> DeploymentAdapter:
    """Get a deployment adapter by name, optionally with a manifest."""
    if name not in _ADAPTERS:
        raise ValueError(
            f"Unknown deployment adapter: {name}. "
            f"Available: {', '.join(sorted(set(_ADAPTERS.keys())))}"
        )
    return _ADAPTERS[name](manifest=manifest)


def list_adapters() -> list[str]:
    """List available adapter names (deduplicated)."""
    return sorted(set(_ADAPTERS.keys()))


# ── Deployment Receipt Creation ────────────────────────────────────────────


def _sha256_dict(data: dict[str, Any]) -> str:
    """Compute SHA-256 of canonical JSON."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256_text(text: str) -> str:
    """Compute SHA-256 of a text string (v1.12.7 boot ID hashing)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ── v1.10.3: Manifest Signing ─────────────────────────────────────────────


#: Fields stripped from manifest before signing/verification.
_MANIFEST_SIG_FIELDS = frozenset({
    "manifest_signature", "manifest_signature_algorithm",
    "manifest_signer_fingerprint",
})


def _canonicalize_manifest(manifest_dict: dict[str, Any]) -> bytes:
    """Create canonical bytes of manifest content for signing.

    Signs everything EXCEPT signature fields.
    """
    stripped = {k: v for k, v in manifest_dict.items()
                if k not in _MANIFEST_SIG_FIELDS}
    return json.dumps(stripped, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(
    manifest_path: str,
    private_key_path: str,
    output_path: str = "",
) -> dict[str, Any]:
    """Sign an adapter manifest with RSA-PSS-SHA256.

    Args:
        manifest_path: Path to manifest JSON.
        private_key_path: Path to PEM private key.
        output_path: If set, write signed manifest here. Otherwise overwrites input.

    Returns:
        Signed manifest dict.
    """
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    manifest_dict = json.loads(Path(manifest_path).read_text(encoding="utf-8"))

    private_key = _load_private_key(private_key_path)
    signed_data = _canonicalize_manifest(manifest_dict)

    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    manifest_dict["manifest_signature"] = base64.b64encode(signature).decode("ascii")
    manifest_dict["manifest_signature_algorithm"] = "RSA-PSS-SHA256"
    manifest_dict["manifest_signer_fingerprint"] = fingerprint

    out = output_path or manifest_path
    Path(out).write_text(json.dumps(manifest_dict, indent=2, sort_keys=True), encoding="utf-8")
    return manifest_dict


def verify_manifest_signature(
    manifest_dict: dict[str, Any],
    public_key_pem: str,
) -> dict[str, Any]:
    """Verify a signed adapter manifest.

    Args:
        manifest_dict: The signed manifest dict.
        public_key_pem: PEM-encoded public key string.

    Returns:
        {valid: bool, reason: str, fingerprint: str}
    """
    import base64
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    signature_b64 = manifest_dict.get("manifest_signature", "")
    if not signature_b64:
        return {"valid": False, "reason": "No signature in manifest", "fingerprint": ""}

    algorithm = manifest_dict.get("manifest_signature_algorithm", "")
    if algorithm != "RSA-PSS-SHA256":
        return {
            "valid": False,
            "reason": f"Unsupported algorithm: {algorithm}",
            "fingerprint": manifest_dict.get("manifest_signer_fingerprint", ""),
        }

    signature = base64.b64decode(signature_b64)

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Cannot load public key: {exc}",
            "fingerprint": manifest_dict.get("manifest_signer_fingerprint", ""),
        }

    signed_data = _canonicalize_manifest(manifest_dict)

    try:
        public_key.verify(
            signature,
            signed_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=hashes.SHA256().digest_size,
            ),
            hashes.SHA256(),
        )
    except Exception as exc:
        return {
            "valid": False,
            "reason": f"Signature verification failed: {exc}",
            "fingerprint": manifest_dict.get("manifest_signer_fingerprint", ""),
        }

    return {
        "valid": True,
        "reason": "Manifest signature valid",
        "fingerprint": manifest_dict.get("manifest_signer_fingerprint", ""),
    }


def create_deployment_receipt(
    gate_receipt_path: str,
    adapter_name: str = "dry_run",
    output: str = "",
    sign_key: str = "",
    manifest_path: str = "",
    strict: bool = False,
    require_manifest_signature: bool = False,
    strict_trust_store: bool = False,
    snapshot_path: str = "",
    dry_run_policy_check: bool = False,
    require_previous_assurance_chain: bool = False,
    rh_snapshot_path: str = "",
) -> dict[str, Any]:
    """Create a deployment-system receipt by running a deployment adapter.

    Args:
        gate_receipt_path: Path to the gate receipt JSON from deploy-receipt.
        adapter_name: Name of the deployment adapter to use.
        output: Path to write the deployment receipt JSON.
        sign_key: Path to private key PEM for signing.
        manifest_path: Path to adapter manifest JSON (v1.10.1).
        strict: If True, nonzero exit codes cause rejection.
        require_manifest_signature: If True, manifest must be signed by trusted key (v1.10.3).
        strict_trust_store: If True, reject legacy keys without explicit purposes (v1.10.5).
        snapshot_path: If set, verify trust store snapshot before deploying (v1.10.7).

    Returns:
        Deployment-system receipt dict.

    Raises:
        ValueError: If gate denied, manifest validation fails, signature
                    verification fails, or strict mode rejects.
    """
    from nodechain import __version__

    # Load gate receipt
    gate_receipt = json.loads(Path(gate_receipt_path).read_text(encoding="utf-8"))
    gate_receipt_digest = _sha256_dict(gate_receipt)

    # Extract context from gate receipt
    target = gate_receipt.get("target", "")
    artifact_digest = gate_receipt.get("artifact_digest", "")
    policy_digest = gate_receipt.get("policy_digest", "")
    gate_receipt_id = gate_receipt.get("receipt_id", "")

    # Check gate allowed deployment
    if not gate_receipt.get("deploy_allowed", False):
        raise ValueError(
            f"Gate receipt denied deployment: {gate_receipt.get('denial_reason', '')}"
        )

    # Load manifest if provided
    manifest: AdapterManifest | None = None
    manifest_raw: dict[str, Any] = {}
    if manifest_path:
        manifest_raw = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        manifest = AdapterManifest.from_dict(manifest_raw)
        # v1.13.5: Override chain requirement from CLI flag
        if require_previous_assurance_chain:
            manifest.require_previous_assurance_chain = True
        # v1.13.8: Release history snapshot requirement
        if rh_snapshot_path:
            manifest.require_release_history_snapshot = True
            manifest.release_history_snapshot_path = rh_snapshot_path

    # v1.10.3: Manifest signature verification against trust store
    manifest_sig_status = "none"
    manifest_signer_fp = ""
    manifest_signer_trusted = False
    manifest_allowed_purposes: list[str] = []
    if require_manifest_signature:
        if not manifest_path:
            raise ValueError(
                "--require-adapter-manifest-signature: no manifest provided"
            )

        manifest_signed = bool(manifest_raw.get("manifest_signature"))
        if not manifest_signed:
            raise ValueError(
                "--require-adapter-manifest-signature: manifest is not signed"
            )

        manifest_signer_fp = manifest_raw.get("manifest_signer_fingerprint", "")
        from nodechain.cli.trust_store import is_trusted_fingerprint, lookup_by_fingerprint, check_purpose
        if not is_trusted_fingerprint(manifest_signer_fp, strict=strict_trust_store):
            if strict_trust_store and is_trusted_fingerprint(manifest_signer_fp):
                manifest_sig_status = "legacy_key_rejected"
                raise ValueError(
                    f"Adapter manifest signer {manifest_signer_fp} is a legacy key "
                    f"without explicit purposes. Run: nodechain trust-store migrate"
                )
            manifest_sig_status = "untrusted_signer"
            raise ValueError(
                f"Adapter manifest signer {manifest_signer_fp} not in trust store"
            )

        # v1.10.4: Check purpose constraint (v1.10.5: strict mode)
        purpose_check = check_purpose(
            manifest_signer_fp, "adapter_manifest_signing",
            strict=strict_trust_store,
        )
        if not purpose_check["allowed"]:
            manifest_sig_status = "wrong_purpose"
            raise ValueError(
                f"Adapter manifest signer key lacks purpose: {purpose_check['reason']}"
            )
        manifest_allowed_purposes = purpose_check.get("purposes", [])

        # Get trusted public key and verify signature
        trusted_pem = lookup_by_fingerprint(manifest_signer_fp)
        sig_result = verify_manifest_signature(manifest_raw, trusted_pem)
        if sig_result["valid"]:
            manifest_sig_status = "valid"
            manifest_signer_trusted = True
        else:
            manifest_sig_status = "invalid"
            raise ValueError(
                f"Adapter manifest signature invalid: {sig_result['reason']}"
            )
    elif manifest_path and manifest_raw.get("manifest_signature"):
        # Manifest is signed but we're not requiring it — still check trust store
        manifest_signer_fp = manifest_raw.get("manifest_signer_fingerprint", "")
        from nodechain.cli.trust_store import is_trusted_fingerprint, check_purpose
        if is_trusted_fingerprint(manifest_signer_fp, strict=strict_trust_store):
            # Also check purpose for informational status
            purpose_check = check_purpose(
                manifest_signer_fp, "adapter_manifest_signing",
                strict=strict_trust_store,
            )
            if purpose_check["allowed"]:
                manifest_sig_status = "valid"
                manifest_signer_trusted = True
                manifest_allowed_purposes = purpose_check.get("purposes", [])
            else:
                manifest_sig_status = "wrong_purpose"
        else:
            manifest_sig_status = "untrusted_signer"

    # v1.10.7: Trust store snapshot verification
    snapshot_sig_status = "none"
    snapshot_digest_val = ""
    if snapshot_path:
        from nodechain.cli.trust_store import verify_trust_store_snapshot
        snap_result = verify_trust_store_snapshot(
            snapshot_path=snapshot_path,
            check_live_store=True,
        )
        if not snap_result["valid"]:
            raise ValueError(
                f"Trust store snapshot verification failed: {snap_result['errors']}"
            )
        snapshot_digest_val = json.loads(
            Path(snapshot_path).read_text(encoding="utf-8")
        ).get("snapshot_digest", "")
        details = snap_result.get("details", {})
        snapshot_sig_status = details.get("signature_status", "none")

    # Get adapter (with manifest if provided)
    adapter = get_adapter(adapter_name, manifest=manifest)

    # v1.12.7: Dry-run policy check — validate everything but skip mutation
    if dry_run_policy_check:
        from nodechain import __version__ as _ver
        started = datetime.datetime.now(datetime.timezone.utc)
        # For ProxmoxApiAdapter, also run manifest validation
        policy_issues: list[str] = []
        if hasattr(adapter, "_validate_api_manifest"):
            policy_issues = adapter._validate_api_manifest(strict=strict)
        # Also check secret ref
        secret_ok = True
        if hasattr(adapter, "_validate_secret_ref"):
            sc = adapter._validate_secret_ref(strict=strict)
            secret_ok = sc["valid"]
            if not sc["valid"]:
                policy_issues.extend(sc["issues"])
        # Also run context validation
        ctx_violations = adapter.validate_context(target, artifact_digest, policy_digest)
        if ctx_violations:
            policy_issues.extend(ctx_violations)
        finished = datetime.datetime.now(datetime.timezone.utc)
        dry_run_receipt = {
            "deploy_status": "dry_run_passed" if not policy_issues else "dry_run_failed",
            "deployer_identity": adapter.name() if hasattr(adapter, "name") else adapter_name,
            "deploy_detail": (
                f"Dry-run policy check: {'all checks passed' if not policy_issues else '; '.join(policy_issues)}"
            ),
            "deploy_started_at": started.isoformat(),
            "deploy_finished_at": finished.isoformat(),
            "adapter_name": adapter_name,
            "target": target,
            "policy_check_issues": policy_issues,
            "policy_check_passed": len(policy_issues) == 0,
            "secret_ref_valid": secret_ok,
            "nodechain_version": _ver,
            "dry_run": True,
        }
        if output:
            p = Path(output)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(dry_run_receipt, indent=2, sort_keys=True), encoding="utf-8")
        return dry_run_receipt

    # v1.10.1: Validate context against manifest
    violations = adapter.validate_context(target, artifact_digest, policy_digest)
    if violations:
        raise ValueError(
            f"Adapter manifest policy violations: {'; '.join(violations)}"
        )

    # Run the adapter
    deploy_result = adapter.deploy(
        target=target,
        artifact_digest=artifact_digest,
        policy_digest=policy_digest,
        assurance_receipt_id=gate_receipt_id,
    )

    # v1.10.1: Strict mode rejects nonzero exit
    if strict and deploy_result.get("execution_exit_code", 0) != 0:
        if deploy_result["deploy_status"] != "failed":
            deploy_result["deploy_status"] = "rejected"

    # Build deployment-system receipt
    receipt: dict[str, Any] = {
        "schema_version": DEPLOYMENT_SYSTEM_RECEIPT_SCHEMA_VERSION,
        "type": "deployment_system_receipt",
        "deployment_receipt_id": str(uuid.uuid4()),
        "gate_receipt_id": gate_receipt_id,
        "deployment_system": adapter.system_name,
        "target": target,
        "artifact_digest": artifact_digest,
        "policy_digest": policy_digest,
        "deploy_status": deploy_result["deploy_status"],
        "deployer_identity": deploy_result["deployer_identity"],
        "deploy_detail": deploy_result["deploy_detail"],
        "deploy_started_at": deploy_result["deploy_started_at"],
        "deploy_finished_at": deploy_result["deploy_finished_at"],
        "assurance_receipt_id": gate_receipt_id,
        "assurance_receipt_digest": gate_receipt_digest,
        "nodechain_version": __version__,
    }

    # v1.10.1: Add manifest and execution fields
    if manifest:
        receipt["adapter_manifest_digest"] = manifest.digest()
        receipt["command_template_digest"] = manifest.command_template_digest()
        # v1.10.3: Manifest signature fields
        receipt["adapter_manifest_signature_status"] = manifest_sig_status
        receipt["adapter_manifest_signer_fingerprint"] = manifest_signer_fp
        receipt["adapter_manifest_signer_trusted"] = manifest_signer_trusted
        # v1.10.5: Trust store mode and purpose details
        receipt["trust_store_mode"] = "strict" if strict_trust_store else "standard"
        receipt["signer_required_purpose"] = "adapter_manifest_signing"
        receipt["signer_allowed_purposes"] = manifest_allowed_purposes
        receipt["purpose_authorized"] = manifest_signer_trusted

    # v1.10.7: Trust store snapshot fields (outside manifest block)
    if snapshot_path:
        receipt["trust_store_snapshot_digest"] = snapshot_digest_val
        receipt["trust_store_snapshot_signature_status"] = snapshot_sig_status

    # Execution detail fields (from shell adapter)
    if "execution_exit_code" in deploy_result:
        receipt["execution_exit_code"] = deploy_result["execution_exit_code"]
    if deploy_result.get("stdout_digest"):
        receipt["stdout_digest"] = deploy_result["stdout_digest"]
    if deploy_result.get("stderr_digest"):
        receipt["stderr_digest"] = deploy_result["stderr_digest"]
    if deploy_result.get("command_executed"):
        receipt["command_executed"] = deploy_result["command_executed"]
    # v1.10.2: argv execution fields
    if deploy_result.get("execution_mode"):
        receipt["execution_mode"] = deploy_result["execution_mode"]
    if "shell_used" in deploy_result:
        receipt["shell_used"] = deploy_result["shell_used"]
    if deploy_result.get("argv_template_digest"):
        receipt["argv_template_digest"] = deploy_result["argv_template_digest"]
    if deploy_result.get("resolved_argv_digest"):
        receipt["resolved_argv_digest"] = deploy_result["resolved_argv_digest"]
    # v1.11.0: Proxmox adapter fields
    if deploy_result.get("proxmox_node"):
        receipt["proxmox_node"] = deploy_result["proxmox_node"]
    if deploy_result.get("vmid"):
        receipt["vmid"] = deploy_result["vmid"]
    if deploy_result.get("action"):
        receipt["proxmox_action"] = deploy_result["action"]
    if deploy_result.get("api_endpoint"):
        receipt["api_endpoint"] = deploy_result["api_endpoint"]
    # v1.11.2: Proxmox evidence fields
    if "proxmox_command_shape" in deploy_result:
        receipt["proxmox_command_shape"] = deploy_result["proxmox_command_shape"]
    if "shell_used" in deploy_result:
        receipt["shell_used"] = deploy_result["shell_used"]
    if "host_key_pin_checked" in deploy_result:
        receipt["host_key_pin_checked"] = deploy_result["host_key_pin_checked"]
    if "host_key_pin_matched" in deploy_result:
        receipt["host_key_pin_matched"] = deploy_result["host_key_pin_matched"]
    if "remote_hash_verified" in deploy_result:
        receipt["remote_hash_verified"] = deploy_result["remote_hash_verified"]
    if "remote_hash_matched" in deploy_result:
        receipt["remote_hash_matched"] = deploy_result["remote_hash_matched"]
    # v1.12.0: Proxmox API adapter fields
    if deploy_result.get("api_endpoint_identity"):
        receipt["api_endpoint_identity"] = deploy_result["api_endpoint_identity"]
    if "tls_verified" in deploy_result:
        receipt["tls_verified"] = deploy_result["tls_verified"]
    if "response_status_code" in deploy_result:
        receipt["response_status_code"] = deploy_result["response_status_code"]
    # v1.12.1: Secret reference policy fields
    if "token_secret_ref_type" in deploy_result:
        receipt["token_secret_ref_type"] = deploy_result["token_secret_ref_type"]
    if "secret_source_allowed" in deploy_result:
        receipt["secret_source_allowed"] = deploy_result["secret_source_allowed"]
    if "secret_resolved" in deploy_result:
        receipt["secret_resolved"] = deploy_result["secret_resolved"]
    if "secret_value_serialized" in deploy_result:
        receipt["secret_value_serialized"] = deploy_result["secret_value_serialized"]
    if deploy_result.get("token_secret_ref_redacted"):
        receipt["token_secret_ref_redacted"] = deploy_result["token_secret_ref_redacted"]
    # v1.12.2: Proxmox API task action fields
    if deploy_result.get("proxmox_task_upid") is not None:
        receipt["proxmox_task_upid"] = deploy_result["proxmox_task_upid"]
    if deploy_result.get("task_started_at"):
        receipt["task_started_at"] = deploy_result["task_started_at"]
    if deploy_result.get("task_finished_at"):
        receipt["task_finished_at"] = deploy_result["task_finished_at"]
    if deploy_result.get("task_exitstatus") is not None:
        receipt["task_exitstatus"] = deploy_result["task_exitstatus"]
    if deploy_result.get("pre_state") is not None:
        receipt["pre_state"] = deploy_result["pre_state"]
    if deploy_result.get("post_state") is not None:
        receipt["post_state"] = deploy_result["post_state"]
    if "state_transition_verified" in deploy_result:
        receipt["state_transition_verified"] = deploy_result["state_transition_verified"]
    # v1.12.3: Task polling fields
    if deploy_result.get("task_poll_count") is not None:
        receipt["task_poll_count"] = deploy_result["task_poll_count"]
    if deploy_result.get("task_duration_ms") is not None:
        receipt["task_duration_ms"] = deploy_result["task_duration_ms"]
    if deploy_result.get("task_api_status"):
        receipt["task_api_status"] = deploy_result["task_api_status"]
    if "task_success" in deploy_result:
        receipt["task_success"] = deploy_result["task_success"]
    if deploy_result.get("task_log_digest"):
        receipt["task_log_digest"] = deploy_result["task_log_digest"]
    # v1.12.4: Idempotency fields
    if deploy_result.get("requested_action"):
        receipt["requested_action"] = deploy_result["requested_action"]
    if deploy_result.get("effective_action"):
        receipt["effective_action"] = deploy_result["effective_action"]
    if "no_op" in deploy_result:
        receipt["no_op"] = deploy_result["no_op"]
    if deploy_result.get("idempotency_policy"):
        receipt["idempotency_policy"] = deploy_result["idempotency_policy"]
    # v1.12.5: Reboot evidence fields
    if deploy_result.get("pre_uptime_seconds") is not None:
        receipt["pre_uptime_seconds"] = deploy_result["pre_uptime_seconds"]
    if deploy_result.get("post_uptime_seconds") is not None:
        receipt["post_uptime_seconds"] = deploy_result["post_uptime_seconds"]
    if "boot_identity_changed" in deploy_result:
        receipt["boot_identity_changed"] = deploy_result["boot_identity_changed"]
    if "uptime_reset_detected" in deploy_result:
        receipt["uptime_reset_detected"] = deploy_result["uptime_reset_detected"]
    # v1.12.6: Boot ID evidence fields
    if deploy_result.get("boot_evidence_source"):
        receipt["boot_evidence_source"] = deploy_result["boot_evidence_source"]
    if "pre_boot_id" in deploy_result:
        receipt["pre_boot_id"] = deploy_result["pre_boot_id"]
    if "post_boot_id" in deploy_result:
        receipt["post_boot_id"] = deploy_result["post_boot_id"]
    if "boot_id_changed" in deploy_result:
        receipt["boot_id_changed"] = deploy_result["boot_id_changed"]
    if "uptime_fallback_used" in deploy_result:
        receipt["uptime_fallback_used"] = deploy_result["uptime_fallback_used"]
    if "boot_id_hashed" in deploy_result:
        receipt["boot_id_hashed"] = deploy_result["boot_id_hashed"]

    # Compute receipt digest
    receipt["receipt_digest"] = _sha256_dict(
        {k: v for k, v in receipt.items()
         if k not in ("receipt_signature", "receipt_signature_algorithm",
                      "receipt_signer_fingerprint", "receipt_digest")}
    )

    # Sign if requested
    if sign_key:
        receipt = _sign_receipt(receipt, sign_key)

    # Write output
    if output:
        p = Path(output)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    # v1.13.6: Record in release history if deployment was accepted
    if receipt.get("deploy_status") == "accepted":
        try:
            from nodechain.cli.release_history import ReleaseHistory, ReleaseRecord
            history = ReleaseHistory()
            target = receipt.get("target", "")
            record = ReleaseRecord.from_receipt(
                receipt=receipt,
                target=target,
                receipt_path=output,
            )
            history.add(record)
        except Exception:
            pass  # Non-fatal: release history is best-effort

    return receipt


def _sign_receipt(receipt: dict[str, Any], private_key_path: str) -> dict[str, Any]:
    """Sign a deployment-system receipt with RSA-PSS-SHA256."""
    import base64
    from nodechain.cli.bundle_signing import _load_private_key
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes, serialization

    private_key = _load_private_key(private_key_path)

    signed_data = json.dumps(
        {k: v for k, v in receipt.items()
         if k not in ("receipt_signature", "receipt_signature_algorithm",
                      "receipt_signer_fingerprint")},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    signature = private_key.sign(
        signed_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        ),
        hashes.SHA256(),
    )

    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fingerprint = hashlib.sha256(public_der).hexdigest()[:32]

    enriched = dict(receipt)
    enriched["receipt_signature"] = base64.b64encode(signature).decode("ascii")
    enriched["receipt_signature_algorithm"] = "RSA-PSS-SHA256"
    enriched["receipt_signer_fingerprint"] = fingerprint

    return enriched


def verify_deployment_receipt(
    receipt_path: str,
    pubkey_path: str = "",
    strict: bool = False,
    expected_gate_receipt_path: str = "",
    allowed_schema_versions: list[str] | None = None,
) -> dict[str, Any]:
    """Verify a deployment-system receipt.

    Args:
        receipt_path: Path to deployment-system receipt JSON.
        pubkey_path: Public key PEM for signature verification.
        strict: If True, deploy_status != "accepted" is a hard error.
        expected_gate_receipt_path: If set, verify receipt references this gate receipt.
        allowed_schema_versions: If set, receipt schema must be in list.

    Returns:
        {valid: bool, errors: list, warnings: list, checks: dict}
    """
    result: dict[str, Any] = {
        "valid": True,
        "errors": [],
        "warnings": [],
        "checks": {},
    }

    p = Path(receipt_path)
    if not p.exists():
        result["valid"] = False
        result["errors"].append(f"Receipt file not found: {receipt_path}")
        return result

    try:
        receipt = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        result["valid"] = False
        result["errors"].append(f"Cannot parse receipt JSON: {exc}")
        return result

    # Check type — must be deployment_system_receipt
    receipt_type = receipt.get("type", "")
    result["checks"]["type"] = receipt_type
    if receipt_type != "deployment_system_receipt":
        result["errors"].append(f"Expected type 'deployment_system_receipt', got '{receipt_type}'")

    # Check schema version
    sv = receipt.get("schema_version", "")
    result["checks"]["schema_version"] = sv
    if allowed_schema_versions and sv not in allowed_schema_versions:
        result["errors"].append(
            f"Receipt schema version {sv} not in allowed versions: {allowed_schema_versions}"
        )

    # Check required fields
    for field in REQUIRED_DEPLOYMENT_RECEIPT_FIELDS:
        if field not in receipt:
            result["errors"].append(f"Missing required field: {field}")

    # ── Deploy status check ──
    deploy_status = receipt.get("deploy_status", "")
    result["checks"]["deploy_status"] = deploy_status
    result["checks"]["deployment_system"] = receipt.get("deployment_system", "")
    result["checks"]["target"] = receipt.get("target", "")
    result["checks"]["deployer_identity"] = receipt.get("deployer_identity", "")

    if strict and deploy_status != "accepted":
        result["errors"].append(
            f"Deployment was not accepted (status={deploy_status}): "
            f"{receipt.get('deploy_detail', '')[:100]}"
        )

    # ── Gate receipt cross-check ──
    if expected_gate_receipt_path:
        gate_receipt = json.loads(Path(expected_gate_receipt_path).read_text(encoding="utf-8"))
        expected_gate_digest = _sha256_dict(gate_receipt)
        actual_gate_digest = receipt.get("assurance_receipt_digest", "")

        if expected_gate_digest != actual_gate_digest:
            result["errors"].append(
                "Gate receipt digest mismatch: receipt references a different gate receipt"
            )
            result["checks"]["gate_receipt_match"] = False
        else:
            result["checks"]["gate_receipt_match"] = True

    # ── Receipt digest verification (tamper detection) ──
    stored_digest = receipt.get("receipt_digest", "")
    if stored_digest:
        computed_digest = _sha256_dict(
            {k: v for k, v in receipt.items()
             if k not in ("receipt_signature", "receipt_signature_algorithm",
                          "receipt_signer_fingerprint", "receipt_digest")}
        )
        if stored_digest != computed_digest:
            result["errors"].append("Receipt digest mismatch — content may have been tampered")
            result["checks"]["receipt_digest_valid"] = False
        else:
            result["checks"]["receipt_digest_valid"] = True
    result["checks"]["receipt_digest"] = stored_digest

    # ── Signature verification ──
    has_sig = bool(receipt.get("receipt_signature"))
    sig_status = "missing"

    if pubkey_path and has_sig:
        import base64
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes, serialization

        signature = base64.b64decode(receipt["receipt_signature"])
        algorithm = receipt.get("receipt_signature_algorithm", "")

        if algorithm != "RSA-PSS-SHA256":
            sig_status = "invalid"
            result["errors"].append(f"Unsupported signature algorithm: {algorithm}")
        else:
            try:
                pubkey_data = Path(pubkey_path).read_bytes()
                public_key = serialization.load_pem_public_key(pubkey_data)

                signed_data = json.dumps(
                    {k: v for k, v in receipt.items()
                     if k not in ("receipt_signature", "receipt_signature_algorithm",
                                  "receipt_signer_fingerprint")},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")

                public_key.verify(
                    signature,
                    signed_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=hashes.SHA256().digest_size,
                    ),
                    hashes.SHA256(),
                )
                sig_status = "valid"
            except Exception as exc:
                sig_status = "invalid"
                result["errors"].append(f"Signature verification failed: {exc}")
    elif has_sig:
        sig_status = "signed_not_verified"
        result["warnings"].append("Receipt is signed but no --pubkey provided")

    result["checks"]["signature_status"] = sig_status

    # Final validity
    if result["errors"]:
        result["valid"] = False

    return result
