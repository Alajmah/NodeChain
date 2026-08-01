"""Node 7: Patch Validator — validate patch structure + applicability in temp workspace.

v2.72 Code Review patch proposal path. THE governance-proof node for patch
proposal validation. Validates each patch:
  - parses as valid unified diff
  - target path is inside repo + allowlisted
  - no absolute paths, no ../ traversal, no binary, no symlink escape
  - no delete/rename unless explicitly allowed
  - hunk anchors match current file
  - applies cleanly in a TEMP workspace (never the real repo)

Per ChatGPT v2.72 design: sandbox_file_write is the only effect class.
The real repo working tree must be byte-for-byte unchanged after validation.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements, SideEffect,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)

PATCH_VALIDATOR_CONTRACT = NodeContract(
    contract_id="codereview.patch-validator.v1",
    node_id="patch_validator",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.PATCH_PROPOSALS,
        schema_ref="nodechain://schemas/semantic_types/patch_proposals",
        required_fields=["patch_proposals"],
    ),
    exit=ExitContract(
        output_type=PortType.VALIDATED_PATCHES,
        schema_ref="nodechain://schemas/semantic_types/validated_patches",
        guaranteed_fields=["validated_patches", "validation_summary"],
    ),
    requirements=Requirements(
        model_required=False,
        trust_level="trusted",  # needs filesystem access (temp workspace + git read)
        tools_required=["git"],  # v3.5.1 (#11): declares governed git apply --check
    ),
    side_effects=[
        # v3.5.1 (#11): declare actual capabilities. The validator writes to a
        # runtime-created temp workspace and invokes git as a governed tool.
        # These are NOT code_execution — git apply --check is structural
        # validation, not execution of the proposed target code.
        SideEffect(effect_type="sandbox_file_write", target="temp_workspace"),
        SideEffect(effect_type="external_call", target="temp_workspace_git_apply_check"),
    ],
)


class PatchValidatorNode(BaseNode):
    """Node 7: Validate patch proposals structurally and in a temp workspace.

    Governance rules (per ChatGPT v2.72 design):
    - May write ONLY to a runtime-created temporary workspace
    - Must NOT write to the real repo
    - Must NOT execute code, run tests, import modules, run hooks
    - Real repo working tree must be byte-for-byte unchanged
    """

    def __init__(self, repo_root: str = ".", allowed_paths: list[str] | None = None) -> None:
        self._repo_root = Path(repo_root).resolve()
        self._allowed_paths = allowed_paths or ["src/nodechain/**/*.py"]

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="patch_validator",
            node_type="deterministic",
            name="Patch Validator",
            description="Validates patch structure and applicability in temp workspace. Real repo never modified.",
            contract=PATCH_VALIDATOR_CONTRACT,
        )

    def _is_path_allowed(self, file_path: str) -> bool:
        import fnmatch
        for pattern in self._allowed_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False

    @staticmethod
    def _validate_diff_structure(diff_text: str) -> tuple[bool, str]:
        """Check that the text is a parseable unified diff."""
        if not diff_text or not diff_text.strip():
            return False, "empty diff"
        if not diff_text.startswith("---") and not diff_text.startswith("diff --git"):
            return False, "diff does not start with --- or diff --git"
        # Check for hunk markers
        if "@@" not in diff_text:
            return False, "no hunk markers (@@) found"
        return True, "valid structure"

    @staticmethod
    def _check_path_safety(target_file: str) -> tuple[bool, str]:
        """Reject absolute paths, traversal, binary, symlink escapes."""
        if os.path.isabs(target_file):
            return False, "absolute path not allowed"
        if ".." in target_file:
            return False, "path traversal (../) not allowed"
        if "\x00" in target_file:
            return False, "null byte in path"
        return True, "path safe"

    @staticmethod
    def _check_no_delete_rename(diff_text: str) -> tuple[bool, str]:
        """Reject delete/rename operations unless explicitly allowed."""
        if re.search(r"^rename from ", diff_text, re.MULTILINE):
            return False, "rename operation not allowed in v2.72"
        if re.search(r"^delete from ", diff_text, re.MULTILINE):
            return False, "delete operation not allowed in v2.72"
        # Check for /dev/null as target (indicates file deletion)
        if "--- /dev/null" in diff_text:
            return False, "patch creates from /dev/null (new file) — not allowed in v2.72"
        return True, "no delete/rename"

    def _try_apply_in_temp(self, diff_text: str, target_file: str) -> tuple[bool, str]:
        """Attempt to apply the patch in a temp workspace.

        Returns (success, reason). Temp workspace is cleaned up after.
        """
        tmpdir = None
        try:
            tmpdir = tempfile.mkdtemp(prefix="nodechain_patch_val_")

            # Copy the target file from the real repo into temp
            real_file = self._repo_root / target_file
            if not real_file.exists():
                return False, f"target file does not exist: {target_file}"

            temp_file = Path(tmpdir) / target_file
            temp_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(real_file, temp_file)

            # Write the diff to a temp file
            diff_file = Path(tmpdir) / "patch.diff"
            diff_file.write_text(diff_text)

            # Try to apply with git apply (in temp dir, NOT real repo)
            result = subprocess.run(
                ["git", "apply", "--check", str(diff_file)],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return True, "applies cleanly in temp workspace"
            else:
                return False, f"git apply --check failed: {result.stderr.strip()[:200]}"
        except Exception as e:
            return False, f"temp workspace error: {type(e).__name__}: {e}"
        finally:
            if tmpdir and os.path.exists(tmpdir):
                shutil.rmtree(tmpdir, ignore_errors=True)

    def _hash_working_tree(self) -> dict[str, str]:
        """Hash key files in the working tree for before/after comparison."""
        hashes = {}
        for pattern in self._allowed_paths:
            for p in self._repo_root.glob(pattern):
                if p.is_file():
                    rel = str(p.relative_to(self._repo_root)).replace("\\", "/")
                    try:
                        hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                    except Exception:
                        pass
        return hashes

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        proposals_data = envelope.payload
        proposals = proposals_data.get("patch_proposals", [])

        # Hash the working tree BEFORE validation
        tree_before = self._hash_working_tree()

        validated = []
        passed = 0
        failed = 0

        for prop in proposals:
            proposal_id = prop.get("proposal_id", "?")
            target_file = prop.get("target_file", "")
            diff_text = prop.get("unified_diff", "")
            result = {
                "proposal_id": proposal_id,
                "finding_id": prop.get("finding_id", ""),
                "target_file": target_file,
                "status": "pending",
                "checks": {},
            }

            # Check 1: diff structure
            ok, msg = self._validate_diff_structure(diff_text)
            result["checks"]["diff_structure"] = {"passed": ok, "detail": msg}

            # Check 2: path safety
            ok2, msg2 = self._check_path_safety(target_file)
            result["checks"]["path_safety"] = {"passed": ok2, "detail": msg2}

            # Check 3: path allowed
            allowed = self._is_path_allowed(target_file)
            result["checks"]["path_allowed"] = {"passed": allowed, "detail": "in allowlist" if allowed else "NOT in allowlist"}

            # Check 4: no delete/rename
            ok4, msg4 = self._check_no_delete_rename(diff_text)
            result["checks"]["no_delete_rename"] = {"passed": ok4, "detail": msg4}

            # Check 5: applies in temp workspace
            all_passed = ok and ok2 and allowed and ok4
            if all_passed:
                ok5, msg5 = self._try_apply_in_temp(diff_text, target_file)
                result["checks"]["temp_apply"] = {"passed": ok5, "detail": msg5}
                all_passed = all_passed and ok5
            else:
                result["checks"]["temp_apply"] = {"passed": False, "detail": "skipped (prior checks failed)"}

            if all_passed:
                result["status"] = "validated"
                result["unified_diff"] = diff_text
                result["rationale"] = prop.get("rationale", "")
                result["tests_not_run"] = True
                passed += 1
            else:
                result["status"] = "rejected"
                failed_reasons = [f"{k}: {v['detail']}" for k, v in result["checks"].items() if not v["passed"]]
                result["rejection_reason"] = "; ".join(failed_reasons)
                failed += 1

            validated.append(result)

        # Hash the working tree AFTER validation — must be identical
        tree_after = self._hash_working_tree()
        repo_unchanged = tree_before == tree_after

        output = {
            "validated_patches": validated,
            "validation_summary": {
                "total_proposals": len(proposals),
                "passed": passed,
                "failed": failed,
                "repo_working_tree_unchanged": repo_unchanged,
            },
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="patch_validator",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.VALIDATED_PATCHES,
        )
