"""v3.5.1 H1 — Fix #11: node governance declarations + validated-only patches.

Three defects:
1. PatchValidatorNode declares no side_effects but writes temp files and
   invokes ``git apply --check`` (an external process).
2. FileReaderNode markets governed Git/tool access but declares no
   ``tools_required`` and invokes git directly.
3. SandboxTestRunnerNode accepts any patch carrying a ``unified_diff`` field
   regardless of ``status``; the ``or "unified_diff" in p`` clause lets a
   rejected/pending patch execute.

v3.5.1 contract:
* PatchValidatorNode declares sandbox_file_write + external_call (git).
* FileReaderNode declares tools_required=["git"].
* SandboxTestRunnerNode accepts ONLY status == "validated".
* PatchValidator's git apply --check is governed tool execution + temp
  workspace mutation — NOT code_execution (reserved for pytest).

Written FIRST (RED).
"""

from __future__ import annotations

import pytest

from nodechain.nodes.patch_validator import PATCH_VALIDATOR_CONTRACT
from nodechain.nodes.file_reader import FILE_READER_CONTRACT


# ── 1. PatchValidatorNode declarations ────────────────────────────────────


class TestPatchValidatorDeclarations:
    def test_declares_sandbox_file_write(self):
        effect_types = {e.effect_type for e in PATCH_VALIDATOR_CONTRACT.side_effects}
        assert "sandbox_file_write" in effect_types, (
            f"PatchValidatorNode writes temp files but does not declare "
            f"sandbox_file_write; declared: {effect_types}"
        )

    def test_declares_external_call_for_git(self):
        effect_types = {e.effect_type for e in PATCH_VALIDATOR_CONTRACT.side_effects}
        assert "external_call" in effect_types, (
            f"PatchValidatorNode runs git apply --check but does not declare "
            f"external_call; declared: {effect_types}"
        )

    def test_does_not_declare_code_execution(self):
        """git apply --check is governed tool execution, NOT code_execution
        (which is reserved for the pytest execution node)."""
        effect_types = {e.effect_type for e in PATCH_VALIDATOR_CONTRACT.side_effects}
        assert "code_execution" not in effect_types, (
            "PatchValidatorNode must not declare code_execution; git apply --check "
            "is external_call + sandbox_file_write, not code execution."
        )


# ── 2. FileReaderNode declarations ────────────────────────────────────────


class TestFileReaderDeclarations:
    def test_declares_git_tool(self):
        tools = FILE_READER_CONTRACT.requirements.tools_required
        assert "git" in tools, (
            f"FileReaderNode invokes git directly but does not declare it; "
            f"tools_required: {tools}"
        )


# ── 3. SandboxTestRunner validated-only execution ─────────────────────────


class TestSandboxRunnerValidatedOnly:
    """The patch filter must accept ONLY status == 'validated'."""

    def _make_runner(self):
        from nodechain.nodes.sandbox_test_runner import SandboxTestRunnerNode
        return SandboxTestRunnerNode(repo_root=".", base_revision="HEAD")

    def test_rejected_patch_with_unified_diff_is_not_executed(self):
        """A patch with status='rejected' but a valid-looking unified_diff
        must NOT pass the filter (v3.5.0 let it through)."""
        import asyncio
        from nodechain.core.envelope import InvocationEnvelope

        runner = self._make_runner()
        envelope = InvocationEnvelope(
            payload={
                "classified_patches": [
                    {
                        "proposal_id": "p1",
                        "target_file": "src/x.py",
                        "status": "rejected",
                        "unified_diff": "--- a/src/x.py\n+++ b/src/x.py\n@@ -1,1 +1,1 @@\n-old\n+new\n",
                    }
                ]
            },
            run_id="r1", chain_id="c", node_id="sandbox_test_runner", step_id=1,
        )

        applied = []
        def fake_apply(ws, diff, target):
            applied.append(target)
            return (True, "ok")
        runner._apply_patch = fake_apply
        runner._hash_git_status = lambda: "before"
        runner._run_pytest = lambda ws: {"exit_code": 0, "stdout": "", "stderr": ""}

        asyncio.run(runner.execute(envelope))
        assert applied == [], (
            f"rejected patch was executed against: {applied}"
        )

    def test_pending_patch_with_unified_diff_is_not_executed(self):
        import asyncio
        from nodechain.core.envelope import InvocationEnvelope

        runner = self._make_runner()
        envelope = InvocationEnvelope(
            payload={
                "classified_patches": [
                    {
                        "proposal_id": "p2",
                        "target_file": "src/y.py",
                        "status": "pending",
                        "unified_diff": "--- a/src/y.py\n+++ b/src/y.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
                    }
                ]
            },
            run_id="r2", chain_id="c", node_id="sandbox_test_runner", step_id=1,
        )

        applied = []
        def fake_apply(ws, diff, target):
            applied.append(target)
            return (True, "ok")
        runner._apply_patch = fake_apply
        runner._hash_git_status = lambda: "before"
        runner._run_pytest = lambda ws: {"exit_code": 0, "stdout": "", "stderr": ""}

        asyncio.run(runner.execute(envelope))
        assert applied == [], (
            f"pending patch was executed against: {applied}"
        )

    def test_validated_patch_still_executes(self):
        """The validated path must still work after tightening the filter."""
        import asyncio
        from nodechain.core.envelope import InvocationEnvelope

        runner = self._make_runner()
        envelope = InvocationEnvelope(
            payload={
                "classified_patches": [
                    {
                        "proposal_id": "p3",
                        "target_file": "src/z.py",
                        "status": "validated",
                        "unified_diff": "--- a/src/z.py\n+++ b/src/z.py\n@@ -1,1 +1,1 @@\n-a\n+b\n",
                    }
                ]
            },
            run_id="r3", chain_id="c", node_id="sandbox_test_runner", step_id=1,
        )

        applied = []
        def fake_apply(ws, diff, target):
            applied.append(target)
            return (True, "ok")
        runner._apply_patch = fake_apply
        runner._hash_git_status = lambda: "before"
        runner._run_pytest = lambda ws: {"exit_code": 0, "stdout": "", "stderr": ""}

        asyncio.run(runner.execute(envelope))
        assert applied == ["src/z.py"], (
            f"validated patch should execute; got {applied}"
        )
