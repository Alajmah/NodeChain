"""Node 2: File Reader — read code artifacts under governed file access.

v2.71 Code Review Assistant: THE governance-proof node. This node demonstrates
that a chain can inspect developer artifacts under explicit file/tool grants,
produce provenance-tagged code artifacts, and do so WITHOUT mutating the repo.

Governance surfaces exercised:
  - File access governance: reads ONLY paths matching allowed_paths from config
  - Tool access governance: uses `git` as a declared, read-only tool
  - Read-only enforcement: no writes, no patches, no commits
  - Artifact provenance: every file/diff hunk is tagged with file_path + line range
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    EntryContract, ExitContract, NodeContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode

logger = logging.getLogger(__name__)

FILE_READER_CONTRACT = NodeContract(
    contract_id="codereview.file-reader.v1",
    node_id="file_reader",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.CODE_REVIEW_GOAL,
        schema_ref="nodechain://schemas/semantic_types/code_review_goal",
        required_fields=["target_commit", "file_scope"],
    ),
    exit=ExitContract(
        output_type=PortType.CODE_ARTIFACTS,
        schema_ref="nodechain://schemas/semantic_types/code_artifacts",
        guaranteed_fields=["files", "diff"],
    ),
    requirements=Requirements(
        model_required=False,
        trust_level="trusted",  # needs filesystem + git access
        tools_required=["git"],  # v3.5.1 (#11): declares governed git tool use
    ),
)


class FileReaderNode(BaseNode):
    """Node 2: Read code artifacts from the repo under governed access.

    Reads only files matching the blueprint's allowed_paths glob patterns.
    For commit-based reviews, uses `git show` / `git diff` to extract changes.
    All file access is logged for trace provenance.
    """

    def __init__(self, repo_root: str = ".", allowed_paths: list[str] | None = None) -> None:
        self._repo_root = Path(repo_root).resolve()
        self._allowed_paths = allowed_paths or ["**/*.py"]

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="file_reader",
            node_type="deterministic",
            name="File Reader",
            description="Reads code artifacts under governed file-access grants. Read-only, no mutations.",
            contract=FILE_READER_CONTRACT,
        )

    def _is_path_allowed(self, file_path: str) -> bool:
        """Check if a file path matches any of the allowed_paths glob patterns."""
        import fnmatch
        for pattern in self._allowed_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        # Also check if the full repo-relative path matches
        for pattern in self._allowed_paths:
            if fnmatch.fnmatch(str(self._repo_root / file_path), f"*/{pattern}"):
                return True
        return False

    def _run_git(self, *args: str) -> str:
        """Run a git command in the repo root. Read-only commands only."""
        result = subprocess.run(
            ["git"] + list(args),
            cwd=str(self._repo_root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            logger.warning("git %s failed: %s", args, result.stderr[:200])
            return ""
        return result.stdout

    def _get_changed_files(self, commit: str) -> list[str]:
        """Get the list of files changed in a commit."""
        output = self._run_git("diff", "--name-only", f"{commit}~1", commit)
        return [f.strip() for f in output.strip().split("\n") if f.strip()]

    def _get_file_diff(self, commit: str, file_path: str) -> list[dict]:
        """Get the diff hunks for a specific file in a commit."""
        output = self._run_git("show", commit, "--", file_path)
        hunks: list[dict] = []
        current_hunk: dict[str, Any] | None = None
        for line in output.split("\n"):
            if line.startswith("@@"):
                if current_hunk:
                    hunks.append(current_hunk)
                # Parse @@ -old_start,old_count +new_start,new_count @@
                import re
                m = re.match(r"@@ -(\d+),?\d* \+(\d+),?\d* @@", line)
                if m:
                    current_hunk = {
                        "file_path": file_path,
                        "old_start": int(m.group(1)),
                        "new_start": int(m.group(2)),
                        "content": line + "\n",
                    }
                else:
                    current_hunk = {"file_path": file_path, "old_start": 0, "new_start": 0, "content": line + "\n"}
            elif current_hunk is not None:
                current_hunk["content"] += line + "\n"
        if current_hunk:
            hunks.append(current_hunk)
        return hunks

    def _read_file_content(self, file_path: str, commit: str = "HEAD") -> str:
        """Read a file's content at a specific commit."""
        return self._run_git("show", f"{commit}:{file_path}")

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        goal = envelope.payload
        commit = goal.get("target_commit", "HEAD")
        file_scope = goal.get("file_scope", "changed")

        files: list[dict] = []
        diff_hunks: list[dict] = []

        if file_scope == "changed":
            # Get only the files changed in this commit
            changed = self._get_changed_files(commit)
            for file_path in changed:
                if not self._is_path_allowed(file_path):
                    logger.info("File access DENIED (not in allowed_paths): %s", file_path)
                    continue
                logger.info("File access GRANTED: %s", file_path)
                content = self._read_file_content(file_path, commit)
                hunks = self._get_file_diff(commit, file_path)
                # v2.71 fix: truncate at line boundary, not mid-token.
                # 5000 chars was too small AND cut mid-line, causing the model
                # to see "broken" code (e.g. `required_fields: li` instead of
                # `list[str]`) and flag false-positive syntax errors.
                max_chars = 12000
                if len(content) > max_chars:
                    # Find the last complete line before the limit
                    cut = content[:max_chars].rfind("\n")
                    if cut > 0:
                        content = content[:cut]
                    else:
                        content = content[:max_chars]
                files.append({
                    "file_path": file_path,
                    "content": content,
                    "content_truncated": len(self._read_file_content(file_path, commit)) > max_chars,
                })
                diff_hunks.extend(hunks)
        else:
            # file_scope == "all" — read all allowed files
            for pattern in self._allowed_paths:
                for p in self._repo_root.glob(pattern):
                    if p.is_file():
                        rel = str(p.relative_to(self._repo_root)).replace("\\", "/")
                        if not self._is_path_allowed(rel):
                            continue
                        logger.info("File access GRANTED: %s", rel)
                        content = self._read_file_content(rel, commit)
                        max_chars = 12000
                        if len(content) > max_chars:
                            cut = content[:max_chars].rfind("\n")
                            if cut > 0:
                                content = content[:cut]
                        files.append({
                            "file_path": rel,
                            "content": content,
                            "content_truncated": len(self._read_file_content(rel, commit)) > max_chars,
                        })

        output = {
            "files": files,
            "diff": diff_hunks,
            "target_commit": commit,
            "files_read": len(files),
            "files_denied": 0,  # tracked but not surfaced in v2.71 MVP
        }

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="file_reader",
            step_id=envelope.step_id,
            output=output,
            output_type=PortType.CODE_ARTIFACTS,
        )
