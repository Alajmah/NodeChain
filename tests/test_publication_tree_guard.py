"""Tests for the permanent publication-tree hygiene guard.

These tests exercise the classification logic directly and the exit-code
contract of ``scripts/check_publication_tree.py``. They do not depend on the
state of the working tree; the guard's source of truth is the committed tree
selected via ``--ref``.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_publication_tree.py"


def _load_guard():
    """Load the guard module from its file path (keeps tests path-independent)."""
    spec = importlib.util.spec_from_file_location("check_publication_tree", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def guard():
    return _load_guard()


class TestClassifyCleanPaths:
    """Paths that must NOT be flagged as violations."""

    @pytest.mark.parametrize(
        "path",
        [
            "src/nodechain/app.py",
            "tests/test_something.py",
            "docs/architecture.md",
            "README.md",
            "data/v2.70_baseline/frozen_comparison_fixture.json",
            "scripts/check_publication_tree.py",
            # ordinary parenthesized names are NOT browser duplicates
            "docs/section_(notes).md",
            "name(v2).md",
            "(intro).md",
            # numeric-in-parens without leading space is not a duplicate
            "config(v1).yaml",
        ],
    )
    def test_clean_path_has_no_violations(self, guard, path):
        assert guard._classify(path) == []

    def test_dbconfig_is_not_a_db_file(self, guard):
        # extension matching must not be a substring match
        assert guard._classify("etc/x.dbconfig") == []

    def test_zero_and_zero_padded_not_duplicates(self, guard):
        # "(0)" and "(01)" are not the browser duplicate scheme (starts at 1)
        assert guard._classify("a (0).md") == []
        assert guard._classify("a (01).md") == []


class TestClassifyForbiddenDirectories:
    @pytest.mark.parametrize(
        "path,segment",
        [
            (".ouroboros/state.db", ".ouroboros"),
            (".ouroboros/inner/trace.log", ".ouroboros"),
            (".zcode/plans/plan-x.md", ".zcode"),
            (".nodechain/eval/latest.json", ".nodechain"),
            (".benchmarks/run1/out.json", ".benchmarks"),
            ("src/.zcode/sneaky.py", ".zcode"),  # segment anywhere in path
        ],
    )
    def test_forbidden_directory_rejected(self, guard, path, segment):
        rules = guard._classify(path)
        assert any(segment in r for r in rules), (path, rules)


class TestClassifyDatabaseExtensions:
    @pytest.mark.parametrize("ext", [".db", ".sqlite", ".sqlite3"])
    def test_lowercase_db_extension_rejected(self, guard, ext):
        assert guard._classify(f"cache/data{ext}") != []

    @pytest.mark.parametrize("ext", [".DB", ".SQLITE", ".Sqlite3"])
    def test_db_extension_case_insensitive(self, guard, ext):
        assert guard._classify(f"cache/data{ext}") != []

    def test_db_extension_only_on_basename(self, guard):
        # a directory named "db" must not trigger the extension rule
        # (it is not a forbidden directory either, so this should pass)
        assert guard._classify("src/db/loader.py") == []


class TestClassifyStrayArtifact:
    def test_sandbox_test_output_rejected(self, guard):
        rules = guard._classify("sandbox_test_output.txt")
        assert any("sandbox_test_output" in r for r in rules)

    def test_sandbox_test_output_in_subdir_not_flagged_as_stray(self, guard):
        # the exact-name rule matches the basename, so a nested copy is also
        # rejected (this is intentional — it is a forbidden artifact anywhere)
        rules = guard._classify("tmp/sandbox_test_output.txt")
        assert any("sandbox_test_output" in r for r in rules)


class TestClassifyBrowserDuplicates:
    @pytest.mark.parametrize(
        "path",
        [
            "Name (1).md",
            "NodeChain_Reference_Implementation (1).md",
            "a/b (2).py",
            "report (10).pdf",
            "archive (3).tar.gz",
        ],
    )
    def test_browser_duplicate_rejected(self, guard, path):
        rules = guard._classify(path)
        assert any("duplicate" in r for r in rules), (path, rules)


class TestFullGuardIntegration:
    """End-to-end exit-code contract via the module's main()."""

    def test_multiple_violations_sorted_and_reported(self, guard, capsys):
        # monkeypatch _list_tree to avoid touching git
        orig = guard._list_tree
        guard._list_tree = lambda ref: [
            "zfile.md",
            ".zcode/a.md",
            ".ouroboros/state.db",
            "sandbox_test_output.txt",
            "Name (1).md",
        ]
        try:
            rc = guard.main(["--ref", "HEAD"])
            captured = capsys.readouterr().out
        finally:
            guard._list_tree = orig

        assert rc == 1
        lines = [ln for ln in captured.splitlines() if ln.strip()]
        # sorted by path
        paths = [ln.split("\t")[0] for ln in lines]
        assert paths == sorted(paths)
        # every violation present
        assert ".zcode/a.md" in paths
        assert ".ouroboros/state.db" in paths
        assert "sandbox_test_output.txt" in paths
        assert "Name (1).md" in paths
        # clean path absent
        assert "zfile.md" not in paths

    def test_clean_tree_returns_zero(self, guard, capsys):
        orig = guard._list_tree
        guard._list_tree = lambda ref: ["src/a.py", "docs/b.md", "README.md"]
        try:
            rc = guard.main(["--ref", "HEAD"])
            out = capsys.readouterr().out
        finally:
            guard._list_tree = orig
        assert rc == 0
        assert out == ""


class TestGitFailureExitCode:
    def test_git_failure_exits_two(self, guard, monkeypatch):
        def _boom(ref):
            raise SystemExit(2)

        # _list_tree calls sys.exit(2) on git failure; ensure main propagates it
        monkeypatch.setattr(guard, "_list_tree", _boom)
        with pytest.raises(SystemExit) as exc:
            guard.main(["--ref", "HEAD"])
        assert exc.value.code == 2


class TestScriptCli:
    """Exercise the actual script file via subprocess to validate the contract."""

    def test_help_exits_zero(self):
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0
        assert "publication" in proc.stdout.lower() or "ref" in proc.stdout.lower()

    def test_bad_ref_does_not_silently_pass(self):
        # an invalid ref must produce exit 2 (git error), never 0
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--ref", "this-ref-cannot-exist-zzz"],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 2
        assert "failed" in proc.stderr.lower() or "ls-tree" in proc.stderr.lower()
