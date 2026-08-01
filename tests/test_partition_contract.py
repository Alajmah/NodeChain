"""Partition-contract test: privileged test classes/modules must carry native_sandbox.

This test prevents privileged tests from silently entering the portable
partition. Privileged test modules (where every test requires the native
sandbox runner) carry a module-level ``pytestmark``. Mixed modules carry
class-level ``@pytest.mark.native_sandbox`` on specific privileged classes.
"""

import ast
from pathlib import Path

import pytest

# Modules where EVERY test requires the native sandbox runner.
# These must carry module-level ``pytestmark = pytest.mark.native_sandbox``.
FULLY_PRIVILEGED_MODULES = [
    "tests/test_v351_h2_r3_supervised_execution.py",
    "tests/test_v351_h2_r3_stress.py",
    "tests/test_v351_h2_s3_adversarial.py",
]

# Mixed modules: specific classes that require native_sandbox.
# These must carry ``@pytest.mark.native_sandbox`` at the class level.
PRIVILEGED_CLASSES = {
    "tests/test_v351_h2_s3_supervisor_integration.py": [
        "TestSupervisorIntegration",
    ],
    "tests/test_v351_h2_s2_fd_isolation.py": [
        "TestIntegration",
    ],
    "tests/test_t2_workload_forwarding.py": [
        "TestT2PayloadForwarding",
        "TestT2DevNull",
        "TestT2WorkloadCwd",
        "TestT2NonexistentCwd",
        "TestT2ConflictingFdAuthority",
        "TestT2EarlyReaderExit",
        "TestT2SHandoffInjection",
        "TestT2IHandoffInjection",
        "TestT2FdReuseAdversarial",
        "TestT2BootstrapCwdStage",
    ],
    "tests/test_v351_h2_s32_characterization.py": [
        "TestRuntimeProcessGroupLocks",
    ],
    "tests/test_v351_h2_s32_task5_namespace_cleanup.py": [
        "TestRealDescendantCleanup",
    ],
    "tests/test_namespace_policy.py": [
        "TestPhysicalIsolation",
    ],
    "tests/test_namespace_confinement.py": [
        "TestNamespaceProfile",
    ],
}

# Specific functions that require native_sandbox (not whole classes).
PRIVILEGED_FUNCTIONS = {
    "tests/test_mount_namespace.py": [
        "test_mount_ns_inode_differs_in_subprocess",
    ],
    "tests/test_native_sandbox_enforcement.py": [
        # This module already has module-level pytestmark.
    ],
}


def _has_module_pytestmark(filepath: Path) -> bool:
    """Check for module-level pytestmark assignment."""
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return False
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "pytestmark":
                    return True
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "pytestmark":
                return True
    return False


def _class_has_native_sandbox(filepath: Path, class_name: str) -> bool:
    """Check whether a class has @pytest.mark.native_sandbox decorator."""
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return False
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for decorator in node.decorator_list:
                if ast.dump(decorator).replace('"', "'").find("native_sandbox") >= 0:
                    return True
            return False
    return False


def _function_has_native_sandbox(filepath: Path, func_name: str) -> bool:
    """Check whether a function has @pytest.mark.native_sandbox decorator."""
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == func_name:
            for decorator in node.decorator_list:
                if ast.dump(decorator).replace('"', "'").find("native_sandbox") >= 0:
                    return True
    return False


class TestPartitionContract:
    """Privileged test partitions must be correctly marked."""

    @pytest.mark.parametrize("module_rel", FULLY_PRIVILEGED_MODULES)
    def test_fully_privileged_module_has_module_pytestmark(self, module_rel: str):
        """Modules where every test needs privilege must have module-level pytestmark."""
        repo_root = Path(__file__).resolve().parent.parent
        filepath = repo_root / module_rel
        assert filepath.exists(), f"module not found: {module_rel}"
        assert _has_module_pytestmark(filepath), (
            f"{module_rel} should have module-level pytestmark = pytest.mark.native_sandbox"
        )

    @pytest.mark.parametrize(
        "module_rel,class_name",
        [(m, c) for m, classes in PRIVILEGED_CLASSES.items() for c in classes],
    )
    def test_privileged_class_has_native_sandbox(self, module_rel: str, class_name: str):
        """Privileged classes in mixed modules must have class-level marker."""
        repo_root = Path(__file__).resolve().parent.parent
        filepath = repo_root / module_rel
        assert filepath.exists(), f"module not found: {module_rel}"
        assert _class_has_native_sandbox(filepath, class_name), (
            f"{module_rel}::{class_name} must have @pytest.mark.native_sandbox decorator"
        )

    @pytest.mark.parametrize(
        "module_rel,func_name",
        [(m, f) for m, funcs in PRIVILEGED_FUNCTIONS.items() for f in funcs if funcs],
    )
    def test_privileged_function_has_native_sandbox(self, module_rel: str, func_name: str):
        """Privileged functions must have function-level marker."""
        repo_root = Path(__file__).resolve().parent.parent
        filepath = repo_root / module_rel
        assert filepath.exists(), f"module not found: {module_rel}"
        assert _function_has_native_sandbox(filepath, func_name), (
            f"{module_rel}::{func_name} must have @pytest.mark.native_sandbox decorator"
        )
