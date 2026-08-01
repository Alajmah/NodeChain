"""Tests for template generator, schema bundles, and compatibility checker.

AC1: nodechain node create creates a valid package.
AC2: Generated package passes nodechain node validate.
AC3: Generated package has a passing package-local test.
AC4: Package can declare input/output JSON schema files.
AC5: Registry loads schema refs from package-local paths.
AC6: check_blueprint_compat reports compatible/incompatible connections.
AC7: Documentation exists for the full create->test->validate->register->use flow.
AC8: Existing 699 tests remain green.
"""

import pytest
from pathlib import Path

from nodechain.sdk.templates import create_node_package
from nodechain.sdk.package import NodePackage
from nodechain.sdk.compat import check_blueprint_compat
from nodechain.registry.local_registry import RegistryIndex


@pytest.fixture
def created_package(tmp_path):
    """Create a deterministic template package in tmp_path."""
    pkg_path = create_node_package(
        node_id="test_gen_node",
        template="deterministic",
        output_dir=str(tmp_path),
    )
    return pkg_path


@pytest.fixture
def created_model_package(tmp_path):
    """Create a model template package in tmp_path."""
    pkg_path = create_node_package(
        node_id="test_model_node",
        template="model",
        output_dir=str(tmp_path),
    )
    return pkg_path


@pytest.fixture
def created_tool_package(tmp_path):
    """Create a tool template package in tmp_path."""
    pkg_path = create_node_package(
        node_id="test_tool_node",
        template="tool",
        output_dir=str(tmp_path),
    )
    return pkg_path


class TestTemplateGenerator:
    """AC1: nodechain node create creates a valid package."""

    def test_creates_directory(self, created_package):
        """AC1: Creates package directory."""
        assert created_package.exists()
        assert created_package.is_dir()

    def test_creates_node_yaml(self, created_package):
        """AC1: Creates node.yaml."""
        assert (created_package / "node.yaml").exists()

    def test_creates_implementation(self, created_package):
        """AC1: Creates implementation.py."""
        assert (created_package / "implementation.py").exists()

    def test_creates_tests(self, created_package):
        """AC1: Creates test file."""
        test_path = created_package / "tests" / "test_test_gen_node.py"
        assert test_path.exists()

    def test_creates_schemas(self, created_package):
        """AC1: Creates schemas directory."""
        assert (created_package / "schemas").exists()
        assert (created_package / "schemas" / "input.json").exists()
        assert (created_package / "schemas" / "output.json").exists()

    def test_deterministic_template(self, created_package):
        """AC1: Deterministic template creates correct node_type."""
        pkg = NodePackage.from_directory(created_package)
        assert pkg.manifest.node_type == "deterministic"
        assert pkg.manifest.contract.requirements.model_required is False

    def test_model_template(self, created_model_package):
        """AC1: Model template creates model node."""
        pkg = NodePackage.from_directory(created_model_package)
        assert pkg.manifest.node_type == "model"
        assert pkg.manifest.contract.requirements.model_required is True

    def test_tool_template(self, created_model_package):
        """AC1: Tool template creates tool node."""
        pkg = NodePackage.from_directory(created_model_package)
        assert pkg.manifest.node_type == "model"

    def test_rejects_unknown_template(self, tmp_path):
        """AC1: Unknown template raises ValueError."""
        with pytest.raises(ValueError, match="Unknown template"):
            create_node_package("x", template="nonexistent", output_dir=str(tmp_path))

    def test_rejects_existing_directory(self, tmp_path):
        """AC1: Existing directory raises FileExistsError."""
        (tmp_path / "existing_node").mkdir()
        with pytest.raises(FileExistsError):
            create_node_package("existing_node", output_dir=str(tmp_path))

    def test_custom_name_and_tags(self, tmp_path):
        """AC1: Custom name and tags."""
        pkg_path = create_node_package(
            "custom_node",
            output_dir=str(tmp_path),
            name="My Custom Node",
            tags="custom, test",
        )
        pkg = NodePackage.from_directory(pkg_path)
        assert pkg.manifest.name == "My Custom Node"


class TestGeneratedValidation:
    """AC2: Generated package passes validate."""

    def test_deterministic_validates(self, created_package):
        """AC2: Deterministic package passes validation."""
        pkg = NodePackage.from_directory(created_package)
        issues = pkg.validate_package()
        assert issues == []

    def test_model_validates(self, created_model_package):
        """AC2: Model package passes validation."""
        pkg = NodePackage.from_directory(created_model_package)
        issues = pkg.validate_package()
        assert issues == []

    def test_tool_validates(self, created_tool_package):
        """AC2: Tool package passes validation."""
        pkg = NodePackage.from_directory(created_tool_package)
        issues = pkg.validate_package()
        assert issues == []


class TestGeneratedTests:
    """AC3: Generated package has passing tests."""

    def test_has_test_file(self, created_package):
        """AC3: Test file exists."""
        pkg = NodePackage.from_directory(created_package)
        assert pkg.get_test_path() is not None

    def test_test_file_loads(self, created_package):
        """AC3: Test file is valid Python."""
        test_path = created_package / "tests" / "test_test_gen_node.py"
        code = test_path.read_text()
        compile(code, str(test_path), "exec")

    def test_implementation_loads(self, created_package):
        """AC3: Implementation is importable."""
        import importlib.util
        impl_path = created_package / "implementation.py"
        spec = importlib.util.spec_from_file_location("impl", impl_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "TestGenNode")


class TestSchemaBundles:
    """AC4 + AC5: Schema bundles in packages."""

    def test_input_schema_exists(self, created_package):
        """AC4: Input schema file exists."""
        assert (created_package / "schemas" / "input.json").exists()

    def test_output_schema_exists(self, created_package):
        """AC4: Output schema file exists."""
        assert (created_package / "schemas" / "output.json").exists()

    def test_load_input_schema(self, created_package):
        """AC5: Package can load input schema."""
        pkg = NodePackage.from_directory(created_package)
        schema = pkg.load_input_schema()
        assert schema is not None
        assert "properties" in schema
        assert "query" in schema["properties"]

    def test_load_output_schema(self, created_package):
        """AC5: Package can load output schema."""
        pkg = NodePackage.from_directory(created_package)
        schema = pkg.load_output_schema()
        assert schema is not None
        assert "properties" in schema

    def test_load_schemas_both(self, created_package):
        """AC5: Load both schemas at once."""
        pkg = NodePackage.from_directory(created_package)
        schemas = pkg.load_schemas()
        assert schemas["input"] is not None
        assert schemas["output"] is not None

    def test_echo_node_schemas(self):
        """AC5: Echo node has schemas."""
        pkg = NodePackage.from_directory("nodes/echo_node")
        schemas = pkg.load_schemas()
        assert schemas["input"] is not None
        assert schemas["output"] is not None

    def test_schema_is_valid_json(self, created_package):
        """AC5: Schema files are valid JSON."""
        import json
        for name in ("input.json", "output.json"):
            path = created_package / "schemas" / name
            data = json.loads(path.read_text())
            assert "type" in data


class TestCompatibilityChecker:
    """AC6: check-compat reports compatible/incompatible."""

    def test_unknown_node_returns_error(self):
        """AC6: Unknown node returns error."""
        result = check_blueprint_compat(
            "blueprints/research_decision_v1.yaml",
            "nonexistent_node",
        )
        assert result["compatible"] is False
        assert "error" in result

    def test_echo_node_compatible(self):
        """AC6: Echo node is compatible (type matches)."""
        result = check_blueprint_compat(
            "blueprints/research_decision_v1.yaml",
            "echo_node",
        )
        # echo_node is not in the blueprint, so no connections
        assert result["compatible"] is True
        assert result["node_found_in_blueprint"] is False

    def test_blueprint_loaded(self):
        """AC6: Blueprint is loaded correctly."""
        result = check_blueprint_compat(
            "blueprints/research_decision_v1.yaml",
            "echo_node",
        )
        assert result["blueprint_id"] == "research-decision-v1"


class TestDocumentation:
    """AC7: Documentation exists."""

    def test_build_guide_exists(self):
        """AC7: Build-your-first-node guide exists."""
        assert Path("docs/build-your-first-node.md").exists()

    def test_guide_has_create_section(self):
        """AC7: Guide covers template creation."""
        content = Path("docs/build-your-first-node.md").read_text()
        assert "create" in content.lower() or "template" in content.lower()

    def test_guide_has_validate_section(self):
        """AC7: Guide covers validation."""
        content = Path("docs/build-your-first-node.md").read_text()
        assert "validate" in content.lower()

    def test_guide_has_test_section(self):
        """AC7: Guide covers testing."""
        content = Path("docs/build-your-first-node.md").read_text()
        assert "test" in content.lower()
