"""Schema packaging and runtime validation tests.

Verifies that JSON schemas are accessible from both source-checkout and
installed-package layouts, and that schema validation produces correct
results (not silent FileNotFoundError-masking).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from nodechain.validation.schema_validator import (
    SCHEMA_ROOT,
    SchemaValidator,
    _PACKAGE_SCHEMA_ROOT,
    _SOURCE_SCHEMA_ROOT,
)


class TestSchemaRootResolution:
    """Schema root must resolve to a real directory with schemas."""

    def test_schema_root_exists(self):
        """SCHEMA_ROOT must point to a directory that exists."""
        assert SCHEMA_ROOT.is_dir(), f"SCHEMA_ROOT {SCHEMA_ROOT} is not a directory"

    def test_schema_root_has_json_files(self):
        """SCHEMA_ROOT must contain at least one .json schema file."""
        json_files = list(SCHEMA_ROOT.rglob("*.json"))
        assert len(json_files) > 0, f"No JSON schemas found in {SCHEMA_ROOT}"

    def test_source_mode_resolves_repository_schemas(self):
        """In source mode, the source-tree schemas must be accessible."""
        # At least one of the two roots must exist
        assert _PACKAGE_SCHEMA_ROOT.is_dir() or _SOURCE_SCHEMA_ROOT.is_dir()


class TestSchemaValidation:
    """Schema validation must produce correct pass/fail results."""

    SENTINEL_REF = "nodechain://schemas/semantic_types/raw_user_query"

    def test_valid_payload_passes(self):
        """A known valid payload must pass validation."""
        sv = SchemaValidator()
        result = sv.validate(
            {"query": "release schema smoke"},
            self.SENTINEL_REF,
        )
        assert result.valid, f"Expected valid, got errors: {result.errors}"

    def test_invalid_payload_fails_with_schema_error(self):
        """An invalid payload must fail with a substantive schema error,
        not a 'Schema not found' error."""
        sv = SchemaValidator()
        result = sv.validate(
            {"query": ""},
            self.SENTINEL_REF,
        )
        assert not result.valid
        # The error must be schema-based, not file-missing
        assert not any("Schema not found" in e for e in result.errors), (
            f"Schema not found error indicates schemas are not packaged: {result.errors}"
        )

    def test_all_canonical_schemas_loadable(self):
        """All canonical schemas must be loadable as valid JSON Schema."""
        sv = SchemaValidator()
        errors = sv.validate_all_schemas_loadable()
        assert errors == [], f"Schema load errors: {errors}"

    def test_custom_schema_root_override(self):
        """A custom schema_root override must still work."""
        sv = SchemaValidator(schema_root=SCHEMA_ROOT)
        result = sv.validate(
            {"query": "test"},
            self.SENTINEL_REF,
        )
        assert result.valid


class TestSchemaSetParity:
    """The source schemas must match the packaged schemas dynamically."""

    def _get_source_schemas(self) -> set[str]:
        """Get relative schema paths from the repository schemas/ directory."""
        source_root = Path(__file__).resolve().parent.parent / "schemas"
        if not source_root.is_dir():
            pytest.skip("Source schemas/ directory not available")
        return {
            str(p.relative_to(source_root)).replace("\\", "/")
            for p in source_root.rglob("*.json")
        }

    def _get_package_schemas(self) -> set[str]:
        """Get relative schema paths from the installed package."""
        pkg_root = Path(__file__).resolve().parent.parent / "nodechain" / "schemas"
        if not pkg_root.is_dir():
            # In editable/source mode, package schemas map to source schemas
            return self._get_source_schemas()
        return {
            str(p.relative_to(pkg_root)).replace("\\", "/")
            for p in pkg_root.rglob("*.json")
        }

    def test_source_and_package_schema_sets_match(self):
        """Source and package schema sets must be identical."""
        source = self._get_source_schemas()
        package = self._get_package_schemas()
        assert source == package, (
            f"Schema set mismatch:\n"
            f"  source-only: {source - package}\n"
            f"  package-only: {package - source}"
        )

    def test_schema_count_at_least_21(self):
        """Sanity check: at least 21 canonical schemas expected."""
        source = self._get_source_schemas()
        assert len(source) >= 21, f"Expected >=21 schemas, got {len(source)}"
