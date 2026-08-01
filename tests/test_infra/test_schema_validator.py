"""Tests for schema validation."""

import pytest
from nodechain.validation.schema_validator import SchemaValidator


class TestSchemaValidator:
    def test_loads_existing_schema(self):
        validator = SchemaValidator()
        schema = validator.load_schema("nodechain://schemas/invocation_envelope")
        assert "properties" in schema

    def test_loads_semantic_type_schema(self):
        validator = SchemaValidator()
        schema = validator.load_schema("nodechain://schemas/semantic_types/raw_user_query")
        assert "properties" in schema

    def test_missing_schema_raises(self):
        validator = SchemaValidator()
        with pytest.raises(FileNotFoundError):
            validator.load_schema("nodechain://schemas/nonexistent")

    def test_valid_payload_passes(self):
        validator = SchemaValidator()
        result = validator.validate(
            {
                "run_id": "550e8400-e29b-41d4-a716-446655440000",
                "chain_id": "c1",
                "status": "running",
                "current_node": "goal_interpreter",
                "step": 1,
                "started_at": "2026-01-01T00:00:00Z",
                "outputs": {},
            },
            "nodechain://schemas/chain_state",
        )
        assert result.valid is True
        assert len(result.errors) == 0

    def test_invalid_payload_fails(self):
        validator = SchemaValidator()
        result = validator.validate(
            {"not_a_field": 123},
            "nodechain://schemas/chain_state",
        )
        assert result.valid is False
        assert len(result.errors) > 0

    def test_all_schemas_loadable(self):
        validator = SchemaValidator()
        errors = validator.validate_all_schemas_loadable()
        assert errors == [], f"Schema errors: {errors}"

    def test_result_repr(self):
        from nodechain.validation.schema_validator import SchemaValidationResult
        result = SchemaValidationResult(valid=True, errors=[], schema_ref="test")
        assert "VALID" in repr(result)

    def test_result_bool(self):
        from nodechain.validation.schema_validator import SchemaValidationResult
        assert SchemaValidationResult(valid=True, errors=[], schema_ref="test")
        assert not SchemaValidationResult(valid=False, errors=["x"], schema_ref="test")
