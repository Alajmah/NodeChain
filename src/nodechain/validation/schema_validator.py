"""Schema validation — loads and validates payloads against JSON schemas."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

# Schema root directory
SCHEMA_ROOT = Path(__file__).parent.parent.parent.parent / "schemas"


class SchemaValidator:
    """Loads JSON schemas from disk and validates payloads against them.

    Schemas are addressed by their schema_ref URI:
        nodechain://schemas/semantic_types/raw_user_query
    maps to: schemas/semantic_types/raw_user_query.json
    """

    def __init__(self, schema_root: Path | None = None):
        self.schema_root = schema_root or SCHEMA_ROOT
        self._cache: dict[str, dict[str, Any]] = {}

    def _resolve_path(self, schema_ref: str) -> Path:
        """Convert a schema_ref URI to a filesystem path."""
        if schema_ref.startswith("nodechain://schemas/"):
            relative = schema_ref[len("nodechain://schemas/"):]
            return self.schema_root / f"{relative}.json"
        # Allow direct relative paths too
        return self.schema_root / f"{schema_ref}.json"

    def load_schema(self, schema_ref: str) -> dict[str, Any]:
        """Load a schema from disk, caching the result."""
        if schema_ref in self._cache:
            return self._cache[schema_ref]

        path = self._resolve_path(schema_ref)
        if not path.exists():
            raise FileNotFoundError(f"Schema not found: {schema_ref} (looked at {path})")

        with open(path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        self._cache[schema_ref] = schema
        return schema



    def validate(self, payload: Any, schema_ref: str) -> SchemaValidationResult:
        """Validate a payload against a schema. Returns a result object."""
        try:
            schema = self.load_schema(schema_ref)
        except FileNotFoundError as e:
            return SchemaValidationResult(
                valid=False,
                errors=[str(e)],
                schema_ref=schema_ref,
            )

        # Pre-validate: normalize enum casing in the payload
        normalized_payload = self._normalize_enum_casing(payload, schema)

        validator = jsonschema.Draft202012Validator(schema)
        errors = list(validator.iter_errors(normalized_payload))

        if not errors:
            return SchemaValidationResult(
                valid=True,
                errors=[],
                schema_ref=schema_ref,
            )

        return SchemaValidationResult(
            valid=False,
            errors=[self._format_error(e) for e in errors],
            schema_ref=schema_ref,
        )

    def _normalize_enum_casing(self, data: Any, schema: dict[str, Any]) -> Any:
        """Recursively normalize string values that correspond to enum fields.
        Only normalizes if the schema declares an enum at that position,
        and only maps to values that actually appear in the enum.
        """
        if isinstance(data, dict) and isinstance(schema, dict):
            props = schema.get("properties", {})
            result = {}
            for key, value in data.items():
                prop_schema = props.get(key, {})
                if prop_schema.get("enum") and isinstance(value, str):
                    # This field has an enum constraint — try case-insensitive match
                    enum_values = prop_schema["enum"]
                    result[key] = self._match_enum(value, enum_values)
                else:
                    result[key] = self._normalize_enum_casing(value, prop_schema)
            return result
        elif isinstance(data, list) and isinstance(schema, dict):
            item_schema = schema.get("items", {})
            return [self._normalize_enum_casing(item, item_schema) for item in data]
        elif isinstance(data, str) and isinstance(schema, dict) and schema.get("enum"):
            return self._match_enum(data, schema["enum"])
        return data

    @staticmethod
    def _match_enum(value: str, enum_values: list[str]) -> str:
        """Match a value to an enum, case-insensitively.
        Returns the original value if no match found (validation will flag it).
        """
        value_lower = value.lower()
        for ev in enum_values:
            if ev.lower() == value_lower:
                return ev
        return value  # No match — let validation catch it

    def validate_all_schemas_loadable(self) -> list[str]:
        """Verify all schema files in the schema root are valid JSON Schema.
        Returns a list of errors (empty = all good).
        """
        errors: list[str] = []
        for path in sorted(self.schema_root.rglob("*.json")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    schema = json.load(f)
                # Verify it's valid JSON Schema by creating a validator
                jsonschema.Draft202012Validator.check_schema(schema)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in {path}: {e}")
            except jsonschema.SchemaError as e:
                errors.append(f"Invalid schema in {path}: {e.message}")
        return errors

    @staticmethod
    def _format_error(error: jsonschema.ValidationError) -> str:
        """Format a validation error into a human-readable string."""
        path = ".".join(str(p) for p in error.absolute_path) if error.absolute_path else "(root)"
        return f"{path}: {error.message}"


class SchemaValidationResult:
    """Result of a schema validation check."""

    def __init__(
        self,
        valid: bool,
        errors: list[str],
        schema_ref: str,
    ):
        self.valid = valid
        self.errors = errors
        self.schema_ref = schema_ref

    def __bool__(self) -> bool:
        return self.valid

    def __repr__(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return f"SchemaValidationResult({status}, schema={self.schema_ref}, errors={len(self.errors)})"
