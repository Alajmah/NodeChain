#!/usr/bin/env python3
"""Validate all JSON schemas in the schemas/ directory."""

import sys
from pathlib import Path

# Add src to path so we can import nodechain
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from nodechain.validation.schema_validator import SchemaValidator


def main() -> int:
    schema_root = Path(__file__).parent.parent / "schemas"
    validator = SchemaValidator(schema_root)

    print(f"Validating schemas in: {schema_root}")
    print()

    # Count schemas
    schema_files = list(schema_root.rglob("*.json"))
    print(f"Found {len(schema_files)} schema files")

    # Validate all schemas are loadable and valid JSON Schema
    errors = validator.validate_all_schemas_loadable()

    if errors:
        print(f"\n[ERROR] {len(errors)} error(s):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print(f"[OK] All {len(schema_files)} schemas are valid JSON Schema (Draft 2020-12)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
