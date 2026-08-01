"""Blueprint-Node compatibility checker.

Checks whether a node package is compatible with a given blueprint:
  - Does the blueprint reference this node_id?
  - Can the node's contract connect to the blueprint's connections?
  - Are port types compatible?
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from nodechain.core.blueprint import load_blueprint
from nodechain.core.contract import check_compatibility


def check_blueprint_compat(
    blueprint_path: str,
    node_id: str,
    extra_paths: list[str] | None = None,
) -> dict[str, Any]:
    """
    Check whether a node is compatible with a blueprint.

    Args:
        blueprint_path: Path to the blueprint YAML
        node_id: Node ID to check
        extra_paths: Additional registry search paths

    Returns:
        Dict with compatibility results
    """
    from nodechain.registry.local_registry import RegistryIndex

    # Load blueprint
    blueprint = load_blueprint(blueprint_path)

    # Load node contract from registry
    registry = RegistryIndex(extra_paths=extra_paths)
    registry.scan()
    contract = registry.get_contract(node_id)

    if contract is None:
        return {
            "node_id": node_id,
            "blueprint_id": blueprint.chain_id,
            "compatible": False,
            "node_found_in_blueprint": False,
            "error": f"Node '{node_id}' not found in registry",
        }

    # Check if node is referenced in blueprint
    blueprint_node_ids = [n.node_id for n in blueprint.nodes]
    node_in_blueprint = node_id in blueprint_node_ids

    # Check connections involving this node
    issues = []
    warnings = []
    compatible_count = 0

    # Get all contracts from registry for connection checking
    registry_contracts = {}
    for nid in blueprint_node_ids:
        c = registry.get_contract(nid)
        if c:
            registry_contracts[nid] = c

    for conn in blueprint.connections:
        from_node = conn.from_node
        to_node = conn.to_node

        if from_node != node_id and to_node != node_id:
            continue

        source_contract = registry_contracts.get(from_node)
        target_contract = registry_contracts.get(to_node)

        if source_contract is None:
            issues.append(
                f"Connection {from_node} -> {to_node}: "
                f"source '{from_node}' not in registry"
            )
            continue

        if target_contract is None:
            issues.append(
                f"Connection {from_node} -> {to_node}: "
                f"target '{to_node}' not in registry"
            )
            continue

        result = check_compatibility(source_contract, target_contract)
        if result.compatible:
            compatible_count += 1
        else:
            issues.extend(result.issues)
        warnings.extend(result.warnings)

    return {
        "node_id": node_id,
        "blueprint_id": blueprint.chain_id,
        "compatible": len(issues) == 0,
        "node_found_in_blueprint": node_in_blueprint,
        "connections_checked": compatible_count + len(issues),
        "compatible_connections": compatible_count,
        "issues": issues,
        "warnings": warnings,
    }
