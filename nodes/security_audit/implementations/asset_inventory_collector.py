"""Asset Inventory Collector — collects all platform assets for audit.

Node 1 of the Security Audit Chain.
Input: dashboard JSON or direct environment scan
Output: structured asset inventory with digests and counts
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from nodechain.nodes.base_node import BaseNode
from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract
from nodechain.core.manifest import NodeManifest


class AssetInventoryCollector(BaseNode):
    """Collects all platform assets for security audit."""

    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="asset_inventory_collector",
            node_type="deterministic",
            name="Asset Inventory Collector",
            description="Collects all platform assets for security audit",
            version="1.0.0",
            contract=self.contract(),
        )

    def contract(self) -> NodeContract:
        return NodeContract(
            contract_id="audit.inventory.v1",
            node_id="asset_inventory_collector",
            version="1.0.0",
            entry={
                "input_type": "dashboard_json_or_empty",
                "schema_ref": "",
                "required_fields": [],
                "optional_fields": ["dashboard", "scan_env"],
            },
            exit={
                "output_type": "asset_inventory",
                "schema_ref": "",
                "guaranteed_fields": [
                    "assets", "asset_count", "inventory_digest", "timestamp",
                ],
            },
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload
        dashboard = payload.get("dashboard", {})
        scan_env = payload.get("scan_env", True)

        assets: list[dict[str, Any]] = []

        # Collect from dashboard sections if provided
        sections = dashboard.get("sections", {})
        if sections:
            for spine, data in sections.items():
                assets.append({
                    "type": "dashboard_section",
                    "spine": spine,
                    "data_keys": sorted(data.keys()) if isinstance(data, dict) else [],
                })

        # Scan environment for artifacts
        if scan_env:
            data_dir = Path("data")
            if data_dir.exists():
                for f in sorted(data_dir.glob("*.json")):
                    try:
                        content = f.read_bytes()
                        digest = hashlib.sha256(content).hexdigest()
                        data = json.loads(content)
                        atype = data.get("type", "unknown")
                        assets.append({
                            "type": atype,
                            "path": str(f),
                            "digest": digest,
                            "size_bytes": len(content),
                        })
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        assets.append({
                            "type": "unreadable",
                            "path": str(f),
                            "digest": "",
                            "size_bytes": f.stat().st_size,
                        })

            # SQLite DB
            db_path = Path(os.environ.get("NODECHAIN_DB_PATH", "data/chain_state.db"))
            if db_path.exists():
                assets.append({
                    "type": "sqlite_database",
                    "path": str(db_path),
                    "size_bytes": db_path.stat().st_size,
                })

        # Compute inventory digest
        inventory_content = json.dumps(
            [{"type": a["type"], "digest": a.get("digest", "")} for a in assets],
            sort_keys=True, separators=(",", ":"),
        )
        inventory_digest = hashlib.sha256(inventory_content.encode()).hexdigest()

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="asset_inventory_collector",
            step_id=envelope.step_id,
            output={
                "assets": assets,
                "asset_count": len(assets),
                "inventory_digest": inventory_digest,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            output_type="dict",
        )
