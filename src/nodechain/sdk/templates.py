"""Node template generator — creates a new node package from a template.

Templates:
  deterministic  — pure computation, no LLM
  model          — requires LLM inference
  tool           — external API/tool invocation
"""

from __future__ import annotations

from pathlib import Path

TEMPLATES = {
    "deterministic": {
        "node_type": "deterministic",
        "model_required": "false",
        "description": "A deterministic node that processes input without LLM calls.",
        "logic_hint": "# Your deterministic logic here\n        result = payload",
        "output_hint": '"result": result',
    },
    "model": {
        "node_type": "model",
        "model_required": "true",
        "description": "A model-powered node that uses LLM inference.",
        "logic_hint": "# Call the model adapter\n        response = self._model.complete(\n            system_prompt=\"You are a helpful assistant.\",\n            user_message=str(payload),\n        )\n        result = response.content",
        "output_hint": '"result": result,\n            "model_output": result',
    },
    "tool": {
        "node_type": "tool",
        "model_required": "false",
        "description": "A tool node that calls external APIs or services.",
        "logic_hint": "# Call external API\n        import httpx\n        # async with httpx.AsyncClient() as client:\n        #     resp = await client.get(url)\n        result = payload  # placeholder",
        "output_hint": '"result": result',
    },
}

NODE_YAML_TEMPLATE = """\
# {node_id} -- {description}
# Generated from template: {template_name}

manifest:
  node_id: {node_id}
  node_type: {node_type}
  name: {name}
  description: >
    {description}
  version: "1.0.0"
  tags: [{tags}]

contract:
  contract_id: {contract_id}
  version: "1.0.0"
  entry:
    input_type: raw_user_query
    schema_ref: "nodechain://schemas/semantic_types/raw_user_query"
    required_fields:
      - query
    optional_fields: []
  exit:
    output_type: raw_user_query
    schema_ref: "nodechain://schemas/semantic_types/raw_user_query"
    guaranteed_fields:
      - query
      - result
    possible_fields: []
  side_effects: []
  requirements:
    model_required: {model_required}
    tools_required: []
    memory_access: none
    trust_level: trusted

meta:
  author: unknown
  license: MIT
  compatibility_version: "1.0.0"
"""

IMPLEMENTATION_TEMPLATE = """\
\"\"\"{node_id} -- {description}\"\"\"

from __future__ import annotations

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import (
    NodeContract, EntryContract, ExitContract, Requirements,
)
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


{node_id_upper}_CONTRACT = NodeContract(
    contract_id="{contract_id}",
    node_id="{node_id}",
    version="1.0.0",
    entry=EntryContract(
        input_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        required_fields=["query"],
    ),
    exit=ExitContract(
        output_type=PortType.RAW_QUERY,
        schema_ref="nodechain://schemas/semantic_types/raw_user_query",
        guaranteed_fields=["query", "result"],
    ),
    requirements=Requirements(
        model_required={model_required_bool},
        memory_access="none",
        trust_level="trusted",
    ),
)


class {class_name}(BaseNode):
    \"\"\"{name} -- {description}\"\"\"

    def __init__(self, **kwargs: Any) -> None:
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="{node_id}",
            node_type="{node_type}",
            name="{name}",
            description="{description}",
            contract={node_id_upper}_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        payload = envelope.payload

        {logic_hint}

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="{node_id}",
            step_id=envelope.step_id,
            output={{
                "query": payload.get("query", ""),
                {output_hint},
            }},
            output_type=PortType.RAW_QUERY,
            cost_usd=0.0,
            latency_ms=0,
        )
"""

TEST_TEMPLATE = """\
\"\"\"Tests for {node_id}.\"\"\"

import asyncio
import importlib.util
from pathlib import Path

import pytest

from nodechain.core.envelope import InvocationEnvelope

# Load implementation
_impl_path = Path(__file__).parent.parent / "implementation.py"
_spec = importlib.util.spec_from_file_location("implementation", _impl_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
{class_name} = _mod.{class_name}


def _make_envelope(payload: dict) -> InvocationEnvelope:
    return InvocationEnvelope(
        envelope_id="test-env",
        run_id="test-run",
        chain_id="test-chain",
        node_id="{node_id}",
        step_id=1,
        payload=payload,
    )


async def _execute(node, payload):
    return await node.execute(_make_envelope(payload))


class Test{class_name}:
    def test_manifest(self):
        node = {class_name}()
        m = node.manifest
        assert m.node_id == "{node_id}"
        assert m.node_type == "{node_type}"

    def test_basic_execution(self):
        node = {class_name}()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {{"query": "test input"}})
        )
        assert result.output["query"] == "test input"
        assert "result" in result.output

    def test_zero_cost(self):
        node = {class_name}()
        result = asyncio.get_event_loop().run_until_complete(
            _execute(node, {{"query": "test"}})
        )
        assert result.cost_usd == 0.0
"""


def create_node_package(
    node_id: str,
    template: str = "deterministic",
    output_dir: str = "nodes",
    name: str | None = None,
    tags: str | None = None,
) -> Path:
    """
    Create a new node package from a template.

    Args:
        node_id: Unique identifier for the node (e.g., "my_summarizer")
        template: Template type (deterministic, model, tool)
        output_dir: Parent directory for the package
        name: Human-readable name (default: title-cased node_id)
        tags: Comma-separated tags

    Returns:
        Path to the created package directory
    """
    if template not in TEMPLATES:
        raise ValueError(
            f"Unknown template '{template}'. "
            f"Available: {', '.join(TEMPLATES.keys())}"
        )

    tmpl = TEMPLATES[template]

    if name is None:
        name = node_id.replace("_", " ").title()

    if tags is None:
        tags = template

    contract_id = f"{template}.{node_id}.v1"
    class_name = "".join(word.capitalize() for word in node_id.split("_"))
    node_id_upper = node_id.upper()

    # Create directory
    pkg_dir = Path(output_dir) / node_id
    tests_dir = pkg_dir / "tests"
    schemas_dir = pkg_dir / "schemas"

    if pkg_dir.exists():
        raise FileExistsError(f"Package directory already exists: {pkg_dir}")

    pkg_dir.mkdir(parents=True)
    tests_dir.mkdir()
    schemas_dir.mkdir()

    # Write node.yaml
    (pkg_dir / "node.yaml").write_text(NODE_YAML_TEMPLATE.format(
        node_id=node_id,
        node_type=tmpl["node_type"],
        name=name,
        description=tmpl["description"],
        contract_id=contract_id,
        model_required=tmpl["model_required"],
        tags=tags,
        template_name=template,
    ))

    # Write implementation.py
    model_required_bool = "True" if tmpl["model_required"] == "true" else "False"
    (pkg_dir / "implementation.py").write_text(IMPLEMENTATION_TEMPLATE.format(
        node_id=node_id,
        node_id_upper=node_id_upper,
        node_type=tmpl["node_type"],
        name=name,
        description=tmpl["description"],
        contract_id=contract_id,
        class_name=class_name,
        model_required_bool=model_required_bool,
        logic_hint=tmpl["logic_hint"],
        output_hint=tmpl["output_hint"],
    ))

    # Write tests
    (tests_dir / f"test_{node_id}.py").write_text(TEST_TEMPLATE.format(
        node_id=node_id,
        node_type=tmpl["node_type"],
        class_name=class_name,
    ))

    # Write empty schemas
    (schemas_dir / "input.json").write_text('{\n  "type": "object",\n  "properties": {\n    "query": { "type": "string" }\n  },\n  "required": ["query"]\n}\n')
    (schemas_dir / "output.json").write_text('{\n  "type": "object",\n  "properties": {\n    "query": { "type": "string" },\n    "result": { "type": "string" }\n  },\n  "required": ["query", "result"]\n}\n')

    return pkg_dir
