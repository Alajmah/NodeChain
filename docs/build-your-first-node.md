# Build Your First Harness Node

This guide walks through creating a packaged, distributable Harness Node
that can be discovered by the NodeChain registry and used in chains.

## Prerequisites

- NodeChain installed (`pip install -e ".[dev]"`)
- A directory for your node package

## Step 1: Create the Package Structure

```
nodes/my_node/
  node.yaml           # Manifest + contract
  implementation.py   # Node logic
  tests/
    test_my_node.py   # Package-local tests
```

## Step 2: Write the Manifest (node.yaml)

The `node.yaml` file defines your node's identity, contract, and metadata:

```yaml
manifest:
  node_id: my_node
  node_type: deterministic    # deterministic | model | hybrid
  name: My Custom Node
  description: What this node does.
  version: "1.0.0"
  tags: [custom, utility]

contract:
  contract_id: custom.my-node.v1
  version: "1.0.0"
  entry:
    input_type: raw_user_query
    schema_ref: "nodechain://schemas/semantic_types/raw_user_query"
    required_fields:
      - query
  exit:
    output_type: raw_user_query
    schema_ref: "nodechain://schemas/semantic_types/raw_user_query"
    guaranteed_fields:
      - query
      - result
  side_effects: []
  requirements:
    model_required: false
    memory_access: none
    trust_level: trusted

meta:
  author: Your Name
  license: MIT
```

### Contract Fields

| Field | Purpose |
|-------|---------|
| `entry.input_type` | Semantic type this node accepts |
| `entry.required_fields` | Fields that must be present in input |
| `exit.output_type` | Semantic type this node produces |
| `exit.guaranteed_fields` | Fields this node always produces |
| `side_effects` | External actions this node performs |
| `requirements.model_required` | Whether this node needs an LLM |
| `requirements.memory_access` | none, read, write, or read_write |
| `requirements.trust_level` | trusted, sandboxed, or untrusted |

### Node Types

| Type | Description |
|------|-------------|
| `deterministic` | No LLM required, pure computation |
| `model` | Requires LLM for inference |
| `hybrid` | Mix of deterministic and model logic |
| `tool` | External API/tool invocation |
| `join` | Merges branch outputs |

## Step 3: Implement the Node

Create `implementation.py` that subclasses `BaseNode`:

```python
"""My Custom Node implementation."""

from typing import Any

from nodechain.core.envelope import InvocationEnvelope, EnvelopeResponse
from nodechain.core.contract import NodeContract, EntryContract, ExitContract, Requirements
from nodechain.core.manifest import NodeManifest
from nodechain.core.port import PortType
from nodechain.nodes.base_node import BaseNode


# Define the contract (matches node.yaml)
MY_NODE_CONTRACT = NodeContract(
    contract_id="custom.my-node.v1",
    node_id="my_node",
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
    requirements=Requirements(model_required=False),
)


class MyNode(BaseNode):
    """My custom node."""

    def __init__(self, **kwargs):
        pass

    @property
    def manifest(self) -> NodeManifest:
        return NodeManifest(
            node_id="my_node",
            node_type="deterministic",
            name="My Custom Node",
            description="What this node does.",
            contract=MY_NODE_CONTRACT,
        )

    async def execute(self, envelope: InvocationEnvelope) -> EnvelopeResponse:
        query = envelope.payload.get("query", "")

        # Your logic here
        result = query.upper()

        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id="my_node",
            step_id=envelope.step_id,
            output={"query": query, "result": result},
            output_type=PortType.RAW_QUERY,
            cost_usd=0.0,
            latency_ms=0,
        )
```

## Step 4: Write Tests

Create `tests/test_my_node.py`:

```python
import asyncio
import importlib.util
from pathlib import Path
from nodechain.core.envelope import InvocationEnvelope

# Load implementation
impl_path = Path(__file__).parent.parent / "implementation.py"
spec = importlib.util.spec_from_file_location("implementation", impl_path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
MyNode = mod.MyNode


def make_envelope(payload):
    return InvocationEnvelope(
        envelope_id="test", run_id="test", chain_id="test",
        node_id="my_node", step_id=1, payload=payload,
    )


def test_basic():
    node = MyNode()
    result = asyncio.get_event_loop().run_until_complete(
        node.execute(make_envelope({"query": "hello"}))
    )
    assert result.output["result"] == "HELLO"
```

## Step 5: Validate and Test

```bash
# Validate the package structure
nodechain node validate nodes/my_node

# Run package-local tests
nodechain node test nodes/my_node
```

## Step 6: Register and Discover

Place your node directory in `nodes/` and it will be discovered by the registry:

```bash
# List all registered nodes
nodechain registry list

# Inspect a specific node
nodechain registry inspect my_node
```

## Example: Echo Node

A complete working example is at `nodes/echo_node/`. It demonstrates:
- `node.yaml` with manifest, contract, and metadata
- `implementation.py` with BaseNode subclass
- `tests/test_echo.py` with importlib-based test loading
- Registry discovery and inspection

## Port Types

Built-in semantic types for typed port connections:

| Type | Description |
|------|-------------|
| `raw_user_query` | Raw input from user |
| `normalized_research_goal` | Parsed research goal |
| `task_plan` | Decomposed task plan |
| `raw_search_results` | Search API output |
| `qualified_source_set` | Quality-filtered sources |
| `evidence_base` | Synthesized evidence |
| `validated_evidence_base` | Validated evidence |
| `risk_assessment` | Risk classification |
| `final_response` | Generated response |
| `memory_write_decision` | Memory write decision |
