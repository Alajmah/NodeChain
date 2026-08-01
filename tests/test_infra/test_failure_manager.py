"""Tests for failure manager."""

import pytest
from nodechain.runtime.failure_manager import FailureManager, FailureType


class TestFailureClassification:
    def test_classifies_schema_failure(self):
        fm = FailureManager()
        result = fm.classify_failure("schema validation failed", {})
        assert result == FailureType.NODE_SCHEMA_VALIDATION

    def test_classifies_timeout(self):
        fm = FailureManager()
        result = fm.classify_failure("model call timed out after 60s", {})
        assert result == FailureType.MODEL_TIMEOUT

    def test_classifies_search_unavailable(self):
        fm = FailureManager()
        result = fm.classify_failure("API unavailable: connection refused", {})
        assert result == FailureType.SEARCH_API_UNAVAILABLE

    def test_classifies_loop_exhausted(self):
        fm = FailureManager()
        result = fm.classify_failure("loop exhausted max iterations", {})
        assert result == FailureType.SOURCE_QUALITY_LOOP_EXHAUSTED

    def test_classifies_claim_failure(self):
        fm = FailureManager()
        result = fm.classify_failure("all claims failed validation", {})
        assert result == FailureType.CLAIM_VALIDATION_FAILURE

    def test_classifies_memory_rejection(self):
        fm = FailureManager()
        result = fm.classify_failure("memory write policy rejected", {})
        assert result == FailureType.MEMORY_WRITE_POLICY_REJECTION

    def test_classifies_trace_failure(self):
        fm = FailureManager()
        result = fm.classify_failure("trace write sink failed", {})
        assert result == FailureType.TRACE_WRITE_FAILURE

    def test_classifies_unknown(self):
        fm = FailureManager()
        result = fm.classify_failure("something unexpected happened", {})
        assert result == FailureType.UNKNOWN


class TestMemoryRejection:
    @pytest.mark.asyncio
    async def test_memory_rejection_returns_recovered(self):
        fm = FailureManager()
        result = await fm.handle(
            FailureType.MEMORY_WRITE_POLICY_REJECTION,
            node=None,
            envelope=None,
            error="policy rejected",
            state={},
            invoke_fn=None,
        )
        assert result.recovered is True
        assert "policy_rejection" in result.action


class TestTraceFailure:
    @pytest.mark.asyncio
    async def test_trace_failure_returns_recovered(self):
        fm = FailureManager()
        result = await fm.handle(
            FailureType.TRACE_WRITE_FAILURE,
            node=None,
            envelope=None,
            error="sink error",
            state={},
            invoke_fn=None,
        )
        assert result.recovered is True
        assert "stderr" in result.action


class TestRetryStepAllocation:
    """Verify retries use StepAllocator, not envelope.step_id + 1."""

    def _make_node(self, node_id: str):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        from nodechain.core.port import PortType
        from unittest.mock import MagicMock
        node = MagicMock()
        node.manifest = NodeManifest(
            node_id=node_id, node_type="model", name="Test", description="test",
            contract=NodeContract(
                contract_id=f"test.{node_id}.v1", node_id=node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test"),
                requirements=Requirements(model_required=True),
            ),
        )
        return node

    def _make_envelope(self, step_id: int = 1):
        from nodechain.core.envelope import InvocationEnvelope, compile_envelope
        return compile_envelope(
            run_id="test-run", chain_id="test-chain",
            node_id="test_node", step_id=step_id, payload={},
        )

    def test_schema_failure_uses_allocator(self):
        """Retry envelope gets step_id from allocator, not +1."""
        allocated_steps = []

        def mock_allocator(run_id, node_id, attempt=2):
            step = 100 + len(allocated_steps)  # Deterministic, not +1
            allocated_steps.append(step)
            return step

        fm = FailureManager(allocate_step_fn=mock_allocator)
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=5)

        import asyncio
        async def mock_invoke(n, env):
            from nodechain.core.envelope import EnvelopeResponse
            return EnvelopeResponse(
                request_envelope_id=env.envelope_id, run_id=env.run_id,
                chain_id=env.chain_id, node_id="test_node", step_id=env.step_id,
                output={"ok": True}, output_type="test",
            )

        result = asyncio.run(fm.handle(
            FailureType.NODE_SCHEMA_VALIDATION, node, envelope, "schema error",
            state={}, invoke_fn=mock_invoke,
        ))

        assert result.recovered is True
        assert len(allocated_steps) == 1
        assert allocated_steps[0] == 100  # From allocator, not 5+1=6

    def test_no_allocator_falls_back_to_plus_one(self):
        """Without allocator, step_id falls back to envelope.step_id + 1."""
        fm = FailureManager()  # No allocator
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=5)

        import asyncio
        async def mock_invoke(n, env):
            from nodechain.core.envelope import EnvelopeResponse
            return EnvelopeResponse(
                request_envelope_id=env.envelope_id, run_id=env.run_id,
                chain_id=env.chain_id, node_id="test_node", step_id=env.step_id,
                output={"ok": True}, output_type="test",
            )

        result = asyncio.run(fm.handle(
            FailureType.NODE_SCHEMA_VALIDATION, node, envelope, "schema error",
            state={}, invoke_fn=mock_invoke,
        ))

        assert result.recovered is True
        # The retry envelope should have step_id=6 (5+1) without allocator
        assert result.response.step_id == 6

    def test_model_timeout_uses_allocator(self):
        """Model timeout retry also uses allocator."""
        allocated_steps = []

        def mock_allocator(run_id, node_id, attempt=2):
            step = 200 + len(allocated_steps)
            allocated_steps.append(step)
            return step

        fm = FailureManager(allocate_step_fn=mock_allocator)
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=10)

        import asyncio
        async def mock_invoke(n, env):
            from nodechain.core.envelope import EnvelopeResponse
            return EnvelopeResponse(
                request_envelope_id=env.envelope_id, run_id=env.run_id,
                chain_id=env.chain_id, node_id="test_node", step_id=env.step_id,
                output={"ok": True}, output_type="test",
            )

        result = asyncio.run(fm.handle(
            FailureType.MODEL_TIMEOUT, node, envelope, "timeout",
            state={}, invoke_fn=mock_invoke,
        ))

        assert result.recovered is True
        assert len(allocated_steps) == 1
        assert allocated_steps[0] == 200  # From allocator, not 10+1=11


class TestRetryRecoveryInvariant:
    """v3.2 invariant: the four retry handlers must return recovered=False
    when the retry response has success=False.

    FIXED (v3.2): each retry handler now gates recovered=True on
    response.success. A failed retry yields recovered=False with a
    matching *_retry_failed action.
    """

    def _make_node(self, node_id: str):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        from nodechain.core.port import PortType
        from unittest.mock import MagicMock
        node = MagicMock()
        node.manifest = NodeManifest(
            node_id=node_id, node_type="model", name="Test", description="test",
            contract=NodeContract(
                contract_id=f"test.{node_id}.v1", node_id=node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test"),
                requirements=Requirements(model_required=True),
            ),
        )
        return node

    def _make_envelope(self, step_id: int = 1):
        from nodechain.core.envelope import compile_envelope
        return compile_envelope(
            run_id="test-run", chain_id="test-chain",
            node_id="test_node", step_id=step_id, payload={},
        )

    def _failing_invoke(self):
        """An invoke_fn that always returns a FAILED response."""
        from nodechain.core.envelope import EnvelopeResponse
        async def invoke(n, env):
            return EnvelopeResponse(
                request_envelope_id=env.envelope_id, run_id=env.run_id,
                chain_id=env.chain_id, node_id="test_node", step_id=env.step_id,
                output={}, output_type="object", success=False, error="retry still failing",
            )
        return invoke

    def test_handle_unknown_failed_retry_not_recovered(self):
        """FIXED (v3.2): _handle_unknown returns recovered=False on a failed retry."""
        import asyncio
        fm = FailureManager()
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=1)
        result = asyncio.run(fm.handle(
            FailureType.UNKNOWN, node, envelope, "something unexpected",
            state={}, invoke_fn=self._failing_invoke(),
        ))
        assert result.recovered is False
        assert result.action == "unknown_retry_failed"
        assert result.response is not None
        assert result.response.success is False

    def test_handle_schema_failure_failed_retry_not_recovered(self):
        """FIXED (v3.2): _handle_schema_failure returns recovered=False on a failed retry."""
        import asyncio
        fm = FailureManager()
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=1)
        result = asyncio.run(fm.handle(
            FailureType.NODE_SCHEMA_VALIDATION, node, envelope, "schema validation error",
            state={}, invoke_fn=self._failing_invoke(),
        ))
        assert result.recovered is False
        assert result.action == "schema_failure_retry_failed"
        assert result.response is not None
        assert result.response.success is False

    def test_handle_model_timeout_failed_retry_not_recovered(self):
        """FIXED (v3.2): _handle_model_timeout returns recovered=False on a failed retry."""
        import asyncio
        fm = FailureManager()
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=1)
        result = asyncio.run(fm.handle(
            FailureType.MODEL_TIMEOUT, node, envelope, "model timeout",
            state={}, invoke_fn=self._failing_invoke(),
        ))
        assert result.recovered is False
        assert result.action == "model_timeout_retry_failed"
        assert result.response is not None
        assert result.response.success is False

    def test_handle_search_unavailable_failed_retry_not_recovered(self):
        """FIXED (v3.2): _handle_search_unavailable returns recovered=False on a failed retry."""
        import asyncio
        fm = FailureManager()
        node = self._make_node("test_node")
        envelope = self._make_envelope(step_id=1)
        result = asyncio.run(fm.handle(
            FailureType.SEARCH_API_UNAVAILABLE, node, envelope, "api unavailable",
            state={}, invoke_fn=self._failing_invoke(),
        ))
        assert result.recovered is False
        assert result.action == "search_unavailable_retry_failed"
        assert result.response is not None
        assert result.response.success is False


class TestRetryRecoveryPositiveControls:
    """v3.2: successful retry still recovers (positive controls)."""

    def _make_node(self, node_id="test_node"):
        from nodechain.core.manifest import NodeManifest
        from nodechain.core.contract import EntryContract, ExitContract, Requirements, NodeContract
        from nodechain.core.port import PortType
        from unittest.mock import MagicMock
        node = MagicMock()
        node.manifest = NodeManifest(
            node_id=node_id, node_type="model", name="Test", description="test",
            contract=NodeContract(
                contract_id=f"test.{node_id}.v1", node_id=node_id, version="1.0.0",
                entry=EntryContract(input_type=PortType.TASK_PLAN, schema_ref="test"),
                exit=ExitContract(output_type=PortType.RAW_SEARCH_RESULTS, schema_ref="test"),
                requirements=Requirements(model_required=True),
            ),
        )
        return node

    def _make_envelope(self, step_id=1):
        from nodechain.core.envelope import compile_envelope
        return compile_envelope(run_id="test-run", chain_id="test-chain", node_id="test_node", step_id=step_id, payload={})

    def _succeeding_invoke(self):
        from nodechain.core.envelope import EnvelopeResponse
        async def invoke(n, env):
            return EnvelopeResponse(
                request_envelope_id=env.envelope_id, run_id=env.run_id,
                chain_id=env.chain_id, node_id="test_node", step_id=env.step_id,
                output={"ok": True}, output_type="object", success=True,
            )
        return invoke

    def test_handle_unknown_successful_retry_recovers(self):
        import asyncio
        fm = FailureManager()
        node = self._make_node(); envelope = self._make_envelope()
        result = asyncio.run(fm.handle(FailureType.UNKNOWN, node, envelope, "oops", state={}, invoke_fn=self._succeeding_invoke()))
        assert result.recovered is True
        assert result.response.success is True

    def test_handle_schema_failure_successful_retry_recovers(self):
        import asyncio
        fm = FailureManager()
        node = self._make_node(); envelope = self._make_envelope()
        result = asyncio.run(fm.handle(FailureType.NODE_SCHEMA_VALIDATION, node, envelope, "schema error", state={}, invoke_fn=self._succeeding_invoke()))
        assert result.recovered is True
        assert result.response.success is True

    def test_handle_model_timeout_successful_retry_recovers(self):
        import asyncio
        fm = FailureManager()
        node = self._make_node(); envelope = self._make_envelope()
        result = asyncio.run(fm.handle(FailureType.MODEL_TIMEOUT, node, envelope, "timeout", state={}, invoke_fn=self._succeeding_invoke()))
        assert result.recovered is True
        assert result.response.success is True

    def test_handle_search_unavailable_successful_retry_recovers(self):
        import asyncio
        fm = FailureManager()
        node = self._make_node(); envelope = self._make_envelope()
        result = asyncio.run(fm.handle(FailureType.SEARCH_API_UNAVAILABLE, node, envelope, "api unavailable", state={}, invoke_fn=self._succeeding_invoke()))
        assert result.recovered is True
        assert result.response.success is True
