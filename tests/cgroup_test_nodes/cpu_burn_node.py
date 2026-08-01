"""Test node that burns CPU to observe throttling under cpu.max quota."""
import time


class CpuBurnNode:
    def __init__(self, config=None, contract=None, manifest=None):
        pass

    async def execute(self, envelope):
        from nodechain.core.envelope import EnvelopeResponse
        # Burn CPU for ~2 seconds of wall time
        end = time.time() + 2
        x = 0
        while time.time() < end:
            x += 1
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=envelope.node_id,
            step_id=envelope.step_id,
            output={"iterations": x},
            output_type="cpu_burn",
            success=True,
            latency_ms=0,
        )
