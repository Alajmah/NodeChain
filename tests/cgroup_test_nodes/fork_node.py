"""Test node that forks beyond pids.max to trigger pid limit."""
import os
import sys


class ForkNode:
    def __init__(self, config=None, contract=None, manifest=None):
        pass

    async def execute(self, envelope):
        from nodechain.core.envelope import EnvelopeResponse
        # Try to fork many processes beyond pids.max
        pids = []
        for i in range(20):
            try:
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                else:
                    pids.append(pid)
            except OSError:
                # Fork failed — pids.max reached
                break
        # Reap children
        for p in pids:
            try:
                os.waitpid(p, 0)
            except Exception:
                pass
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=envelope.node_id,
            step_id=envelope.step_id,
            output={"forks_attempted": len(pids)},
            output_type="pids_test",
            success=True,
            latency_ms=0,
        )
