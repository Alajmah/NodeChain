"""Test node that allocates unreclaimable anonymous memory beyond memory.max.

Uses mmap with MAP_ANONYMOUS | MAP_LOCKED to create memory pressure
that the kernel cannot reclaim — forcing OOM kill behavior rather
than page cache reclamation.
"""
import mmap
import sys


class OomNode:
    def __init__(self, config=None, contract=None, manifest=None):
        pass

    async def execute(self, envelope):
        from nodechain.core.envelope import EnvelopeResponse
        # Allocate 50MB of unreclaimable anonymous memory
        # MAP_ANONYMOUS | MAP_LOCKED prevents kernel reclamation
        regions = []
        chunk_size = 1024 * 1024  # 1MB
        for i in range(50):
            try:
                # mmap with PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_LOCKED
                # Writing to the pages forces them to be resident
                region = mmap.mmap(-1, chunk_size)
                # Touch every page to ensure allocation
                for offset in range(0, chunk_size, 4096):
                    region[offset:offset+1] = b'\x00'
                regions.append(region)
            except (OSError, OverflowError):
                # Allocation failed — memory limit reached
                break
        return EnvelopeResponse(
            request_envelope_id=envelope.envelope_id,
            run_id=envelope.run_id,
            chain_id=envelope.chain_id,
            node_id=envelope.node_id,
            step_id=envelope.step_id,
            output={"allocated_mb": len(regions)},
            output_type="oom_test",
            success=True,
            latency_ms=0,
        )
