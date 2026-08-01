"""Step Allocator — concurrency-safe step ID allocation.

Provides immutable step IDs for node invocations. Each step ID is
allocated exactly once under an async lock, preventing the parallel
branch race where concurrent branches could share step IDs.

For resume, initialize from the highest persisted step.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class InvocationIdentity:
    """Immutable identity for a single node invocation.

    Allocated before execution, never mutated after.
    Used for envelope construction, persistence, and trace emission.
    """
    run_id: str
    step_id: int
    node_id: str
    branch_name: str | None = None
    attempt: int = 1


class StepAllocator:
    """Thread-safe and async-safe step ID allocator.

    Usage:
        allocator = StepAllocator(initial=0)
        identity = await allocator.allocate(run_id="r1", node_id="search_tool")
        # identity.step_id is now 1, guaranteed unique within this run
    """

    def __init__(self, initial: int = 0):
        self._next = initial
        self._lock = asyncio.Lock()

    async def allocate(
        self,
        run_id: str,
        node_id: str,
        branch_name: str | None = None,
        attempt: int = 1,
    ) -> InvocationIdentity:
        """Allocate the next step ID and return an immutable identity.

        Thread-safe: the lock ensures no two concurrent allocations
        receive the same step_id, even under asyncio.gather().
        """
        async with self._lock:
            self._next += 1
            return InvocationIdentity(
                run_id=run_id,
                step_id=self._next,
                node_id=node_id,
                branch_name=branch_name,
                attempt=attempt,
            )

    def allocate_sync(
        self,
        run_id: str,
        node_id: str,
        branch_name: str | None = None,
        attempt: int = 1,
    ) -> InvocationIdentity:
        """Synchronous allocation for backbone (non-branch) nodes.

        Safe for single-threaded sequential execution where no
        concurrency is possible.
        """
        self._next += 1
        return InvocationIdentity(
            run_id=run_id,
            step_id=self._next,
            node_id=node_id,
            branch_name=branch_name,
            attempt=attempt,
        )

    @property
    def current(self) -> int:
        """Current (last allocated) step ID."""
        return self._next

    def initialize_from(self, step: int) -> None:
        """Set allocator start point (for resume)."""
        self._next = step
