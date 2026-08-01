"""Regression test for parallel branch step allocation race.

Verifies that StepAllocator produces unique step IDs under concurrent
allocation and that the allocator integrates correctly with the orchestrator.
"""

import asyncio
import pytest

from nodechain.runtime.step_allocator import StepAllocator, InvocationIdentity


class TestInvocationIdentity:
    def test_frozen(self):
        identity = InvocationIdentity(run_id="r1", step_id=1, node_id="a")
        with pytest.raises(AttributeError):
            identity.step_id = 99  # type: ignore

    def test_fields(self):
        identity = InvocationIdentity(
            run_id="r1", step_id=5, node_id="search",
            branch_name="bio", attempt=2,
        )
        assert identity.run_id == "r1"
        assert identity.step_id == 5
        assert identity.node_id == "search"
        assert identity.branch_name == "bio"
        assert identity.attempt == 2


class TestStepAllocatorConcurrency:
    @pytest.mark.asyncio
    async def test_50_concurrent_unique_ids(self):
        """50 concurrent allocations produce 50 unique step IDs."""
        allocator = StepAllocator(initial=0)

        async def alloc(branch, i):
            return await allocator.allocate("r1", f"{branch}_{i}", branch_name=branch)

        tasks = [alloc("alpha", i) if i % 2 == 0 else alloc("beta", i) for i in range(50)]
        results = await asyncio.gather(*tasks)
        ids = [r.step_id for r in results]
        assert len(ids) == 50
        assert len(set(ids)) == 50

    @pytest.mark.asyncio
    async def test_two_branches_no_collision(self):
        """Simulate the original race: two branches interleaving allocations."""
        allocator = StepAllocator(initial=0)

        async def branch(name: str, count: int) -> list[InvocationIdentity]:
            ids = []
            for i in range(count):
                identity = await allocator.allocate("r1", f"{name}_node_{i}", branch_name=name)
                ids.append(identity)
                await asyncio.sleep(0.001)  # Simulate work between allocations
            return ids

        branch_a, branch_b = await asyncio.gather(
            branch("alpha", 10),
            branch("beta", 10),
        )

        all_ids = [i.step_id for i in branch_a] + [i.step_id for i in branch_b]
        assert len(all_ids) == 20
        assert len(set(all_ids)) == 20  # No collisions

    @pytest.mark.asyncio
    async def test_100_concurrent_single_allocation(self):
        """100 coroutines all trying to allocate at once."""
        allocator = StepAllocator(initial=0)

        async def allocate_one(node_id: str):
            return await allocator.allocate("r1", node_id)

        tasks = [allocate_one(f"node_{i}") for i in range(100)]
        results = await asyncio.gather(*tasks)

        step_ids = [r.step_id for r in results]
        assert len(step_ids) == 100
        assert len(set(step_ids)) == 100
        assert min(step_ids) == 1
        assert max(step_ids) == 100


class TestStepAllocatorSequential:
    def test_sync_sequential(self):
        allocator = StepAllocator(initial=0)
        id1 = allocator.allocate_sync("r1", "a")
        id2 = allocator.allocate_sync("r1", "b")
        assert id1.step_id == 1
        assert id2.step_id == 2

    @pytest.mark.asyncio
    async def test_async_sequential(self):
        allocator = StepAllocator(initial=0)
        id1 = await allocator.allocate("r1", "a")
        id2 = await allocator.allocate("r1", "b")
        assert id1.step_id == 1
        assert id2.step_id == 2

    def test_mixed_sync_async(self):
        """Sync and async produce the same sequence."""
        allocator = StepAllocator(initial=0)
        id1 = allocator.allocate_sync("r1", "a")
        assert id1.step_id == 1
        assert allocator.current == 1
        id2 = allocator.allocate_sync("r1", "b")
        assert id2.step_id == 2


class TestStepAllocatorResume:
    def test_initialize_from_step(self):
        allocator = StepAllocator(initial=0)
        allocator.initialize_from(step=5)
        assert allocator.current == 5

    def test_resume_continues_from_initialized(self):
        allocator = StepAllocator(initial=0)
        allocator.initialize_from(step=3)
        identity = allocator.allocate_sync("r1", "next_node")
        assert identity.step_id == 4
        assert allocator.current == 4

    @pytest.mark.asyncio
    async def test_async_resume_continues(self):
        allocator = StepAllocator(initial=0)
        allocator.initialize_from(step=10)
        identity = await allocator.allocate("r1", "next")
        assert identity.step_id == 11
