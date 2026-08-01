"""Tests for StepAllocator — concurrency-safe step ID allocation.

Covers:
- Sequential allocation
- Async concurrent allocation (no duplicates)
- Sync allocation
- Identity immutability
- Resume initialization
"""

import asyncio
import pytest

from nodechain.runtime.step_allocator import StepAllocator, InvocationIdentity


class TestSequentialAllocation:
    @pytest.mark.asyncio
    async def test_sequential_ids(self):
        alloc = StepAllocator(initial=0)
        id1 = await alloc.allocate("r1", "a")
        id2 = await alloc.allocate("r1", "b")
        id3 = await alloc.allocate("r1", "c")
        assert id1.step_id == 1
        assert id2.step_id == 2
        assert id3.step_id == 3

    @pytest.mark.asyncio
    async def test_identity_fields(self):
        alloc = StepAllocator(initial=0)
        identity = await alloc.allocate("r1", "search_tool", branch_name="bio", attempt=2)
        assert identity.run_id == "r1"
        assert identity.node_id == "search_tool"
        assert identity.branch_name == "bio"
        assert identity.attempt == 2

    def test_identity_is_frozen(self):
        identity = InvocationIdentity(run_id="r1", step_id=1, node_id="a")
        with pytest.raises(AttributeError):
            identity.step_id = 99  # type: ignore


class TestConcurrentAllocation:
    @pytest.mark.asyncio
    async def test_no_duplicate_step_ids_under_concurrency(self):
        """100 concurrent allocations should produce 100 unique step IDs."""
        alloc = StepAllocator(initial=0)

        async def allocate_one(node_id: str):
            return await alloc.allocate("r1", node_id)

        tasks = [allocate_one(f"node_{i}") for i in range(100)]
        results = await asyncio.gather(*tasks)

        step_ids = [r.step_id for r in results]
        assert len(step_ids) == 100
        assert len(set(step_ids)) == 100  # All unique
        assert min(step_ids) == 1
        assert max(step_ids) == 100

    @pytest.mark.asyncio
    async def test_two_branches_no_collision(self):
        """Simulates the original race: two branches allocating concurrently."""
        alloc = StepAllocator(initial=0)

        async def branch(name: str, count: int) -> list[InvocationIdentity]:
            ids = []
            for i in range(count):
                identity = await alloc.allocate("r1", f"{name}_node_{i}", branch_name=name)
                ids.append(identity)
                await asyncio.sleep(0.001)  # Simulate work
            return ids

        branch_a, branch_b = await asyncio.gather(
            branch("alpha", 5),
            branch("beta", 5),
        )

        all_ids = [i.step_id for i in branch_a] + [i.step_id for i in branch_b]
        assert len(all_ids) == 10
        assert len(set(all_ids)) == 10  # No collisions

    @pytest.mark.asyncio
    async def test_allocator_current_tracks_latest(self):
        alloc = StepAllocator(initial=0)
        assert alloc.current == 0
        await alloc.allocate("r1", "a")
        assert alloc.current == 1
        await alloc.allocate("r1", "b")
        assert alloc.current == 2


class TestSyncAllocation:
    def test_sync_sequential(self):
        alloc = StepAllocator(initial=0)
        id1 = alloc.allocate_sync("r1", "a")
        id2 = alloc.allocate_sync("r1", "b")
        assert id1.step_id == 1
        assert id2.step_id == 2

    def test_sync_identity_fields(self):
        alloc = StepAllocator(initial=0)
        identity = alloc.allocate_sync("r1", "goal_interpreter")
        assert identity.run_id == "r1"
        assert identity.node_id == "goal_interpreter"
        assert identity.branch_name is None


class TestResumeInitialization:
    def test_initialize_from_step(self):
        alloc = StepAllocator(initial=0)
        alloc.initialize_from(step=5)
        assert alloc.current == 5

    @pytest.mark.asyncio
    async def test_resume_continues_from_initialized(self):
        alloc = StepAllocator(initial=0)
        alloc.initialize_from(step=3)
        identity = await alloc.allocate("r1", "next_node")
        assert identity.step_id == 4
        assert alloc.current == 4

    def test_initialize_preserves_identity(self):
        alloc = StepAllocator(initial=10)
        alloc.initialize_from(step=5)
        assert alloc.current == 5
        identity = alloc.allocate_sync("r1", "a")
        assert identity.step_id == 6
