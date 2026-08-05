"""Scoped environment variable context manager.

Applies environment variables for the duration of a block and restores all
previous values in ``finally``. Used for the review seam env vars that the
runtime's HumanAdapter reads — these are process-global by design (the
existing runtime contract), but the runner must not leak them permanently.

Thread safety: a reentrant lock prevents concurrent contexts from
overlapping, which would corrupt the save/restore invariant.
"""

from __future__ import annotations

import os
import threading
from contextlib import contextmanager
from typing import Iterator


_env_lock = threading.RLock()


@contextmanager
def scoped_env(updates: dict[str, str]) -> Iterator[None]:
    """Apply ``updates`` to ``os.environ`` for the duration of the block,
    restoring every previous value (or deleting newly-set keys) on exit.

    Thread-safe via a reentrant lock — nested contexts from the same thread
    are allowed (each saves/restores its own snapshot), but concurrent
    contexts from different threads are serialized.
    """
    saved: dict[str, str | None] = {}
    with _env_lock:
        for key, value in updates.items():
            saved[key] = os.environ.get(key)
            os.environ[key] = value
        try:
            yield
        finally:
            for key, original in saved.items():
                if original is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = original
