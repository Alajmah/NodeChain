"""Scoped environment variable context manager.

Applies environment variables for the duration of a block and restores all
previous values in ``finally``. Used for the review seam env vars that the
runtime's HumanAdapter reads — these are process-global by design (the
existing runtime contract), but the runner must not leak them permanently.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator


@contextmanager
def scoped_env(updates: dict[str, str]) -> Iterator[None]:
    """Apply ``updates`` to ``os.environ`` for the duration of the block,
    restoring every previous value (or deleting newly-set keys) on exit."""
    saved: dict[str, str | None] = {}
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
