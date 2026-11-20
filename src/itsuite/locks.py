"""Locks shared by parallel runs (threads in one process, and separate processes)."""

from __future__ import annotations

import fcntl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_GUARD = threading.Lock()


@contextmanager
def file_lock(path: Path) -> Iterator[None]:
    """Exclusive lock across threads (a lock per path) and processes (flock)."""
    with _GUARD:
        local = _THREAD_LOCKS.setdefault(str(path), threading.Lock())
    path.parent.mkdir(parents=True, exist_ok=True)
    with local, path.open("a", encoding="utf-8") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield
