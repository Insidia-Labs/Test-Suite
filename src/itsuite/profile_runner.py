"""Run a profile's plan in parallel, and pick up where an interrupted run stopped.

Every planned run (target, mode, variant, task, repeat number) gets a line in a ledger,
``results/profile-<profile>-<tool>.jsonl``. With ``resume``, runs whose last ledger
line is scored are skipped; anything else (crashed, unscored, never started) runs
again. Runs that raise before the tool starts are recorded too, with the reason.
"""

from __future__ import annotations

import fcntl
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PlanItem:
    target: str
    mode: str
    variant: str
    task: str
    repeat: int

    @property
    def item_id(self) -> str:
        return f"{self.target}|{self.mode}|{self.variant}|{self.task}|{self.repeat}"


def expand(plan: Sequence[tuple[str, str, str, str]], repeats: int) -> list[PlanItem]:
    return [PlanItem(t, m, v, k, r) for t, m, v, k in plan for r in range(1, repeats + 1)]


class Ledger:
    """Append-only JSON lines, safe to write from several threads and processes."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def entries(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        last: dict[str, dict[str, Any]] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entry = json.loads(line)
                last[str(entry["item"])] = entry
        return last

    def record(self, item: PlanItem, outcome: Mapping[str, Any]) -> None:
        line = json.dumps({
            "item": item.item_id, "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **outcome,
        })  # fmt: skip
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.write(line + "\n")


def pending(items: Sequence[PlanItem], ledger: Ledger, resume: bool) -> list[PlanItem]:
    if not resume:
        return list(items)
    done = {k for k, v in ledger.entries().items() if v.get("scored")}
    return [item for item in items if item.item_id not in done]


RunOne = Callable[[PlanItem], Mapping[str, Any]]
Report = Callable[[PlanItem, Mapping[str, Any]], None]


def _attempt(item: PlanItem, run_one: RunOne) -> dict[str, Any]:
    try:
        score = run_one(item)
    except Exception as exc:  # one failed run must not stop the profile; it is recorded
        return {
            "scored": False,
            "status": "harness-error",
            "reason": f"{type(exc).__name__}: {exc}",
        }
    return {k: score.get(k) for k in ("run_id", "status", "scored", "reason")}


def run(items: Sequence[PlanItem], run_one: RunOne, ledger: Ledger, jobs: int = 1,
        report: Report | None = None) -> dict[str, int]:  # fmt: skip
    """Run every item (``jobs`` at a time); returns counts of scored and not scored."""
    counts = {"scored": 0, "not_scored": 0}
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {pool.submit(_attempt, item, run_one): item for item in items}
        for future in as_completed(futures):
            item, outcome = futures[future], future.result()
            ledger.record(item, outcome)
            counts["scored" if outcome.get("scored") else "not_scored"] += 1
            if report:
                report(item, outcome)
    return counts
