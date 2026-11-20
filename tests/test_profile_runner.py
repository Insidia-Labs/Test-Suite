"""Parallel, resumable profile runs and the locks they rely on."""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from itsuite import docker_ops, profile_runner
from itsuite.locks import file_lock

PLAN = [
    ("dvwa", "dast", "low", ""),
    ("dvwa", "dast", "impossible", ""),
    ("castle", "sast", "default", ""),
]


def test_expand_and_ids() -> None:
    items = profile_runner.expand(PLAN, 2)
    assert len(items) == 6 and items[0].item_id == "dvwa|dast|low||1"
    assert {i.repeat for i in items} == {1, 2}


def test_run_records_every_outcome_and_resume_skips_scored(tmp_path: Path) -> None:
    ledger = profile_runner.Ledger(tmp_path / "ledger.jsonl")
    items = profile_runner.expand(PLAN, 1)

    def run_one(item: profile_runner.PlanItem) -> Mapping[str, Any]:
        if item.variant == "impossible":
            raise RuntimeError("compose up failed")
        return {"run_id": f"r-{item.variant}", "status": "ok", "scored": item.target != "castle"}

    seen: list[str] = []
    counts = profile_runner.run(items, run_one, ledger, jobs=3,
                                report=lambda item, out: seen.append(item.item_id))  # fmt: skip
    assert counts == {"scored": 1, "not_scored": 2} and len(seen) == 3
    entries = ledger.entries()
    assert entries["dvwa|dast|impossible||1"]["status"] == "harness-error"
    assert "compose up failed" in entries["dvwa|dast|impossible||1"]["reason"]
    left = profile_runner.pending(items, ledger, resume=True)
    assert [i.item_id for i in left] == ["dvwa|dast|impossible||1", "castle|sast|default||1"]
    assert profile_runner.pending(items, ledger, resume=False) == items
    assert profile_runner.Ledger(tmp_path / "missing.jsonl").entries() == {}


def test_free_port_never_repeats_across_threads() -> None:
    ports: list[int] = []
    workers = [
        threading.Thread(target=lambda: ports.append(docker_ops.free_port())) for _ in range(20)
    ]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert len(ports) == len(set(ports)) == 20


def test_file_lock_is_exclusive_across_threads(tmp_path: Path) -> None:
    inside: list[int] = []
    overlaps: list[bool] = []

    def work() -> None:
        with file_lock(tmp_path / "x.lock"):
            inside.append(1)
            overlaps.append(len(inside) > 1)
            inside.pop()

    workers = [threading.Thread(target=work) for _ in range(10)]
    for w in workers:
        w.start()
    for w in workers:
        w.join()
    assert overlaps and not any(overlaps)
