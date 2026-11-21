"""Import results from benchmarks that grade themselves (the ``bridge`` targets).

Two inputs are accepted:

* AgentDojo's own log folder. Each JSON log has ``suite_name``, ``user_task_id``,
  ``injection_task_id`` and ``security``; in AgentDojo ``security: true`` means the
  injection task succeeded. When the tool under test is the attacker, that is a
  success for the tool.
* A normalized JSON Lines file written by a bridge script, one task per line:
  ``{"task_id": str, "success": bool, "variant": str?, "duration_s": float?,
  "cost_usd": float?, "error": str?}``. A line with ``error`` is not a failure of the
  target; it is reported as an errored task and left out of the rate.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsuite.metrics import wilson


class UpstreamImportError(ValueError):
    """Upstream results could not be read."""


@dataclass(frozen=True)
class TaskResult:
    task_id: str
    success: bool
    variant: str = "default"
    duration_s: float | None = None
    cost_usd: float | None = None
    error: str = ""


def import_agentdojo(folder: Path) -> list[TaskResult]:
    results = []
    for path in sorted(folder.rglob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise UpstreamImportError(f"{path}: not JSON") from exc
        if not isinstance(data, dict) or data.get("injection_task_id") in (None, "none"):
            continue  # utility-only runs have no attack to score
        task = "/".join(
            str(data.get(k)) for k in ("suite_name", "user_task_id", "injection_task_id")
        )
        results.append(
            TaskResult(
                task_id=task,
                success=bool(data.get("security")),
                variant=str(data.get("pipeline_name") or "default"),
                duration_s=data.get("duration"),
                error=str(data.get("error") or ""),
            )
        )
    return results


def _task_line(item: Any, where: str) -> TaskResult:
    if (
        not isinstance(item, dict)
        or "task_id" not in item
        or not isinstance(item.get("success"), bool)
    ):
        raise UpstreamImportError(f"{where}: needs task_id and a boolean success")
    return TaskResult(
        task_id=str(item["task_id"]),
        success=item["success"],
        variant=str(item.get("variant", "default")),
        duration_s=item.get("duration_s"),
        cost_usd=item.get("cost_usd"),
        error=str(item.get("error") or ""),
    )


def import_jsonl(path: Path) -> list[TaskResult]:
    results = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise UpstreamImportError(f"{path.name}:{number}: not JSON") from exc
        results.append(_task_line(item, f"{path.name}:{number}"))
    return results


def summarize(results: Iterable[TaskResult]) -> dict[str, Any]:
    by_variant: dict[str, list[TaskResult]] = {}
    for result in results:
        by_variant.setdefault(result.variant, []).append(result)
    summary = {}
    for variant, items in sorted(by_variant.items()):
        graded = [r for r in items if not r.error]
        wins = sum(1 for r in graded if r.success)
        bounds = wilson(wins, len(graded))
        summary[variant] = {
            "tasks": len(items),
            "errored": len(items) - len(graded),
            "successes": wins,
            "success_rate": wins / len(graded) if graded else None,
            # Errored tasks counted as failures: the lower bound, so a tool that crashes
            # often can't look better than it is.
            "success_rate_errors_as_failures": wins / len(items) if items else None,
            "success_ci95": list(bounds) if bounds else None,
            "cost_usd": sum(r.cost_usd or 0.0 for r in items) or None,
        }
    return summary
