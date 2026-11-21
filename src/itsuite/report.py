"""Collect score.json files into one table per tool, with errors and contamination shown."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

_COLUMNS = (
    "run",
    "tool",
    "target",
    "variant",
    "task",
    "mode",
    "status",
    "sealed",
    "contamination",
    "cases",
    "tp",
    "fp",
    "fn",
    "tn",
    "precision",
    "recall",
    "youden",
    "unmatched",
)


def load_scores(results_root: Path) -> list[dict[str, Any]]:
    """Every run folder. One without score.json (the harness stopped before scoring) is
    listed as not scored instead of disappearing from the report."""
    scores = []
    for run_dir in sorted(p for p in results_root.glob("*") if p.is_dir()):
        score_path, run_path = run_dir / "score.json", run_dir / "run.json"
        if score_path.exists():
            scores.append(json.loads(score_path.read_text(encoding="utf-8")))
        elif run_path.exists():
            run = json.loads(run_path.read_text(encoding="utf-8"))
            scores.append({**run, "scored": False, "status": run.get("status", "incomplete")})
        else:
            scores.append({"run_id": run_dir.name, "scored": False, "status": "incomplete"})
    return scores


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def row(score: Mapping[str, Any]) -> dict[str, Any]:
    overall = score.get("overall") or {}
    youden = score.get("youden_mean_of_categories")
    return {
        "run": str(score.get("run_id") or "")[:16],
        "tool": score.get("tool"),
        "target": score.get("target"),
        "variant": score.get("variant"),
        "task": score.get("task") or "",
        "mode": score.get("mode"),
        "status": score.get("status")
        if score.get("scored")
        else f"NOT SCORED ({score.get('status')})",
        "sealed": score.get("sealed"),
        "contamination": score.get("contamination"),
        "cases": score.get("cases"),
        "tp": overall.get("tp"),
        "fp": overall.get("fp"),
        "fn": overall.get("fn"),
        "tn": overall.get("tn"),
        "precision": overall.get("precision"),
        "recall": overall.get("recall"),
        "youden": youden if youden is not None else overall.get("youden"),
        "unmatched": score.get("unmatched_findings"),
    }


def markdown(scores: Sequence[Mapping[str, Any]]) -> str:
    if not scores:
        return "No scored runs yet.\n"
    rows = sorted(
        (row(s) for s in scores), key=lambda r: tuple(_fmt(r[c]) for c in (*_COLUMNS[1:6], "run"))
    )
    lines = [
        "| " + " | ".join(_COLUMNS) + " |",
        "|" + "---|" * len(_COLUMNS),
        *("| " + " | ".join(_fmt(r[c]) for c in _COLUMNS) + " |" for r in rows),
    ]
    notes = _notes(scores)
    return "\n".join(lines) + "\n" + ("\n" + "\n".join(notes) + "\n" if notes else "")


def _notes(scores: Iterable[Mapping[str, Any]]) -> list[str]:
    items = list(scores)
    notes = []
    if any(s.get("contamination") == "high" for s in items):
        notes.append(
            "- High-contamination targets: solutions are public and likely in LLM "
            "training data. Read those rows separately."
        )
    if any(not s.get("sealed") for s in items):
        notes.append("- Unsealed runs (host mode): the tool could read the answer cache.")
    if any(not s.get("scored") for s in items):
        notes.append(
            "- NOT SCORED rows crashed, timed out or wrote no output. They are not "
            "counted as clean results."
        )
    return notes
