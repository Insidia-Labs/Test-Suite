"""One scorecard per tool, built from every score.json, plus a tool-vs-tool comparison.

Rules (METHODOLOGY.md):
* Each (tool, target, mode, variant, task) counts once in the totals: its latest scored
  run. Repeats are shown as a recall range, not added up.
* High-contamination targets are kept in their own rows, never mixed into a total.
* Unscored runs (crash, timeout, no output) are counted and shown, never as clean results.
* Precision and F1 come only from cases with negatives (a positives-only key can't show
  a false positive), so they are pooled over those runs alone.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from itsuite.catalog import Catalog
from itsuite.metrics import Confusion, wilson

GROUPINGS = ("capability", "level", "target")
_RUN_KEY = ("tool", "target", "mode", "variant", "task")


@dataclass
class Cell:
    runs: int = 0
    unscored: int = 0
    sealed: int = 0
    with_negatives: Confusion = field(default_factory=Confusion)
    all_cases: Confusion = field(default_factory=Confusion)
    recalls: list[float] = field(default_factory=list)
    cost_usd: float = 0.0
    has_cost: bool = False
    adjudicated: dict[str, int] = field(default_factory=dict)


def _confusion(score: Mapping[str, Any]) -> Confusion:
    overall = score.get("overall") or {}
    return Confusion(*(int(overall.get(k) or 0) for k in ("tp", "fp", "fn", "tn")))


def _key(score: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(str(score.get(k) or "") for k in _RUN_KEY)


RunKey = tuple[str, ...]


def latest(
    scores: Iterable[Mapping[str, Any]],
) -> tuple[dict[RunKey, Mapping[str, Any]], dict[RunKey, list[float]]]:
    """The latest scored run per key (a sealed run beats any unsealed one, since sealed
    numbers are the ones to publish), and every repeat's recall per key."""
    chosen: dict[tuple[str, ...], Mapping[str, Any]] = {}
    recalls: dict[tuple[str, ...], list[float]] = {}
    for score in sorted(scores, key=lambda s: str(s.get("run_id") or "")):
        if not score.get("scored"):
            continue
        key = _key(score)
        if key not in chosen or score.get("sealed") or not chosen[key].get("sealed"):
            chosen[key] = score
        recall = (score.get("overall") or {}).get("recall")
        if recall is not None:
            recalls.setdefault(key, []).append(float(recall))
    return chosen, recalls


LIVE_CAPABILITIES = ("web", "api", "graphql", "microservices", "llm-app", "agent", "mcp")


def groups_for(score: Mapping[str, Any], catalog: Catalog, by: str) -> list[str]:
    """Live runs group by what the target is (web, api...); every other mode by the mode
    itself (sast, secrets...), so a source scan never counts as a web result."""
    target = catalog.targets.get(str(score.get("target")))
    contaminated = " (high contamination)" if score.get("contamination") == "high" else ""
    if by == "level":
        return [f"{score.get('level') or '?'}{contaminated}"]
    if by == "target":
        return [f"{score.get('target')} {score.get('mode')}{contaminated}"]
    if score.get("mode") != "dast":
        return [f"{score.get('mode')}{contaminated}"]
    caps = [c for c in (target.capabilities if target else ()) if c in LIVE_CAPABILITIES]
    return [f"{cap}{contaminated}" for cap in caps or ["web"]]


def _add(cell: Cell, score: Mapping[str, Any], recalls: Sequence[float]) -> None:
    confusion = _confusion(score)
    cell.runs += 1
    cell.sealed += 1 if score.get("sealed") else 0
    cell.all_cases = cell.all_cases + confusion
    if int(score.get("negatives") or 0) > 0:
        cell.with_negatives = cell.with_negatives + confusion
    if len(recalls) > 1:
        cell.recalls += [min(recalls), max(recalls)]
    for name, count in (score.get("adjudicated") or {}).items():
        cell.adjudicated[name] = cell.adjudicated.get(name, 0) + int(count)
    cost = (score.get("cost") or {}).get("usd")
    if isinstance(cost, (int, float)):
        cell.cost_usd += float(cost)
        cell.has_cost = True


def build(scores: Sequence[Mapping[str, Any]], catalog: Catalog, by: str = "capability",
          ) -> dict[str, dict[str, Cell]]:  # fmt: skip
    """tool -> group -> Cell."""
    if by not in GROUPINGS:
        raise ValueError(f"group by one of {GROUPINGS}")
    known = [s for s in scores if str(s.get("tool")) in catalog.tools]
    chosen, recalls = latest(known)
    table: dict[str, dict[str, Cell]] = {}
    for key, score in chosen.items():
        for group in groups_for(score, catalog, by):
            _add(
                table.setdefault(key[0], {}).setdefault(group, Cell()), score, recalls.get(key, [])
            )
    for score in known:
        if not score.get("scored"):
            for group in groups_for(score, catalog, by):
                table.setdefault(str(score["tool"]), {}).setdefault(group, Cell()).unscored += 1
    return table


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def _ci(successes: int, trials: int) -> str:
    bounds = wilson(successes, trials)
    return "" if bounds is None else f" ({bounds[0] * 100:.0f}-{bounds[1] * 100:.0f})"


def cell_row(group: str, cell: Cell) -> list[str]:
    allc, neg = cell.all_cases, cell.with_negatives
    spread = (
        f"{min(cell.recalls) * 100:.0f}-{max(cell.recalls) * 100:.0f}%" if cell.recalls else "-"
    )
    cost = f"${cell.cost_usd:.2f}" if cell.has_cost else "-"
    adj = cell.adjudicated
    outside = (
        f"{adj.get('real', 0)}/{adj.get('not_real', 0)}/{adj.get('pending', 0)}" if adj else "-"
    )
    per_tp = f"${cell.cost_usd / allc.tp:.2f}" if cell.has_cost and allc.tp else "-"
    return [
        group, str(cell.runs), str(cell.unscored), f"{cell.sealed}/{cell.runs}",
        f"{allc.tp}/{allc.tp + allc.fn}", _pct(allc.recall) + _ci(allc.tp, allc.tp + allc.fn),
        _pct(neg.precision) + _ci(neg.tp, neg.tp + neg.fp), _pct(neg.fpr), spread, outside,
        cost, per_tp,
    ]  # fmt: skip


HEADER = ["group", "runs", "unscored", "sealed", "found", "recall (95% CI)",
          "precision (95% CI)", "FP rate", "repeat recall", "outside key real/not/pending",
          "cost", "cost/TP"]  # fmt: skip


def _table(rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(HEADER) + " |", "|" + "---|" * len(HEADER)]
    return lines + ["| " + " | ".join(row) + " |" for row in rows]


def comparison(table: Mapping[str, Mapping[str, Cell]]) -> list[str]:
    groups = sorted({g for cells in table.values() for g in cells})
    tools = sorted(table)
    lines = ["| group | " + " | ".join(tools) + " |", "|" + "---|" * (len(tools) + 1)]
    for group in groups:
        cells = [table[t].get(group) for t in tools]
        shown = [
            "-" if c is None else f"{_pct(c.all_cases.recall)} / {_pct(c.with_negatives.precision)}"
            for c in cells
        ]
        lines.append(f"| {group} | " + " | ".join(shown) + " |")
    return lines


def upstream_rows(results_root: Path) -> list[str]:
    lines = []
    for path in sorted(results_root.glob("upstream-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for variant, s in (data.get("variants") or {}).items():
            rate = s.get("success_rate")
            low = s.get("success_rate_errors_as_failures")
            solved = f"{s.get('successes')}/{s.get('tasks')}"
            lines.append(f"| {data.get('tool')} | {data.get('target')} | {variant} | {solved} | "
                         f"{_pct(rate)} | {_pct(low)} |")  # fmt: skip
    if not lines:
        return []
    return ["## Benchmarks graded by their own harness", "",
            "| tool | target | variant | solved | success | errors as failures |",
            "|---|---|---|---|---|---|", *lines, ""]  # fmt: skip


def markdown(table: Mapping[str, Mapping[str, Cell]], by: str, results_root: Path) -> str:
    out = [f"# Scorecard (by {by})", "",
           "Recall counts every case; precision and FP rate only cases with negatives. "
           "High-contamination rows are kept apart. Each run key counts once (its latest "
           "scored run); repeats show as a recall range.", "",
           "## Comparison (recall / precision)", "", *comparison(table), ""]  # fmt: skip
    for tool in sorted(table):
        rows = [cell_row(group, cell) for group, cell in sorted(table[tool].items())]
        out += [f"## {tool}", "", *_table(rows), ""]
    out += upstream_rows(results_root)
    return "\n".join(out)
