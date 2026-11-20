"""Decisions a person makes about findings that match no answer-key case.

Real-world targets have bugs nobody labelled (VAmPI's exposed debug console, DVWA's
default login). Those findings land in a run's ``adjudication.jsonl``. A person marks
each one ``real`` or ``not-real``; the decision goes to ``adjudications/<target>.yaml``
in the repo, so it is reviewed and versioned like any other suite data.

A decision is about a location and CWE in the target, not about the tool that reported
it, so it applies to every tool's findings there. Scores report adjudicated findings in
their own block (real, not real, pending) and never change the upstream answer key's
numbers.
"""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from itsuite.findings import Finding
from itsuite.keys.base import AnswerKey, Case, Location
from itsuite.matching import MatchParams, match_findings

VERDICTS = ("real", "not-real")
ANY_VARIANT = "*"


class AdjudicationError(ValueError):
    """An adjudication file or request is invalid."""


@dataclass(frozen=True)
class Decision:
    entry_id: str
    variant: str
    task: str
    path: str
    token: str
    start_line: int | None
    end_line: int | None
    cwes: tuple[int, ...]
    verdict: str
    note: str
    by: str
    day: str
    from_run: str


def file_for(root: Path, target: str) -> Path:
    return root / "adjudications" / f"{target}.yaml"


def _decision(item: Mapping[str, Any], where: str) -> Decision:
    verdict = str(item.get("verdict", ""))
    if verdict not in VERDICTS:
        raise AdjudicationError(f"{where}: verdict must be one of {VERDICTS}")
    if not item.get("by") or not (item.get("path") or item.get("token")):
        raise AdjudicationError(f"{where}: needs by, and a path or a token")
    return Decision(
        entry_id=str(item["id"]), variant=str(item.get("variant", ANY_VARIANT)),
        task=str(item.get("task", "")), path=str(item.get("path", "")),
        token=str(item.get("token", "")), start_line=item.get("start_line"),
        end_line=item.get("end_line"), cwes=tuple(int(c) for c in item.get("cwes") or ()),
        verdict=verdict, note=str(item.get("note", "")), by=str(item["by"]),
        day=str(item.get("date", "")), from_run=str(item.get("from_run", "")),
    )  # fmt: skip


def load(root: Path, target: str) -> list[Decision]:
    path = file_for(root, target)
    if not path.exists():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [_decision(item, f"{path.name}#{n}") for n, item in enumerate(data.get("entries") or [])]


def applicable(decisions: Sequence[Decision], variant: str, task: str) -> list[Decision]:
    return [d for d in decisions if d.variant in (ANY_VARIANT, variant) and d.task == task]


def _key(decisions: Sequence[Decision], match: str) -> AnswerKey:
    cases = tuple(
        Case(
            d.entry_id,
            d.verdict == "real",
            d.cwes,
            (Location(d.path, d.start_line, d.end_line, d.token),),
        )
        for d in decisions
        if (match == "token") == bool(d.token)
    )
    return AnswerKey("adjudicated", "", "adjudication", match, "", cases)


def classify(
    decisions: Sequence[Decision], findings: Sequence[Finding], unmatched: Sequence[int],
    match: str, paths: Sequence[str], params: MatchParams,
) -> dict[str, int]:  # fmt: skip
    """Count the unmatched findings that land on a real or not-real decision."""
    pending = [
        replace(findings[i], path=paths[i]) if i < len(paths) else findings[i] for i in unmatched
    ]
    key = _key(decisions, match)
    if not key.cases or not pending:
        return {"real": 0, "not_real": 0, "pending": len(pending)}
    result = match_findings(key, pending, params)
    real = {f for o in result.outcomes if o.positive for f in o.findings}
    not_real = {f for o in result.outcomes if not o.positive for f in o.findings} - real
    return {"real": len(real), "not_real": len(not_real),
            "pending": len(pending) - len(real) - len(not_real)}  # fmt: skip


def url_token(url: str) -> str:
    """The path of a URL, which is what a live finding is decided on."""
    return urllib.parse.urlparse(url).path or "/"


def entry_from(row: Mapping[str, Any], run: Mapping[str, Any], verdict: str, note: str,
               by: str, any_variant: bool, number: int) -> dict[str, Any]:  # fmt: skip
    live = bool(row.get("url")) and not row.get("source_path")
    entry: dict[str, Any] = {
        "id": f"{run['target']}-{number}",
        "variant": ANY_VARIANT if any_variant else run["variant"],
        "task": run.get("task") or "",
        "cwes": list(row.get("cwes") or []),
        "verdict": verdict, "note": note, "by": by, "date": date.today().isoformat(),
        "from_run": run["run_id"],
    }  # fmt: skip
    if live:
        entry["token"] = url_token(str(row["url"]))
    else:
        entry.update(path=row.get("source_path") or row.get("path"),
                     start_line=row.get("start_line"), end_line=row.get("end_line"))  # fmt: skip
    return entry


def mark(root: Path, run_dir: Path, indexes: Sequence[int], verdict: str, note: str, by: str,
         any_variant: bool = False) -> list[str]:  # fmt: skip
    """Record a decision for each listed unmatched finding of a run; returns new ids."""
    if verdict not in VERDICTS:
        raise AdjudicationError(f"verdict must be one of {VERDICTS}")
    if not by.strip():
        raise AdjudicationError("say who decided (--by)")
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    rows = {int(r["index"]): r for r in pending_rows(run_dir)}
    missing = [i for i in indexes if i not in rows]
    if missing:
        raise AdjudicationError(f"no unmatched finding with index {missing} in this run")
    path = file_for(root, run["target"])
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else None
    data = data or {"target": run["target"], "entries": []}
    start = len(data["entries"]) + 1
    new = [entry_from(rows[i], run, verdict, note, by, any_variant, start + n)
           for n, i in enumerate(indexes)]  # fmt: skip
    data["entries"] += new
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return [e["id"] for e in new]


def pending_rows(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "adjudication.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
