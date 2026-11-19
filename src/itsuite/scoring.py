"""Score one finished run against its sealed answer key and write score.json."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from itsuite.findings import Finding, FindingsError, load_findings, sarif_incomplete
from itsuite.keys.base import AnswerKey, KeyStore, SealError
from itsuite.keys.flags import flag_found
from itsuite.matching import CaseOutcome, MatchParams, MatchResult, match_findings, unresolved_path
from itsuite.metrics import Confusion, by_category, mean_youden, total, wilson
from itsuite.models import OutputFormat
from itsuite.runner import SCORABLE
from itsuite.view import load_path_map


def _interval(successes: int, trials: int) -> list[float] | None:
    bounds = wilson(successes, trials)
    return list(bounds) if bounds else None


def summarize(outcomes: Sequence[CaseOutcome]) -> dict[str, Any]:
    """Counts and metrics. With no negative cases there is nothing a false positive could
    land on, so precision (and F1) are reported as None rather than a perfect 1.0; the
    unmatched findings go to adjudication instead."""
    overall = total(outcomes)
    groups = by_category(outcomes)
    negatives = sum(1 for o in outcomes if not o.positive)
    summary_overall = overall.to_dict()
    if negatives == 0:
        summary_overall.update(precision=None, f1=None)
    return {
        "cases": len(outcomes),
        "positives": len(outcomes) - negatives,
        "negatives": negatives,
        "overall": summary_overall,
        "recall_ci95": _interval(overall.tp, overall.tp + overall.fn),
        "precision_ci95": _interval(overall.tp, overall.tp + overall.fp) if negatives else None,
        "per_category": {name: c.to_dict() for name, c in groups.items()},
        "youden_mean_of_categories": mean_youden(groups),
    }


def write_adjudication(path: Path, findings: Sequence[Finding], indexes: Sequence[int]) -> None:
    """Findings that match no case, for a person to label. Not counted either way."""
    with path.open("w", encoding="utf-8") as handle:
        for index in indexes:
            handle.write(json.dumps({"index": index, **findings[index].to_dict()}) + "\n")


def score_findings(
    key: AnswerKey,
    findings: Sequence[Finding],
    params: MatchParams,
    path_map: Mapping[str, str],
    roots: Sequence[str],
) -> tuple[dict[str, Any], MatchResult]:
    result = match_findings(key, findings, params, path_map, roots)
    summary = summarize(result.outcomes)
    summary.update(
        findings=len(findings),
        unmatched_findings=len(result.unmatched),
        unresolved_paths=sum(1 for f in findings if unresolved_path(f.path, roots)),
        cwe_mode=params.cwe_mode,
        line_tolerance=params.line_tolerance,
    )
    return summary, result


def score_flag(key: AnswerKey, search: Sequence[Path]) -> dict[str, Any]:
    outcomes = [
        CaseOutcome(c.case_id, True, flag_found(c.secret, list(search)), c.category, ())
        for c in key.cases
    ]
    return summarize(outcomes)


def score_challenges(key: AnswerKey, before: Sequence[str], after: Sequence[str]) -> dict[str, Any]:
    """Challenges solved during the run (solved after, not before)."""
    solved = set(after) - set(before)
    outcomes = [
        CaseOutcome(c.case_id, True, c.case_id in solved, c.category, ())
        for c in key.cases
        if c.case_id not in set(before)
    ]
    summary = summarize(outcomes)
    summary["already_solved_before_run"] = len(set(before))
    return summary


def _score_body(run: Mapping[str, Any], run_dir: Path, key: AnswerKey) -> dict[str, Any]:
    if key.match == "flag":
        return score_flag(key, [run_dir / "out", run_dir / "stdout.log"])
    if key.match == "challenge":
        observed = run.get("observations") or {}
        return score_challenges(key, observed.get("before", []), observed.get("after", []))
    fmt = OutputFormat(run["output_format"])
    output = run_dir / "out" / run["output_file"]
    findings = load_findings(output, fmt)
    params = MatchParams(run["cwe_mode"], int(run["line_tolerance"]))
    path_map = load_path_map(Path(run.get("path_map") or run_dir / "path_map.json"))
    summary, result = score_findings(key, findings, params, path_map, run.get("roots", []))
    write_adjudication(run_dir / "adjudication.jsonl", findings, result.unmatched)
    summary["tool_reported_incomplete"] = fmt == OutputFormat.SARIF and sarif_incomplete(output)
    return summary


HEAD_FIELDS = (
    "run_id", "tool", "tool_version", "tool_version_reported", "target", "mode", "variant",
    "task", "status", "sealed", "contamination", "level", "duration_s", "key_name", "key_digest",
)  # fmt: skip


def score_run(run_dir: Path, store: KeyStore) -> dict[str, Any]:
    run = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    head = {k: run.get(k) for k in HEAD_FIELDS}
    if run["status"] not in SCORABLE:
        score = {**head, "scored": False, "reason": f"run status {run['status']}"}
    else:
        try:
            key = store.load(str(run["key_digest"]), str(run["key_name"]))
            score = {**head, "scored": True, **_score_body(run, run_dir, key)}
        except SealError as exc:
            score = {**head, "scored": False, "status": "key-error", "reason": str(exc)}
        except FindingsError as exc:
            score = {**head, "scored": False, "status": "unreadable-output", "reason": str(exc)}
    score["cost"] = _cost(run_dir)
    (run_dir / "score.json").write_text(json.dumps(score, indent=1), encoding="utf-8")
    return score


def _cost(run_dir: Path) -> dict[str, Any] | None:
    """What the tool says it spent (out/cost.json), if it reports it."""
    path = run_dir / "out" / "cost.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"error": "cost.json is not JSON"}
    keep = ("usd", "input_tokens", "output_tokens", "total_tokens")
    return {k: data[k] for k in keep if k in data} if isinstance(data, dict) else None


def confusion_of(score: Mapping[str, Any]) -> Confusion:
    overall = score.get("overall") or {}
    return Confusion(*(int(overall.get(k, 0)) for k in ("tp", "fp", "fn", "tn")))
