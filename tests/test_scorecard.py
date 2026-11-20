"""Per-tool scorecards built from score.json files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SUITE_ROOT, write
from itsuite import scorecard
from itsuite.catalog import load_catalog

CATALOG = load_catalog(SUITE_ROOT)


def _score(run_id: str, tool: str = "bandit", target: str = "owasp-benchmark-python",
           mode: str = "sast", tp: int = 5, fp: int = 1, fn: int = 5, tn: int = 9,
           negatives: int = 10, **extra: Any) -> dict[str, Any]:  # fmt: skip
    recall = tp / (tp + fn) if tp + fn else None
    return {
        "run_id": run_id, "tool": tool, "target": target, "mode": mode, "variant": "default",
        "task": "", "scored": True, "sealed": False, "contamination": "medium", "level": "L2",
        "negatives": negatives, "overall": {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "recall": recall},
        "cost": None, **extra,
    }  # fmt: skip


def test_each_run_key_counts_once_and_repeats_show_a_range() -> None:
    scores = [_score("1", tp=4, fn=6), _score("2", tp=6, fn=4), _score("3", scored=False)]
    cell = scorecard.build(scores, CATALOG)["bandit"]["sast"]
    assert cell.runs == 1 and cell.unscored == 1
    assert cell.all_cases.tp == 6  # the latest scored run, not 4 + 6
    assert cell.recalls == [0.4, 0.6]


def test_sealed_run_beats_a_later_unsealed_one() -> None:
    scores = [_score("1", tp=8, fn=2, sealed=True), _score("2", tp=1, fn=9)]
    cell = scorecard.build(scores, CATALOG)["bandit"]["sast"]
    assert cell.all_cases.tp == 8 and cell.sealed == 1


def test_grouping_keeps_contamination_apart_and_live_by_capability() -> None:
    dvwa = _score("1", tool="zap", target="dvwa", mode="dast", contamination="high", negatives=0)
    vampi = _score("2", tool="zap", target="vampi", mode="dast", negatives=6)
    table = scorecard.build([dvwa, vampi], CATALOG)
    assert set(table["zap"]) == {"web (high contamination)", "api"}
    assert scorecard.groups_for(dvwa, CATALOG, "level") == ["L2 (high contamination)"]
    assert scorecard.groups_for(vampi, CATALOG, "target") == ["vampi dast"]
    with pytest.raises(ValueError):
        scorecard.build([], CATALOG, "colour")


def test_precision_only_from_runs_with_negatives_and_unknown_tools_dropped() -> None:
    positives_only = _score("1", tool="semgrep", target="cwe-bench-java", tp=1, fp=0, fn=0, tn=0,
                            negatives=0, task="p")  # fmt: skip
    with_negatives = _score("2", tool="semgrep", tp=3, fp=3, fn=1, tn=5)
    selftest = _score("3", tool="flagcheck")
    table = scorecard.build([positives_only, with_negatives, selftest], CATALOG)
    cell = table["semgrep"]["sast"]
    assert cell.all_cases.tp == 4 and cell.with_negatives.precision == 0.5
    assert "flagcheck" not in table


def test_markdown_has_comparison_tool_sections_cost_and_upstream(tmp_path: Path) -> None:
    scores = [_score("1", cost={"usd": 2.0}), _score("2", tool="semgrep")]
    write(
        tmp_path,
        "upstream-argus-cybench.json",
        json.dumps(
            {
                "tool": "argus",
                "target": "cybench",
                "variants": {
                    "unguided": {
                        "successes": 1,
                        "tasks": 4,
                        "success_rate": 0.25,
                        "success_rate_errors_as_failures": 0.2,
                    }
                },
            }
        ),
    )
    text = scorecard.markdown(scorecard.build(scores, CATALOG), "capability", tmp_path)
    assert "## Comparison" in text and "## bandit" in text and "## semgrep" in text
    assert "$2.00" in text and "$0.40" in text  # cost and cost per true positive
    assert "| argus | cybench | unguided | 1/4 | 25.0% | 20.0% |" in text
    row = scorecard.cell_row("g", scorecard.Cell())
    assert row[5] == "-" and row[-1] == "-"
