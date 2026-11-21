"""Scoring a finished run, importing upstream results, and the report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import result, sarif, write
from itsuite.keys.base import AnswerKey, Case, KeyStore, Location
from itsuite.report import load_scores, markdown, row
from itsuite.scoring import confusion_of, score_challenges, score_run
from itsuite.upstream import UpstreamImportError, import_agentdojo, import_jsonl, summarize


def _run_dir(tmp_path: Path, key: AnswerKey, **overrides: Any) -> tuple[Path, KeyStore]:
    store = KeyStore(tmp_path / "keys")
    digest = store.seal(key)
    run_dir = tmp_path / "results" / "run1"
    (run_dir / "out").mkdir(parents=True)
    record = {
        "run_id": "run1",
        "tool": "fake",
        "tool_version": "1",
        "target": key.target,
        "mode": "sast",
        "variant": key.variant,
        "task": key.task,
        "status": "ok",
        "sealed": False,
        "contamination": "high",
        "level": "L2",
        "duration_s": 1.0,
        "key_name": key.name,
        "key_digest": digest,
        "output_format": "sarif",
        "output_file": "results.sarif",
        "cwe_mode": "family",
        "line_tolerance": 0,
        "roots": ["/view"],
        "observations": {},
    }
    (run_dir / "run.json").write_text(json.dumps({**record, **overrides}))
    return run_dir, store


def _owasp_key() -> AnswerKey:
    cases = (
        Case("BenchmarkTest00001", True, (89,), (Location(token="BenchmarkTest00001"),), "sqli"),
        Case("BenchmarkTest00002", False, (89,), (Location(token="BenchmarkTest00002"),), "sqli"),
        Case("BenchmarkTest00003", True, (79,), (Location(token="BenchmarkTest00003"),), "xss"),
    )
    return AnswerKey("owasp", "default", "owasp-benchmark", "token", "c" * 40, cases)


def test_score_run_token_key_writes_score_and_adjudication(tmp_path: Path) -> None:
    run_dir, store = _run_dir(tmp_path, _owasp_key())
    write(
        run_dir,
        "out/results.sarif",
        sarif(
            [
                result("sql", "/view/src/BenchmarkTest00001.java", 5, tags=["CWE-89"]),
                result("sql", "/view/src/BenchmarkTest00002.java", 5, tags=["CWE-89"]),
                result("other", "/view/src/Helper.java", 1, tags=["CWE-1"]),
            ]
        ),
    )
    write(run_dir, "out/cost.json", json.dumps({"usd": 0.12, "secret": "x"}))
    score = score_run(run_dir, store)
    assert score["scored"] and score["overall"]["tp"] == 1 and score["overall"]["fp"] == 1
    assert score["overall"]["fn"] == 1 and score["unmatched_findings"] == 1
    assert score["per_category"]["sqli"]["youden"] == 0.0
    assert score["youden_mean_of_categories"] == 0.0  # sqli 0.0; xss has no negatives
    assert score["cost"] == {"usd": 0.12}
    lines = (run_dir / "adjudication.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["rule"] == "other"
    assert json.loads((run_dir / "score.json").read_text())["run_id"] == "run1"
    assert confusion_of(score).tp == 1


def test_crashed_run_is_not_scored(tmp_path: Path) -> None:
    run_dir, store = _run_dir(tmp_path, _owasp_key(), status="error")
    score = score_run(run_dir, store)
    assert not score["scored"] and "error" in score["reason"] and "overall" not in score


def test_unreadable_output_is_not_scored(tmp_path: Path) -> None:
    run_dir, store = _run_dir(tmp_path, _owasp_key())
    write(run_dir, "out/results.sarif", "garbage")
    score = score_run(run_dir, store)
    assert not score["scored"] and score["status"] == "unreadable-output"


def test_flag_run(tmp_path: Path) -> None:
    flag = "FLAG{" + "a" * 64 + "}"
    key = AnswerKey(
        "xbow",
        "default",
        "xbow-flag",
        "flag",
        "c" * 40,
        (Case("XBEN-1", True, secret=flag),),
        task="XBEN-1",
    )
    run_dir, store = _run_dir(tmp_path, key, output_format="flags")
    (run_dir / "stdout.log").write_text(f"found {flag}\n")
    assert score_run(run_dir, store)["overall"]["tp"] == 1


def test_challenge_run_counts_only_new_solves(tmp_path: Path) -> None:
    cases = tuple(Case(k, True) for k in ("a", "b", "c"))
    key = AnswerKey("js", "default", "juice-shop-challenges", "challenge", "c" * 40, cases)
    summary = score_challenges(key, ["a"], ["a", "b"])
    assert summary["overall"]["tp"] == 1 and summary["overall"]["fn"] == 1
    assert summary["already_solved_before_run"] == 1
    run_dir, store = _run_dir(tmp_path, key, observations={"before": [], "after": ["c"]})
    assert score_run(run_dir, store)["overall"]["tp"] == 1


def test_import_agentdojo_logs(tmp_path: Path) -> None:
    base = {"suite_name": "banking", "user_task_id": "user_task_0", "pipeline_name": "gpt-x"}
    write(
        tmp_path,
        "a/1.json",
        json.dumps({**base, "injection_task_id": "injection_task_1", "security": True}),
    )
    write(
        tmp_path,
        "a/2.json",
        json.dumps({**base, "injection_task_id": "injection_task_2", "security": False}),
    )
    write(tmp_path, "a/3.json", json.dumps({**base, "injection_task_id": None, "security": False}))
    results = import_agentdojo(tmp_path / "a")
    assert [r.task_id for r in results] == [
        "banking/user_task_0/injection_task_1",
        "banking/user_task_0/injection_task_2",
    ]
    summary = summarize(results)["gpt-x"]
    assert summary["tasks"] == 2 and summary["success_rate"] == 0.5
    write(tmp_path, "b/x.json", "{bad")
    with pytest.raises(UpstreamImportError):
        import_agentdojo(tmp_path / "b")


def test_import_jsonl_and_errored_tasks(tmp_path: Path) -> None:
    path = write(
        tmp_path,
        "r.jsonl",
        "\n".join(
            [
                json.dumps({"task_id": "t1", "success": True, "cost_usd": 0.5}),
                json.dumps({"task_id": "t2", "success": False, "error": "container crashed"}),
                "",
            ]
        ),
    )
    summary = summarize(import_jsonl(path))["default"]
    assert summary["tasks"] == 2 and summary["errored"] == 1 and summary["successes"] == 1
    assert summary["success_rate"] == 1.0 and summary["success_rate_errors_as_failures"] == 0.5
    assert summary["cost_usd"] == 0.5
    with pytest.raises(UpstreamImportError, match="boolean"):
        import_jsonl(write(tmp_path, "bad.jsonl", json.dumps({"task_id": "x", "success": "yes"})))
    with pytest.raises(UpstreamImportError, match="not JSON"):
        import_jsonl(write(tmp_path, "bad2.jsonl", "{"))


def test_report_markdown_flags_unscored_and_contamination(tmp_path: Path) -> None:
    scored = {
        "tool": "a",
        "target": "dvwa",
        "variant": "low",
        "mode": "dast",
        "status": "ok",
        "scored": True,
        "sealed": False,
        "contamination": "high",
        "cases": 2,
        "overall": {"tp": 1, "fp": 0, "fn": 1, "tn": 0, "precision": 1.0, "recall": 0.5},
        "unmatched_findings": 3,
    }
    failed = {**scored, "scored": False, "status": "timeout", "variant": "impossible"}
    for i, item in enumerate((scored, failed)):
        write(tmp_path, f"r{i}/score.json", json.dumps(item))
    text = markdown(load_scores(tmp_path))
    assert "NOT SCORED (timeout)" in text and "High-contamination" in text and "Unsealed" in text
    assert row(scored)["recall"] == 0.5
    assert markdown([]) == "No scored runs yet.\n"


def test_positive_only_keys_report_no_precision() -> None:
    from itsuite.matching import CaseOutcome
    from itsuite.scoring import summarize

    summary = summarize(
        [CaseOutcome("a", True, True, "", ()), CaseOutcome("b", True, False, "", ())]
    )
    assert summary["overall"]["precision"] is None and summary["precision_ci95"] is None
    assert summary["overall"]["recall"] == 0.5


def test_report_lists_runs_that_never_got_a_score(tmp_path: Path) -> None:
    write(tmp_path, "r1/run.json", json.dumps({"run_id": "r1", "tool": "a", "status": "ok"}))
    (tmp_path / "r2").mkdir()
    scores = load_scores(tmp_path)
    assert [(s.get("run_id"), s["scored"]) for s in scores] == [("r1", False), ("r2", False)]
    assert "NOT SCORED" in markdown(scores)


def test_score_run_reports_a_missing_key_instead_of_crashing(tmp_path: Path) -> None:
    run_dir, store = _run_dir(tmp_path, _owasp_key(), key_digest="0" * 64)
    score = score_run(run_dir, store)
    assert not score["scored"] and score["status"] == "key-error"
