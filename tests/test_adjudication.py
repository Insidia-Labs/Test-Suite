"""Deciding findings outside the answer key, and applying decisions to every tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import write
from itsuite import adjudication
from itsuite.findings import Finding
from itsuite.matching import MatchParams


def _run(root: Path, rows: list[dict[str, object]], variant: str = "low") -> Path:
    run_dir = root / "results" / "r1"
    write(run_dir, "run.json", json.dumps({"run_id": "r1", "target": "dvwa", "variant": variant,
                                           "task": ""}))  # fmt: skip
    write(run_dir, "adjudication.jsonl", "\n".join(json.dumps(r) for r in rows) + "\n")
    return run_dir


ROWS = [
    {
        "index": 3,
        "rule": "default-login",
        "cwes": [798],
        "url": "http://127.0.0.1:9/index.php",
        "path": "",
        "start_line": None,
        "end_line": None,
        "source_path": "",
    },
    {
        "index": 7,
        "rule": "sqli",
        "cwes": [89],
        "url": "",
        "path": "/view/src/db.php",
        "start_line": 12,
        "end_line": 12,
        "source_path": "src/db.php",
    },
]


def test_mark_writes_reviewable_decisions(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, ROWS)
    ids = adjudication.mark(tmp_path, run_dir, [3, 7], "real", "default creds", "rushi", True)
    assert ids == ["dvwa-1", "dvwa-2"]
    decisions = adjudication.load(tmp_path, "dvwa")
    live, source = decisions
    assert (live.token, live.variant, live.by) == ("/index.php", "*", "rushi")
    assert (source.path, source.start_line) == ("src/db.php", 12)
    more = adjudication.mark(tmp_path, run_dir, [7], "not-real", "", "rushi")
    assert more == ["dvwa-3"] and adjudication.load(tmp_path, "dvwa")[2].variant == "low"


def test_mark_refuses_bad_requests(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, ROWS)
    with pytest.raises(adjudication.AdjudicationError, match="verdict"):
        adjudication.mark(tmp_path, run_dir, [3], "maybe", "", "rushi")
    with pytest.raises(adjudication.AdjudicationError, match="--by"):
        adjudication.mark(tmp_path, run_dir, [3], "real", "", " ")
    with pytest.raises(adjudication.AdjudicationError, match="index"):
        adjudication.mark(tmp_path, run_dir, [99], "real", "", "rushi")


def test_classify_applies_decisions_to_any_tools_findings(tmp_path: Path) -> None:
    run_dir = _run(tmp_path, ROWS)
    adjudication.mark(tmp_path, run_dir, [3], "real", "", "rushi", True)
    adjudication.mark(tmp_path, run_dir, [7], "not-real", "", "rushi", True)
    decisions = adjudication.applicable(adjudication.load(tmp_path, "dvwa"), "impossible", "")
    other_tool = [Finding("creds", (798,), url="http://127.0.0.1:5/index.php?x=1"),
                  Finding("hdr", (693,), url="http://127.0.0.1:5/index.php")]  # fmt: skip
    counts = adjudication.classify(decisions, other_tool, [0, 1], "token", ["", ""], MatchParams())
    assert counts == {"real": 1, "not_real": 0, "pending": 1}  # CWE must still fit
    source = [Finding("s", (89,), "/other/view/src/db.php", 13, 13)]
    counts = adjudication.classify(decisions, source, [0], "location", ["src/db.php"],
                                   MatchParams("family", 1))  # fmt: skip
    assert counts == {"real": 0, "not_real": 1, "pending": 0}
    assert adjudication.classify([], source, [0], "location", [""], MatchParams()) == {
        "real": 0,
        "not_real": 0,
        "pending": 1,
    }


def test_bad_adjudication_file_is_refused(tmp_path: Path) -> None:
    write(
        tmp_path,
        "adjudications/x.yaml",
        "entries:\n  - {id: a, verdict: true-ish, by: r, token: /}\n",
    )
    with pytest.raises(adjudication.AdjudicationError, match="verdict"):
        adjudication.load(tmp_path, "x")
    write(tmp_path, "adjudications/y.yaml", "entries:\n  - {id: a, verdict: real, token: /}\n")
    with pytest.raises(adjudication.AdjudicationError, match="needs by"):
        adjudication.load(tmp_path, "y")
    assert adjudication.load(tmp_path, "none") == [] and adjudication.url_token("http://h") == "/"
