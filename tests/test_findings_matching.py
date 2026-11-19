"""Reading tool output and matching it to answer-key cases."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from conftest import result, sarif, write
from itsuite.findings import Finding, FindingsError, load_findings, parse_sarif, parse_trufflehog
from itsuite.keys.base import AnswerKey, Case, Location
from itsuite.matching import (
    MatchParams,
    match_findings,
    normalize_path,
    same_file,
    token_candidates,
)
from itsuite.models import OutputFormat


def test_sarif_cwe_from_tags_rules_and_taxa(tmp_path: Path) -> None:
    rules = [
        {"id": "r1", "properties": {"tags": ["security", "external/cwe/cwe-089"]}},
        {"id": "r2", "relationships": [{"target": {"id": "79", "toolComponent": {"name": "CWE"}}}]},
    ]
    results = [
        result("r1", "src/A.java", 10),
        {**result("r2", url="http://127.0.0.1:5/x?q=1"), "ruleIndex": 1},
        {
            **result("r3", "file:///work/src/B%20C.py", 3),
            "taxa": [{"id": "CWE-22", "toolComponent": {"name": "CWE"}}],
        },
    ]
    path = write(tmp_path, "r.sarif", sarif(results, rules))
    found = parse_sarif(path)
    assert [f.cwes for f in found] == [(89,), (79,), (22,)]
    assert found[0].path == "src/A.java" and found[0].start_line == 10 and found[0].end_line == 10
    assert found[1].url == "http://127.0.0.1:5/x?q=1" and found[1].path == ""
    assert found[2].path == "/work/src/B C.py"


def test_sarif_logical_locations_and_result_tags(tmp_path: Path) -> None:
    item = result("x", "api/users", tags=["CWE-200"])
    item["locations"][0]["logicalLocations"] = [{"fullyQualifiedName": "GET /users/v1/_debug"}]
    found = parse_sarif(write(tmp_path, "r.sarif", sarif([item])))[0]
    assert found.cwes == (200,) and "GET /users/v1/_debug" in found.locator_text()
    assert found.to_dict()["logical"] == ["GET /users/v1/_debug"]


@pytest.mark.parametrize("body", ["not json", json.dumps({"runs": "nope"})])
def test_sarif_errors(tmp_path: Path, body: str) -> None:
    with pytest.raises(FindingsError):
        parse_sarif(write(tmp_path, "r.sarif", body))


def test_trufflehog_jsonl(tmp_path: Path) -> None:
    line = {
        "DetectorName": "AWS",
        "Verified": False,
        "SourceMetadata": {"Data": {"Filesystem": {"file": "./data/x.py", "line": 4}}},
    }
    path = write(tmp_path, "r.jsonl", json.dumps(line) + "\n\n")
    found = load_findings(path, OutputFormat.TRUFFLEHOG)
    assert found == [Finding("AWS", (798,), "data/x.py", 4, 4, message="unverified")]
    with pytest.raises(FindingsError):
        parse_trufflehog(write(tmp_path, "bad.jsonl", "{oops\n"))
    with pytest.raises(FindingsError, match="importer"):
        load_findings(path, OutputFormat.UPSTREAM_JSONL)


def _token_key(*cases: Case) -> AnswerKey:
    return AnswerKey("t", "v", "k", "token", "c" * 40, cases)


def _case(case_id: str, token: str, cwes: tuple[int, ...] = (), positive: bool = True) -> Case:
    return Case(case_id, positive, cwes, (Location(token=token),))


def test_token_boundaries_keep_similar_modules_apart() -> None:
    cases = [_case("sqli", "/vulnerabilities/sqli"), _case("blind", "/vulnerabilities/sqli_blind")]
    hit = Finding("r", (89,), url="http://h/vulnerabilities/sqli_blind/?id=1")
    assert token_candidates(cases, hit) == [1]
    other = Finding("r", (89,), path="src/BenchmarkTest000010.java")
    assert token_candidates([_case("b1", "BenchmarkTest00001")], other) == []


def test_most_specific_template_wins_and_wildcard_always_counts() -> None:
    cases = [
        _case("sqli", "/users/v1/{username}", (89,)),
        _case("login", "/users/v1/login", (204,)),
        _case("pw", "/users/v1/{username}/password", (620,)),
        _case("jwt", "*", (321,)),
    ]
    assert token_candidates(cases, Finding("r", (), url="http://h/users/v1/login")) == [1, 3]
    assert token_candidates(cases, Finding("r", (), url="http://h/users/v1/bob/password")) == [2, 3]
    assert token_candidates(cases, Finding("r", (), url="http://h/users/v1/bob")) == [0, 3]


def test_token_match_applies_cwe_mode_and_reports_unmatched() -> None:
    key = _token_key(
        _case("sqli", "/users/v1/{username}", (89,)),
        _case("login", "/users/v1/login", (204,), False),
    )
    findings = [
        Finding("a", (89,), url="http://h/users/v1/bob"),
        Finding("b", (89,), url="http://h/users/v1/login"),  # login wins, CWE doesn't fit
        Finding("c", (204,), url="http://h/users/v1/login"),
    ]
    res = match_findings(key, findings, MatchParams("family"))
    assert [(o.case_id, o.hit, o.findings) for o in res.outcomes] == [
        ("sqli", True, (0,)),
        ("login", True, (2,)),
    ]
    assert res.unmatched == (1,)


def _loc_key(*cases: Case) -> AnswerKey:
    return AnswerKey("t", "v", "k", "location", "c" * 40, cases)


def test_location_match_with_tolerance_path_map_and_roots() -> None:
    key = _loc_key(
        Case("c1", True, (125,), (Location("dataset/125/a.c", 8, 8),)),
        Case("c2", False, (125,), (Location("dataset/125/b.c"),)),
    )
    findings = [
        Finding("r", (125,), "/view/cases/abc.c", 9, 9),  # tolerance 1 reaches line 8
        Finding("r", (125,), "/view/cases/def.c", 40, None),  # file-level negative -> FP
        Finding("r", (125,), "/view/cases/abc.c", None),  # no line: can't hit a line case
    ]
    path_map = {"cases/abc.c": "dataset/125/a.c", "cases/def.c": "dataset/125/b.c"}
    res = match_findings(key, findings, MatchParams("strict", 1), path_map, ["/view"])
    assert [(o.case_id, o.hit) for o in res.outcomes] == [("c1", True), ("c2", True)]
    assert res.unmatched == (2,)
    strict = match_findings(key, findings[:1], MatchParams("strict", 0), path_map, ["/view"])
    assert not strict.outcomes[0].hit


def test_path_helpers() -> None:
    assert normalize_path("/tmp/v/src/A.java", ["/tmp/v"]) == "src/A.java"
    assert normalize_path("./x\\y.py") == "x/y.py"
    assert same_file("project/src/A.java", "src/A.java")
    assert not same_file("src/AA.java", "A.java")
    assert not same_file("", "a")


def test_flag_and_challenge_keys_are_not_matched_from_findings() -> None:
    key = AnswerKey("t", "v", "k", "flag", "c" * 40, ())
    with pytest.raises(ValueError):
        match_findings(key, [], MatchParams())


def test_sarif_skips_passes_and_suppressed_results(tmp_path: Path) -> None:
    results = [
        result("real", "a.py", 1, tags=["CWE-89"]),
        {**result("passed", "a.py", 2), "kind": "pass"},
        {**result("na", "a.py", 3), "kind": "notApplicable"},
        {**result("hidden", "a.py", 4), "suppressions": [{"kind": "inSource"}]},
        {
            **result("rejected", "a.py", 5),
            "suppressions": [{"kind": "external", "status": "rejected"}],
        },
    ]
    found = parse_sarif(write(tmp_path, "r.sarif", sarif(results)))
    assert [f.rule for f in found] == ["real", "rejected"]


def test_sarif_malformed_and_incomplete(tmp_path: Path) -> None:
    from itsuite.findings import sarif_incomplete

    bad = json.dumps({"runs": [{"tool": "not-a-dict", "results": [{"ruleId": "x"}]}]})
    with pytest.raises(FindingsError, match="malformed"):
        parse_sarif(write(tmp_path, "bad.sarif", bad))
    doc = {
        "runs": [
            {
                "tool": {"driver": {"name": "t"}},
                "results": [],
                "invocations": [{"executionSuccessful": False}],
            }
        ]
    }
    assert sarif_incomplete(write(tmp_path, "inc.sarif", json.dumps(doc)))
    assert not sarif_incomplete(write(tmp_path, "ok.sarif", sarif([])))
    assert not sarif_incomplete(tmp_path / "missing.sarif")
    (tmp_path / "bin.jsonl").write_bytes(b"\xff\xfe\x00")
    with pytest.raises(FindingsError, match="not readable"):
        parse_trufflehog(tmp_path / "bin.jsonl")


def test_file_wide_finding_counts_at_its_first_line_only() -> None:
    key = _loc_key(
        Case("top", True, (), (Location("a.c", 3, 3),)),
        Case("far", False, (), (Location("a.c", 400, 400),)),
    )
    wide = Finding("r", (), "a.c", 1, 5000)
    res = match_findings(key, [wide], MatchParams("any", 2))
    assert [(o.case_id, o.hit) for o in res.outcomes] == [("top", True), ("far", False)]


def test_finding_goes_to_the_nearest_case() -> None:
    key = _loc_key(
        Case("t-row", True, (), (Location("d/x.py", 10, 10),)),
        Case("f-row", False, (), (Location("d/x.py", 11, 11),)),
    )
    res = match_findings(key, [Finding("r", (), "d/x.py", 10, 10)], MatchParams("any", 2))
    assert [(o.case_id, o.hit) for o in res.outcomes] == [("t-row", True), ("f-row", False)]
    shared = _loc_key(
        Case("a", True, (), (Location("x.ts", 5, 5),)),
        Case("b", True, (), (Location("x.ts", 5, 5),)),
    )
    both = match_findings(shared, [Finding("r", (), "x.ts", 5, 5)], MatchParams("any"))
    assert all(o.hit for o in both.outcomes)  # cases on the same line all count


def test_bare_file_names_and_unresolved_paths() -> None:
    from itsuite.matching import unresolved_path

    assert not same_file("src/main/A.java", "A.java")
    assert same_file("src/main/A.java", "main/A.java")
    assert same_file("src/main/A.java", "/tmp/x/src/main/A.java")
    assert unresolved_path("/somewhere/else/A.java", ["/view"])
    assert not unresolved_path("/view/A.java", ["/view"])
    assert not unresolved_path("src/A.java", ["/view"])
