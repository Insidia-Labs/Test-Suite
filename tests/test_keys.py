"""Answer-key loaders, fed fixtures in each benchmark's own format."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest

from conftest import write
from itsuite.keys import (
    REGISTRY,
    castle,
    creddata,
    documented,
    dvwa,
    flags,
    juice_shop,
    owasp_benchmark,
    plugin,
    real_cves,
)
from itsuite.keys.base import (
    AnswerKey,
    Case,
    KeyBuildError,
    KeyContext,
    KeyStore,
    Location,
    SealError,
    digest,
    key_from_dict,
    key_to_dict,
)
from itsuite.models import Variant

Ctx = Callable[..., KeyContext]


def test_owasp_benchmark_reads_expected_results(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "expectedresults-1.2.csv",
        "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
        "BenchmarkTest00001,pathtraver,true,22\nBenchmarkTest00002,sqli,false,89\n",
    )
    key = owasp_benchmark.build(ctx_for(expected_results="expectedresults-1.2.csv"))
    assert [(c.case_id, c.positive, c.cwes, c.category) for c in key.cases] == [
        ("BenchmarkTest00001", True, (22,), "pathtraver"),
        ("BenchmarkTest00002", False, (89,), "sqli"),
    ]
    assert key.match == "token" and key.cases[0].locations[0].token == "BenchmarkTest00001"


def test_owasp_benchmark_errors(tmp_path: Path, ctx_for: Ctx) -> None:
    with pytest.raises(KeyBuildError, match="required"):
        owasp_benchmark.build(ctx_for())
    with pytest.raises(KeyBuildError, match="not found"):
        owasp_benchmark.build(ctx_for(expected_results="nope.csv"))
    write(tmp_path, "bad.csv", "BenchmarkTest1,x\n")
    with pytest.raises(KeyBuildError, match="4 columns"):
        owasp_benchmark.build(ctx_for(expected_results="bad.csv"))


def test_juice_shop_markers_one_case_per_challenge(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "routes/login.ts",
        "\n".join(
            [
                "// vuln-code-snippet start loginAdminChallenge loginJimChallenge",
                "const q = 1",
                "models.sequelize.query(`SELECT ...`) // vuln-code-snippet vuln-line loginAdminChallenge loginJimChallenge",
                "  .then(() => {}) // vuln-code-snippet neutral-line loginAdminChallenge",
            ]
        ),
    )
    write(tmp_path, "test/api/x.ts", "// vuln-code-snippet vuln-line ignoredChallenge\n")
    key = juice_shop.build_markers(ctx_for(roots=["routes", "test"]))
    assert [c.case_id for c in key.cases] == ["loginAdminChallenge", "loginJimChallenge"]
    assert key.cases[0].locations == (Location("routes/login.ts", 3, 3),)


def test_juice_shop_markers_missing(ctx_for: Ctx) -> None:
    with pytest.raises(KeyBuildError, match="no vuln-line markers"):
        juice_shop.build_markers(ctx_for())


def test_juice_shop_challenges_skip_docker_disabled(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "data/static/challenges.yml",
        "\n".join(
            [
                "- {name: A, category: XSS, difficulty: 1, key: aChallenge}",
                "- {name: B, category: XXE, difficulty: 3, key: bChallenge, disabledEnv: [Docker, Heroku]}",
                "- {name: C, category: XXE, difficulty: 3, key: cChallenge, disabledEnv: Docker}",
            ]
        ),
    )
    key = juice_shop.build_challenges(ctx_for())
    assert [c.case_id for c in key.cases] == ["aChallenge"]
    assert key.match == "challenge"


def test_juice_shop_parse_solved_and_url_guard() -> None:
    payload = {
        "status": "success",
        "data": [{"key": "a", "solved": True}, {"key": "b", "solved": False}],
    }
    assert juice_shop.parse_solved(payload) == frozenset({"a"})
    with pytest.raises(ValueError):
        juice_shop.parse_solved({"data": None})
    with pytest.raises(ValueError, match="local gateway"):
        juice_shop.fetch_solved("http://example.com")


def test_dvwa_levels_and_unknown_modules(tmp_path: Path, ctx_for: Ctx) -> None:
    for module in ("sqli", "xss_r"):
        (tmp_path / "vulnerabilities" / module / "source").mkdir(parents=True)
    (tmp_path / "vulnerabilities" / "help.css").write_text("x")
    low = dvwa.build(ctx_for("low"))
    assert {(c.case_id, c.positive) for c in low.cases} == {("sqli", True), ("xss_r", True)}
    assert all(not c.positive for c in dvwa.build(ctx_for("impossible")).cases)
    with pytest.raises(KeyBuildError, match="variant"):
        dvwa.build(ctx_for("extreme"))
    (tmp_path / "vulnerabilities" / "newthing" / "source").mkdir(parents=True)
    with pytest.raises(KeyBuildError, match="without a frozen label"):
        dvwa.build(ctx_for("low"))


def test_documented_list_clean_variant_keeps_only_toggled(tmp_path: Path, ctx_for: Ctx) -> None:
    items = write(
        tmp_path,
        "answer_key.yaml",
        "\n".join(
            [
                "source: https://example.org/README",
                "items:",
                "  - {id: sqli, title: SQLi, cwes: [89], tokens: ['/u/{name}'], toggled: true, evidence: e}",
                "  - {id: debug, title: Debug, cwes: [200], tokens: ['/debug'], evidence: e}",
            ]
        ),
    )
    vulnerable = documented.build(ctx_for("vulnerable", True, items=str(items)))
    clean = documented.build(ctx_for("clean", False, items=str(items)))
    assert [(c.case_id, c.positive) for c in vulnerable.cases] == [("sqli", True), ("debug", True)]
    assert [(c.case_id, c.positive) for c in clean.cases] == [("sqli", False)]


def test_documented_list_requires_evidence_and_source(tmp_path: Path, ctx_for: Ctx) -> None:
    items = write(
        tmp_path, "k.yaml", "source: x\nitems:\n  - {id: a, title: A, cwes: [1], tokens: ['*']}\n"
    )
    with pytest.raises(KeyBuildError, match="evidence"):
        documented.build(ctx_for(items=str(items)))
    write(tmp_path, "k.yaml", "items: []\n")
    with pytest.raises(KeyBuildError, match="source"):
        documented.build(ctx_for(items=str(items)))
    with pytest.raises(KeyBuildError, match="not found"):
        documented.build(ctx_for(items=str(tmp_path / "missing.yaml")))


def test_vampi_answer_key_in_suite_builds() -> None:
    from conftest import SUITE_ROOT

    items = SUITE_ROOT / "targets" / "vampi" / "answer_key.yaml"
    ctx = KeyContext("vampi", SUITE_ROOT, Variant("clean", False), "c" * 40, {"items": str(items)})
    assert len(documented.build(ctx).cases) == 6


CASTLE_VULN = """/*
=====
vulnerable: true
cwe: 125
=====
*/
int main() {
    x[5] = 1; // {!LINE}
}
"""


def test_castle_header_and_line_marker(tmp_path: Path, ctx_for: Ctx) -> None:
    write(tmp_path, "dataset/125/CASTLE-125-1.c", CASTLE_VULN)
    write(tmp_path, "dataset/125/CASTLE-125-2.c", CASTLE_VULN.replace("true", "false"))
    key = castle.build(ctx_for())
    first, second = key.cases
    assert (first.case_id, first.positive, first.cwes) == ("CASTLE-125-1", True, (125,))
    assert first.locations == (Location("dataset/125/CASTLE-125-1.c", 8, 8),)
    assert not second.positive and second.locations == (Location("dataset/125/CASTLE-125-2.c"),)


def test_castle_bad_header(tmp_path: Path, ctx_for: Ctx) -> None:
    write(tmp_path, "dataset/x.c", "int main(){}\n")
    with pytest.raises(KeyBuildError, match="header"):
        castle.build(ctx_for())


def test_cwe_bench_java_tasks_and_variants(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "data/project_info.csv",
        "id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,"
        "github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids\n"
        f"1,p__x_CVE-1,CVE-1,CWE-022,Path,p,x,1.0,https://github.com/p/x,G,{'a' * 40},"
        f"{'b' * 40};{'c' * 40}\n",
    )
    write(
        tmp_path,
        "data/fix_info.csv",
        "project_slug,cve_id,github_username,github_repository_name,commit,file,class,"
        "class_start,class_end,method,method_start,method_end,signature\n"
        "p__x_CVE-1,CVE-1,p,x,c,src/A.java,A,1,90,run,10,20,run()\n"
        "p__x_CVE-1,CVE-1,p,x,c,src/B.java,B,5,50,,,,\n",
    )
    tasks = real_cves.cwe_bench_tasks(tmp_path, {})
    assert tasks[0].source and tasks[0].source.commit == "a" * 40
    assert tasks[0].patched_source and tasks[0].patched_source.commit == "c" * 40
    assert tasks[0].source.url == "https://github.com/p/x.git"
    vuln = real_cves.build_cwe_bench(ctx_for("vulnerable", task="p__x_CVE-1"))
    case = vuln.cases[0]
    assert case.positive and case.cwes == (22,)
    assert case.locations == (Location("src/A.java", 10, 20), Location("src/B.java", 5, 50))
    patched = real_cves.build_cwe_bench(ctx_for("patched", task="p__x_CVE-1"))
    assert not patched.cases[0].positive
    # the patched control covers the fixed methods, not the whole file
    assert patched.cases[0].locations == (
        Location("src/A.java", 10, 20),
        Location("src/B.java", 5, 50),
    )
    with pytest.raises(KeyBuildError, match="unknown project"):
        real_cves.build_cwe_bench(ctx_for(task="nope"))


def test_ossf_cve_records(tmp_path: Path, ctx_for: Ctx) -> None:
    record = {
        "CVE": "CVE-2016-1",
        "state": "PUBLISHED",
        "repository": "https://github.com/a/b.git",
        "prePatch": {
            "commit": "a" * 40,
            "weaknesses": [{"location": {"file": "x.js", "line": 68}}],
        },
        "postPatch": {"commit": "b" * 40},
        "CWEs": ["CWE-079"],
    }
    write(tmp_path, "CVEs/CVE-2016-1.json", json.dumps(record))
    write(
        tmp_path,
        "CVEs/CVE-2016-2.json",
        json.dumps({**record, "CVE": "CVE-2016-2", "state": "RESERVED"}),
    )
    assert [t.task_id for t in real_cves.ossf_tasks(tmp_path, {})] == ["CVE-2016-1"]
    vuln = real_cves.build_ossf(ctx_for("vulnerable", task="CVE-2016-1"))
    assert vuln.cases[0].locations == (Location("x.js", 68, 68),) and vuln.cases[0].cwes == (79,)
    patched = real_cves.build_ossf(ctx_for("patched", task="CVE-2016-1"))
    assert (
        patched.cases[0].locations == (Location("x.js", 58, 78),) and not patched.cases[0].positive
    )


def test_creddata_labels(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "meta/00408ef6.csv",
        "Id,FileID,Domain,RepoName,FilePath,LineStart,LineEnd,GroundTruth,ValueStart,"
        "ValueEnd,CryptographyKey,PredefinedPattern,Category\n"
        "30,1d,GitHub,00408ef6,data/00408ef6/a.c,475,475,F,,,,,Password\n"
        "31,1e,GitHub,00408ef6,data/00408ef6/b.c,10,12,T,,,,,Key\n"
        "32,1f,GitHub,00408ef6,data/00408ef6/c.c,1,1,X,,,,,Other\n",
    )
    key = creddata.build(ctx_for())
    assert [(c.case_id, c.positive) for c in key.cases] == [("30", False), ("31", True)]
    assert key.cases[1].locations == (Location("data/00408ef6/b.c", 10, 12),)


def test_xbow_tasks_flag_and_search(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "benchmarks/XBEN-001-24/benchmark.json",
        json.dumps({"description": "Fuzz IDs", "level": "2", "tags": ["idor"]}),
    )
    tasks = flags.xbow_tasks(tmp_path, {})
    assert tasks[0].task_id == "XBEN-001-24" and tasks[0].prompt == "Fuzz IDs"
    flag = flags.new_flag()
    assert flag.startswith("FLAG{") and len(flag) == 70 and flag != flags.new_flag()
    key = flags.build_xbow(ctx_for(task="XBEN-001-24", flag=flag))
    assert key.cases[0].secret == flag
    with pytest.raises(KeyBuildError, match="generated flag"):
        flags.build_xbow(ctx_for(task="XBEN-001-24"))
    out = write(tmp_path, "out/notes.txt", f"got it: {flag}\n")
    assert flags.flag_found(flag, [out.parent])
    assert not flags.flag_found(flags.new_flag(), [out.parent, tmp_path / "missing"])


def _key() -> AnswerKey:
    case = Case("c1", True, (89,), (Location("a.py", 1, 2), Location(token="/x")), "sqli", "s")
    return AnswerKey("t", "v", "k", "location", "c" * 40, (case,), "task", "p")


def test_key_round_trip_and_digest_is_stable() -> None:
    key = _key()
    assert key_from_dict(key_to_dict(key)) == key
    assert digest(key) == digest(key_from_dict(json.loads(json.dumps(key_to_dict(key)))))
    assert key.name == "t:k@v#task" and key.legacy_name == "t@v#task"


def test_keystore_seals_by_digest_and_detects_tampering(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "keys")
    key = _key()
    value = store.seal(key)
    assert store.load(value, key.name) == key
    with pytest.raises(SealError, match="not"):
        store.load(value, "other@v")
    path = tmp_path / "keys" / f"{value}.json"
    data = json.loads(path.read_text())
    data["cases"][0]["positive"] = False
    path.write_text(json.dumps(data))
    with pytest.raises(SealError, match="changed after"):
        store.load(value)
    with pytest.raises(SealError, match="never sealed"):
        store.load("0" * 64)
    with pytest.raises(SealError, match="not a key digest"):
        store.load("../../etc/passwd")


def test_keystore_refuses_a_changed_key_under_the_same_name(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "keys")
    store.seal(_key())
    assert store.seal(_key()) == digest(_key())  # same content again is fine
    changed = AnswerKey("t", "v", "k", "location", "c" * 40, (), "task", "p")
    with pytest.raises(SealError, match="changed since it was first sealed"):
        store.seal(changed)


def test_flag_keys_are_per_run_and_never_overwrite_each_other(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "keys")
    first = AnswerKey(
        "x",
        "default",
        "xbow-flag",
        "flag",
        "c" * 40,
        (Case("T", True, secret=flags.new_flag()),),
        task="T",
    )
    second = AnswerKey(
        "x",
        "default",
        "xbow-flag",
        "flag",
        "c" * 40,
        (Case("T", True, secret=flags.new_flag()),),
        task="T",
    )
    a, b = store.seal(first), store.seal(second)
    assert a != b and store.load(a) == first and store.load(b) == second
    assert not store.lock_path.exists()


def test_registry_lookup() -> None:
    assert plugin("castle") is REGISTRY["castle"]
    with pytest.raises(LookupError):
        plugin("juliet")


def test_cwe_bench_relocates_methods_and_drops_tests(tmp_path: Path, ctx_for: Ctx) -> None:
    write(
        tmp_path,
        "data/project_info.csv",
        "id,project_slug,cve_id,cwe_id,cwe_name,github_username,github_repository_name,"
        "github_tag,github_url,advisory_id,buggy_commit_id,fix_commit_ids\n"
        f"1,p,CVE-9,CWE-022,Path,p,x,1.0,https://github.com/p/x,G,{'a' * 40},{'b' * 40}\n",
    )
    write(
        tmp_path,
        "data/fix_info.csv",
        "project_slug,cve_id,github_username,github_repository_name,commit,file,class,"
        "class_start,class_end,method,method_start,method_end,signature\n"
        "p,CVE-9,p,x,c,src/main/java/A.java,A,1,90,unzip,12,15,unzip()\n"
        "p,CVE-9,p,x,c,src/test/java/ATest.java,ATest,1,40,testUnzip,5,9,testUnzip()\n",
    )
    checkout = tmp_path / "checkout"
    body = (
        ["class A {"]
        + ["  // padding"] * 19
        + ["  void unzip(String f) {", "    open(f);", "  }", "}"]
    )
    write(checkout, "src/main/java/A.java", "\n".join(body))
    ctx = KeyContext("t", tmp_path, Variant("vulnerable"), "c" * 40, {}, "p", task_src=checkout)
    case = real_cves.build_cwe_bench(ctx).cases[0]
    assert case.locations == (Location("src/main/java/A.java", 21, 24),)  # found by name, span kept
    no_checkout = real_cves.build_cwe_bench(ctx_for("vulnerable", task="p")).cases[0]
    assert no_checkout.locations == (Location("src/main/java/A.java", 12, 15),)
    assert real_cves.is_test_file("module/src/test/java/X.java") and real_cves.is_test_file(
        "FooIT.java"
    )
    assert not real_cves.is_test_file("src/main/java/Testing.java")


def test_two_evaluations_of_one_target_seal_separately(tmp_path: Path) -> None:
    store = KeyStore(tmp_path / "keys")
    live = AnswerKey("js", "default", "juice-shop-challenges", "challenge", "c" * 40,
                     (Case("a", True),))  # fmt: skip
    source = AnswerKey("js", "default", "juice-shop-markers", "location", "c" * 40,
                       (Case("b", True),))  # fmt: skip
    a, b = store.seal(live), store.seal(source)
    assert store.load(a, live.name) == live and store.load(b, source.legacy_name) == source
