"""The real catalog in this repo, manifest parsing errors, validation and the CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import SUITE_ROOT, write
from itsuite import cli
from itsuite.catalog import load_catalog, parse_source, parse_target, parse_tool, parse_view
from itsuite.models import CatalogError, Integration, Mode
from itsuite.validate import validate

COMMIT = "a" * 40


def _target(**overrides: Any) -> dict[str, Any]:
    data = {
        "id": "demo",
        "name": "Demo",
        "level": "L1",
        "license": "MIT",
        "contamination": "low",
        "answer_key": "x",
        "source": {"kind": "git", "url": "https://x/y.git", "commit": COMMIT},
        "evaluations": [{"mode": "sast", "key": "castle", "integration": "native"}],
    }
    return {**data, **overrides}


def test_repo_catalog_loads_and_validates() -> None:
    catalog = load_catalog(SUITE_ROOT)
    assert validate(catalog, SUITE_ROOT) == []
    assert len(catalog.targets) >= 40 and {"argus", "lynx", "taylon"} <= set(catalog.tools)
    natives = {
        t.id
        for t in catalog.targets.values()
        for e in t.evaluations
        if e.integration == Integration.NATIVE
    }
    assert {"dvwa", "juice-shop", "vampi", "owasp-benchmark-java", "castle", "xbow"} <= natives


def test_every_pin_is_a_full_commit_or_digest() -> None:
    for target in load_catalog(SUITE_ROOT).targets.values():
        assert len(target.source.commit) == 40 or len(target.source.sha256) == 64, target.id


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ({"kind": "git", "url": "u", "commit": "main"}, "40-character"),
        ({"kind": "archive", "url": "u", "sha256": "abc"}, "64 hex"),
        ({"kind": "svn", "url": "u"}, "git or archive"),
        ({"kind": "git", "url": "u"}, "missing 'commit'"),
    ],
)
def test_source_errors(source: dict[str, Any], message: str) -> None:
    with pytest.raises(CatalogError, match=message):
        parse_source(source, "t")


def test_target_errors() -> None:
    with pytest.raises(CatalogError, match="kebab"):
        parse_target(_target(id="Bad_ID"), "t")
    with pytest.raises(CatalogError, match="bad value"):
        parse_target(_target(level="L9"), "t")
    bad_cwe = [{"mode": "sast", "key": "castle", "integration": "native", "cwe_mode": "loose"}]
    with pytest.raises(CatalogError, match="cwe_mode"):
        parse_target(_target(evaluations=bad_cwe), "t")
    bad_variant = [
        {
            "mode": "dast",
            "key": "k",
            "integration": "planned",
            "variants": [{"name": "x", "positive": "yes"}],
        }
    ]
    with pytest.raises(CatalogError, match="positive"):
        parse_target(_target(evaluations=bad_variant), "t")
    with pytest.raises(CatalogError, match="bad regex"):
        parse_view({"strip": ["("]}, "t")
    with pytest.raises(CatalogError, match="rename"):
        parse_view({"rename": "shuffle"}, "t")


def test_target_defaults_and_lookups() -> None:
    target = parse_target(_target(runtime={"compose": "c.yml", "expose": "auto"}), "t")
    evaluation = target.evaluation(Mode.SAST)
    assert (
        evaluation.variants[0].name == "default" and target.runtime and target.runtime.auto_expose
    )
    with pytest.raises(CatalogError):
        target.evaluation(Mode.DAST)
    with pytest.raises(CatalogError):
        evaluation.variant("nope")


def test_tool_errors() -> None:
    base = {
        "id": "t",
        "name": "T",
        "role": "baseline",
        "version": "1",
        "source": "s",
        "license": "MIT",
        "modes": {"sast": {"command": "x", "output": "sarif"}},
    }
    assert parse_tool(base, "t").modes[Mode.SAST].output_file == "results.sarif"
    with pytest.raises(CatalogError, match="role"):
        parse_tool({**base, "role": "judge"}, "t")
    with pytest.raises(CatalogError, match="status"):
        parse_tool({**base, "status": "beta"}, "t")
    with pytest.raises(CatalogError, match="bad value"):
        parse_tool({**base, "modes": {"sast": {"command": "x", "output": "xml"}}}, "t")


def _mini_suite(root: Path, evaluation: dict[str, Any], profile_variant: str = "default") -> None:
    import yaml

    write(root, "catalog/targets/demo.yaml", yaml.safe_dump(_target(evaluations=[evaluation])))
    write(
        root,
        "catalog/tools/fake.yaml",
        yaml.safe_dump(
            {
                "id": "fake",
                "name": "F",
                "role": "baseline",
                "version": "1",
                "source": "s",
                "license": "MIT",
                "modes": {},
            }
        ),
    )
    write(
        root,
        "profiles/p.yaml",
        yaml.safe_dump(
            {
                "id": "p",
                "description": "d",
                "wall_seconds": 10,
                "entries": [{"target": "demo", "mode": "sast", "variants": [profile_variant]}],
            }
        ),
    )


def test_validate_catches_overclaims(tmp_path: Path) -> None:
    _mini_suite(tmp_path, {"mode": "sast", "key": "juliet", "integration": "native"}, "nope")
    problems = validate(load_catalog(tmp_path), tmp_path)
    assert any("no answer-key plugin" in p for p in problems)
    assert any("has no variants" in p for p in problems)
    assert any("declares no modes" in p for p in problems)


def test_validate_live_needs_runtime(tmp_path: Path) -> None:
    _mini_suite(tmp_path, {"mode": "dast", "key": "dvwa-modules", "integration": "native"})
    problems = validate(load_catalog(tmp_path), tmp_path)
    assert any("runtime block" in p for p in problems)
    assert any("has no sast" in p for p in problems)


def test_validate_build_pin_files_must_exist(tmp_path: Path) -> None:
    import yaml

    evaluation = {"mode": "dast", "key": "dvwa-modules", "integration": "native"}
    _mini_suite(tmp_path, evaluation)
    runtime = {"compose": "compose.yml", "base_images": "suite:targets/demo/bases.yaml",
               "pip_constraints": "suite:targets/demo/pins.txt"}  # fmt: skip
    demo = _target(evaluations=[evaluation], runtime=runtime)
    write(tmp_path, "catalog/targets/demo.yaml", yaml.safe_dump(demo))
    problems = validate(load_catalog(tmp_path), tmp_path)
    assert any("bases.yaml does not exist" in p for p in problems)
    assert any("pins.txt does not exist" in p for p in problems)


def test_file_name_must_match_id(tmp_path: Path) -> None:
    import yaml

    write(tmp_path, "catalog/targets/other.yaml", yaml.safe_dump(_target()))
    (tmp_path / "catalog/tools").mkdir(parents=True)
    (tmp_path / "profiles").mkdir()
    with pytest.raises(CatalogError, match="must match"):
        load_catalog(tmp_path)


def test_cli_list_validate_report(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("ITS_ROOT", str(SUITE_ROOT))
    assert cli.main(["validate"]) == 0
    assert "targets" in capsys.readouterr().out
    assert cli.main(["list", "--level", "L0", "--mode", "dast"]) == 0
    out = capsys.readouterr().out
    assert "dvwa" in out and "castle" not in out
    assert cli.main(["report", "--results", str(tmp_path)]) == 0
    assert "No scored runs" in capsys.readouterr().out
    assert cli.main(["run", "--tool", "lynx", "--target", "dvwa", "--mode", "dast"]) == 2
    assert "not-yet-available" in capsys.readouterr().err


def test_cli_import_upstream(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import shutil

    root = tmp_path / "suite"
    shutil.copytree(SUITE_ROOT / "catalog", root / "catalog")
    shutil.copytree(SUITE_ROOT / "profiles", root / "profiles")
    monkeypatch.setenv("ITS_ROOT", str(root))
    path = write(tmp_path, "r.jsonl", json.dumps({"task_id": "a", "success": True}) + "\n")
    assert (
        cli.main(
            [
                "import-upstream",
                str(path),
                "--format",
                "jsonl",
                "--tool",
                "argus",
                "--target",
                "cybench",
            ]
        )
        == 0
    )
    saved = json.loads((root / "results" / "upstream-argus-cybench.json").read_text())
    assert saved["variants"]["default"]["successes"] == 1
    capsys.readouterr()


def test_find_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ITS_ROOT", raising=False)
    assert cli.find_root(SUITE_ROOT / "src" / "itsuite") == SUITE_ROOT
    with pytest.raises(CatalogError):
        cli.find_root(tmp_path)


def test_profile_plan_is_deterministic() -> None:
    catalog = load_catalog(SUITE_ROOT)
    profile = catalog.profiles["smoke"]
    tasks = {"xbow": [f"XBEN-{i:03d}-24" for i in range(1, 105)]}
    first = cli.plan_profile(profile, catalog, tasks)
    assert first == cli.plan_profile(profile, catalog, tasks)
    assert ("dvwa", "dast", "impossible", "") in first
    assert len([p for p in first if p[0] == "xbow"]) == 3
