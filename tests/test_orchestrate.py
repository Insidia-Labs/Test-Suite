"""Whole runs with a fake tool. Fetching and Docker are replaced, everything else is real."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from conftest import write
from itsuite import live, orchestrate
from itsuite.docker_ops import ComposeProject, DockerError
from itsuite.models import (
    Contamination,
    Evaluation,
    Expose,
    Integration,
    Level,
    Mode,
    OutputFormat,
    Runtime,
    Source,
    TargetSpec,
    ToolMode,
    ToolSpec,
    Variant,
    ViewSpec,
)

CASTLE_FILE = "/*\nvulnerable: {v}\ncwe: 125\n*/\nint main() {{\n  x[5] = 1; // {{!LINE}}\n}}\n"

# The fake SAST tool flags every line that writes past an array, with CWE-125.
SAST_TOOL = """
import json, pathlib, sys
src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
results = []
for f in sorted(src.rglob("*.c")):
    text = f.read_text()
    assert "vulnerable" not in text and "{!LINE}" not in text, "answer leaked into the view"
    for n, line in enumerate(text.splitlines(), 1):
        if "x[5]" in line:
            results.append({"ruleId": "oob", "properties": {"tags": ["CWE-125"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(f)},
                "region": {"startLine": n}}}]})
(out / "results.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
    {"tool": {"driver": {"name": "fake"}}, "results": results}]}))
"""

DAST_TOOL = """
import json, pathlib, sys
url, out = sys.argv[1], pathlib.Path(sys.argv[2])
hits = [url + "users/v1/admin", url + "users/v1/_debug"]
results = [{"ruleId": "r", "properties": {"tags": [cwe]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": u}}}]}
           for u, cwe in zip(hits, ["CWE-89", "CWE-200"])]
(out / "results.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
    {"tool": {"driver": {"name": "fake"}}, "results": results}]}))
"""


def _tool(root: Path, mode: Mode, script: str, args: str) -> ToolSpec:
    write(root, f"adapters/fake/{mode.value}.py", script)
    command = f"{sys.executable} {{adapter_dir}}/{mode.value}.py {args} {{out_dir}}"
    return ToolSpec(
        "fake", "Fake", "baseline", "1", "s", "MIT", {mode: ToolMode(command, OutputFormat.SARIF)}
    )


def _castle_target() -> TargetSpec:
    view = ViewSpec(
        include=("dataset",),
        rename="opaque",
        strip=(r"^\s*(vulnerable|cwe)\s*:.*$", r"\s*//\s*\{!LINE\}"),
    )
    ev = Evaluation(Mode.SAST, "castle", Integration.NATIVE, (Variant("default"),), "family")
    return TargetSpec(
        "castle",
        "CASTLE",
        Level.L2,
        ("source",),
        Source("git", "u", "c" * 40),
        "MIT",
        "",
        Contamination.LOW,
        "x",
        (ev,),
        view=view,
    )


@pytest.fixture
def suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> orchestrate.SuitePaths:
    src = tmp_path / "upstream"
    write(src, "dataset/125/CASTLE-125-1.c", CASTLE_FILE.format(v="true"))
    write(src, "dataset/125/CASTLE-125-2.c", CASTLE_FILE.format(v="false"))
    write(src, "README.md", "the answers are in the headers")
    monkeypatch.setattr(orchestrate, "fetch", lambda source, dest: src)
    monkeypatch.setenv("ITS_VIEWS_DIR", str(tmp_path / "views"))
    return orchestrate.SuitePaths(tmp_path / "suite")


def test_whitebox_run_end_to_end(suite: orchestrate.SuitePaths) -> None:
    tool = _tool(suite.root, Mode.SAST, SAST_TOOL, "{source_dir}")
    score = orchestrate.run(orchestrate.RunRequest(tool, _castle_target(), Mode.SAST), suite)
    assert score["scored"], score
    assert score["overall"]["tp"] == 1 and score["overall"]["fp"] == 1
    assert score["sealed"] is False and score["contamination"] == "low"
    run_dir = next(suite.results.iterdir())
    record = json.loads((run_dir / "run.json").read_text())
    assert record["status"] == "ok" and record["source_commit"] == "c" * 40
    assert not (suite.views / run_dir.name).exists()  # view removed after the run


def test_crashing_tool_is_recorded_not_scored(suite: orchestrate.SuitePaths) -> None:
    tool = _tool(suite.root, Mode.SAST, "raise SystemExit(4)", "{source_dir}")
    score = orchestrate.run(orchestrate.RunRequest(tool, _castle_target(), Mode.SAST), suite)
    assert not score["scored"] and score["status"] == "error"


def test_prepare_refuses_bridge_and_missing_modes(suite: orchestrate.SuitePaths) -> None:
    target = _castle_target()
    bridged = TargetSpec(
        **{
            **target.__dict__,
            "evaluations": (
                Evaluation(Mode.SAST, "upstream-jsonl", Integration.BRIDGE, (Variant("default"),)),
            ),
        }
    )
    tool = _tool(suite.root, Mode.SAST, "", "{source_dir}")
    with pytest.raises(orchestrate.RunError, match="import-upstream"):
        orchestrate.prepare(orchestrate.RunRequest(tool, bridged, Mode.SAST), suite, "")
    no_mode = ToolSpec("fake", "F", "baseline", "1", "s", "MIT", {})
    with pytest.raises(orchestrate.RunError, match="no sast adapter"):
        orchestrate.prepare(orchestrate.RunRequest(no_mode, target, Mode.SAST), suite, "")


def test_prepare_requires_declared_paths(suite: orchestrate.SuitePaths) -> None:
    target = _castle_target()
    ev = Evaluation(
        Mode.SAST,
        "castle",
        Integration.NATIVE,
        (Variant("default"),),
        params={"requires_paths": ["data"]},
    )
    needs_data = TargetSpec(**{**target.__dict__, "evaluations": (ev,)})
    tool = _tool(suite.root, Mode.SAST, "", "{source_dir}")
    with pytest.raises(orchestrate.RunError, match="missing"):
        orchestrate.prepare(orchestrate.RunRequest(tool, needs_data, Mode.SAST), suite, "")


def _vampi_target(root: Path) -> TargetSpec:
    items = write(
        root,
        "targets/vampi/answer_key.yaml",
        "\n".join(
            [
                "source: README",
                "items:",
                "  - {id: sqli, title: SQLi, cwes: [89], tokens: ['/users/v1/{username}'], toggled: true, evidence: e}",
                "  - {id: debug, title: Debug, cwes: [200], tokens: ['/users/v1/_debug'], evidence: e}",
            ]
        ),
    )
    ev = Evaluation(
        Mode.DAST,
        "documented-list",
        Integration.NATIVE,
        (Variant("vulnerable", True, {"vulnerable": "1"}),),
        "family",
        params={"items": f"suite:{items.relative_to(root)}"},
    )
    runtime = Runtime(
        "suite:targets/vampi/compose.yml", (Expose("vampi", 5000),), setup="targets/vampi/setup.sh"
    )
    return TargetSpec(
        "vampi",
        "VAmPI",
        Level.L0,
        ("api",),
        Source("git", "u", "c" * 40),
        "MIT",
        "",
        Contamination.MEDIUM,
        "x",
        (ev,),
        runtime=runtime,
    )


def _fake_live(calls: list[str]) -> Any:
    def start(runtime: Runtime, variant: Variant, *args: Any, **kwargs: Any) -> live.LiveTarget:
        calls.append(f"start:{variant.env}")
        project = ComposeProject("its-x", Path("c.yml"), Path("."))
        return live.LiveTarget(
            project,
            "http://127.0.0.1:9/",
            "http://127.0.0.1:9",
            (Expose("vampi", 5000),),
            {},
            ("its-x_default",),
            "/",
        )

    return start


def test_live_run_starts_sets_up_scores_and_stops(
    suite: orchestrate.SuitePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(live, "start", _fake_live(calls))
    monkeypatch.setattr(live, "stop", lambda target: calls.append("stop"))
    monkeypatch.setattr(live, "run_setup", lambda *a, **k: calls.append("setup") or True)
    tool = _tool(suite.root, Mode.DAST, DAST_TOOL, "{target_url}")
    request = orchestrate.RunRequest(tool, _vampi_target(suite.root), Mode.DAST, "vulnerable")
    score = orchestrate.run(request, suite)
    assert calls == ["start:{'vulnerable': '1'}", "setup", "stop"]
    assert score["scored"] and score["overall"]["tp"] == 2


def test_live_target_failure_is_recorded(
    suite: orchestrate.SuitePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: Any, **kwargs: Any) -> live.LiveTarget:
        raise DockerError("compose up failed")

    monkeypatch.setattr(live, "start", broken)
    tool = _tool(suite.root, Mode.DAST, DAST_TOOL, "{target_url}")
    request = orchestrate.RunRequest(tool, _vampi_target(suite.root), Mode.DAST, "vulnerable")
    score = orchestrate.run(request, suite)
    assert not score["scored"] and score["status"] == "target-error"


def test_container_argv_mounts_env_and_network(
    suite: orchestrate.SuitePaths, tmp_path: Path
) -> None:
    from itsuite import container

    tool = ToolSpec("fake", "F", "baseline", "1", "s", "MIT", {}, image="img@sha256:" + "0" * 64)
    request = orchestrate.RunRequest(tool, _castle_target(), Mode.SAST, container=True)
    plan = orchestrate._container_plan(
        request, tmp_path, "/v", suite, "bridge", ("ITS_OUT_DIR", "KEY")
    )
    argv = container.argv(["scan"], plan)
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert mounts == [
        f"{tmp_path}/out:/its/out",
        f"{tmp_path}/input:/its/input:ro",
        f"{suite.root}/adapters/fake:/its/adapter:ro",
        f"{suite.root}/adapters/common.sh:/its/common.sh:ro",
        "/v:/its/src:ro",
    ]
    envs = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert envs == ["ITS_OUT_DIR", "KEY"]  # by name only: values never on the command line
    assert "--network" in argv and argv[argv.index("--network") + 1] == "bridge"
    assert "no-new-privileges" in argv and argv[-2:] == ["img@sha256:" + "0" * 64, "scan"]
    no_image = orchestrate.RunRequest(
        ToolSpec("f", "F", "baseline", "1", "s", "MIT", {}),
        _castle_target(),
        Mode.SAST,
        container=True,
    )
    with pytest.raises(orchestrate.RunError, match="no tools image"):
        orchestrate._container_plan(no_image, tmp_path, "", suite, "bridge", ())
    (suite.cache / "tools").mkdir(parents=True)
    (suite.cache / "tools" / "image.txt").write_text("itsuite-tools:abc\n")
    plan = orchestrate._container_plan(no_image, tmp_path, "", suite, "bridge", ())
    assert plan.image == "itsuite-tools:abc"  # falls back to the suite tools image
    assert "--user" in container.argv(["x"], plan)
    from itsuite.models import Install

    docker_tool = ToolSpec(
        "zap",
        "Z",
        "baseline",
        "1",
        "s",
        "MIT",
        {},
        install=Install("docker", image="zap@sha256:" + "0" * 64),
    )
    zap = orchestrate.RunRequest(docker_tool, _castle_target(), Mode.SAST, container=True)
    with pytest.raises(orchestrate.RunError, match="runs Docker itself"):
        orchestrate._container_plan(zap, tmp_path, "", suite, "bridge", ())


def test_container_reaches_live_target_only_through_the_gateway() -> None:
    project = ComposeProject("its-p", Path("c.yml"), Path("."))
    target = live.LiveTarget(
        project,
        "http://127.0.0.1:9/",
        "http://127.0.0.1:9",
        (Expose("web", 80),),
        {},
        ("its-p_default",),
        "/app/",
    )
    network, url = orchestrate._container_target(target)
    assert network == "its-p_its-edge" and url == "http://its-gateway-web-80:80/app/"
    assert orchestrate._container_target(None) == ("bridge", "")


def test_variant_and_task_never_reach_the_tool(
    suite: orchestrate.SuitePaths, tmp_path: Path
) -> None:
    tool = _tool(suite.root, Mode.SAST, "", "{source_dir}")
    request = orchestrate.RunRequest(
        tool, _castle_target(), Mode.SAST, "patched", "proj_CVE-2020-1"
    )
    values = orchestrate._values(request, tmp_path, "/v", "", suite)
    assert "variant" not in values and "task_id" not in values
    assert not any("patched" in v or "CVE" in v for v in values.values())
    name = orchestrate.run_id(request)
    assert "patched" not in name and "CVE" not in name
    with pytest.raises(Exception, match="unknown placeholder"):
        orchestrate.render_command("x {variant}", values)


def test_run_id_is_safe() -> None:
    tool = ToolSpec("fake", "F", "baseline", "1", "s", "MIT", {})
    name = orchestrate.run_id(orchestrate.RunRequest(tool, _castle_target(), Mode.SAST))
    assert "/" not in name and " " not in name


def test_tool_runs_outside_the_folder_with_private_files(suite: orchestrate.SuitePaths) -> None:
    # The fake tool fails the run if it can see the path map anywhere it can easily look.
    probe = (
        """
import pathlib, sys, os
assert not pathlib.Path("path_map.json").exists() and not pathlib.Path("../path_map.json").exists()
assert pathlib.Path.cwd().name == "out", os.getcwd()
"""
        + SAST_TOOL
    )
    tool = _tool(suite.root, Mode.SAST, probe, "{source_dir}")
    score = orchestrate.run(orchestrate.RunRequest(tool, _castle_target(), Mode.SAST), suite)
    assert score["scored"], score
    run_dir = next(suite.results.iterdir())
    assert (suite.cache / "private" / run_dir.name / "path_map.json").exists()


def test_app_down_after_the_run_is_a_target_error(
    suite: orchestrate.SuitePaths, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(live, "start", _fake_live(calls))
    monkeypatch.setattr(live, "stop", lambda target: calls.append("stop"))
    monkeypatch.setattr(live, "run_setup", lambda *a, **k: True)
    answers = iter([["a"], OSError("connection refused")])

    def observe(prep: Any, target: Any) -> Any:
        value = next(answers)
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(orchestrate, "_observe", observe)
    tool = _tool(suite.root, Mode.DAST, DAST_TOOL, "{target_url}")
    request = orchestrate.RunRequest(tool, _vampi_target(suite.root), Mode.DAST, "vulnerable")
    score = orchestrate.run(request, suite)
    assert not score["scored"] and score["status"] == "target-error" and calls[-1] == "stop"


def test_views_default_outside_the_suite_repo(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ITS_VIEWS_DIR", raising=False)
    paths = orchestrate.SuitePaths(tmp_path / "suite")
    assert paths.views == Path.home() / ".cache" / "itsuite" / "views"
    assert not str(paths.views).startswith(str(paths.root))
