"""Starting live targets: isolation is applied, egress is probed, failures clean up."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from conftest import write
from itsuite import docker_ops, live
from itsuite.docker_ops import DockerError
from itsuite.isolation import IsolationError
from itsuite.models import Expose, Runtime, Variant


class Docker:
    """Fake docker CLI: compose up/down succeed; the egress probe answers as told."""

    def __init__(self, egress: bool = False, up_code: int = 0) -> None:
        self.egress = egress
        self.up_code = up_code
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        self.calls.append(args)
        if args[:2] == ["docker", "run"]:
            return subprocess.CompletedProcess(args, 0 if self.egress else 7, "", "")
        code = self.up_code if "up" in args else 0
        return subprocess.CompletedProcess(args, code, "", "up failed\n")


@pytest.fixture
def project(tmp_path: Path) -> Path:
    write(
        tmp_path,
        "src/compose.yml",
        yaml.safe_dump({"services": {"app": {"build": ".", "ports": ["8080:80"]}}}),
    )
    (tmp_path / "run").mkdir()
    return tmp_path


def _start(project: Path, docker: Docker, runtime: Runtime | None = None) -> live.LiveTarget:
    return live.start(
        runtime or Runtime("compose.yml", auto_expose=True),
        Variant("v", True, {"X": "1"}),
        project / "src",
        project,
        project / "run",
        "its-test",
        {"FLAG": "f"},
        docker,
    )


def test_start_writes_isolated_compose_and_checks_egress(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: True)
    docker = Docker()
    target = _start(project, docker)
    spec = yaml.safe_load((project / "run" / "compose.isolated.yml").read_text())
    assert "ports" not in spec["services"]["app"]
    assert spec["services"]["app"]["environment"] == {"X": "1"}
    assert target.exposes == (Expose("app", 80),) and target.networks == ("its-test_default",)
    assert target.base_url.startswith("http://127.0.0.1:") and target.base_url.endswith("/")
    assert any(c[:2] == ["docker", "run"] and "its-test_default" in c for c in docker.calls)
    live.stop(target, docker)
    assert "down" in docker.calls[-1]


def test_start_stops_and_refuses_when_egress_is_open(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: True)
    docker = Docker(egress=True)
    with pytest.raises(IsolationError, match="can reach the internet"):
        _start(project, docker)
    assert "down" in docker.calls[-1]


def test_start_cleans_up_when_compose_or_readiness_fails(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    docker = Docker(up_code=1)
    with pytest.raises(DockerError, match="up failed"):
        _start(project, docker)
    assert "down" in docker.calls[-1]
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: False)
    with pytest.raises(DockerError, match="never answered"):
        _start(project, Docker())


def test_start_needs_an_exposed_port(project: Path) -> None:
    write(project, "src/compose.yml", yaml.safe_dump({"services": {"app": {"build": "."}}}))
    with pytest.raises(IsolationError, match="exposes no port"):
        _start(project, Docker())


def test_compose_file_from_suite_or_source(tmp_path: Path) -> None:
    assert live.compose_file(Runtime("suite:targets/x/c.yml"), tmp_path / "s", tmp_path) == (
        tmp_path / "targets/x/c.yml"
    )
    assert live.compose_file(Runtime("c.yml"), tmp_path / "s", tmp_path) == tmp_path / "s/c.yml"


def test_run_setup(tmp_path: Path) -> None:
    good = write(tmp_path, "ok.sh", 'echo "{}" > "$3/auth.json"; echo "ready $2"\n')
    assert live.run_setup(good, "http://127.0.0.1:1/", "low", tmp_path / "in")
    assert (tmp_path / "in" / "auth.json").exists()
    assert "ready low" in (tmp_path / "in" / "setup.log").read_text()
    bad = write(tmp_path, "bad.sh", "exit 1\n")
    assert not live.run_setup(bad, "http://127.0.0.1:1/", "low", tmp_path / "in2")
