"""Starting live targets: isolation is applied, egress is probed, failures clean up."""

from __future__ import annotations

import re
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

    def __init__(self, egress: bool = False, up_code: int = 0, model_ok: bool = True) -> None:
        self.egress = egress
        self.up_code = up_code
        self.model_ok = model_ok
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        args = list(argv)
        self.calls.append(args)
        if args[:2] == ["docker", "run"] and args[-1].endswith("/v1/models"):
            return subprocess.CompletedProcess(args, 0 if self.model_ok else 28, "", "")
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


def test_rewritten_copy_replaces_flags_and_leaves_the_original(tmp_path: Path) -> None:
    write(tmp_path, "src/server.py", 'FLAG = "DVMCP{old}"\n')
    write(tmp_path, "src/logo.png", "")
    (tmp_path / "src" / "logo.png").write_bytes(b"\x89PNG\x00\xff")
    write(tmp_path, "src/.git/config", "DVMCP{old}")
    copy = live.rewritten_copy(tmp_path / "src", tmp_path / "copy", {"DVMCP{old}": "DVMCP{new}"})
    assert (copy / "server.py").read_text() == 'FLAG = "DVMCP{new}"\n'
    assert (tmp_path / "src/server.py").read_text() == 'FLAG = "DVMCP{old}"\n'
    assert (copy / "logo.png").read_bytes() == b"\x89PNG\x00\xff" and not (copy / ".git").exists()


def test_endpoints_list_every_exposed_port() -> None:
    from itsuite.docker_ops import ComposeProject

    exposes = (Expose("mcp", 9001), Expose("mcp", 9002))
    target = live.LiveTarget(ComposeProject("its-p", Path("c"), Path(".")), "u", "r", exposes,
                             {exposes[0]: 40001, exposes[1]: 40002}, (), "/mcp")  # fmt: skip
    assert live.endpoints(target, False) == {"mcp:9001": "http://127.0.0.1:40001/mcp",
                                             "mcp:9002": "http://127.0.0.1:40002/mcp"}  # fmt: skip
    assert live.endpoints(target, True)["mcp:9002"] == "http://its-gateway-mcp-9002:9002/mcp"


def test_overlay_adds_suite_files_to_the_build_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write(tmp_path, "suite/targets/x/its_api.py", "print('api')\n")
    write(
        tmp_path,
        "src/compose.yml",
        yaml.safe_dump({"services": {"app": {"build": ".", "ports": ["8080"]}}}),
    )
    write(tmp_path, "src/app.py", "SECRET = 'S1'\n")
    (tmp_path / "run").mkdir()
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: True)
    runtime = Runtime("compose.yml", auto_expose=True,
                      overlay={"suite:targets/x/its_api.py": "its_api.py"})  # fmt: skip
    target = live.start(runtime, Variant("v"), tmp_path / "src", tmp_path / "suite", tmp_path / "run",
                        "its-o", {}, Docker(), rewrite={"S1": "S2"},
                        model=("172.17.0.1", 8000, "suite-model"))  # fmt: skip
    copy = tmp_path / "run" / "build-src"
    assert (copy / "its_api.py").read_text() == "print('api')\n"
    assert (copy / "app.py").read_text() == "SECRET = 'S2'\n" and target.project.project_dir == copy
    spec = yaml.safe_load((tmp_path / "run" / "compose.isolated.yml").read_text())
    assert "its-model" in spec["services"]


def test_load_spec_applies_pip_pins_from_the_suite(tmp_path: Path) -> None:
    write(tmp_path, "suite/targets/x/pins.txt", "# pins\nstreamlit==1.46.0\n")
    write(
        tmp_path, "src/Dockerfile", "FROM python:3.9-slim\nRUN pip3 install -r requirements.txt\n"
    )
    write(tmp_path, "src/compose.yml", yaml.safe_dump({"services": {"app": {"build": "."}}}))
    runtime = Runtime("compose.yml", pip_constraints="suite:targets/x/pins.txt")
    spec = live.load_spec(runtime, tmp_path / "src", tmp_path / "suite")
    inline = spec["services"]["app"]["build"]["dockerfile_inline"]
    assert "'streamlit==1.46.0'" in inline and "ENV PIP_CONSTRAINT=" in inline


def test_tcp_target_gets_tcp_urls_and_a_greeting_check(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    waited: list[tuple[str, int]] = []
    monkeypatch.setattr(
        docker_ops, "wait_tcp", lambda host, port: waited.append((host, port)) or True
    )
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: pytest.fail("not an HTTP target"))
    target = _start(project, Docker(), Runtime("compose.yml", auto_expose=True, protocol="tcp"))
    port = target.host_ports[target.exposes[0]]
    assert target.base_url == f"tcp://127.0.0.1:{port}" and waited == [("127.0.0.1", port)]
    assert live.endpoints(target, False) == {"app:80": f"tcp://127.0.0.1:{port}"}
    assert live.endpoints(target, True) == {"app:80": "tcp://its-gateway-app-80:80"}


def test_start_stops_with_a_firewall_hint_when_the_model_is_unreachable(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(docker_ops, "wait_http", lambda url: True)
    docker = Docker(model_ok=False)
    hint = re.escape("ufw allow from 172.16.0.0/12 to 172.17.0.1 port 8000")
    with pytest.raises(DockerError, match=hint):
        live.start(Runtime("compose.yml", auto_expose=True), Variant("v"), project / "src",
                   project, project / "run", "its-m", {}, docker,
                   model=("172.17.0.1", 8000, "suite-model"))  # fmt: skip
    assert "down" in docker.calls[-1]
    probe = next(c for c in docker.calls if c[-1].endswith("/v1/models"))
    assert probe[probe.index("--network") + 1] == "its-m_its-edge"
