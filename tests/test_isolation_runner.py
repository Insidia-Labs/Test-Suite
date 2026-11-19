"""Network isolation of live targets, docker wrappers, and running adapters."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from itsuite import docker_ops
from itsuite.isolation import (
    EDGE_NETWORK,
    GATEWAY_IMAGE,
    IsolationError,
    auto_exposes,
    container_port,
    isolate,
    target_networks,
    violations,
)
from itsuite.models import Expose
from itsuite.runner import (
    ERROR,
    NO_OUTPUT,
    OK,
    TIMEOUT,
    TOOL_MISSING,
    AdapterError,
    ExecResult,
    clean_env,
    execute,
    final_status,
    render_command,
)

XBOW_LIKE = {
    "services": {
        "db": {"build": "./mysql", "expose": ["3306:3306"]},
        "web": {
            "build": {"context": "./app", "args": ["FLAG"]},
            "ports": [80],
            "container_name": "fixed",
            "environment": ["A=1", "B"],
        },
    }
}


@pytest.mark.parametrize(
    ("service", "problem"),
    [
        ({"network_mode": "host"}, "network_mode host"),
        ({"network_mode": "bridge"}, "network_mode bridge"),
        ({"network_mode": "container:abc"}, "network_mode container:abc"),
        ({"network_mode": "service:ghost"}, "network_mode service:ghost"),
        ({"privileged": True}, "privileged"),
        ({"volumes": ["/var/run/docker.sock:/var/run/docker.sock"]}, "Docker socket"),
        ({"volumes": ["/etc:/host-etc:ro"]}, "outside the project: /etc"),
        ({"volumes": ["../../..:/up"]}, "outside the project: ../../.."),
        ({"volumes": ["${HOME}/.ssh:/k"]}, "uses a variable"),
        ({"volumes": [{"type": "bind", "source": "/", "target": "/h"}]}, "outside the project: /"),
        ({"cap_add": ["NET_ADMIN"]}, "cap_add"),
        ({"cap_add": ["CAP_DAC_READ_SEARCH"]}, "cap_add"),
        ({"security_opt": ["seccomp:unconfined"]}, "unconfined"),
        ({"pid": "host"}, "pid: host"),
        ({"uts": "host"}, "uts: host"),
        ({"ipc": "container:abc"}, "ipc: container:abc"),
        ({"devices": ["/dev/kvm"]}, "devices"),
        ({"extends": {"file": "x.yml", "service": "y"}}, "extends"),
        ({"volumes_from": ["container:abc"]}, "volumes_from"),
    ],
)
def test_violations_refuse_escape_hatches(service: dict[str, Any], problem: str) -> None:
    found = violations({"services": {"s": service}})
    assert any(problem in p for p in found)
    with pytest.raises(IsolationError, match="refusing"):
        isolate({"services": {"s": service}}, {})


def test_relative_binds_and_named_volumes_are_fine() -> None:
    spec = {
        "services": {
            "s": {
                "volumes": [
                    "./data:/data",
                    "dbdata:/var/lib/mysql",
                    {"type": "volume", "source": "x", "target": "/x"},
                ]
            }
        }
    }
    assert violations(spec) == []


def test_top_level_escape_hatches_refused() -> None:
    assert violations({"services": {}, "networks": {"n": {"external": True}}})
    assert violations({"services": {}, "include": ["other.yml"]})
    device = {"driver_opts": {"type": "none", "o": "bind", "device": "/"}}
    assert violations({"services": {}, "volumes": {"root": device}})
    assert violations({"services": {}, "volumes": {"ext": {"external": True}}})
    assert violations({"services": {}, "volumes": {"data": None}}) == []


def test_network_mode_inside_the_project_is_allowed() -> None:
    spec = {
        "services": {"db": {}, "app": {"network_mode": "service:db"}, "x": {"network_mode": "none"}}
    }
    assert violations(spec) == []


def test_isolate_makes_networks_internal_and_adds_gateway() -> None:
    expose = Expose("web", 80)
    out = isolate(
        XBOW_LIKE, {expose: 41234}, env={"vulnerable": "0"}, build_args={"FLAG": "FLAG{x}"}
    )
    web = out["services"]["web"]
    assert "ports" not in web and "container_name" not in web
    assert web["build"] == {"context": "./app", "args": {"FLAG": "FLAG{x}"}}
    assert web["environment"] == {"A": "1", "B": "", "vulnerable": "0"}
    assert out["services"]["db"]["build"] == {"context": "./mysql", "args": {"FLAG": "FLAG{x}"}}
    gateway = out["services"]["its-gateway-web-80"]
    assert gateway["image"] == GATEWAY_IMAGE
    assert gateway["ports"] == ["127.0.0.1:41234:80"]
    assert gateway["networks"] == ["default", EDGE_NETWORK]
    assert out["networks"]["default"] == {"internal": True}
    assert out["networks"][EDGE_NETWORK] == {"driver": "bridge"}
    assert XBOW_LIKE["services"]["web"]["ports"] == [80]  # the input is untouched
    assert target_networks(out, "proj") == ["proj_default"]


def test_isolate_named_networks_and_unknown_service() -> None:
    spec = {"services": {"app": {"networks": ["dvwa"]}}, "networks": {"dvwa": None}}
    out = isolate(spec, {Expose("app", 80): 1})
    assert out["networks"]["dvwa"] == {"internal": True}
    assert out["services"]["its-gateway-app-80"]["networks"] == ["dvwa", EDGE_NETWORK]
    assert target_networks(out, "p") == ["p_dvwa"]
    with pytest.raises(IsolationError, match="not in the compose file"):
        isolate(spec, {Expose("ghost", 1): 2})


@pytest.mark.parametrize(
    ("entry", "port"),
    [
        (80, 80),
        ("8080:80", 80),
        ("127.0.0.1:4280:80", 80),
        ("5000/tcp", 5000),
        ("8000-8010:8000-8010", 8000),
        ({"target": 3000, "published": 3}, 3000),
        ("x", None),
    ],
)
def test_container_port_forms(entry: Any, port: int | None) -> None:
    assert container_port(entry) == port


def test_auto_exposes() -> None:
    assert auto_exposes(XBOW_LIKE) == [Expose("web", 80)]


class FakeRunner:
    def __init__(self, codes: Sequence[int]) -> None:
        self.codes = list(codes)
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.codes.pop(0), "", "boom\n")


def test_compose_project_argv_and_errors(tmp_path: Path) -> None:
    project = docker_ops.ComposeProject("its-x", tmp_path / "c.yml", tmp_path)
    runner = FakeRunner([0, 0])
    docker_ops.compose_up(project, runner)
    docker_ops.compose_down(project, runner)
    assert runner.calls[0][:4] == ["docker", "compose", "-p", "its-x"]
    assert runner.calls[0][-4:] == ["up", "-d", "--build", "--wait"]
    assert "down" in runner.calls[1] and "-v" in runner.calls[1]
    with pytest.raises(docker_ops.DockerError, match="boom"):
        docker_ops.compose_up(project, FakeRunner([1]))


def test_egress_probe() -> None:
    blocked = FakeRunner([6, 28])
    assert not docker_ops.egress_open("its_default", blocked)
    assert blocked.calls[0][:5] == ["docker", "run", "--rm", "--network", "its_default"]
    assert docker_ops.egress_open("its_default", FakeRunner([7, 0]))
    assert docker_ops.egress_open("its_default", FakeRunner([35]))  # TLS error: it got out


def test_egress_probe_that_cannot_run_is_an_error_not_blocked() -> None:
    with pytest.raises(docker_ops.DockerError, match="could not run"):
        docker_ops.egress_open("its_missing", FakeRunner([125]))


def test_free_port_and_wait_http_guard() -> None:
    assert 0 < docker_ops.free_port() < 65536
    with pytest.raises(ValueError):
        docker_ops.wait_http("http://example.com")
    assert not docker_ops.wait_http(f"http://127.0.0.1:{docker_ops.free_port()}/", 0.3, 0.1)


def test_render_command_fills_each_argument() -> None:
    argv = render_command(
        "bash {adapter_dir}/dast.sh {target_url} --name '{task_id}'",
        {"adapter_dir": "/a", "target_url": "http://x; rm -rf /", "task_id": "a b"},
    )
    assert argv == ["bash", "/a/dast.sh", "http://x; rm -rf /", "--name", "a b"]
    with pytest.raises(AdapterError, match="unknown placeholder"):
        render_command("run {nope}", {})
    with pytest.raises(AdapterError):
        render_command("", {})
    with pytest.raises(AdapterError):
        render_command("run 'unclosed", {})


def test_clean_env_drops_everything_else(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "nope")
    monkeypatch.setenv("MODEL_KEY", "yes")
    env = clean_env(["MODEL_KEY"], {"ITS_OUT_DIR": "/o"})
    assert "AWS_SECRET_ACCESS_KEY" not in env and env["MODEL_KEY"] == "yes"
    assert env["ITS_OUT_DIR"] == "/o"


def test_execute_statuses(tmp_path: Path) -> None:
    env = clean_env((), {})
    ok = execute([sys.executable, "-c", "print('hi')"], tmp_path, env, 30, tmp_path / "a")
    assert ok.status == OK and ok.exit_code == 0
    assert (tmp_path / "a" / "stdout.log").read_text().strip() == "hi"
    bad = execute([sys.executable, "-c", "raise SystemExit(3)"], tmp_path, env, 30, tmp_path / "b")
    assert (bad.status, bad.exit_code) == (ERROR, 3)
    slow = execute(
        [sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, env, 1, tmp_path / "c"
    )
    assert slow.status == TIMEOUT
    missing = execute(["/no/such/tool"], tmp_path, env, 5, tmp_path / "d")
    assert missing.status == TOOL_MISSING


def test_final_status_requires_output(tmp_path: Path) -> None:
    ok = ExecResult(OK, 0, 1.0)
    assert final_status(ok, tmp_path / "missing.sarif") == NO_OUTPUT
    (tmp_path / "r.sarif").write_text("{}")
    assert final_status(ok, tmp_path / "r.sarif") == OK
    assert final_status(ExecResult(ERROR, 2, 1.0), tmp_path / "r.sarif") == ERROR
    assert final_status(ok, None) == OK


def test_timeout_stops_the_whole_process_group(tmp_path: Path) -> None:
    marker = tmp_path / "child-still-running"
    script = f"(sleep 3; touch {marker}) & sleep 30"
    called: list[str] = []
    result = execute(
        ["sh", "-c", script],
        tmp_path,
        clean_env((), {}),
        1,
        tmp_path / "l",
        on_timeout=lambda: called.append("cleanup"),
    )
    assert result.status == TIMEOUT and called == ["cleanup"]
    import time

    time.sleep(3.5)
    assert not marker.exists()  # the background child was killed with its group
