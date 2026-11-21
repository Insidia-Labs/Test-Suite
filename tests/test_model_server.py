"""The pinned model service for LLM-backed targets, and the gateway that reaches it."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import SUITE_ROOT, write
from itsuite import model_server
from itsuite.catalog import load_catalog, parse_model
from itsuite.isolation import (
    EDGE_NETWORK,
    MODEL_SERVICE,
    isolate,
    target_networks,
    with_model_gateway,
)
from itsuite.models import CatalogError, Expose

SPEC = load_catalog(SUITE_ROOT).models["qwen3.5-0.8b"]


class Recorder:
    def __init__(self, code: int = 0, out: str = "") -> None:
        self.code, self.out = code, out
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[:2] == ["uv", "venv"]:
            (Path(argv[-1]) / "bin").mkdir(parents=True)
            (Path(argv[-1]) / "bin" / "python").write_text("")
        if "-c" in argv and self.code == 0:  # the snapshot download writes the model folder
            write(Path(argv[-1]), "config.json", "{}")
        return subprocess.CompletedProcess(argv, self.code, self.out, "boom\n")


def test_model_manifest_is_pinned() -> None:
    assert len(SPEC.revision) == 40 and SPEC.server_package == "vllm==0.34.0"
    assert SPEC.license == "Apache-2.0" and "--seed" in SPEC.server_args
    base = {"id": "m", "name": "M", "license": "MIT", "repo": "o/m", "served_name": "s"}
    with pytest.raises(CatalogError, match="40-character"):
        parse_model({**base, "revision": "main", "server_package": "vllm==1"}, "c")
    with pytest.raises(CatalogError, match="pinned"):
        parse_model({**base, "revision": "a" * 40, "server_package": "vllm"}, "c")


def test_install_download_and_serve_command(tmp_path: Path) -> None:
    runner = Recorder()
    model_server.install(SPEC, tmp_path, runner)
    assert runner.calls[0][:2] == ["uv", "venv"] and "vllm==0.34.0" in runner.calls[1]
    dest = model_server.download(SPEC, tmp_path, runner)
    assert SPEC.revision in runner.calls[-1] and dest.name.endswith(SPEC.revision[:12])
    calls = len(runner.calls)
    model_server.download(SPEC, tmp_path, runner)  # already there: no second download
    assert len(runner.calls) == calls
    argv = model_server.serve_argv(SPEC, tmp_path, "172.17.0.1")
    assert argv[1] == "serve" and argv[argv.index("--host") + 1] == "172.17.0.1"
    assert argv[argv.index("--served-model-name") + 1] == "suite-model"
    with pytest.raises(model_server.ModelServerError, match="failed: boom"):
        model_server.install(SPEC, tmp_path / "x", Recorder(1))
    empty = Recorder()
    empty.calls = []
    with pytest.raises(model_server.ModelServerError, match="produced nothing"):
        model_server.download(
            SPEC, tmp_path / "y", lambda argv, **k: subprocess.CompletedProcess(argv, 0, "", "")
        )


def test_bridge_ip_status_and_stop(tmp_path: Path) -> None:
    assert model_server.bridge_ip(Recorder(out="172.17.0.1\n")) == "172.17.0.1"
    assert model_server.status(tmp_path) is None and not model_server.stop(tmp_path)
    write(tmp_path, "models/server.json", json.dumps({"model": "m", "pid": 0, "host": "127.0.0.1",
                                                     "port": 1}))  # fmt: skip
    assert model_server.status(tmp_path) is None  # pid not alive
    assert not model_server.stop(tmp_path) and not model_server.state_path(tmp_path).exists()


def test_model_gateway_is_the_only_way_out() -> None:
    spec = {"services": {"dvla": {"build": ".", "environment": ["A=1"]}}}
    isolated = isolate(spec, {Expose("dvla", 8080): 41000})
    out = with_model_gateway(isolated, "172.17.0.1", 8000, "suite-model")
    gateway = out["services"][MODEL_SERVICE]
    assert gateway["command"] == ["TCP-LISTEN:8000,fork,reuseaddr", "TCP:172.17.0.1:8000"]
    assert gateway["networks"] == ["default", EDGE_NETWORK] and "ports" not in gateway
    env = out["services"]["dvla"]["environment"]
    assert env["ITS_MODEL_BASE"] == "http://its-model:8000/v1" and env["A"] == "1"
    assert "ITS_MODEL_BASE" not in out["services"]["its-gateway-dvla-8080"].get("environment", {})
    assert target_networks(out, "p") == ["p_default"]  # the gateways aren't probed as targets
    assert out["networks"]["default"]["internal"] is True


class FakeProcess:
    pid = 4242

    def __init__(self, exits: int | None) -> None:
        self.returncode = exits

    def poll(self) -> int | None:
        return self.returncode


def test_serve_runs_offline_without_a_compiler_and_reports_early_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    launched: list[dict[str, Any]] = []

    def popen(exits: int | None) -> Any:
        def fake(argv: Sequence[str], **kwargs: Any) -> FakeProcess:
            launched.append(kwargs)
            return FakeProcess(exits)

        return fake

    monkeypatch.setattr(model_server, "_answers", lambda url: True)
    monkeypatch.setattr(model_server.subprocess, "Popen", popen(None))
    state = model_server.serve(SPEC, tmp_path, "172.17.0.1")
    env = launched[0]["env"]
    assert env["HF_HUB_OFFLINE"] == "1" and env["VLLM_NO_USAGE_STATS"] == "1"
    assert env["VLLM_USE_FLASHINFER_SAMPLER"] == "0" and launched[0]["start_new_session"]
    assert state["pid"] == 4242 and model_server.state_path(tmp_path).is_file()
    monkeypatch.setattr(model_server.subprocess, "Popen", popen(1))
    with pytest.raises(model_server.ModelServerError, match="exited with 1"):
        model_server.serve(SPEC, tmp_path, "172.17.0.1")
