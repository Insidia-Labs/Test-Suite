"""Serve a catalog model with vLLM on the host GPU, for LLM-backed targets.

vLLM runs on the host because the GPU isn't available to containers here. It binds to
Docker's bridge address (not 0.0.0.0, so not the LAN), with usage statistics off and
Hugging Face offline once the pinned revision is downloaded. Targets reach it through
one gateway container on their own network (see ``isolation.with_model_gateway``).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from itsuite.models import ModelSpec

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
START_TIMEOUT = 1200
_QUIET_ENV = {"VLLM_NO_USAGE_STATS": "1", "DO_NOT_TRACK": "1", "HF_HUB_DISABLE_TELEMETRY": "1"}
# FlashInfer's sampler compiles kernels on first use, which needs nvcc; the plain one doesn't.
_NO_JIT_ENV = {"VLLM_USE_FLASHINFER_SAMPLER": "0"}


class ModelServerError(RuntimeError):
    """The model could not be installed, downloaded or served."""


def venv(cache: Path) -> Path:
    return cache / "tools" / "venvs" / "vllm"


def model_dir(cache: Path, spec: ModelSpec) -> Path:
    return cache / "models" / f"{spec.repo.replace('/', '__')}@{spec.revision[:12]}"


def state_path(cache: Path) -> Path:
    return cache / "models" / "server.json"


def _run(argv: list[str], runner: Runner, what: str, env: dict[str, str] | None = None) -> str:
    done = runner(argv, capture_output=True, text=True, check=False, timeout=7200,
                  env={**os.environ, **(env or {})})  # fmt: skip
    if done.returncode != 0:
        tail = " | ".join((done.stderr or "").strip().splitlines()[-3:])
        raise ModelServerError(f"{what} failed: {tail}")
    return str(done.stdout)


def install(spec: ModelSpec, cache: Path, runner: Runner = subprocess.run) -> None:
    python = venv(cache) / "bin" / "python"
    if not python.exists():
        _run(["uv", "venv", "-q", "-p", "3.12", str(venv(cache))], runner, "vllm venv")
    _run(["uv", "pip", "install", "-q", "--python", str(python), spec.server_package], runner,
         "vllm install")  # fmt: skip


def download(spec: ModelSpec, cache: Path, runner: Runner = subprocess.run) -> Path:
    """The pinned revision of the model, downloaded once."""
    dest = model_dir(cache, spec)
    marker = dest / ".itsuite-revision"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() == spec.revision:
        return dest
    script = (
        "import sys; from huggingface_hub import snapshot_download; "
        "snapshot_download(sys.argv[1], revision=sys.argv[2], local_dir=sys.argv[3])"
    )
    python = str(venv(cache) / "bin" / "python")
    _run([python, "-c", script, spec.repo, spec.revision, str(dest)], runner, "model download",
         {"HF_HUB_DISABLE_TELEMETRY": "1"})  # fmt: skip
    if not dest.is_dir() or not any(dest.iterdir()):
        raise ModelServerError(f"downloading {spec.repo}@{spec.revision[:12]} produced nothing")
    marker.write_text(spec.revision, encoding="utf-8")
    return dest


def bridge_ip(runner: Runner = subprocess.run) -> str:
    out = _run(["docker", "network", "inspect", "bridge", "--format",
                "{{(index .IPAM.Config 0).Gateway}}"], runner, "docker bridge lookup")  # fmt: skip
    return out.strip()


def _answers(url: str, timeout: float = 5.0) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout):
            return True
    except (urllib.error.URLError, OSError):
        return False


def status(cache: Path) -> dict[str, Any] | None:
    """The running server's state, or None when nothing is serving."""
    path = state_path(cache)
    if not path.exists():
        return None
    state = json.loads(path.read_text(encoding="utf-8"))
    alive = _pid_alive(int(state.get("pid", 0)))
    url = f"http://{state['host']}:{state['port']}/v1/models"
    return state if alive and _answers(url) else None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def serve_argv(spec: ModelSpec, cache: Path, host: str) -> list[str]:
    return [str(venv(cache) / "bin" / "vllm"), "serve", str(model_dir(cache, spec)),
            "--served-model-name", spec.served_name, "--host", host, "--port", str(spec.port),
            *spec.server_args]  # fmt: skip


def serve(spec: ModelSpec, cache: Path, host: str, wait_s: int = START_TIMEOUT) -> dict[str, Any]:
    """Start vLLM in the background (or reuse a running one) and wait until it answers."""
    running = status(cache)
    if running and running.get("model") == spec.id:
        return running
    if running:
        raise ModelServerError(f"{running['model']} is already being served; stop it first")
    log = cache / "models" / "server.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, **_QUIET_ENV, **_NO_JIT_ENV, "HF_HUB_OFFLINE": "1"}
    with log.open("ab") as handle:
        process = subprocess.Popen(
            serve_argv(spec, cache, host), stdout=handle, stderr=handle,
            stdin=subprocess.DEVNULL, env=env, start_new_session=True,
        )  # fmt: skip
    state = {"model": spec.id, "served_name": spec.served_name, "pid": process.pid,
             "host": host, "port": spec.port, "revision": spec.revision}  # fmt: skip
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ModelServerError(f"vLLM exited with {process.returncode}; see {log}")
        if _answers(f"http://{host}:{spec.port}/v1/models"):
            state_path(cache).write_text(json.dumps(state, indent=1), encoding="utf-8")
            return state
        time.sleep(3)
    os.killpg(process.pid, signal.SIGTERM)
    raise ModelServerError(f"vLLM did not answer within {wait_s}s; see {log}")


def stop(cache: Path) -> bool:
    path = state_path(cache)
    if not path.exists():
        return False
    pid = int(json.loads(path.read_text(encoding="utf-8")).get("pid", 0))
    path.unlink()
    if _pid_alive(pid):
        os.killpg(pid, signal.SIGTERM)
        return True
    return False
