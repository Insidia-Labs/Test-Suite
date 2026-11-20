"""Start and stop an isolated live target, and run its setup script."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from itsuite import apt_pin, docker_ops
from itsuite.docker_ops import ComposeProject, DockerError, Runner
from itsuite.isolation import (
    IsolationError,
    auto_exposes,
    gateway_name,
    isolate,
    target_networks,
)
from itsuite.models import Expose, Runtime, Variant
from itsuite.runner import clean_env

SETUP_TIMEOUT = 600


@dataclass(frozen=True)
class LiveTarget:
    project: ComposeProject
    base_url: str
    root_url: str
    exposes: tuple[Expose, ...]
    host_ports: Mapping[Expose, int]
    networks: tuple[str, ...]
    base_path: str


def compose_file(runtime: Runtime, project_dir: Path, suite_root: Path) -> Path:
    if runtime.compose.startswith("suite:"):
        return suite_root / runtime.compose.removeprefix("suite:")
    return project_dir / runtime.compose


def _base_images(runtime: Runtime, suite_root: Path) -> dict[str, str]:
    if not runtime.base_images:
        return {}
    path = suite_root / runtime.base_images.removeprefix("suite:")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in (data.get("images") or {}).items()}


def _exposes(runtime: Runtime, spec: Mapping[str, object]) -> tuple[Expose, ...]:
    exposes = tuple(auto_exposes(spec)) if runtime.auto_expose else runtime.expose
    if not exposes:
        raise IsolationError("the target exposes no port; set runtime.expose")
    return exposes


def _write_isolated(spec: dict[str, object], run_dir: Path) -> Path:
    path = run_dir / "compose.isolated.yml"
    path.write_text(yaml.safe_dump(spec, sort_keys=False), encoding="utf-8")
    return path


def _check_egress(project: ComposeProject, spec: Mapping[str, object], runner: Runner) -> None:
    for network in target_networks(spec, project.name):
        if docker_ops.egress_open(network, runner):
            raise IsolationError(f"network {network} can reach the internet; stopping the run")


def load_spec(runtime: Runtime, project_dir: Path, suite_root: Path) -> dict[str, Any]:
    """The target's compose spec with its build pins (base images, apt snapshot) applied."""
    spec = yaml.safe_load(
        compose_file(runtime, project_dir, suite_root).read_text(encoding="utf-8")
    )
    if runtime.apt_snapshot or runtime.base_images:
        spec = apt_pin.with_build_pins(
            spec, project_dir, runtime.apt_snapshot, _base_images(runtime, suite_root)
        )
    return dict(spec)


def build_only(
    runtime: Runtime, project_dir: Path, suite_root: Path, work: Path, name: str,
    build_args: Mapping[str, str], runner: Runner = subprocess.run,
) -> tuple[bool, str]:  # fmt: skip
    """Build a target's images the way a run would, without starting anything."""
    spec = isolate(load_spec(runtime, project_dir, suite_root), {}, None, build_args)
    work.mkdir(parents=True, exist_ok=True)
    project = ComposeProject(name, _write_isolated(spec, work), project_dir)
    try:
        done = runner(project.argv("build"), capture_output=True, text=True, check=False,
                      timeout=docker_ops.UP_TIMEOUT)  # fmt: skip
    except subprocess.TimeoutExpired:
        return False, "build timed out"
    tail = " | ".join((done.stderr or "").strip().splitlines()[-2:])
    return done.returncode == 0, tail


def start(
    runtime: Runtime,
    variant: Variant,
    project_dir: Path,
    suite_root: Path,
    run_dir: Path,
    project_name: str,
    build_args: Mapping[str, str],
    runner: Runner = subprocess.run,
    rewrite: Mapping[str, str] | None = None,
) -> LiveTarget:
    """Start the target isolated. With ``rewrite``, it is built from a copy of its source
    in which each key string (a published flag) is replaced by its value (a fresh one)."""
    if rewrite:
        project_dir = rewritten_copy(project_dir, run_dir / "build-src", rewrite)
    spec = load_spec(runtime, project_dir, suite_root)
    exposes = _exposes(runtime, spec)
    host_ports = {expose: docker_ops.free_port() for expose in exposes}
    isolated = isolate(spec, host_ports, variant.env, build_args)
    project = ComposeProject(project_name, _write_isolated(isolated, run_dir), project_dir)
    try:
        docker_ops.compose_up(project, runner)
        _check_egress(project, isolated, runner)
        root_url = f"http://127.0.0.1:{host_ports[exposes[0]]}"
        base_url = root_url + runtime.base_path
        if not docker_ops.wait_http(base_url):
            raise DockerError(f"{base_url} never answered")
    except (DockerError, IsolationError):
        docker_ops.compose_down(project, runner)
        raise
    networks = tuple(target_networks(isolated, project.name))
    return LiveTarget(project, base_url, root_url, exposes, host_ports, networks, runtime.base_path)


def rewritten_copy(src: Path, dest: Path, rewrite: Mapping[str, str]) -> Path:
    """Copy the source (without .git) and replace every key of ``rewrite`` in text files."""
    shutil.rmtree(dest, ignore_errors=True)
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for path in dest.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        new = text
        for old, value in rewrite.items():
            new = new.replace(old, value)
        if new != text:
            path.write_text(new, encoding="utf-8")
    return dest


def endpoints(target: LiveTarget, container: bool) -> dict[str, str]:
    """Every exposed port's URL, for targets with more than one (one MCP server per port)."""
    if container:
        return {f"{e.service}:{e.port}": f"http://{gateway_name(e)}:{e.port}{target.base_path}"
                for e in target.exposes}  # fmt: skip
    return {f"{e.service}:{e.port}": f"http://127.0.0.1:{target.host_ports[e]}{target.base_path}"
            for e in target.exposes}  # fmt: skip


def stop(target: LiveTarget, runner: Runner = subprocess.run) -> None:
    docker_ops.compose_down(target.project, runner)


def run_setup(
    script: Path, base_url: str, variant: str, input_dir: Path, runner: Runner = subprocess.run
) -> bool:
    """Run the target's setup script (create the database, log in, pick a level).

    The script gets the base URL, the variant and a folder to write ``auth.json`` to.
    Returns False when it fails; the run is then not scored.
    """
    input_dir.mkdir(parents=True, exist_ok=True)
    try:
        done = runner(
            ["bash", str(script), base_url, variant, str(input_dir)],
            env=clean_env((), {}),
            capture_output=True,
            text=True,
            timeout=SETUP_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    (input_dir / "setup.log").write_text(
        (done.stdout or "") + (done.stderr or ""), encoding="utf-8"
    )
    return done.returncode == 0
