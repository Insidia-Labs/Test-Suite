"""One run end to end: fetch, seal the key, build the view, start the target, run the
tool, stop the target, record what happened, score it."""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from itsuite import container, images, live
from itsuite.adapter_check import tool_env
from itsuite.docker_ops import DockerError
from itsuite.fetch import fetch
from itsuite.isolation import EDGE_NETWORK, IsolationError, gateway_name
from itsuite.keys import plugin as key_plugin
from itsuite.keys.base import AnswerKey, KeyContext, KeyPlugin, KeyStore, Task
from itsuite.keys.flags import new_flag
from itsuite.keys.juice_shop import fetch_solved
from itsuite.models import Evaluation, Integration, Mode, Source, TargetSpec, ToolMode, ToolSpec
from itsuite.runner import ExecResult, execute, final_status, render_command
from itsuite.scoring import score_run
from itsuite.view import build_view, save_path_map, view_salt

WHITEBOX = frozenset({Mode.SAST, Mode.SECRETS, Mode.SCA, Mode.IAC, Mode.FIX, Mode.PR_REVIEW})
LIVE = frozenset({Mode.DAST, Mode.CTF, Mode.EXPLOIT})
CONTAINER_ROOT = container.ROOT


class RunError(RuntimeError):
    """The run could not be set up (before the tool started)."""


@dataclass(frozen=True)
class SuitePaths:
    root: Path

    @property
    def cache(self) -> Path:
        return self.root / ".cache"

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def keys(self) -> KeyStore:
        return KeyStore(self.cache / "keys")

    @property
    def views(self) -> Path:
        """Where tool views are built: outside the suite's git repo by default. Some tools
        (OSV-Scanner) honour the .gitignore of an enclosing repo, and the suite's repo
        ignores .cache/, so a view inside it would look empty to them."""
        configured = os.environ.get("ITS_VIEWS_DIR")
        return Path(configured) if configured else Path.home() / ".cache" / "itsuite" / "views"

    def private(self, run_name: str) -> Path:
        """Harness-only files for one run (path map, isolated compose with the flag).
        Kept outside the run folder the tool works in."""
        folder = self.cache / "private" / run_name
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def source_dir(self, source: Source) -> Path:
        slug = re.sub(r"[^a-z0-9]+", "-", source.url.lower().removesuffix(".git")).strip("-")
        return self.cache / "src" / f"{slug[-60:]}-{(source.commit or source.sha256)[:12]}"


@dataclass(frozen=True)
class RunRequest:
    tool: ToolSpec
    target: TargetSpec
    mode: Mode
    variant: str = "default"
    task: str = ""
    wall_seconds: int = 3600
    budget_usd: float = 0.0
    budget_tokens: int = 0
    container: bool = False
    extra: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Prepared:
    evaluation: Evaluation
    tool_mode: ToolMode
    plugin: KeyPlugin
    task: Task
    source: Source
    source_dir: Path
    key: AnswerKey
    key_digest: str


def run_id(request: RunRequest) -> str:
    """Time, tool and target only. The variant (e.g. ``patched``) and the task id (a
    CVE id for some targets) would tell the tool the answer, and the tool can see its
    own working folder, so they live in run.json instead."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"{stamp}-{request.tool.id}-{request.target.id}"
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name)[:100] + "-" + secrets.token_hex(3)


def _resolve_task(plugin: KeyPlugin, bench_src: Path, ev: Evaluation, task_id: str) -> Task:
    if plugin.tasks is None:
        if task_id:
            raise RunError(f"{plugin.key_type} has no tasks; drop --task")
        return Task(task_id="")
    tasks = {t.task_id: t for t in plugin.tasks(bench_src, ev.params)}
    if task_id not in tasks:
        sample = ", ".join(list(tasks)[:5])
        raise RunError(f"pick a task with --task (e.g. {sample}); {len(tasks)} available")
    return tasks[task_id]


def _task_source(target: TargetSpec, task: Task, variant: str) -> Source:
    if variant == "patched":
        if task.patched_source is None:
            raise RunError(f"{target.id} task {task.task_id} has no patched source")
        return task.patched_source
    return task.source or target.source


def _resolved_params(ev: Evaluation, root: Path, flag: str) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for name, value in ev.params.items():
        text = value if isinstance(value, str) else None
        params[name] = (
            str(root / text.removeprefix("suite:")) if text and text.startswith("suite:") else value
        )
    return {**params, "flag": flag} if flag else params


def prepare(request: RunRequest, paths: SuitePaths, flag: str) -> Prepared:
    target = request.target
    ev = target.evaluation(request.mode)
    if ev.integration != Integration.NATIVE:
        raise RunError(
            f"{target.id} [{ev.mode.value}] is {ev.integration.value}; "
            "run its own harness and use import-upstream"
        )
    if request.mode not in request.tool.modes:
        raise RunError(f"{request.tool.id} has no {request.mode.value} adapter")
    plugin = key_plugin(ev.key)
    bench_src = fetch(target.source, paths.source_dir(target.source))
    task = _resolve_task(plugin, bench_src, ev, request.task)
    source = _task_source(target, task, request.variant)
    src = bench_src if source == target.source else fetch(source, paths.source_dir(source))
    missing = [p for p in ev.params.get("requires_paths", ()) if not (src / str(p)).exists()]
    if missing:
        raise RunError(f"{target.id}: {missing} missing in {src}; see the manifest notes")
    ctx = KeyContext(
        target.id,
        bench_src,
        ev.variant(request.variant),
        target.source.commit,
        _resolved_params(ev, paths.root, flag),
        task.task_id,
    )
    key = plugin.build(ctx)
    digest = paths.keys.seal(key)
    return Prepared(ev, request.tool.modes[request.mode], plugin, task, source, src, key, digest)


def _values(
    request: RunRequest, run_dir: Path, view_dir: str, target_url: str, paths: SuitePaths
) -> dict[str, str]:
    inside = request.container
    base = CONTAINER_ROOT if inside else ""
    return {
        "target_url": target_url,
        "source_dir": (f"{base}/src" if inside else view_dir) if view_dir else "",
        "out_dir": f"{base}/out" if inside else str(run_dir / "out"),
        "input_dir": f"{base}/input" if inside else str(run_dir / "input"),
        "adapter_dir": f"{base}/adapter"
        if inside
        else str(paths.root / "adapters" / request.tool.id),
        **request.extra,
    }


def _container_plan(
    request: RunRequest,
    run_dir: Path,
    view_dir: str,
    paths: SuitePaths,
    network: str,
    env_names: tuple[str, ...],
) -> container.ContainerPlan:
    install = request.tool.install
    if install is not None and install.kind == "docker":
        raise RunError(f"{request.tool.id} runs Docker itself, so it can't run sealed")
    image = request.tool.image or images.current_image(paths.cache)
    if not image:
        raise RunError("no tools image yet; run `itsuite tools image` first")
    return container.ContainerPlan(
        image=image,
        name=f"its-tool-{run_dir.name.lower()}",
        run_dir=run_dir,
        view_dir=view_dir,
        adapter_dir=paths.root / "adapters" / request.tool.id,
        common_sh=paths.root / "adapters" / "common.sh",
        network=network,
        env_names=env_names,
    )


def _its_env(request: RunRequest, values: Mapping[str, str]) -> dict[str, str]:
    env = {f"ITS_{k.upper()}": v for k, v in values.items()}
    env["ITS_BUDGET_USD"] = str(request.budget_usd)
    env["ITS_BUDGET_TOKENS"] = str(request.budget_tokens)
    env["ITS_WALL_SECONDS"] = str(request.wall_seconds)
    return env


def _make_view(request: RunRequest, prep: Prepared, run_dir: Path, paths: SuitePaths) -> str:
    if request.mode not in WHITEBOX:
        return ""
    view_root = paths.views / run_dir.name
    src = prep.source_dir / prep.task.subdir if prep.task.subdir else prep.source_dir
    result = build_view(src, view_root, request.target.view, view_salt(paths.cache / "private"))
    save_path_map(result, paths.private(run_dir.name) / "path_map.json")
    return str(view_root)


def _write_task_prompt(prep: Prepared, input_dir: Path) -> None:
    if prep.task.prompt:
        (input_dir / "task.md").write_text(prep.task.prompt + "\n", encoding="utf-8")


def _start_live(
    request: RunRequest, prep: Prepared, run_dir: Path, paths: SuitePaths, flag: str
) -> live.LiveTarget | None:
    runtime = request.target.runtime
    if request.mode not in LIVE or runtime is None:
        return None
    project_dir = prep.source_dir / prep.task.subdir if prep.task.subdir else prep.source_dir
    build_args = {k: v.replace("{flag}", flag) for k, v in runtime.build_args.items()}
    name = "its-" + re.sub(r"[^a-z0-9]+", "-", run_dir.name.lower())[-40:].strip("-")
    variant = prep.evaluation.variant(request.variant)
    private = paths.private(run_dir.name)
    return live.start(runtime, variant, project_dir, paths.root, private, name, build_args)


def _observe(prep: Prepared, target: live.LiveTarget | None) -> list[str] | None:
    if prep.key.match != "challenge" or target is None:
        return None
    return sorted(fetch_solved(target.root_url))


def _container_target(target: live.LiveTarget | None) -> tuple[str, str]:
    """(network, url) for a tool container: the edge network and the gateway's name."""
    if target is None:
        return "bridge", ""
    first = target.exposes[0]
    network = f"{target.project.name}_{EDGE_NETWORK}"
    return network, f"http://{gateway_name(first)}:{first.port}{target.base_path}"


def _execute_tool(
    request: RunRequest,
    prep: Prepared,
    run_dir: Path,
    paths: SuitePaths,
    view_dir: str,
    target: live.LiveTarget | None,
) -> ExecResult:
    network, url = _container_target(target) if request.container else ("", "")
    url = url or (target.base_url if target else "")
    values = _values(request, run_dir, view_dir, url, paths)
    command = render_command(prep.tool_mode.command, values)
    env = tool_env(request.tool, paths.cache, _its_env(request, values))
    if not request.container:
        return execute(command, run_dir / "out", env, request.wall_seconds, run_dir)
    names = tuple(
        sorted(n for n in env if n.startswith("ITS_") or n in request.tool.env_passthrough)
    )
    plan = _container_plan(request, run_dir, view_dir, paths, network, names)
    return execute(container.argv(command, plan), run_dir / "out", env, request.wall_seconds,
                   run_dir, on_timeout=lambda: container.kill(plan.name))  # fmt: skip


def _reported_version(run_dir: Path) -> str:
    """The version the adapter saw (out/tool-version.txt), first line only."""
    path = run_dir / "out" / "tool-version.txt"
    if not path.exists():
        return ""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[0][:200] if lines else ""


def _record(
    request: RunRequest,
    prep: Prepared,
    run_dir: Path,
    status: str,
    result: ExecResult | None,
    observations: dict[str, Any],
    files: Mapping[str, Any],
) -> None:
    """run.json. ``files`` says where scoring finds the view roots and the path map."""
    record = {
        "run_id": run_dir.name,
        "tool": request.tool.id,
        "tool_version": request.tool.version,
        "target": request.target.id,
        "level": request.target.level.value,
        "contamination": request.target.contamination.value,
        "mode": request.mode.value,
        "variant": request.variant,
        "task": request.task,
        "status": status,
        "exit_code": result.exit_code if result else None,
        "duration_s": round(result.duration_s, 3) if result else None,
        "sealed": request.container,
        "key_name": prep.key.name,
        "key_digest": prep.key_digest,
        "source_commit": prep.source.commit,
        "output_format": prep.tool_mode.output.value,
        "output_file": prep.tool_mode.output_file,
        "cwe_mode": prep.evaluation.cwe_mode,
        "line_tolerance": prep.evaluation.line_tolerance,
        **files,
        "observations": observations,
        "wall_seconds": request.wall_seconds,
        "budget_usd": request.budget_usd,
        "budget_tokens": request.budget_tokens,
        "tool_version_reported": _reported_version(run_dir),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    (run_dir / "run.json").write_text(json.dumps(record, indent=1), encoding="utf-8")


def _live_phase(
    request: RunRequest, prep: Prepared, run_dir: Path, paths: SuitePaths, view_dir: str, flag: str
) -> tuple[str, ExecResult | None, dict[str, Any]]:
    try:
        target = _start_live(request, prep, run_dir, paths, flag)
    except (DockerError, IsolationError) as exc:
        return "target-error", None, {"error": str(exc)}
    try:
        runtime = request.target.runtime
        if (
            target
            and runtime
            and runtime.setup
            and not live.run_setup(
                paths.root / runtime.setup, target.base_url, request.variant, run_dir / "input"
            )
        ):
            return "setup-error", None, {}
        before = _observe(prep, target)
        result = _execute_tool(request, prep, run_dir, paths, view_dir, target)
        try:
            after = _observe(prep, target)
        except (OSError, ValueError) as exc:  # the app went down during the run
            return "target-error", result, {"before": before, "after": None, "error": str(exc)}
        seen = {"before": before, "after": after} if before is not None else {}
        output = (
            None
            if prep.key.match in ("flag", "challenge")
            else (run_dir / "out" / prep.tool_mode.output_file)
        )
        return final_status(result, output), result, seen
    finally:
        if target:
            live.stop(target)


def run(request: RunRequest, paths: SuitePaths, keep_view: bool = False) -> dict[str, Any]:
    flag = (
        new_flag()
        if key_plugin(request.target.evaluation(request.mode).key).match == "flag"
        else ""
    )
    prep = prepare(request, paths, flag)
    run_dir = paths.results / run_id(request)
    for sub in ("out", "input"):
        (run_dir / sub).mkdir(parents=True, exist_ok=True)
    _write_task_prompt(prep, run_dir / "input")
    view_dir = _make_view(request, prep, run_dir, paths)
    status, result, observations = _live_phase(request, prep, run_dir, paths, view_dir, flag)
    files = {
        "roots": [r for r in (view_dir, f"{CONTAINER_ROOT}/src") if r],
        "path_map": str(paths.private(run_dir.name) / "path_map.json"),
    }
    _record(request, prep, run_dir, status, result, observations, files)
    score = score_run(run_dir, paths.keys)
    if view_dir and not keep_view:
        shutil.rmtree(view_dir, ignore_errors=True)
    return score


def docker_available() -> bool:
    try:
        done = subprocess.run(["docker", "info"], capture_output=True, timeout=30, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0
