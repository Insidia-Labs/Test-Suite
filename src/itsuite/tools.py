"""Install tools at their pinned versions into the suite's own cache (``.cache/tools``).

Nothing is installed system-wide. Binaries and archives are kept only when their
SHA-256 matches the manifest; Python tools get their own virtualenv with exact
versions; Docker images are pulled by digest. Adapters find the tools because the
runner puts ``.cache/tools/bin`` first on ``PATH``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsuite.fetch import FetchError, download, extract
from itsuite.models import Install, ToolSpec

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
PIP_PYTHON = "3.12"


class ToolInstallError(RuntimeError):
    """A tool could not be installed at its pinned version."""


@dataclass(frozen=True)
class ToolPaths:
    root: Path

    @property
    def bin(self) -> Path:
        return self.root / "bin"

    def downloads(self, tool_id: str) -> Path:
        return self.root / "downloads" / tool_id

    def venv(self, tool_id: str) -> Path:
        return self.root / "venvs" / tool_id


def _run(argv: Sequence[str], runner: Runner, what: str) -> None:
    try:
        done = runner(list(argv), capture_output=True, text=True, check=False, timeout=1800)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise ToolInstallError(f"{what}: {exc}") from exc
    if done.returncode != 0:
        tail = " | ".join((done.stderr or "").strip().splitlines()[-3:])
        raise ToolInstallError(f"{what} failed: {tail}")


def _place(source: Path, paths: ToolPaths, name: str) -> str:
    paths.bin.mkdir(parents=True, exist_ok=True)
    target = paths.bin / name
    shutil.copyfile(source, target)
    target.chmod(0o755)
    return name


def _install_archive(
    tool: ToolSpec, spec: Install, paths: ToolPaths, opener: Callable[..., Any]
) -> list[str]:
    folder = paths.downloads(tool.id)
    archive = download(spec.url, spec.sha256, folder / spec.url.rsplit("/", 1)[-1], opener)
    unpacked = folder / f"unpacked-{spec.sha256[:12]}"
    if not unpacked.exists():
        extract(archive, unpacked)
    found = [p for p in unpacked.rglob(spec.binary) if p.is_file()]
    if not found:
        raise ToolInstallError(f"{tool.id}: {spec.binary} not found in {archive.name}")
    return [_place(found[0], paths, Path(spec.binary).name)]


def _install_binary(
    tool: ToolSpec, spec: Install, paths: ToolPaths, opener: Callable[..., Any]
) -> list[str]:
    folder = paths.downloads(tool.id)
    path = download(spec.url, spec.sha256, folder / spec.url.rsplit("/", 1)[-1], opener)
    return [_place(path, paths, spec.binary)]


def _install_pip(tool: ToolSpec, spec: Install, paths: ToolPaths, runner: Runner) -> list[str]:
    venv = paths.venv(tool.id)
    if not (venv / "bin" / "python").exists():
        version = spec.python or PIP_PYTHON
        _run(["uv", "venv", "-q", "--python", version, str(venv)], runner, f"{tool.id} venv")
    python = str(venv / "bin" / "python")
    _run(["uv", "pip", "install", "-q", "--python", python, *spec.packages], runner,
         f"{tool.id} pip install")  # fmt: skip
    paths.bin.mkdir(parents=True, exist_ok=True)
    for name in spec.binaries:
        link = paths.bin / name
        if link.is_symlink() or link.exists():
            link.unlink()
        os.symlink(venv / "bin" / name, link)
    return list(spec.binaries)


def install(
    tool: ToolSpec,
    cache: Path,
    opener: Callable[..., Any] = urllib.request.urlopen,
    runner: Runner = subprocess.run,
) -> list[str]:
    """Install one tool; returns the commands (or image) it provides."""
    spec = tool.install
    if spec is None:
        raise ToolInstallError(f"{tool.id} has no install block in its manifest")
    paths = ToolPaths(cache / "tools")
    try:
        if spec.kind == "archive":
            return _install_archive(tool, spec, paths, opener)
        if spec.kind == "binary":
            return _install_binary(tool, spec, paths, opener)
    except FetchError as exc:
        raise ToolInstallError(f"{tool.id}: {exc}") from exc
    if spec.kind == "pip":
        return _install_pip(tool, spec, paths, runner)
    _run(["docker", "pull", spec.image], runner, f"{tool.id} docker pull")
    return [spec.image]


def commands(tool: ToolSpec) -> tuple[str, ...]:
    spec = tool.install
    if spec is None or spec.kind == "docker":
        return ()
    if spec.kind == "pip":
        return spec.binaries
    return (Path(spec.binary).name,)


def installed(tool: ToolSpec, cache: Path) -> bool:
    names = commands(tool)
    return bool(names) and all((cache / "tools" / "bin" / n).exists() for n in names)


def bin_dir(cache: Path) -> Path:
    return ToolPaths(cache / "tools").bin
