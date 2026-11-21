"""The image sealed (container) runs use: the pinned tools on a pinned base, nothing else.

Built from the same install blocks as ``itsuite tools install``. Release binaries are
copied from ``.cache/tools/bin`` after their SHA-256 was checked; Python tools are
installed with their exact pins into their own virtualenvs. Tools that run Docker
themselves (ZAP) are left out: a sealed container has no Docker socket. The image tag
is a hash of everything that went into it, so a pin change gives a new image.
"""

from __future__ import annotations

import hashlib
import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path

from itsuite.models import ToolSpec
from itsuite.tools import ToolInstallError, bin_dir, commands

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
BASE_IMAGE = (
    "python:3.12-slim-bookworm"
    "@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
)
IMAGE_REPO = "itsuite-tools"
_SYSTEM_PACKAGES = "bash ca-certificates curl git"


def image_tools(tools: Sequence[ToolSpec]) -> list[ToolSpec]:
    """The tools that go in the image: installable, and not Docker-based."""
    return [t for t in tools if t.install is not None and t.install.kind != "docker"]


def dockerfile(tools: Sequence[ToolSpec]) -> str:
    lines = [
        f"FROM {BASE_IMAGE}",
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        f"{_SYSTEM_PACKAGES} && rm -rf /var/lib/apt/lists/*",
        "COPY bin/ /usr/local/bin/",
    ]
    for tool in image_tools(tools):
        spec = tool.install
        if spec is None or spec.kind != "pip":
            continue
        venv = f"/opt/itsuite/{tool.id}"
        packages = " ".join(shlex.quote(p) for p in spec.packages)
        lines.append(
            f"RUN python -m venv {venv} && {venv}/bin/pip install --no-cache-dir {packages}"
        )
        lines += [f"RUN ln -s {venv}/bin/{name} /usr/local/bin/{name}" for name in spec.binaries]
    lines += ["ENV HOME=/tmp", "WORKDIR /its/out"]
    return "\n".join(lines) + "\n"


def build_context(tools: Sequence[ToolSpec], cache: Path, dest: Path) -> Path:
    """A clean build folder: the Dockerfile and the checked release binaries."""
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "bin").mkdir(parents=True)
    for tool in image_tools(tools):
        if tool.install is None or tool.install.kind == "pip":
            continue
        for name in commands(tool):
            source = bin_dir(cache) / name
            if not source.is_file() or source.is_symlink():
                raise ToolInstallError(f"{tool.id}: run `itsuite tools install {tool.id}` first")
            shutil.copy2(source, dest / "bin" / name)
    (dest / "Dockerfile").write_text(dockerfile(tools), encoding="utf-8")
    return dest


def context_tag(context: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(p for p in context.rglob("*") if p.is_file()):
        digest.update(path.relative_to(context).as_posix().encode("utf-8"))
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return f"{IMAGE_REPO}:{digest.hexdigest()[:16]}"


def build(tools: Sequence[ToolSpec], cache: Path, runner: Runner = subprocess.run) -> str:
    context = build_context(tools, cache, cache / "tools" / "image-context")
    tag = context_tag(context)
    done = runner(["docker", "build", "-q", "-t", tag, str(context)], capture_output=True,
                  text=True, check=False, timeout=3600)  # fmt: skip
    if done.returncode != 0:
        tail = " | ".join((done.stderr or "").strip().splitlines()[-4:])
        raise ToolInstallError(f"image build failed: {tail}")
    (cache / "tools" / "image.txt").write_text(tag + "\n", encoding="utf-8")
    return tag


def current_image(cache: Path) -> str:
    """The last image built for this suite cache, or "" if none."""
    path = cache / "tools" / "image.txt"
    return path.read_text(encoding="utf-8").strip() if path.exists() else ""
