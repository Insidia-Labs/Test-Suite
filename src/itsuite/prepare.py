"""Run a target's documented setup step once, in a container, on a copy of its checkout.

The prepared copy is what tools read (the view is built from it). The answer key is
still read from the pinned checkout, and every file of that checkout must come out of
the setup step byte-for-byte unchanged, so the key and the view can't drift apart.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

from itsuite.fetch import sha256_file
from itsuite.models import Prepare, TargetSpec

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
MARKER = ".itsuite-prepared.json"
PREPARE_TIMEOUT = 6 * 3600


class PrepareError(RuntimeError):
    """The setup step failed, or changed files it must not change."""


def prepared_dir(cache: Path, target: TargetSpec) -> Path:
    commit = (target.source.commit or target.source.sha256)[:12]
    return cache / "prepared" / f"{target.id}-{commit}"


def _fingerprint(spec: Prepare) -> str:
    text = json.dumps([spec.image, spec.command, list(spec.outputs), list(spec.cleanup)])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_prepared(cache: Path, target: TargetSpec) -> bool:
    if target.prepare is None:
        return True
    marker = prepared_dir(cache, target) / MARKER
    if not marker.exists():
        return False
    data = json.loads(marker.read_text(encoding="utf-8"))
    return bool(data.get("fingerprint") == _fingerprint(target.prepare))


def _hashes(root: Path) -> dict[str, str]:
    return {
        p.relative_to(root).as_posix(): sha256_file(p)
        for p in sorted(root.rglob("*"))
        if p.is_file() and not p.is_symlink() and ".git" not in p.relative_to(root).parts
    }


def _container(spec: Prepare, work: Path) -> list[str]:
    owner = f"{os.getuid()}:{os.getgid()}"
    script = f"{spec.command} && chown -R {owner} /work"
    network = "bridge" if spec.network else "none"
    return ["docker", "run", "--rm", "--network", network, "-v", f"{work}:/work", "-w", "/work",
            spec.image, "sh", "-c", script]  # fmt: skip


def _check_unchanged(before: dict[str, str], work: Path) -> None:
    """Only the original files are compared; new files (downloads, outputs) are fine."""
    changed = sorted(
        p for p, digest in before.items()
        if not (work / p).is_file() or sha256_file(work / p) != digest
    )  # fmt: skip
    if changed:
        raise PrepareError(f"the setup step changed or removed checkout files: {changed[:5]}")


def run(target: TargetSpec, src: Path, cache: Path, runner: Runner = subprocess.run) -> Path:
    """Prepare the target once; later calls reuse the result."""
    spec = target.prepare
    if spec is None:
        return src
    dest = prepared_dir(cache, target)
    if is_prepared(cache, target):
        return dest
    work = dest.with_name(dest.name + ".work")
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(src, work, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    before = _hashes(work)
    done = runner(_container(spec, work), capture_output=True, text=True, check=False,
                  timeout=PREPARE_TIMEOUT)  # fmt: skip
    (work.parent / f"{dest.name}.log").write_text((done.stdout or "") + (done.stderr or ""))
    if done.returncode != 0:
        raise PrepareError(f"{target.id}: setup step exited {done.returncode}; see {dest.name}.log")
    _check_unchanged(before, work)
    for path in spec.cleanup:
        shutil.rmtree(work / path, ignore_errors=True)
    missing = [p for p in spec.outputs if not (work / p).exists()]
    if missing:
        raise PrepareError(f"{target.id}: the setup step didn't create {missing}")
    (work / MARKER).write_text(json.dumps({"fingerprint": _fingerprint(spec)}), encoding="utf-8")
    shutil.rmtree(dest, ignore_errors=True)
    os.replace(work, dest)
    return dest
