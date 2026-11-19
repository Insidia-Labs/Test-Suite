"""Fetch a target at its pinned commit (or archive digest) and refuse anything else."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tarfile
import urllib.request
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from itsuite.models import Source

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
GIT_TIMEOUT = 1800
_SAFE_GIT = ("-c", "protocol.file.allow=never", "-c", "core.hooksPath=/dev/null")


class FetchError(RuntimeError):
    """The target could not be fetched at the pinned version."""


def _git(args: Sequence[str], cwd: Path, runner: Runner) -> str:
    try:
        done = runner(
            ["git", *_SAFE_GIT, *args],
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )
    except subprocess.CalledProcessError as exc:
        tail = (exc.stderr or "").strip().splitlines()[-3:]
        raise FetchError(f"git {args[0]} failed: {' | '.join(tail)}") from exc
    except subprocess.TimeoutExpired as exc:
        raise FetchError(f"git {args[0]} timed out") from exc
    return str(done.stdout)


def head_commit(dest: Path, runner: Runner = subprocess.run) -> str:
    return _git(["rev-parse", "HEAD"], dest, runner).strip()


def _reset_clean(dest: Path, runner: Runner) -> None:
    """Undo anything a build or container wrote into the cached checkout."""
    if _git(["status", "--porcelain", "--ignored", "--untracked-files=all"], dest, runner).strip():
        _git(["checkout", "-q", "--force", "HEAD"], dest, runner)
        _git(["clean", "-q", "-fdx"], dest, runner)


def fetch_git(source: Source, dest: Path, runner: Runner = subprocess.run) -> Path:
    if (dest / ".git").exists():
        if head_commit(dest, runner) == source.commit:
            _reset_clean(dest, runner)
            return dest
    elif dest.exists() and any(dest.iterdir()):
        raise FetchError(f"{dest} exists and is not a git checkout")
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        _git(["init", "-q"], dest, runner)
        _git(["remote", "add", "origin", source.url], dest, runner)
    _git(["fetch", "-q", "--depth", "1", "origin", source.commit], dest, runner)
    _git(["checkout", "-q", "--force", "--detach", "FETCH_HEAD"], dest, runner)
    if source.submodules:
        _git(["submodule", "update", "-q", "--init", "--recursive", "--depth", "1"], dest, runner)
    actual = head_commit(dest, runner)
    if actual != source.commit:
        raise FetchError(f"checked out {actual}, pinned {source.commit}")
    return dest


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_member(name: str) -> bool:
    """Reject absolute paths and paths that climb out of the extraction folder."""
    path = PurePosixPath(name.replace("\\", "/"))
    return not path.is_absolute() and ".." not in path.parts and bool(path.parts)


def extract(archive: Path, dest: Path) -> None:
    if zipfile.is_zipfile(archive):
        with zipfile.ZipFile(archive) as bundle:
            bad = [n for n in bundle.namelist() if not safe_member(n)]
            if bad:
                raise FetchError(f"archive has unsafe paths: {bad[:3]}")
            bundle.extractall(dest)
        return
    with tarfile.open(archive) as bundle:
        members = bundle.getmembers()
        bad = [m.name for m in members if not safe_member(m.name) or not (m.isfile() or m.isdir())]
        if bad:
            raise FetchError(f"archive has unsafe paths, links or devices: {bad[:3]}")
        if hasattr(tarfile, "data_filter"):  # drops setuid bits and odd modes too
            bundle.extractall(dest, members=members, filter="data")
        else:
            bundle.extractall(dest, members=members)


def fetch_archive(
    source: Source, dest: Path, opener: Callable[..., Any] = urllib.request.urlopen
) -> Path:
    marker = dest / ".itsuite-sha256"
    if marker.exists() and marker.read_text(encoding="utf-8").strip() == source.sha256:
        return dest
    if not source.url.startswith("https://"):
        raise FetchError("archives are only fetched over https")
    dest.mkdir(parents=True, exist_ok=True)
    part = dest.parent / (dest.name + ".download")
    with opener(source.url, timeout=600) as response, part.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    actual = sha256_file(part)
    if actual != source.sha256:
        part.unlink()
        raise FetchError(f"archive sha256 {actual} does not match pinned {source.sha256}")
    extract(part, dest)
    part.unlink()
    marker.write_text(source.sha256, encoding="utf-8")
    return dest


def fetch(source: Source, dest: Path, runner: Runner = subprocess.run) -> Path:
    if source.kind == "git":
        return fetch_git(source, dest, runner)
    if source.kind == "archive":
        return fetch_archive(source, dest)
    raise FetchError(f"unknown source kind {source.kind!r}")
