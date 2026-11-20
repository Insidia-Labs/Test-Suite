"""Every pin the suite depends on, in one lock file, and checks that each still resolves.

Pins live in many places: target commits and archive hashes, tool installs, the model
revision, base-image digests, a Debian snapshot date, pip constraints, image digests in
Dockerfiles and adapter scripts, and the harness's own helper images. ``itsuite lock``
gathers them into ``suite.lock.json``, one line per pin, with a digest of the whole
set. A pin change then shows up as a diff, and CI fails when the lock file is out of
date. ``itsuite lock --online`` asks upstream whether each pin still resolves (a
force-pushed commit, a deleted release or image, a yanked package), and tells "gone"
apart from "couldn't check".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from itsuite import apt_pin, images, isolation, live
from itsuite.catalog import Catalog
from itsuite.models import ModelSpec, TargetSpec, ToolSpec

LOCK_FILE = "suite.lock.json"
USER_AGENT = "itsuite-lock (pin check)"
Runner = Callable[..., "subprocess.CompletedProcess[str]"]


@dataclass(frozen=True, order=True)
class Pin:
    kind: str  # git, archive, image, pypi, hf-model, apt-snapshot
    ref: str  # url@commit, url, image@digest, name==version, repo@revision, timestamp
    used_by: str
    sha256: str = ""  # archives: the content hash the fetcher checks


@dataclass(frozen=True)
class Problem:
    pin: Pin
    status: str  # "missing" (upstream says it's gone) or "error" (couldn't check)
    detail: str


def collect(catalog: Catalog, root: Path) -> list[Pin]:
    """Every pin, sorted and without duplicates."""
    pins: set[Pin] = {
        Pin("image", isolation.GATEWAY_IMAGE, "harness gateway"),
        Pin("image", isolation.PROBE_IMAGE, "harness probes"),
        Pin("image", images.BASE_IMAGE, "harness tools image"),
    }
    for target in catalog.targets.values():
        pins.update(_target_pins(target, root))
    for tool in catalog.tools.values():
        pins.update(_tool_pins(tool))
    for model in catalog.models.values():
        pins.update(_model_pins(model))
    pins.update(_file_pins(root))
    return sorted(pins)


def _target_pins(target: TargetSpec, root: Path) -> list[Pin]:
    who, source = f"target {target.id}", target.source
    pins = (
        [Pin("git", f"{source.url}@{source.commit}", who)]
        if source.kind == "git"
        else [Pin("archive", source.url, who, source.sha256)]
    )
    if target.prepare is not None:
        pins.append(Pin("image", target.prepare.image, f"{who} prepare"))
    runtime = target.runtime
    if runtime is None:
        return pins
    if runtime.apt_snapshot:
        pins.append(Pin("apt-snapshot", runtime.apt_snapshot, who))
    pins += [Pin("image", f"{image}@{digest}", who)
             for image, digest in live.base_images(runtime, root).items()]  # fmt: skip
    if runtime.pip_constraints:
        path = root / runtime.pip_constraints.removeprefix("suite:")
        pins += [Pin("pypi", pin, who) for pin in apt_pin.read_pins(path)]
    return pins


_GIT_PACKAGE = re.compile(r"git\+(?P<url>https://[^@#\s]+)@(?P<commit>[0-9a-f]{40})")


def _tool_pins(tool: ToolSpec) -> list[Pin]:
    install, who = tool.install, f"tool {tool.id}"
    if install is None:
        return []
    if install.kind in ("archive", "binary"):
        return [Pin("archive", install.url, who, install.sha256)]
    if install.kind == "docker":
        return [Pin("image", install.image, who)]
    pins = []
    for package in install.packages:
        git = _GIT_PACKAGE.search(package)
        pins.append(Pin("git", f"{git['url']}@{git['commit']}", who) if git else
                    Pin("pypi", package, who))  # fmt: skip
    return pins


def _model_pins(model: ModelSpec) -> list[Pin]:
    who = f"model {model.id}"
    return [Pin("hf-model", f"{model.repo}@{model.revision}", who),
            Pin("pypi", model.server_package, who)]  # fmt: skip


_IMAGE_REF = re.compile(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}")
_COMMIT_VAR = re.compile(r'^commit="([0-9a-f]{40})"', re.MULTILINE)
_GIT_URL = re.compile(r"https://\S+?\.git\b")


def _file_pins(root: Path) -> list[Pin]:
    """Image digests in the suite's Dockerfiles and adapter scripts, and a script's pinned
    ``commit="..."`` together with the git URL it clones (Nuclei's templates)."""
    files = sorted((root / "targets").glob("**/Dockerfile")) + sorted(
        (root / "adapters").glob("**/*.sh")
    )
    pins = []
    for path in files:
        text, who = path.read_text(encoding="utf-8"), path.relative_to(root).as_posix()
        pins += [Pin("image", ref, who) for ref in _IMAGE_REF.findall(text)]
        commit, url = _COMMIT_VAR.search(text), _GIT_URL.search(text)
        if commit and url:
            pins.append(Pin("git", f"{url.group(0)}@{commit.group(1)}", who))
    return pins


def _row(pin: Pin) -> dict[str, str]:
    row = {"kind": pin.kind, "ref": pin.ref, "used_by": pin.used_by}
    return {**row, "sha256": pin.sha256} if pin.sha256 else row


def _line(pin: Pin) -> str:
    return f"{pin.kind} {pin.ref} ({pin.used_by})"


def write(root: Path, pins: Iterable[Pin]) -> str:
    """Write the lock file, one pin per line so a change is a one-line diff; return its
    digest."""
    rows = [json.dumps(_row(pin), sort_keys=True) for pin in sorted(set(pins))]
    digest = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
    body = ",\n  ".join(rows)
    note = "Written by itsuite lock. Do not edit; change the pins at their source."
    text = (f'{{\n "note": "{note}",\n "digest": "{digest}",\n'
            f' "pins": [\n  {body}\n ]\n}}\n')  # fmt: skip
    (root / LOCK_FILE).write_text(text, encoding="utf-8")
    return digest


def stale(root: Path, pins: Iterable[Pin]) -> list[str]:
    """What differs between the lock file and the pins: added pins first, then removed."""
    path = root / LOCK_FILE
    if not path.is_file():
        return [f"{LOCK_FILE} is missing"]
    locked = {Pin(**row) for row in json.loads(path.read_text(encoding="utf-8"))["pins"]}
    current = set(pins)
    return [f"+ {_line(p)}" for p in sorted(current - locked)] + [
        f"- {_line(p)}" for p in sorted(locked - current)
    ]


def http_status(url: str) -> int:
    """The status a GET answers with, reading at most one byte of the body."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return exc.code


def _from_status(code: int) -> tuple[str, str]:
    if code in (200, 206):
        return "ok", ""
    return ("missing" if code in (404, 410) else "error"), f"HTTP {code}"


def check_pypi(pin: Pin) -> tuple[str, str]:
    name, version = pin.ref.split("==", 1)
    name = re.sub(r"\[.*\]", "", name).strip()
    return _from_status(http_status(f"https://pypi.org/pypi/{name}/{version.strip()}/json"))


def check_hf_model(pin: Pin) -> tuple[str, str]:
    repo, revision = pin.ref.rsplit("@", 1)
    return _from_status(
        http_status(f"https://huggingface.co/api/models/{repo}/revision/{revision}")
    )


def check_archive(pin: Pin) -> tuple[str, str]:
    return _from_status(http_status(pin.ref))


def check_apt_snapshot(pin: Pin) -> tuple[str, str]:
    return _from_status(http_status(f"http://snapshot.debian.org/archive/debian/{pin.ref}/"))


_GIT_GONE = ("not our ref", "couldn't find remote ref", "repository not found",
             "could not read username", "not found")  # fmt: skip


def check_git(pin: Pin, runner: Runner = subprocess.run) -> tuple[str, str]:
    """Fetch only the pinned commit object (no trees or files) into a throwaway repo."""
    url, commit = pin.ref.rsplit("@", 1)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}  # a gone repo asks for a login
    with tempfile.TemporaryDirectory() as tmp:
        runner(["git", "init", "-q", "--bare", tmp], capture_output=True, text=True, check=False)
        fetch = ["git", "-C", tmp, "fetch", "-q", "--depth=1", "--filter=tree:0", url, commit]
        done = runner(fetch, capture_output=True, text=True, check=False, timeout=180, env=env)
    if done.returncode == 0:
        return "ok", ""
    lines = (done.stderr or "").strip().splitlines()
    detail = lines[-1] if lines else f"git exit {done.returncode}"
    return ("missing" if any(g in detail.lower() for g in _GIT_GONE) else "error"), detail


def check_image(pin: Pin, runner: Runner = subprocess.run) -> tuple[str, str]:
    done = runner(["docker", "buildx", "imagetools", "inspect", pin.ref],
                  capture_output=True, text=True, check=False, timeout=120)  # fmt: skip
    if done.returncode == 0:
        return "ok", ""
    lines = (done.stderr or "").strip().splitlines()
    detail = lines[-1] if lines else f"docker exit {done.returncode}"
    gone = "not found" in detail.lower() or "manifest unknown" in detail.lower()
    return ("missing" if gone else "error"), detail


Checker = Callable[[Pin], tuple[str, str]]
CHECKERS: Mapping[str, Checker] = {
    "git": check_git, "archive": check_archive, "image": check_image, "pypi": check_pypi,
    "hf-model": check_hf_model, "apt-snapshot": check_apt_snapshot,
}  # fmt: skip


def check_online(
    pins: Sequence[Pin], checkers: Mapping[str, Checker] | None = None, workers: int = 8
) -> list[Problem]:
    """Check each distinct pin once; report every pin whose check didn't come back ok."""
    table = checkers or CHECKERS
    groups: dict[tuple[str, str], list[Pin]] = {}
    for pin in pins:
        groups.setdefault((pin.kind, pin.ref), []).append(pin)

    def one(pin: Pin) -> tuple[str, str]:
        try:
            return table[pin.kind](pin)
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return "error", str(exc) or type(exc).__name__

    firsts = [group[0] for group in groups.values()]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(one, firsts))
    return [Problem(pin, status, detail)
            for group, (status, detail) in zip(groups.values(), results, strict=True)
            if status != "ok" for pin in group]  # fmt: skip
