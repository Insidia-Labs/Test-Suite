"""Pin target builds so old images keep building: base images and Debian packages.

Many targets (XBOW above all) build from Debian images and run ``apt-get install``
against the live mirrors. Debian later moves or prunes those versions (for example
bullseye-security now answers 404 for packages its old index still lists), so the
build breaks. For each Dockerfile stage that uses apt, the harness inserts one step
right after ``FROM`` that points apt at snapshot.debian.org at a fixed date, or at
archive.debian.org (complete and frozen) for the releases Debian has retired, jessie to
bullseye. The Dockerfile on disk is left alone; the changed copy reaches compose as
``dockerfile_inline``. Base images are pinned to the
digest they had on the same date, so installed packages never outrun the snapshot.
Only base images and package sources change, never the target's code. Ubuntu images
keep their sources: their archive keeps old versions, and its snapshot service needs
HTTPS certificates base images may lack.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SNAPSHOT_RE = re.compile(r"^\d{8}T\d{6}Z$")
_FROM = re.compile(r"^\s*FROM\s", re.IGNORECASE)
_FROM_IMAGE = re.compile(r"^(\s*FROM\s+(?:--platform=\S+\s+)?)(\S+)(.*)$", re.IGNORECASE)
_USES_APT = re.compile(r"\bapt(-get)?\s+(update|install)\b")


def snapshot_step(timestamp: str) -> str:
    """One RUN line that rewrites apt sources on Debian and does nothing elsewhere."""
    if not SNAPSHOT_RE.match(timestamp):
        raise ValueError(f"snapshot timestamp must look like 20240601T000000Z, got {timestamp!r}")
    snap = f"http://snapshot.debian.org/archive/debian/{timestamp}"
    snap_sec = f"http://snapshot.debian.org/archive/debian-security/{timestamp}"
    old, old_sec = "http://archive.debian.org/debian", "http://archive.debian.org/debian-security"
    script = (
        "if [ -f /etc/debian_version ] && command -v apt-get >/dev/null 2>&1 "
        "&& ! grep -qi ubuntu /etc/os-release 2>/dev/null; then "
        ". /etc/os-release; C=${VERSION_CODENAME:-}; "
        '[ -n "$C" ] || case "$(cut -d. -f1 /etc/debian_version)" in '
        "8) C=jessie;; 9) C=stretch;; 10) C=buster;; esac; "
        "echo 'Acquire::Check-Valid-Until \"false\";' > /etc/apt/apt.conf.d/99itsuite-snapshot; "
        'case "$C" in '
        f'jessie|stretch|buster) M={old}; S="{old_sec} $C/updates";; '
        f'bullseye) M={old}; S="{old_sec} bullseye-security";; '
        f'*) M={snap}; S="{snap_sec} $C-security";; '
        "esac; "
        "rm -f /etc/apt/sources.list.d/debian.sources; "
        'printf \'deb %s %s main\\ndeb %s main\\n\' "$M" "$C" "$S" > /etc/apt/sources.list; '
        "fi"
    )
    return f"RUN {script}"


def pin_from(line: str, bases: Mapping[str, str]) -> str:
    """FROM image:tag -> FROM image:tag@digest when the image is in the pinned list."""
    match = _FROM_IMAGE.match(line)
    if not match or "@" in match.group(2):
        return line
    image = match.group(2) if ":" in match.group(2) else f"{match.group(2)}:latest"
    digest = bases.get(image)
    return f"{match.group(1)}{image}@{digest}{match.group(3)}" if digest else line


_COPY_FROM = re.compile(r"^(\s*COPY\s+(?:--\S+\s+)*--from=)(\S+)(.*)$", re.IGNORECASE)


def pin_copy_from(line: str, bases: Mapping[str, str]) -> str:
    """COPY --from=image:tag -> --from=image:tag@digest (stage names are left alone)."""
    match = _COPY_FROM.match(line)
    if not match or "@" in match.group(2) or ":" not in match.group(2):
        return line
    digest = bases.get(match.group(2))
    return f"{match.group(1)}{match.group(2)}@{digest}{match.group(3)}" if digest else line


def pin_dockerfile(text: str, timestamp: str, bases: Mapping[str, str] | None = None) -> str:
    """Pin each FROM to its digest and, when ``timestamp`` is set, insert the apt
    snapshot step after every FROM whose stage uses apt."""
    lines = [
        pin_from(line, bases or {}) if _FROM.match(line) else pin_copy_from(line, bases or {})
        for line in text.splitlines()
    ]
    starts = [i for i, line in enumerate(lines) if _FROM.match(line)]
    if not starts:
        return text
    step = snapshot_step(timestamp) if timestamp else ""
    out: list[str] = lines[: starts[0]]
    for n, start in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        stage = lines[start:end]
        uses_apt = bool(step) and any(_USES_APT.search(line) for line in stage)
        out += [stage[0], step, *stage[1:]] if uses_apt else stage
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _dockerfile_path(build: Any, project_dir: Path) -> Path | None:
    if isinstance(build, str):
        return project_dir / build / "Dockerfile"
    if isinstance(build, Mapping) and "dockerfile_inline" not in build:
        context = project_dir / str(build.get("context", "."))
        return context / str(build.get("dockerfile", "Dockerfile"))
    return None


def with_build_pins(
    spec: Mapping[str, Any],
    project_dir: Path,
    timestamp: str,
    bases: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """A new compose spec whose builds use pinned base images and dated apt sources."""
    new = copy.deepcopy(dict(spec))
    for service in (new.get("services") or {}).values():
        build = (service or {}).get("build")
        path = _dockerfile_path(build, project_dir)
        if path is None or not path.is_file():
            continue
        original = path.read_text(encoding="utf-8")
        pinned = pin_dockerfile(original, timestamp, bases)
        if pinned == original:
            continue
        spec_build: dict[str, Any] = (
            {"context": build} if isinstance(build, str) else dict(build or {})
        )
        spec_build.pop("dockerfile", None)
        # Compose interpolates ${VAR} inside dockerfile_inline; $$ keeps every $ literal, so
        # neither the snapshot step nor the target's own lines (RUN echo $FLAG) change.
        service["build"] = {**spec_build, "dockerfile_inline": pinned.replace("$", "$$")}
    return new
