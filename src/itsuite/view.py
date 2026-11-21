"""Build the copy of a target's source that a tool is allowed to read.

Answer files are left out, in-source answer markers are removed (line numbers stay
the same), and with ``rename: opaque`` file names are replaced by random ones. The
map from view paths back to source paths stays with the harness, never in the view.
Symlinks are skipped so a target can't pull host files into the view.
"""

from __future__ import annotations

import fnmatch
import hashlib
import hmac
import json
import re
import secrets
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from itsuite.models import ViewSpec

# Git metadata, plus instruction files written for AI coding agents. Those steer an
# LLM-based tool (e.g. "this app is intentionally insecure, don't fix bugs") and do
# nothing to a deterministic one, so keeping them would favour one kind of tool.
AGENT_FILES = (
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
    ".ai", ".claude", ".cursor", ".continue", ".junie", ".codeium", ".windsurf",
    ".github/copilot-instructions.md",
)  # fmt: skip
ALWAYS_EXCLUDE = (".git", ".gitmodules", *AGENT_FILES)
_BINARY_PROBE = 8192


@dataclass(frozen=True)
class ViewResult:
    root: Path
    files: int
    excluded: int
    skipped_links: int
    markers_removed: int
    path_map: Mapping[str, str] = field(default_factory=dict)  # view path -> source path


def matches_any(rel: str, patterns: Sequence[str]) -> bool:
    for pattern in patterns:
        base = pattern.rstrip("/")
        if (
            fnmatch.fnmatchcase(rel, base)
            or rel.startswith(base + "/")
            or fnmatch.fnmatchcase(rel, base + "/*")
        ):
            return True
    return False


def _is_text(data: bytes) -> bool:
    if b"\0" in data[:_BINARY_PROBE]:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _strip_line(line: str, patterns: Sequence[re.Pattern[str]]) -> tuple[str, int]:
    body = line.rstrip("\r\n")
    ending = line[len(body) :]
    removed = 0
    for pattern in patterns:
        body, count = pattern.subn("", body)
        removed += count
    return (body.rstrip() + ending if removed else line), removed


def transform_text(text: str, spec: ViewSpec) -> tuple[str, int]:
    """Strip marker patterns line by line; returns (text, markers removed)."""
    strips = [re.compile(p) for p in spec.strip]
    out: list[str] = []
    removed = 0
    for line in text.splitlines(keepends=True):
        new_line, count = _strip_line(line, strips)
        removed += count
        out.append(new_line)
    return "".join(out), removed


def view_salt(folder: Path) -> bytes:
    """A random salt made once per suite cache, so opaque names are the same for every
    tool (same names, same order) but can't be reversed from the public file names."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "view-salt"
    if not path.exists():
        path.write_text(secrets.token_hex(32), encoding="utf-8")
    return bytes.fromhex(path.read_text(encoding="utf-8").strip())


def _view_name(rel: str, spec: ViewSpec, salt: bytes) -> str:
    if spec.rename != "opaque":
        return rel
    suffix = Path(rel).suffix
    if not salt:
        return f"cases/{secrets.token_hex(8)}{suffix}"
    tag = hmac.new(salt, rel.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"cases/{tag}{suffix}"


def _copy_one(path: Path, target: Path, spec: ViewSpec) -> int:
    target.parent.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()
    if not spec.strip or not _is_text(data):
        shutil.copyfile(path, target)
        return 0
    text, removed = transform_text(data.decode("utf-8"), spec)
    target.write_text(text, encoding="utf-8", newline="")
    return removed


def build_view(src: Path, dest: Path, spec: ViewSpec, salt: bytes = b"") -> ViewResult:
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    files = excluded = links = removed = 0
    path_map: dict[str, str] = {}
    for path in sorted(src.rglob("*")):
        rel = path.relative_to(src).as_posix()
        if path.is_symlink():
            links += 1
            continue
        if not path.is_file():
            continue
        hidden = matches_any(rel, (*ALWAYS_EXCLUDE, *spec.exclude))
        if hidden or (spec.include and not matches_any(rel, spec.include)):
            excluded += 1
            continue
        name = _view_name(rel, spec, salt)
        removed += _copy_one(path, dest / name, spec)
        path_map[name] = rel
        files += 1
    return ViewResult(dest, files, excluded, links, removed, path_map)


def save_path_map(result: ViewResult, path: Path) -> None:
    changed = {view: source for view, source in result.path_map.items() if view != source}
    path.write_text(json.dumps(changed, indent=1, sort_keys=True), encoding="utf-8")


def load_path_map(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): str(v) for k, v in data.items()}
