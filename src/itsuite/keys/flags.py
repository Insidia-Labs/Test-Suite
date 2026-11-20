"""Flag targets: a task is solved when the tool returns the flag.

For XBOW the harness makes a fresh random flag per run and passes it in as the
``FLAG`` build argument, because XBOW's default flag is the SHA-256 of the
benchmark's name and can be computed without solving anything. The flag is sealed
in the answer key; the tool only sees the running app.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Task

_MAX_SCAN_BYTES = 20 * 1024 * 1024


def new_flag() -> str:
    return "FLAG{" + secrets.token_hex(32) + "}"


_PREFIX = re.compile(r"^([A-Za-z0-9_]*\{)")


def rotation(originals: list[str]) -> dict[str, str]:
    """A fresh flag for each published one, same prefix (DVMCP{...}) so format checks in
    the target still pass."""
    rotated = {}
    for original in dict.fromkeys(originals):
        match = _PREFIX.match(original)
        prefix = match.group(1) if match else "FLAG{"
        rotated[original] = f"{prefix}{secrets.token_hex(16)}}}"
    return rotated


_DVMCP_FLAG = re.compile(r'^\s*(\d+)\s*:\s*"(DVMCP\{[^"]+\})"', re.MULTILINE)
DVMCP_FLAGS_FILE = "dashboard/backend/api/routes/submissions.py"


def dvmcp_originals(src: Path) -> list[str]:
    return [flag for _, flag in _dvmcp_table(src)]


def _dvmcp_table(src: Path) -> list[tuple[int, str]]:
    path = src / DVMCP_FLAGS_FILE
    if not path.is_file():
        raise KeyBuildError(f"{DVMCP_FLAGS_FILE} not found")
    table = [(int(n), flag) for n, flag in _DVMCP_FLAG.findall(path.read_text(encoding="utf-8"))]
    if not table:
        raise KeyBuildError(f"no FLAGS table in {DVMCP_FLAGS_FILE}")
    return table


def build_dvmcp(ctx: KeyContext) -> AnswerKey:
    """One case per challenge; the secret is that run's rotated flag."""
    rotated = ctx.params.get("rotation") or {}
    table = _dvmcp_table(ctx.src)
    missing = [flag for _, flag in table if flag not in rotated]
    if missing:
        raise KeyBuildError(f"{ctx.target_id}: the run must rotate every flag")
    cases = tuple(
        Case(
            case_id=f"challenge{n}",
            positive=True,
            secret=str(rotated[flag]),
            category=f"challenge {n}",
        )
        for n, flag in sorted(table)
    )
    return AnswerKey(
        target=ctx.target_id, variant=ctx.variant.name, key_type="dvmcp-flags", match="flag",
        source_commit=ctx.commit, cases=cases, task=ctx.task,
        provenance=f"{DVMCP_FLAGS_FILE} FLAGS at {ctx.commit}; every flag rotated per run",
    )  # fmt: skip


def xbow_tasks(src: Path, params: Mapping[str, Any]) -> list[Task]:
    folder = src / "benchmarks"
    if not folder.is_dir():
        raise KeyBuildError("benchmarks/ not found")
    tasks = []
    for meta in sorted(folder.glob("*/benchmark.json")):
        data = json.loads(meta.read_text(encoding="utf-8"))
        tasks.append(
            Task(
                task_id=meta.parent.name,
                subdir=meta.parent.relative_to(src).as_posix(),
                prompt=str(data.get("description", "")),
            )
        )
    return tasks


def build_xbow(ctx: KeyContext) -> AnswerKey:
    flag = str(ctx.params.get("flag", ""))
    if not flag.startswith("FLAG{"):
        raise KeyBuildError(f"{ctx.target_id}: the run must supply a generated flag")
    meta = ctx.src / "benchmarks" / ctx.task / "benchmark.json"
    if not meta.is_file():
        raise KeyBuildError(f"{ctx.target_id}: unknown benchmark {ctx.task!r}")
    data = json.loads(meta.read_text(encoding="utf-8"))
    case = Case(
        case_id=ctx.task,
        positive=True,
        secret=flag,
        category=f"level {data.get('level', '?')} / {','.join(data.get('tags', []))}",
    )
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="xbow-flag",
        match="flag",
        source_commit=ctx.commit,
        cases=(case,),
        task=ctx.task,
        provenance=f"benchmarks/{ctx.task}/benchmark.json at {ctx.commit}; flag generated per run",
    )


def flag_found(flag: str, paths: list[Path]) -> bool:
    """Whether the exact flag appears in any of the files (tool output and logs)."""
    needle = flag.encode("utf-8")
    for root in paths:
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for path in files:
            with path.open("rb") as handle:
                if needle in handle.read(_MAX_SCAN_BYTES):
                    return True
    return False


XBOW = KeyPlugin("xbow-flag", "flag", build_xbow, xbow_tasks)
DVMCP = KeyPlugin("dvmcp-flags", "flag", build_dvmcp, rotates=dvmcp_originals)
