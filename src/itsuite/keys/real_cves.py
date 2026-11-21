"""Real-world CVE sets where each task is a project checkout at a known commit.

* ``cwe-bench-java``: ``data/project_info.csv`` gives the repo, the buggy commit and
  the fix commits; ``data/fix_info.csv`` gives the files and methods the fix changed.
  Its line numbers mix buggy-commit and fix-commit coordinates (checked on
  2026-11-20), and it lists test methods the fix added, so test files are dropped and
  each method is found by name in the scanned checkout. Vulnerable variant: buggy
  commit, those methods are positive.
  Patched variant: last fix commit, the same methods (found by name there) are negatives.
* ``ossf-cve``: ``CVEs/*.json`` gives the repo, ``prePatch.commit`` with weakness
  locations, and ``postPatch.commit``. Patched variant: the weakness line ±10 lines
  (the patch shifts lines and OSSF gives no post-patch line) is the negative region.

A finding elsewhere in a fixed file is left unmatched (adjudication), not counted
against the tool.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from itsuite.keys.base import (
    AnswerKey,
    Case,
    KeyBuildError,
    KeyContext,
    KeyPlugin,
    Location,
    Task,
)
from itsuite.models import Source

_PATCHED = "patched"
PATCHED_WINDOW = 10


def _csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise KeyBuildError(f"{path.name} not found")
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _git(url: str, commit: str) -> Source:
    clean = url.removesuffix("/")
    return Source("git", clean if clean.endswith(".git") else clean + ".git", commit)


def _int(value: str) -> int | None:
    return int(value) if value.strip().isdigit() else None


def cwe_bench_tasks(src: Path, params: Mapping[str, Any]) -> list[Task]:
    tasks = []
    for row in _csv(src / "data" / "project_info.csv"):
        fixes = [c for c in row["fix_commit_ids"].split(";") if c.strip()]
        tasks.append(
            Task(
                task_id=row["project_slug"],
                source=_git(row["github_url"], row["buggy_commit_id"]),
                patched_source=_git(row["github_url"], fixes[-1]) if fixes else None,
            )
        )
    return tasks


def _fix_location(row: dict[str, str]) -> Location:
    start = _int(row.get("method_start", "")) or _int(row.get("class_start", ""))
    end = _int(row.get("method_end", "")) or _int(row.get("class_end", ""))
    return Location(row["file"], start, end)


def is_test_file(path: str) -> bool:
    """Tests the fix added or changed aren't vulnerable code."""
    name = path.rsplit("/", 1)[-1]
    return "/src/test/" in f"/{path}" or name.endswith(("Test.java", "Tests.java", "IT.java"))


def _declaration_lines(text: list[str], method: str) -> list[int]:
    call = re.compile(rf"\b{re.escape(method)}\s*\(")
    return [
        number
        for number, line in enumerate(text, start=1)
        if call.search(line) and not line.strip().endswith(";") and "." + method not in line
    ]


def relocate(loc: Location, method: str, checkout: Path | None) -> Location:
    """fix_info.csv mixes buggy-commit and fix-commit line numbers, so find the method
    by name in the checkout being scanned: the declaration nearest the listed line,
    keeping the listed span. Without a checkout, or a match, the listed range stays."""
    if checkout is None or not method or loc.start_line is None:
        return loc
    path = checkout / loc.path
    if not path.is_file():
        return loc
    found = _declaration_lines(path.read_text(encoding="utf-8", errors="replace").splitlines(),
                               method)  # fmt: skip
    if not found:
        return loc
    start = min(found, key=lambda n: abs(n - (loc.start_line or 0)))
    span = (loc.end_line or loc.start_line) - loc.start_line
    return Location(loc.path, start, start + span)


def _positive_locations(rows: list[dict[str, str]], checkout: Path | None) -> tuple[Location, ...]:
    code = [r for r in rows if not is_test_file(r["file"])] or rows
    return tuple(
        dict.fromkeys(relocate(_fix_location(r), r.get("method", ""), checkout) for r in code)
    )


def build_cwe_bench(ctx: KeyContext) -> AnswerKey:
    info = {r["project_slug"]: r for r in _csv(ctx.src / "data" / "project_info.csv")}
    if ctx.task not in info:
        raise KeyBuildError(f"{ctx.target_id}: unknown project {ctx.task!r}")
    rows = [r for r in _csv(ctx.src / "data" / "fix_info.csv") if r["project_slug"] == ctx.task]
    if not rows:
        raise KeyBuildError(f"{ctx.target_id}: no fix_info rows for {ctx.task}")
    patched = ctx.variant.name == _PATCHED
    # Both variants find the fixed methods by name in the checkout being scanned, so the
    # patched control covers the fixed code only, not unrelated findings elsewhere in the
    # same file.
    locations = _positive_locations(rows, ctx.task_src)
    project = info[ctx.task]
    case = Case(
        case_id=project["cve_id"],
        positive=not patched,
        cwes=(int(project["cwe_id"].upper().removeprefix("CWE-")),),
        locations=locations,
        category=project["cwe_id"],
    )
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="cwe-bench-java",
        match="location",
        source_commit=ctx.commit,
        cases=(case,),
        task=ctx.task,
        provenance=(
            f"data/project_info.csv and data/fix_info.csv at {ctx.commit}; test files dropped, "
            "methods located by name in the scanned checkout"
        ),
    )


def _ossf_records(src: Path) -> dict[str, dict[str, Any]]:
    folder = src / "CVEs"
    if not folder.is_dir():
        raise KeyBuildError("CVEs/ not found")
    records = {}
    for path in sorted(folder.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("state", "PUBLISHED") == "PUBLISHED":
            records[str(data["CVE"])] = data
    return records


def ossf_tasks(src: Path, params: Mapping[str, Any]) -> list[Task]:
    return [
        Task(
            task_id=cve,
            source=_git(data["repository"], data["prePatch"]["commit"]),
            patched_source=_git(data["repository"], data["postPatch"]["commit"]),
        )
        for cve, data in _ossf_records(src).items()
    ]


def build_ossf(ctx: KeyContext) -> AnswerKey:
    records = _ossf_records(ctx.src)
    if ctx.task not in records:
        raise KeyBuildError(f"{ctx.target_id}: unknown CVE {ctx.task!r}")
    data = records[ctx.task]
    patched = ctx.variant.name == _PATCHED
    weak = [w["location"] for w in data["prePatch"].get("weaknesses", [])]
    # OSSF gives no post-patch line, so the patched control is the pre-patch line with a
    # window for the lines the patch shifted.
    window = int(ctx.params.get("patched_window", PATCHED_WINDOW)) if patched else 0
    locations = tuple(
        Location(w["file"], max(1, int(w["line"]) - window), int(w["line"]) + window) for w in weak
    )
    cwes = tuple(int(str(c).upper().removeprefix("CWE-")) for c in data.get("CWEs", []))
    case = Case(
        case_id=ctx.task,
        positive=not patched,
        cwes=cwes,
        locations=tuple(dict.fromkeys(locations)),
        category=",".join(f"CWE-{c}" for c in cwes),
    )
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="ossf-cve",
        match="location",
        source_commit=ctx.commit,
        cases=(case,),
        task=ctx.task,
        provenance=f"CVEs/{ctx.task}.json at {ctx.commit}",
    )


CWE_BENCH_JAVA = KeyPlugin("cwe-bench-java", "location", build_cwe_bench, cwe_bench_tasks)
OSSF_CVE = KeyPlugin("ossf-cve", "location", build_ossf, ossf_tasks)
