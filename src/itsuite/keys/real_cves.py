"""Real-world CVE sets where each task is a project checkout at a known commit.

* ``cwe-bench-java``: ``data/project_info.csv`` gives the repo, the buggy commit and
  the fix commits; ``data/fix_info.csv`` gives the files and method line ranges the
  fix changed. Vulnerable variant: buggy commit, those methods are positive.
  Patched variant: last fix commit, the same files are file-level negatives.
* ``ossf-cve``: ``CVEs/*.json`` gives the repo, ``prePatch.commit`` with weakness
  locations, and ``postPatch.commit``.

In the patched variant a finding in a fixed file with a related CWE counts as a
false positive. That is coarse on purpose: the methodology reports it as a
file-level control.
"""

from __future__ import annotations

import csv
import json
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


def build_cwe_bench(ctx: KeyContext) -> AnswerKey:
    info = {r["project_slug"]: r for r in _csv(ctx.src / "data" / "project_info.csv")}
    if ctx.task not in info:
        raise KeyBuildError(f"{ctx.target_id}: unknown project {ctx.task!r}")
    rows = [r for r in _csv(ctx.src / "data" / "fix_info.csv") if r["project_slug"] == ctx.task]
    if not rows:
        raise KeyBuildError(f"{ctx.target_id}: no fix_info rows for {ctx.task}")
    patched = ctx.variant.name == _PATCHED
    fixed = (_fix_location(row) for row in rows)
    locations = tuple(dict.fromkeys(Location(loc.path) if patched else loc for loc in fixed))
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
        provenance=f"data/project_info.csv and data/fix_info.csv at {ctx.commit}",
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
    locations = tuple(
        Location(w["file"]) if patched else Location(w["file"], int(w["line"]), int(w["line"]))
        for w in weak
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
