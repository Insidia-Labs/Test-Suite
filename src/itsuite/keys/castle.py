"""CASTLE: one C file per case; the label and CWE are in the file's header comment.

Header lines ``vulnerable: true|false`` and ``cwe: N`` give the label. Vulnerable
lines carry a ``{!LINE}`` comment. Both, and the CWE in the path and file name, are
hidden from the tool's view (see the target's ``view`` block); the scorer maps the
opaque view paths back to these originals.
"""

from __future__ import annotations

import re
from pathlib import Path

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location

_FIELD = re.compile(r"^\s*(vulnerable|cwe)\s*:\s*(\S+)\s*$", re.IGNORECASE)
_LINE_MARK = "{!LINE}"
_HEADER_LINES = 20


def _header(lines: list[str], rel: str) -> tuple[bool, int]:
    fields: dict[str, str] = {}
    for line in lines[:_HEADER_LINES]:
        match = _FIELD.match(line)
        if match:
            fields[match.group(1).lower()] = match.group(2).lower()
    if "vulnerable" not in fields or "cwe" not in fields:
        raise KeyBuildError(f"{rel}: header has no vulnerable/cwe fields")
    if fields["vulnerable"] not in ("true", "false"):
        raise KeyBuildError(f"{rel}: vulnerable must be true or false")
    return fields["vulnerable"] == "true", int(fields["cwe"])


def _case(path: Path, src: Path) -> Case:
    rel = path.relative_to(src).as_posix()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    vulnerable, cwe = _header(lines, rel)
    marked = tuple(
        Location(rel, number, number)
        for number, line in enumerate(lines, start=1)
        if _LINE_MARK in line
    )
    locations = marked if vulnerable and marked else (Location(rel),)
    return Case(path.stem, vulnerable, (cwe,), locations, category=f"CWE-{cwe}")


def build(ctx: KeyContext) -> AnswerKey:
    folder = ctx.src / str(ctx.params.get("dataset_dir", "dataset"))
    files = sorted(folder.rglob("*.c")) if folder.is_dir() else []
    if not files:
        raise KeyBuildError(f"{ctx.target_id}: no .c files under {folder.name}/")
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="castle",
        match="location",
        source_commit=ctx.commit,
        cases=tuple(_case(p, ctx.src) for p in files),
        task=ctx.task,
        provenance=f"CASTLE file headers and {{!LINE}} markers at {ctx.commit}",
    )


PLUGIN = KeyPlugin("castle", "location", build)
