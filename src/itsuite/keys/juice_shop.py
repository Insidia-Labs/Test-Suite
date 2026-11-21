"""OWASP Juice Shop: two answer keys from upstream data.

* ``juice-shop-markers`` (source): Juice Shop marks the vulnerable lines of its
  coding challenges with ``vuln-code-snippet vuln-line <challengeKey...>``
  comments. Each challenge key becomes one positive case at those lines.
* ``juice-shop-challenges`` (live): ``data/static/challenges.yml`` lists every
  challenge. The app marks a challenge solved when someone actually exploits it, so
  the score is the set of challenges solved during the tool's run, read from the
  app's ``/api/Challenges`` endpoint before and after.
"""

from __future__ import annotations

import json
import re
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location

_MARKER = re.compile(r"vuln-code-snippet\s+vuln-line\s+([A-Za-z0-9 ]+?)\s*(?:-->|\*/|$)")
_SKIP_DIRS = {"node_modules", ".git", "test", "codefixes", "dist", "build", ".angular"}
_SUFFIXES = {".ts", ".js", ".html", ".yml", ".yaml", ".sol", ".py"}
DEFAULT_ROOTS = (
    "routes",
    "lib",
    "models",
    "server.ts",
    "frontend/src",
    "data/static/web3-snippets",
)


def _source_files(src: Path, roots: tuple[str, ...]) -> Iterator[Path]:
    for root in roots:
        start = src / root
        if start.is_file():
            yield start
            continue
        for path in sorted(start.rglob("*")) if start.is_dir() else ():
            if path.is_file() and path.suffix in _SUFFIXES and not _SKIP_DIRS & set(path.parts):
                yield path


def _marked_lines(src: Path, roots: tuple[str, ...]) -> dict[str, list[Location]]:
    found: dict[str, list[Location]] = {}
    for path in _source_files(src, roots):
        rel = path.relative_to(src).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for number, line in enumerate(text.splitlines(), start=1):
            match = _MARKER.search(line)
            if not match:
                continue
            for challenge in match.group(1).split():
                found.setdefault(challenge, []).append(Location(rel, number, number))
    return found


def build_markers(ctx: KeyContext) -> AnswerKey:
    roots = tuple(ctx.params.get("roots", DEFAULT_ROOTS))
    found = _marked_lines(ctx.src, roots)
    if not found:
        raise KeyBuildError(f"{ctx.target_id}: no vuln-line markers under {roots}")
    cases = tuple(
        Case(case_id=challenge, positive=True, locations=tuple(locations))
        for challenge, locations in sorted(found.items())
    )
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="juice-shop-markers",
        match="location",
        source_commit=ctx.commit,
        cases=cases,
        task=ctx.task,
        provenance=f"vuln-code-snippet markers under {', '.join(roots)} at {ctx.commit}",
    )


def _disabled(entry: dict[str, Any], environment: str) -> bool:
    disabled = entry.get("disabledEnv") or []
    if isinstance(disabled, str):
        disabled = [disabled]
    return environment in disabled


def build_challenges(ctx: KeyContext) -> AnswerKey:
    path = ctx.src / "data" / "static" / "challenges.yml"
    if not path.exists():
        raise KeyBuildError(f"{ctx.target_id}: data/static/challenges.yml not found")
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    environment = str(ctx.params.get("environment", "Docker"))
    cases = tuple(
        Case(
            case_id=str(entry["key"]),
            positive=True,
            category=f"{entry.get('category', '')} / difficulty {entry.get('difficulty', '?')}",
        )
        for entry in entries
        if "key" in entry and not _disabled(entry, environment)
    )
    if not cases:
        raise KeyBuildError(f"{ctx.target_id}: challenges.yml has no challenges")
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="juice-shop-challenges",
        match="challenge",
        source_commit=ctx.commit,
        cases=cases,
        task=ctx.task,
        provenance=f"challenges.yml at {ctx.commit}, minus those disabled in {environment}",
    )


def parse_solved(payload: dict[str, Any]) -> frozenset[str]:
    """The solved challenge keys in a /api/Challenges response."""
    rows = payload.get("data")
    if not isinstance(rows, list):
        raise ValueError("unexpected /api/Challenges response: no data list")
    return frozenset(str(row["key"]) for row in rows if row.get("solved") is True)


def fetch_solved(base_url: str, timeout: float = 15.0) -> frozenset[str]:
    url = base_url.rstrip("/") + "/api/Challenges/"
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("challenge snapshots only read from the local gateway")
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return parse_solved(json.loads(response.read().decode("utf-8")))


MARKERS = KeyPlugin("juice-shop-markers", "location", build_markers)
CHALLENGES = KeyPlugin("juice-shop-challenges", "challenge", build_challenges)
