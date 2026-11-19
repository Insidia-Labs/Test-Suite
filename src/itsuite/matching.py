"""Decide which answer-key case each finding belongs to.

Token keys (OWASP Benchmark, DVWA, documented lists) match a case's token in the
finding's path, URL or logical location. When several cases match, only the most
specific token wins, so a finding on ``/users/v1/login`` doesn't also count for
``/users/v1/{username}``. A ``*`` token matches anywhere and is always a candidate.

Location keys match a finding in the same file whose lines overlap the case's lines
(± tolerance). A case location without lines matches anywhere in that file.

In both, the finding's CWEs must also fit the case's CWEs under the run's CWE mode.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache

from itsuite.cwe import compatible
from itsuite.findings import Finding
from itsuite.keys.base import AnswerKey, Case, Location

WILDCARD = "*"


@dataclass(frozen=True)
class MatchParams:
    cwe_mode: str = "family"
    line_tolerance: int = 0


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    positive: bool
    hit: bool
    category: str
    findings: tuple[int, ...]


@dataclass(frozen=True)
class MatchResult:
    outcomes: tuple[CaseOutcome, ...]
    unmatched: tuple[int, ...]


@lru_cache(maxsize=4096)
def _token_regex(token: str) -> re.Pattern[str]:
    if "{" in token:
        literal_parts = re.split(r"\{[^}/]+\}", token)
        body = "[^/?#\\s]+".join(re.escape(part) for part in literal_parts)
    else:
        body = re.escape(token)
    before = r"(?<![A-Za-z0-9_])" if token[:1].isalnum() or token[:1] == "_" else ""
    after = r"(?![A-Za-z0-9_])" if token[-1:].isalnum() or token[-1:] in "_}" else ""
    return re.compile(before + body + after)


def _specificity(token: str) -> int:
    return len(re.sub(r"\{[^}/]+\}", "", token))


def token_candidates(cases: Sequence[Case], finding: Finding) -> list[int]:
    """Indexes of the cases a finding can belong to, by token alone."""
    text = finding.locator_text()
    scored: list[tuple[int, int]] = []
    wildcard: list[int] = []
    for index, case in enumerate(cases):
        tokens = [loc.token for loc in case.locations if loc.token]
        if WILDCARD in tokens:
            wildcard.append(index)
        hits = [_specificity(t) for t in tokens if t != WILDCARD and _token_regex(t).search(text)]
        if hits:
            scored.append((max(hits), index))
    best = max((score for score, _ in scored), default=-1)
    return [index for score, index in scored if score == best] + wildcard


def normalize_path(path: str, roots: Sequence[str] = ()) -> str:
    clean = path.replace("\\", "/")
    for root in sorted(roots, key=len, reverse=True):
        prefix = root.rstrip("/") + "/"
        if root and clean.startswith(prefix):
            clean = clean[len(prefix) :]
            break
    return clean.lstrip("/").removeprefix("./")


def unresolved_path(path: str, roots: Sequence[str]) -> bool:
    """An absolute path outside every view root: the scorer can't place it, so it can
    only miss. Counted in score.json so a path mix-up doesn't look like low recall."""
    clean = path.replace("\\", "/")
    if not clean.startswith("/"):
        return False
    return not any(r and clean.startswith(r.rstrip("/") + "/") for r in roots)


def same_file(case_path: str, finding_path: str) -> bool:
    """Equal, or the finding's path ends with the case's path (an unstripped prefix).
    A shorter finding path only counts when it still has a folder in it, so a bare
    file name can't match a same-named file somewhere else."""
    a, b = case_path.lstrip("/"), finding_path.lstrip("/")
    if not (a and b):
        return False
    return a == b or b.endswith("/" + a) or ("/" in b and a.endswith("/" + b))


# A finding whose region spans more lines than this is placed at its first line, so one
# file-wide result can't land on every case in the file.
MAX_SPAN = 25


def line_distance(loc: Location, finding: Finding, tolerance: int) -> int | None:
    """0 when the finding's lines overlap the case's lines, the gap in lines when it is
    within the tolerance, None when it is too far. A case without lines matches the file."""
    if loc.start_line is None:
        return 0
    if finding.start_line is None:
        return None
    f_start = finding.start_line
    f_end = finding.end_line or f_start
    if f_end - f_start > MAX_SPAN:
        f_end = f_start
    low, high = loc.start_line, loc.end_line or loc.start_line
    gap = max(low - f_end, f_start - high, 0)
    return gap if gap <= tolerance else None


def location_distance(case: Case, finding: Finding, path: str, tolerance: int) -> int | None:
    distances = [
        d for loc in case.locations
        if same_file(loc.path, path)
        and (d := line_distance(loc, finding, tolerance)) is not None
    ]  # fmt: skip
    return min(distances) if distances else None


def location_hit(case: Case, finding: Finding, path: str, tolerance: int) -> bool:
    return location_distance(case, finding, path, tolerance) is not None


def _assign_token(
    key: AnswerKey, findings: Sequence[Finding], params: MatchParams
) -> list[set[int]]:
    hits: list[set[int]] = [set() for _ in key.cases]
    for f_index, finding in enumerate(findings):
        for c_index in token_candidates(key.cases, finding):
            if compatible(key.cases[c_index].cwes, finding.cwes, params.cwe_mode):
                hits[c_index].add(f_index)
    return hits


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _cases_by_basename(cases: Sequence[Case]) -> dict[str, list[int]]:
    """Index so each finding is only compared with cases in a file of the same name."""
    index: dict[str, list[int]] = {}
    for c_index, case in enumerate(cases):
        for name in dict.fromkeys(_basename(loc.path) for loc in case.locations):
            index.setdefault(name, []).append(c_index)
    return index


def _assign_location(
    key: AnswerKey, findings: Sequence[Finding], params: MatchParams, paths: Sequence[str]
) -> list[set[int]]:
    """Each finding goes to the nearest case(s) it fits; ties (cases on the same line,
    such as Juice Shop challenges that share one vulnerable line) all count."""
    hits: list[set[int]] = [set() for _ in key.cases]
    index = _cases_by_basename(key.cases)
    for f_index, finding in enumerate(findings):
        near: list[tuple[int, int]] = []
        for c_index in index.get(_basename(paths[f_index]), ()):
            case = key.cases[c_index]
            distance = location_distance(case, finding, paths[f_index], params.line_tolerance)
            if distance is not None and compatible(case.cwes, finding.cwes, params.cwe_mode):
                near.append((distance, c_index))
        best = min((d for d, _ in near), default=None)
        for distance, c_index in near:
            if distance == best:
                hits[c_index].add(f_index)
    return hits


def match_findings(
    key: AnswerKey,
    findings: Sequence[Finding],
    params: MatchParams,
    path_map: Mapping[str, str] | None = None,
    roots: Sequence[str] = (),
) -> MatchResult:
    """Match findings to cases. ``path_map`` maps view paths back to source paths."""
    mapping = path_map or {}
    paths = [mapping.get(p, p) for p in (normalize_path(f.path, roots) for f in findings)]
    if key.match == "token":
        hits = _assign_token(key, findings, params)
    elif key.match == "location":
        hits = _assign_location(key, findings, params, paths)
    else:
        raise ValueError(f"{key.match} keys are not scored from findings")
    used = set().union(*hits) if hits else set()
    outcomes = tuple(
        CaseOutcome(c.case_id, c.positive, bool(h), c.category, tuple(sorted(h)))
        for c, h in zip(key.cases, hits, strict=True)
    )
    unmatched = tuple(i for i in range(len(findings)) if i not in used)
    return MatchResult(outcomes, unmatched)
