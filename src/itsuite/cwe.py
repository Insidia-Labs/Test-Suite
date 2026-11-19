"""CWE parsing and the related-CWE table used by the "family" match mode.

Two CWEs are related when one is an ancestor of the other through ChildOf links in
MITRE's CWE-1000 view (e.g. 564 > 89 > 943). Siblings, which only share a parent
(80 and 81 under 79), are not related. Only the edges below are used; each one was
checked against cwec_v5.0.xml on 2026-11-19, and ``scripts/check_cwe_families.py``
re-checks them against any CWE release. Frozen with the suite; see METHODOLOGY.md 1.2.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

_CWE_RE = re.compile(r"(?i)\bcwe[-_ /:]?0*(\d{1,4})\b")

# child -> parents (ChildOf, CWE-1000 view)
CWE_CHILD_OF: dict[int, tuple[int, ...]] = {
    89: (943,),  # SQL injection < data query logic injection
    564: (89,),  # Hibernate SQL injection
    **{child: (79,) for child in (80, 81, 83, 84, 85, 86, 87)},  # XSS variants
    23: (22,),  # relative path traversal
    36: (22,),  # absolute path traversal
    78: (77,),  # OS command injection < command injection
    88: (77,),  # argument injection
    643: (91,),  # XPath injection < XML injection
    95: (94,),  # eval injection < code injection
    96: (94,),  # static code injection
    338: (330,),  # weak PRNG < insufficient randomness
    259: (798,),  # hard-coded password < hard-coded credentials
    321: (798,),  # hard-coded crypto key
    285: (284,),  # improper authorization < access control
    862: (285,),  # missing authorization
    863: (285,),  # incorrect authorization
    639: (863,),  # user-controlled key (IDOR/BOLA)
    **{child: (200,) for child in (209, 213, 215, 497)},  # information exposure variants
    770: (400,),  # allocation without limits < uncontrolled resource consumption
    1333: (407,),  # ReDoS < inefficient algorithmic complexity
    307: (799,),  # brute force < interaction frequency
    204: (203,),  # response discrepancy < observable discrepancy
    328: (326, 327),  # weak hash < inadequate strength, broken or risky algorithm
}

CWE_MODES = ("strict", "family", "any")


def parse_cwe(text: str) -> int | None:
    """Return the first CWE number in text, e.g. 'CWE-079' -> 79, 'external/cwe/cwe-89' -> 89."""
    match = _CWE_RE.search(text)
    return int(match.group(1)) if match else None


def extract_cwes(values: Iterable[str]) -> tuple[int, ...]:
    """All CWE numbers in values, deduplicated, in first-seen order."""
    seen: list[int] = []
    for value in values:
        for match in _CWE_RE.finditer(value):
            number = int(match.group(1))
            if number not in seen:
                seen.append(number)
    return tuple(seen)


def ancestors(cwe: int) -> frozenset[int]:
    found: set[int] = set()
    todo = [cwe]
    while todo:
        for parent in CWE_CHILD_OF.get(todo.pop(), ()):
            if parent not in found:
                found.add(parent)
                todo.append(parent)
    return frozenset(found)


def related(first: int, second: int) -> bool:
    """Equal, or one is an ancestor of the other."""
    return first == second or first in ancestors(second) or second in ancestors(first)


def compatible(case_cwes: Iterable[int], finding_cwes: Iterable[int], mode: str) -> bool:
    """Whether a finding's CWEs satisfy a case's CWEs under the given mode.

    A case with no CWEs accepts any finding. A finding with no CWE only matches in
    "any" mode, so a tool can't collect hits by leaving CWEs out.
    """
    if mode not in CWE_MODES:
        raise ValueError(f"unknown cwe mode {mode!r}; use one of {CWE_MODES}")
    wanted = tuple(case_cwes)
    reported = tuple(finding_cwes)
    if mode == "any" or not wanted:
        return True
    if mode == "strict":
        return any(cwe in wanted for cwe in reported)
    return any(related(a, b) for a in wanted for b in reported)
