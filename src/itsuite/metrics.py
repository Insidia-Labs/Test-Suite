"""Confusion counts and the metrics built on them. Undefined ratios are None, not 0."""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from itsuite.matching import CaseOutcome

Z_95 = 1.959963984540054


@dataclass(frozen=True)
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def __add__(self, other: Confusion) -> Confusion:
        return Confusion(
            self.tp + other.tp, self.fp + other.fp, self.fn + other.fn, self.tn + other.tn
        )

    @property
    def precision(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float | None:
        return _ratio(self.tp, self.tp + self.fn)

    @property
    def fpr(self) -> float | None:
        return _ratio(self.fp, self.fp + self.tn)

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None:
            return None
        return 0.0 if p + r == 0 else 2 * p * r / (p + r)

    @property
    def youden(self) -> float | None:
        """TPR - FPR: OWASP Benchmark's score. Needs both positives and negatives."""
        r, f = self.recall, self.fpr
        return None if r is None or f is None else r - f

    def to_dict(self) -> dict[str, float | int | None]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": self.precision,
            "recall": self.recall,
            "fpr": self.fpr,
            "f1": self.f1,
            "youden": self.youden,
        }


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def outcome_confusion(outcome: CaseOutcome) -> Confusion:
    if outcome.positive:
        return Confusion(tp=1) if outcome.hit else Confusion(fn=1)
    return Confusion(fp=1) if outcome.hit else Confusion(tn=1)


def total(outcomes: Iterable[CaseOutcome]) -> Confusion:
    return sum((outcome_confusion(o) for o in outcomes), Confusion())


def by_category(outcomes: Iterable[CaseOutcome]) -> dict[str, Confusion]:
    groups: dict[str, Confusion] = {}
    for outcome in outcomes:
        name = outcome.category or "(none)"
        groups[name] = groups.get(name, Confusion()) + outcome_confusion(outcome)
    return dict(sorted(groups.items()))


def mean_youden(groups: Mapping[str, Confusion]) -> float | None:
    """Average of per-category Youden scores, as the OWASP Benchmark scorecard reports."""
    scores = [c.youden for c in groups.values() if c.youden is not None]
    return sum(scores) / len(scores) if scores else None


def wilson(successes: int, trials: int, z: float = Z_95) -> tuple[float, float] | None:
    """Wilson score interval for a proportion; None when there are no trials."""
    if trials <= 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and trials")
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denominator
    return max(0.0, centre - margin), min(1.0, centre + margin)


def pass_at_k(n: int, c: int, k: int) -> float:
    """Unbiased pass@k from n attempts with c successes (Chen et al., 2021)."""
    if not 0 <= c <= n or not 0 < k <= n:
        raise ValueError("need 0 <= c <= n and 0 < k <= n")
    if n - c < k:
        return 1.0
    return 1.0 - math.comb(n - c, k) / math.comb(n, k)
