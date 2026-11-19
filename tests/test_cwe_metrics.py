from __future__ import annotations

import math

import pytest

from itsuite.cwe import compatible, extract_cwes, parse_cwe, related
from itsuite.matching import CaseOutcome
from itsuite.metrics import Confusion, by_category, mean_youden, pass_at_k, total, wilson


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CWE-079", 79),
        ("external/cwe/cwe-89", 89),
        ("cwe:22", 22),
        ("CWE_798", 798),
        ("B608", None),
    ],
)
def test_parse_cwe_reads_common_spellings(text: str, expected: int | None) -> None:
    assert parse_cwe(text) == expected


def test_extract_cwes_deduplicates_in_order() -> None:
    assert extract_cwes(["CWE-89 and CWE-79", "cwe-089"]) == (89, 79)


def test_related_follows_parent_child_links_only() -> None:
    assert related(89, 564)
    assert related(79, 80)
    assert related(327, 328)  # CWE-328 is ChildOf 327 in CWE 5.0
    assert not related(326, 327)  # siblings under 328's two parents
    assert not related(80, 81)  # siblings under 79
    assert related(943, 564)  # grandparent
    assert not related(89, 79)


def test_compatible_modes() -> None:
    assert compatible((89,), (564,), "family")
    assert not compatible((89,), (564,), "strict")
    assert compatible((89,), (79,), "any")


def test_finding_without_cwe_only_matches_in_any_mode() -> None:
    assert not compatible((89,), (), "family")
    assert compatible((89,), (), "any")
    assert compatible((), (), "strict")  # a case with no CWEs accepts anything


def test_compatible_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="unknown cwe mode"):
        compatible((1,), (1,), "loose")


def test_confusion_metrics_and_undefined_ratios() -> None:
    c = Confusion(tp=8, fp=2, fn=2, tn=8)
    assert c.precision == 0.8 and c.recall == 0.8 and c.fpr == 0.2
    assert math.isclose(c.youden or 0, 0.6)
    assert math.isclose(c.f1 or 0, 0.8)
    empty = Confusion()
    assert empty.precision is None and empty.youden is None and empty.f1 is None


def test_confusion_addition_and_dict() -> None:
    assert Confusion(1, 0, 0, 0) + Confusion(0, 1, 0, 0) == Confusion(1, 1, 0, 0)
    assert Confusion(tp=1).to_dict()["recall"] == 1.0


def test_owasp_style_score_is_mean_of_category_youden() -> None:
    outcomes = [
        CaseOutcome("a1", True, True, "sqli", ()),
        CaseOutcome("a2", False, False, "sqli", ()),  # sqli: TPR 1, FPR 0 -> 1.0
        CaseOutcome("b1", True, True, "xss", ()),
        CaseOutcome("b2", False, True, "xss", ()),  # xss: TPR 1, FPR 1 -> 0.0
    ]
    groups = by_category(outcomes)
    assert mean_youden(groups) == 0.5
    assert total(outcomes) == Confusion(tp=2, fp=1, fn=0, tn=1)


def test_wilson_interval_known_value() -> None:
    low, high = wilson(8, 10) or (0, 0)
    assert math.isclose(low, 0.4902, abs_tol=1e-3)
    assert math.isclose(high, 0.9433, abs_tol=1e-3)
    assert wilson(0, 0) is None
    with pytest.raises(ValueError):
        wilson(5, 3)


def test_pass_at_k() -> None:
    assert pass_at_k(10, 0, 1) == 0.0
    assert pass_at_k(10, 10, 5) == 1.0
    assert math.isclose(pass_at_k(10, 3, 1), 0.3)
    with pytest.raises(ValueError):
        pass_at_k(3, 4, 1)


def test_f1_is_zero_not_missing_when_nothing_is_right() -> None:
    assert Confusion(tp=0, fp=3, fn=2).f1 == 0.0
    assert Confusion(tp=0, fp=0, fn=2).f1 is None  # precision undefined


def test_pass_at_k_rejects_k_above_n() -> None:
    with pytest.raises(ValueError):
        pass_at_k(3, 0, 5)
