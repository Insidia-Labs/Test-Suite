"""OWASP Benchmark (Java and Python): expectedresults-*.csv.

Each row is one test case: name, category, real vulnerability (true/false), CWE.
A finding belongs to a case when the case name (BenchmarkTest00001) appears in the
finding's file path, URL or logical location, which is how the upstream scorecard
assigns results too.
"""

from __future__ import annotations

import csv

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location


def _rows(text: str) -> list[list[str]]:
    lines = [line for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return [row for row in csv.reader(lines) if row]


def build(ctx: KeyContext) -> AnswerKey:
    name = str(ctx.params.get("expected_results", ""))
    if not name:
        raise KeyBuildError(f"{ctx.target_id}: params.expected_results is required")
    path = ctx.src / name
    if not path.exists():
        raise KeyBuildError(f"{ctx.target_id}: {name} not found in the checkout")
    cases = []
    for row in _rows(path.read_text(encoding="utf-8")):
        if len(row) < 4:
            raise KeyBuildError(f"{name}: expected 4 columns, got {row!r}")
        test, category, real, cwe = (cell.strip() for cell in row[:4])
        cases.append(
            Case(
                case_id=test,
                positive=real.lower() == "true",
                cwes=(int(cwe),),
                category=category,
                locations=(Location(token=test),),
            )
        )
    if not cases:
        raise KeyBuildError(f"{name}: no test cases")
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="owasp-benchmark",
        match="token",
        source_commit=ctx.commit,
        cases=tuple(cases),
        task=ctx.task,
        provenance=f"{name} at {ctx.commit}",
    )


PLUGIN = KeyPlugin("owasp-benchmark", "token", build)
