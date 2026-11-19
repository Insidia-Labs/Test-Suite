"""Samsung CredData: labelled candidate lines from real repositories.

``meta/*.csv`` rows give a file, a line range and ``GroundTruth``: ``T`` (a real
credential) or ``F`` (looks like one but isn't). Other values are skipped. The
files themselves come from CredData's own ``download_data.py`` (see the manifest).
"""

from __future__ import annotations

import csv

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location

_LABELS = {"T": True, "F": False}


def _cases_in(text: str, name: str) -> list[Case]:
    cases = []
    for row in csv.DictReader(text.splitlines()):
        label = (row.get("GroundTruth") or "").strip()
        if label not in _LABELS:
            continue
        try:
            start, end = int(row["LineStart"]), int(row["LineEnd"])
        except (KeyError, ValueError) as exc:
            raise KeyBuildError(f"{name}: bad line range in row {row.get('Id')}") from exc
        cases.append(
            Case(
                case_id=f"{row['Id']}",
                positive=_LABELS[label],
                locations=(Location(row["FilePath"], start, end),),
                category=row.get("Category", ""),
            )
        )
    return cases


def build(ctx: KeyContext) -> AnswerKey:
    folder = ctx.src / "meta"
    files = sorted(folder.glob("*.csv")) if folder.is_dir() else []
    if not files:
        raise KeyBuildError(f"{ctx.target_id}: meta/*.csv not found")
    cases = [c for path in files for c in _cases_in(path.read_text(encoding="utf-8"), path.name)]
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="creddata",
        match="location",
        source_commit=ctx.commit,
        cases=tuple(cases),
        task=ctx.task,
        provenance=f"meta/*.csv GroundTruth at {ctx.commit}",
    )


PLUGIN = KeyPlugin("creddata", "location", build)
