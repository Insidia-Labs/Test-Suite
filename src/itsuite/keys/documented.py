"""Documented vulnerability lists, transcribed from a target's own docs.

The list lives in the suite (``targets/<id>/answer_key.yaml``) because upstream
publishes it as prose. Every item must cite where upstream documents it, and an
item can only be a clean control when upstream's own switch turns it off
(``toggled: true``). Format::

    source: https://github.com/... (README "List of Vulnerabilities")
    items:
      - id: sqli
        title: SQL injection
        cwes: [89]
        tokens: ["/users/v1/{username}"]   # "*" = anywhere in the app
        toggled: true
        evidence: models/user_model.py `if vuln:  # SQLi Injection`
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from itsuite.keys.base import AnswerKey, Case, KeyBuildError, KeyContext, KeyPlugin, Location


def _item_case(item: dict[str, Any], positive_variant: bool | None, ctx: str) -> Case | None:
    for field in ("id", "title", "cwes", "tokens", "evidence"):
        if field not in item:
            raise KeyBuildError(f"{ctx}: item {item.get('id', '?')} is missing {field!r}")
    toggled = bool(item.get("toggled", False))
    if positive_variant is False and not toggled:
        return None  # still vulnerable in the clean variant: not a usable control
    return Case(
        case_id=str(item["id"]),
        positive=True if positive_variant is None else positive_variant,
        cwes=tuple(int(c) for c in item["cwes"]),
        category=str(item["title"]),
        locations=tuple(Location(token=str(t)) for t in item["tokens"]),
    )


def build(ctx: KeyContext) -> AnswerKey:
    path = Path(str(ctx.params.get("items", "")))
    if not path.is_file():
        raise KeyBuildError(f"{ctx.target_id}: documented list {path} not found")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not data.get("source"):
        raise KeyBuildError(f"{path.name}: 'source' (the upstream document) is required")
    built = (_item_case(item, ctx.variant.positive, path.name) for item in data.get("items", []))
    cases = tuple(case for case in built if case is not None)
    if not cases:
        raise KeyBuildError(f"{path.name}: no usable items for variant {ctx.variant.name}")
    return AnswerKey(
        target=ctx.target_id,
        variant=ctx.variant.name,
        key_type="documented-list",
        match="token",
        source_commit=ctx.commit,
        cases=cases,
        task=ctx.task,
        provenance=f"{data['source']} (transcribed in {path.name})",
    )


PLUGIN = KeyPlugin("documented-list", "token", build)
