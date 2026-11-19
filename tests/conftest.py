"""Shared test helpers. Fixtures mimic upstream file formats checked at the pinned commits."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from itsuite.keys.base import KeyContext
from itsuite.models import Variant

SUITE_ROOT = Path(__file__).resolve().parents[1]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "docker: needs a Docker daemon and network (opt-in)")


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def ctx_for(tmp_path: Path) -> Callable[..., KeyContext]:
    def make(
        variant: str = "default", positive: bool | None = None, task: str = "", **params: Any
    ) -> KeyContext:
        return KeyContext("t", tmp_path, Variant(variant, positive), "c" * 40, params, task)

    return make


def sarif(results: list[dict[str, Any]], rules: list[dict[str, Any]] | None = None) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {"tool": {"driver": {"name": "fake", "rules": rules or []}}, "results": results}
            ],
        }
    )


def result(
    rule: str, path: str = "", line: int | None = None, url: str = "", tags: list[str] | None = None
) -> dict[str, Any]:
    location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": url or path}}}
    if line is not None:
        location["physicalLocation"]["region"] = {"startLine": line}
    return {
        "ruleId": rule,
        "message": {"text": rule},
        "locations": [location],
        "properties": {"tags": tags or []},
    }
