"""Answer keys: what is true about a target, built from upstream data and sealed."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from itsuite.models import Source, Variant

MATCH_KINDS = ("token", "location", "flag", "challenge")


class KeyBuildError(RuntimeError):
    """An answer key could not be built from the upstream data."""


class SealError(RuntimeError):
    """A sealed answer key changed after it was sealed, or was never sealed."""


@dataclass(frozen=True)
class Location:
    path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    token: str = ""


@dataclass(frozen=True)
class Case:
    case_id: str
    positive: bool
    cwes: tuple[int, ...] = ()
    locations: tuple[Location, ...] = ()
    category: str = ""
    secret: str = ""  # flag value for flag keys; never shown to a tool


@dataclass(frozen=True)
class AnswerKey:
    target: str
    variant: str
    key_type: str
    match: str
    source_commit: str
    cases: tuple[Case, ...]
    task: str = ""
    provenance: str = ""

    @property
    def name(self) -> str:
        task = f"#{self.task}" if self.task else ""
        return f"{self.target}@{self.variant}{task}"


@dataclass(frozen=True)
class Task:
    """One unit of a multi-task target (an XBOW benchmark, a CVE project)."""

    task_id: str
    source: Source | None = None  # None: the target's own source
    patched_source: Source | None = None
    subdir: str = ""
    prompt: str = ""


@dataclass(frozen=True)
class KeyContext:
    target_id: str
    src: Path  # the benchmark's own checkout (metadata lives here)
    variant: Variant
    commit: str
    params: Mapping[str, Any] = field(default_factory=dict)
    task: str = ""


@dataclass(frozen=True)
class KeyPlugin:
    key_type: str
    match: str
    build: Callable[[KeyContext], AnswerKey]
    tasks: Callable[[Path, Mapping[str, Any]], list[Task]] | None = None


def label(variant: Variant, upstream: bool) -> bool:
    """A variant's fixed label wins over the per-case upstream label."""
    return upstream if variant.positive is None else variant.positive


def key_to_dict(key: AnswerKey) -> dict[str, Any]:
    return {
        "target": key.target,
        "variant": key.variant,
        "task": key.task,
        "key_type": key.key_type,
        "match": key.match,
        "source_commit": key.source_commit,
        "provenance": key.provenance,
        "cases": [
            {
                "case_id": c.case_id,
                "positive": c.positive,
                "cwes": list(c.cwes),
                "category": c.category,
                "secret": c.secret,
                "locations": [
                    {
                        "path": loc.path,
                        "start_line": loc.start_line,
                        "end_line": loc.end_line,
                        "token": loc.token,
                    }
                    for loc in c.locations
                ],
            }
            for c in key.cases
        ],
    }


def key_from_dict(data: Mapping[str, Any]) -> AnswerKey:
    cases = tuple(
        Case(
            case_id=c["case_id"],
            positive=bool(c["positive"]),
            cwes=tuple(c["cwes"]),
            category=c.get("category", ""),
            secret=c.get("secret", ""),
            locations=tuple(Location(**loc) for loc in c["locations"]),
        )
        for c in data["cases"]
    )
    return AnswerKey(
        target=data["target"],
        variant=data["variant"],
        key_type=data["key_type"],
        match=data["match"],
        source_commit=data["source_commit"],
        cases=cases,
        task=data.get("task", ""),
        provenance=data.get("provenance", ""),
    )


def digest(key: AnswerKey) -> str:
    canonical = json.dumps(key_to_dict(key), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


class KeyStore:
    """Sealed answer keys on disk, one file per digest, plus a lock of first digests.

    Files are named by their SHA-256, so two runs can never overwrite each other's
    key (flag keys get a new random flag every run). Scoring loads the exact digest
    the run recorded. The lock remembers the first digest sealed for each name; a
    later key with the same name and different content is refused, because a frozen
    answer key must not change between tools. Flag keys are per run and stay out of
    the lock.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.lock_path = root / "keys.lock.json"

    def _lock(self) -> dict[str, str]:
        if not self.lock_path.exists():
            return {}
        data = json.loads(self.lock_path.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in data.items()}

    def _path(self, value: str) -> Path:
        if not _DIGEST_RE.match(value):
            raise SealError(f"not a key digest: {value!r}")
        return self.root / f"{value}.json"

    def seal(self, key: AnswerKey) -> str:
        self.root.mkdir(parents=True, exist_ok=True)
        value = digest(key)
        _write_atomic(self._path(value), json.dumps(key_to_dict(key), indent=1))
        if key.match == "flag":
            return value
        lock = self._lock()
        first = lock.get(key.name)
        if first is not None and first != value:
            raise SealError(
                f"answer key {key.name!r} changed since it was first sealed "
                f"({first[:12]} -> {value[:12]}). If the upstream data or the suite's "
                f"answer files changed on purpose, start a new suite version and delete "
                f"{self.lock_path}."
            )
        if first is None:
            lock[key.name] = value
            _write_atomic(self.lock_path, json.dumps(lock, indent=1, sort_keys=True))
        return value

    def load(self, value: str, name: str = "") -> AnswerKey:
        """The key with this digest; raises if it is missing, altered or misnamed."""
        path = self._path(value)
        if not path.exists():
            raise SealError(f"answer key {value[:12]} was never sealed")
        key = key_from_dict(json.loads(path.read_text(encoding="utf-8")))
        if digest(key) != value:
            raise SealError(f"answer key {value[:12]} changed after it was sealed")
        if name and key.name != name:
            raise SealError(f"answer key {value[:12]} is {key.name!r}, not {name!r}")
        return key
