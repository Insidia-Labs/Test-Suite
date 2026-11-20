"""Catalog data types. Every type is frozen: the harness builds new values, never edits."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class CatalogError(ValueError):
    """A manifest is missing a field or has a value the suite cannot use."""


class Level(str, Enum):
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"


class Mode(str, Enum):
    """How a tool meets a target."""

    DAST = "dast"
    SAST = "sast"
    SECRETS = "secrets"
    SCA = "sca"
    IAC = "iac"
    CTF = "ctf"
    AGENT_ATTACK = "agent-attack"
    EXPLOIT = "exploit"
    FIX = "fix"
    PR_REVIEW = "pr-review"


class Integration(str, Enum):
    """How far the suite runs a target by itself."""

    NATIVE = "native"  # fetch, view, key, run and score all done by this harness
    BRIDGE = "bridge"  # the benchmark's own runner and grader; the suite imports results
    PLANNED = "planned"  # pinned and described; no scorer yet


class Contamination(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class OutputFormat(str, Enum):
    SARIF = "sarif"
    TRUFFLEHOG = "trufflehog-jsonl"
    NUCLEI = "nuclei-jsonl"
    UPSTREAM_JSONL = "upstream-jsonl"
    AGENTDOJO = "agentdojo-logs"
    FLAGS = "flags"  # any text the tool writes; the scorer looks for the sealed flag


@dataclass(frozen=True)
class Source:
    kind: str  # "git" or "archive"
    url: str
    commit: str = ""
    ref: str = ""
    sha256: str = ""
    submodules: bool = False


@dataclass(frozen=True)
class Expose:
    service: str
    port: int


@dataclass(frozen=True)
class Runtime:
    """How to start a live target. Paths are relative to the target's source root,
    or to the suite root when they start with ``suite:``."""

    compose: str
    expose: tuple[Expose, ...] = ()
    auto_expose: bool = False
    setup: str = ""
    base_path: str = "/"
    build_args: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ViewSpec:
    """What the tool is allowed to read."""

    exclude: tuple[str, ...] = ()
    include: tuple[str, ...] = ()
    strip: tuple[str, ...] = ()
    rename: str = ""  # "" or "opaque"


@dataclass(frozen=True)
class Variant:
    name: str
    positive: bool | None = None  # None: each case carries its own label
    env: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Evaluation:
    mode: Mode
    key: str
    integration: Integration
    variants: tuple[Variant, ...]
    cwe_mode: str = "family"
    line_tolerance: int = 0
    params: Mapping[str, Any] = field(default_factory=dict)
    notes: str = ""

    def variant(self, name: str) -> Variant:
        for item in self.variants:
            if item.name == name:
                return item
        raise CatalogError(f"no variant {name!r}; have {[v.name for v in self.variants]}")


@dataclass(frozen=True)
class TargetSpec:
    id: str
    name: str
    level: Level
    capabilities: tuple[str, ...]
    source: Source
    license: str
    homepage: str
    contamination: Contamination
    answer_key: str
    evaluations: tuple[Evaluation, ...]
    runtime: Runtime | None = None
    view: ViewSpec = ViewSpec()
    archived: bool = False
    notes: str = ""

    def evaluation(self, mode: Mode) -> Evaluation:
        for item in self.evaluations:
            if item.mode == mode:
                return item
        raise CatalogError(f"{self.id} has no {mode.value} evaluation")


@dataclass(frozen=True)
class ToolMode:
    command: str
    output: OutputFormat
    output_file: str = "results.sarif"


@dataclass(frozen=True)
class Install:
    """How to install a tool at its pinned version into the suite's own cache.

    archive: download ``url`` (checked against ``sha256``) and take ``binary`` from it.
    binary:  download ``url`` (checked) and install it under the name ``binary``.
    pip:     a virtualenv with ``packages`` (exact versions); expose ``binaries``.
    docker:  pull ``image`` (pinned by digest).
    """

    kind: str
    url: str = ""
    sha256: str = ""
    binary: str = ""
    packages: tuple[str, ...] = ()
    binaries: tuple[str, ...] = ()
    image: str = ""


@dataclass(frozen=True)
class ToolSpec:
    id: str
    name: str
    role: str  # "under-test" or "baseline"
    version: str
    source: str
    license: str
    modes: Mapping[Mode, ToolMode]
    status: str = "available"  # or "not-yet-available"
    image: str = ""
    env_passthrough: tuple[str, ...] = ()
    verified: bool = False
    notes: str = ""
    install: Install | None = None


@dataclass(frozen=True)
class ProfileEntry:
    target: str
    mode: Mode
    variants: tuple[str, ...] = ()
    tasks: tuple[str, ...] = ()
    sample: int = 0
    seed: int = 0


@dataclass(frozen=True)
class Profile:
    id: str
    description: str
    wall_seconds: int
    repeat: int
    budget_usd: float
    budget_tokens: int
    entries: tuple[ProfileEntry, ...]
