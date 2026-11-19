"""Load and validate the YAML catalog: targets, tools and profiles."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import yaml

from itsuite.cwe import CWE_MODES
from itsuite.models import (
    CatalogError,
    Contamination,
    Evaluation,
    Expose,
    Install,
    Integration,
    Level,
    Mode,
    OutputFormat,
    Profile,
    ProfileEntry,
    Runtime,
    Source,
    TargetSpec,
    ToolMode,
    ToolSpec,
    Variant,
    ViewSpec,
)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_VARIANT = Variant(name="default")

E = TypeVar("E")


def _field(data: Mapping[str, Any], key: str, ctx: str) -> Any:
    if key not in data or data[key] in (None, ""):
        raise CatalogError(f"{ctx}: missing {key!r}")
    return data[key]


def _enum(kind: Callable[[str], E], value: Any, ctx: str) -> E:
    try:
        return kind(str(value))
    except ValueError as exc:
        raise CatalogError(f"{ctx}: bad value {value!r}") from exc


def _strings(data: Mapping[str, Any], key: str) -> tuple[str, ...]:
    value = data.get(key) or ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _str_map(value: Any, ctx: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CatalogError(f"{ctx}: expected a mapping")
    return {str(k): str(v) for k, v in value.items()}


def parse_source(data: Mapping[str, Any], ctx: str) -> Source:
    kind = str(_field(data, "kind", ctx))
    url = str(_field(data, "url", ctx))
    if kind == "git":
        commit = str(_field(data, "commit", ctx))
        if not SHA1_RE.match(commit):
            raise CatalogError(f"{ctx}: commit must be a full 40-character SHA, got {commit!r}")
        return Source(
            "git", url, commit, str(data.get("ref", "")), "", bool(data.get("submodules"))
        )
    if kind == "archive":
        digest = str(_field(data, "sha256", ctx))
        if not SHA256_RE.match(digest):
            raise CatalogError(f"{ctx}: sha256 must be 64 hex characters")
        return Source("archive", url, "", str(data.get("ref", "")), digest)
    raise CatalogError(f"{ctx}: source kind must be git or archive, got {kind!r}")


def parse_view(data: Mapping[str, Any] | None, ctx: str) -> ViewSpec:
    if not data:
        return ViewSpec()
    for pattern in _strings(data, "strip"):
        try:
            re.compile(pattern)
        except re.error as exc:
            raise CatalogError(f"{ctx}: bad regex {pattern!r}: {exc}") from exc
    rename = str(data.get("rename", ""))
    if rename not in ("", "opaque"):
        raise CatalogError(f"{ctx}: rename must be empty or 'opaque'")
    return ViewSpec(
        _strings(data, "exclude"), _strings(data, "include"), _strings(data, "strip"), rename
    )


def parse_runtime(data: Mapping[str, Any] | None, ctx: str) -> Runtime | None:
    if not data:
        return None
    expose_raw = data.get("expose", ())
    auto = expose_raw == "auto"
    exposes = (
        ()
        if auto
        else tuple(
            Expose(str(_field(e, "service", ctx)), int(_field(e, "port", ctx))) for e in expose_raw
        )
    )
    return Runtime(
        compose=str(_field(data, "compose", ctx)),
        expose=exposes,
        auto_expose=auto,
        setup=str(data.get("setup", "")),
        base_path=str(data.get("base_path", "/")),
        build_args=_str_map(data.get("build_args"), ctx),
    )


def parse_variant(item: Any, ctx: str) -> Variant:
    if isinstance(item, str):
        return Variant(name=item)
    name = str(_field(item, "name", ctx))
    positive = item.get("positive")
    if positive is not None and not isinstance(positive, bool):
        raise CatalogError(f"{ctx}: variant {name}: positive must be true, false or absent")
    return Variant(name, positive, _str_map(item.get("env"), ctx))


def parse_evaluation(data: Mapping[str, Any], ctx: str) -> Evaluation:
    mode = _enum(Mode, _field(data, "mode", ctx), ctx)
    ctx = f"{ctx} [{mode.value}]"
    variants = tuple(parse_variant(v, ctx) for v in data.get("variants") or ()) or (
        DEFAULT_VARIANT,
    )
    cwe_mode = str(data.get("cwe_mode", "family"))
    if cwe_mode not in CWE_MODES:
        raise CatalogError(f"{ctx}: cwe_mode must be one of {CWE_MODES}")
    return Evaluation(
        mode=mode,
        key=str(_field(data, "key", ctx)),
        integration=_enum(Integration, _field(data, "integration", ctx), ctx),
        variants=variants,
        cwe_mode=cwe_mode,
        line_tolerance=int(data.get("line_tolerance", 0)),
        params=dict(data.get("params") or {}),
        notes=str(data.get("notes", "")),
    )


def parse_target(data: Mapping[str, Any], ctx: str) -> TargetSpec:
    target_id = str(_field(data, "id", ctx))
    if not ID_RE.match(target_id):
        raise CatalogError(f"{ctx}: id must be lowercase kebab-case")
    evaluations = tuple(parse_evaluation(e, ctx) for e in _field(data, "evaluations", ctx))
    return TargetSpec(
        id=target_id,
        name=str(_field(data, "name", ctx)),
        level=_enum(Level, _field(data, "level", ctx), ctx),
        capabilities=_strings(data, "capabilities"),
        source=parse_source(_field(data, "source", ctx), ctx),
        license=str(_field(data, "license", ctx)),
        homepage=str(data.get("homepage", "")),
        contamination=_enum(Contamination, _field(data, "contamination", ctx), ctx),
        answer_key=str(_field(data, "answer_key", ctx)),
        evaluations=evaluations,
        runtime=parse_runtime(data.get("runtime"), ctx),
        view=parse_view(data.get("view"), ctx),
        archived=bool(data.get("archived", False)),
        notes=str(data.get("notes", "")),
    )


def parse_tool_mode(data: Mapping[str, Any], ctx: str) -> ToolMode:
    output = _enum(OutputFormat, _field(data, "output", ctx), ctx)
    return ToolMode(
        str(_field(data, "command", ctx)), output, str(data.get("output_file", "results.sarif"))
    )


INSTALL_KINDS = ("archive", "binary", "pip", "docker")


def parse_install(data: Mapping[str, Any] | None, ctx: str) -> Install | None:
    if not data:
        return None
    kind = str(_field(data, "kind", ctx))
    if kind not in INSTALL_KINDS:
        raise CatalogError(f"{ctx}: install kind must be one of {INSTALL_KINDS}")
    install = Install(
        kind=kind, url=str(data.get("url", "")), sha256=str(data.get("sha256", "")),
        binary=str(data.get("binary", "")), packages=_strings(data, "packages"),
        binaries=_strings(data, "binaries"), image=str(data.get("image", "")),
    )  # fmt: skip
    if kind in ("archive", "binary"):
        if not install.url.startswith("https://") or not SHA256_RE.match(install.sha256):
            raise CatalogError(f"{ctx}: {kind} installs need an https url and a sha256")
        if not install.binary:
            raise CatalogError(f"{ctx}: {kind} installs need a binary name")
    if kind == "pip" and not all("==" in p or "@" in p for p in install.packages):
        raise CatalogError(f"{ctx}: pip packages must be pinned (name==version or name @ url)")
    if kind == "docker" and "@sha256:" not in install.image:
        raise CatalogError(f"{ctx}: docker installs must pin the image by digest")
    return install


def parse_tool(data: Mapping[str, Any], ctx: str) -> ToolSpec:
    tool_id = str(_field(data, "id", ctx))
    if not ID_RE.match(tool_id):
        raise CatalogError(f"{ctx}: id must be lowercase kebab-case")
    role = str(_field(data, "role", ctx))
    if role not in ("under-test", "baseline"):
        raise CatalogError(f"{ctx}: role must be under-test or baseline")
    modes = {
        _enum(Mode, name, ctx): parse_tool_mode(spec, f"{ctx} [{name}]")
        for name, spec in (data.get("modes") or {}).items()
    }
    status = str(data.get("status", "available"))
    if status not in ("available", "not-yet-available"):
        raise CatalogError(f"{ctx}: status must be available or not-yet-available")
    return ToolSpec(
        id=tool_id,
        name=str(_field(data, "name", ctx)),
        role=role,
        version=str(_field(data, "version", ctx)),
        source=str(_field(data, "source", ctx)),
        license=str(_field(data, "license", ctx)),
        modes=modes,
        status=status,
        image=str(data.get("image", "")),
        env_passthrough=_strings(data, "env_passthrough"),
        verified=bool(data.get("verified", False)),
        notes=str(data.get("notes", "")),
        install=parse_install(data.get("install"), f"{ctx} [install]"),
    )


def parse_profile(data: Mapping[str, Any], ctx: str) -> Profile:
    entries = tuple(
        ProfileEntry(
            target=str(_field(e, "target", ctx)),
            mode=_enum(Mode, _field(e, "mode", ctx), ctx),
            variants=_strings(e, "variants"),
            tasks=_strings(e, "tasks"),
            sample=int(e.get("sample", 0)),
            seed=int(e.get("seed", 0)),
        )
        for e in _field(data, "entries", ctx)
    )
    return Profile(
        id=str(_field(data, "id", ctx)),
        description=str(_field(data, "description", ctx)),
        wall_seconds=int(_field(data, "wall_seconds", ctx)),
        repeat=int(data.get("repeat", 1)),
        budget_usd=float(data.get("budget_usd", 0)),
        budget_tokens=int(data.get("budget_tokens", 0)),
        entries=entries,
    )


@dataclass(frozen=True)
class Catalog:
    targets: Mapping[str, TargetSpec]
    tools: Mapping[str, ToolSpec]
    profiles: Mapping[str, Profile]


def _load_dir(folder: Path, parse: Callable[[Mapping[str, Any], str], E]) -> dict[str, E]:
    items: dict[str, E] = {}
    for path in sorted(folder.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping):
            raise CatalogError(f"{path.name}: expected a mapping at the top level")
        item = parse(data, path.name)
        item_id = getattr(item, "id")  # noqa: B009 - every catalog type has an id
        if path.stem != item_id:
            raise CatalogError(f"{path.name}: file name must match id {item_id!r}")
        items[item_id] = item
    return items


def load_catalog(root: Path) -> Catalog:
    return Catalog(
        targets=_load_dir(root / "catalog" / "targets", parse_target),
        tools=_load_dir(root / "catalog" / "tools", parse_tool),
        profiles=_load_dir(root / "profiles", parse_profile),
    )
