"""Cross-checks on the whole catalog, beyond what parsing one file can see.

The important one: an evaluation can only claim ``native`` when its answer-key
plugin exists, and ``bridge`` only when its results have an importer. So the
catalog can't overstate what the suite actually scores.
"""

from __future__ import annotations

from pathlib import Path

from itsuite.catalog import Catalog
from itsuite.keys import REGISTRY, UPSTREAM_KEYS
from itsuite.models import Integration, Mode, TargetSpec

LIVE_MODES = frozenset({Mode.DAST, Mode.CTF, Mode.EXPLOIT})


def _target_problems(target: TargetSpec, root: Path) -> list[str]:
    problems = []
    for ev in target.evaluations:
        where = f"{target.id} [{ev.mode.value}]"
        if ev.integration == Integration.NATIVE and ev.key not in REGISTRY:
            problems.append(f"{where}: native, but no answer-key plugin for {ev.key!r}")
        if ev.integration == Integration.BRIDGE and ev.key not in UPSTREAM_KEYS | set(REGISTRY):
            problems.append(f"{where}: bridge, but no importer for {ev.key!r}")
        live = ev.mode in LIVE_MODES and ev.integration == Integration.NATIVE
        if live and target.runtime is None:
            problems.append(f"{where}: live mode needs a runtime block")
        names = [v.name for v in ev.variants]
        if len(names) != len(set(names)):
            problems.append(f"{where}: duplicate variant names")
    runtime = target.runtime
    suite_compose = runtime.compose.removeprefix("suite:") if runtime else ""
    if runtime and runtime.compose.startswith("suite:") and not (root / suite_compose).is_file():
        problems.append(f"{target.id}: {runtime.compose} does not exist")
    if runtime and runtime.setup and not (root / runtime.setup).is_file():
        problems.append(f"{target.id}: setup script {runtime.setup} does not exist")
    return problems


def _profile_problems(catalog: Catalog) -> list[str]:
    problems = []
    for profile in catalog.profiles.values():
        for entry in profile.entries:
            target = catalog.targets.get(entry.target)
            if target is None:
                problems.append(f"profile {profile.id}: unknown target {entry.target}")
                continue
            modes = {ev.mode: ev for ev in target.evaluations}
            if entry.mode not in modes:
                problems.append(f"profile {profile.id}: {entry.target} has no {entry.mode.value}")
                continue
            known = {v.name for v in modes[entry.mode].variants}
            unknown = set(entry.variants) - known
            if unknown:
                problems.append(f"profile {profile.id}: {entry.target} has no variants {unknown}")
    return problems


def validate(catalog: Catalog, root: Path) -> list[str]:
    problems = [p for t in catalog.targets.values() for p in _target_problems(t, root)]
    problems += _profile_problems(catalog)
    for tool in catalog.tools.values():
        if tool.status == "available" and not tool.modes:
            problems.append(f"tool {tool.id}: available but declares no modes")
    return problems
