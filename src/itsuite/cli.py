"""Command line: ``itsuite <command>``. Exit codes: 0 ok, 1 problems found, 2 usage error."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from itsuite import (
    FREEZE_DATE,
    __version__,
    adapter_check,
    adjudication,
    images,
    live,
    lock,
    model_server,
    profile_runner,
    scorecard,
    tools,
)
from itsuite import prepare as prepare_step
from itsuite.catalog import Catalog, load_catalog
from itsuite.fetch import FetchError, fetch
from itsuite.keys import REGISTRY
from itsuite.keys.base import KeyBuildError, SealError
from itsuite.models import CatalogError, Integration, Mode, Profile
from itsuite.orchestrate import RunError, RunRequest, SuitePaths, docker_available
from itsuite.orchestrate import run as run_one
from itsuite.report import load_scores, markdown
from itsuite.scoring import score_run
from itsuite.upstream import import_agentdojo, import_jsonl, summarize
from itsuite.validate import validate


def find_root(start: Path) -> Path:
    env = os.environ.get("ITS_ROOT")
    if env:
        return Path(env).resolve()
    for folder in (start, *start.parents):
        if (folder / "catalog" / "targets").is_dir():
            return folder
    raise CatalogError("not inside the suite (no catalog/targets); set ITS_ROOT")


def _print_table(rows: Sequence[Sequence[str]]) -> None:
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    for r in rows:
        print("  ".join(cell.ljust(w) for cell, w in zip(r, widths, strict=True)).rstrip())


def cmd_list(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    rows = [["id", "level", "modes", "integration", "contamination", "license"]]
    for target in sorted(catalog.targets.values(), key=lambda t: (t.level.value, t.id)):
        evs = [e for e in target.evaluations if not args.mode or e.mode.value == args.mode]
        if (args.level and target.level.value != args.level) or not evs:
            continue
        rows.append(
            [
                target.id,
                target.level.value,
                ",".join(e.mode.value for e in evs),
                ",".join(sorted({e.integration.value for e in evs})),
                target.contamination.value,
                target.license,
            ]
        )
    _print_table(rows)
    print(f"\n{len(rows) - 1} targets")
    return 0


def cmd_validate(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    problems = validate(catalog, paths.root)
    for problem in problems:
        print(f"problem: {problem}")
    counts = {i.value: 0 for i in Integration}
    for target in catalog.targets.values():
        for ev in target.evaluations:
            counts[ev.integration.value] += 1
    print(
        f"{len(catalog.targets)} targets, {len(catalog.tools)} tools, "
        f"{len(catalog.profiles)} profiles; evaluations: "
        + ", ".join(f"{n} {k}" for k, n in counts.items())
    )
    return 1 if problems else 0


def cmd_fetch(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    ids = list(catalog.targets) if args.target == "all" else [args.target]
    failed = 0
    for target_id in ids:
        target = catalog.targets[target_id]
        try:
            dest = fetch(target.source, paths.source_dir(target.source))
            print(f"{target_id}: {dest}")
        except FetchError as exc:
            failed += 1
            print(f"{target_id}: FAILED {exc}", file=sys.stderr)
    return 1 if failed else 0


def _request(args: argparse.Namespace, catalog: Catalog, profile: Profile | None) -> RunRequest:
    tool = catalog.tools[args.tool]
    if tool.status != "available":
        raise RunError(f"{tool.id} is {tool.status}; see catalog/tools/{tool.id}.yaml")
    return RunRequest(
        tool=tool,
        target=catalog.targets[args.target],
        mode=Mode(args.mode),
        variant=args.variant,
        task=args.task or "",
        wall_seconds=profile.wall_seconds if profile else args.timeout,
        budget_usd=profile.budget_usd if profile else 0.0,
        budget_tokens=profile.budget_tokens if profile else 0,
        container=args.container,
    )


def cmd_run(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    request = _request(args, catalog, None)
    scores = [run_one(request, paths, keep_view=args.keep_view) for _ in range(args.repeat)]
    for score in scores:
        print(
            json.dumps(
                {
                    k: score.get(k)
                    for k in (
                        "run_id",
                        "status",
                        "scored",
                        "cases",
                        "overall",
                        "youden_mean_of_categories",
                        "unmatched_findings",
                        "reason",
                    )
                },
                indent=1,
            )
        )
    return 0 if all(s.get("scored") for s in scores) else 1


def plan_profile(
    profile: Profile, catalog: Catalog, seed_tasks: dict[str, list[str]]
) -> list[tuple[str, str, str, str]]:
    """(target, mode, variant, task) for every run in a profile, in a fixed order."""
    plan = []
    for entry in profile.entries:
        target = catalog.targets[entry.target]
        ev = target.evaluation(entry.mode)
        variants = entry.variants or tuple(v.name for v in ev.variants)
        tasks: list[str] = list(entry.tasks) or seed_tasks.get(entry.target, [""])
        if entry.sample and len(tasks) > entry.sample:
            tasks = sorted(random.Random(entry.seed).sample(tasks, entry.sample))
        plan += [(entry.target, entry.mode.value, v, t) for v in variants for t in tasks]
    return plan


def profile_tasks(profile: Profile, catalog: Catalog, paths: SuitePaths) -> dict[str, list[str]]:
    """All task ids of the multi-task targets a profile uses (fetches their metadata)."""
    found: dict[str, list[str]] = {}
    for entry in profile.entries:
        target = catalog.targets[entry.target]
        plugin = REGISTRY.get(target.evaluation(entry.mode).key)
        if entry.tasks or plugin is None or plugin.tasks is None or entry.target in found:
            continue
        src = fetch(target.source, paths.source_dir(target.source))
        found[entry.target] = [
            t.task_id for t in plugin.tasks(src, target.evaluation(entry.mode).params)
        ]
    return found


def cmd_profile(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    profile = catalog.profiles[args.profile]
    tool = catalog.tools[args.tool]
    full = plan_profile(profile, catalog, profile_tasks(profile, catalog, paths))
    plan = [p for p in full if Mode(p[1]) in tool.modes]
    skipped = sorted({f"{p[0]} {p[1]}" for p in full if Mode(p[1]) not in tool.modes})
    if skipped:
        print(f"skipped (no {tool.id} adapter for the mode): {', '.join(skipped)}")
    items = profile_runner.expand(plan, profile.repeat)
    ledger = profile_runner.Ledger(paths.results / f"profile-{profile.id}-{args.tool}.jsonl")
    todo = profile_runner.pending(items, ledger, args.resume)
    print(f"{len(items)} runs planned ({len(plan)} x {profile.repeat} repeat(s), "
          f"{profile.wall_seconds}s each); {len(todo)} to run, {args.jobs} at a time")  # fmt: skip
    if args.dry_run:
        for item in todo:
            print(f"  {item.target} {item.mode} {item.variant} {item.task} #{item.repeat}")
        return 0

    def run_item(item: profile_runner.PlanItem) -> Mapping[str, Any]:
        ns = argparse.Namespace(tool=args.tool, target=item.target, mode=item.mode,
                                variant=item.variant, task=item.task, container=args.container,
                                timeout=0)  # fmt: skip
        return run_one(_request(ns, catalog, profile), paths)

    def report(item: profile_runner.PlanItem, outcome: Mapping[str, Any]) -> None:
        state = "scored" if outcome.get("scored") else f"NOT SCORED ({outcome.get('status')})"
        print(f"{item.target} {item.variant} {item.task} #{item.repeat}: {state}", flush=True)

    counts = profile_runner.run(todo, run_item, ledger, args.jobs, report)
    print(f"{counts['scored']} scored, {counts['not_scored']} not scored; ledger: {ledger.path}")
    return 1 if counts["not_scored"] else 0


def cmd_import(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    path = Path(args.path)
    results = import_agentdojo(path) if args.format == "agentdojo" else import_jsonl(path)
    summary = {"tool": args.tool, "target": args.target, "variants": summarize(results)}
    out = paths.results / f"upstream-{args.tool}-{args.target}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


def cmd_report(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    scores = load_scores(Path(args.results) if args.results else paths.results)
    print(json.dumps(scores, indent=1) if args.json else markdown(scores), end="")
    return 0


def cmd_tools(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    if args.action == "image":
        tag = images.build(list(catalog.tools.values()), paths.cache)
        print(f"built {tag}; sealed runs (--container) use it")
        return 0
    ids = [t for t in catalog.tools if catalog.tools[t].install] if args.all else args.ids
    if args.action == "list" or not ids:
        rows = [["tool", "version", "install", "installed", "verified"]]
        for tool in catalog.tools.values():
            kind = tool.install.kind if tool.install else "-"
            have = "yes" if tools.installed(tool, paths.cache) else "-"
            rows.append([tool.id, tool.version, kind, have, "yes" if tool.verified else "no"])
        _print_table(rows)
        return 0
    failed = 0
    for tool_id in ids:
        try:
            provided = tools.install(catalog.tools[tool_id], paths.cache)
            print(f"{tool_id}: {', '.join(provided)}")
        except tools.ToolInstallError as exc:
            failed += 1
            print(f"{tool_id}: FAILED {exc}", file=sys.stderr)
    print(f"tools are in {tools.bin_dir(paths.cache)}")
    return 1 if failed else 0


def cmd_prepare(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    target = catalog.targets[args.target]
    if target.prepare is None:
        print(f"{target.id} has no setup step")
        return 0
    src = fetch(target.source, paths.source_dir(target.source))
    print(f"running {target.id}'s setup step in {target.prepare.image.split('@')[0]} ...")
    try:
        dest = prepare_step.run(target, src, paths.cache)
    except prepare_step.PrepareError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"prepared: {dest}")
    return 0


def cmd_build_check(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    """Build every task of a live target with the suite's pins; report what fails."""
    target = catalog.targets[args.target]
    if target.runtime is None:
        raise RunError(f"{target.id} has no live runtime")
    src = fetch(target.source, paths.source_dir(target.source))
    plugin = REGISTRY.get(target.evaluations[0].key)
    tasks = [t.subdir for t in plugin.tasks(src, {})] if plugin and plugin.tasks else [""]
    if args.sample and len(tasks) > args.sample:
        tasks = sorted(random.Random(args.seed).sample(tasks, args.sample))
    args_for_build = {k: v.replace("{flag}", "FLAG{build-check}")
                      for k, v in target.runtime.build_args.items()}  # fmt: skip
    failed = 0
    for subdir in tasks:
        name = "its-build-" + (subdir.rsplit("/", 1)[-1].lower() or target.id)
        project_dir = src / subdir if subdir else src
        work = paths.cache / "private" / name
        ok, detail = live.build_only(
            target.runtime, project_dir, paths.root, work, name, args_for_build
        )
        failed += 0 if ok else 1
        print(f"{'ok  ' if ok else 'FAIL'} {subdir or target.id}" + ("" if ok else f"  {detail}"))
    print(f"{len(tasks) - failed}/{len(tasks)} built")
    return 1 if failed else 0


def cmd_check_adapter(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    tool = catalog.tools[args.tool]
    mode = Mode(args.mode)
    if mode not in tool.modes:
        raise RunError(f"{tool.id} has no {mode.value} adapter")
    source = str(Path(args.source).resolve()) if args.source else ""
    result = adapter_check.check(tool, mode, paths.root, source, args.url or "", args.timeout)
    print(f"{tool.id} {mode.value}: {result.status}; findings: {result.findings}; "
          f"version: {result.reported_version or '?'}; output: {result.out_dir}")  # fmt: skip
    if result.detail:
        print(result.detail, file=sys.stderr)
    return 0 if result.status == "ok" else 1


def cmd_scorecard(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    root = Path(args.results) if args.results else paths.results
    table = scorecard.build(load_scores(root), catalog, args.by)
    text = scorecard.markdown(table, args.by, root)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        print(text, end="")
    return 0


def _run_dir(paths: SuitePaths, run_id: str) -> Path:
    run_dir = paths.results / run_id
    if not (run_dir / "run.json").exists():
        raise RunError(f"no run {run_id} under {paths.results}")
    return run_dir


def cmd_adjudicate(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    run_dir = _run_dir(paths, args.run)
    if args.action == "mark":
        ids = adjudication.mark(paths.root, run_dir, args.index, args.verdict, args.note or "",
                                args.by or "", args.any_variant)  # fmt: skip
        print(f"recorded {', '.join(ids)}; run `itsuite rescore --all` to apply")
        return 0
    rows = adjudication.pending_rows(run_dir)
    for row in rows:
        where = row.get("source_path") or row.get("url") or row.get("path")
        line = f":{row['start_line']}" if row.get("start_line") else ""
        print(f"[{row['index']}] {row['rule'][:50]}  cwe={row['cwes']}  {where}{line}")
        if row.get("message"):
            print(f"      {row['message'][:110]}")
    print(f"\n{len(rows)} unmatched findings")
    return 0


def cmd_rescore(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    dirs = ([p.parent for p in sorted(paths.results.glob("*/run.json"))] if args.all
            else [_run_dir(paths, r) for r in args.runs])  # fmt: skip
    for run_dir in dirs:
        score = score_run(run_dir, paths.keys, paths.root)
        print(f"{run_dir.name}: {'scored' if score.get('scored') else 'not scored'}; "
              f"adjudicated {score.get('adjudicated')}")  # fmt: skip
    return 0


def cmd_model(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    """Install, download and serve the pinned model LLM-backed targets run on."""
    if args.action == "status":
        state = model_server.status(paths.cache)
        print(json.dumps(state, indent=1) if state else "no model is being served")
        return 0 if state else 1
    if args.action == "stop":
        print("stopped" if model_server.stop(paths.cache) else "nothing was running")
        return 0
    if not args.model or args.model not in catalog.models:
        raise RunError(f"name a model: {', '.join(sorted(catalog.models))}")
    spec = catalog.models[args.model]
    if args.action in ("install", "serve"):
        model_server.install(spec, paths.cache)
        where = model_server.download(spec, paths.cache)
        print(f"{spec.repo}@{spec.revision[:12]} in {where}")
    if args.action == "serve":
        state = model_server.serve(spec, paths.cache, model_server.bridge_ip())
        print(f"serving {spec.served_name} at http://{state['host']}:{state['port']}/v1")
    return 0


def cmd_lock(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    """Write the lock file, check it is up to date (--check), or check every pin upstream."""
    pins = lock.collect(catalog, paths.root)
    if args.online:
        problems = lock.check_online(pins)
        for problem in problems:
            pin = problem.pin
            print(f"{problem.status}: {pin.kind} {pin.ref} ({pin.used_by}): {problem.detail}")
        gone = sum(p.status == "missing" for p in problems)
        print(f"{len(pins)} pins checked: {gone} gone upstream, {len(problems) - gone} not checked")
        return 1 if problems else 0
    changes = lock.stale(paths.root, pins)
    for line in changes:
        print(line)
    if args.check:
        print(f"{lock.LOCK_FILE} is {'out of date: run itsuite lock' if changes else 'up to date'}")
        return 1 if changes else 0
    digest = lock.write(paths.root, pins)
    print(f"{lock.LOCK_FILE}: {len(pins)} pins, digest {digest[:16]}")
    return 0


def cmd_doctor(args: argparse.Namespace, catalog: Catalog, paths: SuitePaths) -> int:
    print(f"itsuite {__version__} (frozen {FREEZE_DATE}), root {paths.root}")
    print(f"answer-key plugins: {', '.join(sorted(REGISTRY))}")
    has_docker = docker_available()
    print(f"docker: {'ok' if has_docker else 'not available (live targets will not run)'}")
    return 0 if has_docker else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="itsuite", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    ls = sub.add_parser("list", help="list targets")
    ls.add_argument("--level", choices=[f"L{i}" for i in range(5)])
    ls.add_argument("--mode", choices=[m.value for m in Mode])
    sub.add_parser("validate", help="check the catalog")
    lk = sub.add_parser("lock", help="write suite.lock.json, or check it or the pins")
    lk_mode = lk.add_mutually_exclusive_group()
    lk_mode.add_argument(
        "--check", action="store_true", help="fail if the lock file is out of date"
    )
    lk_mode.add_argument("--online", action="store_true", help="check every pin still resolves")
    sub.add_parser("doctor", help="check docker and plugins")
    fe = sub.add_parser("fetch", help="fetch a target (or all) at its pinned commit")
    fe.add_argument("target")
    for name in ("run", "profile"):
        p = sub.add_parser(
            name, help=f"{name} a tool against {'a target' if name == 'run' else 'a profile'}"
        )
        p.add_argument("--tool", required=True)
        p.add_argument("--container", action="store_true", help="sealed run in the tool's image")
    run_p = sub.choices["run"]
    run_p.add_argument("--target", required=True)
    run_p.add_argument("--mode", required=True, choices=[m.value for m in Mode])
    run_p.add_argument("--variant", default="default")
    run_p.add_argument("--task")
    run_p.add_argument("--timeout", type=int, default=3600)
    run_p.add_argument("--repeat", type=int, default=1)
    run_p.add_argument("--keep-view", action="store_true")
    prof = sub.choices["profile"]
    prof.add_argument("profile")
    prof.add_argument("--dry-run", action="store_true")
    prof.add_argument("--jobs", type=int, default=1, help="runs at the same time")
    prof.add_argument("--resume", action="store_true", help="skip runs the ledger has scored")
    imp = sub.add_parser("import-upstream", help="import results from a bridge benchmark")
    imp.add_argument("path")
    imp.add_argument("--format", choices=["agentdojo", "jsonl"], required=True)
    imp.add_argument("--tool", required=True)
    imp.add_argument("--target", required=True)
    tl = sub.add_parser("tools", help="install tools at their pinned versions, or list them")
    tl.add_argument("action", choices=["install", "list", "image"])
    tl.add_argument("ids", nargs="*")
    tl.add_argument("--all", action="store_true")
    bc = sub.add_parser("build-check", help="build a live target's images with the pins")
    bc.add_argument("target")
    bc.add_argument("--sample", type=int, default=0)
    bc.add_argument("--seed", type=int, default=0)
    pr = sub.add_parser("prepare", help="run a target's documented setup step (e.g. CredData)")
    pr.add_argument("target")
    ca = sub.add_parser("check-adapter", help="run one adapter once and check its output parses")
    ca.add_argument("--tool", required=True)
    ca.add_argument("--mode", required=True, choices=[m.value for m in Mode])
    ca.add_argument("--source", help="folder to scan (source modes)")
    ca.add_argument("--url", help="URL to scan (live modes)")
    ca.add_argument("--timeout", type=int, default=1800)
    ad = sub.add_parser("adjudicate", help="show or decide a run's unmatched findings")
    ad.add_argument("action", choices=["show", "mark"])
    ad.add_argument("run")
    ad.add_argument("index", type=int, nargs="*")
    ad.add_argument("--verdict", choices=adjudication.VERDICTS)
    ad.add_argument("--note")
    ad.add_argument("--by", help="who decided")
    ad.add_argument("--any-variant", action="store_true", help="applies to every variant")
    rs = sub.add_parser("rescore", help="score runs again (after new adjudications)")
    rs.add_argument("runs", nargs="*")
    rs.add_argument("--all", action="store_true")
    md = sub.add_parser("model", help="serve the pinned model LLM-backed targets use (vLLM)")
    md.add_argument("action", choices=["install", "serve", "status", "stop"])
    md.add_argument("model", nargs="?")
    sc = sub.add_parser("scorecard", help="per-tool scorecard and comparison")
    sc.add_argument("--by", choices=scorecard.GROUPINGS, default="capability")
    sc.add_argument("--results")
    sc.add_argument("--out", help="write Markdown here instead of printing it")
    rep = sub.add_parser("report", help="summarize scored runs")
    rep.add_argument("--results")
    rep.add_argument("--json", action="store_true")
    return parser


COMMANDS = {
    "list": cmd_list,
    "validate": cmd_validate,
    "lock": cmd_lock,
    "fetch": cmd_fetch,
    "run": cmd_run,
    "profile": cmd_profile,
    "import-upstream": cmd_import,
    "report": cmd_report,
    "doctor": cmd_doctor,
    "tools": cmd_tools,
    "check-adapter": cmd_check_adapter,
    "prepare": cmd_prepare,
    "build-check": cmd_build_check,
    "scorecard": cmd_scorecard,
    "adjudicate": cmd_adjudicate,
    "rescore": cmd_rescore,
    "model": cmd_model,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = SuitePaths(find_root(Path.cwd()))
        catalog = load_catalog(paths.root)
        return COMMANDS[args.command](args, catalog, paths)
    except (
        CatalogError,
        RunError,
        FetchError,
        KeyBuildError,
        SealError,
        KeyError,
        tools.ToolInstallError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
