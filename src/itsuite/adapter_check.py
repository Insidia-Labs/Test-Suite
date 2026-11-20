"""Check that an adapter works: run it once against a folder or URL and parse its output.

Nothing is scored. This is what ``verified: true`` in a tool manifest means: the
adapter ran end to end with the pinned tool and wrote output the scorer can read.
"""

from __future__ import annotations

import os
import secrets
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from itsuite.findings import FindingsError, load_findings
from itsuite.models import Mode, OutputFormat, ToolSpec
from itsuite.runner import OK, clean_env, execute, final_status, render_command
from itsuite.tools import bin_dir

SCORED_FORMATS = (OutputFormat.SARIF, OutputFormat.TRUFFLEHOG, OutputFormat.NUCLEI)


@dataclass(frozen=True)
class CheckResult:
    status: str
    findings: int | None
    out_dir: Path
    reported_version: str
    detail: str = ""


def tool_env(tool: ToolSpec, cache: Path, extra: dict[str, str]) -> dict[str, str]:
    """The adapter's environment: scrubbed, with the suite's tools first on PATH."""
    env = clean_env(tool.env_passthrough, extra)
    env["PATH"] = str(bin_dir(cache)) + os.pathsep + env.get("PATH", "")
    return env


def _read_version(out_dir: Path) -> str:
    path = out_dir / "tool-version.txt"
    return path.read_text(encoding="utf-8").splitlines()[0][:200] if path.exists() else ""


def check(tool: ToolSpec, mode: Mode, root: Path, source: str = "", url: str = "",
          timeout_s: int = 1800) -> CheckResult:  # fmt: skip
    tool_mode = tool.modes[mode]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    work = root / ".cache" / "checks" / f"{stamp}-{tool.id}-{mode.value}-{secrets.token_hex(3)}"
    out_dir, input_dir = work / "out", work / "input"
    out_dir.mkdir(parents=True)
    input_dir.mkdir()
    values = {
        "target_url": url, "source_dir": source, "out_dir": str(out_dir),
        "input_dir": str(input_dir), "adapter_dir": str(root / "adapters" / tool.id),
    }  # fmt: skip
    env = tool_env(tool, root / ".cache", {f"ITS_{k.upper()}": v for k, v in values.items()})
    result = execute(render_command(tool_mode.command, values), out_dir, env, timeout_s, work)
    output = out_dir / tool_mode.output_file if tool_mode.output in SCORED_FORMATS else None
    status = final_status(result, output)
    version = _read_version(out_dir)
    if status != OK or output is None:
        detail = (work / "stderr.log").read_text(encoding="utf-8", errors="replace")[-600:]
        return CheckResult(status, None, out_dir, version, detail.strip())
    try:
        count = len(load_findings(output, tool_mode.output))
    except FindingsError as exc:
        return CheckResult("unreadable-output", None, out_dir, version, str(exc))
    return CheckResult(OK, count, out_dir, version)


def clear_checks(root: Path) -> None:
    shutil.rmtree(root / ".cache" / "checks", ignore_errors=True)
