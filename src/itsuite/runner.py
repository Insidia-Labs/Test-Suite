"""Run one tool adapter with a clean environment, a time limit and an honest status.

Statuses: ``ok`` (exit 0 and the output file exists), ``no-output`` (exit 0, no
output), ``error`` (non-zero exit), ``timeout``, ``tool-missing``. Only ``ok`` runs
are scored; a crashed run is never read as "found nothing".
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

BASE_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER")
OK, NO_OUTPUT, ERROR, TIMEOUT, TOOL_MISSING = "ok", "no-output", "error", "timeout", "tool-missing"
SCORABLE = frozenset({OK})


class AdapterError(ValueError):
    """An adapter command template is invalid."""


class _StrictValues(dict[str, str]):
    def __missing__(self, key: str) -> str:
        raise AdapterError(f"command uses unknown placeholder {{{key}}}")


def render_command(template: str, values: Mapping[str, str]) -> list[str]:
    """Split the template into argv first, then fill placeholders per argument.

    Values never pass through a shell, so a value with spaces or quotes stays one
    argument and can't inject anything.
    """
    try:
        tokens = shlex.split(template)
    except ValueError as exc:
        raise AdapterError(f"bad command template: {exc}") from exc
    if not tokens:
        raise AdapterError("empty command template")
    lookup = _StrictValues(values)
    return [token.format_map(lookup) for token in tokens]


def clean_env(passthrough: Sequence[str], extra: Mapping[str, str]) -> dict[str, str]:
    """Only a few base variables, the tool's declared ones, and the ITS_* values."""
    names = (*BASE_ENV, *passthrough)
    env = {name: os.environ[name] for name in names if name in os.environ}
    return {**env, **extra}


@dataclass(frozen=True)
class ExecResult:
    status: str
    exit_code: int | None
    duration_s: float


def _stop_group(process: subprocess.Popen[bytes], grace: float = 10.0) -> None:
    """Terminate the whole process group the adapter started, then kill what's left."""
    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 5.0)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def execute(
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    timeout_s: int,
    log_dir: Path,
    on_timeout: Callable[[], None] | None = None,
) -> ExecResult:
    """Run the adapter in its own process group so a timeout stops all of it.

    ``on_timeout`` runs after the group is stopped, for things outside the group (a
    tool container keeps running when its ``docker run`` client is killed).
    """
    log_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with (log_dir / "stdout.log").open("wb") as out, (log_dir / "stderr.log").open("wb") as err:
        try:
            process = subprocess.Popen(
                list(argv), cwd=cwd, env=dict(env), stdout=out, stderr=err,
                stdin=subprocess.DEVNULL, start_new_session=True,
            )  # fmt: skip
        except (FileNotFoundError, PermissionError):
            return ExecResult(TOOL_MISSING, None, time.monotonic() - started)
        try:
            code = process.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            _stop_group(process)
            if on_timeout is not None:
                on_timeout()
            return ExecResult(TIMEOUT, None, time.monotonic() - started)
    return ExecResult(OK if code == 0 else ERROR, code, time.monotonic() - started)


def final_status(result: ExecResult, output: Path | None) -> str:
    """An ok exit with a missing output file is ``no-output``, not a clean result."""
    if result.status == OK and output is not None and not output.exists():
        return NO_OUTPUT
    return result.status
