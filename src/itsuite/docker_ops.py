"""Thin wrappers around the docker CLI. The runner is injectable so tests need no daemon."""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsuite.isolation import PROBE_IMAGE

Runner = Callable[..., "subprocess.CompletedProcess[str]"]
UP_TIMEOUT = 1800
PROBE_URLS = ("https://1.1.1.1", "https://example.com")


class DockerError(RuntimeError):
    """A docker command failed."""


@dataclass(frozen=True)
class ComposeProject:
    name: str
    file: Path
    project_dir: Path

    def argv(self, *args: str) -> list[str]:
        return [
            "docker",
            "compose",
            "-p",
            self.name,
            "-f",
            str(self.file),
            "--project-directory",
            str(self.project_dir),
            *args,
        ]


def _run(argv: Sequence[str], runner: Runner, timeout: int) -> subprocess.CompletedProcess[str]:
    try:
        return runner(list(argv), capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise DockerError(f"{' '.join(argv[:3])} timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise DockerError("docker is not installed or not on PATH") from exc


def compose_up(project: ComposeProject, runner: Runner = subprocess.run) -> None:
    done = _run(project.argv("up", "-d", "--build", "--wait"), runner, UP_TIMEOUT)
    if done.returncode != 0:
        tail = " | ".join((done.stderr or "").strip().splitlines()[-4:])
        raise DockerError(f"compose up failed: {tail}")


def compose_down(project: ComposeProject, runner: Runner = subprocess.run) -> None:
    """Stop only the project the harness started (its own -p name), and its volumes."""
    _run(project.argv("down", "-v", "--remove-orphans", "--timeout", "10"), runner, 300)


# curl exit codes that mean the request could not leave: 6 can't resolve host,
# 7 can't connect, 28 timed out. Any other curl result (0, or a TLS error after
# connecting) means the network let traffic out. Docker's own 125-127 mean the
# probe never ran, which must not be read as "blocked".
_BLOCKED = frozenset({6, 7, 28})
_PROBE_FAILED = frozenset({125, 126, 127})


def egress_open(network: str, runner: Runner = subprocess.run) -> bool:
    """True if a container on the network can reach the internet."""
    for url in PROBE_URLS:
        argv = ["docker", "run", "--rm", "--network", network, PROBE_IMAGE,
                "-s", "-o", "/dev/null", "-m", "5", url]  # fmt: skip
        code = _run(argv, runner, 120).returncode
        if code in _PROBE_FAILED:
            raise DockerError(f"egress probe could not run on {network} (docker exit {code})")
        if code not in _BLOCKED:
            return True
    return False


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None  # a redirect is an answer; never follow it off the gateway


_OPENER = urllib.request.build_opener(_NoRedirect)


def wait_http(url: str, timeout: float = 300.0, interval: float = 2.0) -> bool:
    """Wait until the URL answers with any HTTP status (the app is up)."""
    if not url.startswith("http://127.0.0.1:"):
        raise ValueError("readiness checks only go to the local gateway")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with _OPENER.open(url, timeout=5):
                return True
        except urllib.error.HTTPError:
            return True
        except (urllib.error.URLError, OSError):
            time.sleep(interval)
    return False
