"""Container (sealed) mode: the tool runs in its own image and sees only what is mounted.

Mounted: the view (read-only), the input folder (read-only), the out folder, the
tool's adapter folder and ``adapters/common.sh`` (read-only). Nothing else from the
host, and no Docker socket, so the answer cache and the target's images are out of
reach. Against a live target the tool joins only the edge network, where it can
reach the gateway and the internet (for its own model API) but not the target's
other services, such as its database.
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = "/its"
HARDENING = ("--security-opt", "no-new-privileges", "--pids-limit", "4096")


@dataclass(frozen=True)
class ContainerPlan:
    image: str
    name: str
    run_dir: Path
    view_dir: str
    adapter_dir: Path
    common_sh: Path
    network: str
    env_names: tuple[str, ...]


def mounts(plan: ContainerPlan) -> list[str]:
    pairs = [
        f"{plan.run_dir / 'out'}:{ROOT}/out",
        f"{plan.run_dir / 'input'}:{ROOT}/input:ro",
        f"{plan.adapter_dir}:{ROOT}/adapter:ro",
        f"{plan.common_sh}:{ROOT}/common.sh:ro",
    ]
    if plan.view_dir:
        pairs.append(f"{plan.view_dir}:{ROOT}/src:ro")
    return [arg for pair in pairs for arg in ("-v", pair)]


def argv(command: Sequence[str], plan: ContainerPlan) -> list[str]:
    """``docker run`` for the tool. Environment values are passed by name (``-e NAME``),
    so they come from the docker client's scrubbed environment and never sit on argv."""
    env = [arg for name in plan.env_names for arg in ("-e", name)]
    user = f"{os.getuid()}:{os.getgid()}"  # output stays owned by whoever runs the suite
    return [
        "docker", "run", "--rm", "--name", plan.name, "--network", plan.network,
        "--user", user, *HARDENING, *env, *mounts(plan), "-w", f"{ROOT}/out", plan.image,
        *command,
    ]  # fmt: skip


def kill(name: str) -> None:
    """Stop a tool container whose ``docker run`` client was killed on timeout."""
    subprocess.run(["docker", "kill", name], capture_output=True, timeout=60, check=False)
