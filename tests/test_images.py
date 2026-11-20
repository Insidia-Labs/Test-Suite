"""The suite tools image for sealed runs."""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from itsuite import images
from itsuite.models import Install, ToolSpec
from itsuite.tools import ToolInstallError


def _tool(tool_id: str, install: Install | None) -> ToolSpec:
    return ToolSpec(tool_id, tool_id, "baseline", "1", "s", "MIT", {}, install=install)


TOOLS = [
    _tool("gitleaks", Install("archive", "https://x/g.tgz", "a" * 64, "gitleaks")),
    _tool("semgrep", Install("pip", packages=("semgrep==1.186.0",), binaries=("semgrep",))),
    _tool("zap", Install("docker", image="zap@sha256:" + "0" * 64)),
    _tool("lynx", None),
]


def test_dockerfile_pins_base_and_packages_and_skips_docker_tools() -> None:
    text = images.dockerfile(TOOLS)
    assert text.startswith(f"FROM {images.BASE_IMAGE}\n") and "@sha256:" in images.BASE_IMAGE
    assert "/opt/itsuite/semgrep/bin/pip install --no-cache-dir semgrep==1.186.0" in text
    assert "ln -s /opt/itsuite/semgrep/bin/semgrep /usr/local/bin/semgrep" in text
    assert "zap" not in text and "COPY bin/ /usr/local/bin/" in text
    assert [t.id for t in images.image_tools(TOOLS)] == ["gitleaks", "semgrep"]


def test_build_context_needs_installed_binaries_and_tag_tracks_content(tmp_path: Path) -> None:
    with pytest.raises(ToolInstallError, match="tools install gitleaks"):
        images.build_context(TOOLS, tmp_path, tmp_path / "ctx")
    binary = tmp_path / "tools" / "bin" / "gitleaks"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"v1")
    first = images.context_tag(images.build_context(TOOLS, tmp_path, tmp_path / "ctx"))
    assert (tmp_path / "ctx" / "bin" / "gitleaks").read_bytes() == b"v1"
    binary.write_bytes(b"v2")
    second = images.context_tag(images.build_context(TOOLS, tmp_path, tmp_path / "ctx"))
    assert first != second and first.startswith("itsuite-tools:")


class Docker:
    def __init__(self, code: int) -> None:
        self.code = code
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(argv, self.code, "", "step failed\n")


def test_build_records_the_image(tmp_path: Path) -> None:
    binary = tmp_path / "tools" / "bin" / "gitleaks"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"v1")
    assert images.current_image(tmp_path) == ""
    docker = Docker(0)
    tag = images.build(TOOLS, tmp_path, docker)
    assert docker.calls[0][:4] == ["docker", "build", "-q", "-t"] and docker.calls[0][4] == tag
    assert images.current_image(tmp_path) == tag
    with pytest.raises(ToolInstallError, match="step failed"):
        images.build(TOOLS, tmp_path, Docker(1))
