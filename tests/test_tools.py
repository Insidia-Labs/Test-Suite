"""Pinned tool installs, the install block in manifests, and adapter checks."""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import tarfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import write
from itsuite import adapter_check, tools
from itsuite.catalog import parse_install
from itsuite.models import CatalogError, Install, Mode, OutputFormat, ToolMode, ToolSpec


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _tar_with(name: str, body: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        info = tarfile.TarInfo(name)
        info.size = len(body)
        bundle.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def _tool(install: Install) -> ToolSpec:
    return ToolSpec("demo", "Demo", "baseline", "1.0", "s", "MIT", {}, install=install)


def test_parse_install_requires_pins() -> None:
    sha = "a" * 64
    ok = parse_install(
        {"kind": "archive", "url": "https://x/t.tgz", "sha256": sha, "binary": "t"}, "c"
    )
    assert ok and ok.kind == "archive" and ok.binary == "t"
    assert parse_install(None, "c") is None
    with pytest.raises(CatalogError, match="sha256"):
        parse_install({"kind": "binary", "url": "https://x/t", "sha256": "abc", "binary": "t"}, "c")
    with pytest.raises(CatalogError, match="https"):
        parse_install({"kind": "archive", "url": "http://x/t", "sha256": sha, "binary": "t"}, "c")
    with pytest.raises(CatalogError, match="binary name"):
        parse_install({"kind": "archive", "url": "https://x/t", "sha256": sha}, "c")
    with pytest.raises(CatalogError, match="pinned"):
        parse_install({"kind": "pip", "packages": ["semgrep"]}, "c")
    with pytest.raises(CatalogError, match="digest"):
        parse_install({"kind": "docker", "image": "zap:latest"}, "c")
    with pytest.raises(CatalogError, match="kind"):
        parse_install({"kind": "brew"}, "c")


def test_archive_install_checks_digest_and_places_binary(tmp_path: Path) -> None:
    data = _tar_with("tool-1.0/demo", b"#!/bin/sh\necho demo 1.0\n")
    spec = Install("archive", "https://x/demo.tgz", hashlib.sha256(data).hexdigest(), "demo")
    provided = tools.install(_tool(spec), tmp_path, opener=lambda *a, **k: _Response(data))
    binary = tmp_path / "tools" / "bin" / "demo"
    assert provided == ["demo"] and binary.read_bytes().startswith(b"#!/bin/sh")
    assert binary.stat().st_mode & 0o111 and tools.installed(_tool(spec), tmp_path)
    bad = Install("archive", "https://x/demo2.tgz", "0" * 64, "demo")
    with pytest.raises(tools.ToolInstallError, match="does not match"):
        tools.install(_tool(bad), tmp_path, opener=lambda *a, **k: _Response(data))


def test_archive_without_the_binary_and_tool_without_install(tmp_path: Path) -> None:
    data = _tar_with("README", b"x")
    spec = Install("archive", "https://x/a.tgz", hashlib.sha256(data).hexdigest(), "demo")
    with pytest.raises(tools.ToolInstallError, match="not found"):
        tools.install(_tool(spec), tmp_path, opener=lambda *a, **k: _Response(data))
    with pytest.raises(tools.ToolInstallError, match="no install block"):
        tools.install(ToolSpec("x", "X", "baseline", "1", "s", "MIT", {}), tmp_path)


def test_binary_install(tmp_path: Path) -> None:
    data = b"\x7fELF fake"
    spec = Install("binary", "https://x/osv", hashlib.sha256(data).hexdigest(), "osv-scanner")
    assert tools.install(_tool(spec), tmp_path, opener=lambda *a, **k: _Response(data)) == [
        "osv-scanner"
    ]
    assert tools.commands(_tool(spec)) == ("osv-scanner",)


class Recorder:
    def __init__(self, code: int = 0) -> None:
        self.code = code
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv[:2] == ["uv", "venv"]:
            (Path(argv[-1]) / "bin").mkdir(parents=True)
            (Path(argv[-1]) / "bin" / "python").write_text("")
        return subprocess.CompletedProcess(argv, self.code, "", "boom\n")


def test_pip_and_docker_installs(tmp_path: Path) -> None:
    runner = Recorder()
    spec = Install("pip", packages=("semgrep==1.186.0",), binaries=("semgrep",))
    assert tools.install(_tool(spec), tmp_path, runner=runner) == ["semgrep"]
    assert runner.calls[0][:2] == ["uv", "venv"] and "semgrep==1.186.0" in runner.calls[1]
    assert (tmp_path / "tools" / "bin" / "semgrep").is_symlink()
    tools.install(_tool(spec), tmp_path, runner=runner)  # relinking is fine
    image = Install("docker", image="zap@sha256:" + "0" * 64)
    assert tools.install(_tool(image), tmp_path, runner=runner) == [image.image]
    assert tools.commands(_tool(image)) == () and not tools.installed(_tool(image), tmp_path)
    with pytest.raises(tools.ToolInstallError, match="failed: boom"):
        tools.install(_tool(image), tmp_path, runner=Recorder(1))


SARIF_ADAPTER = """
import json, pathlib, sys
out = pathlib.Path(sys.argv[2])
(out / "tool-version.txt").write_text("demo 1.0\\n")
(out / "results.sarif").write_text(json.dumps({"version": "2.1.0", "runs": [
    {"tool": {"driver": {"name": "demo"}}, "results": [{"ruleId": "r", "message": {"text": "m"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": sys.argv[1] + "/a.py"}}}]}]}]}))
"""


def _checked_tool(root: Path, body: str) -> ToolSpec:
    write(root, "adapters/demo/sast.py", body)
    command = f"{sys.executable} {{adapter_dir}}/sast.py {{source_dir}} {{out_dir}}"
    return ToolSpec(
        "demo",
        "Demo",
        "baseline",
        "1",
        "s",
        "MIT",
        {Mode.SAST: ToolMode(command, OutputFormat.SARIF)},
    )


def test_check_adapter_ok_and_failures(tmp_path: Path) -> None:
    ok = adapter_check.check(_checked_tool(tmp_path, SARIF_ADAPTER), Mode.SAST, tmp_path, "/src")
    assert (ok.status, ok.findings, ok.reported_version) == ("ok", 1, "demo 1.0")
    crash = adapter_check.check(
        _checked_tool(tmp_path, "raise SystemExit('broken')"), Mode.SAST, tmp_path, "/src"
    )
    assert crash.status == "error" and "broken" in crash.detail
    junk = "import pathlib,sys; (pathlib.Path(sys.argv[2])/'results.sarif').write_text('junk')"
    bad = adapter_check.check(_checked_tool(tmp_path, junk), Mode.SAST, tmp_path, "/src")
    assert bad.status == "unreadable-output"
    adapter_check.clear_checks(tmp_path)
    assert not (tmp_path / ".cache" / "checks").exists()


def test_tool_env_puts_suite_tools_first(tmp_path: Path) -> None:
    env = adapter_check.tool_env(_tool(Install("pip")), tmp_path, {"ITS_X": "1"})
    assert env["PATH"].startswith(str(tmp_path / "tools" / "bin")) and env["ITS_X"] == "1"
