"""The lock file lists every pin; checks find a stale lock and pins that no longer resolve."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import SUITE_ROOT
from itsuite import cli, lock
from itsuite.catalog import load_catalog
from itsuite.lock import Pin

CATALOG = load_catalog(SUITE_ROOT)


def _refs(kind: str) -> set[str]:
    return {p.ref for p in lock.collect(CATALOG, SUITE_ROOT) if p.kind == kind}


def test_collect_finds_pins_in_the_catalog_files_and_code() -> None:
    pins = lock.collect(CATALOG, SUITE_ROOT)
    assert pins == sorted(set(pins))
    git = _refs("git")
    assert any(r.startswith("https://github.com/digininja/DVWA") and "@" in r for r in git)
    assert any("Insidia-Labs-Argus@f783775a" in r for r in git)  # a tool installed from git
    assert any("nuclei-templates.git@5442582a" in r for r in git)  # pinned in an adapter
    assert "bandit[sarif]==1.9.4" in _refs("pypi") and "vllm==0.34.0" in _refs("pypi")
    assert "streamlit==1.46.0" in _refs("pypi")  # DVLA's pip constraints
    assert "Qwen/Qwen3.5-0.8B@2fc06364715b967f1860aea9cf38778875588b17" in _refs("hf-model")
    images = _refs("image")
    assert any(i.startswith("zaproxy/zap-stable:2.17.0@sha256:") for i in images)
    assert any(i.startswith("rootcauz/ai-base:0.0.1@sha256:") for i in images)  # a Dockerfile
    assert any(i.startswith("alpine/socat:") for i in images)  # the harness's own gateway
    assert any(i.startswith("composer:latest@sha256:") for i in images)  # XBOW base images
    assert "20261119T000000Z" in _refs("apt-snapshot")
    archives = [p for p in pins if p.kind == "archive"]
    assert archives and all(len(p.sha256) == 64 for p in archives)
    assert all(p.used_by for p in pins)


def test_repo_lock_file_is_up_to_date() -> None:
    assert lock.stale(SUITE_ROOT, lock.collect(CATALOG, SUITE_ROOT)) == []


def test_write_then_stale_reports_added_and_removed_pins(tmp_path: Path) -> None:
    pins = [Pin("pypi", "a==1", "tool x"), Pin("image", "b:1@sha256:" + "0" * 64, "harness")]
    assert lock.stale(tmp_path, pins) == [f"{lock.LOCK_FILE} is missing"]
    digest = lock.write(tmp_path, pins)
    document = json.loads((tmp_path / lock.LOCK_FILE).read_text())
    assert document["digest"] == digest and len(document["pins"]) == 2
    assert lock.stale(tmp_path, pins) == []
    changed = [pins[0], Pin("pypi", "a==2", "tool x")]
    assert lock.stale(tmp_path, changed) == [
        "+ pypi a==2 (tool x)",
        f"- image b:1@sha256:{'0' * 64} (harness)",
    ]
    assert lock.write(tmp_path, changed) != digest


class Git:
    """Fake git: the fetch answers as told; other commands succeed."""

    def __init__(self, code: int, stderr: str = "") -> None:
        self.code, self.stderr = code, stderr
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        code = self.code if "fetch" in argv else 0
        return subprocess.CompletedProcess(argv, code, "", self.stderr if "fetch" in argv else "")


def test_git_pin_check_tells_missing_from_unreachable() -> None:
    pin = Pin("git", "https://github.com/o/r.git@" + "a" * 40, "target r")
    assert lock.check_git(pin, Git(0)) == ("ok", "")
    assert (
        lock.check_git(pin, Git(128, "fatal: remote error: upload-pack: not our ref"))[0]
        == "missing"
    )
    assert (
        lock.check_git(pin, Git(128, "fatal: unable to access: Could not resolve host"))[0]
        == "error"
    )
    runner = Git(0)
    lock.check_git(pin, runner)
    fetch = next(c for c in runner.calls if "fetch" in c)
    assert fetch[-2:] == ["https://github.com/o/r.git", "a" * 40] and "--depth=1" in fetch


def test_http_based_checks_map_status_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []

    def status(url: str) -> int:
        asked.append(url)
        return {"missing": 404, "down": 503}.get(url.rsplit("/", 2)[-2], 200)

    monkeypatch.setattr(lock, "http_status", status)
    assert lock.check_pypi(Pin("pypi", "bandit[sarif]==1.9.4", "tool")) == ("ok", "")
    assert asked[-1] == "https://pypi.org/pypi/bandit/1.9.4/json"
    assert lock.check_pypi(Pin("pypi", "x==missing", "t"))[0] == "missing"
    assert lock.check_hf_model(Pin("hf-model", "Qwen/Q@" + "b" * 40, "m")) == ("ok", "")
    assert asked[-1] == "https://huggingface.co/api/models/Qwen/Q/revision/" + "b" * 40
    assert lock.check_archive(Pin("archive", "https://x/down/f.zip", "t", "c" * 64))[0] == "error"
    assert lock.check_apt_snapshot(Pin("apt-snapshot", "20261119T000000Z", "t")) == ("ok", "")
    assert asked[-1] == "http://snapshot.debian.org/archive/debian/20261119T000000Z/"


def test_image_pin_check_uses_the_registry() -> None:
    def runner(code: int, err: str = "") -> Any:
        return lambda argv, **k: subprocess.CompletedProcess(argv, code, "", err)

    pin = Pin("image", "a/b:1@sha256:" + "d" * 64, "tool")
    assert lock.check_image(pin, runner(0)) == ("ok", "")
    assert lock.check_image(pin, runner(1, "ERROR: a/b: not found"))[0] == "missing"
    assert lock.check_image(pin, runner(1, "ERROR: dial tcp: i/o timeout"))[0] == "error"


def test_check_online_reports_only_problems() -> None:
    pins = [Pin("pypi", "a==1", "t"), Pin("pypi", "b==1", "t"), Pin("image", "c", "t")]
    answers = {"a==1": ("ok", ""), "b==1": ("missing", "404"), "c": ("error", "timeout")}
    checkers = {kind: (lambda pin: answers[pin.ref]) for kind in ("pypi", "image")}
    problems = lock.check_online(pins, checkers, workers=2)
    assert [(p.pin.ref, p.status) for p in problems] == [("b==1", "missing"), ("c", "error")]


def test_cli_lock_writes_and_checks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import shutil

    root = tmp_path / "suite"
    for folder in ("catalog", "profiles", "targets", "adapters"):
        shutil.copytree(SUITE_ROOT / folder, root / folder)
    monkeypatch.setenv("ITS_ROOT", str(root))
    assert cli.main(["lock", "--check"]) == 1
    assert "is missing" in capsys.readouterr().out
    assert cli.main(["lock"]) == 0
    assert "pins" in capsys.readouterr().out
    assert cli.main(["lock", "--check"]) == 0
