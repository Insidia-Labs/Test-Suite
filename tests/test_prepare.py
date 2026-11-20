"""A target's setup step: runs on a copy, must leave checkout files unchanged."""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import write
from itsuite import prepare
from itsuite.catalog import parse_prepare
from itsuite.models import CatalogError, Contamination, Level, Prepare, Source, TargetSpec

IMAGE = "python:3.11@sha256:" + "0" * 64


def _target(spec: Prepare | None) -> TargetSpec:
    return TargetSpec(
        "cred",
        "Cred",
        Level.L2,
        (),
        Source("git", "u", "c" * 40),
        "MIT",
        "",
        Contamination.LOW,
        "x",
        (),
        prepare=spec,
    )


def _fake(effect: Callable[[Path], None], code: int = 0) -> Any:
    def runner(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        work = Path(argv[argv.index("-v") + 1].split(":")[0])
        effect(work)
        return subprocess.CompletedProcess(argv, code, "log line\n", "")

    return runner


@pytest.fixture
def src(tmp_path: Path) -> Path:
    write(tmp_path, "src/meta/a.csv", "Id,GroundTruth\n1,T\n")
    write(tmp_path, "src/.git/HEAD", "ref")
    return tmp_path / "src"


def test_parse_prepare_requires_pins_and_outputs() -> None:
    spec = parse_prepare({"image": IMAGE, "command": "make", "outputs": ["data"]}, "c")
    assert spec and spec.outputs == ("data",) and not spec.network
    with pytest.raises(CatalogError, match="digest"):
        parse_prepare({"image": "python:3.11", "command": "x", "outputs": ["d"]}, "c")
    with pytest.raises(CatalogError, match="outputs"):
        parse_prepare({"image": IMAGE, "command": "x"}, "c")
    assert parse_prepare(None, "c") is None


def test_prepare_runs_on_a_copy_and_keeps_outputs(src: Path, tmp_path: Path) -> None:
    def effect(work: Path) -> None:
        write(work, "data/x/1.c", "password = 'x'\n")
        write(work, "tmp/clone/file", "big")

    target = _target(Prepare(IMAGE, "python download.py", ("data",), ("tmp",), network=True))
    dest = prepare.run(target, src, tmp_path / "cache", _fake(effect))
    assert (dest / "data/x/1.c").exists() and not (dest / "tmp").exists()
    assert not (dest / ".git").exists() and not (src / "data").exists()
    assert prepare.is_prepared(tmp_path / "cache", target)
    assert (
        prepare.run(target, src, tmp_path / "cache", _fake(lambda w: pytest.fail("reran"))) == dest
    )


def test_prepare_refuses_changed_metadata_and_missing_outputs(src: Path, tmp_path: Path) -> None:
    spec = Prepare(IMAGE, "x", ("data",))
    with pytest.raises(prepare.PrepareError, match="changed or removed"):
        prepare.run(
            _target(spec),
            src,
            tmp_path / "c1",
            _fake(lambda w: (w / "meta/a.csv").write_text("Id,GroundTruth\n1,F\n")),
        )
    with pytest.raises(prepare.PrepareError, match="didn't create"):
        prepare.run(_target(spec), src, tmp_path / "c2", _fake(lambda w: None))
    with pytest.raises(prepare.PrepareError, match="exited 2"):
        prepare.run(_target(spec), src, tmp_path / "c3", _fake(lambda w: None, code=2))
    assert not prepare.is_prepared(tmp_path / "c1", _target(spec))


def test_container_command_and_no_prepare(src: Path, tmp_path: Path) -> None:
    argv = prepare._container(Prepare(IMAGE, "make data", ("data",)), tmp_path)
    assert argv[argv.index("--network") + 1] == "none" and argv[-3:-1] == ["sh", "-c"]
    assert argv[-1].startswith("make data && chown -R ")
    assert prepare.run(_target(None), src, tmp_path) == src
    assert prepare.is_prepared(tmp_path, _target(None))
