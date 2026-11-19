"""The tool's view of the source, and pinned fetching."""

from __future__ import annotations

import io
import subprocess
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from conftest import write
from itsuite.fetch import FetchError, extract, fetch, fetch_archive, fetch_git, safe_member
from itsuite.models import Source, ViewSpec
from itsuite.view import build_view, load_path_map, matches_any, save_path_map, transform_text


def test_view_excludes_answers_and_keeps_line_numbers(tmp_path: Path) -> None:
    src = tmp_path / "src"
    write(src, "routes/login.ts", "a\nquery() // vuln-code-snippet vuln-line x\nb\n")
    write(src, "SOLUTIONS.md", "answers")
    write(src, "data/static/codefixes/x.ts", "fix")
    write(src, ".git/config", "secret")
    spec = ViewSpec(
        exclude=("SOLUTIONS.md", "data/static/codefixes"),
        strip=(r"\s*//\s*vuln-code-snippet\b.*$",),
    )
    result = build_view(src, tmp_path / "view", spec)
    text = (tmp_path / "view/routes/login.ts").read_text()
    assert text == "a\nquery()\nb\n" and text.count("\n") == 3
    assert result.files == 1 and result.excluded == 3 and result.markers_removed == 1
    assert not (tmp_path / "view/SOLUTIONS.md").exists()


def test_view_include_opaque_rename_and_path_map(tmp_path: Path) -> None:
    src = tmp_path / "src"
    write(src, "dataset/125/CASTLE-125-1.c", "vulnerable: true\ncode // {!LINE}\n")
    write(src, "README.md", "x")
    spec = ViewSpec(
        include=("dataset",),
        rename="opaque",
        strip=(r"^\s*(vulnerable|cwe)\s*:.*$", r"\s*//\s*\{!LINE\}"),
    )
    result = build_view(src, tmp_path / "view", spec)
    ((name, original),) = result.path_map.items()
    assert (
        name.startswith("cases/")
        and name.endswith(".c")
        and original == "dataset/125/CASTLE-125-1.c"
    )
    assert (tmp_path / "view" / name).read_text() == "\ncode\n"
    save_path_map(result, tmp_path / "map.json")
    assert load_path_map(tmp_path / "map.json") == {name: original}
    assert load_path_map(tmp_path / "missing.json") == {}


def test_view_skips_symlinks_and_copies_binary(tmp_path: Path) -> None:
    src = tmp_path / "src"
    write(src, "a.txt", "x")
    (src / "link").symlink_to("/etc/hostname")
    (src / "blob.bin").write_bytes(b"\x00\x01vuln-code-snippet")
    result = build_view(src, tmp_path / "view", ViewSpec(strip=("vuln-code-snippet",)))
    assert result.skipped_links == 1 and not (tmp_path / "view/link").exists()
    assert (tmp_path / "view/blob.bin").read_bytes() == b"\x00\x01vuln-code-snippet"
    build_view(src, tmp_path / "view", ViewSpec())  # rebuilding replaces the old view


def test_matches_any_and_transform() -> None:
    assert matches_any("test/api/x.ts", ["test"])
    assert matches_any("expectedresults-1.2.csv", ["expectedresults-*.csv"])
    assert matches_any("a/node_modules/b.js", ["*/node_modules"])
    assert not matches_any("tests.py", ["test"])
    assert transform_text("x\r\ny // m\r\n", ViewSpec(strip=(r"\s*// m",))) == ("x\r\ny\r\n", 1)


def test_safe_member() -> None:
    assert safe_member("a/b.c")
    assert not safe_member("../x") and not safe_member("/etc/passwd") and not safe_member("")


def test_extract_refuses_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../evil.txt", "x")
    with pytest.raises(FetchError, match="unsafe"):
        extract(archive, tmp_path / "out")


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("juliet/README.txt", "hi")
    return buffer.getvalue()


def test_fetch_archive_checks_digest(tmp_path: Path) -> None:
    import hashlib

    data = _zip_bytes()
    good = Source("archive", "https://example.org/j.zip", sha256=hashlib.sha256(data).hexdigest())
    dest = fetch_archive(good, tmp_path / "j", opener=lambda *a, **k: _Response(data))
    assert (dest / "juliet/README.txt").read_text() == "hi"
    assert fetch_archive(good, dest, opener=lambda *a, **k: pytest.fail("no refetch")) == dest
    bad = Source("archive", "https://example.org/j.zip", sha256="0" * 64)
    with pytest.raises(FetchError, match="does not match"):
        fetch_archive(bad, tmp_path / "k", opener=lambda *a, **k: _Response(data))
    with pytest.raises(FetchError, match="https"):
        fetch_archive(Source("archive", "http://x/j.zip", sha256="0" * 64), tmp_path / "m")


class FakeGit:
    """Records git calls; rev-parse answers with the commit given."""

    def __init__(self, head: str) -> None:
        self.head = head
        self.calls: list[list[str]] = []

    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        args = [a for a in argv[1:] if not a.startswith(("protocol.", "core.")) and a != "-c"]
        self.calls.append(args)
        if args[0] == "init":
            (Path(kwargs["cwd"]) / ".git").mkdir()
        out = self.head + "\n" if args[0] == "rev-parse" else ""
        return subprocess.CompletedProcess(argv, 0, out, "")


def test_fetch_git_pins_and_verifies(tmp_path: Path) -> None:
    commit = "a" * 40
    git = FakeGit(commit)
    source = Source("git", "https://github.com/x/y.git", commit, submodules=True)
    fetch(source, tmp_path / "y", runner=git)
    verbs = [c[0] for c in git.calls]
    assert verbs == ["init", "remote", "fetch", "checkout", "submodule", "rev-parse"]
    assert ["fetch", "-q", "--depth", "1", "origin", commit] in git.calls
    git.calls.clear()
    fetch_git(source, tmp_path / "y", runner=git)  # already at the pin and clean
    assert [c[0] for c in git.calls] == ["rev-parse", "status"]


def test_fetch_git_refuses_wrong_commit_and_foreign_dirs(tmp_path: Path) -> None:
    with pytest.raises(FetchError, match="pinned"):
        fetch_git(Source("git", "u", "a" * 40), tmp_path / "z", runner=FakeGit("b" * 40))
    write(tmp_path, "other/file.txt", "x")
    with pytest.raises(FetchError, match="not a git checkout"):
        fetch_git(Source("git", "u", "a" * 40), tmp_path / "other", runner=FakeGit("a" * 40))


def test_fetch_git_reports_git_errors(tmp_path: Path) -> None:
    def failing(argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        raise subprocess.CalledProcessError(128, argv, "", "fatal: repository not found\n")

    with pytest.raises(FetchError, match="repository not found"):
        fetch_git(Source("git", "u", "a" * 40), tmp_path / "q", runner=failing)
    with pytest.raises(FetchError, match="unknown source kind"):
        fetch(Source("svn", "u"), tmp_path / "s")


def test_view_drops_ai_agent_instruction_files(tmp_path: Path) -> None:
    src = tmp_path / "src"
    for rel in (
        "AGENTS.md",
        "CLAUDE.md",
        ".claude/settings.json",
        ".ai/skills/x/SKILL.md",
        ".github/copilot-instructions.md",
        ".github/workflows/ci.yml",
        "app.py",
    ):
        write(src, rel, "x")
    build_view(src, tmp_path / "view", ViewSpec())
    kept = sorted(
        p.relative_to(tmp_path / "view").as_posix()
        for p in (tmp_path / "view").rglob("*")
        if p.is_file()
    )
    assert kept == [".github/workflows/ci.yml", "app.py"]


def test_opaque_names_are_stable_with_a_salt(tmp_path: Path) -> None:
    from itsuite.view import view_salt

    src = tmp_path / "src"
    write(src, "dataset/a.c", "x")
    salt = view_salt(tmp_path / "private")
    assert salt == view_salt(tmp_path / "private") and len(salt) == 32
    first = build_view(src, tmp_path / "v1", ViewSpec(rename="opaque"), salt).path_map
    second = build_view(src, tmp_path / "v2", ViewSpec(rename="opaque"), salt).path_map
    assert first == second and "a.c" not in next(iter(first))


class DirtyGit(FakeGit):
    def __call__(self, argv: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        done = super().__call__(argv, **kwargs)
        if self.calls[-1][0] == "status":
            return subprocess.CompletedProcess(argv, 0, "?? build-output.txt\n", "")
        return done


def test_dirty_cached_checkout_is_cleaned(tmp_path: Path) -> None:
    commit = "a" * 40
    (tmp_path / "y" / ".git").mkdir(parents=True)
    git = DirtyGit(commit)
    fetch_git(Source("git", "u", commit), tmp_path / "y", runner=git)
    assert [c[0] for c in git.calls] == ["rev-parse", "status", "checkout", "clean"]


def test_tar_with_device_or_link_is_refused(tmp_path: Path) -> None:
    import tarfile

    archive = tmp_path / "x.tar"
    with tarfile.open(archive, "w") as bundle:
        info = tarfile.TarInfo("dev/null-ish")
        info.type = tarfile.CHRTYPE
        bundle.addfile(info)
    with pytest.raises(FetchError, match="devices"):
        extract(archive, tmp_path / "out")
