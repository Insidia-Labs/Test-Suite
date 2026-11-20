"""Build pinning: base images by digest and Debian apt sources at a fixed date."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import write
from itsuite import apt_pin

TS = "20261119T000000Z"
BASES = {"debian:bullseye-slim": "sha256:" + "a" * 64, "nginx:latest": "sha256:" + "b" * 64}

DOCKERFILE = """FROM debian:bullseye-slim AS build
RUN apt-get update && apt-get install -y curl
ARG FLAG
RUN echo -n $FLAG > /flag
FROM nginx
COPY --from=build /flag /flag
"""


def test_snapshot_step_covers_retired_and_current_releases() -> None:
    step = apt_pin.snapshot_step(TS)
    assert step.startswith("RUN if [ -f /etc/debian_version ]")
    assert "jessie|stretch|buster) M=http://archive.debian.org/debian" in step
    assert (
        'bullseye) M=http://archive.debian.org/debian; S="http://archive.debian.org/debian-security bullseye-security"'
        in step
    )
    assert f"snapshot.debian.org/archive/debian/{TS}" in step and "grep -qi ubuntu" in step
    with pytest.raises(ValueError):
        apt_pin.snapshot_step("2026-11-19")


def test_pin_dockerfile_pins_from_and_adds_step_only_where_apt_runs() -> None:
    out = apt_pin.pin_dockerfile(DOCKERFILE, TS, BASES).splitlines()
    assert out[0] == f"FROM debian:bullseye-slim@{BASES['debian:bullseye-slim']} AS build"
    assert out[1].startswith("RUN if [ -f /etc/debian_version ]")
    assert out[2].startswith("RUN apt-get update") and "RUN echo -n $FLAG > /flag" in out
    nginx = out.index(f"FROM nginx:latest@{BASES['nginx:latest']}")
    assert not out[nginx + 1].startswith("RUN if")  # that stage doesn't use apt


def test_pin_from_leaves_digests_unknown_images_and_variables_alone() -> None:
    assert apt_pin.pin_from("FROM alpine@sha256:abc", BASES) == "FROM alpine@sha256:abc"
    assert apt_pin.pin_from("FROM ubuntu:20.04", BASES) == "FROM ubuntu:20.04"
    assert apt_pin.pin_from("FROM --platform=linux/amd64 debian:bullseye-slim", BASES).endswith(
        "debian:bullseye-slim@" + BASES["debian:bullseye-slim"]
    )
    assert apt_pin.pin_dockerfile("RUN true\n", TS) == "RUN true\n"


def test_with_build_pins_inlines_an_escaped_dockerfile(tmp_path: Path) -> None:
    write(tmp_path, "app/Dockerfile", DOCKERFILE)
    write(tmp_path, "db/Dockerfile", "FROM mysql:5.7\n")
    spec = {
        "services": {
            "web": {"build": {"context": "./app", "args": ["FLAG"]}},
            "db": {"build": "./db"},
            "cache": {"image": "redis:7"},
        }
    }
    out = apt_pin.with_build_pins(spec, tmp_path, TS, BASES)
    web = out["services"]["web"]["build"]
    assert "dockerfile" not in web and web["args"] == ["FLAG"]
    assert "$$FLAG" in web["dockerfile_inline"] and "$$C" in web["dockerfile_inline"]
    assert out["services"]["db"] == {"build": "./db"}  # nothing to pin: left as is
    assert spec["services"]["web"]["build"] == {"context": "./app", "args": ["FLAG"]}
    reparsed = yaml.safe_load(yaml.safe_dump(out))
    assert reparsed["services"]["web"]["build"]["dockerfile_inline"].count("FROM ") == 2


def test_copy_from_images_are_pinned_but_stages_are_not() -> None:
    bases = {"composer:latest": "sha256:" + "c" * 64}
    assert apt_pin.pin_copy_from(
        "COPY --from=composer:latest /usr/bin/composer /usr/bin/", bases
    ) == ("COPY --from=composer:latest@sha256:" + "c" * 64 + " /usr/bin/composer /usr/bin/")
    assert (
        apt_pin.pin_copy_from("COPY --from=builder /app /app", bases)
        == "COPY --from=builder /app /app"
    )
    assert (
        apt_pin.pin_copy_from("COPY --chown=1:1 --from=composer:latest /a /b", bases).count("@")
        == 1
    )


PIP_DOCKERFILE = """FROM python:3.9-slim
RUN apt-get update && apt-get install -y curl
RUN pip install python-dotenv
RUN pip3 install -r requirements.txt
FROM nginx
COPY --from=0 /app /app
"""
PINS = ("langchain==0.3.26", "python-dotenv==1.1.1")


def test_pip_pins_hold_every_pip_install_in_the_stage() -> None:
    out = apt_pin.pin_dockerfile(PIP_DOCKERFILE, TS, {}, PINS).splitlines()
    assert out[0] == "FROM python:3.9-slim" and out[1].startswith(
        "RUN if [ -f /etc/debian_version ]"
    )
    assert out[2] == (
        "RUN printf '%s\\n' 'langchain==0.3.26' 'python-dotenv==1.1.1'"
        " > /etc/itsuite-pip-constraints.txt"
    )
    assert out[3] == "ENV PIP_CONSTRAINT=/etc/itsuite-pip-constraints.txt"
    assert out[4] == "RUN apt-get update && apt-get install -y curl"
    nginx = out.index("FROM nginx")
    assert not any("PIP_CONSTRAINT" in line for line in out[nginx:])  # no pip in that stage
    assert apt_pin.pin_dockerfile(PIP_DOCKERFILE, "", {}, ()) == PIP_DOCKERFILE


def test_pip_pins_must_be_exact_and_shell_safe(tmp_path: Path) -> None:
    for bad in ("langchain~=0.3.25", "streamlit", "x==1'; touch /pwned; '"):
        with pytest.raises(ValueError, match="exact"):
            apt_pin.pip_step([bad])
    with pytest.raises(ValueError, match="no pins"):
        apt_pin.pip_step([])
    path = write(
        tmp_path,
        "pins.txt",
        "# resolved 2025-06-25\n\nLangChain==0.3.26\nuvicorn[standard]==0.34.3\n",
    )
    assert apt_pin.read_pins(path) == ("LangChain==0.3.26", "uvicorn[standard]==0.34.3")
