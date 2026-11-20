"""Rewrite a target's compose file so it can't reach the internet.

Every network becomes ``internal: true`` and published ports are removed. For each
exposed port, a small socat gateway joins the target's network and an edge network
and listens on 127.0.0.1 only. The gateway forwards inbound connections; it can't
route the target's own traffic out. Compose features that would break out of the
sandbox are refused before anything starts.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from typing import Any

from itsuite.models import Expose

GATEWAY_IMAGE = (
    "alpine/socat:1.8.1.3@sha256:71131702f671a88b3808a70b7330f9679cd9b9933adcafadc191508edfe55bba"
)
PROBE_IMAGE = (
    "curlimages/curl:8.23.0@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93"
)
EDGE_NETWORK = "its-edge"
_RISKY_CAPS = frozenset({
    "ALL", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_RAW", "DAC_READ_SEARCH",
    "SYS_RAWIO", "BPF", "PERFMON", "SYS_BOOT", "SYS_TIME", "SYSLOG", "MAC_ADMIN",
    "MAC_OVERRIDE", "LINUX_IMMUTABLE",
})  # fmt: skip
_NAMESPACE_KEYS = ("pid", "ipc", "uts", "cgroup", "userns_mode")


class IsolationError(RuntimeError):
    """The target's compose file can't be run safely, or isolation failed."""


def _volume_source(volume: Any) -> str:
    if isinstance(volume, str):
        return volume.split(":", 1)[0] if ":" in volume else ""
    if isinstance(volume, Mapping) and volume.get("type", "volume") == "bind":
        return str(volume.get("source", ""))
    return ""


def _bind_problem(source: str) -> str:
    """Why a volume source is unsafe, or "" when it is a named volume or a path inside
    the project. Only plain relative paths that stay inside the project are allowed."""
    if not source or ("/" not in source and not source.startswith(".")):
        return ""  # a named volume
    if "docker.sock" in source:
        return "mounts the Docker socket"
    if "$" in source:
        return f"bind source uses a variable: {source}"
    if source.startswith(("/", "~")) or ".." in source.replace("\\", "/").split("/"):
        return f"binds a path outside the project: {source}"
    return ""


def _network_mode_problem(name: str, service: Mapping[str, Any], services: set[str]) -> str:
    mode = str(service.get("network_mode", ""))
    if not mode or mode == "none":
        return ""
    if mode.startswith("service:") and mode.removeprefix("service:") in services:
        return ""
    return f"{name}: network_mode {mode} (only none or service:<one of this project>)"


def _host_problems(name: str, service: Mapping[str, Any]) -> list[str]:
    problems = []
    for key in _NAMESPACE_KEYS:
        value = str(service.get(key, ""))
        if value == "host" or value.startswith("container:"):
            problems.append(f"{name}: {key}: {value}")
    if service.get("privileged"):
        problems.append(f"{name}: privileged")
    if service.get("devices"):
        problems.append(f"{name}: devices")
    if service.get("extends"):
        problems.append(f"{name}: extends pulls in a file the suite doesn't check")
    if any(str(v).startswith("container:") for v in service.get("volumes_from") or ()):
        problems.append(f"{name}: volumes_from another container")
    return problems


def _service_violations(name: str, service: Mapping[str, Any], services: set[str]) -> list[str]:
    problems = _host_problems(name, service)
    mode = _network_mode_problem(name, service, services)
    if mode:
        problems.append(mode)
    caps = {str(c).upper().removeprefix("CAP_") for c in service.get("cap_add") or ()}
    if caps & _RISKY_CAPS:
        problems.append(f"{name}: cap_add {sorted(caps & _RISKY_CAPS)}")
    if any("unconfined" in str(opt) for opt in service.get("security_opt") or ()):
        problems.append(f"{name}: security_opt unconfined")
    for volume in service.get("volumes") or ():
        problem = _bind_problem(_volume_source(volume))
        if problem:
            problems.append(f"{name}: {problem}")
    return problems


def _top_level_violations(spec: Mapping[str, Any]) -> list[str]:
    problems = ["include pulls in files the suite doesn't check"] if spec.get("include") else []
    for name, network in (spec.get("networks") or {}).items():
        if isinstance(network, Mapping) and network.get("external"):
            problems.append(f"network {name}: external networks can't be made internal")
    for name, volume in (spec.get("volumes") or {}).items():
        opts = (volume or {}).get("driver_opts") or {} if isinstance(volume, Mapping) else {}
        if isinstance(volume, Mapping) and (volume.get("external") or "device" in opts):
            problems.append(f"volume {name}: external or host-device volumes aren't allowed")
    return problems


def violations(spec: Mapping[str, Any]) -> list[str]:
    services = spec.get("services") or {}
    names = {str(n) for n in services}
    problems = [
        problem
        for name, service in services.items()
        for problem in _service_violations(str(name), service or {}, names)
    ]
    return problems + _top_level_violations(spec)


def container_port(entry: Any) -> int | None:
    """The container side of a compose ports entry, short or long syntax."""
    if isinstance(entry, Mapping):
        target = entry.get("target")
        return int(target) if target is not None else None
    text = str(entry).split("/", 1)[0]
    last = text.rsplit(":", 1)[-1]
    first = last.split("-", 1)[0]
    return int(first) if first.isdigit() else None


def auto_exposes(spec: Mapping[str, Any]) -> list[Expose]:
    exposes = []
    for name, service in (spec.get("services") or {}).items():
        for entry in (service or {}).get("ports") or ():
            port = container_port(entry)
            if port is not None and Expose(str(name), port) not in exposes:
                exposes.append(Expose(str(name), port))
    return exposes


def _service_networks(service: Mapping[str, Any]) -> list[str]:
    networks = service.get("networks")
    if isinstance(networks, Mapping):
        return [str(n) for n in networks]
    if isinstance(networks, list):
        return [str(n) for n in networks]
    return ["default"]


def _env_dict(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    pairs = (str(item).split("=", 1) for item in value or ())
    return {pair[0]: pair[1] if len(pair) > 1 else "" for pair in pairs}


def _with_build_args(build: Any, args: Mapping[str, str]) -> Any:
    if not args or build is None:
        return build
    spec = {"context": build} if isinstance(build, str) else dict(build)
    spec["args"] = {**_env_dict(spec.get("args")), **args}
    return spec


def _isolated_service(
    service: Mapping[str, Any], env: Mapping[str, str], build_args: Mapping[str, str]
) -> dict[str, Any]:
    # ports: published ports would bypass the gateway; container_name: fixed names collide
    # between runs. Both go.
    new = {k: copy.deepcopy(v) for k, v in service.items() if k not in ("ports", "container_name")}
    if env:
        new["environment"] = {**_env_dict(service.get("environment")), **env}
    if "build" in service:
        new["build"] = _with_build_args(service["build"], build_args)
    if service.get("expose"):
        # expose is internal-only and takes container ports; some targets write
        # "3306:3306", which newer compose rejects. Keep the container side.
        ports = (container_port(e) for e in service["expose"])
        new["expose"] = [str(port) for port in ports if port is not None]
    return new


def _gateway(expose: Expose, host_port: int, network: str) -> dict[str, Any]:
    return {
        "image": GATEWAY_IMAGE,
        "command": [
            f"TCP-LISTEN:{expose.port},fork,reuseaddr",
            f"TCP:{expose.service}:{expose.port}",
        ],
        "networks": [network, EDGE_NETWORK],
        "ports": [f"127.0.0.1:{host_port}:{expose.port}"],
        "depends_on": [expose.service],
        "restart": "unless-stopped",
    }


def gateway_name(expose: Expose) -> str:
    return f"its-gateway-{expose.service}-{expose.port}"


def isolate(
    spec: Mapping[str, Any],
    host_ports: Mapping[Expose, int],
    env: Mapping[str, str] | None = None,
    build_args: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """A new compose spec with internal networks, no published ports, and gateways."""
    problems = violations(spec)
    if problems:
        raise IsolationError("refusing to run: " + "; ".join(problems))
    services = dict(spec.get("services") or {})
    for expose in host_ports:
        if expose.service not in services:
            raise IsolationError(f"exposed service {expose.service!r} is not in the compose file")
    new_services = {
        str(name): _isolated_service(svc or {}, env or {}, build_args or {})
        for name, svc in services.items()
    }
    for expose, host_port in host_ports.items():
        network = _service_networks(services[expose.service])[0]
        new_services[gateway_name(expose)] = _gateway(expose, host_port, network)
    networks = {
        str(name): {**(cfg or {}), "internal": True}
        for name, cfg in (spec.get("networks") or {}).items()
    }
    networks.setdefault("default", {"internal": True})
    networks[EDGE_NETWORK] = {"driver": "bridge"}
    top = {k: copy.deepcopy(v) for k, v in spec.items() if k not in ("services", "networks")}
    return {**top, "services": new_services, "networks": networks}


def target_networks(isolated: Mapping[str, Any], project: str) -> list[str]:
    """Docker names of the networks the target's own services use, for the egress probe."""
    used: list[str] = []
    for name, service in (isolated.get("services") or {}).items():
        if str(name).startswith("its-gateway-") or (service or {}).get("network_mode"):
            continue
        used += [n for n in _service_networks(service or {}) if n not in used]
    configs = isolated.get("networks") or {}
    names = []
    for network in used:
        cfg = configs.get(network) or {}
        names.append(str(cfg["name"]) if cfg.get("name") else f"{project}_{network}")
    return names
