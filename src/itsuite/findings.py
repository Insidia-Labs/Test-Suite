"""Normalize tool output into one finding type. SARIF 2.1.0 is the main format."""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from itsuite.cwe import extract_cwes
from itsuite.models import OutputFormat


class FindingsError(ValueError):
    """Tool output could not be read."""


@dataclass(frozen=True)
class Finding:
    rule: str
    cwes: tuple[int, ...]
    path: str = ""
    start_line: int | None = None
    end_line: int | None = None
    url: str = ""
    logical: tuple[str, ...] = ()
    message: str = ""
    level: str = ""

    def locator_text(self) -> str:
        return " ".join(part for part in (self.path, self.url, *self.logical) if part)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "cwes": list(self.cwes),
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "url": self.url,
            "logical": list(self.logical),
            "message": self.message[:500],
            "level": self.level,
        }


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable) and not isinstance(value, Mapping):
        return [str(item) for item in value]
    return []


def _taxon_ids(items: Any) -> list[str]:
    """CWE ids from SARIF taxa or relationships whose tool component is CWE."""
    ids = []
    for item in items or ():
        ref = item.get("target", item) if isinstance(item, Mapping) else {}
        component = (ref.get("toolComponent") or {}).get("name", "")
        if str(component).upper() == "CWE" and ref.get("id"):
            ids.append(f"CWE-{ref['id']}".replace("CWE-CWE-", "CWE-"))
    return ids


def _cwes(result: Mapping[str, Any], rule: Mapping[str, Any]) -> tuple[int, ...]:
    texts: list[str] = []
    for holder in (result.get("properties") or {}, rule.get("properties") or {}):
        texts += _strings(holder.get("tags")) + _strings(holder.get("cwe"))
        texts += _strings(holder.get("cwe_id"))
    texts += _taxon_ids(result.get("taxa")) + _taxon_ids(rule.get("relationships"))
    texts += [str(result.get("ruleId", "")), str(rule.get("id", ""))]
    return extract_cwes(texts)


def _split_uri(uri: str) -> tuple[str, str]:
    """(path, url): web URLs stay URLs; file URIs and relative paths become paths."""
    if uri.startswith(("http://", "https://")):
        return "", uri
    if uri.startswith("file://"):
        uri = urllib.parse.urlparse(uri).path
    return urllib.parse.unquote(uri).removeprefix("./"), ""


def _location(
    result: Mapping[str, Any],
) -> tuple[str, str, int | None, int | None, tuple[str, ...]]:
    locations = result.get("locations") or [{}]
    first = locations[0] if isinstance(locations[0], Mapping) else {}
    physical = first.get("physicalLocation") or {}
    path, url = _split_uri(str((physical.get("artifactLocation") or {}).get("uri", "")))
    region = physical.get("region") or {}
    start = region.get("startLine")
    end = region.get("endLine", start)
    logical = tuple(
        str(item.get("fullyQualifiedName") or item.get("name"))
        for loc in locations
        if isinstance(loc, Mapping)
        for item in loc.get("logicalLocations") or ()
        if item.get("fullyQualifiedName") or item.get("name")
    )
    return path, url, start, end, logical


def _rules(run: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    tool = run.get("tool") or {}
    components = [tool.get("driver") or {}, *(tool.get("extensions") or [])]
    ordered = list((tool.get("driver") or {}).get("rules") or [])
    by_id = {str(r.get("id")): r for c in components for r in c.get("rules") or []}
    return ordered, by_id


def _finding(result: Mapping[str, Any], ordered: list[Any], by_id: dict[str, Any]) -> Finding:
    index = result.get("ruleIndex")
    rule_id = str(result.get("ruleId", ""))
    rule = by_id.get(rule_id) or (
        ordered[index] if isinstance(index, int) and 0 <= index < len(ordered) else {}
    )
    path, url, start, end, logical = _location(result)
    message = (result.get("message") or {}).get("text", "")
    return Finding(
        rule=rule_id or str(rule.get("id", "")),
        cwes=_cwes(result, rule),
        path=path,
        start_line=start,
        end_line=end,
        url=url,
        logical=logical,
        message=str(message),
        level=str(result.get("level", "")),
    )


# SARIF result kinds that are not problems (a check that passed, or didn't apply).
_NOT_FINDINGS = frozenset({"pass", "notApplicable", "informational"})


def _suppressed(result: Mapping[str, Any]) -> bool:
    """SARIF: a suppression without a status, or with status "accepted", hides the result."""
    return any(
        isinstance(s, Mapping) and s.get("status", "accepted") == "accepted"
        for s in result.get("suppressions") or ()
    )


def _is_finding(result: Any) -> bool:
    return (
        isinstance(result, Mapping)
        and str(result.get("kind", "fail")) not in _NOT_FINDINGS
        and not _suppressed(result)
    )


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FindingsError(f"{path.name}: not readable ({exc})") from exc


def parse_sarif(path: Path) -> list[Finding]:
    data = _read_json(path)
    if not isinstance(data, Mapping) or not isinstance(data.get("runs"), list):
        raise FindingsError(f"{path.name}: SARIF has no runs list")
    findings = []
    try:
        for run in data["runs"]:
            ordered, by_id = _rules(run)
            results = run.get("results") or []
            findings += [_finding(r, ordered, by_id) for r in results if _is_finding(r)]
    except (AttributeError, TypeError, KeyError, ValueError, IndexError) as exc:
        raise FindingsError(f"{path.name}: malformed SARIF ({type(exc).__name__}: {exc})") from exc
    return findings


def sarif_incomplete(path: Path) -> bool:
    """Whether the tool itself says a run didn't finish (executionSuccessful: false).
    Reported next to the score; the findings it did write are still scored."""
    try:
        data = _read_json(path)
        runs = data.get("runs") or [] if isinstance(data, Mapping) else []
        return any(
            inv.get("executionSuccessful") is False
            for run in runs if isinstance(run, Mapping)
            for inv in run.get("invocations") or () if isinstance(inv, Mapping)
        )  # fmt: skip
    except FindingsError:
        return False


def _trufflehog_finding(item: Any) -> Finding:
    meta = ((item.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
    line = meta.get("line")
    return Finding(
        rule=str(item.get("DetectorName", "")),
        cwes=(798,),
        path=str(meta.get("file", "")).removeprefix("./"),
        start_line=line if isinstance(line, int) else None,
        end_line=line if isinstance(line, int) else None,
        message="verified" if item.get("Verified") else "unverified",
    )


def parse_trufflehog(path: Path) -> list[Finding]:
    """TruffleHog --json output: one JSON object per line."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise FindingsError(f"{path.name}: not readable ({exc})") from exc
    findings = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            findings.append(_trufflehog_finding(json.loads(line)))
        except (json.JSONDecodeError, AttributeError, TypeError) as exc:
            raise FindingsError(f"{path.name}:{number}: not a TruffleHog result") from exc
    return findings


def load_findings(path: Path, fmt: OutputFormat) -> list[Finding]:
    if fmt == OutputFormat.SARIF:
        return parse_sarif(path)
    if fmt == OutputFormat.TRUFFLEHOG:
        return parse_trufflehog(path)
    raise FindingsError(f"{fmt.value} output is scored by its own importer, not as findings")
