"""Answer-key plugins by key type. A target can only be ``native`` if its key is here."""

from __future__ import annotations

from itsuite.keys import (
    castle,
    creddata,
    documented,
    dvwa,
    flags,
    juice_shop,
    owasp_benchmark,
    real_cves,
)
from itsuite.keys.base import KeyPlugin

REGISTRY: dict[str, KeyPlugin] = {
    plugin.key_type: plugin
    for plugin in (
        owasp_benchmark.PLUGIN,
        juice_shop.MARKERS,
        juice_shop.CHALLENGES,
        dvwa.PLUGIN,
        documented.PLUGIN,
        castle.PLUGIN,
        creddata.PLUGIN,
        real_cves.CWE_BENCH_JAVA,
        real_cves.OSSF_CVE,
        flags.XBOW,
        flags.DVMCP,
        flags.DVLA,
        flags.AI_GOAT,
    )
}

# Key types scored by the benchmark's own grader; the suite imports the results.
UPSTREAM_KEYS = frozenset({"agentdojo", "upstream-jsonl"})


def plugin(key_type: str) -> KeyPlugin:
    if key_type not in REGISTRY:
        raise LookupError(f"no answer-key plugin for {key_type!r}")
    return REGISTRY[key_type]
