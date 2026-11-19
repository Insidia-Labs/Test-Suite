"""Re-check the suite's CWE ChildOf edges against MITRE's CWE XML (CWE-1000 view).

Usage: python scripts/check_cwe_families.py path/to/cwec_vX.Y.xml.zip
Download the file from https://cwe.mitre.org/data/xml/cwec_latest.xml.zip first.
Exits 1 if any edge in CWE_CHILD_OF is not a ChildOf link in that release.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from itsuite.cwe import CWE_CHILD_OF


def parents_by_cwe(archive: Path) -> dict[int, set[int]]:
    with zipfile.ZipFile(archive) as bundle:
        root = ET.fromstring(bundle.read(bundle.namelist()[0]))
    namespace = root.tag.split("}")[0].strip("{")
    parents: dict[int, set[int]] = {}
    for weakness in root.iter(f"{{{namespace}}}Weakness"):
        links = weakness.iter(f"{{{namespace}}}Related_Weakness")
        parents[int(weakness.get("ID", "0"))] = {
            int(link.get("CWE_ID", "0"))
            for link in links
            if link.get("Nature") == "ChildOf" and link.get("View_ID") == "1000"
        }
    return parents


def main(archive: Path) -> int:
    parents = parents_by_cwe(archive)
    bad = [
        (child, parent)
        for child, wanted in CWE_CHILD_OF.items()
        for parent in wanted
        if parent not in parents.get(child, set())
    ]
    for child, parent in bad:
        print(f"not in MITRE's data: CWE-{child} ChildOf CWE-{parent}")
    edges = sum(len(p) for p in CWE_CHILD_OF.values())
    print(f"{edges} ChildOf edges checked, {len(bad)} problems")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(Path(sys.argv[1])))
