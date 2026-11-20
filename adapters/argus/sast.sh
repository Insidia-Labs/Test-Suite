#!/usr/bin/env bash
# Argus repository scan of the source view (a `kind: repo` target).
# Usage: sast.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version insidia "1.0.0"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$work"
# Argus only scans a repo inside the folder that holds its config, so scan a copy of the
# view there; the view itself stays untouched and Argus sees exactly the same files.
cp -a "$src" repo
printf 'version: 1\npolicy: L1\ncoverage: standard\nscope:\n  - host: localhost\ntargets:\n  repo:\n    kind: repo\n    path: repo\n' > insidia.yaml
set +e; insidia scan --policy L1 --json > "$out/argus-scan.json"; code=$?; set -e
# Argus exit codes: 0 policy passed, 1 a check found a problem, 2 incomplete or error,
# 130 cancelled. Exit 2 covers both a finished-but-inconclusive scan and a crash, so its
# own --json execution_status decides: "complete" means it finished.
if [[ "$code" == 2 ]] && python3 -I -c 'import json,sys; sys.exit(json.load(open(sys.argv[1])).get("execution_status") != "complete")' "$out/argus-scan.json"; then
  code=0
fi
finished_if "$code" 0 1
run=$(ls -td .insidia/runs/*/ | head -1)
cp "$run/results.sarif" "$out/results.sarif"
