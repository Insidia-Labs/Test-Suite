#!/usr/bin/env bash
# Argus (insidia CLI) against a live URL: one L1 scan, SARIF to the out folder.
# Usage: dast.sh <target_url> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
url="$1"; out="$2"
require_version insidia "1.0.0"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$work"
insidia init --url "$url" --kind "${ITS_ARGUS_KIND:-web}" >/dev/null
# Argus defaults a URL target to POST; a crawlable web app is read with GET. Session
# cookies from the target's setup (input/auth.json, the same file every tool gets) are
# sent as a Cookie header.
python3 -I - "${ITS_ARGUS_METHOD:-GET}" "${ITS_INPUT_DIR:-}" <<'PY'
import json, pathlib, sys
method, input_dir = sys.argv[1], sys.argv[2]
config = pathlib.Path("insidia.yaml")
lines = config.read_text().splitlines()
at = next(i for i, line in enumerate(lines) if line.startswith("    url:")) + 1
extra = [f"    method: {method}"]
auth = pathlib.Path(input_dir, "auth.json") if input_dir else None
cookies = json.loads(auth.read_text()).get("cookies", {}) if auth and auth.exists() else {}
if cookies:
    header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    extra += ["    headers:", f"      Cookie: {json.dumps(header)}"]
config.write_text("\n".join(lines[:at] + extra + lines[at:]) + "\n")
PY
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
cp "$run/findings.json" "$out/argus-findings.json" 2>/dev/null || true
cp "$run/benchmark.json" "$out/argus-benchmark.json" 2>/dev/null || true
