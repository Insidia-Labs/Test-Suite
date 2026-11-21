#!/usr/bin/env bash
# Argus (insidia CLI) against a live URL: one L1 scan, SARIF to the out folder.
# Usage: dast.sh <target_url> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
url="$1"; out="$2"
require_version insidia "1.0.0"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
cd "$work"
# The config is written here rather than by `insidia init`, which only accepts local
# hosts. In a sealed run the target is the suite's gateway (e.g. its-gateway-web-80), an
# isolated lab host, so it is listed in scope with authorized: true; that is the scope
# setting Argus asks for before it scans a non-local host.
# Argus defaults a URL target to POST; a crawlable web app is read with GET. Session
# cookies from the target's setup (input/auth.json, the same file every tool gets) are
# sent as a Cookie header.
python3 -I - "$url" "${ITS_ARGUS_KIND:-web}" "${ITS_ARGUS_METHOD:-GET}" "${ITS_INPUT_DIR:-}" <<'PY'
import json, pathlib, sys, urllib.parse
url, kind, method, input_dir = sys.argv[1:5]
host = urllib.parse.urlparse(url).hostname or ""
local = {"localhost", "127.0.0.1", "::1"}
scope = [f"  - host: {json.dumps(h)}" for h in sorted(local)]
if host not in local:
    scope.append(f"  - host: {json.dumps(host)}\n    authorized: true")
auth = pathlib.Path(input_dir, "auth.json") if input_dir else None
cookies = json.loads(auth.read_text()).get("cookies", {}) if auth and auth.exists() else {}
headers = []
if cookies:
    value = "; ".join(f"{k}={v}" for k, v in cookies.items())
    headers = ["    headers:", f"      Cookie: {json.dumps(value)}"]
lines = ["version: 1", "policy: L1", "coverage: standard", "scope:", *scope, "targets:",
         "  app:", f"    kind: {kind}", f"    url: {json.dumps(url)}", f"    method: {method}",
         *headers, "    rate_limit:", "      rps: 5", "      concurrency: 1"]
pathlib.Path("insidia.yaml").write_text("\n".join(lines) + "\n")
PY
set +e; insidia scan --policy L1 --json --yes > "$out/argus-scan.json"; code=$?; set -e
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
