#!/usr/bin/env bash
# ZAP 2.17.0 (container): spider, passive and active scan, SARIF report.
# The ZAP container uses host networking only to reach the 127.0.0.1 gateway.
# Usage: dast.sh <target_url> <out_dir>
set -euo pipefail
url="$1"; out="$2"
image="zaproxy/zap-stable:2.17.0@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
python3 -I - "$url" "$out/plan.yaml" "${ITS_WALL_SECONDS:-3600}" "${ITS_INPUT_DIR:-}" <<'PY'
import json, pathlib, sys
url, path, wall, input_dir = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
minutes = max(1, wall // 60 - 5)
auth_file = pathlib.Path(input_dir, "auth.json") if input_dir else None
auth = json.loads(auth_file.read_text()) if auth_file and auth_file.exists() else {}
# An OpenAPI document from the target's setup is input every tool gets (ADAPTERS.md rule 3).
openapi = [{"type": "openapi", "parameters": {"apiUrl": auth["openapi_url"], "targetUrl": url}}
           ] if auth.get("openapi_url") else []
plan = {
  "env": {"contexts": [{"name": "target", "urls": [url]}],
          "parameters": {"failOnError": True, "progressToStdout": True}},
  "jobs": openapi + [
    {"type": "spider", "parameters": {"maxDuration": max(1, minutes // 4)}},
    {"type": "passiveScan-wait"},
    {"type": "activeScan", "parameters": {"maxScanDurationInMins": max(1, minutes // 2)}},
    {"type": "report", "parameters": {"template": "sarif-json", "reportDir": "/zap/wrk",
                                      "reportFile": "results.sarif"}},
  ],
}
open(path, "w").write(json.dumps(plan))  # JSON is valid YAML
PY
docker run --rm --network host -v "$out":/zap/wrk:rw "$image" zap.sh -cmd -autorun /zap/wrk/plan.yaml
# ZAP's sarif-json template appends .json to the report name.
if [ -s "$out/results.sarif.json" ]; then mv "$out/results.sarif.json" "$out/results.sarif"; fi
test -s "$out/results.sarif"
