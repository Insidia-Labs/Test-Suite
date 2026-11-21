#!/usr/bin/env bash
# OSV-Scanner 2.7.1, recursive source scan.
# Usage: sca.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version osv-scanner "2.7.1"
set +e; osv-scanner scan source -r --format sarif --output "$out/results.sarif" "$src"; code=$?; set -e
# 0 = no vulnerabilities, 1 = vulnerabilities found; anything else did not finish.
finished_if "$code" 0 1
