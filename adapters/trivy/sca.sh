#!/usr/bin/env bash
# Trivy 0.76.2 dependency scan. The vulnerability database is downloaded at run time
# and changes daily; the run's date is recorded.
# Usage: sca.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version trivy "0.76.2"
trivy fs --scanners vuln --format sarif --output "$out/results.sarif" --quiet "$src"
