#!/usr/bin/env bash
# Semgrep CE 1.186.0 with the p/default registry ruleset. Metrics are off.
# Note: registry rulesets change over time; the run records the date (METHODOLOGY 4).
# Usage: sast.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version semgrep "1.186.0"
semgrep scan --config p/default --sarif --output "$out/results.sarif" --metrics=off --quiet "$src"
