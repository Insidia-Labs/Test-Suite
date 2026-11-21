#!/usr/bin/env bash
# Bandit 1.9.4 (Python only), SARIF via the bandit[sarif] extra.
# Usage: sast.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version bandit "1.9.4"
bandit -r "$src" -f sarif -o "$out/results.sarif" --exit-zero -q
