#!/usr/bin/env bash
# Gitleaks 8.30.1 over the files in the view (no git history). Secrets are redacted.
# Usage: secrets.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version gitleaks "8.30.1"
gitleaks dir "$src" --report-format sarif --report-path "$out/results.sarif" \
  --exit-code 0 --no-banner --redact
