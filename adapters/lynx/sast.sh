#!/usr/bin/env bash
# Lynx scan of the source view. Lynx runs gitleaks and OSV-Scanner, which must be
# installed too (`itsuite tools install gitleaks osv-scanner`).
# Usage: sast.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version lynx "0.0.1"
# Lynx already follows the contract: exit 0 when the scan finished (a missing detector
# is reported inside the SARIF as an incomplete run), 2 when nothing could run.
lynx scan "$src" --sarif "$out/results.sarif"
