#!/usr/bin/env bash
# TruffleHog 3.99.9 over the view. Verification is off so found secrets are never sent
# to the services they belong to.
# Usage: secrets.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version trufflehog "3.99.9"
trufflehog filesystem "$src" --json --no-update --no-verification > "$out/results.jsonl"
