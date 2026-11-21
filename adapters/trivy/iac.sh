#!/usr/bin/env bash
# Trivy 0.76.2 misconfiguration scan (Terraform, CloudFormation, Kubernetes, Dockerfile).
# Usage: iac.sh <source_dir> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
src="$1"; out="$2"
require_version trivy "0.76.2"
trivy config --format sarif --output "$out/results.sarif" --quiet "$src"
