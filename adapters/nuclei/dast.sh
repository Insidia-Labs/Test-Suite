#!/usr/bin/env bash
# Nuclei 3.11.1 with templates pinned to v10.5.2. Interactsh (outside callbacks) is off:
# targets have no internet access, so those checks could never fire.
# Usage: dast.sh <target_url> <out_dir>
set -euo pipefail
source "$(dirname "$0")/../common.sh"
url="$1"; out="$2"
require_version nuclei "3.11.1"
ref="v10.5.2"
commit="5442582a875f96887bfe403c6de562de460897e7"  # tags can move; the commit can't
templates="${XDG_CACHE_HOME:-$HOME/.cache}/itsuite/nuclei-templates-$commit"
if [ ! -d "$templates" ]; then
  git clone -q --depth 1 --branch "$ref" https://github.com/projectdiscovery/nuclei-templates.git "$templates"
fi
[ "$(git -C "$templates" rev-parse HEAD)" = "$commit" ] || { echo "nuclei templates are not at $commit" >&2; exit 3; }
nuclei -u "$url" -t "$templates" -sarif-export "$out/results.sarif" -silent \
  -disable-update-check -no-interactsh -rate-limit 50
# A finished scan with no results may write no file; record it as an empty run so it
# scores as "found nothing" rather than "no output".
if [ ! -s "$out/results.sarif" ]; then
  printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"nuclei"}},"results":[]}]}\n' > "$out/results.sarif"
fi
