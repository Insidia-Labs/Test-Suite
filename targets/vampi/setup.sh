#!/usr/bin/env bash
# VAmPI setup: create the database and record where the OpenAPI document is.
# Usage: setup.sh <base_url> <variant> <input_dir>
set -euo pipefail
base="${1%/}"
out="$3"
for _ in $(seq 1 60); do curl -fsS "$base/createdb" >/dev/null 2>&1 && break; sleep 2; done
curl -fsS "$base/createdb" >/dev/null
spec=""
for path in openapi.json openapi.yaml; do
  if curl -fsS -o /dev/null "$base/$path"; then spec="$base/$path"; break; fi
done
printf '{"openapi_url": "%s"}\n' "$spec" > "$out/auth.json"
echo "VAmPI ready; OpenAPI at ${spec:-<not found>}"
