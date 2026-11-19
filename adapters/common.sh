#!/usr/bin/env bash
# Shared helpers for adapters. Contract (ADAPTERS.md): exit 0 when the tool finished,
# whatever it found; non-zero when it did not finish. Write output to the out folder.

# require_version <tool-command> <expected substring>
# Refuses to run an unpinned version: a different version gives different results.
require_version() {
  local cmd="$1" want="$2" have
  have=$("$cmd" --version 2>&1 | head -3 || true)
  # Whole version only: 1.9.4 must not accept 1.9.40 or 11.9.4.
  if ! grep -qE "(^|[^0-9.])${want//./\\.}([^0-9.]|$)" <<<"$have"; then
    echo "itsuite: $cmd version '$want' is pinned, found: ${have:-nothing}" >&2
    exit 3
  fi
  # Record the exact build that ran (e.g. a commit after the tag) next to the results.
  if [[ -n "${ITS_OUT_DIR:-}" ]]; then printf '%s\n' "$have" > "$ITS_OUT_DIR/tool-version.txt"; fi
}

# finished_if <exit code> <codes that mean the tool finished...>
finished_if() {
  local code="$1"; shift
  for ok in "$@"; do [[ "$code" == "$ok" ]] && return 0; done
  echo "itsuite: tool exited $code" >&2
  exit "$code"
}
