#!/usr/bin/env bash
# Upgrade pending OTS proofs to Bitcoin-anchored ones. Calendars commit their
# aggregation tree to Bitcoin on their own schedule (roughly hourly), so run
# this periodically; each completed proof becomes independently verifiable
# against Bitcoin headers with no trusted server.
set -uo pipefail
OTS="${OTS_BIN:-$HOME/.venvs/ots/bin/ots}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
shopt -s nullglob
for f in "$ROOT"/data/ots/artifacts/*.ots "$ROOT"/data/ots/verifications/*.ots; do
  "$OTS" upgrade "$f" >/dev/null 2>&1 || true
done
