#!/usr/bin/env bash
# The most gratuitous possible use of OpenTimestamps.
#
# Exactly ONE of these timestamps is load-bearing: the address. The soundness of
# every receipt rests on the address provably pre-dating the transaction — OTS
# turns that assumption into an artifact.
#
# Everything after that is tribute:
#   pass 1: the address, every receipt bundle, the README, the source, the
#           binary, the web page, the server, and this script itself
#   pass 2: every timestamp proof produced by pass 1  (the proofs of the proofs)
#
# We stop at depth two only because the calendar servers asked us nicely.
set -euo pipefail

OTS="${OTS_BIN:-$HOME/.venvs/ots/bin/ots}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ART="$ROOT/data/ots/artifacts"
mkdir -p "$ART" "$ROOT/data/ots/verifications"

command -v "$OTS" >/dev/null || { echo "ots client not found at $OTS" >&2; exit 1; }

# --- the load-bearing one: the address (pre-commitment) ---------------------
if [ -f "$ROOT/data/keys.json" ]; then
  python3 -c "import json;print(json.load(open('$ROOT/data/keys.json'))['address'],end='')" \
    > "$ART/address.txt"
fi

# --- pass 1: copy public artifacts in, stamp anything unstamped -------------
# If a file changed since it was stamped, drop the stale proof and restamp:
# a timestamp for bytes you no longer serve proves nothing about the bytes you do.
copy_in() {
  [ -f "$1" ] || return 0
  local cp_path="$ART/$(basename "$1")"
  if [ -e "$cp_path" ] && ! cmp -s "$1" "$cp_path"; then
    rm -f "$cp_path.ots" "$cp_path.ots.ots"
  fi
  cp -f "$1" "$cp_path"
}
copy_in "$ROOT/README.md"
copy_in "$ROOT/Cargo.toml"
copy_in "$ROOT/src/main.rs"
copy_in "$ROOT/web/index.html"
copy_in "$ROOT/web/serve.py"
copy_in "$ROOT/receipt"
copy_in "$ROOT/scripts/ots_everything.sh"          # yes, this script stamps itself
for b in "$ROOT"/data/bundles/*.json; do copy_in "$b"; done

to_stamp=()
for f in "$ART"/*; do
  case "$f" in *.ots) continue;; esac
  [ -e "$f.ots" ] || to_stamp+=("$f")
done
if [ "${#to_stamp[@]}" -gt 0 ]; then
  echo "pass 1: stamping ${#to_stamp[@]} artifact(s)..." >&2
  "$OTS" stamp "${to_stamp[@]}"
fi

# --- pass 2: stamp the stamps ------------------------------------------------
meta=()
for f in "$ART"/*.ots; do
  case "$f" in *.ots.ots) continue;; esac
  [ -e "$f.ots" ] || meta+=("$f")
done
if [ "${#meta[@]}" -gt 0 ]; then
  echo "pass 2: stamping ${#meta[@]} proof(s) of proofs..." >&2
  "$OTS" stamp "${meta[@]}"
fi

echo "done. $(ls "$ART" | grep -c '\.ots$') timestamp proofs on disk." >&2
