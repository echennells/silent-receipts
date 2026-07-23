#!/usr/bin/env bash
# Fetch a transaction + its prevouts from mempool.space's esplora API into the
# local cache, so `receipt prove` / `receipt verify` run fully offline.
#
#   scripts/fetch_tx.sh <txid> [signet|mainnet|testnet]     (default: signet)
set -euo pipefail

TXID="${1:?usage: fetch_tx.sh <txid> [signet|mainnet|testnet]}"
NET="${2:-signet}"
CACHE="${CACHE_DIR:-data/cache}"

case "$NET" in
  mainnet) BASE="https://mempool.space/api" ;;
  signet)  BASE="https://mempool.space/signet/api" ;;
  testnet) BASE="https://mempool.space/testnet/api" ;;
  *) echo "unknown network: $NET" >&2; exit 1 ;;
esac

mkdir -p "$CACHE"

echo "fetching $TXID from $BASE ..." >&2
curl -fsS "$BASE/tx/$TXID/hex" -o "$CACHE/$TXID.hex"

# Prevouts in input order: esplora inlines each input's prevout.
curl -fsS "$BASE/tx/$TXID" \
  | jq '[.vin[] | {scriptpubkey: .prevout.scriptpubkey, value: .prevout.value}]' \
  > "$CACHE/$TXID.prevouts.json"

N_IN=$(jq length "$CACHE/$TXID.prevouts.json")
echo "cached: $CACHE/$TXID.hex + $CACHE/$TXID.prevouts.json ($N_IN inputs)" >&2
