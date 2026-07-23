#!/usr/bin/env bash
# The CLI demo: the raw tool, no GUI. Run from the repo root.
#   scripts/cli_demo.sh "Peter"        <- addressee for the live-minted receipt
set -euo pipefail
R="${RECEIPT_BIN:-./receipt}"
VER="${1:-a judge}"
TXID=$(python3 -c "import json;print(json.load(open('data/bundles/auditor-receipt.json'))['txid'])")

step() { echo; echo "──────────────────────────────────────────────"; echo "── $1"; echo "\$ $2"; echo; }

step "The published identity (the silent payment code)" "receipt address"
$R address

step "Verify the auditor receipt — public chain data only, no keys, offline" \
     "receipt verify --bundle data/bundles/auditor-receipt.json"
$R verify --bundle data/bundles/auditor-receipt.json

step "Mint a receipt addressed to '$VER' — live, ownership tier on" \
     "receipt prove --txid ${TXID:0:8}… --verifier '$VER' --own"
$R prove --txid "$TXID" --verifier "$VER" --own \
   --out data/bundles/live-receipt-cli.json >/dev/null
echo "minted: data/bundles/live-receipt-cli.json (bound to '$VER' — replay-proof)"

step "Verify it" "receipt verify --bundle data/bundles/live-receipt-cli.json"
$R verify --bundle data/bundles/live-receipt-cli.json

step "Flip ONE hex digit of the secret — watch the whole thing die" "tamper + verify"
python3 - <<'EOF'
import json
b = json.load(open("data/bundles/live-receipt-cli.json"))
s = list(b["shared_secret"])
s[10] = "0" if s[10] != "0" else "1"
b["shared_secret"] = "".join(s)
json.dump(b, open("data/bundles/live-receipt-cli-tampered.json", "w"), indent=2)
print("tampered one nibble of shared_secret")
EOF
$R verify --bundle data/bundles/live-receipt-cli-tampered.json

echo
echo "── done. cleanup: rm data/bundles/live-receipt-cli*.json (or the wallet page's 'reset demo')"
