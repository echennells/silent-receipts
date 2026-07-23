# Silent Receipts

**Receipts for Bitcoin silent payments (BIP352): prove one payment — or one non-payment — to one
chosen verifier, without revealing your scan key.**

Built at bitcoin++ Toronto 2026. Crypto core: [bdk-sp](https://github.com/bitcoindevkit/bdk-sp)
(the bitcoindevkit silent payments toolkit). Think of it as **Monero's `InProof`/`OutProof`,
ported to Bitcoin** — deliberately, and stated up front.

## Why

Silent payments give a receiver one static address (`sp1…`) whose payments land on fresh,
random-looking taproot outputs. Nobody can see what you received — that's the feature. But
invisibility cuts both ways:

- **Attack 1 — the fake payment claim.** A scammer points at *any* transaction: "that was me
  paying you, where's my refund?" You're the only person alive who can tell it's a lie — and
  until now, proving it meant surrendering your scan key: every payment, past and future, forever.
- **Attack 2 — the payment denial.** A merchant who *was* paid says "never arrived, send again."
  Nothing on-chain publicly connects the payment to them, so the lie is cheap.

Silent Receipts settles both, one transaction at a time, with a ~130-byte bundle. Master keys
never move.

## One primitive, four sentences

Reveal the per-transaction ECDH shared secret `S`, bound by a BIP374 DLEQ proof to the published
scan key and the transaction's own inputs. The verifier — using **public chain data only** —
re-derives every slot where a payment to the address could exist (`P_k = B_spend + hash(S‖k)·G`)
and looks:

| | "YES, paid" | "NO, not paid" |
|---|---|---|
| **Receiver proves** | payment receipt | "tx T paid me nothing" |
| **Sender proves** | "I paid you" (BIP375 territory — future work) | "my tx didn't pay that address" |

This tool implements the receiver row. The DLEQ is belt-and-suspenders for the "yes" — and
**load-bearing for the "no"**: without it, a liar reveals a wrong secret, every slot looks empty,
and a false "nothing arrived" verifies. The proof forces the real tour.

**Ownership tier** (`--own`): the prover additionally signs the challenge with each derived output
key `p_k = b_spend + t_k` (BIP340), upgrading "I *detected* this payment" to "I detected it **and
can spend it**" — a receipt no delegated scanner can forge.

## Quickstart

```bash
# native (Rust >= 1.75)
cargo build --release

# 1. keys + address (signet); OpenTimestamp the address immediately — see Security model
./target/release/receipt keygen --network signet

# 2. get paid: send a silent payment to the printed tsp1… address
#    (e.g. Dana wallet on signet), then cache the tx:
scripts/fetch_tx.sh <txid> signet

# 3. mint the receipt (add --own for the ownership tier)
./target/release/receipt prove --txid <txid> --verifier judge --own

# 4. verify — public data only, works offline
./target/release/receipt verify --bundle data/bundles/<file>.json

# GUI
RECEIPT_BIN=target/release/receipt python3 web/serve.py   # http://localhost:8552
```

Or containerized:

```bash
docker compose up --build            # GUI on :8552
docker compose run --rm receipts receipt keygen --network signet
```

A **non-payment receipt** is minted the same way: run `prove` against a transaction that did *not*
pay the address — the bundle's claim becomes `not_paid`, and the verifier proves the absence.

## Architecture

```
bitcoin 0.32 (via bdk_sp re-export)
   └── bdk-sp crates (pinned rev): tweak-data, ECDH, scanning, DLEQ, address codec
         └── receipt (this repo, ~500 lines): cache adapter, bundle format,
             claim logic, spend-sig tier, verdict JSON
               └── web/serve.py + index.html: display only — every gram of
                   crypto is in the CLI; the GUI is a subprocess bridge
```

Chain data comes from mempool.space's esplora API, cached to disk on first fetch
(`scripts/fetch_tx.sh`) — proving and verifying then run fully offline. No node required.

## Security model — read before trusting a receipt

- **Soundness rests on pre-commitment, not the DLEQ.** An attacker who crafts a *fresh* address
  after seeing the chain can bind it to any existing taproot output (the DLEQ never constrains
  `B_spend`). A receipt is only meaningful for an address that **provably pre-dates the
  transaction** — so timestamp your address (e.g. [OpenTimestamps](https://opentimestamps.org))
  the moment you create it. `receipt keygen` prints the command.
- **Scope.** Every statement is about *this address* (base code, no labels) in *this transaction*.
  A non-payment receipt does **not** claim "I was never paid anywhere under any address I could
  derive" — BIP352 labels make that unprovable short of revealing the scan key (the same reason
  Monero can't prove non-receipt across subaddresses). Bilateral disputes name the exact address,
  which is exactly the sound case.
- **What a receipt never proves:** the payer's identity (it binds outputs to keys, not people),
  or completeness of your history. Auditors who need "you disclosed everything" need viewing-key
  disclosure — a different, older tool. Without `--own`, a receiver receipt proves scan-key
  control (detection), not spendability.
- Revealing `S` discloses every output paying this code *in that transaction* (per-tx granularity,
  not per-output).

## License

MIT
