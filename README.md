# Silent Receipts

**Receipts for Bitcoin silent payments (BIP352): prove one payment — or one non-payment — to one
chosen verifier, without revealing your scan key.**

Built at bitcoin++ Toronto 2026. Crypto core: [bdk-sp](https://github.com/bitcoindevkit/bdk-sp)
(the bitcoindevkit silent payments toolkit). Think of it as **Monero's `InProof`/`OutProof`,
ported to Bitcoin** — deliberately, and stated up front.

## Two strings, never conflated

- **The silent payment code** — `sp1…` (mainnet) / `tsp1…` (signet). The thing you *publish*: on
  a website, an invoice, a DM. It is your payment identity, and it **never appears on-chain**.
- **The on-chain output** — an ordinary-looking `bc1p…` taproot output inside some transaction,
  where money actually lands. Nothing public connects any output to any silent payment code.

When someone pays your code, their wallet derives a fresh output from (their transaction's input
keys × your code). Only you, holding the **scan key**, can find it. Everywhere below, "code"
means the `sp1…` string and "output" means the on-chain coin.

## Why

Nobody can see what your code received — that's the feature. But invisibility cuts both ways:

- **Attack 1 — the fake payment claim.** A scammer points at *any* transaction: "that was me
  paying your code — where's my refund?" Nothing on-chain can confirm or deny that any output
  belongs to your code, so you were the only person alive who knew he was lying — and proving it
  used to mean surrendering your scan key: every payment, past and future, forever.
- **Attack 2 — the payment denial.** A merchant who *was* paid to his published code says "never
  arrived, send again." No public data connects the payment's output to his code, so the lie is
  cheap.

Silent Receipts settles both, one transaction at a time, with a ~130-byte bundle. Master keys
never move.

## One primitive, four sentences

Reveal the per-transaction ECDH shared secret `S`, bound by a BIP374 DLEQ proof to the published
code's scan key and the transaction's own inputs. The verifier — using **public chain data
only** — re-derives every slot where a payment to the code could exist
(`P_k = B_spend + hash(S‖k)·G`) and looks:

| | "YES, paid" | "NO, not paid" |
|---|---|---|
| **Receiver proves** | payment receipt | "tx T paid my code nothing" |
| **Sender proves** | "I paid you" (BIP375 territory — future work) | "my tx didn't pay that code" |

This tool implements the receiver row. The DLEQ is belt-and-suspenders for the "yes" — and
**load-bearing for the "no"**: without it, a liar reveals a wrong secret, every slot looks empty,
and a false "nothing arrived" verifies. The proof forces the real tour.

**Ownership tier** (`--own`): the prover additionally signs the challenge with each derived output
key `p_k = b_spend + t_k` (BIP340), upgrading "I *detected* this payment" to "I detected it **and
can spend it**" — a receipt no delegated scanner can forge.

## The three uses — and which one needs a timestamp

One machine, three situations. What changes is who is looking at the receipt, and whether they
already have independent knowledge of your code:

| Use | You show it to | Receipt says | Code must be timestamped? |
|---|---|---|---|
| **The auditor case** — "this payment went to me" | A stranger to your code: accountant, exchange, arbitrator you just met | "tx T paid my code" | **Yes — load-bearing** |
| **Attack 1 defense** — "you never paid me" | An arbitrator, against the (self-claimed) sender | "tx T paid my code *nothing*" | No |
| **Attack 2 offense** — "he was paid and denies it" | An arbitrator, with the payer present | "tx T paid the code he published" | No |

**The auditor case is the original point of the tool.** The scan key is all-or-nothing: hand it
to an accountant and they see every payment you have ever received or ever will receive. A
receipt inverts the deal — the auditor learns about **exactly one transaction**, verifies it
against public chain data, and the scan key never leaves your machine:

```bash
./target/release/receipt prove --txid <txid> --verifier accountant --own
# hand over the bundle; they run:
./target/release/receipt verify --bundle <bundle>.json
```

**Why only the auditor needs the timestamp.** In both attacks, the *other side* pins the code
before the argument starts: the scammer's own claim is "I paid *your published code*," and the
payer in attack 2 can produce the invoice that handed her the code — she needed it before she
could pay it. A stranger has no such anchor. Without evidence that your code pre-dates the
transaction, they cannot rule out that you built the code *backwards* around someone's existing
fat output (see Security model). The timestamp is that evidence. **Bilateral disputes never need
it; receipts shown to strangers are worthless without it.**

## Quickstart

```bash
# native (Rust >= 1.75)
cargo build --release

# 1. keys + code (signet); OpenTimestamp the code immediately — see Security model
./target/release/receipt keygen --network signet

# 2. get paid: send a silent payment to the printed tsp1… code
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
pay the code — the bundle's claim becomes `not_paid`, and the verifier proves the absence.

## Architecture

```
bitcoin 0.32 (via bdk_sp re-export)
   └── bdk-sp crates (pinned rev): tweak-data, ECDH, scanning, DLEQ, code codec
         └── receipt (this repo, ~500 lines): cache adapter, bundle format,
             claim logic, spend-sig tier, verdict JSON
               └── web/serve.py + index.html: display only — every gram of
                   crypto is in the CLI; the GUI is a subprocess bridge
```

Chain data comes from mempool.space's esplora API, cached to disk on first fetch
(`scripts/fetch_tx.sh`) — proving and verifying then run fully offline. No node required.

## Security model — read before trusting a receipt

- **Soundness rests on pre-commitment, not the DLEQ.** An attacker who crafts a *fresh* silent
  payment code after seeing the chain can bind it to any existing taproot output (the DLEQ never
  constrains `B_spend`) and "prove" that a stranger's coins were paid to them. A "yes" receipt is
  only meaningful to a verifier with evidence that the code **pre-dates the transaction**. People
  you transact with have that evidence in their own records (see *The three uses*); for
  strangers, timestamp the code (e.g. [OpenTimestamps](https://opentimestamps.org)) the moment
  you create it — `receipt keygen` prints the command. The `--own` signature narrows this forgery
  to the attacker's *own* coins (fake provenance, not fake ownership); the timestamp closes it
  entirely.
- **Scope.** Every statement is about *this silent payment code* (base variant, no labels) in
  *this transaction*. A non-payment receipt does **not** claim "I was never paid anywhere under
  any code I could derive" — BIP352 labels make that unprovable short of revealing the scan key
  (the same reason Monero can't prove non-receipt across subaddresses). Bilateral disputes name
  the exact code, which is exactly the sound case.
- **What a receipt never proves:** the payer's identity (it binds outputs to keys, not people),
  or completeness of your history. Auditors who need "you disclosed everything" need viewing-key
  disclosure — a different, older tool. Without `--own`, a receiver receipt proves scan-key
  control (detection), not spendability.
- Revealing `S` discloses every output paying this code *in that transaction* (per-tx
  granularity, not per-output).

## OpenTimestamps (gratuitous)

Exactly **one** timestamp in this project is load-bearing: **the silent payment code**. The
auditor case above rests on the code provably pre-dating the transaction, and an
[OpenTimestamps](https://opentimestamps.org) attestation turns that assumption into an artifact.

We did not stop there. `scripts/ots_everything.sh` stamps: the code, every receipt bundle,
this README, the source, the compiled binary, the web page, the server, **and itself** — then
makes a second pass and stamps **the proofs of the proofs**. (We stop at depth two only because
the calendar servers asked us nicely.) The demo server goes further: every verification anyone
triggers through the GUI is written to disk and timestamped — *the act of checking a receipt is
itself receipted* — and the page shows a live counter (`GET /timestamps`). The `ots` client is
baked into the container image, so a fresh clone gets the full tribute with `docker compose up`.

## License

MIT
