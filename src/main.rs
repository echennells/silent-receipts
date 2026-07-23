//! Silent Receipts — receipts for BIP352 silent payments.
//!
//! One primitive: reveal the per-transaction ECDH shared secret `S`, bound by a
//! BIP374 DLEQ proof to the receiver's published scan key and the transaction's
//! own inputs, and let anyone recompute — from public chain data only — where
//! payments to a silent payment code could land in that transaction.
//!
//!   receipt keygen  --network signet
//!   receipt prove   --keys data/keys.json --txid <txid> --verifier <name> [--own]
//!   receipt verify  --bundle data/bundles/<file>.json
//!
//! Chain data is read from a local cache (see scripts/fetch_tx.sh) so proving
//! and verifying work fully offline.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Read;
use std::process::exit;

use bdk_sp::bitcoin::absolute::LockTime;
use bdk_sp::bitcoin::consensus::encode::deserialize as consensus_deserialize;
use bdk_sp::bitcoin::consensus::encode::serialize_hex;
use bdk_sp::bitcoin::hashes::{sha256, Hash};
use bdk_sp::bitcoin::key::Parity;
use bdk_sp::bitcoin::secp256k1::{
    schnorr, Keypair, Message, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bdk_sp::bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bdk_sp::bitcoin::transaction::Version;
use bdk_sp::bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bdk_sp::compute_shared_secret;
use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::hashes::get_input_hash;
use bdk_sp::receive::{compute_tweak_data, get_silentpayment_script_pubkey, scan_txouts};
use bdk_sp::LexMin;
use dleq::{dleq_generate_proof, dleq_verify_proof};
use serde::{Deserialize, Serialize};

const BUNDLE_VERSION: &str = "silent-receipts/v0";

const SCOPE_NOTE: &str = "Scope: statements are about THIS address (base code, no labels) in THIS \
transaction only. A non-payment proof does not claim 'never paid anywhere under any derivable \
address' — no scheme can prove that short of revealing the scan key.";

// ---------- serialized formats ----------

#[derive(Serialize, Deserialize)]
struct KeysFile {
    network: String,
    scan_sk: String,
    spend_sk: String,
    address: String,
}

#[derive(Serialize, Deserialize)]
struct PrevoutJson {
    scriptpubkey: String,
    value: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct BundleOutput {
    vout: u32,
    k: u32,
    amount_sats: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    spend_sig: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    version: String,
    network: String,
    address: String,
    txid: String,
    verifier: String,
    /// "paid" or "not_paid" — what this receipt claims about (txid, address).
    claim: String,
    /// 33-byte compressed ECDH shared secret S, hex.
    shared_secret: String,
    /// 64-byte BIP374 DLEQ proof binding S to (scan key, tx inputs), hex.
    dleq_proof: String,
    outputs: Vec<BundleOutput>,
}

#[derive(Serialize, Deserialize)]
struct Step {
    step: String,
    ok: bool,
    detail: String,
}

#[derive(Serialize, Deserialize)]
struct VerdictOutput {
    vout: u32,
    amount_sats: u64,
    spend_sig: String,
}

#[derive(Serialize, Deserialize)]
struct Verdict {
    verdict: String,
    address: String,
    txid: String,
    verifier: String,
    claim: String,
    outputs: Vec<VerdictOutput>,
    steps: Vec<Step>,
    scope_note: String,
}

// ---------- small helpers ----------

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(1);
}

fn urandom32() -> [u8; 32] {
    let mut f = fs::File::open("/dev/urandom").unwrap_or_else(|e| die(&format!("urandom: {e}")));
    let mut b = [0u8; 32];
    f.read_exact(&mut b)
        .unwrap_or_else(|e| die(&format!("urandom read: {e}")));
    b
}

/// The secp256k1 generator as a PublicKey (1·G) — bdk-sp's dleq takes G as a parameter.
fn generator() -> PublicKey {
    let secp = Secp256k1::new();
    let mut one = [0u8; 32];
    one[31] = 1;
    PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&one).expect("1 is a valid secret key"),
    )
}

/// Challenge binding a receipt to one verifier and one transaction (anti-replay).
fn challenge(verifier: &str, txid: &str, address: &str) -> [u8; 32] {
    let data = format!("{BUNDLE_VERSION}|challenge|{verifier}|{txid}|{address}");
    sha256::Hash::hash(data.as_bytes()).to_byte_array()
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Load a transaction + its prevouts (in input order) from the local cache.
fn load_tx(cache: &str, txid: &str) -> Result<(Transaction, Vec<TxOut>), String> {
    let hexpath = format!("{cache}/{txid}.hex");
    let pvpath = format!("{cache}/{txid}.prevouts.json");
    let txhex = fs::read_to_string(&hexpath)
        .map_err(|e| format!("{hexpath}: {e} — run scripts/fetch_tx.sh {txid} first"))?;
    let raw = hex::decode(txhex.trim()).map_err(|e| format!("tx hex decode: {e}"))?;
    let tx: Transaction =
        consensus_deserialize(&raw).map_err(|e| format!("tx deserialize: {e}"))?;
    let pvraw = fs::read_to_string(&pvpath)
        .map_err(|e| format!("{pvpath}: {e} — run scripts/fetch_tx.sh {txid} first"))?;
    let pvs: Vec<PrevoutJson> =
        serde_json::from_str(&pvraw).map_err(|e| format!("prevouts parse: {e}"))?;
    if pvs.len() != tx.input.len() {
        return Err(format!(
            "prevout count {} != input count {}",
            pvs.len(),
            tx.input.len()
        ));
    }
    let prevouts = pvs
        .iter()
        .map(|p| {
            Ok(TxOut {
                value: Amount::from_sat(p.value),
                script_pubkey: ScriptBuf::from_hex(&p.scriptpubkey)
                    .map_err(|e| format!("prevout scriptpubkey: {e}"))?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((tx, prevouts))
}

fn load_keys(path: &str) -> (KeysFile, SecretKey, SecretKey) {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|e| die(&format!("{path}: {e} — run `receipt keygen` first")));
    let keys: KeysFile =
        serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("keys parse: {e}")));
    let scan_sk = SecretKey::from_slice(
        &hex::decode(&keys.scan_sk).unwrap_or_else(|e| die(&format!("scan_sk hex: {e}"))),
    )
    .unwrap_or_else(|e| die(&format!("scan_sk: {e}")));
    let spend_sk = SecretKey::from_slice(
        &hex::decode(&keys.spend_sk).unwrap_or_else(|e| die(&format!("spend_sk hex: {e}"))),
    )
    .unwrap_or_else(|e| die(&format!("spend_sk: {e}")));
    (keys, scan_sk, spend_sk)
}

/// Terminal failure inside `verify`: emit an INVALID verdict JSON and exit 0
/// (the verdict itself is the output — the GUI renders it either way).
fn fail_verdict(bundle: &Bundle, mut steps: Vec<Step>, step: &str, detail: String) -> ! {
    steps.push(Step {
        step: step.into(),
        ok: false,
        detail,
    });
    let verdict = Verdict {
        verdict: "INVALID".into(),
        address: bundle.address.clone(),
        txid: bundle.txid.clone(),
        verifier: bundle.verifier.clone(),
        claim: bundle.claim.clone(),
        outputs: vec![],
        steps,
        scope_note: SCOPE_NOTE.into(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&verdict).expect("serialize")
    );
    exit(0);
}

// ---------- commands ----------

fn cmd_keygen(args: &[String]) {
    let network = flag(args, "--network").unwrap_or_else(|| "signet".into());
    let out = flag(args, "--out").unwrap_or_else(|| "data/keys.json".into());
    let net = match network.as_str() {
        "mainnet" | "bitcoin" => Network::Bitcoin,
        "signet" => Network::Signet,
        "testnet" => Network::Testnet,
        "regtest" => Network::Regtest,
        other => die(&format!("unknown network {other}")),
    };
    let secp = Secp256k1::new();
    let scan_sk = SecretKey::from_slice(&urandom32()).expect("urandom scalar");
    let spend_sk = SecretKey::from_slice(&urandom32()).expect("urandom scalar");
    let code = SilentPaymentCode::new_v0(
        PublicKey::from_secret_key(&secp, &scan_sk),
        PublicKey::from_secret_key(&secp, &spend_sk),
        net,
    );
    let address = code.to_string();
    let keys = KeysFile {
        network,
        scan_sk: hex::encode(scan_sk.secret_bytes()),
        spend_sk: hex::encode(spend_sk.secret_bytes()),
        address: address.clone(),
    };
    if let Some(dir) = std::path::Path::new(&out).parent() {
        fs::create_dir_all(dir).unwrap_or_else(|e| die(&format!("mkdir: {e}")));
    }
    fs::write(&out, serde_json::to_string_pretty(&keys).expect("serialize"))
        .unwrap_or_else(|e| die(&format!("write {out}: {e}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&out, fs::Permissions::from_mode(0o600));
    }
    eprintln!("keys written to {out} (mode 600) — KEEP PRIVATE, never commit");
    eprintln!("timestamp this address NOW:   echo -n '{address}' > address.txt && ots stamp address.txt");
    println!("{address}");
}

fn cmd_address(args: &[String]) {
    let keys_path = flag(args, "--keys").unwrap_or_else(|| "data/keys.json".into());
    let (keys, _, _) = load_keys(&keys_path);
    println!("{}", keys.address);
}

fn cmd_prove(args: &[String]) {
    let keys_path = flag(args, "--keys").unwrap_or_else(|| "data/keys.json".into());
    let txid = flag(args, "--txid").unwrap_or_else(|| die("--txid required"));
    let cache = flag(args, "--cache").unwrap_or_else(|| "data/cache".into());
    let verifier = flag(args, "--verifier").unwrap_or_else(|| "verifier".into());
    let own = has_flag(args, "--own");

    let (keys, scan_sk, spend_sk) = load_keys(&keys_path);
    let secp = Secp256k1::new();
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

    let (tx, prevouts) = load_tx(&cache, &txid).unwrap_or_else(|e| die(&e));
    let real_txid = tx.compute_txid().to_string();
    if real_txid != txid {
        die(&format!("cache file txid mismatch: {real_txid} != {txid}"));
    }

    // B = input_hash · A_sum — the DLEQ base point, computable from public tx data.
    let tweak_point = compute_tweak_data(&tx, &prevouts).unwrap_or_else(|e| {
        die(&format!(
            "compute_tweak_data: {e:?} (no BIP352-eligible inputs?)"
        ))
    });
    // S = b_scan · B — the per-transaction shared secret.
    let shared_secret = compute_shared_secret(&scan_sk, &tweak_point);

    // Which outputs of this tx (if any) pay this code? Empty label map: base address only.
    let founds = scan_txouts(spend_pk, &BTreeMap::new(), &tx, shared_secret)
        .unwrap_or_else(|e| die(&format!("scan_txouts: {e:?}")));

    let claim = if founds.is_empty() { "not_paid" } else { "paid" };
    let m = challenge(&verifier, &txid, &keys.address);
    let proof = dleq_generate_proof(scan_sk, tweak_point, &urandom32(), generator(), Some(&m))
        .unwrap_or_else(|e| die(&format!("dleq_generate_proof: {e:?}")));

    let mut outputs = Vec::new();
    for (k, spout) in founds.iter().enumerate() {
        let spend_sig = if own {
            // Ownership tier: sign the challenge with the derived output key
            // p_k = b_spend + t_k — proves we can SPEND, not just detect.
            let p_k = spend_sk
                .add_tweak(&Scalar::from(spout.tweak))
                .unwrap_or_else(|e| die(&format!("p_k tweak: {e}")));
            let keypair = Keypair::from_secret_key(&secp, &p_k);
            let sig = secp.sign_schnorr_with_aux_rand(
                &Message::from_digest(m),
                &keypair,
                &urandom32(),
            );
            Some(sig.to_string())
        } else {
            None
        };
        outputs.push(BundleOutput {
            vout: spout.outpoint.vout,
            k: k as u32,
            amount_sats: spout.amount.to_sat(),
            spend_sig,
        });
    }

    let bundle = Bundle {
        version: BUNDLE_VERSION.into(),
        network: keys.network.clone(),
        address: keys.address.clone(),
        txid: txid.clone(),
        verifier,
        claim: claim.into(),
        shared_secret: hex::encode(shared_secret.serialize()),
        dleq_proof: hex::encode(proof),
        outputs,
    };

    let default_out = format!("data/bundles/{}-{}.json", &txid[..8.min(txid.len())], claim);
    let out = flag(args, "--out").unwrap_or(default_out);
    if let Some(dir) = std::path::Path::new(&out).parent() {
        fs::create_dir_all(dir).unwrap_or_else(|e| die(&format!("mkdir: {e}")));
    }
    let json = serde_json::to_string_pretty(&bundle).expect("serialize");
    fs::write(&out, &json).unwrap_or_else(|e| die(&format!("write {out}: {e}")));
    eprintln!(
        "receipt bundle ({claim}, {} output(s)) written to {out}",
        bundle.outputs.len()
    );
    println!("{json}");
}

fn cmd_verify(args: &[String]) {
    let bundle_path = flag(args, "--bundle").unwrap_or_else(|| die("--bundle required"));
    let cache = flag(args, "--cache").unwrap_or_else(|| "data/cache".into());

    let mut steps: Vec<Step> = Vec::new();
    let secp = Secp256k1::new();

    let raw =
        fs::read_to_string(&bundle_path).unwrap_or_else(|e| die(&format!("{bundle_path}: {e}")));
    let bundle: Bundle =
        serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("bundle parse: {e}")));

    // 1. Parse the silent payment code from the bundle's address string.
    let code = match SilentPaymentCode::try_from(bundle.address.as_str()) {
        Ok(c) => {
            steps.push(Step {
                step: "parse_address".into(),
                ok: true,
                detail: format!("scan + spend keys extracted from {}", bundle.address),
            });
            c
        }
        Err(e) => fail_verdict(&bundle, steps, "parse_address", format!("{e:?}")),
    };

    // 2. Load the transaction from the local cache and confirm its txid.
    let (tx, prevouts) = match load_tx(&cache, &bundle.txid) {
        Ok(v) => v,
        Err(e) => fail_verdict(&bundle, steps, "load_transaction", e),
    };
    let real_txid = tx.compute_txid().to_string();
    if real_txid != bundle.txid {
        fail_verdict(
            &bundle,
            steps,
            "load_transaction",
            format!(
                "cached tx hashes to {real_txid}, bundle says {}",
                bundle.txid
            ),
        );
    }
    steps.push(Step {
        step: "load_transaction".into(),
        ok: true,
        detail: format!(
            "txid verified against raw tx bytes; {} inputs, {} outputs",
            tx.input.len(),
            tx.output.len()
        ),
    });

    // 3. Recompute B = input_hash · A_sum from the transaction's own inputs.
    let tweak_point = match compute_tweak_data(&tx, &prevouts) {
        Ok(b) => {
            steps.push(Step {
                step: "recompute_input_tweak".into(),
                ok: true,
                detail: "B = input_hash · (sum of eligible input pubkeys), from public data"
                    .into(),
            });
            b
        }
        Err(e) => fail_verdict(&bundle, steps, "recompute_input_tweak", format!("{e:?}")),
    };

    // 4. Verify the DLEQ: S is THE genuine shared secret for (scan key, this tx).
    let shared_secret = match hex::decode(&bundle.shared_secret)
        .map_err(|e| e.to_string())
        .and_then(|b| PublicKey::from_slice(&b).map_err(|e| e.to_string()))
    {
        Ok(p) => p,
        Err(e) => fail_verdict(&bundle, steps, "parse_shared_secret", e),
    };
    let proof: [u8; 64] = match hex::decode(&bundle.dleq_proof)
        .map_err(|e| e.to_string())
        .and_then(|v| <[u8; 64]>::try_from(v.as_slice()).map_err(|_| "want 64 bytes".to_string()))
    {
        Ok(p) => p,
        Err(e) => fail_verdict(&bundle, steps, "parse_dleq_proof", e),
    };
    let m = challenge(&bundle.verifier, &bundle.txid, &bundle.address);
    match dleq_verify_proof(
        code.scan,
        tweak_point,
        shared_secret,
        &proof,
        generator(),
        Some(&m),
    ) {
        Ok(true) => steps.push(Step {
            step: "verify_dleq".into(),
            ok: true,
            detail: "S provably derived from the address's scan key and THIS tx's inputs \
                     (bound to this verifier via challenge)"
                .into(),
        }),
        Ok(false) => fail_verdict(
            &bundle,
            steps,
            "verify_dleq",
            "DLEQ proof did not verify — the shared secret is NOT trustworthy; bundle rejected"
                .into(),
        ),
        Err(e) => fail_verdict(&bundle, steps, "verify_dleq", format!("{e}")),
    }

    // 5. With the genuine S, derive every possible payment slot and compare.
    let founds = match scan_txouts(code.spend, &BTreeMap::new(), &tx, shared_secret) {
        Ok(f) => f,
        Err(e) => fail_verdict(&bundle, steps, "scan_outputs", format!("{e:?}")),
    };
    steps.push(Step {
        step: "scan_outputs".into(),
        ok: true,
        detail: format!(
            "derived candidate outputs P_k = B_spend + hash(S‖k)·G; {} match(es) in tx",
            founds.len()
        ),
    });

    let mut outputs: Vec<VerdictOutput> = Vec::new();
    let verdict_str = match bundle.claim.as_str() {
        "paid" => {
            if founds.is_empty() {
                fail_verdict(
                    &bundle,
                    steps,
                    "check_claim",
                    "claim is 'paid' but no output matches the genuine secret".into(),
                );
            }
            let found_vouts: Vec<u32> = founds.iter().map(|s| s.outpoint.vout).collect();
            for b_out in &bundle.outputs {
                if !found_vouts.contains(&b_out.vout) {
                    fail_verdict(
                        &bundle,
                        steps,
                        "check_claim",
                        format!("bundle lists vout {} but it does not match", b_out.vout),
                    );
                }
            }
            steps.push(Step {
                step: "check_claim".into(),
                ok: true,
                detail: format!(
                    "PAID: output(s) {found_vouts:?} of this tx are payments to this address"
                ),
            });
            // Optional ownership tier: BIP340 signature under each derived output key.
            for spout in &founds {
                let b_out = bundle
                    .outputs
                    .iter()
                    .find(|o| o.vout == spout.outpoint.vout);
                let sig_status = match b_out.and_then(|o| o.spend_sig.as_ref()) {
                    Some(sig_hex) => {
                        let sig_ok = (|| -> Option<bool> {
                            let sig_bytes = hex::decode(sig_hex).ok()?;
                            let sig = schnorr::Signature::from_slice(&sig_bytes).ok()?;
                            let spk = spout.script_pubkey.as_bytes();
                            let xonly = XOnlyPublicKey::from_slice(spk.get(2..34)?).ok()?;
                            Some(
                                secp.verify_schnorr(&sig, &Message::from_digest(m), &xonly)
                                    .is_ok(),
                            )
                        })()
                        .unwrap_or(false);
                        if !sig_ok {
                            fail_verdict(
                                &bundle,
                                steps,
                                "verify_spend_sig",
                                format!(
                                    "spend signature for vout {} INVALID",
                                    spout.outpoint.vout
                                ),
                            );
                        }
                        steps.push(Step {
                            step: "verify_spend_sig".into(),
                            ok: true,
                            detail: format!(
                                "vout {}: prover holds the SPEND key (not just scan) — \
                                 ownership, not mere detection",
                                spout.outpoint.vout
                            ),
                        });
                        "valid".to_string()
                    }
                    None => "none".to_string(),
                };
                outputs.push(VerdictOutput {
                    vout: spout.outpoint.vout,
                    amount_sats: spout.amount.to_sat(),
                    spend_sig: sig_status,
                });
            }
            "PAID_PROVEN"
        }
        "not_paid" => {
            if !founds.is_empty() {
                fail_verdict(
                    &bundle,
                    steps,
                    "check_claim",
                    format!(
                        "claim is 'not_paid' but output(s) {:?} DO pay this address — \
                         the claim is false",
                        founds.iter().map(|s| s.outpoint.vout).collect::<Vec<_>>()
                    ),
                );
            }
            steps.push(Step {
                step: "check_claim".into(),
                ok: true,
                detail: "NOT PAID: no output of this tx derives from the genuine secret for \
                         this address"
                    .into(),
            });
            "NOT_PAID_PROVEN"
        }
        other => fail_verdict(&bundle, steps, "check_claim", format!("unknown claim '{other}'")),
    };

    let result = Verdict {
        verdict: verdict_str.into(),
        address: bundle.address,
        txid: bundle.txid,
        verifier: bundle.verifier,
        claim: bundle.claim,
        outputs,
        steps,
        scope_note: SCOPE_NOTE.into(),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).expect("serialize")
    );
}

#[derive(Serialize, Deserialize)]
struct SenderFile {
    network: String,
    privkey: String,
    xonly: String,
    address: String,
}

/// Construct, derive, and sign a real BIP352 silent payment from a single
/// P2TR key-path UTXO held by the demo's sender wallet. Prints {txid, hex};
/// broadcasting is the caller's job (the server POSTs it to esplora).
fn cmd_send(args: &[String]) {
    let sender_path = flag(args, "--sender").unwrap_or_else(|| "data/sender.json".into());
    let utxo = flag(args, "--utxo").unwrap_or_else(|| die("--utxo txid:vout:value:spk_hex"));
    let amount: u64 = flag(args, "--amount")
        .unwrap_or_else(|| "21000".into())
        .parse()
        .unwrap_or_else(|e| die(&format!("--amount: {e}")));
    let fee: u64 = flag(args, "--fee")
        .unwrap_or_else(|| "400".into())
        .parse()
        .unwrap_or_else(|e| die(&format!("--fee: {e}")));
    let to = flag(args, "--to").unwrap_or_else(|| {
        let (keys, _, _) = load_keys(&flag(args, "--keys").unwrap_or_else(|| "data/keys.json".into()));
        keys.address
    });

    let secp = Secp256k1::new();
    let raw = fs::read_to_string(&sender_path)
        .unwrap_or_else(|e| die(&format!("{sender_path}: {e}")));
    let sender: SenderFile =
        serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("sender parse: {e}")));
    let mut sk = SecretKey::from_slice(
        &hex::decode(&sender.privkey).unwrap_or_else(|e| die(&format!("privkey hex: {e}"))),
    )
    .unwrap_or_else(|e| die(&format!("privkey: {e}")));
    // Taproot key-path + BIP352 both want the even-Y key; normalize defensively.
    let (xonly, parity) = Keypair::from_secret_key(&secp, &sk).x_only_public_key();
    if parity == Parity::Odd {
        sk = sk.negate();
    }
    let keypair = Keypair::from_secret_key(&secp, &sk);

    let code = SilentPaymentCode::try_from(to.as_str())
        .unwrap_or_else(|e| die(&format!("recipient code: {e:?}")));

    // --utxo txid:vout:value:spk_hex
    let parts: Vec<&str> = utxo.split(':').collect();
    if parts.len() != 4 {
        die("--utxo must be txid:vout:value:spk_hex");
    }
    let txid: bdk_sp::bitcoin::Txid =
        parts[0].parse().unwrap_or_else(|e| die(&format!("utxo txid: {e}")));
    let vout: u32 = parts[1].parse().unwrap_or_else(|e| die(&format!("utxo vout: {e}")));
    let value: u64 = parts[2].parse().unwrap_or_else(|e| die(&format!("utxo value: {e}")));
    let spk = ScriptBuf::from_hex(parts[3]).unwrap_or_else(|e| die(&format!("utxo spk: {e}")));
    let mut expect = vec![0x51u8, 0x20];
    expect.extend_from_slice(&xonly.serialize());
    if spk.as_bytes() != expect.as_slice() {
        die("utxo scriptpubkey does not match the sender key");
    }
    if value <= amount + fee {
        die(&format!("utxo too small: {value} <= {} needed", amount + fee));
    }

    // BIP352 sender-side derivation for a single taproot key-path input:
    // S = (input_hash · a) · B_scan, output = B_spend + hash(S‖0)·G.
    let outpoint = OutPoint::new(txid, vout);
    let mut lex_min = LexMin::default();
    lex_min.update(&outpoint);
    let a_sum_pub = xonly.public_key(Parity::Even);
    let input_hash = get_input_hash(
        &lex_min.bytes().unwrap_or_else(|e| die(&format!("lex_min: {e}"))),
        &a_sum_pub,
    );
    let combined = sk
        .mul_tweak(&input_hash)
        .unwrap_or_else(|e| die(&format!("scalar combine: {e}")));
    let shared_secret = code
        .scan
        .mul_tweak(&secp, &Scalar::from(combined))
        .unwrap_or_else(|e| die(&format!("ecdh: {e}")));
    let sp_spk = get_silentpayment_script_pubkey(&code.spend, &shared_secret, 0, None);

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: sp_spk,
    }];
    let change = value - amount - fee;
    if change >= 330 {
        outputs.push(TxOut {
            value: Amount::from_sat(change),
            script_pubkey: spk.clone(),
        });
    }
    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: outputs,
    };

    let prevout = TxOut {
        value: Amount::from_sat(value),
        script_pubkey: spk,
    };
    let sighash = SighashCache::new(&tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&[prevout]), TapSighashType::Default)
        .unwrap_or_else(|e| die(&format!("sighash: {e}")));
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &urandom32());
    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    tx.input[0].witness = witness;

    let out = serde_json::json!({
        "txid": tx.compute_txid().to_string(),
        "hex": serialize_hex(&tx),
        "to": to,
        "amount_sats": amount,
        "fee_sats": fee,
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("serialize"));
}

fn usage() -> ! {
    eprintln!(
        "silent-receipts — receipts for BIP352 silent payments

USAGE:
  receipt keygen  [--network signet|mainnet|testnet|regtest] [--out data/keys.json]
  receipt address [--keys data/keys.json]
  receipt prove   --txid <txid> [--keys data/keys.json] [--cache data/cache]
                  [--verifier <name>] [--own] [--out <bundle.json>]
  receipt verify  --bundle <bundle.json> [--cache data/cache]
  receipt send    --utxo txid:vout:value:spk_hex [--to <sp code>] [--amount 21000]
                  [--fee 400] [--sender data/sender.json]

Fetch chain data first:  scripts/fetch_tx.sh <txid> [signet|mainnet]"
    );
    exit(2);
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("keygen") => cmd_keygen(&args),
        Some("address") => cmd_address(&args),
        Some("prove") => cmd_prove(&args),
        Some("verify") => cmd_verify(&args),
        Some("send") => cmd_send(&args),
        _ => usage(),
    }
}
