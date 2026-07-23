//! Integration tests for Silent Receipts.
//!
//! Strategy: construct synthetic BIP352 transactions in-process (no network,
//! no real signet payment needed), cache them to disk, then exercise the full
//! prove → verify pipeline through the `receipt` CLI binary as a subprocess.
//!
//! Run:  cargo test --test integration

use std::fs;
use std::process::Command;

use bdk_sp::bitcoin::absolute::LockTime;
use bdk_sp::bitcoin::consensus::encode::serialize_hex;
use bdk_sp::bitcoin::hashes::sha256;
use bdk_sp::bitcoin::key::Parity;
use bdk_sp::bitcoin::secp256k1::{
    Keypair, PublicKey, Scalar, SecretKey, Secp256k1, XOnlyPublicKey,
};
use bdk_sp::bitcoin::transaction::Version;
use bdk_sp::bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bdk_sp::encoding::SilentPaymentCode;
use bdk_sp::hashes::get_input_hash;
use bdk_sp::receive::get_silentpayment_script_pubkey;
use bdk_sp::LexMin;
use serde::{Deserialize, Serialize};

// ---------- types mirroring the CLI's JSON output ----------

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
    claim: String,
    shared_secret: String,
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
    #[serde(default)]
    scope_note: String,
}

// ---------- test fixture ----------

struct Fixture {
    dir: String,
    address: String,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let dir = format!("/tmp/sr-test-{label}");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&format!("{dir}/cache")).unwrap();
        fs::create_dir_all(&format!("{dir}/bundles")).unwrap();

        let secp = Secp256k1::new();
        let scan_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
        let spend_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
        let code = SilentPaymentCode::new_v0(
            PublicKey::from_secret_key(&secp, &scan_sk),
            PublicKey::from_secret_key(&secp, &spend_sk),
            Network::Signet,
        );
        let address = code.to_string();

        let keys_json = serde_json::json!({
            "network": "signet",
            "scan_sk": hex::encode(scan_sk.secret_bytes()),
            "spend_sk": hex::encode(spend_sk.secret_bytes()),
            "address": address,
        });
        fs::write(
            format!("{dir}/keys.json"),
            serde_json::to_string_pretty(&keys_json).unwrap(),
        )
        .unwrap();

        Fixture { dir, address }
    }

    /// Build a synthetic tx with one P2TR key-path input.
    /// If `pay` is true, the output pays our SP address; otherwise it's junk.
    fn make_tx(&self, pay: bool) -> String {
        let secp = Secp256k1::new();

        // Sender keypair (fake, never broadcast).
        let sender_sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let sender_kp = Keypair::from_secret_key(&secp, &sender_sk);
        let (sender_xonly, parity) = sender_kp.x_only_public_key();
        let sender_sk = if parity == Parity::Odd {
            sender_sk.negate()
        } else {
            sender_sk
        };
        let sender_pk = PublicKey::from_secret_key(&secp, &sender_sk);

        // Sender's P2TR scriptPubKey (the prevout being spent).
        let mut spk_bytes = vec![0x51u8, 0x20];
        spk_bytes.extend_from_slice(&sender_xonly.serialize());
        let sender_spk = ScriptBuf::from_bytes(spk_bytes);

        // Fake outpoint.
        let hash = sha256::Hash::hash(&[0xAA]);
        let outpoint = OutPoint::new(hash.to_byte_array().into(), 0);

        // input_hash = hash(outpoint_L || A_sum)
        let mut lex_min = LexMin::default();
        lex_min.update(&outpoint);
        let input_hash = get_input_hash(&lex_min.bytes().unwrap(), &sender_pk);

        // Shared secret S = (input_hash * a) * B_scan
        let code = SilentPaymentCode::try_from(self.address.as_str()).unwrap();
        let combined = sender_sk.mul_tweak(&input_hash).unwrap();
        let shared_secret = code
            .scan
            .mul_tweak(&secp, &Scalar::from(combined))
            .unwrap();

        let output_spk = if pay {
            get_silentpayment_script_pubkey(&code.spend, &shared_secret, 0, None)
        } else {
            let junk = SecretKey::from_slice(&[0x99; 32]).unwrap();
            let junk_xonly = XOnlyPublicKey::from_secret_key(&secp, &junk);
            let mut s = vec![0x51u8, 0x20];
            s.extend_from_slice(&junk_xonly.serialize());
            ScriptBuf::from_bytes(s)
        };

        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: output_spk,
            }],
        };

        let txid = tx.compute_txid().to_string();
        let tx_hex = serialize_hex(&tx);
        fs::write(format!("{}/cache/{txid}.hex", self.dir), &tx_hex).unwrap();

        let prevouts = vec![PrevoutJson {
            scriptpubkey: sender_spk.to_hex(),
            value: 100_000,
        }];
        fs::write(
            format!("{}/cache/{txid}.prevouts.json", self.dir),
            serde_json::to_string_pretty(&prevouts).unwrap(),
        )
        .unwrap();

        txid
    }

    fn receipt_bin() -> String {
        env!("CARGO_BIN_EXE_receipt").to_string()
    }

    fn prove(&self, txid: &str, verifier: &str, own: bool) -> Bundle {
        let out = format!("{}/bundles/{txid}.json", self.dir);
        let mut cmd = Command::new(Self::receipt_bin());
        cmd.arg("prove")
            .arg("--keys").arg(format!("{}/keys.json", self.dir))
            .arg("--txid").arg(txid)
            .arg("--cache").arg(format!("{}/cache", self.dir))
            .arg("--verifier").arg(verifier)
            .arg("--out").arg(&out);
        if own {
            cmd.arg("--own");
        }
        let output = cmd.output().expect("prove subprocess failed");
        assert!(
            output.status.success(),
            "prove failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // prove prints the bundle JSON to stdout; read from --out file for reliability.
        let raw = fs::read_to_string(&out).unwrap();
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("bundle JSON parse: {e}\n{raw}"))
    }

    fn verify(&self, bundle_path: &str) -> Verdict {
        let output = Command::new(Self::receipt_bin())
            .arg("verify")
            .arg("--bundle").arg(bundle_path)
            .arg("--cache").arg(format!("{}/cache", self.dir))
            .output()
            .expect("verify subprocess failed");
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("verdict JSON parse: {e}\nstdout: {stdout}"))
    }

    fn verify_named(&self, name: &str) -> Verdict {
        self.verify(&format!("{}/bundles/{name}", self.dir))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

// =========================================================================
// THE TESTS
// =========================================================================

/// POSITIVE: a tx that pays the receiver's SP address.
/// prove → claim="paid"; verify → PAID_PROVEN, all steps green.
#[test]
fn paid_receipt_round_trip() {
    let f = Fixture::new("paid");
    let txid = f.make_tx(true);
    let bundle = f.prove(&txid, "judge", false);

    assert_eq!(bundle.claim, "paid");
    assert_eq!(bundle.txid, txid);
    assert!(!bundle.shared_secret.is_empty());
    assert!(!bundle.dleq_proof.is_empty());
    assert_eq!(bundle.outputs.len(), 1);

    let v = f.verify_named(&format!("{txid}.json"));
    assert_eq!(v.verdict, "PAID_PROVEN");
    assert!(v.steps.iter().all(|s| s.ok), "a step failed: {:?}", v.steps);
}

/// POSITIVE with ownership tier: --own produces a spend-sig that verifies.
#[test]
fn paid_receipt_with_ownership() {
    let f = Fixture::new("own");
    let txid = f.make_tx(true);
    let bundle = f.prove(&txid, "judge", true);

    assert_eq!(bundle.claim, "paid");
    assert!(
        bundle.outputs[0].spend_sig.is_some(),
        "spend_sig should be present with --own"
    );

    let v = f.verify_named(&format!("{txid}.json"));
    assert_eq!(v.verdict, "PAID_PROVEN");
    assert_eq!(v.outputs.len(), 1);
    assert_eq!(v.outputs[0].spend_sig, "valid");
    assert!(v.steps.iter().all(|s| s.ok));
}

/// NEGATIVE: a tx that does NOT pay the receiver.
/// prove → claim="not_paid"; verify → NOT_PAID_PROVEN.
#[test]
fn not_paid_receipt_round_trip() {
    let f = Fixture::new("notpaid");
    let txid = f.make_tx(false);
    let bundle = f.prove(&txid, "judge", false);

    assert_eq!(bundle.claim, "not_paid");
    assert!(bundle.outputs.is_empty());

    let v = f.verify_named(&format!("{txid}.json"));
    assert_eq!(v.verdict, "NOT_PAID_PROVEN");
    assert!(v.steps.iter().all(|s| s.ok));
}

/// FORGERY 1 — claim flip: genuine not_paid bundle, claim flipped to "paid".
/// Verifier re-scans, finds 0 matches → INVALID at check_claim.
#[test]
fn forged_claim_rejected() {
    let f = Fixture::new("forged-claim");
    let txid = f.make_tx(false);
    let _ = f.prove(&txid, "judge", false);

    let path = format!("{}/bundles/{txid}.json", f.dir);
    let mut raw: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    raw["claim"] = serde_json::json!("paid");
    let forged = format!("{}/bundles/forged.json", f.dir);
    fs::write(&forged, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    let v = f.verify(&forged);
    assert_eq!(v.verdict, "INVALID");
    let failed = v.steps.iter().find(|s| !s.ok).unwrap();
    assert_eq!(failed.step, "check_claim");
}

/// FORGERY 2 — tampered shared secret: genuine paid bundle, S corrupted.
/// DLEQ proof no longer matches → INVALID at verify_dleq.
#[test]
fn tampered_secret_rejected_at_dleq() {
    let f = Fixture::new("tampered-s");
    let txid = f.make_tx(true);
    let _ = f.prove(&txid, "judge", false);

    let path = format!("{}/bundles/{txid}.json", f.dir);
    let mut raw: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    let s = raw["shared_secret"].as_str().unwrap().to_string();
    let mut bytes = hex::decode(&s).unwrap();
    bytes[0] ^= 0xFF;
    raw["shared_secret"] = serde_json::json!(hex::encode(&bytes));

    let tampered = format!("{}/bundles/tampered.json", f.dir);
    fs::write(&tampered, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    let v = f.verify(&tampered);
    assert_eq!(v.verdict, "INVALID");
    let failed = v.steps.iter().find(|s| !s.ok).unwrap();
    assert_eq!(failed.step, "verify_dleq");
}

/// FORGERY 3 — tampered DLEQ proof: genuine bundle, proof bytes corrupted.
/// → INVALID at verify_dleq.
#[test]
fn tampered_dleq_proof_rejected() {
    let f = Fixture::new("tampered-proof");
    let txid = f.make_tx(true);
    let _ = f.prove(&txid, "judge", false);

    let path = format!("{}/bundles/{txid}.json", f.dir);
    let mut raw: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();

    let p = raw["dleq_proof"].as_str().unwrap().to_string();
    let mut bytes = hex::decode(&p).unwrap();
    bytes[0] ^= 0xFF;
    raw["dleq_proof"] = serde_json::json!(hex::encode(&bytes));

    let tampered = format!("{}/bundles/tampered-proof.json", f.dir);
    fs::write(&tampered, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    let v = f.verify(&tampered);
    assert_eq!(v.verdict, "INVALID");
    let failed = v.steps.iter().find(|s| !s.ok).unwrap();
    assert_eq!(failed.step, "verify_dleq");
}

/// ANTI-REPLAY: a bundle minted for verifier "alice" must not verify under
/// verifier "bob" — the challenge m binds (verifier, txid, address).
#[test]
fn verifier_binding_prevents_replay() {
    let f = Fixture::new("replay");
    let txid = f.make_tx(true);

    // Mint for "alice".
    let out_alice = format!("{}/bundles/alice.json", f.dir);
    let _ = f.prove(&txid, "alice", false);

    // Verify as "alice" → should pass.
    let v_alice = f.verify(&out_alice);
    assert_eq!(v_alice.verdict, "PAID_PROVEN");

    // Tamper: change verifier to "bob", keep the same DLEQ proof.
    let mut raw: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&out_alice).unwrap()).unwrap();
    raw["verifier"] = serde_json::json!("bob");
    let bob_path = format!("{}/bundles/bob.json", f.dir);
    fs::write(&bob_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    let v_bob = f.verify(&bob_path);
    assert_eq!(v_bob.verdict, "INVALID");
    let failed = v_bob.steps.iter().find(|s| !s.ok).unwrap();
    assert_eq!(failed.step, "verify_dleq");
}
