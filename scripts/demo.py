#!/usr/bin/env python3
"""Interactive CLI demo driver for Silent Receipts.

    cd ~/silent-receipts && python3 scripts/demo.py

Number keys drive it. Option 4 tampers the REAL payment receipt in place
(one hex digit of the secret); option 1 then fails on the exact same file;
option 6 restores it. Quitting auto-restores.
"""
import json
import os
import shutil
import subprocess
import sys

R = os.environ.get("RECEIPT_BIN", "./receipt")
BD = os.environ.get("BUNDLE_DIR", "data/bundles")
CACHE = os.environ.get("CACHE_DIR", "data/cache")
RECEIPT = os.path.join(BD, "auditor-receipt.json")
BACKUP = RECEIPT + ".orig"

G, B, Y, D, X = "\033[92m", "\033[94m", "\033[93m", "\033[2m", "\033[0m"
BOLD = "\033[1m"

STAMP = {
    "PAID_PROVEN": (G, "✔ PAYMENT PROVEN"),
    "NOT_PAID_PROVEN": (B, "✘ NOTHING RECEIVED — PROVEN"),
    "INVALID": (Y, "⚠ REJECTED — INVALID PROOF"),
}


def verify(path):
    p = subprocess.run([R, "verify", "--bundle", path, "--cache", CACHE],
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(Y + "verifier error: " + p.stderr.strip() + X)
        return
    v = json.loads(p.stdout)
    color, text = STAMP.get(v["verdict"], (Y, v["verdict"]))
    print()
    print(color + BOLD + "   ┌" + "─" * (len(text) + 4) + "┐" + X)
    print(color + BOLD + "   │  " + text + "  │" + X)
    print(color + BOLD + "   └" + "─" * (len(text) + 4) + "┘" + X)
    for o in v.get("outputs", []):
        own = "  · spend key proven (ownership)" if o.get("spend_sig") == "valid" else ""
        print(f"   output {o['vout']}: {G}{o['amount_sats']:,} sats{X}{own}")
    print(D + f"   issued to: {v['verifier']}" + X)
    for s in v["steps"]:
        mark = (G + "✓" + X) if s["ok"] else (Y + "✗" + X)
        print(f"   {mark} {s['step']}" + D + f" — {s['detail'][:76]}" + X)
    print()


def tamper():
    if not os.path.exists(BACKUP):
        shutil.copy2(RECEIPT, BACKUP)
    b = json.load(open(RECEIPT))
    s = list(b["shared_secret"])
    s[10] = "0" if s[10] != "0" else "1"
    b["shared_secret"] = "".join(s)
    json.dump(b, open(RECEIPT, "w"), indent=2)
    print(Y + f"\n   flipped ONE hex digit of the shared secret in {RECEIPT}" + X)
    print(D + "   (the GUI's green button is now broken too — same file)\n" + X)


def restore():
    if os.path.exists(BACKUP):
        shutil.move(BACKUP, RECEIPT)
        print(G + "\n   receipt restored — original bytes back in place\n" + X)
    else:
        print(D + "\n   nothing to restore\n" + X)


def mint():
    name = input("   address the receipt to whom? ").strip() or "a judge"
    txid = json.load(open(BACKUP if os.path.exists(BACKUP) else RECEIPT))["txid"]
    out = os.path.join(BD, "live-receipt-cli.json")
    p = subprocess.run([R, "prove", "--txid", txid, "--verifier", name, "--own",
                        "--cache", CACHE, "--out", out],
                       capture_output=True, text=True)
    if p.returncode != 0:
        print(Y + "   " + p.stderr.strip()[:200] + X)
        return
    print(G + f"\n   minted, cryptographically bound to '{name}' — replay-proof" + X)
    verify(out)


def main():
    ident = json.load(open("data/keys.json"))["address"]
    while True:
        print(BOLD + "SILENT RECEIPTS — interactive demo" + X)
        print(D + f"identity: {ident[:22]}…{ident[-8:]}" + X)
        print(f"""
 {G}1{X}) verify the payment receipt        {D}expect: ✔ PAYMENT PROVEN{X}
 {B}2{X}) verify the dispute                {D}expect: ✘ NOTHING RECEIVED — PROVEN{X}
 {Y}3{X}) verify the sender's forged receipt {D}expect: ⚠ REJECTED{X}
 {Y}4{X}) TAMPER the payment receipt        {D}flip one hex digit, in place{X}
 {Y}5{X}) verify the fake tour              {D}expect: ⚠ REJECTED at the DLEQ{X}
 {G}6{X}) restore the tampered receipt
 {G}7{X}) mint a fresh receipt addressed to someone
 q) quit {D}(auto-restores){X}
""")
        try:
            c = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            c = "q"
        if c == "1":
            verify(RECEIPT)
        elif c == "2":
            verify(os.path.join(BD, "attack1-he-says-he-paid-me.json"))
        elif c == "3":
            verify(os.path.join(BD, "attack1-forged-receipt.json"))
        elif c == "4":
            tamper()
        elif c == "5":
            verify(os.path.join(BD, "attack2-fake-tour.json"))
        elif c == "6":
            restore()
        elif c == "7":
            mint()
        elif c == "q":
            restore()
            print("bye")
            return


if __name__ == "__main__":
    main()
