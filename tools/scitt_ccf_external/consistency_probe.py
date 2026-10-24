#!/usr/bin/env python3
"""CCF consistency receipts (draft-ietf-scitt-receipts-ccf-profile-05, section 4), measured.

WHY. The working group runs a focused last call on section 4 of -05 (consistency proofs). The owner
asked for the section read rule by rule, a verifier behind the [scitt] extra, a measurement on a
local scitt-ccf-ledger with variants, a cross-check against third-party code, and every place where
the text is not enough for an independent implementation. The text read is the WG source at the
commit tagged -05 (ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile, e729c2ec, sha256 of
draft-ietf-scitt-receipts-ccf-profile.md 7efdb7aa...0077, retrieved 2026-09-25); the IETF archive
copy and the last-call mail were not reachable from this environment.

WHAT NO SERVICE DOES. No code measured emits a consistency receipt: CCF 7.0.17 (the version inside
the ledger image), CCF main at 9f9ba74b (2026-09-25) and scitt-ccf-ledger at 00101f76 (its main)
have no consistency-proof code; merklecpp in CCF main has past_root and past_path, the building
blocks, and nothing that serialises a -05 proof. So what is real here is the ledger: three states
of one local ledger, each signed by the service, and the ledger's leaves read from its own files
with the ccf package 7.0.17 (Apache-2.0, from PyPI), whose validator checks every root signature
against the tree it rebuilds. The consistency proof between two signed states is computed here from
those leaves, and the consistency receipt is the service's own COSE_Sign1 over the newer root,
taken from the newer inclusion receipt, with the proof in its unprotected header, which no signature
covers. A proof computed wrongly cannot verify under the service's signature.

SUBCOMMANDS
  register    --url URL --service-cert PEM --out DIR
              three hash envelopes over the root of examples/example_bundle.json, registered one
              after another so that each receipt signs a later state; keeps receipts in DIR
  leaves      --ledger-dir DIR --out FILE          (in an environment with ccf==7.0.17)
              every leaf and every signed root of the ledger, validated by the ccf package
  measure     --run DIR --leaves FILE [--tdev-merkle-clone PATH] [--vector-out PATH]
              proofs, the consistency receipt, the variants, proofbundle.scitt_ccf against a literal
              transcription of the 4.2 pseudo-code, and the third-party RFC 9162 oracle
  exhaustive  --max-n N [--tdev-merkle-clone PATH]
              every pair 0 < m < n <= N on random leaves: the anchor claim and the RFC 9162 claim

THE THIRD-PARTY ORACLE. github.com/transparency-dev/merkle (Apache-2.0) at TDEV_COMMIT, its
testonly.Tree and proof.VerifyConsistency, driven by rfc9162_oracle.go with CCF's hashing (children
SHA-256(l || r) without prefixes, leaves given hashed). Built offline from a local clone at the pin;
the tool refuses another commit. Its go.sum is made in a temporary directory, never here.

Output: consistency_result.json next to this file.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
RESULT = HERE / "consistency_result.json"
ORACLE_SRC = HERE / "rfc9162_oracle.go"
TDEV_COMMIT = "fbbcd741c3d1c69d8498487baa8edc9e5824847c"
DRAFT = {"repository": "https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile",
         "commit": "e729c2ec037ac763d0cf422bb58a219f8d6a02f4", "tag": "draft-ietf-scitt-receipts-ccf-profile-05",
         "file": "draft-ietf-scitt-receipts-ccf-profile.md",
         "sha256": "7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077", "retrieved": "2026-09-25"}
ISSUER = "127.0.0.1:8000"
H = lambda b: hashlib.sha256(b).digest()  # noqa: E731


# ------------------------------------------------------------------------------------------------
# The tree, the -05 prover and RFC 9162 section 2.1.4.1, written from the texts
# ------------------------------------------------------------------------------------------------
class Tree:
    """MTH of section 2.1 of -05 over leaf hashes (CCF stores leaves hashed)."""

    def __init__(self, leaves: list):
        self.leaves = leaves
        self.memo: dict = {}

    def node(self, lo: int, hi: int) -> bytes:
        if (lo, hi) not in self.memo:
            if hi - lo == 1:
                self.memo[(lo, hi)] = self.leaves[lo]
            else:
                k = _lp2(hi - lo)
                self.memo[(lo, hi)] = H(self.node(lo, lo + k) + self.node(lo + k, hi))
        return self.memo[(lo, hi)]

    def root(self, size: int) -> bytes:
        return self.node(0, size)

    def subproof(self, m: int, lo: int, hi: int, b: bool) -> list:
        """RFC 9162 2.1.4.1 SUBPROOF, keeping for each sibling which side it is on."""
        n = hi - lo
        if m == n:
            return [] if b else [("anchor", self.node(lo, hi))]
        k = _lp2(n)
        if m <= k:
            return self.subproof(m, lo, lo + k, b) + [(False, self.node(lo + k, hi))]
        return self.subproof(m - k, lo + k, hi, False) + [(True, self.node(lo, lo + k))]

    def rfc9162(self, m: int, n: int) -> list:
        return [h for _side, h in self.subproof(m, 0, n, True)]

    def proof05(self, m: int, n: int) -> tuple:
        """(anchor, [(left, hash)]) as section 4 of -05 describes it."""
        sp = self.subproof(m, 0, n, True)
        if sp and sp[0][0] == "anchor":
            return sp[0][1], [(bool(s), h) for s, h in sp[1:]]
        return self.root(m), [(bool(s), h) for s, h in sp]

    def deeper(self, m: int, n: int) -> list:
        """Every proof whose anchor lies below the section 4 anchor on its right edge."""
        anchor, path = self.proof05(m, n)
        t = (m & -m).bit_length() - 1
        out = []
        for j in range(t):
            lefts = [(True, self.node(m - (1 << (i + 1)), m - (1 << i))) for i in range(j, t)]
            out.append((self.node(m - (1 << j), m), lefts + path))
        return out


def _lp2(n: int) -> int:
    """The largest power of two smaller than n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


def fold(anchor: bytes, path: list) -> tuple:
    """compute_roots of -05 section 4.2, transcribed."""
    older = newer = anchor
    for left, h in path:
        if left:
            older, newer = H(h + older), H(h + newer)
        else:
            newer = H(newer + h)
    return older, newer


def rfc9162_digests(anchor: bytes, path: list, m: int) -> list:
    """What section 4 says the RFC 9162 proof holds: the anchor first when m is not a power of two."""
    return ([anchor] if m & (m - 1) else []) + [h for _l, h in path]


def enc_proof(anchor: bytes, path: list) -> bytes:
    import cbor2
    return cbor2.dumps({1: anchor, 2: [[left, h] for left, h in path]})


# ------------------------------------------------------------------------------------------------
# The third-party oracle
# ------------------------------------------------------------------------------------------------
def build_oracle(clone: Path, workdir: Path) -> Path:
    head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True,
                          text=True).stdout.strip()
    if head != TDEV_COMMIT:
        raise SystemExit(f"REFUSED: {clone} is at {head or 'no commit'}, not {TDEV_COMMIT}.")
    workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy(ORACLE_SRC, workdir / "main.go")
    (workdir / "go.mod").write_text(
        "module proofbundle.local/rfc9162oracle\n\ngo 1.22.7\n\n"
        "require github.com/transparency-dev/merkle v0.0.3-0.20260921000000-fbbcd741c3d1\n\n"
        f"replace github.com/transparency-dev/merkle => {clone}\n", encoding="utf-8")
    env = {**os.environ, "GOFLAGS": "-mod=mod", "GOPROXY": "off"}
    subprocess.run(["go", "build", "-o", "oracle", "."], cwd=workdir, env=env, check=True)
    return workdir / "oracle"


def run_oracle(binary: Path, leaves: list, pairs: list, claims: list) -> dict:
    inp = {"leaves": [x.hex() for x in leaves], "pairs": pairs, "claims": claims}
    p = subprocess.run([str(binary)], input=json.dumps(inp), capture_output=True, text=True, check=True)
    return json.loads(p.stdout)


def oracle_cross_check(tree: Tree, pairs: list, binary: Path) -> dict:
    claims, kinds = [], []
    for m, n in pairs:
        a, path = tree.proof05(m, n)
        claims.append({"m": m, "n": n, "root_m": tree.root(m).hex(), "root_n": tree.root(n).hex(),
                       "proof": [d.hex() for d in rfc9162_digests(a, path, m)]})
        kinds.append("canonical")
        for da, dp in tree.deeper(m, n):
            claims.append({"m": m, "n": n, "root_m": tree.root(m).hex(), "root_n": tree.root(n).hex(),
                           "proof": [x.hex() for x in [da] + [h for _l, h in dp]]})
            kinds.append("deeper")
    out = run_oracle(binary, tree.leaves, pairs, claims)
    rows = out["rows"]
    refusals = sorted({c for c, k in zip(out["claims"], kinds) if k == "deeper" and c != "ok"})
    return {
        "pairs": len(pairs),
        "oracle_rfc9162_proof_equals_ours": sum(r["proof"] == [h.hex() for h in tree.rfc9162(r["M"], r["N"])]
                                                for r in rows),
        "oracle_roots_equal_ours": sum(r["root_m"] == tree.root(r["M"]).hex()
                                       and r["root_n"] == tree.root(r["N"]).hex() for r in rows),
        "oracle_verifies_its_own_proofs": sum(r["verify_consistency"] == "ok" for r in rows),
        "canonical_05_digests_accepted_by_oracle": sum(c == "ok" for c, k in zip(out["claims"], kinds)
                                                       if k == "canonical"),
        "deeper_anchor_proofs": kinds.count("deeper"),
        "deeper_anchor_proofs_rejected_by_oracle": sum(c != "ok" for c, k in zip(out["claims"], kinds)
                                                       if k == "deeper"),
        "oracle_refusal_texts": refusals[:3],
    }


# ------------------------------------------------------------------------------------------------
# exhaustive
# ------------------------------------------------------------------------------------------------
def exhaustive(max_n: int, binary: Path | None) -> dict:
    tree = Tree([os.urandom(32) for _ in range(max_n)])
    c = dict(max_n=max_n, pairs=0, anchor_is_section4_anchor=0, digests_equal_rfc9162=0,
             folds_to_both_roots=0, canonical_first_sibling_right=0, deeper_anchor_proofs=0,
             deeper_pass_the_42_algorithm=0, deeper_first_sibling_left=0)
    pairs = []
    for n in range(2, max_n + 1):
        for m in range(1, n):
            pairs.append([m, n])
            c["pairs"] += 1
            a, path = tree.proof05(m, n)
            c["anchor_is_section4_anchor"] += a == tree.node(m - (m & -m), m)
            c["digests_equal_rfc9162"] += rfc9162_digests(a, path, m) == tree.rfc9162(m, n)
            c["folds_to_both_roots"] += fold(a, path) == (tree.root(m), tree.root(n))
            c["canonical_first_sibling_right"] += path[0][0] is False
            for da, dp in tree.deeper(m, n):
                c["deeper_anchor_proofs"] += 1
                c["deeper_pass_the_42_algorithm"] += fold(da, dp) == (tree.root(m), tree.root(n))
                c["deeper_first_sibling_left"] += dp[0][0] is True
    if binary is not None:
        small = [p for p in pairs if p[1] <= 64]
        c["third_party_oracle_n_le_64"] = oracle_cross_check(tree, small, binary)
    return c


# ------------------------------------------------------------------------------------------------
# register
# ------------------------------------------------------------------------------------------------
def register(url: str, service_cert: Path, out: Path) -> int:
    sys.path.insert(0, str(HERE))
    import local_ledger_probe as P  # noqa: PLC0415 - the signer and service client of this directory
    from proofbundle.anchors import receipt_canonical_root  # noqa: PLC0415
    bundle = json.loads(P.BUNDLE.read_text(encoding="utf-8"))
    root = receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})
    svc = P.Service(url, service_cert)
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        print(f"NOT MEASURABLE: the service did not serve its keys ({code}).", file=sys.stderr)
        return 2
    key, chain, did, spki = P.make_signer()
    out.mkdir(parents=True, exist_ok=True)
    runs = []
    # The middle state takes two statements at once, so that one signature can cover both and the
    # signed tree size can be even: only an even older size has an anchor below the section 4 one.
    for name, count in (("older", 1), ("middle", 2), ("newer", 1)):
        stmts = [P.statements(key, chain, did, root)["control"] for _ in range(count)]  # ECDSA: new signatures
        with ThreadPoolExecutor(max_workers=count) as pool:
            recs = list(pool.map(svc.register, stmts))
        for rec in recs:
            if not rec.get("receipt") or not rec.get("transparent_statement"):
                print(f"NOT MEASURABLE: {name} was not registered: {rec.get('error')}", file=sys.stderr)
                return 2
        rec = recs[0]
        (out / f"{name}.receipt.cbor").write_bytes(rec["receipt"])
        (out / f"{name}.transparent.cose").write_bytes(rec["transparent_statement"])
        runs.append({"name": name, "txids": [r["txid"] for r in recs]})
        time.sleep(1.5)                                     # let the next state be signed on its own
    (out / "scitt-keys.cbor").write_bytes(keys_raw)
    (out / "run.json").write_text(json.dumps({
        "url": url, "issuer": ISSUER, "canonical_root_hex": root.hex(), "registered": runs,
        "statement_signer_spki_b64": base64.b64encode(spki).decode(), "signer_did": did,
        "measured_on": datetime.date.today().isoformat()}, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(runs))
    return 0


# ------------------------------------------------------------------------------------------------
# leaves (ccf package)
# ------------------------------------------------------------------------------------------------
def leaves(ledger_dir: Path, out: Path) -> int:
    import ccf  # noqa: PLC0415 - third-party, the oracle for the tree
    import ccf.ledger as L  # noqa: PLC0415
    from ccf import signatures as SIG  # noqa: PLC0415
    from importlib.metadata import version  # noqa: PLC0415
    validator = L.LedgerValidator(verification_level=L.VerificationLevel.FULL)
    ledger = L.Ledger([str(ledger_dir)], committed_only=False, verification_level=L.VerificationLevel.FULL)
    signed = []
    count = 0
    for chunk in ledger:
        for tx in chunk:
            tables = tx.get_public_domain().get_tables()
            is_sig = SIG.is_signature_transaction(tables)
            size_before = validator.merkle.get_leaf_count()
            validator.add_transaction(tx)                # raises if a signed root does not match
            count += 1
            if is_sig:
                signed.append({"seqno": tx.gcm_header.seqno, "view": tx.gcm_header.view,
                               "tree_size": size_before,
                               "root": _root_of(validator.merkle, size_before)})
    leaves_ = [x.hex() for x in validator.merkle.leaves]
    doc = {"ccf_package": version("ccf"), "ccf_module": ccf.__file__, "transactions": count,
           "signatures_verified": validator.signature_count, "last_verified": str(validator.last_verified_txid()),
           "leaf_count": len(leaves_), "leaves": leaves_, "signed_states": signed,
           "leaf_zero_note": "leaf 0 is 32 zero bytes, not hashed, as the ccf package's validator starts its tree"}
    out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(f"{count} transactions, {validator.signature_count} signatures verified, {len(leaves_)} leaves")
    return 0


def _root_of(merkle, size: int) -> str:
    """The ccf package's own root over its first ``size`` leaves (a fresh tree, same class)."""
    from ccf.merkletree import MerkleTree  # noqa: PLC0415
    t = MerkleTree()
    for leaf in merkle.leaves[:size]:
        t.add_leaf(leaf, do_hash=False)
    return t.get_merkle_root().hex()


# ------------------------------------------------------------------------------------------------
# measure
# ------------------------------------------------------------------------------------------------
def as_written(receipt: bytes, older_root: bytes, keys: list) -> str:
    """The 4.2 pseudo-code, transcribed with cbor2 and cryptography only: 'accepts' or the assert
    that fails. Independent of proofbundle.scitt_ccf."""
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    tag = cbor2.loads(receipt)
    prot_raw, unprot, payload, sig = tag.value
    if 396 not in unprot:
        return "assert VDP_LABEL in unprotected_header"
    vdp = unprot[396]
    if -2 not in vdp:
        return "assert CONSISTENCY_PROOF_LABEL in vdp"
    proofs = vdp[-2]
    if not len(proofs) > 0:
        return "assert len(proofs) > 0"
    if payload is not None:
        return "assert consistency_receipt.payload == nil"
    payloads = []
    for p in proofs:
        d = cbor2.loads(p)
        older, newer = fold(d[1], [(e[0], e[1]) for e in d[2]])
        if older == older_root:
            payloads.append(newer)
    if not payloads:
        return "assert len(payloads) > 0"
    for pl in payloads:
        tbs = cbor2.dumps(["Signature1", prot_raw, b"", pl])
        ok = False
        for spki in keys:
            key = load_der_public_key(spki)
            n = (key.curve.key_size + 7) // 8
            try:
                key.verify(utils.encode_dss_signature(int.from_bytes(sig[:n], "big"),
                                                      int.from_bytes(sig[n:], "big")),
                           tbs, ec.ECDSA(hashes.SHA384() if n == 48 else hashes.SHA256()))
                ok = True
            except Exception:  # noqa: BLE001 - a failed verify is the measured outcome
                pass
        if not ok:
            return "assert verify_cose(consistency_receipt, payload)"
    return "accepts"


def with_proofs(receipt: bytes, proofs: list, *, payload=None, inclusion: bool = False) -> bytes:
    """The service's own COSE_Sign1 over the newer root, its unprotected header replaced."""
    import cbor2
    tag = cbor2.loads(receipt)
    prot_raw, unprot, _payload, sig = tag.value
    vdp = {-2: proofs}
    if inclusion:
        vdp[-1] = list(unprot[396][-1])
    return b"\xd2" + cbor2.dumps([prot_raw, {396: vdp}, payload, sig])


def measure(run: Path, leaves_file: Path, clone: Path | None, vector_out: Path | None) -> int:
    sys.path.insert(0, str(REPO / "src"))
    import cryptography
    from proofbundle import scitt_ccf as S
    from proofbundle._wire_b64 import decode_b64   # the one strict base64 decoder tools may use
    info = json.loads((run / "run.json").read_text(encoding="utf-8"))
    ld = json.loads(leaves_file.read_text(encoding="utf-8"))
    keys_raw = (run / "scitt-keys.cbor").read_bytes()
    keyset = S.load_cose_keyset(keys_raw)
    rp = {"scitt_ccf_services": {ISSUER: keyset},
          "scitt_statement_keys": [decode_b64(info["statement_signer_spki_b64"])]}
    root = bytes.fromhex(info["canonical_root_hex"])
    tree = Tree([bytes.fromhex(x) for x in ld["leaves"]])

    states = {}
    for name in ("older", "middle", "newer"):
        ts = (run / f"{name}.transparent.cose").read_bytes()
        r = S.verify_transparent_statement(ts, canonical_root=root, rp_trust=rp)
        rc = r.receipts[0]
        size = next((s for s in range(1, len(tree.leaves) + 1) if tree.root(s) == rc.merkle_root), None)
        signed = next((x for x in ld["signed_states"] if x["root"] == (rc.merkle_root or b"").hex()), None)
        states[name] = {"txid": rc.ccf_txid, "inclusion_status": r.status, "root": rc.merkle_root,
                        "tree_size": size, "ccf_package_signed_state": signed}
    sizes = {k: v["tree_size"] for k, v in states.items()}
    if None in sizes.values() or not sizes["older"] < sizes["middle"] < sizes["newer"]:
        print(f"NOT MEASURABLE: the three receipts are not three growing states: {sizes}", file=sys.stderr)
        return 2
    m1, m2, n = sizes["older"], sizes["middle"], sizes["newer"]
    newer_receipt = (run / "newer.receipt.cbor").read_bytes()
    p_on = {k: tree.proof05(*k) for k in ((m1, n), (m2, n), (m1, m2))}
    enc = {k: enc_proof(*v) for k, v in p_on.items()}
    r_old, r_mid, r_new = states["older"]["root"], states["middle"]["root"], states["newer"]["root"]
    real = with_proofs(newer_receipt, [enc[(m1, n)]])

    def flip(b: bytes, i: int = 0) -> bytes:
        return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]
    a, path = p_on[(m1, n)]
    deeper = tree.deeper(m2, n)
    variants = {
        "control: older state to newer state": (real, r_old),
        "control: middle state to newer state": (with_proofs(newer_receipt, [enc[(m2, n)]]), r_mid),
        "wrong older root: the middle root held, the older proof carried": (real, r_mid),
        "wrong older root: one bit of the older root": (real, flip(r_old)),
        "swapped states: the newer root held as the older one": (real, r_new),
        "swapped states: the older-to-middle proof under the newer signature":
            (with_proofs(newer_receipt, [enc[(m1, m2)]]), r_old),
        "altered anchor: one bit": (with_proofs(newer_receipt, [enc_proof(flip(a), path)]), r_old),
        "altered path: one tag flipped": (with_proofs(newer_receipt, [enc_proof(a, [(not path[0][0], path[0][1])] + path[1:])]), r_old),
        "multiple proofs: older and middle, both to the newer root":
            (with_proofs(newer_receipt, [enc[(m1, n)], enc[(m2, n)]]), r_old),
        "multiple proofs: the same proof twice": (with_proofs(newer_receipt, [enc[(m1, n)]] * 2), r_old),
        "multiple proofs: a valid one and one to another newer root":
            (with_proofs(newer_receipt, [enc[(m1, n)], enc[(m1, m2)]]), r_old),
        "multiple proofs: a valid one and a corrupted one (one anchor bit flipped)":
            (with_proofs(newer_receipt, [enc[(m1, n)], enc_proof(flip(p_on[(m2, n)][0], 5), p_on[(m2, n)][1])]), r_old),
        "anchor deeper than section 4 requires (middle state to newer state)":
            (with_proofs(newer_receipt, [enc_proof(*deeper[0])]), r_mid) if deeper else None,
        "detached payload missing: the newer root attached": (with_proofs(newer_receipt, [enc[(m1, n)]], payload=r_new), r_old),
        "detached payload not recomputable: -2 is an empty array": (with_proofs(newer_receipt, []), r_old),
        "inclusion and consistency proofs in one receipt": (with_proofs(newer_receipt, [enc[(m1, n)]], inclusion=True), r_old),
    }
    rows = []
    for name, v in variants.items():
        if v is None:
            rows.append({"variant": name, "note": f"m = {m2} is odd: no anchor below the section 4 anchor"})
            continue
        rcpt, older = v
        c = S.verify_consistency_receipt(rcpt, older_root=older, older_issuer=ISSUER, rp_trust=rp)
        rows.append({"variant": name, "proofbundle": c.status, "signature_valid": c.signature_valid,
                     "older_root_matches": c.older_root_matches,
                     "algorithm_42_as_written": as_written(rcpt, older, [k["spki"] for k in keyset])})
    other_issuer = S.verify_consistency_receipt(real, older_root=r_old, older_issuer="another.service",
                                                rp_trust=rp).status
    no_trust = S.verify_consistency_receipt(real, older_root=r_old, older_issuer=ISSUER).status

    oracle = None
    if clone is not None:
        with tempfile.TemporaryDirectory() as t:
            binary = build_oracle(clone, Path(t))
            oracle = oracle_cross_check(tree, [[m1, n], [m2, n], [m1, m2]], binary)
            oracle["real_proofs"] = {f"{m}->{nn}": run_oracle(binary, tree.leaves, [], [{
                "m": m, "n": nn, "root_m": tree.root(m).hex(), "root_n": tree.root(nn).hex(),
                "proof": [d.hex() for d in rfc9162_digests(*p_on[(m, nn)], m)]}])["claims"][0]
                for (m, nn) in p_on}
    doc = {
        "tool": "tools/scitt_ccf_external/consistency_probe.py", "measured_on": datetime.date.today().isoformat(),
        "draft": DRAFT,
        "environment": {"python": platform.python_version(), "cryptography": cryptography.__version__,
                        "cbor2": _dist_version("cbor2")},
        "service": {"issuer": ISSUER, "registered": info["registered"], "keyset_sha256": hashlib.sha256(keys_raw).hexdigest()},
        "ledger": {"ccf_package": ld["ccf_package"], "transactions": ld["transactions"],
                   "signatures_verified_by_ccf_package": ld["signatures_verified"], "leaf_count": ld["leaf_count"],
                   "leaf_zero_note": ld["leaf_zero_note"], "leaves": ld["leaves"]},
        "states": {k: {**v, "root": v["root"].hex()} for k, v in states.items()},
        "proofs": {f"{m}->{nn}": {"anchor": pv[0].hex(), "path": [[left, h.hex()] for left, h in pv[1]],
                                  "rfc9162_digests_equal": rfc9162_digests(*pv, m) == tree.rfc9162(m, nn),
                                  "fold": [x.hex() for x in fold(*pv)]} for (m, nn), pv in p_on.items()},
        "variants": rows,
        "other_checks": {"older root verified from another service's receipt": other_issuer,
                         "no relying-party key set": no_trust},
        "third_party_oracle": oracle,
    }
    prev = json.loads(RESULT.read_text(encoding="utf-8")) if RESULT.exists() else {}
    if "exhaustive" in prev:
        doc["exhaustive"] = prev["exhaustive"]
    RESULT.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    for r in rows:
        print(f"  {r['variant'][:70]:70s} {r.get('proofbundle', '-'):34s} {r.get('algorithm_42_as_written', '')}")
    if vector_out:
        vec = {
            "what": "two and three signed states of one local scitt-ccf-ledger, and a consistency receipt: "
                    "the service's COSE_Sign1 over the newer root with a -05 consistency proof computed "
                    "here from the ledger's own leaves (no service measured emits one)",
            "source": "tools/scitt_ccf_external/consistency_probe.py", "measured_on": doc["measured_on"],
            "ledger_commit": "00101f769d872711356e080fbb089ac48589c60a", "issuer": ISSUER,
            "canonical_root_hex": info["canonical_root_hex"],
            "service_keyset_b64": base64.b64encode(keys_raw).decode(),
            "statement_signer_spki_b64": info["statement_signer_spki_b64"],
            "states": {k: {"tree_size": v["tree_size"], "root_hex": v["root"].hex(), "txid": v["txid"],
                           "transparent_statement_b64": base64.b64encode(
                               (run / f"{k}.transparent.cose").read_bytes()).decode()}
                       for k, v in states.items()},
            "newer_receipt_b64": base64.b64encode(newer_receipt).decode(),
            "proofs_b64": {f"{m}->{nn}": base64.b64encode(e).decode() for (m, nn), e in enc.items()},
            "deeper_anchor_proof_b64": base64.b64encode(enc_proof(*deeper[0])).decode() if deeper else None,
            "consistency_receipt_b64": base64.b64encode(real).decode(),
        }
        vector_out.write_text(json.dumps(vec, indent=2) + "\n", encoding="utf-8")
    return 0


def _dist_version(name: str) -> str:
    from importlib.metadata import version  # noqa: PLC0415
    return version(name)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="CCF consistency receipts of -05 section 4, measured.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("register")
    r.add_argument("--url", default="https://127.0.0.1:8000")
    r.add_argument("--service-cert", required=True, type=Path)
    r.add_argument("--out", required=True, type=Path)
    lv = sub.add_parser("leaves")
    lv.add_argument("--ledger-dir", required=True, type=Path)
    lv.add_argument("--out", required=True, type=Path)
    me = sub.add_parser("measure")
    me.add_argument("--run", required=True, type=Path)
    me.add_argument("--leaves", required=True, type=Path)
    me.add_argument("--tdev-merkle-clone", type=Path)
    me.add_argument("--vector-out", type=Path)
    ex = sub.add_parser("exhaustive")
    ex.add_argument("--max-n", type=int, default=257)
    ex.add_argument("--tdev-merkle-clone", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "register":
        return register(args.url, args.service_cert, args.out)
    if args.cmd == "leaves":
        return leaves(args.ledger_dir, args.out)
    if args.cmd == "measure":
        return measure(args.run, args.leaves, args.tdev_merkle_clone, args.vector_out)
    binary = None
    with tempfile.TemporaryDirectory() as t:
        if args.tdev_merkle_clone:
            binary = build_oracle(args.tdev_merkle_clone, Path(t))
        res = exhaustive(args.max_n, binary)
    prev = json.loads(RESULT.read_text(encoding="utf-8")) if RESULT.exists() else {}
    prev["exhaustive"] = {**res, "measured_on": datetime.date.today().isoformat()}
    RESULT.write_text(json.dumps(prev, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(res, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
