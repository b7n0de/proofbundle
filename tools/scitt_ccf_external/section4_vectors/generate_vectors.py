#!/usr/bin/env python3
"""Generate the receipt-level vectors for section 4 of draft-ietf-scitt-receipts-ccf-profile-05.

    python generate_vectors.py

Inputs, committed in this repository:
- tests/fixtures/scitt_ccf/local_ledger_consistency.json: three signed states (tree sizes 19, 22 and
  24) of a local scitt-ccf-ledger at 00101f76 on CCF 7.0.17 in virtual mode, and the service's own
  COSE_Sign1 over the newest root, R_24
- tools/scitt_ccf_external/consistency_result.json: the ledger's 25 leaves, read with the ccf package
  7.0.17, from which every proof here is computed

Thirteen vectors reuse that COSE_Sign1 unchanged: its protected header and signature cover the newer
root only, and vdp sits in the unprotected header, so the signature stays valid whatever proofs are
placed beside it. S4-14 flips one bit of that signature, so it does not verify. S4-10, a deliberately
noncanonical root, is signed with the one TEST ONLY key in this
directory, TEST_ONLY_es384_private_key.pem, created on the first run and never replaced; its ECDSA
signatures are deterministic (RFC 6979), so a run reproduces the same bytes.

Every vector also carries older_size, the size of the state older_root is the root of, and
newer_size, the seqno of the receipt's ccf.v1 txid: that a seqno is the tree size its signature
covers is measured on CCF 7.0.17 (leaf 0 counted), not stated by -05. Reading B is recorded size-free
(B1 to B13, no size) and size-aware (B14 with these sizes), and the reader's status without and with
them. CASES carries the size-aware result; the size-free one is that result, or
passes_size_free_checks where it passes or fails only at B14.

The results under reading A and reading B written in CASES are what each case was built to show.
They are not taken on trust: check_vectors.py recomputes them independently, and the test fails when
the two differ. The proofbundle reader's status is recorded as information, from src/ of this
checkout.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
FIXTURE = REPO / "tests" / "fixtures" / "scitt_ccf" / "local_ledger_consistency.json"
LEAVES = REPO / "tools" / "scitt_ccf_external" / "consistency_result.json"
TEST_KEY = HERE / "TEST_ONLY_es384_private_key.pem"
TEST_ISSUER = "test-only.section4-vectors.invalid"
READER_COMMIT = "f455cc8494b811e1de03ca1e0c156008d32b7f2d"
DRAFT = {"name": "draft-ietf-scitt-receipts-ccf-profile-05",
         "repository": "https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile",
         "commit": "e729c2ec037ac763d0cf422bb58a219f8d6a02f4",
         "file": "draft-ietf-scitt-receipts-ccf-profile.md",
         "file_sha256": "7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077"}
LIST = {"EMILIA": "https://mailarchive.ietf.org/arch/msg/scitt/FmclkmQ4eDiyOTB409P0WJSjdEk/",
        "Pinto": "https://mailarchive.ietf.org/arch/msg/scitt/eF_K0AwI5dQRDUwnLazYem0YrJA/",
        "Templeman": "https://mailarchive.ietf.org/arch/msg/scitt/55Ausn8Rf5oyBJ2t67uAyZWpxWs/"}

S_4 = ("4", "A CCF consistency proof establishes that the tree of `m` transactions with root `R_m` is a "
            "prefix of the tree of `n` transactions with root `R_n`, where `0 < m < n`: every transaction "
            "of the older tree is at the same position in the newer tree.")
S_ANCHOR = ("4", "The `anchor` MUST be the root of the subtree covering transactions `T[m - 2^t], ..., "
                 "T[m - 1]`, where `2^t` is the largest power of two dividing `m`; when `m` is a power of "
                 "two, the anchor is `R_m`.")
S_NO_SIZE = ("4", "Neither tree size is needed for verification.")
S_PATH = ("4", "The `path` lists the sibling of each node on the path from the anchor to `R_n`, tagged as "
               "in inclusion proofs.")
S_ONE_OR_MORE = ("4.1", "It MUST contain the `consistency-proof` (-2) key, whose value is an array of one or "
                        "more `ccf-consistency-proof` values, each relating one older root to the newer root.")
S_SAME_NEWER = ("4.1", "When the array contains more than one consistency proof, every proof MUST compute to "
                       "the same newer root.")
S_BINDS = ("4.2", "The comparison with `older_root` binds the receipt to a state the verifier already "
                  "trusts: a receipt in which no proof recomputes `older_root` proves nothing about that state.")
S_NOT_CHECKED = ("4.2", "It also confirms that the anchor is a node of that state, but not that it is the "
                        "anchor required in {{ccf-consistency-proofs}}, which cannot be checked without "
                        "knowing `m`.")
S_FIG9 = ("4.2", "A consistency receipt is verified against a trusted `older_root` as follows: (Figure 9)")
S_SIG = ("4.2", "assert(verify_cose(consistency_receipt, payload)) (Figure 9)")
S_ALL_SAME = ("5", "All proofs in a receipt recompute the same root (the newer root, for consistency "
                   "proofs), which is the detached payload.")
S_CDDL = ("5", "verifiable-proofs = { &(inclusion-proof: -1) => inclusion-proofs ? &(consistency-proof: -2) "
               "=> consistency-proofs // &(consistency-proof: -2) => consistency-proofs } (Figure 11)")

#: S4-10 carries a synthetic txid under the test key: the newer size is asserted by it, not measured.
SIZES_NOTE_S4_10 = ("older_size: 6 from the constructed older tree; newer_size: 7 asserted by the synthetic "
                    "test-key header txid 2.7; the signed N1 is not the canonical root R_7.")
A_OK = ("accept", "return true")
A_NO_PROOFS = ("reject", "assert(len(proofs) > 0)")
A_NO_OLDER = ("reject", "assert(len(payloads) > 0)")
A_BAD_SIG = ("reject", "assert(verify_cose(consistency_receipt, payload))")
B_OK = ("accept", "B1 to B14 hold")                     # the size-aware result; size-free: B1 to B13


def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _lp2(n: int) -> int:
    return 1 << ((n - 1).bit_length() - 1)


class Tree:
    """MTH of -05 section 2.1 over the ledger's leaf hashes (the ledger stores leaves hashed)."""

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

    def _sub(self, m: int, lo: int, hi: int, b: bool) -> list:
        n = hi - lo
        if m == n:
            return [] if b else [("anchor", self.node(lo, hi))]
        k = _lp2(n)
        if m <= k:
            return self._sub(m, lo, lo + k, b) + [(False, self.node(lo + k, hi))]
        return self._sub(m - k, lo + k, hi, False) + [(True, self.node(lo, lo + k))]

    def proof(self, m: int, n: int) -> tuple:
        """(anchor, [(left, sibling)]) of section 4 for sizes m < n, from RFC 9162 SUBPROOF."""
        sp = self._sub(m, 0, n, True)
        if sp and sp[0][0] == "anchor":
            return sp[0][1], [(bool(s), h) for s, h in sp[1:]]
        return self.root(m), [(bool(s), h) for s, h in sp]


def enc(anchor: bytes, path: list) -> bytes:
    return cbor2.dumps({1: anchor, 2: [[left, h] for left, h in path]})


def flip(b: bytes, i: int) -> bytes:
    return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]


def test_key() -> ec.EllipticCurvePrivateKey:
    if not TEST_KEY.exists():
        key = ec.generate_private_key(ec.SECP384R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        TEST_KEY.write_bytes(pem)
    return serialization.load_pem_private_key(TEST_KEY.read_bytes(), password=None)


def spki_of(pub) -> bytes:
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def main() -> int:
    sys.path.insert(0, str(REPO / "src"))
    from proofbundle._wire_b64 import decode_b64   # the one strict base64 decoder tools may use
    fx = json.loads(FIXTURE.read_text(encoding="utf-8"))
    tree = Tree([bytes.fromhex(x) for x in json.loads(LEAVES.read_text(encoding="utf-8"))["ledger"]["leaves"]])
    states = fx["states"]
    roots = {s["tree_size"]: bytes.fromhex(s["root_hex"]) for s in states.values()}
    for size, root in roots.items():
        assert tree.root(size) == root, f"the leaves do not give the signed root at {size}"
    R19, R22, R24 = roots[19], roots[22], roots[24]

    newer = cbor2.loads(decode_b64(fx["newer_receipt_b64"]))
    prot_raw, newer_unprot, _payload, service_sig = newer.value
    service_prot = cbor2.loads(prot_raw)
    service_kid = service_prot[4]
    service_issuer = service_prot[15][1]
    service_keys = cbor2.loads(decode_b64(fx["service_keyset_b64"]))
    service_key = next(k for k in service_keys if k.get(2) == service_kid)
    curve = {1: ec.SECP256R1(), 2: ec.SECP384R1()}[service_key[-1]]
    service_spki = spki_of(ec.EllipticCurvePublicNumbers(int.from_bytes(service_key[-2], "big"),
                                                         int.from_bytes(service_key[-3], "big"), curve).public_key())
    newer_inclusion = list(newer_unprot[396][-1])

    def inclusion_of(state: str) -> list:
        ts = cbor2.loads(decode_b64(states[state]["transparent_statement_b64"]))
        receipt = cbor2.loads(ts.value[1][394][0])
        return list(receipt.value[1][396][-1])
    older_inclusion = inclusion_of("older")

    key = test_key()
    test_spki = spki_of(key.public_key())
    test_kid = hashlib.sha256(test_spki).hexdigest().encode("ascii")

    p19, p22, p20_22 = enc(*tree.proof(19, 24)), enc(*tree.proof(22, 24)), enc(*tree.proof(20, 22))
    a22, path22 = tree.proof(22, 24)
    a19, path19 = tree.proof(19, 24)
    deeper = decode_b64(fx["deeper_anchor_proof_b64"])
    unchanged = enc(tree.node(16, 24), [(True, tree.node(0, 16))])
    n1_sibling = tree.node(6, 7)                  # the ledger's leaf 6: HASH(d[6]) in Tiago Pinto's notation
    n1 = H(tree.root(6) + n1_sibling)
    assert n1 != tree.root(7), "N1 must not be the canonical root R_7"     # the S4-10 note says so

    def service(vdp: dict, payload=None, sig: bytes = service_sig) -> bytes:
        return b"\xd2" + cbor2.dumps([prot_raw, {396: vdp}, payload, sig])

    def test_signed(vdp: dict, root: bytes, txid: str) -> bytes:
        prot = cbor2.dumps({1: -35, 4: test_kid, 15: {1: TEST_ISSUER}, 395: 2, "ccf.v1": {"txid": txid}})
        tbs = cbor2.dumps(["Signature1", prot, b"", root])
        r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA384(), deterministic_signing=True)))
        return b"\xd2" + cbor2.dumps([prot, {396: vdp}, None, r.to_bytes(48, "big") + s.to_bytes(48, "big")])

    SERVICE = ("service", "the service's own COSE_Sign1 over R_24 from the fixture, its unprotected header "
                          "replaced; the proofs are computed from the ledger's leaves")
    FLIPPED = ("service, one signature bit flipped",
               "the service's COSE_Sign1 over R_24 from the fixture with bit 0 of signature byte 0 flipped, so "
               "it does not verify; its unprotected header replaced; the proofs are computed from the ledger's "
               "leaves")
    TEST = ("test key", "signed with TEST_ONLY_es384_private_key.pem over a deliberately noncanonical root")

    cases = [
        ("S4-01", "Canonical proof 19 to 24, control", service({-2: [p19]}), R19, SERVICE,
         [{"m": 19, "n": 24}], [S_FIG9, S_4], A_OK, B_OK, [], "the canonical proof from R_19 to R_24"),
        ("S4-02", "Canonical proof 22 to 24, control", service({-2: [p22]}), R22, SERVICE,
         [{"m": 22, "n": 24}], [S_FIG9, S_4], A_OK, B_OK, [], "the canonical proof from R_22 to R_24"),
        ("S4-03", "A second proof with one anchor bit flipped", service({-2: [p19, enc(flip(a22, 5), path22)]}),
         R19, SERVICE, [{"m": 19, "n": 24}, None], [S_SAME_NEWER], A_OK, ("reject", "B8"), ["G2"],
         "the canonical 19-to-24 proof, and the canonical 22-to-24 proof with bit 0 of anchor byte 5 flipped"),
        ("S4-04", "Two valid proofs to the same newer root, control for multiple proofs",
         service({-2: [p19, p22]}), R19, SERVICE, [{"m": 19, "n": 24}, {"m": 22, "n": 24}], [S_SAME_NEWER],
         A_OK, B_OK, ["Templeman"], "the canonical proofs 19 to 24 and 22 to 24"),
        ("S4-05", "A second proof whose older and newer roots are both other roots",
         service({-2: [p19, p20_22]}), R19, SERVICE, [{"m": 19, "n": 24}, {"m": 20, "n": 22}], [S_SAME_NEWER],
         A_OK, ("reject", "B8"), ["EMILIA", "Templeman"],
         "the canonical 19-to-24 proof, and the canonical proof from R_20 to R_22 of the same ledger"),
        ("S4-06", "Mixed: a valid consistency proof and an inclusion proof to another root",
         service({-1: older_inclusion, -2: [p19]}), R19, SERVICE, [{"m": 19, "n": 24}], [S_ALL_SAME],
         A_OK, ("reject", "B9"), ["Pinto", "G7"],
         "the canonical 19-to-24 proof, and under -1 the service's inclusion proof of the 19-leaf state, "
         "whose root is R_19"),
        ("S4-07", "Mixed: a valid consistency proof and a valid inclusion proof to the same root, control",
         service({-1: newer_inclusion, -2: [p19]}), R19, SERVICE, [{"m": 19, "n": 24}], [S_ALL_SAME],
         A_OK, B_OK, ["Pinto", "G7"],
         "the canonical 19-to-24 proof, and under -1 the service's own inclusion proof of R_24"),
        ("S4-08", "Unchanged tree: m = n, left siblings only", service({-2: [unchanged]}), R24, SERVICE,
         [{"m": 24, "n": 24}], [S_4], A_OK, ("reject", "B10"), ["EMILIA", "G4"],
         "anchor node(16, 24) of the 24-leaf tree and its one left sibling node(0, 16); both folds give R_24"),
        ("S4-09", "Deeper anchor: the first sibling is a left one", service({-2: [deeper]}), R22, SERVICE,
         [{"m": 22, "n": 24}], [S_ANCHOR, S_NOT_CHECKED], A_OK, ("reject", "B11"), ["G1"],
         "deeper_anchor_proof of the fixture: anchor leaf 21, below the anchor node(20, 22) section 4 requires"),
        ("S4-10", "Tiago Pinto's N1 = HASH(R_6 || HASH(d[6])), signed as the root of 7 leaves",
         test_signed({-2: [enc(tree.root(6), [(False, n1_sibling)])]}, n1, "2.7"), tree.root(6), TEST,
         [{"m": 6, "n": 7}], [S_ANCHOR, S_NO_SIZE], A_OK, ("reject", "B14"),
         ["Pinto"],
         "anchor R_6 of the ledger's first 6 leaves, path [right HASH(d[6])] with the ledger's leaf 6, signed "
         "over N1 = HASH(R_6 || HASH(d[6])) with the txid 2.7 a service writes for a state of 7 leaves; "
         "N1 is a deliberately noncanonical root (R_7 is HASH(node(0, 4) || HASH(node(4, 6) || HASH(d[6])))). "
         "Without sizes the proof has the form of a canonical proof from 4 to 5"),
        ("S4-11", "Empty consistency-proof array", service({-2: []}), R19, SERVICE, None, [S_ONE_OR_MORE],
         A_NO_PROOFS, ("reject", "B4"), [], "vdp {-2: []}"),
        ("S4-12", "A vdp key other than -1 and -2", service({-2: [p19], -3: [p19]}), R19, SERVICE,
         [{"m": 19, "n": 24}], [S_CDDL], A_OK, ("reject", "B3"), [],
         "the canonical 19-to-24 proof under -2, and the same bytes under -3, a label -05 does not define"),
        ("S4-13", "One tag flipped, negative control",
         service({-2: [enc(a19, [(not path19[0][0], path19[0][1])] + path19[1:])]}), R19, SERVICE,
         [{"m": 19, "n": 24}], [S_PATH], A_NO_OLDER, ("reject", "B11"), [],
         "the canonical 19-to-24 proof with the tag of its first path element flipped"),
        ("S4-14", "One signature byte flipped, negative control", service({-2: [p19]}, sig=flip(service_sig, 0)),
         R19, FLIPPED, [{"m": 19, "n": 24}], [S_SIG], A_BAD_SIG, ("reject", "B13"), [],
         "S4-01 with bit 0 of signature byte 0 flipped"),
        ("S4-15", "The older root matches no proof", service({-2: [p19]}), R22, SERVICE,
         [{"m": 19, "n": 24}], [S_BINDS], A_NO_OLDER, ("reject", "B12"), [],
         "the S4-01 receipt, checked against R_22, a root of the same ledger that its proof does not recompute"),
    ]

    try:
        from proofbundle import scitt_ccf as reader
        reader_sha256 = hashlib.sha256((REPO / "src" / "proofbundle" / "scitt_ccf.py").read_bytes()).hexdigest()
    except ImportError:
        reader = None

    for name in [p.name for p in HERE.glob("S4-*.json")]:
        (HERE / name).unlink()
    for (vid, title, receipt, older_root, (prov, prov_note), sizes, sentences, a, b, refs, construction) in cases:
        is_test = prov == "test key"
        spki = test_spki if is_test else service_spki
        kid = test_kid if is_test else service_kid
        issuer = TEST_ISSUER if is_test else service_issuer
        decoded = [{"anchor_hex": d[1].hex(), "path": [[left, h.hex()] for left, h in d[2]]}
                   for d in (cbor2.loads(p) for p in cbor2.loads(receipt).value[1][396].get(-2, []))]
        older_size = next(size for size in range(1, len(tree.leaves) + 1) if tree.root(size) == older_root)
        txid = cbor2.loads(cbor2.loads(receipt).value[0])["ccf.v1"]["txid"]
        newer_size = int(txid.split(".")[1])
        b_free = SIZE_FREE_PASS if b == B_OK or b[1] == "B14" else b
        vector = {
            "id": vid,
            "title": title,
            "draft": DRAFT["name"],
            "sentences": [{"section": s, "text": t} for s, t in sentences],
            "receipt_hex": receipt.hex(),
            "older_root_hex": older_root.hex(),
            "public_key": {"kid": kid.decode("ascii"), "alg": cbor2.loads(cbor2.loads(receipt).value[0])[1],
                           "crv": "P-384" if (key.curve if is_test else curve).name == "secp384r1" else "P-256",
                           "spki_der_hex": spki.hex(), "issuer": issuer},
            "reading_a": {"result": a[0], "step": a[1]},
            "reading_b_size_free": {"result": b_free[0], "rule": b_free[1], "rule_text": None},
            "older_size": older_size,
            "newer_size": newer_size,
            "tree_sizes_note": SIZES_NOTE_S4_10 if vid == "S4-10" else
                               f"older_size: the size of the ledger tree whose root older_root is; newer_size: "
                               f"the seqno of the receipt's ccf.v1 txid {txid}, the tree size its signature "
                               "covers as measured on CCF 7.0.17 with leaf 0 counted (not stated by -05)",
            "reading_b_size_aware": {"result": b[0], "rule": b[1], "rule_text": None},
            "generator_tree_sizes": sizes,
            "consistency_proofs_decoded": decoded,
            "construction": construction,
            "provenance": {"signer": prov, "note": prov_note,
                           "ledger": "scitt-ccf-ledger 00101f769d872711356e080fbb089ac48589c60a, CCF 7.0.17, "
                                     "virtual mode, one node, local; not a production service"},
            "list_references": [{"name": r, "url": LIST[r]} if r in LIST else {"name": r,
                                 "url": "tools/scitt_ccf_external/SECTION4_WGLC.md"} for r in refs],
        }
        if reader is not None:
            trust = ({"scitt_ccf_services": {TEST_ISSUER: [{"spki": test_spki, "kid": test_kid}]}} if is_test
                     else {"scitt_ccf_services": {service_issuer: reader.load_cose_keyset(
                         decode_b64(fx["service_keyset_b64"]))}})
            bare = reader.verify_consistency_receipt(receipt, older_root=older_root, older_issuer=issuer,
                                                     rp_trust=trust)
            with_sizes = reader.verify_consistency_receipt(receipt, older_root=older_root, older_issuer=issuer,
                                                           rp_trust=trust, older_size=older_size,
                                                           newer_size=newer_size)
            vector["proofbundle_reader"] = {
                "information_only": True, "function": "proofbundle.scitt_ccf.verify_consistency_receipt",
                "status_without_sizes": bare.status, "status_with_sizes": with_sizes.status,
                "commit": READER_COMMIT, "scitt_ccf_py_sha256": reader_sha256, "older_issuer": issuer}
        vector["reading_b_size_free"]["rule_text"] = RULE_TEXT.get(b_free[1])
        vector["reading_b_size_aware"]["rule_text"] = RULE_TEXT.get(b[1])
        (HERE / f"{vid}.json").write_text(json.dumps(vector, indent=1) + "\n", encoding="utf-8")

    files = sorted(p for p in HERE.iterdir() if p.is_file() and p.name != "manifest.json"
                   and not p.name.startswith("."))
    manifest = {"what": "every file of this directory but this one, with its length and SHA-256",
                "files": [{"path": p.name, "length": p.stat().st_size,
                           "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    print(f"{len(cases)} vectors, {len(files)} files in manifest.json")
    return 0


# The rule texts and the size-free label are check_vectors.py's own, so a vector names the rule it is
# checked against in the checker's words.
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from check_vectors import B_RULES, SIZE_FREE_PASS  # noqa: E402

RULE_TEXT = {**B_RULES,
             "B1 to B13 hold": "the size-free checks B1 to B13 hold; this does not establish 0 < m < n or "
                               "the canonical anchor position",
             "B1 to B14 hold": "B1 to B13 hold, and B14 with older_size and newer_size"}

if __name__ == "__main__":
    sys.exit(main())
