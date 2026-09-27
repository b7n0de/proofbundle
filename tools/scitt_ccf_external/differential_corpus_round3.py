#!/usr/bin/env python3
"""The differential corpus, third round: the core of the policy-boundary matrix, design version 2.

WHY. Owner order of 2026-09-27 (round 3, design version 2): in a NEW frozen cohort on a rebuilt local
scitt-ccf-ledger, rerun the ordinary control and a10, h08, h07, h06; register five core mutations
(M-u15, M-u258, M-u259, B259-conflicting, M-u2) with their controls; and run the two-key x5chain
experiment. The diagnostic policy probe is not run. Historical rows keep their own pins; nothing here
is combined with an observation of rounds 1 and 2.

THE VECTORS. ``vectors()`` defines each one with the control it is qualified by, what its protected
(P) and unprotected (U) buckets carry, how it is signed, and the outcome predicted BEFORE the run
(``predicted``), written into the tool and committed before the first registration. A movement
removes the P occurrence of a label and inserts the same value in U, and is signed again over its own
protected bytes. A vector that changes only U reuses the control's exact protected bytes, payload and
signature. The rejection controls (h01 again, a signature-invalid twin of the control, and g09 as an
implementation-regression control) are counted apart from the mutations.

TWO KEYS. Leaf A and leaf B are issued by one CA with one subject, so the did:x509 issuer and the
service's trust policy are the same for both. A-only and B-only are controls. With P33 = A and U33 = B
the statement is signed once with A and once with B, then the same with the assignments reversed.
Which key verifies each signature is established independently (``which_key_verifies``) from the
Sig_structure and both public keys; no conflicting kid is used as an oracle.

STORED FORM, as in rounds 1 and 2 (owner answer C1 b): per vector request.hex, receipt.hex and
statement.hex where they exist, every HTTP response body of the registration under http/, and a
record.json with what cannot be derived from bytes (the definition, the prediction, the pins, the raw
API status and detail, and the final state). The derived columns are computed by policy_matrix.py.

STATES. ``registered``: the receipt was retrieved and verifies with the service's key set, checked
with recompute.py, not with the reader under test. ``refused``: the service answered the POST with an
error, or the operation failed. ``timeout``: the operation did not finish within 30 s. ``unfinished``:
the operation succeeded and no receipt came back within 30 s. ``receipt_unverified``: a receipt came
back and does not verify with the service's key set.

USAGE, against a ledger opened with ``scitt governance local_development``:

    python3 differential_corpus_round3.py run --service-cert CERT --ledger-commit SHA --image-id ID \\
        --build-inputs FILE --cohort-pins FILE

Talks to the given URL only, never through a proxy. Output: differential_corpus_round3/.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "differential_corpus_round3"
sys.path.insert(0, str(HERE))
import differential_corpus as D  # noqa: E402 - the first round's writer and pins
import differential_corpus_round2 as D2  # noqa: E402 - the head-width encoders
import local_ledger_probe as P  # noqa: E402 - the signer's certificate profile and the service client
import recompute as R  # noqa: E402 - the independent receipt check

SHA = D.SHA
i_, t_, b_, a_, m_ = D2.i_, D2.t_, D2.b_, D2.a_, D2.m_
CN = "proofbundle-scitt-probe"
LABEL = "proofbundle differential corpus, round 3"
POLL_SECONDS = 30


# ------------------------------------------------------------------------------------------------
# Two leaf keys under one CA and one subject: one did:x509 issuer, one trust policy
# ------------------------------------------------------------------------------------------------
def make_signers():
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN + " CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))

    def leaf():
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)]))
                .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                             key_encipherment=False, data_encipherment=False, key_agreement=False,
                                             key_cert_sign=False, crl_sign=False, encipher_only=False,
                                             decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                               critical=False)
                .sign(ca_key, hashes.SHA256()))
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        return key, cert.public_bytes(serialization.Encoding.DER), spki

    ca_der = ca.public_bytes(serialization.Encoding.DER)
    fp = base64.urlsafe_b64encode(hashlib.sha256(ca_der).digest()).rstrip(b"=").decode()
    did = f"did:x509:0:sha256:{fp}::subject:CN:{CN}"
    return {"A": leaf(), "B": leaf()}, ca_der, did


def which_key_verifies(protected: bytes, payload: bytes, sig: bytes, spkis: dict) -> dict:
    """For each named SubjectPublicKeyInfo: does ES256 over this Sig_structure verify? Independent of
    the service and of the reader under test: cryptography's ECDSA over RFC 9052 section 4.4."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    tbs = R.sig_structure(protected, payload)
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
    out = {}
    for name, spki in spkis.items():
        try:
            serialization.load_der_public_key(spki).verify(der, tbs, ec.ECDSA(hashes.SHA256()))
            out[name] = True
        except InvalidSignature:
            out[name] = False
    return out


# ------------------------------------------------------------------------------------------------
# The vectors, with the outcome predicted before the run
# ------------------------------------------------------------------------------------------------
def vectors(signers: dict, ca: bytes, did: str, payload: bytes) -> list:
    """(definition, bytes, signer name) per vector. A definition holds id, kind, control, mutation, P, U,
    signing and predicted; ``predicted`` was written before the first registration of this round."""
    (key_a, leaf_a, _spki_a), (key_b, leaf_b, _spki_b) = signers["A"], signers["B"]
    cwt = m_([(i_(1), t_(did)), (i_(2), t_(LABEL))])
    chain_a, chain_b = a_([b_(leaf_a), b_(ca)]), a_([b_(leaf_b), b_(ca)])
    base = [(i_(1), i_(-7)), (i_(15), cwt), (i_(33), chain_a), (i_(258), i_(-16)),
            (i_(259), t_("application/json"))]
    keys = {"A": key_a, "B": key_b}

    def signed(prot_map: bytes, unprot: bytes = b"\xa0", signer: str = "A") -> tuple:
        sig = P.sign(keys[signer], R.sig_structure(prot_map, payload))
        return D.sign1(b_(prot_map), unprot, b_(payload), b_(sig)), sig

    def without(label: int) -> list:
        return [(k, v) for k, v in base if k != i_(label)]

    def value(label: int) -> bytes:
        return dict(base)[i_(label)]

    ctl_prot = m_(base)
    ctl, ctl_sig = signed(ctl_prot)
    v: list = []

    def add(vid, kind, control, mutation, p, u, signing, predicted, why, raw, signer="A"):
        v.append(({"id": vid, "kind": kind, "control": control, "mutation": mutation,
                   "p_semantics": p, "u_semantics": u, "signing": signing, "signer": signer,
                   "external_aad": "", "predicted": {"outcome": predicted, "why": why}}, raw, signer))

    same_sig = "the control's exact protected bytes, payload and signature"
    p_ctl = "alg -7, CWT Claims {iss: did:x509, sub}, x5chain [leaf A, CA], 258 = -16, 259 = application/json"
    add("control", "control", None, "the ordinary control, as in rounds 1 and 2", p_ctl, "empty",
        "signed with A over its own protected bytes", "accepted",
        "the v1 shape was accepted in rounds 1 and 2", ctl)

    # rejection controls, counted apart from the mutations
    bad = bytearray(ctl_sig)
    bad[-1] ^= 1
    add("c-signature-invalid", "rejection control", "control", "the control with the last signature byte changed",
        p_ctl, "empty", "the control's protected bytes and payload, one signature byte changed", "refused",
        "an ES256 signature that does not verify under the x5chain key",
        D.sign1(b_(ctl_prot), b"\xa0", b_(payload), b_(bytes(bad))))
    add("c-h01-protected-duplicate-alg-equal", "rejection control", "control",
        "h01 again: alg (1) twice in the protected map, -7 both times, adjacent",
        "as the control, alg twice", "empty", "signed with A over its own protected bytes", "refused",
        "h01 was refused in round 2", signed(m_(base[:1] + [(i_(1), i_(-7))] + base[1:]))[0])
    add("c-g09-map-indefinite", "implementation-regression control", "control",
        "g09 again: the protected map with an indefinite length (bf ... ff)",
        "as the control, map head indefinite", "empty", "signed with A over its own protected bytes", "refused",
        "g09 was refused in round 2", signed(m_(base, indefinite=True))[0])
    crit_base = sorted(base + [(i_(2), a_([i_(33)]))], key=lambda p: p[0])
    crit_prot = m_(crit_base)
    add("c-crit33", "control", None, "crit [33] in the protected header, x5chain protected (i01 of round 2)",
        "as the control, plus crit [33]", "empty", "signed with A over its own protected bytes", "accepted",
        "i01 was accepted in round 2", signed(crit_prot)[0])

    # reruns of historical vectors in this cohort; never combined with their historical observations
    def rerun(vid, pairs, mutation, u, why):
        add(vid, "rerun", "control", mutation, p_ctl, u, same_sig, "accepted", why,
            D.sign1(b_(ctl_prot), m_(pairs), b_(payload), b_(ctl_sig)))
    rerun("r-a10-cwt-claims-unprotected", [(i_(15), m_([(i_(1), t_("did:example:spoofed"))]))],
          "a10 again: CWT Claims with another issuer in the unprotected bucket",
          "CWT Claims {iss: did:example:spoofed}", "a10 was accepted in round 1")
    rerun("r-h08-cwt-claims-both-buckets-equal", [(i_(15), cwt)],
          "h08 again: CWT Claims also in the unprotected bucket, equal", "CWT Claims, equal to P",
          "h08 was accepted in round 2")
    rerun("r-h07-payload-hash-alg-both-buckets-conflicting", [(i_(258), i_(-43))],
          "h07 again: 258 also in the unprotected bucket, -43", "258 = -43",
          "h07 was accepted in round 2")
    rerun("r-h06-alg-both-buckets-conflicting", [(i_(1), i_(-35))],
          "h06 again: alg also in the unprotected bucket, -35", "alg = -35", "h06 was accepted in round 2")

    # the five core mutations
    def moved(vid, label, why, predicted):
        prot = m_(without(label))
        add(vid, "mutation", "control", f"label {label} removed from P and the same value inserted in U",
            f"as the control without {label}", f"{label}, the control's P value",
            "signed with A over its own protected bytes", predicted, why,
            signed(prot, m_([(i_(label), value(label))]))[0])
    moved("m-u15", 15, "the service's policy reads phdr.cwt.iss, which is protected only; the issuer is "
          "then absent", "refused")
    moved("m-u258", 258, "no measured rule of this service requires 258; the unprotected bucket was ignored "
          "in every accepted row of rounds 1 and 2", "accepted")
    moved("m-u259", 259, "no measured rule of this service requires 259; the unprotected bucket was ignored "
          "in every accepted row of rounds 1 and 2", "accepted")
    add("b259-conflicting", "mutation", "control",
        "259 also in U with a conflicting value; P, payload and signature unchanged", p_ctl,
        "259 = text/plain", same_sig, "accepted",
        "a label in both buckets was accepted in h05 to h09 of round 2",
        D.sign1(b_(ctl_prot), m_([(i_(259), t_("text/plain"))]), b_(payload), b_(ctl_sig)))
    add("m-u2", "mutation", "c-crit33", "crit [33] removed from P and inserted in U; 33 stays in P",
        p_ctl, "crit [33]", "signed with A over its own protected bytes", "accepted",
        "the unprotected bucket was ignored in every accepted row of rounds 1 and 2",
        signed(ctl_prot, m_([(i_(2), a_([i_(33)]))]))[0])

    # the two-key x5chain experiment
    prot_a = ctl_prot
    prot_b = m_([(k, chain_b if k == i_(33) else val) for k, val in base])
    p_a, p_b = "as the control, x5chain [leaf A, CA]", "as the control, x5chain [leaf B, CA]"
    add("x-a-only", "two-key control", None, "x5chain A in P only, signed with A", p_a, "empty",
        "signed with A over its own protected bytes", "accepted", "the control's shape", signed(prot_a)[0])
    add("x-b-only", "two-key control", None, "x5chain B in P only, signed with B", p_b, "empty",
        "signed with B over its own protected bytes", "accepted", "the control's shape with key B",
        signed(prot_b, signer="B")[0], signer="B")
    for vid, prot, u_chain, p_text, u_text, signer, predicted in (
            ("x-pa-ub-sig-a", prot_a, chain_b, p_a, "x5chain [leaf B, CA]", "A", "accepted"),
            ("x-pa-ub-sig-b", prot_a, chain_b, p_a, "x5chain [leaf B, CA]", "B", "refused"),
            ("x-pb-ua-sig-a", prot_b, chain_a, p_b, "x5chain [leaf A, CA]", "A", "refused"),
            ("x-pb-ua-sig-b", prot_b, chain_a, p_b, "x5chain [leaf A, CA]", "B", "accepted")):
        add(vid, "two-key", f"x-{'a' if p_text.endswith('A, CA]') else 'b'}-only",
            f"x5chain in both buckets, conflicting; signed with {signer}", p_text, u_text,
            f"signed with {signer} over its own protected bytes", predicted,
            "predicted under the hypothesis that the service selects the key from the protected x5chain only",
            signed(prot, m_([(i_(33), u_chain)]), signer)[0], signer=signer)
    return v


# ------------------------------------------------------------------------------------------------
# Registration, every HTTP exchange recorded
# ------------------------------------------------------------------------------------------------
def _headers(h: dict) -> dict:
    keep = ("content-type", "location", "x-ms-ccf-transaction-id", "retry-after")
    return {k.lower(): v for k, v in h.items() if k.lower() in keep}


def _detail(body: bytes) -> str:
    try:
        v, _ = R.loads(body)
        return json.dumps(v, default=repr)[:600]
    except Exception:  # noqa: BLE001 - the body is kept as bytes anyway
        return body[:600].decode("utf-8", "replace")


def register(svc, stmt: bytes, keyset: dict) -> tuple:
    """-> (exchanges [(step, method, path, status, headers, body)], outcome dict)."""
    ex: list = []

    def call(step, method, path, body=None, ctype=None):
        code, headers, resp = svc.call(method, path, body, ctype)
        ex.append((step, method, path, code, _headers(headers), resp))
        return code, headers, resp

    code, headers, body = call("register", "POST", "/entries", stmt, "application/cose")
    if code == 303:
        loc = headers.get("Location") or headers.get("location") or ""
        txid = loc.rsplit("/entries/", 1)[-1]
    elif code == 202:
        try:
            op, _ = R.loads(body)
            op_id = op["OperationId"]
        except Exception:  # noqa: BLE001
            return ex, {"state": "unfinished", "error_stage": "POST /entries (unreadable operation)",
                        "api_status": code, "api_detail": _detail(body)}
        txid = None
        deadline = time.monotonic() + POLL_SECONDS
        while time.monotonic() < deadline:
            c, _h, b2 = call("operation", "GET", f"/operations/{op_id}")
            try:
                st, _ = R.loads(b2)
            except Exception:  # noqa: BLE001
                st = {}
            if c == 200 and st.get("Status") == "succeeded":
                txid = st.get("EntryId")
                break
            if c == 200 and st.get("Status") == "failed":
                return ex, {"state": "refused", "error_stage": "operation", "api_status": c,
                            "api_detail": _detail(b2)}
            time.sleep(0.5)
        if not txid:
            return ex, {"state": "timeout", "error_stage": "operation", "api_status": code,
                        "api_detail": f"the operation did not finish within {POLL_SECONDS} s"}
    else:
        return ex, {"state": "refused", "error_stage": "POST /entries", "api_status": code,
                    "api_detail": _detail(body)}
    receipt = None
    deadline = time.monotonic() + POLL_SECONDS
    while time.monotonic() < deadline:
        c, _h, b3 = call("receipt", "GET", f"/entries/{txid}")
        if c == 200:
            receipt = b3
            break
        time.sleep(0.5)
    if receipt is None:
        return ex, {"state": "unfinished", "error_stage": f"GET /entries/{txid}", "txid": txid,
                    "api_status": c, "api_detail": f"no receipt within {POLL_SECONDS} s"}
    c, _h, served = call("statement", "GET", f"/entries/{txid}/statement")
    check = R.receipt(receipt, keyset, None)
    independent = {"readable": check.get("readable"), "signature_valid": check.get("signature_valid"),
                   "receipt_profile_satisfied": check.get("receipt_profile_satisfied"),
                   "problems": check.get("problems", [])[:5]}
    state = "registered" if check.get("readable") and check.get("signature_valid") is True else "receipt_unverified"
    return ex, {"state": state, "error_stage": None if state == "registered" else "receipt check",
                "txid": txid, "api_status": code, "api_detail": None, "receipt": receipt,
                "statement": served if c == 200 else None, "statement_status": c,
                "receipt_check_recompute": independent}


def _write(out: Path, meta: dict, stmt: bytes, ex: list, outcome: dict, pinned: dict, extra: dict) -> None:
    d = out / "vectors" / meta["id"]
    (d / "http").mkdir(parents=True, exist_ok=False)
    files = {"request.hex": stmt, "receipt.hex": outcome.pop("receipt", None),
             "statement.hex": outcome.pop("statement", None)}
    files = {k: x for k, x in files.items() if x is not None}
    for name, data in files.items():
        D.write_hex(d / name, data)
    http = []
    for n, (step, method, path, code, headers, body) in enumerate(ex, 1):
        name = f"http/{n:02d}-{step}.hex"
        D.write_hex(d / name, body)
        http.append({"n": n, "step": step, "method": method, "path": path, "status": code, "headers": headers,
                     "body": name, "body_sha256": SHA(body), "body_length": len(body)})
    record = {**meta, "cohort": "round 3", **extra, "pins": pinned, "outcome": outcome, "http": http,
              "files": {k: {"sha256": SHA(x), "length": len(x)} for k, x in files.items()}}
    (d / "record.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")


def _pins(args, svc) -> dict:
    pinned = D.pins(args, svc)
    own = str(args.out.resolve().relative_to(D.REPO))
    pinned["verifier"]["tree_clean"] = D._git("status", "--porcelain", "--", ".", f":(exclude){own}") == ""
    pinned["verifier"]["tree_clean_excludes"] = own + "/, this run's own output"
    pinned["verifier"]["tool"] = "tools/scitt_ccf_external/differential_corpus_round3.py"
    reader = "src/proofbundle/scitt_ccf.py"
    pinned["verifier"]["reader_file"] = {"path": reader, "git_blob": D._git("rev-parse", f"HEAD:{reader}")}
    code, headers, cfg = svc.call("GET", "/configuration")
    pinned["service"]["configuration_sha256"] = SHA(cfg) if code == 200 else None
    pinned["service"]["configuration_read_at_txid"] = headers.get("x-ms-ccf-transaction-id")
    return pinned


def run(args) -> int:
    from proofbundle.anchors import receipt_canonical_root
    bundle = json.loads(P.BUNDLE.read_text(encoding="utf-8"))
    root = receipt_canonical_root({k: x for k, x in bundle.items() if k != "anchors"})
    if (args.out / "manifest.json").exists():
        raise SystemExit(f"REFUSED: {args.out} holds a run; its bytes are kept, not replaced")
    (args.out / "vectors").mkdir(parents=True, exist_ok=True)
    svc = P.Service(args.url, args.service_cert)
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        raise SystemExit(f"NOT MEASURABLE: the service did not serve its keys ({code}).")
    D.write_hex(args.out / "scitt-keys.hex", keys_raw)
    keyset = R.cose_keyset(keys_raw)
    code, _h, gov = svc.call("GET", "/gov/members/proposals?api-version=2024-07-01")
    signers, ca, did = make_signers()
    spkis = {name: s[2] for name, s in signers.items()}
    started = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    ids = []
    for meta, stmt, _signer in vectors(signers, ca, did, root):
        prot, pl, sig, _spans = D.contents(stmt)
        extra = {"signature_verifies_under": which_key_verifies(prot, pl if pl is not None else b"", sig, spkis)}
        pinned = _pins(args, svc)
        ex, outcome = register(svc, stmt, keyset)
        _write(args.out, meta, stmt, ex, outcome, pinned, extra)
        ids.append(meta["id"])
        print(f"  {meta['id']:48s} {outcome['state']:18s} predicted {meta['predicted']['outcome']:8s} "
              f"{outcome.get('txid') or outcome.get('api_detail', '')[:60]}")
    manifest = {
        "tool": "tools/scitt_ccf_external/differential_corpus_round3.py", "started": started,
        "measured_on": datetime.date.today().isoformat(), "cohort": "round 3 (new frozen cohort)",
        "cohort_pins": json.loads(Path(args.cohort_pins).read_text(encoding="utf-8")) if args.cohort_pins else None,
        "image_build_inputs": (json.loads(Path(args.build_inputs).read_text(encoding="utf-8"))
                               if args.build_inputs else None),
        "service_keyset": {"file": "scitt-keys.hex", "sha256": SHA(keys_raw)},
        "governance_proposals": {"status": code, "body_sha256": SHA(gov), "body": gov.decode("utf-8", "replace")},
        "signer": {"did": did, "ca_sha256": SHA(ca), "ca_hex": ca.hex(),
                   "keys": {name: {"leaf_sha256": SHA(s[1]), "spki_hex": s[2].hex()} for name, s in signers.items()},
                   "alg": "ES256", "note": "one CA, two leaves with one subject; made for this run, private keys "
                                          "discarded"},
        "target": {"bundle": str(P.BUNDLE.relative_to(D.REPO)), "receipt_canonical_root": root.hex()},
        "vectors": ids,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--url", default="https://127.0.0.1:8000")
    r.add_argument("--service-cert", type=Path, required=True)
    r.add_argument("--ledger-commit", required=True)
    r.add_argument("--image-id", required=True)
    r.add_argument("--build-inputs", default=None)
    r.add_argument("--cohort-pins", default=None)
    r.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
