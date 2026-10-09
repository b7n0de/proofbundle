#!/usr/bin/env python3
"""Register statements on a LOCAL scitt-ccf-ledger and record what the service does with each form.

WHY (owner decision Q6 a, ADR 0009 Decision 3). The data-hash rule was measured on four statements
someone else registered, all tagged, definite, shortest-form, with an embedded payload. What a CCF
service does with any other form was NOT MEASURABLE without registering one. This script registers
them, on a ledger run locally in virtual mode (no TEE, no account), and records per form: whether
the service accepted it, which bytes it stored, and which candidate byte string its receipt's
data-hash equals.

WHAT IS REGISTERED. One signer made here (a P-256 CA and leaf with the extensions the ledger's own
client gives its test certificates: KeyUsage, BasicConstraints, Subject and Authority Key Identifier;
a did:x509 issuer pinned to the CA),
and one payload: the RFC 8785 root of ``examples/example_bundle.json``, a real proofbundle receipt
that verifies. The forms:

  control              tagged, definite, shortest-form, embedded payload: the ADR 0009 v1 shape
  detached             payload nil, signed over the same 32 bytes
  untagged             the control without tag 18
  indefinite_array     the control's four elements inside 9f ... ff
  nonshortest_sig_head the signature's byte-string head as 59 00 40 instead of 58 40
  nonshortest_alg      alg -7 encoded as 38 06 inside the protected header (signed that way)
  indefinite_payload   the payload as an indefinite-length byte string of one chunk
  extra_unprotected    an unprotected map carrying label 99 besides nothing else

WHAT IT IS NOT. Not a production service: the service identity is made at start-up and attested by
nothing. The receipts are CCF receipts produced by the scitt-ccf-ledger code at the pinned commit,
which is what the measurement is about. The signer's private key is made here, used, and discarded;
it is not written anywhere.

USAGE, against a ledger already running and opened with ``scitt governance local_development``:

    python3 local_ledger_probe.py --url https://127.0.0.1:8000 --service-cert service_cert.pem \\
        --ledger-commit <sha> [--vector-out PATH]

Standard library plus ``cryptography`` and ``proofbundle`` (for the bundle root and the verify
check at the end). Talks to the given URL only, never through a proxy.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import platform
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import recompute as R  # noqa: E402 - the measuring aid of this directory, not a basis for src/

RESULT = HERE / "local_ledger_result.json"
BUNDLE = REPO / "examples" / "example_bundle.json"
CN = "proofbundle-scitt-probe"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------------------------------------
# The signer and the statements
# ------------------------------------------------------------------------------------------------
def make_signer():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN + " CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False,
                                       key_agreement=False, key_cert_sign=True, crl_sign=True,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                         critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CN)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_der = ca.public_bytes(serialization.Encoding.DER)
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)
    fp = base64.urlsafe_b64encode(hashlib.sha256(ca_der).digest()).rstrip(b"=").decode()
    did = f"did:x509:0:sha256:{fp}::subject:CN:{CN}"
    spki = leaf_key.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    return leaf_key, [leaf_der, ca_der], did, spki


def sign(key, tbs: bytes) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def statements(key, chain, did, payload: bytes) -> dict:
    enc = R.encode
    prot_map = {1: -7, 15: {1: did, 2: "proofbundle scitt-ccf/v1 probe"}, 33: chain,
                258: -16, 259: "application/json"}
    prot = enc(prot_map)
    sig = sign(key, R.sig_structure(prot, payload))
    bstr = lambda b: enc(b)  # noqa: E731
    control = b"\xd2\x84" + bstr(prot) + b"\xa0" + bstr(payload) + bstr(sig)
    out = {"control": control}
    out["detached"] = b"\xd2\x84" + bstr(prot) + b"\xa0\xf6" + bstr(sig)
    out["untagged"] = control[1:]
    out["indefinite_array"] = b"\xd2\x9f" + bstr(prot) + b"\xa0" + bstr(payload) + bstr(sig) + b"\xff"
    out["nonshortest_sig_head"] = (b"\xd2\x84" + bstr(prot) + b"\xa0" + bstr(payload)
                                   + b"\x59\x00\x40" + sig)
    # alg -7 is normally 26; 38 06 is the same integer with a one-byte argument (not shortest)
    prot_ns = enc(prot_map).replace(b"\x01\x26", b"\x01\x38\x06", 1)
    assert prot_ns != prot
    sig_ns = sign(key, R.sig_structure(prot_ns, payload))
    out["nonshortest_alg"] = b"\xd2\x84" + bstr(prot_ns) + b"\xa0" + bstr(payload) + bstr(sig_ns)
    out["indefinite_payload"] = (b"\xd2\x84" + bstr(prot) + b"\xa0" + b"\x5f" + bstr(payload)
                                 + b"\xff" + bstr(sig))
    out["extra_unprotected"] = (b"\xd2\x84" + bstr(prot) + enc({99: "probe"}) + bstr(payload)
                                + bstr(sig))
    return out


# ------------------------------------------------------------------------------------------------
# The service
# ------------------------------------------------------------------------------------------------
class Service:
    def __init__(self, url: str, service_cert: Path):
        ctx = ssl.create_default_context(cafile=str(service_cert))
        ctx.check_hostname = False     # the node certificate names 127.0.0.1 and localhost only
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=ctx),
                                                  _NoRedirect())

    def call(self, method: str, path: str, body: bytes | None = None, ctype: str | None = None):
        req = urllib.request.Request(self.url + path, data=body, method=method)
        if ctype:
            req.add_header("Content-Type", ctype)
        try:
            with self.opener.open(req, timeout=30) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def register(self, stmt: bytes) -> dict:
        code, headers, body = self.call("POST", "/entries", stmt, "application/cose")
        rec = {"post_status": code}
        if code == 303:                        # SCRAPI: Location names the entry
            loc = headers.get("Location") or headers.get("location") or ""
            txid = loc.rsplit("/entries/", 1)[-1]
        elif code == 202:                      # the legacy flow this service answers with
            try:
                op, _ = R.loads(body)
                op_id = op["OperationId"]
            except Exception:  # noqa: BLE001
                rec.update(accepted=False, error=_problem(body, headers))
                return rec
            txid = None
            for _ in range(60):
                c, _h, b2 = self.call("GET", f"/operations/{op_id}")
                try:
                    st, _ = R.loads(b2)
                except Exception:  # noqa: BLE001
                    st = {}
                if c == 200 and st.get("Status") == "succeeded":
                    txid = st.get("EntryId")
                    break
                if c == 200 and st.get("Status") == "failed":
                    rec.update(accepted=False, error=json.dumps(st.get("Error"), default=repr)[:400])
                    return rec
                time.sleep(0.5)
            if not txid:
                rec.update(accepted=False, error="operation did not finish within 30 s")
                return rec
        else:
            rec["accepted"] = False
            rec["error"] = _problem(body, headers)
            return rec
        rec.update(accepted=True, txid=txid)
        for _ in range(60):
            code, _h, body = self.call("GET", f"/entries/{txid}")
            if code == 200:
                rec["receipt"] = body
                break
            time.sleep(0.5)
        else:
            rec["error"] = f"no receipt after 30 s (last status {code})"
            return rec
        code, _h, body = self.call("GET", f"/entries/{txid}/statement")
        rec["statement_status"] = code
        if code == 200:
            rec["transparent_statement"] = body
        return rec


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _problem(body: bytes, headers: dict) -> str:
    try:
        v, _ = R.loads(body)
        return json.dumps(v, default=repr)[:400]
    except Exception:  # noqa: BLE001 - the error body is recorded, whatever it is
        return body[:400].decode("utf-8", "replace")


# ------------------------------------------------------------------------------------------------
# What the service did
# ------------------------------------------------------------------------------------------------
def analyse(name: str, submitted: bytes, rec: dict, keyset: dict) -> dict:
    out = {"form": name, "submitted_length": len(submitted), "submitted_sha256": sha(submitted),
           "post_status": rec["post_status"], "accepted": rec.get("accepted", False)}
    if not rec.get("accepted"):
        out["service_error"] = rec.get("error")
        return out
    out["txid"] = rec["txid"]
    receipt = rec.get("receipt")
    ts = rec.get("transparent_statement")
    if receipt is None or ts is None:
        out["incomplete"] = rec.get("error", "no receipt or no statement")
        return out
    rr = R.receipt(receipt, keyset, None)
    leaf_dh = rr["inclusion_proofs"][0]["data_hash"] if rr.get("inclusion_proofs") else None
    out["receipt_signature_valid_with_service_keyset"] = rr["signature_valid"]
    out["receipt_leaf_data_hash"] = leaf_dh
    try:
        served = R.parse_sign1(ts)
    except R.Refused as exc:
        out["stored_statement_not_readable_by_measuring_reader"] = str(exc)
        return out
    served_elems = [ts[a:b] for (a, b) in served.spans]
    out["stored_statement"] = {
        "tagged": served.tagged, "all_heads_shortest_form": served.shortest,
        "unprotected_labels": sorted(map(str, served.unprotected)),
        "protected_as_submitted": None, "payload_element_hex_head": served_elems[2][:3].hex(),
        "signature_element_hex_head": served_elems[3][:3].hex()}
    try:
        sub = R.parse_sign1(submitted)
        sub_elems = [submitted[a:b] for (a, b) in sub.spans]
        out["stored_statement"]["protected_as_submitted"] = served_elems[0] == sub_elems[0]
        out["stored_statement"]["payload_element_as_submitted"] = served_elems[2] == sub_elems[2]
        out["stored_statement"]["signature_element_as_submitted"] = served_elems[3] == sub_elems[3]
        spliced = b"\xd2\x84" + sub_elems[0] + b"\xa0" + sub_elems[2] + sub_elems[3]
    except R.Refused as exc:
        out["submitted_not_readable_by_measuring_reader"] = str(exc)
        spliced = None
    stored_emptied = b"\xd2\x84" + served_elems[0] + b"\xa0" + served_elems[2] + served_elems[3]
    cands = {"sha256(submitted bytes)": sha(submitted),
             "sha256(stored statement, unprotected emptied)": sha(stored_emptied)}
    if spliced is not None:
        cands["sha256(submitted elements spliced, tag 18, unprotected a0)"] = sha(spliced)
    out["data_hash_candidates"] = {k: {"sha256": v, "equals_receipt": v == leaf_dh}
                                   for k, v in cands.items()}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Register statement forms on a local scitt-ccf-ledger.")
    ap.add_argument("--url", default="https://127.0.0.1:8000")
    ap.add_argument("--service-cert", required=True, type=Path)
    ap.add_argument("--ledger-commit", required=True)
    ap.add_argument("--image-note", default="")
    ap.add_argument("--vector-out", type=Path)
    ap.add_argument("--build-inputs", type=Path,
                    help="the image's /opt/scitt/share/build-inputs.json, recorded as given")
    args = ap.parse_args(argv)

    import cryptography
    from proofbundle.anchors import receipt_canonical_root
    from proofbundle.bundle import verify_bundle
    bundle = json.loads(BUNDLE.read_text(encoding="utf-8"))
    if not getattr(verify_bundle(bundle), "ok", False):
        print(f"REFUSED: {BUNDLE} does not verify; it is no real proofbundle target.", file=sys.stderr)
        return 1
    root = receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})

    svc = Service(args.url, args.service_cert)
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        print(f"NOT MEASURABLE: the service did not serve its keys ({code}).", file=sys.stderr)
        return 2
    keyset = R.cose_keyset(keys_raw)
    code, _h, cfg = svc.call("GET", "/configuration")

    key, chain, did, spki = make_signer()
    forms = statements(key, chain, did, root)
    results, raw = [], {}
    for name, stmt in forms.items():
        rec = svc.register(stmt)
        raw[name] = rec
        results.append(analyse(name, stmt, rec, keyset))

    doc = {
        "tool": "tools/scitt_ccf_external/local_ledger_probe.py",
        "measured_on": datetime.date.today().isoformat(),
        "environment": {"python": platform.python_version(), "cryptography": cryptography.__version__},
        "service": {"url": args.url, "ledger_repository": "https://github.com/microsoft/scitt-ccf-ledger",
                    "ledger_commit": args.ledger_commit, "image_note": args.image_note,
                    "mode": "virtual (no TEE), single node, opened with `scitt governance local_development`",
                    "configuration": cfg.decode("utf-8", "replace"),
                    "image_build_inputs": (json.loads(args.build_inputs.read_text(encoding="utf-8"))
                                           if args.build_inputs else None),
                    "service_keyset_sha256": sha(keys_raw)},
        "target": {"bundle": str(BUNDLE.relative_to(REPO)), "receipt_canonical_root": root.hex()},
        "signer": {"did": did, "leaf_spki_sha256": sha(spki), "alg": "ES256",
                   "note": "made for this run, private key discarded"},
        "forms": results,
    }
    RESULT.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for r in results:
        dh = r.get("data_hash_candidates", {})
        match = [k for k, v in dh.items() if v["equals_receipt"]]
        print(f"  {r['form']:22s} post={r['post_status']} accepted={r['accepted']!s:5} "
              f"sig={r.get('receipt_signature_valid_with_service_keyset')} match={match} "
              f"{r.get('service_error', '')[:90]}")
    if args.vector_out and raw["control"].get("transparent_statement"):
        vec = {
            "what": "an end-to-end scitt-ccf/v1 control: a hash envelope over a real proofbundle root, "
                    "registered on a local scitt-ccf-ledger in virtual mode",
            "source": "tools/scitt_ccf_external/local_ledger_probe.py", "measured_on": doc["measured_on"],
            "ledger_commit": args.ledger_commit, "issuer": _issuer(raw["control"]["receipt"]),
            "target_bundle": doc["target"]["bundle"], "canonical_root_hex": root.hex(),
            "transparent_statement_b64": base64.b64encode(raw["control"]["transparent_statement"]).decode(),
            "service_keyset_b64": base64.b64encode(keys_raw).decode(),
            "statement_signer_spki_b64": base64.b64encode(spki).decode(),
            "accepted_variants_b64": {n: base64.b64encode(r["transparent_statement"]).decode()
                                      for n, r in raw.items()
                                      if n != "control" and r.get("transparent_statement")},
        }
        args.vector_out.parent.mkdir(parents=True, exist_ok=True)
        args.vector_out.write_text(json.dumps(vec, indent=2) + "\n", encoding="utf-8")
    print(f"written: {RESULT.relative_to(REPO)}")
    return 0


def _issuer(receipt: bytes):
    rc = R.parse_sign1(receipt)
    cwt = rc.protected.get(15) or {}
    return cwt.get(1)


if __name__ == "__main__":
    raise SystemExit(main())
