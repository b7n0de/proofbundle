#!/usr/bin/env python3
"""The differential corpus, second round: four further classes on a LOCAL scitt-ccf-ledger.

WHY. Owner order of 2026-09-26, step 3 of the seventh addendum. It runs only after the data-hash
preimage was identified (preimage_candidates.py: one byte string, 29 of 29). A reviewer of the first
round asked for these four classes before any other.

CLASSES. Each is measured against a control made in this run. Every vector carries a valid signature.
A vector whose protected header changes is signed again over its own protected bytes. A vector that
changes only the unprotected map keeps the control's signature, which covers no unprotected byte.

  g  semantically equivalent protected-header encodings and orderings: the same labels and values,
     encoded another way
  h  duplicate map keys, and labels present in both buckets, equal and conflicting
  i  crit (label 2): parameters this service knows, against unknown ones
  j  one fixed accepted statement (the control's bytes) registered again after a configuration
     change and after a restart. A software-version boundary is measured only when a second service
     image is available.

STORED FORM, as in differential_corpus/ (owner answer C1 b): request.hex, receipt.hex,
statement.hex and record.json per vector, the key set of every phase as scitt-keys.<phase>.hex, and
the run in manifest.json. summary.json and admissibility.json are derived by ``derive``. Every
record pins the service commit, image, CCF version and the configuration the service reported when
that vector was registered.

USAGE, against a ledger already running and opened with ``scitt governance local_development``:

    python3 differential_corpus_round2.py run --phase initial --service-cert CERT \\
        --ledger-commit SHA --image-id ID --build-inputs FILE
    python3 differential_corpus_round2.py repeat --phase after-configuration-change --service-cert CERT \\
        --ledger-commit SHA --image-id ID --build-inputs FILE --note TEXT
    python3 differential_corpus_round2.py derive [--vector ID] [--write] [--check]

Talks to the given URL only, never through a proxy. Output: differential_corpus_round2/.
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "differential_corpus_round2"
sys.path.insert(0, str(HERE))
import differential_corpus as D  # noqa: E402 - the first round's writer, reader and chain
import local_ledger_probe as P  # noqa: E402 - the signer and service client of this directory
import recompute as R  # noqa: E402 - the measuring aid of this directory

SHA = D.SHA
RULE = "sha256(returned elements as served, unprotected emptied, tag 18)"


# ------------------------------------------------------------------------------------------------
# Encoding pieces that can write every head width, including the ones a serializer would not choose
# ------------------------------------------------------------------------------------------------
def hd(mt: int, n: int, width: int | None = None) -> bytes:
    return D.head(mt, n, width)


def i_(n: int, width: int | None = None) -> bytes:
    return hd(0, n, width) if n >= 0 else hd(1, -1 - n, width)


def t_(s: str, width: int | None = None) -> bytes:
    r = s.encode("utf-8")
    return hd(3, len(r), width) + r


def b_(x: bytes, width: int | None = None) -> bytes:
    return hd(2, len(x), width) + x


def a_(items: list, width: int | None = None) -> bytes:
    return hd(4, len(items), width) + b"".join(items)


def m_(pairs: list, width: int | None = None, indefinite: bool = False) -> bytes:
    body = b"".join(k + v for k, v in pairs)
    return (b"\xbf" + body + b"\xff") if indefinite else hd(5, len(pairs), width) + body


# ------------------------------------------------------------------------------------------------
# The vectors
# ------------------------------------------------------------------------------------------------
def vectors(key, chain, did, payload: bytes) -> list:
    leaf, ca = chain
    label = "proofbundle differential corpus, round 2"
    cwt = m_([(i_(1), t_(did)), (i_(2), t_(label))])
    base = [(i_(1), i_(-7)), (i_(15), cwt), (i_(33), a_([b_(leaf), b_(ca)])), (i_(258), i_(-16)),
            (i_(259), t_("application/json"))]

    def signed(prot_map: bytes, unprot: bytes = b"\xa0") -> bytes:
        sig = P.sign(key, R.sig_structure(prot_map, payload))
        return D.sign1(b_(prot_map), unprot, b_(payload), b_(sig))

    ctl_prot = m_(base)
    ctl = signed(ctl_prot)
    ctl_sig = D.contents(ctl)[2]

    def unsigned_change(unprot: bytes) -> bytes:
        return D.sign1(b_(ctl_prot), unprot, b_(payload), b_(ctl_sig))

    def replace(label_int: int, value: bytes) -> list:
        return [(k, value if k == i_(label_int) else v) for k, v in base]

    v = [("control", "control", None, "the v1 shape of this run: tagged, definite, shortest, embedded payload, "
          "empty unprotected, protected labels in ascending order", ctl)]

    def g(vid, prot_map, what):
        v.append((vid, "g", "control", what + "; signed again", signed(prot_map)))
    g("g01-keys-descending", m_(list(reversed(base))), "the protected labels in descending order")
    g("g02-cwt-claims-keys-reversed", m_(replace(15, m_([(i_(2), t_(label)), (i_(1), t_(did))]))),
      "the CWT claims map (15) with its keys 2 before 1")
    g("g03-alg-1-byte-argument", m_(replace(1, i_(-7, 1))), "alg -7 as 38 06, a 1-byte argument")
    g("g04-alg-2-byte-argument", m_(replace(1, i_(-7, 2))), "alg -7 as 39 00 06, a 2-byte argument")
    g("g05-label-1-byte-argument", m_([(i_(1, 1), i_(-7))] + base[1:]), "the label 1 as 18 01, a 1-byte argument")
    g("g06-map-count-1-byte-argument", m_(base, width=1), "the protected map head b8 05, a 1-byte count")
    g("g07-text-2-byte-length", m_(replace(259, t_("application/json", 2))),
      "the content type text of 259 with a 2-byte length argument")
    g("g08-x5chain-array-1-byte-count", m_(replace(33, a_([b_(leaf), b_(ca)], 1))),
      "the x5chain array head 98 02, a 1-byte count")
    g("g09-map-indefinite", m_(base, indefinite=True), "the protected map with an indefinite length (bf ... ff)")

    def hp(vid, prot_map, what):
        v.append((vid, "h", "control", what + "; signed again", signed(prot_map)))
    hp("h01-protected-duplicate-alg-equal", m_(base[:1] + [(i_(1), i_(-7))] + base[1:]),
       "alg (1) twice in the protected map, -7 both times, the two entries adjacent")
    hp("h02-protected-duplicate-alg-conflicting", m_(base[:1] + [(i_(1), i_(-35))] + base[1:]),
       "alg (1) twice in the protected map, -7 then -35, the two entries adjacent")

    def hu(vid, pairs, what):
        v.append((vid, "h", "control", what + "; the control's signature", unsigned_change(m_(pairs))))
    hu("h03-unprotected-duplicate-equal", [(i_(99), t_("a")), (i_(99), t_("a"))], "label 99 twice in the unprotected map, equal")
    hu("h04-unprotected-duplicate-conflicting", [(i_(99), t_("a")), (i_(99), t_("b"))],
       "label 99 twice in the unprotected map, conflicting")
    hu("h05-alg-both-buckets-equal", [(i_(1), i_(-7))], "alg (1) also in the unprotected bucket, equal")
    hu("h06-alg-both-buckets-conflicting", [(i_(1), i_(-35))], "alg (1) also in the unprotected bucket, -35")
    hu("h07-payload-hash-alg-both-buckets-conflicting", [(i_(258), i_(-43))],
       "the payload hash algorithm (258) also in the unprotected bucket, -43")
    hu("h08-cwt-claims-both-buckets-equal", [(i_(15), cwt)], "CWT claims (15) also in the unprotected bucket, equal")
    hu("h09-x5chain-both-buckets-conflicting", [(i_(33), b_(leaf))],
       "x5chain (33) also in the unprotected bucket, the end-entity certificate alone")

    def ic(vid, crit_items, extra, what):
        # every label in its core deterministic place (bytewise order of the encoded label), so crit is
        # the only variable of this class
        pairs = sorted(base + [(i_(2), a_(crit_items))] + extra, key=lambda p: p[0])
        v.append((vid, "i", "control", what + "; signed again", signed(m_(pairs))))
    ic("i01-crit-x5chain", [i_(33)], [], "crit [33], x5chain")
    ic("i02-crit-cwt-claims", [i_(15)], [], "crit [15], CWT claims")
    ic("i03-crit-cwt-claims-and-x5chain", [i_(15), i_(33)], [], "crit [15, 33]")
    ic("i04-crit-unknown-int-present", [i_(99)], [(i_(99), t_("x"))], "crit [99], label 99 present")
    ic("i05-crit-unknown-int-absent", [i_(99)], [], "crit [99], label 99 absent")
    ic("i06-crit-unknown-text-present", [t_("x")], [(t_("x"), i_(1))], "crit [\"x\"], label \"x\" present")
    ic("i07-crit-registered-not-listed", [i_(259)], [], "crit [259], a registered label the service does not list")
    ic("i08-crit-empty", [], [], "crit [], an empty array")
    return v


# ------------------------------------------------------------------------------------------------
# The run: raw bytes and the pins of the moment each vector was registered
# ------------------------------------------------------------------------------------------------
def _pins(args, svc) -> dict:
    """The first round's pins, with the tree judged clean apart from this run's own output directory,
    which the run writes into before its first registration."""
    pinned = D.pins(args, svc)
    own = str(args.out.resolve().relative_to(D.REPO))
    dirty = D._git("status", "--porcelain", "--", ".", f":(exclude){own}")
    pinned["verifier"]["tree_clean"] = dirty == ""
    pinned["verifier"]["tree_clean_excludes"] = own + "/, this run's own output"
    return pinned


def _write_vector(out: Path, meta: dict, request: bytes, rec: dict, pinned: dict, phase: dict) -> None:
    d = out / "vectors" / meta["id"]
    d.mkdir(parents=True, exist_ok=False)
    files = {"request.hex": request, "receipt.hex": rec.get("receipt"), "statement.hex": rec.get("transparent_statement")}
    files = {k: x for k, x in files.items() if x is not None}
    for name, data in files.items():
        D.write_hex(d / name, data)
    record = {**meta, "phase": phase, "pins": pinned,
              "service": {"post_status": rec.get("post_status"), "accepted": bool(rec.get("accepted")),
                          "txid": rec.get("txid"), "error": rec.get("error")},
              "files": {k: {"sha256": SHA(x), "length": len(x)} for k, x in files.items()}}
    (d / "record.json").write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")


def _phase_keys(out: Path, svc, phase: str) -> str:
    code, _h, keys_raw = svc.call("GET", "/.well-known/scitt-keys")
    if code != 200:
        raise SystemExit(f"NOT MEASURABLE: the service did not serve its keys ({code}).")
    name = f"scitt-keys.{phase}.hex"
    D.write_hex(out / name, keys_raw)
    return name


def run(args) -> int:
    from proofbundle.anchors import receipt_canonical_root
    bundle = json.loads(P.BUNDLE.read_text(encoding="utf-8"))
    root = receipt_canonical_root({k: x for k, x in bundle.items() if k != "anchors"})
    if (args.out / "manifest.json").exists():
        raise SystemExit(f"REFUSED: {args.out} holds a run; its bytes are kept, not replaced")
    (args.out / "vectors").mkdir(parents=True)
    svc = P.Service(args.url, args.service_cert)
    keys_file = _phase_keys(args.out, svc, args.phase)
    key, chain, did, spki = P.make_signer()
    phase = {"name": args.phase, "keyset": keys_file, "note": args.note}
    ids = []
    for vid, cls, base, what, stmt in vectors(key, chain, did, root):
        pinned = _pins(args, svc)
        rec = svc.register(stmt)
        _write_vector(args.out, {"id": vid, "class": cls, "base": base, "mutation": what}, stmt, rec, pinned, phase)
        ids.append(vid)
        print(f"  {vid:48s} {rec.get('post_status')} accepted={bool(rec.get('accepted'))!s:5} {rec.get('txid') or ''}")
    manifest = {
        "tool": "tools/scitt_ccf_external/differential_corpus_round2.py", "measured_on": datetime.date.today().isoformat(),
        "image_build_inputs": (json.loads(Path(args.build_inputs).read_text(encoding="utf-8"))
                               if args.build_inputs else None),
        "signer": {"did": did, "spki_hex": spki.hex(), "alg": "ES256", "note": "made for this run, private key discarded"},
        "target": {"bundle": str(P.BUNDLE.relative_to(D.REPO)), "receipt_canonical_root": root.hex()},
        "phases": [phase], "vectors": ids,
    }
    (args.out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    return 0


def repeat(args) -> int:
    """Register the control's stored bytes again, in a new phase (after a change the operator made)."""
    man = json.loads((args.out / "manifest.json").read_text(encoding="utf-8"))
    if any(p["name"] == args.phase for p in man["phases"]):
        raise SystemExit(f"REFUSED: phase {args.phase} is already recorded")
    stmt = D.read_hex(args.out / "vectors" / "control" / "request.hex")
    svc = P.Service(args.url, args.service_cert)
    keys_file = _phase_keys(args.out, svc, args.phase)
    phase = {"name": args.phase, "keyset": keys_file, "note": args.note}
    vid = f"j{len(man['phases']):02d}-{args.phase}"
    pinned = _pins(args, svc)
    rec = svc.register(stmt)
    _write_vector(args.out, {"id": vid, "class": "j", "base": "control",
                             "mutation": f"the control's bytes registered again, {args.phase}: {args.note}"},
                  stmt, rec, pinned, phase)
    man["phases"].append(phase)
    man["vectors"].append(vid)
    (args.out / "manifest.json").write_text(json.dumps(man, indent=1) + "\n", encoding="utf-8")
    print(f"  {vid:48s} {rec.get('post_status')} accepted={bool(rec.get('accepted'))!s:5} {rec.get('txid') or ''}")
    return 0


# ------------------------------------------------------------------------------------------------
# Derived views
# ------------------------------------------------------------------------------------------------
def derive(corpus: Path) -> tuple:
    from proofbundle import scitt_ccf as S
    man = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    root = bytes.fromhex(man["target"]["receipt_canonical_root"])
    keysets = {}
    for ph in man["phases"]:
        raw = D.read_hex(corpus / ph["keyset"])
        keysets[ph["name"]] = (R.cose_keyset(raw), S.load_cose_keyset(raw))
    records, control_dh = [], None
    for vid in man["vectors"]:
        d = corpus / "vectors" / vid
        meta = json.loads((d / "record.json").read_text(encoding="utf-8"))
        raw = {}
        for name, want in meta["files"].items():
            raw[name] = D.read_hex(d / name)
            if SHA(raw[name]) != want["sha256"]:
                raise SystemExit(f"REFUSED: {vid}/{name} is not the recorded bytes")
        svc = meta["service"]
        rec = {"post_status": svc["post_status"], "accepted": svc["accepted"], "txid": svc["txid"],
               "error": svc["error"], "receipt": raw.get("receipt.hex"), "transparent_statement": raw.get("statement.hex")}
        keyset, loaded = keysets[meta["phase"]["name"]]
        rp = {"scitt_ccf_services": {"127.0.0.1:8000": loaded},
              "scitt_statement_keys": [bytes.fromhex(man["signer"]["spki_hex"])]}
        r = D.record((vid, meta["class"], meta["base"], meta["mutation"], raw["request.hex"]), rec, keyset,
                     meta["pins"], root, rp, control_dh)
        r["phase"] = meta["phase"]
        if vid == "control" and "response" in r:
            control_dh = r["response"]["receipt_leaf_data_hash"]
        records.append(r)

    def row(r):
        resp = r.get("response") or {}
        return {"id": r["id"], "class": r["class"], "phase": r["phase"]["name"], "mutation": r["mutation"],
                "accepted": r["service"]["accepted"], "service_error": r["service"].get("error"),
                "txid": resp.get("txid"), "data_hash": resp.get("receipt_leaf_data_hash"),
                "data_hash_equals_control": resp.get("receipt_data_hash_equals_control"),
                "receipt_signature_valid": resp.get("receipt_signature_valid_with_service_keyset"),
                "preimage_rule_holds": (resp.get("data_hash_candidates") or {}).get(RULE, {}).get("equals_receipt_data_hash"),
                "returned_elements_equal_submitted": resp.get("returned_elements_equal_submitted_elements"),
                "v1_reader_on_submitted_bytes": r["v1_reader_on_submitted_bytes"]["status"],
                "v1_reader_on_returned": (resp.get("v1_reader_on_returned_transparent_statement") or {}).get("status")}
    rows = [row(r) for r in records]
    classes = {}
    for cls in "ghij":
        rs = [x for x in rows if x["class"] == cls]
        acc = [x for x in rs if x["accepted"]]
        classes[cls] = {"vectors": len(rs), "accepted": len(acc), "refused": len(rs) - len(acc),
                        "preimage_rule_holds": sum(1 for x in acc if x["preimage_rule_holds"]),
                        "data_hash_equals_control": sorted(x["id"] for x in acc if x["data_hash_equals_control"])}
    accepted = [x for x in rows if x["accepted"]]
    summary = {
        "tool": "tools/scitt_ccf_external/differential_corpus_round2.py", "measured_on": man["measured_on"],
        "signer": man["signer"], "target": man["target"], "phases": man["phases"],
        "vectors": rows, "classes": classes,
        "preimage_rule": RULE,
        "preimage_rule_holds_for_every_accepted_vector": all(x["preimage_rule_holds"] for x in accepted),
    }
    admissibility = {"note": "Refusals of this service, as returned. A refusal is what this service did with the "
                             "bytes; it is not judged SCITT-invalid here.",
                     "refused": [{k: x[k] for k in ("id", "class", "phase", "mutation", "service_error",
                                                    "v1_reader_on_submitted_bytes")}
                                 | {"files": f"vectors/{x['id']}/"} for x in rows if not x["accepted"]]}
    return records, summary, admissibility


def _dump(v) -> str:
    return json.dumps(v, indent=1) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="The differential corpus, second round, on a local scitt-ccf-ledger.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "repeat"):
        r = sub.add_parser(name)
        r.add_argument("--phase", required=True)
        r.add_argument("--note", default="")
        r.add_argument("--url", default="https://127.0.0.1:8000")
        r.add_argument("--service-cert", required=True, type=Path)
        r.add_argument("--ledger-commit", required=True)
        r.add_argument("--image-id", required=True)
        r.add_argument("--build-inputs", type=Path)
        r.add_argument("--out", type=Path, default=OUT)
    d = sub.add_parser("derive")
    d.add_argument("--corpus", type=Path, default=OUT)
    d.add_argument("--vector")
    d.add_argument("--write", action="store_true")
    d.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd == "run":
        return run(args)
    if args.cmd == "repeat":
        return repeat(args)
    records, summary, admissibility = derive(args.corpus)
    if args.vector:
        print(_dump(next(x for x in records if x["id"] == args.vector)), end="")
        return 0
    if args.write:
        (args.corpus / "summary.json").write_text(_dump(summary), encoding="utf-8")
        (args.corpus / "admissibility.json").write_text(_dump(admissibility), encoding="utf-8")
    if args.check:
        same = all((args.corpus / n).read_text(encoding="utf-8") == _dump(x)
                   for n, x in (("summary.json", summary), ("admissibility.json", admissibility)))
        print("derived equals stored" if same else "DIFFERS")
        return 0 if same else 1
    print(json.dumps(summary["classes"], indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
