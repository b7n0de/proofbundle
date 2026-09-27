#!/usr/bin/env python3
"""The policy-boundary matrix over the differential corpus: one row per registered vector.

WHY. Owner order of 2026-09-27 (20:2x Berlin, addendum 20:4x; design version 2 of 21:4x Berlin): a
reviewer of the corpus asked to see two things apart, (1) which bytes the service commits to in
data-hash, and (2) which semantically awkward or conflicting COSE structures its parser and policy still
accept. The rows of rounds 1 and 2 are derived from their stored bytes; they keep their own pins and are
never combined with round 3, which was registered in a new frozen cohort on a rebuilt ledger
(differential_corpus_round3.py).

COLUMNS (design version 2):
  vector                                  round and id
  profile and mutation                    the statement profile of the row and what changes against its control
  P semantics, U semantics                both buckets as submitted, decoded entry by entry, every encoding that
                                          is not the preferred one named
  normative class and source              JUDGEMENT, kept apart: normative.json, one of six classes, the sources
                                          and the rule as quoted from the archived revision (sources.json), and
                                          the condition of a conditional rule
  predicted local outcome                 round 3: written into the generator before the run; rounds 1 and 2:
                                          NOT RECORDED
  final registration outcome, error stage registered (a receipt that verifies with the service's key set,
                                          checked with recompute.py), refused, timeout, unfinished or
                                          receipt_unverified, and where it ended
  data-hash rule match                    registered: the receipt's data-hash against the preimage rule through
                                          own computation, cbor2 and EverCBOR (round 3: EverCBOR NOT MEASURED)
  reconstructed commitment preimage       registered: the bytes the data-hash commits to, and the evidence
  interpretation observation and method   what can be observed without changing the service, and how
  own decode, submitted / returned        decode_cose_sign1 of src/proofbundle/scitt_ccf.py on both forms
  statement signature, both forms         verify_statement_signature on both forms under the round's signer
                                          key(s); round 3 also which key verifies, established independently
  own full verification, returned         verify_transparent_statement on the returned statement: status and the
                                          three booleans readable, signature_valid, profile_satisfied

ORACLES. The service's answers, the returned statements and the receipts are fixtures: the bytes the
generators recorded, checked against their recorded digests before use. The preimage rule and the "own"
data-hash path are our own computation (preimage_candidates.py, candidate 4-tagged); the "cbor2" path is
a foreign library re-encoding the same candidate; the "EverCBOR" path is a foreign tool built by us
(vendored_encoder_probe.py, CCF's vendored encoder). The receipt check is recompute.py, independent of
the reader under test. The reader columns are our own reader, run here on the stored bytes. The
unprotected check (`reader_unprotected_effect`) runs the reader again on the submitted bytes with the
unprotected map replaced by an empty one, to see whether anything in that bucket changes its verdict.

USAGE:
    python3 policy_matrix.py --write      # derive and write differential_corpus_round3/matrix.json and the
                                          # matrix table in differential_corpus_round3/README.md
    python3 policy_matrix.py --check      # derive and compare with the written matrix.json (exit 1 on any
                                          # difference)
Offline. Needs the [scitt] extra (cbor2) for the reader.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "differential_corpus_round3"
sys.path.insert(0, str(HERE))
import differential_corpus as D  # noqa: E402 - the corpus's own reader and hex files
import recompute as R  # noqa: E402 - the independent receipt check

ROUNDS = ((1, "differential_corpus"), (2, "differential_corpus_round2"), (3, "differential_corpus_round3"))
VENDORED = HERE / "vendored_encoder_result.json"
NORMATIVE = OUT / "normative.json"
PREIMAGE_RULE = "4-tagged"
NOT_RECORDED = "NOT RECORDED: rounds 1 and 2 were registered before any outcome was predicted"
EVERCBOR_R3 = ("NOT MEASURED for round 3: vendored_encoder_probe.py needs a CCF clone at ccf-7.0.17 and an "
               "EverParse build, not run in this step")
PROFILE = ("v1 hash envelope over the example bundle's root: ES256, CWT Claims {iss: did:x509, sub}, "
           "x5chain [leaf, CA], 258 = -16, 259 = application/json")
NOT_MEASURABLE_ACCEPTED = (
    "NOT MEASURABLE: the service accepted, and what it returned (the statement, the receipt) does not say "
    "which of the submitted header values its parser or policy read; the corpus queried no other read "
    "endpoint, and observing it otherwise needs a change to the service")

LABELS = {1: "alg", 2: "crit", 3: "content type", 4: "kid", 15: "CWT claims", 33: "x5chain",
          258: "payload hash alg", 259: "preimage content type", 260: "payload location", 394: "receipts"}
CWT = {1: "iss", 2: "sub", 3: "aud", 4: "exp", 5: "nbf", 6: "iat", 7: "cti"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _note(node: dict) -> str:
    framing = node.get("framing", "")
    if "NOT shortest" in framing or "indefinite" in framing:
        return f" <{framing}>"
    return ""


def value_text(node, *, cwt: bool = False) -> str:
    """A decoded item of cose_structure as short text, with every encoding that is not preferred named."""
    if not isinstance(node, dict):
        return repr(node)
    kind = node.get("type")
    if kind == "int":
        text = str(node.get("value"))
    elif kind == "tstr":
        t = node.get("text", "")
        text = repr(t if len(t) <= 60 else t[:57] + "...")
    elif kind == "bstr":
        text = f"bstr[{node.get('length')}]"
    elif kind == "array":
        text = "[" + ", ".join(value_text(i) for i in node.get("items", [])) + "]"
    elif kind == "map":
        text = "{" + map_text(node, cwt=cwt) + "}"
    else:
        text = str(kind)
    return text + _note(node)


def map_text(node: dict, *, top: bool = False, cwt: bool = False) -> str:
    parts = []
    for key, val in node.get("entries", []):
        k = key.get("value", key.get("text")) if isinstance(key, dict) else key
        names = CWT if cwt else (LABELS if top else {})
        name = names.get(k) if isinstance(k, int) and not isinstance(k, bool) else None
        shown = (repr(k) if key.get("type") == "tstr" else str(k)) + (f" {name}" if name else "")
        parts.append(f"{shown}{_note(key)}: {value_text(val, cwt=top and k == 15)}")
    return "; ".join(parts)


def header_text(node) -> str:
    if not isinstance(node, dict):
        return "(absent)"
    if node.get("type") != "map":
        return f"not a map: {node.get('type')}"
    inner = map_text(node, top=True)
    return ("{" + inner + "}" if inner else "{} (empty)") + _note(node)


def reader_on(raw: bytes, *, root: bytes, rp: dict) -> dict:
    """Our reader on one byte string: decode, statement side, statement signature, whole check."""
    from proofbundle import scitt_ccf as S
    try:
        S.decode_cose_sign1(raw, role="statement")
        decode = {"status": "read", "text": "decode_cose_sign1 reads it"}
    except S.ScittFormatError as exc:
        decode = {"status": exc.status, "text": str(exc)}
    check = S.verify_transparent_statement(raw, canonical_root=root, rp_trust=rp)
    sig_status, sig_valid = S.verify_statement_signature(raw, statement_keys=rp["scitt_statement_keys"])
    return {"decode": decode, "statement_status": check.statement_status, "status": check.status,
            "detail": check.detail, "statement_signature": {"status": sig_status, "valid": sig_valid}}


def _unprotected_emptied(raw: bytes) -> bytes:
    """The same bytes with the unprotected map replaced by an empty one (a0), every other byte kept."""
    st = D.cose_structure(raw)
    a, b = st["unprotected"]["span"]
    return raw[:a] + b"\xa0" + raw[b:]


def _load_round(number: int, name: str) -> list:
    corpus = HERE / name
    man = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    from proofbundle import scitt_ccf as S
    root = bytes.fromhex(man["target"]["receipt_canonical_root"])
    if "spki_hex" in man["signer"]:
        signer = [bytes.fromhex(man["signer"]["spki_hex"])]
    else:   # round 3: one CA, two leaves; the reader selects among them by the protected x5chain
        signer = [bytes.fromhex(k["spki_hex"]) for _n, k in sorted(man["signer"]["keys"].items())]
    if "phases" in man:
        keysets = {ph["name"]: D.read_hex(corpus / ph["keyset"]) for ph in man["phases"]}
    else:
        raw = D.read_hex(corpus / "scitt-keys.hex")
        if _sha(raw) != man["service_keyset"]["sha256"]:
            raise SystemExit(f"REFUSED: {name}/scitt-keys.hex is not the recorded key set")
        keysets = {None: raw}
    vendored = {v["id"]: v for v in json.loads(VENDORED.read_text(encoding="utf-8"))["corpora"]
                .get(name, {}).get("vectors", [])}
    out = []
    for vid in man["vectors"]:
        d = corpus / "vectors" / vid
        meta = json.loads((d / "record.json").read_text(encoding="utf-8"))
        files = {}
        for fname, want in meta["files"].items():
            files[fname] = D.read_hex(d / fname)
            if _sha(files[fname]) != want["sha256"]:
                raise SystemExit(f"REFUSED: {name}/{vid}/{fname} is not the recorded bytes")
        phase = (meta.get("phase") or {}).get("name")
        if "outcome" in meta:     # round 3: the generator's states, read as the earlier rounds' fields
            o = meta["outcome"]
            meta = {**meta, "class": meta["kind"],
                    "service": {"post_status": meta["http"][0]["status"], "accepted": o["state"] == "registered",
                                "txid": o.get("txid"), "error": o.get("api_detail")}}
        rp = {"scitt_ccf_services": {"127.0.0.1:8000": S.load_cose_keyset(keysets[phase])},
              "scitt_statement_keys": signer}
        cands = d / "candidate_hashes.json"
        out.append({"round": number, "corpus": name, "id": vid, "meta": meta, "files": files, "rp": rp,
                    "root": root, "candidates": json.loads(cands.read_text(encoding="utf-8")) if cands.exists() else None,
                    "vendored": vendored.get(vid), "keyset": R.cose_keyset(keysets[phase])})
    return out


def _receipt_data_hash(v: dict):
    """The data-hash of the first inclusion proof, read by recompute.py (independent of the reader)."""
    rr = R.receipt(v["files"]["receipt.hex"], v["keyset"], None)
    proofs = rr.get("inclusion_proofs") or []
    return (proofs[0]["data_hash"] if proofs else None), rr


def _own_4_tagged(v: dict) -> tuple:
    """Candidate 4-tagged computed here: deterministic [protected, {}, payload, signature], tag 18, the
    contents as submitted, preferred heads; and the same through cbor2."""
    import cbor2
    prot, payload, sig, _spans = D.contents(v["files"]["request.hex"])
    bstr = lambda b: R.encode(b)  # noqa: E731
    own = b"\xd2\x84" + bstr(prot) + b"\xa0" + bstr(payload) + bstr(sig)
    via = cbor2.dumps(cbor2.CBORTag(18, [prot, {}, payload, sig]))
    return _sha(own), via == own


def _data_hash_match(v: dict) -> dict:
    if not v["meta"]["service"]["accepted"]:
        return {"text": "NOT MEASURABLE: refused, no receipt"}
    if v["candidates"] is None:
        dh, _rr = _receipt_data_hash(v)
        own_hash, cbor2_same = _own_4_tagged(v)
        own = own_hash == dh
        paths = {"own": own, "cbor2": own and cbor2_same, "evercbor": None}
        yes = [k for k, x in paths.items() if x is True]
        no = [k for k, x in paths.items() if x is False]
        text = ("match: " + ", ".join(yes) if yes else "") + (("; NO: " + ", ".join(no)) if no else "")
        return {**paths, "text": (text + "; evercbor " + EVERCBOR_R3).strip("; "), "receipt_data_hash": dh}
    cand = ((v["candidates"] or {}).get("candidates") or {}).get(PREIMAGE_RULE) or {}
    own = cand.get("equals_data_hash")
    cbor2 = (own is True and cand.get("cbor2_equal") is True) if cand.get("cbor2_equal") is not None else None
    ever = (v["vendored"] or {}).get("output_sha256_equals_data_hash")
    paths = {"own": own, "cbor2": cbor2, "evercbor": ever}
    yes = [k for k, x in paths.items() if x is True]
    no = [k for k, x in paths.items() if x is False]
    missing = [k for k, x in paths.items() if x is None]
    text = ("match: " + ", ".join(yes) if yes else "") + (("; NO: " + ", ".join(no)) if no else "") + \
           (("; not recorded: " + ", ".join(missing)) if missing else "")
    return {**paths, "text": text.strip("; ")}


def _committed(v: dict, statement: dict) -> str:
    if not v["meta"]["service"]["accepted"]:
        return "NOT MEASURABLE: refused, no receipt, nothing committed"
    facts = (v["candidates"] or {}).get("facts") or {}
    sub = D.cose_structure(v["files"]["request.hex"])
    ret = statement
    same = {k: D.contents(v["files"]["request.hex"])[i] == D.contents(v["files"]["statement.hex"])[i]
            for i, k in ((0, "protected"), (1, "payload"), (2, "signature"))}
    parts = [f"tag {ret.get('tag')}",
             "protected " + ("as submitted" if same["protected"] else "NOT as submitted") +
             f" ({sub['protected'].get('length')} bytes)",
             "unprotected emptied in the preimage",
             "payload " + ("as submitted" if same["payload"] else "NOT as submitted"),
             "signature " + ("as submitted" if same["signature"] else "NOT as submitted")]
    labels = facts.get("returned_unprotected_labels")
    if labels is None:
        labels = [e[0].get("value", e[0].get("text")) for e in ret["unprotected"].get("entries", [])]
    return ("preimage = [" + ", ".join(parts) + f"]; the returned statement's unprotected labels: {labels}")


def row(v: dict) -> dict:
    meta, files = v["meta"], v["files"]
    sub = files["request.hex"]
    st_sub = D.cose_structure(sub)
    accepted = bool(meta["service"]["accepted"])
    returned = files.get("statement.hex")
    st_ret = D.cose_structure(returned) if returned else None
    ours_sub = reader_on(sub, root=v["root"], rp=v["rp"])
    emptied = reader_on(_unprotected_emptied(sub), root=v["root"], rp=v["rp"])
    ours_ret = reader_on(returned, root=v["root"], rp=v["rp"]) if returned else None
    effect = ("none: the same statement-side status with the unprotected map emptied"
              if emptied["statement_status"] == ours_sub["statement_status"] else
              f"changes: {ours_sub['statement_status']} as submitted, {emptied['statement_status']} with the "
              "unprotected map emptied")
    error = meta["service"].get("error")
    vector = f"r{v['round']}/{v['id']}"
    full_ret = _full(returned, root=v["root"], rp=v["rp"]) if returned else None
    out = {
        "vector": vector,
        "round": v["round"], "cohort": "round 3, new frozen cohort" if v["round"] == 3 else f"round {v['round']}",
        "class": meta.get("class"), "phase": (meta.get("phase") or {}).get("name"),
        "profile_and_mutation": {"profile": PROFILE, "control": meta.get("control", meta.get("base")),
                                 "mutation": meta.get("mutation")},
        "mutation": meta.get("mutation"),
        "protected_semantics": header_text((st_sub.get("protected") or {}).get("decoded")),
        "unprotected_semantics": header_text(st_sub.get("unprotected")),
        "normative": v["normative"],
        "predicted": (meta["predicted"] if "predicted" in meta else {"outcome": None, "why": NOT_RECORDED}),
        "registration": _registration(v, accepted),
        "accepted_refused": "accepted" if accepted else "refused",
        "service": {"post_status": meta["service"].get("post_status"), "txid": meta["service"].get("txid"),
                    "error": error},
        "data_hash_match": _data_hash_match(v),
        "committed_representation": _committed(v, st_ret) if accepted else "NOT MEASURABLE: refused, no receipt, nothing committed",
        "parser_visible_interpretation": (f"error text: {error}" if not accepted and error else
                                          ("NOT MEASURABLE: refused without an error text" if not accepted
                                           else NOT_MEASURABLE_ACCEPTED)),
        "interpretation": _interpretation(meta, accepted, error),
        "our_reader_submitted": ours_sub,
        "our_reader_returned": ours_ret,
        "statement_signature_checks": {
            "submitted": ours_sub["statement_signature"],
            "returned": ours_ret["statement_signature"] if ours_ret else None,
            "which_key_verifies": meta.get("signature_verifies_under"),
        },
        "own_full_verification_returned": full_ret,
        "reader_booleans_submitted": _full(sub, root=v["root"], rp=v["rp"]),
        "reader_unprotected_effect": effect,
        "reader_against_service": _against(accepted, ours_sub),
        "files": {"corpus": v["corpus"], "vector": f"vectors/{v['id']}/",
                  "request_sha256": _sha(sub), "statement_sha256": _sha(returned) if returned else None},
    }
    if "outcome" in meta:
        out["record"] = _machine_record(meta)
    return out


def _full(raw: bytes, *, root: bytes, rp: dict) -> dict:
    """verify_transparent_statement: the status and the three booleans, apart."""
    from proofbundle import scitt_ccf as S
    r = S.verify_transparent_statement(raw, canonical_root=root, rp_trust=rp)
    return {"status": r.status, "readable": r.readable, "signature_valid": r.signature_valid,
            "profile_satisfied": r.profile_satisfied, "statement_status": r.statement_status}


def _registration(v: dict, accepted: bool) -> dict:
    """The final state and where it ended. Rounds 1 and 2 recorded the POST answer and the receipt; the
    receipt is checked here with recompute.py, as round 3's generator checked it."""
    meta = v["meta"]
    if "outcome" in meta:
        o = meta["outcome"]
        return {"state": o["state"], "error_stage": o.get("error_stage"), "api_status": o.get("api_status"),
                "api_detail": o.get("api_detail"), "receipt_check": o.get("receipt_check_recompute")}
    s = meta["service"]
    if not accepted:
        return {"state": "refused", "error_stage": "POST /entries" if s.get("post_status") == 400 else "operation",
                "api_status": s.get("post_status"), "api_detail": s.get("error"), "receipt_check": None}
    _dh, rr = _receipt_data_hash(v)
    ok = bool(rr.get("readable")) and rr.get("signature_valid") is True
    return {"state": "registered" if ok else "receipt_unverified", "error_stage": None if ok else "receipt check",
            "api_status": s.get("post_status"), "api_detail": None,
            "receipt_check": {"readable": rr.get("readable"), "signature_valid": rr.get("signature_valid")}}


def _interpretation(meta: dict, accepted: bool, error) -> dict:
    """What can be observed without changing the service, and how."""
    keys = meta.get("signature_verifies_under")
    if keys is not None and meta.get("kind", "").startswith("two-key"):
        who = [k for k, ok in sorted(keys.items()) if ok]
        return {"observation": f"{'registered' if accepted else 'refused'}; the signature verifies under key "
                               f"{', '.join(who) or 'none'}; P and U as in the semantics columns",
                "method": "the registration outcome beside which key verifies the signature, established "
                          "with cryptography over the Sig_structure, independent of the service"}
    if not accepted:
        return {"observation": f"error text: {error}" if error else "refused without an error text",
                "method": "the service's error answer"}
    return {"observation": NOT_MEASURABLE_ACCEPTED, "method": "none available without changing the service"}


def _machine_record(meta: dict) -> dict:
    """Round 3's machine record, as the design asks for it: bytes and digests, commits, pins, trust
    material, configuration digest and transaction, external AAD, the control, the raw API answer."""
    pins = meta["pins"]
    return {
        "generator": {"tool": pins["verifier"].get("tool"), "commit": pins["verifier"]["commit"],
                      "tree_clean": pins["verifier"]["tree_clean"]},
        "reader": pins["verifier"].get("reader_file"),
        "service": {k: pins["service"].get(k) for k in ("commit", "image_id", "node_version", "attestation_format",
                                                         "configuration_sha256", "configuration_read_at_txid")},
        "configuration_written_at_txid": ("NOT MEASURED: the governance API names the accepted proposal, not the "
                                          "transaction that applied it"),
        "external_aad": meta.get("external_aad"), "control": meta.get("control"), "signer": meta.get("signer"),
        "signing": meta.get("signing"),
        "http": [{k: h[k] for k in ("n", "step", "method", "path", "status", "body_sha256")} for h in meta["http"]],
        "files": meta["files"],
    }


def _against(accepted: bool, ours_sub: dict) -> str:
    """Measured, not judged: our reader's statement-side status beside what the service did."""
    ok = ours_sub["statement_status"] == "confirmed"
    if accepted and not ok:
        return f"stricter than the service: the service accepted, our reader says {ours_sub['statement_status']}"
    if not accepted and ok:
        return "less strict than the service: the service refused, our reader's statement side is confirmed"
    return "same direction as the service"


def derive() -> dict:
    normative = json.loads(NORMATIVE.read_text(encoding="utf-8"))["rows"]
    rows = []
    for number, name in ROUNDS:
        vectors = _load_round(number, name)
        control = next((v for v in vectors if v["id"] == "control"), None)
        control_dh = (((control or {}).get("candidates") or {}).get("receipt_data_hash") if number < 3
                      else _receipt_data_hash(control)[0])
        for v in vectors:
            n = normative[f"r{number}/{v['id']}"]      # the quoted rules stay in normative.json
            v["normative"] = {"normative_class": n["normative_class"],
                              "sections": sorted({s["section"] for s in n["sources"]}),
                              **{k: n[k] for k in ("condition", "note") if k in n}}
            r = row(v)
            dh = (((v["candidates"] or {}).get("receipt_data_hash") if number < 3 else _receipt_data_hash(v)[0])
                  if r["accepted_refused"] == "accepted" else None)
            r["data_hash_match"]["receipt_data_hash"] = dh
            r["data_hash_match"]["equals_round_control"] = (dh == control_dh) if dh and control_dh else None
            rows.append(r)
    counts: dict = {}
    by_class: dict = {}
    for r in rows:
        key = f"r{r['round']}/{r['class']}"
        c = counts.setdefault(key, {"vectors": 0, "accepted": 0, "refused": 0})
        c["vectors"] += 1
        c["accepted" if r["accepted_refused"] == "accepted" else "refused"] += 1
        cohort = "round 3" if r["round"] == 3 else "rounds 1 and 2"
        n = by_class.setdefault(r["normative"]["normative_class"], {}).setdefault(
            cohort, {"vectors": 0, "accepted": 0, "refused": 0})
        n["vectors"] += 1
        n["accepted" if r["accepted_refused"] == "accepted" else "refused"] += 1
    return {
        "tool": "tools/scitt_ccf_external/policy_matrix.py",
        "rounds": {"1": "differential_corpus/", "2": "differential_corpus_round2/",
                   "3": "differential_corpus_round3/vectors/, a new frozen cohort on a rebuilt ledger (design version 2)"},
        "normative": "normative.json (judgement) and sources.json (the archived revisions)",
        "counts_by_normative_class": {k: by_class[k] for k in sorted(by_class)},
        "preimage_rule": "candidate 4-tagged of preimage_candidates.py: deterministic [protected, {}, payload, "
                         "signature], tag 18, the protected header as the bytes submitted",
        "oracles": {"service answers, returned statements, receipts": "fixtures, the recorded bytes",
                    "own": "own computation (preimage_candidates.py)",
                    "cbor2": "foreign library, cbor2, re-encoding the same candidate",
                    "evercbor": "foreign tool built by us (vendored_encoder_probe.py)",
                    "our reader": "src/proofbundle/scitt_ccf.py, run on the stored bytes"},
        "counts": counts,
        "rows": rows,
    }


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _data_hash_cell(d: dict) -> str:
    same = d.get("equals_round_control")
    if same is None:
        return d["text"]
    return d["text"] + ("; the same data-hash as the round's control" if same else "; other than the round's control")



def _normative_cell(n: dict) -> str:
    return n["normative_class"] + ": " + "; ".join(n["sections"]) + (f" (condition: {n['condition']})" if n.get("condition") else "")


def _predicted_cell(p: dict) -> str:
    return p["why"] if p.get("outcome") is None else f"{p['outcome']}: {p['why']}"


def _registration_cell(r: dict) -> str:
    stage = f", at {r['error_stage']}" if r.get("error_stage") else ""
    return f"{r['state']}{stage}" + (f": {r['api_detail']}" if r.get("api_detail") else "")


def _decode_cell(o) -> str:
    if o is None:
        return "n/a: nothing returned"
    d = o["decode"]
    return d["status"] + ("" if d["status"] == "read" else f": {d['text']}")


def _signature_cell(r: dict) -> str:
    s = r["statement_signature_checks"]
    ret = s["returned"]["status"] if s["returned"] else "n/a"
    text = f"submitted {s['submitted']['status']}; returned {ret}"
    if s.get("which_key_verifies") is not None:
        keys = [k for k, ok in sorted(s["which_key_verifies"].items()) if ok]
        text += f"; verifies under key {', '.join(keys) or 'none'}"
    return text


def _full_cell(f) -> str:
    if f is None:
        return "n/a: nothing returned"
    return (f"{f['status']} (readable {str(f['readable']).lower()}, signature_valid "
            f"{str(f['signature_valid']).lower()}, profile_satisfied {str(f['profile_satisfied']).lower()})")


def table(m: dict) -> str:
    cols = ["vector", "profile and mutation", "P semantics", "U semantics", "normative class and source",
            "predicted local outcome", "final registration outcome and error stage", "data-hash rule match",
            "reconstructed commitment preimage and evidence", "interpretation observation and method",
            "own decode, submitted", "own decode, returned", "statement signature, both forms",
            "own full verification, returned"]
    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    lines = []
    for r in m["rows"]:
        pm = r["profile_and_mutation"]
        cells = [r["vector"], f"control {pm['control']}; {pm['mutation']}" if pm["control"] else pm["mutation"],
                 r["protected_semantics"], r["unprotected_semantics"], _normative_cell(r["normative"]),
                 _predicted_cell(r["predicted"]), _registration_cell(r["registration"]),
                 _data_hash_cell(r["data_hash_match"]), r["committed_representation"],
                 f"{r['interpretation']['observation']} (method: {r['interpretation']['method']})",
                 _decode_cell(r["our_reader_submitted"]), _decode_cell(r["our_reader_returned"]),
                 _signature_cell(r), _full_cell(r["own_full_verification_returned"])]
        lines.append("| " + " | ".join(_cell(c) for c in cells) + " |")
    return head + "\n".join(lines) + "\n"


BEGIN = "<!-- matrix table: written by policy_matrix.py --write -->"
END = "<!-- end of the matrix table -->"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    m = derive()
    text = json.dumps(m, indent=1, ensure_ascii=False) + "\n"
    target = OUT / "matrix.json"
    if args.check:
        same = target.exists() and target.read_text(encoding="utf-8") == text
        print(f"{'OK  ' if same else 'DIFF'} {target.relative_to(HERE)}: {len(m['rows'])} rows")
        return 0 if same else 1
    if args.write:
        OUT.mkdir(exist_ok=True)
        target.write_text(text, encoding="utf-8")
        readme = OUT / "README.md"
        body = readme.read_text(encoding="utf-8") if readme.exists() else ""
        if BEGIN in body and END in body:
            body = body.split(BEGIN)[0] + BEGIN + "\n\n" + table(m) + "\n" + END + body.split(END, 1)[1]
            readme.write_text(body, encoding="utf-8")
    for key, c in sorted(m["counts"].items()):
        print(f"{key:6s} vectors {c['vectors']:2d} accepted {c['accepted']:2d} refused {c['refused']:2d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
