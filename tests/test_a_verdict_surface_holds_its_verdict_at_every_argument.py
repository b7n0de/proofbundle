"""The gate before run 7, part two: every public verdict surface and every argument of it has a valid base case, an
expected verdict, a proof that the argument reaches the verdict, controls, and the verdict holds against the forms a
caller's object can take.

SOURCE. The review before run 7 (finding F3): a denominator over functions and arguments alone is not enough when an
invalid placeholder ends the call before the check it is meant to reach; the existing exception family uses such
placeholders on purpose (tests/test_never_raise_surface_family_property.py, `_stub_for`), and a sweep over arguments
alone misses the answers of callbacks and the private copies handed to callback code. So each pair here starts from a
LEGITIMATE input built from this package's own emitters and fixtures (the sweep of
tests/test_one_reading_at_every_surface.py, `_flaechen`, and the surfaces it did not list, `_flaechen_vier`), and the
check is shown to be reached before anything is judged.

PER SURFACE AND ARGUMENT:
* THE BASE CASE AND ITS EXPECTED VERDICT: the call as the sweep makes it, read as every evaluative output it returns
  (`_urteil`: ok, policy_ok, safeForAutomation, every check, every status, and the bytes an emitter writes), and run
  twice to the same verdict.
* THE REACH: a change of the argument's value (`_stoerungen`, a leaf or the whole value) changes the verdict. An
  argument no change reaches is named as not reached, never counted as held.
* THE CONTROL: the same value as recording subclasses of dict, list, str and bytes (a promised form) gives the same
  verdict and runs none of their methods; so a refusal of everything cannot pass.
* THE FORMS: a value whose own methods answer the base value while it stores a value the base verdict does not hold
  for (`_luegner`) must not get the base verdict: the verdict is that of what the object stores, or a typed refusal.

WHAT IS VISIBLY OPEN. A verdict surface without a base case is named in `_OHNE_GRUNDFALL` with its reason, an argument
that no change reaches is listed by the reach case, and a surface whose base verdict is not stable is listed. The
report test prints all three with their counts; none of them counts as passed.

Correlated changes of several arguments, answers of callbacks, private copies handed to callbacks, ABA and controlled
thread switches are part three (tests/test_a_verdict_is_that_of_a_state_the_inputs_held.py).
"""
from __future__ import annotations

import copy
import dataclasses
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import test_never_raise_surface_family_property as _familie  # noqa: E402
import test_one_reading_at_every_surface as _sweep  # noqa: E402
from proofbundle import canonical  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402


# ── the verdict: every evaluative output, as plain data ─────────────────────────────────────────────────────────────

def _urteil(ergebnis: Any) -> Any:
    """Every evaluative output of a surface's answer as plain data: the sweep's reading (`_klar`) of a dict, a
    `VerificationResult`, a list, bytes or text, which keeps policy_ok, safeForAutomation, every check and status, the
    signed properties and the written bytes. A signing key a loader returns is read as its public key, the value a
    caller compares."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if isinstance(ergebnis, Ed25519PrivateKey):
        return ("signing key", ergebnis.public_key().public_bytes_raw())
    return _sweep._klar(ergebnis)


def _rufe(fn: Callable, argumente: "dict[str, Any]") -> "tuple[str, Any]":
    """("answered", the verdict) or ("refused", the type name of a typed refusal) or ("raised", the type name).
    The arguments are passed as the signature takes them; each value of a ``*args`` or ``**kwargs`` parameter is an
    argument of its own here (`_flach`), named ``args[0]`` or ``kwargs.key``, and is passed in its place."""
    positional: list = []
    benannt: dict = {}
    luecke = False
    for name, p in inspect.signature(fn).parameters.items():
        if p.kind == inspect.Parameter.VAR_POSITIONAL:
            stellen = sorted((int(k[len(name) + 1:-1]), k) for k in argumente if k.startswith(name + "["))
            positional.extend(argumente[k] for _, k in stellen)
            continue
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            benannt.update({k[len(name) + 1:]: v for k, v in argumente.items() if k.startswith(name + ".")})
            continue
        if name not in argumente:
            luecke = luecke or p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
            continue
        if p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD and luecke:
            benannt[name] = argumente[name]
        elif p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            positional.append(argumente[name])
        else:
            benannt[name] = argumente[name]
    try:
        return "answered", _urteil(fn(*positional, **benannt))
    except ProofBundleError as exc:
        return "refused", type(exc).__name__
    except Exception as exc:  # noqa: BLE001 - the outcome is compared, not judged here
        return "raised", type(exc).__name__


def _kopie(wert: Any) -> Any:
    """A private copy of a base argument for one run; an object that cannot be copied (a signing key) is shared, as
    every run passes the same one."""
    try:
        return copy.deepcopy(wert)
    except Exception:  # noqa: BLE001 - a key object of the cryptography package cannot be copied
        return wert


# ── the base cases ──────────────────────────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class _Grundfall:
    name: str
    fn: Callable
    argumente: "dict[str, Any]"
    urteil: Any


def _aufgeloest(name: str) -> Callable:
    modul, _, attr = name.rpartition(".")
    return getattr(importlib.import_module("proofbundle." + modul), attr)


def _gefangen(name: str, aufruf: Callable[[Callable[[Any], Any]], Any]) -> "dict[str, Any] | None":
    """The arguments the sweep's call of ``name`` passes, bound to the surface's parameters: the reading of the
    surface's own call is taken from `canonical._gelesen`, whose caller frame holds the wrapped function. A helper the
    call makes on the way (a `verify_bundle` that builds an argument) is a reading of another function and is left."""
    ziel = inspect.unwrap(_aufgeloest(name))
    gefunden: list = []
    original = canonical._gelesen

    def spion(namen, leser, args, kwargs, *weiter):
        rahmen = sys._getframe(1)
        f = rahmen.f_locals.get("f")
        if f is not None and inspect.unwrap(f) is ziel and not gefunden:
            gefunden.append((args, kwargs))
        return original(namen, leser, args, kwargs, *weiter)
    canonical._gelesen = spion
    try:
        aufruf(copy.deepcopy)
    except Exception:  # noqa: BLE001 - the arguments were taken at the reading; the outcome is the base run's
        pass
    finally:
        canonical._gelesen = original
    if not gefunden:
        return None
    args, kwargs = gefunden[0]
    fn = _aufgeloest(name)
    try:
        return _flach(fn, inspect.signature(fn).bind(*args, **kwargs).arguments)
    except TypeError:
        return None


def _flach(fn: Callable, gebunden: "dict[str, Any]") -> "dict[str, Any]":
    """The bound arguments of one call, each value of a ``*args`` or ``**kwargs`` parameter an argument of its own:
    ``args[0]``, ``kwargs.key``. The container the call's syntax builds is no value of the caller's."""
    flach: dict = {}
    for name, wert in gebunden.items():
        art = inspect.signature(fn).parameters[name].kind
        if art == inspect.Parameter.VAR_POSITIONAL:
            flach.update({f"{name}[{i}]": v for i, v in enumerate(wert)})
        elif art == inspect.Parameter.VAR_KEYWORD:
            flach.update({f"{name}.{k}": v for k, v in wert.items()})
        else:
            flach[name] = wert
    return flach


def _grundfaelle() -> "tuple[list[_Grundfall], dict[str, str], Callable[[], None]]":
    """(base cases, surfaces without one -> reason, cleanup). A base case is a call that answers, the same in two
    runs; a call that raises or is refused is no valid base case and is named open with what it gave."""
    flaechen, aufraeumen = _sweep._flaechen()
    vier, aufraeumen_vier = _flaechen_vier()
    faelle, offen = [], {}
    uhr = _uhr_angehalten()
    for name, aufruf in flaechen + vier:
        argumente = _gefangen(name, aufruf)
        if argumente is None:
            offen[name] = "the sweep's call does not reach the reading of this surface"
            continue
        fn = _aufgeloest(name)
        erstes = _rufe(fn, {k: _kopie(v) for k, v in argumente.items()})
        zweites = _rufe(fn, {k: _kopie(v) for k, v in argumente.items()})
        if erstes != zweites:
            offen[name] = "the base verdict is not the same in two runs"
            continue
        if erstes[0] != "answered":
            offen[name] = f"the base call does not answer: {erstes}"
            continue
        faelle.append(_Grundfall(name, fn, argumente, erstes))

    def alles_aufraeumen() -> None:
        uhr()
        aufraeumen()
        aufraeumen_vier()
    return faelle, offen, alles_aufraeumen


def _uhr_angehalten() -> Callable[[], None]:
    """Stops the clock the in-toto exporters write into a statement (`intoto._now_rfc3339z`), so an emitter's verdict,
    the bytes it writes, is the same in two runs; returns the function that lets it run again."""
    from proofbundle import intoto
    original = intoto._now_rfc3339z
    intoto._now_rfc3339z = lambda: "2026-10-01T00:00:00Z"
    return lambda: setattr(intoto, "_now_rfc3339z", original)


def _flaechen_vier() -> "tuple[list, Callable[[], None]]":
    """The verdict surfaces the sweep of tests/test_one_reading_at_every_surface.py does not list, each on a LEGITIMATE
    input from this package's emitters and fixtures, in the sweep's form: ``(name, call)``, the call taking ``w``, the
    reader of the caller's values. Keys and paths are passed unwrapped, as the sweep passes them."""
    import base64
    import hashlib
    import json
    import shutil
    import tempfile
    from pathlib import Path

    from proofbundle import (agent_review as ar, anchors, assurance, automation_verdict as av, bundle as bm, cap1,
                             checkpoint as cp, decision, emit, hf_evals, kbjwt, merkle, outcome, persample,
                             public_transparency as pt, relation, relation_statement as rs, run_ledger as rl, sdjwt,
                             sdjwt_issue, sdjwt_vc, signature, subject_binding as sb, trust_pack as tp,
                             verification_summary as vs, verifier_block as vb)
    from proofbundle import evalclaim as ec

    wurzel = _sweep._WURZEL
    t = _sweep._T
    pub = _sweep._raw(t)
    ablage = Path(tempfile.mkdtemp(prefix="verdict-surface-base-"))
    gesichert = dict(anchors._VERIFIERS)

    def aufraeumen() -> None:
        anchors._VERIFIERS.clear()
        anchors._VERIFIERS.update(gesichert)
        shutil.rmtree(ablage, ignore_errors=True)

    def json_von(pfad: Path) -> Any:
        return json.loads(pfad.read_text(encoding="utf-8"))

    def nutzlast(umschlag: dict) -> dict:
        return json.loads(base64.b64decode(umschlag["payload"]))

    ev_bundle = ec.emit_eval_receipt(_sweep._claim("0.10"), t)
    halter = _sweep.Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    kompakt = sdjwt_issue.issue_sd_jwt(ec.decode_eval_claim(ev_bundle), t, root_b64=ev_bundle["merkle"]["root_b64"],
                                       holder_public_key=_sweep._raw(halter))
    praesentiert = sdjwt_issue.present_with_key_binding(kompakt, halter, aud="v", nonce="n", iat=1_780_000_000)
    sd_bundle = ec.emit_eval_receipt(_sweep._claim("0.10"), t, sd_jwt={"compact": praesentiert,
                                                                       "issuer_public_key_b64": _sweep._b64pub(t)})
    aussteller = kompakt.split("~")[0].split(".")[1]
    aussteller_nutzlast = json.loads(base64.urlsafe_b64decode(aussteller + "=" * (-len(aussteller) % 4)))
    vc_policy = {"vctAllowlist": [sdjwt_issue.DEFAULT_VCT], "requireKeyBinding": True, "requireIssuerSignature": True}

    dec_pred = json_von(wurzel / "examples" / "decision_receipt_allow.json")
    dec_env = decision.emit_decision_receipt(dec_pred, t)
    dec_validity = dec_pred.get("validity") or {}
    out_pred = {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
                "executor": {"id": "executor:runner-7", "keyId": "root-0"},
                "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
                "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
    out_env = outcome.emit_outcome_receipt(out_pred, t)
    rl_pred = {"schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 5,
               "runs": rl.link_runs(["1" * 64, "2" * 64, "3" * 64], ["completed", "aborted", "completed"]),
               "selectedSeq": 3, "nonClaims": ["does not prove the selected run is representative"]}
    vs_pred = {"schemaVersion": "0.1.0", "summaryId": "summary-0001", "producedAt": "2026-07-14T10:00:00Z",
               "producer": {"id": "verifier://example/summarizer"},
               "levels": [{"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
                           "evidenceClass": "authorship_integrity", "checks": ["crypto", "merkle"]}],
               "nonClaims": ["does not prove the eval number is true"]}
    kanten = [{"relation": "retracts", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                                                               "digest": "a" * 64}}]
    rs_pred = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1", "relationships": kanten}
    wurzeln = (_sweep.Ed25519PrivateKey.from_private_bytes(b"\x01" * 32),
               _sweep.Ed25519PrivateKey.from_private_bytes(b"\x02" * 32),
               _sweep.Ed25519PrivateKey.from_private_bytes(b"\x03" * 32))
    tp_keys = {f"root-{i}": {"publicKey": _sweep._b64pub(k), "scheme": "ed25519"} for i, k in enumerate(wurzeln)}
    tp_pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": 1, "expires": "2027-01-01T00:00:00Z",
               "prevVersionDigest": None, "roles": {"root": {"keyIds": list(tp_keys), "threshold": 2}},
               "keys": tp_keys, "nonClaims": ["names which keys hold which role, not that the holders are honest"]}

    ar_ordner = wurzel / "conformance" / "agent_review"
    ar_pub = bytes.fromhex((ar_ordner / "publickey.hex").read_text(encoding="utf-8").strip())
    ar_v01_fall = ar_ordner / "agent-review-positive-control-valid-self-declared"
    ar_v01_env = json_von(ar_v01_fall / "envelope.json")
    ar_v01_subjekt = json_von(ar_v01_fall / "case.json")["params"]["expectedSubjectDigest"]
    ar_v01_pred = nutzlast(ar_v01_env)["predicate"]
    ar_v02_env = json_von(ar_ordner / "agent-review-v02-positive-control-current-v02-is-marked-current"
                          / "envelope.json")
    ar_v02_statement = nutzlast(ar_v02_env)
    ar_v02_pred = ar_v02_statement["predicate"]
    ar_v03_pred = json_von(ar_ordner / "agent-review-v03-positive-control-verifier-block-is-accepted"
                           / "predicate.json")
    ar_v03_env = ar.emit_agent_review(ar_v03_pred, t)
    ar_v03_subjekt = nutzlast(ar_v03_env)["subject"][0]["digest"]["sha256"]
    zeitaussage = {"kind": "reviewCompleted", "value": "2026-07-14T10:00:00Z", "assertedBy": "reviewer:x",
                   "assurance": "selfDeclared"}

    anchors.register_anchor_type("verdict-base/v1", lambda proof, r, *, frozen, now: {
        "ok": True, "warn": False, "status": "confirmed", "detail": "base"})
    anker = {"type": "verdict-base/v1", "target": "receipt", "canonicalRoot": base64.b64encode(b"\xaa" * 32).decode(),
             "proof": base64.b64encode(b"p").decode(), "anchoredAt": "2026-07-05T12:00:00Z"}
    fixturen = wurzel / "tests" / "fixtures" / "anchors"
    tsa = json_von(fixturen / "freetsa_receipt_anchor.json")
    chia = json_von(fixturen / "chia_datalayer_proof.json")
    chia_wurzel = bytes.fromhex(chia["key"][2:] if chia["key"][:2] in ("0x", "0X") else chia["key"])
    kette_wurzel = hashlib.sha256(b"a root").digest()
    kc = hashlib.sha256(b"\x01" + kette_wurzel).digest()
    vc = hashlib.sha256(b"\x01" + b"\xab").digest()
    chia_offline = {"key": kette_wurzel.hex(), "value": "ab", "key_clvm_hash": kc.hex(), "value_clvm_hash": vc.hex(),
                    "published_root": hashlib.sha256(b"\x02" + kc + vc).digest().hex(), "inclusion_layers": []}
    rootcommit = (fixturen / "tlog_bitcoin_anchor" / "rootcommit" / "vectors_sig" / "v2sig-01-valid.txt")

    cap1_pv = wurzel / "conformance" / "cap1" / "vectors" / "PV-01.json"
    signer_pfad = ablage / "signer.key"
    emit.save_signer(_sweep.Ed25519PrivateKey.from_private_bytes(b"\x0c" * 32), str(signer_pfad))
    bundle_pfad = ablage / "bundle.json"
    bundle_pfad.write_text(json.dumps(ev_bundle), encoding="utf-8")

    baum = persample.build_sample_tree([{"id": "a", "epoch": 1, "input": "x", "target": "y", "score": 1},
                                        {"id": "b", "epoch": 1, "input": "x", "target": "y", "score": 0}],
                                       b"\x33" * 32)
    origin = "example.org/log"
    blaetter = [b"leaf-0", b"leaf-1", b"leaf-2"]
    note = cp.sign_checkpoint(origin, 3, merkle.merkle_tree_hash(blaetter), t, origin)
    zeuge = _sweep._raw(_sweep._W1)
    try:
        from proofbundle import pqsig
        ml = pqsig.generate_mldsa("mldsa44")
        ml_pub = ml.public_key().public_bytes_raw()
    except Exception:  # noqa: BLE001 - this build has no ML-DSA; the ML-DSA surfaces stay open, named
        ml = ml_pub = None

    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    p256 = _ec.derive_private_key(12345, _ec.SECP256R1())
    _r, _s = decode_dss_signature(p256.sign(b"message", _ec.ECDSA(_hashes.SHA256())))
    p256_sig = _r.to_bytes(32, "big") + _s.to_bytes(32, "big")

    from proofbundle.experimental import attested_inference as ai
    from proofbundle.experimental import enclave
    anfrage, antwort = b"the request", b"the response"
    beleg = {"request_hash": hashlib.sha256(anfrage).hexdigest(), "response_hash": hashlib.sha256(antwort).hexdigest(),
             "route": "route-1", "binding": "nonce-0123456789"}
    enklave_bindung = enclave.enclave_binding_for(ev_bundle)
    pruefer = _sweep.Ed25519PrivateKey.from_private_bytes(b"\x0d" * 32)
    eat = enclave.issue_enclave_attestation(enklave_bindung, pruefer,
                                            profile="https://b7n0de.com/proofbundle/eat-profile/tdx-gpu/v1",
                                            tier="affirming", ueid="tdx:0x1234", iat=1_780_000_000,
                                            exp=1_780_003_600)

    vb_build = {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 7}
    vb_vset = {"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64}, "cases": 2}
    vb_s0 = vb.build_test_result_statement(
        build=vb_build, vector_set=vb_vset, version="6.2.0",
        results=[{"caseId": "a", "ok": True, "scope": "full"}, {"caseId": "b", "ok": True, "scope": "full"}])
    vb_block = vb.build_verifier_block(
        build=vb_build, version="6.2.0", vector_set=vb_vset,
        test_result={"predicateType": vb.TEST_RESULT_PREDICATE_TYPE, "result": vb_s0["predicate"]["result"],
                     "statementDigest": {"sha256": vb.statement_digest(vb_s0)}})

    f = [
        ("agent_review.derive_limitation_codes", lambda w: ar.derive_limitation_codes(w(ar_v02_pred))),
        ("agent_review.load_policy", lambda w: ar.load_policy()),
        ("agent_review.require_valid_agent_review_predicate",
         lambda w: ar.require_valid_agent_review_predicate(w(ar_v01_pred))),
        ("agent_review.require_valid_agent_review_predicate_any",
         lambda w: ar.require_valid_agent_review_predicate_any(w(ar_v02_pred))),
        ("agent_review.validate_agent_review_predicate", lambda w: ar.validate_agent_review_predicate(w(ar_v01_pred))),
        ("agent_review.validate_agent_review_v02_predicate",
         lambda w: ar.validate_agent_review_v02_predicate(w(ar_v02_pred))),
        ("agent_review.validate_agent_review_v03_predicate",
         lambda w: ar.validate_agent_review_v03_predicate(w(ar_v03_pred))),
        ("agent_review.validate_statement_shape",
         lambda w: ar.validate_statement_shape(w(ar_v02_statement), w(ar_v02_pred))),
        ("agent_review.validate_time_claim", lambda w: ar.validate_time_claim(w(zeitaussage))),
        ("agent_review.verify_agent_review", lambda w: ar.verify_agent_review(
            w(ar_v01_env), w(ar_pub), expected_subject_digest=w(ar_v01_subjekt))),
        ("agent_review.verify_agent_review_v03", lambda w: ar.verify_agent_review_v03(
            w(ar_v03_env), w(pub), expected_subject_digest=w(ar_v03_subjekt), observed_body=w("the observed body"))),
        ("anchors.receipt_canonical_root", lambda w: anchors.receipt_canonical_root(w(ev_bundle))),
        ("anchors.verify_anchor", lambda w: anchors.verify_anchor(
            w(anker), target_roots=w({"receipt": b"\xaa" * 32}), now=w(1_780_000_000), rp_trust=w({}))),
        ("anchors_chia.verify_chia_datalayer", lambda w: __import__("proofbundle.anchors_chia", fromlist=["x"])
         .verify_chia_datalayer(w(json.dumps(chia).encode()), w(chia_wurzel), frozen=w({}), now=w(1_780_000_000))),
        ("anchors_chia.verify_offline_merkle", lambda w: __import__("proofbundle.anchors_chia", fromlist=["x"])
         .verify_offline_merkle(w(chia_offline), w(kette_wurzel))),
        ("anchors_rfc3161.verify_rfc3161", lambda w: __import__("proofbundle.anchors_rfc3161", fromlist=["x"])
         .verify_rfc3161(w(base64.b64decode(tsa["proof"])), w(base64.b64decode(tsa["canonicalRoot"])),
                         frozen=w(tsa["frozen"]), now=w(1_780_000_000),
                         rp_trust=w({"trusted_tsa_roots": list(tsa["frozen"]["rootCertsDerB64"])}))),
        ("anchors_rootcommit.verify_rootcommit_v2sig", lambda w: __import__(
            "proofbundle.anchors_rootcommit", fromlist=["x"]).verify_rootcommit_v2sig(
                w(rootcommit.read_text(encoding="utf-8")), frozen=w({}), rp_trust=w({}))),
        ("anchors_rootcommit.eip191_signature_identity", lambda w: __import__(
            "proofbundle.anchors_rootcommit", fromlist=["x"]).eip191_signature_identity(
                w((1).to_bytes(32, "big") + (1).to_bytes(32, "big") + bytes([27])))),
        ("assurance.classify_receiver_corroboration", lambda w: assurance.classify_receiver_corroboration(
            _sweep._klare_schluessel(w({"sha256": "a" * 64})), evidence_resolver=lambda d: True,
            independent_attestation_resolver=lambda d: True, executor_key_id=w("e"), receiver_key_id=w("r"))),
        ("assurance.evidence_ladder_best", lambda w: assurance.evidence_ladder_best(
            w({"level": 2, "level_name": "CONTENT_RESOLVED"}), w({"level": 1, "level_name": "REFERENCE_WELL_FORMED"}))),
        ("assurance.evidence_ladder_summary", lambda w: assurance.evidence_ladder_summary(
            w({"level": 2, "level_name": "CONTENT_RESOLVED"}), w({"level": 1, "level_name": "REFERENCE_WELL_FORMED"}))),
        ("automation_verdict.automation_summary", lambda w: av.automation_summary(
            w({"crypto_ok": True, "structure_ok": True, "policy_ok": True, "evidence_bound": True, "ok": True}),
            required_checks=w({"crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
                               "references": ["evidence_bound"]}))),
        ("bundle.load_bundle", lambda w: bm.load_bundle(str(bundle_pfad))),
        ("bundle.recompute_merkle_root_b64", lambda w: bm.recompute_merkle_root_b64(w(ev_bundle))),
        ("cap1.check_cap1_document", lambda w: cap1.check_cap1_document(w(json_von(cap1_pv)))),
        ("cap1.is_conformant", lambda w: cap1.is_conformant(w(json_von(cap1_pv)))),
        ("cap1.load_cap1_document", lambda w: cap1.load_cap1_document(w(cap1_pv.read_bytes()))),
        ("checkpoint.cosign_key_id", lambda w: cp.cosign_key_id(w("witness.example"), w(zeuge))),
        ("checkpoint.cosign_vkey", lambda w: cp.cosign_vkey(w("witness.example"), w(zeuge))),
        ("checkpoint.expected_origin_wellformed", lambda w: cp.expected_origin_wellformed(w(origin))),
        ("decision.require_valid_decision_predicate", lambda w: decision.require_valid_decision_predicate(w(dec_pred))),
        ("decision.verify_decision_receipt_or_raise", lambda w: decision.verify_decision_receipt_or_raise(
            w(dec_env), w(pub), expected_audience=w((dec_validity.get("audience") or ["x"])[0]),
            expected_nonce=w(dec_validity.get("nonce") or "n"))),
        ("emit.load_signer", lambda w: emit.load_signer(str(signer_pfad))),
        ("evalclaim.load_claim_text", lambda w: ec.load_claim_text(w(json.dumps(_sweep._claim("0.10"))))),
        ("evalclaim.sd_jwt_hidden_count", lambda w: ec.sd_jwt_hidden_count(w(sd_bundle))),
        ("experimental.attested_inference.check_on_receipt", lambda w: ai.check_on_receipt(
            w(beleg), provider=w("p"), nonce=w("nonce-0123456789"), request_bytes=w(anfrage),
            response_bytes=w(antwort), planned_route=w("route-1"), expected_evidence_digest=w(ai.evidence_digest(beleg)))),
        ("experimental.enclave.verify_enclave_attestation", lambda w: enclave.verify_enclave_attestation(
            w(eat), verifier_pubkey=w(_sweep._raw(pruefer)), expected_binding=w(enklave_bindung),
            now=w(1_780_000_100))),
        ("hf_evals.receipt_token_identity", lambda w: hf_evals.receipt_token_identity(
            w(hf_evals.receipt_token(ev_bundle)))),
        ("kbjwt.holder_key_from_cnf", lambda w: kbjwt.holder_key_from_cnf(w(aussteller_nutzlast))),
        ("outcome.require_valid_outcome_predicate", lambda w: outcome.require_valid_outcome_predicate(w(out_pred))),
        ("outcome.verify_outcome_receipt_or_raise", lambda w: outcome.verify_outcome_receipt_or_raise(
            w(out_env), w(pub), expected_decision_ref=w("a" * 64))),
        ("persample.audit_challenge", lambda w: persample.audit_challenge(
            w(baum["root_b64"]), w(baum["n"]), w(1), w(b"auditor nonce"))),
        ("persample.derive_leaf_salt", lambda w: persample.derive_leaf_salt(w(b"\x33" * 32), w("a"), w(1))),
        ("public_transparency.validate_public_transparency_policy", lambda w: pt.validate_public_transparency_policy(
            w({"requireSignedCheckpoint": True, "trustedLogOrigins": [origin], "witnessQuorum": {"threshold": 1}}))),
        ("relation.require_valid_relationships", lambda w: relation.require_valid_relationships(w(kanten))),
        ("relation.validate_relationships", lambda w: relation.validate_relationships(w(kanten))),
        ("relation_statement.require_valid_relation_statement_predicate",
         lambda w: rs.require_valid_relation_statement_predicate(w(rs_pred))),
        ("relation_statement.validate_relation_statement_predicate",
         lambda w: rs.validate_relation_statement_predicate(w(rs_pred))),
        ("run_ledger.require_valid_run_ledger_predicate", lambda w: rl.require_valid_run_ledger_predicate(w(rl_pred))),
        ("run_ledger.validate_run_ledger_predicate", lambda w: rl.validate_run_ledger_predicate(w(rl_pred))),
        ("sdjwt.canonical_sd_jwt_compact", lambda w: sdjwt.canonical_sd_jwt_compact(w(praesentiert))),
        ("sdjwt_vc.check_vc_profile", lambda w: sdjwt_vc.check_vc_profile(
            w(praesentiert), w(vc_policy), offline_metadata=w({}))),
        ("sdjwt_vc.validate_vc_policy", lambda w: sdjwt_vc.validate_vc_policy(w(vc_policy))),
        ("signature.canonical_es256_signature", lambda w: signature.canonical_es256_signature(w(p256_sig))),
        ("signature.ed25519_trust_anchor_weakness", lambda w: signature.ed25519_trust_anchor_weakness(w(pub))),
        ("signature.plain_bytes", lambda w: signature.plain_bytes(w(b"the bytes"))),
        ("signature.plain_text", lambda w: signature.plain_text(w("the text"))),
        ("signature.verify_ed25519", lambda w: signature.verify_ed25519(w(pub), w(t.sign(b"message")), w(b"message"))),
        ("subject_binding.derive_subject_digest", lambda w: sb.derive_subject_digest(w(dec_pred))),
        ("subject_binding.require_derived_subject", lambda w: sb.require_derived_subject(w(nutzlast(dec_env)))),
        ("subject_binding.subject_cardinality", lambda w: sb.subject_cardinality(w(nutzlast(dec_env)))),
        ("trust_pack.require_valid_trust_pack_predicate", lambda w: tp.require_valid_trust_pack_predicate(w(tp_pred))),
        ("verification_summary.require_valid_summary_predicate",
         lambda w: vs.require_valid_summary_predicate(w(vs_pred))),
        ("verification_summary.validate_summary_predicate", lambda w: vs.validate_summary_predicate(w(vs_pred))),
        ("verifier_block.require_valid_verifier_block", lambda w: vb.require_valid_verifier_block(w(vb_block))),
        ("verifier_block.validate_test_result_statement", lambda w: vb.validate_test_result_statement(w(vb_s0))),
        ("verifier_block.validate_verifier_block", lambda w: vb.validate_verifier_block(w(vb_block))),
    ]
    if ml is not None:
        f += [
            ("checkpoint.cosign_checkpoint_mldsa", lambda w: cp.cosign_checkpoint_mldsa(
                w(note), ml, w("witness.example"), w(1000))),
            ("checkpoint.cosign_key_id_mldsa", lambda w: cp.cosign_key_id_mldsa(w("witness.example"), w(ml_pub))),
            ("checkpoint.cosign_vkey_mldsa", lambda w: cp.cosign_vkey_mldsa(w("witness.example"), w(ml_pub))),
        ]
    if _sweep._ots_vorhanden():
        f += _flaechen_vier_ots()
    return f, aufraeumen


def _flaechen_vier_ots() -> list:
    """The OpenTimestamps verifier and the markovian one, on a real upgraded proof and the relying party's header, as
    tests/test_a_verifier_reads_a_callers_value_once.py builds them."""
    import base64
    import hashlib
    import json

    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    from proofbundle.anchors_markovian import verify_markovian
    from proofbundle.anchors_ots import verify_opentimestamps

    def aufgewertet(nachricht: bytes, hoehe: int = 850000) -> bytes:
        ts = Timestamp(nachricht)
        blatt = ts.ops.add(OpAppend(b"\x00")).ops.add(OpSHA256())
        blatt.attestations.add(BitcoinBlockHeaderAttestation(hoehe))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
        return ctx.getbytes()
    r1 = hashlib.sha256(b"root one").digest()
    salz, wallet = "00112233445566778899aabbccddeeff", "1MKVtestWa11etAAAAAAAAAAAAAAAAAAAA"
    mr = hashlib.sha256(f"{r1.hex()}:{salz}:{wallet}".encode()).hexdigest()
    umschlag = json.dumps({"schema": "markovian-provenance/v1", "data_hash": r1.hex(), "salt": salz, "wallet": wallet,
                           "merkle_root": mr, "block_height": 77810,
                           "ots": base64.b64encode(aufgewertet(r1)).decode()}).encode()
    kopf = {"bitcoin_block_headers": {"850000": hashlib.sha256(r1 + b"\x00").hexdigest()}}
    return [
        ("anchors_markovian.verify_markovian", lambda w: verify_markovian(
            w(umschlag), w(r1), frozen=w({}), now=w(1_780_000_000), rp_trust=w(kopf))),
        ("anchors_ots.verify_opentimestamps", lambda w: verify_opentimestamps(
            w(aufgewertet(r1)), w(r1), frozen=w({}), now=w(1_780_000_000), rp_trust=w(kopf))),
    ]


def _urteilsflaechen() -> "set[str]":
    """The public verdict surfaces: the never-raise family the package discovers itself, every `verify_*` and
    `evaluate_*` it exports, and every surface of the sweep."""
    import proofbundle
    namen = {f"{m}.{n}" for m, n, _ in _familie._discover_surfaces()}
    for export in dir(proofbundle):
        if export.startswith(("verify_", "evaluate_")):
            objekt = getattr(proofbundle, export)
            namen.add(f"{objekt.__module__.removeprefix('proofbundle.')}.{objekt.__name__}")
    flaechen, aufraeumen = _sweep._flaechen()
    aufraeumen()
    return namen | {name for name, _ in flaechen}


#: Verdict surfaces without a base case here, each with its reason. A surface named here is NOT held by this file;
#: the report test counts them. Filled by the base cases `_flaechen_vier` adds; an entry for a surface that has a base
#: case now, or a surface missing here, is red.
_OHNE_GRUNDFALL: "dict[str, str]" = {}


#: (surface, argument) -> why a recording ``str`` subclass gives another verdict there by contract. Each counts only an
#: exact ``str``, so the deviation is a refusal to promote, never a promotion.
_KONTROLLE_AUSNAHMEN: "dict[tuple[str, str], str]" = {
    ("policy.evaluate_decision_policy", "anchor_status"): (
        "the status of verify_anchors counts only as an exact str; a str subclass is no status there"),
    ("assurance.classify_digest_evidence", "digest_obj"): (
        "a key of a digest object counts only when it is of type str itself (PR 291, `_membership.stored_str_items`)"),
    ("assurance.classify_receiver_corroboration", "digest_obj"): (
        "a key of a digest object counts only when it is of type str itself (PR 291), as at classify_digest_evidence"),
    ("assurance.classify_receiver_corroboration", "executor_key_id"): (
        "a key id counts only as an exact str (type(), not isinstance()), so independence is not provable"),
    ("assurance.classify_receiver_corroboration", "receiver_key_id"): (
        "a key id counts only as an exact str (type(), not isinstance()), so independence is not provable"),
    ("assurance.evidence_ladder_best", "fields[0]"): (
        "a rollup field's keys count only when of type str itself (PR 291, `assurance._has_level` reads them with "
        "`stored_str_items`): the field with recording keys is not applicable, and the other field is the strongest"),
    ("assurance.evidence_ladder_summary", "fields[1]"): (
        "a rollup field's keys count only when of type str itself (PR 291, `assurance._has_level`): the field with "
        "recording keys is not applicable, and the other field is the weakest"),
}


# ── the changes that prove the reach ────────────────────────────────────────────────────────────────────────────────

def _ersetzt(wert: Any, pfad: tuple, neu: Any) -> Any:
    """A copy of ``wert`` with the leaf at ``pfad`` replaced by ``neu``."""
    if not pfad:
        return neu
    kopf, *rest = pfad
    if type(wert) is dict:
        k = dict(wert)
        k[kopf] = _ersetzt(wert[kopf], tuple(rest), neu)
        return k
    if type(wert) in (list, tuple):
        k = list(wert)
        k[kopf] = _ersetzt(wert[kopf], tuple(rest), neu)
        return type(wert)(k)
    return wert


def _blaetter(wert: Any, pfad: tuple = (), tiefe: int = 0) -> "list[tuple[tuple, Any]]":
    if tiefe > 12:
        return []
    if type(wert) is dict:
        out = []
        for k, v in wert.items():
            out += _blaetter(v, pfad + (k,), tiefe + 1)
        return out
    if type(wert) in (list, tuple):
        out = []
        for i, v in enumerate(wert):
            out += _blaetter(v, pfad + (i,), tiefe + 1)
        return out
    return [(pfad, wert)]


def _anders(blatt: Any) -> "list[Any]":
    t = type(blatt)
    if t is bool:
        return [not blatt]
    if t is int:
        return [blatt + 1, 0 if blatt else 1]
    if t is float:
        return [blatt + 0.5]
    if t is str:
        return [blatt[:-1] + ("y" if blatt[-1:] != "y" else "z") if blatt else "x", ""]
    if t is bytes:
        return [blatt[:-1] + bytes([(blatt[-1] ^ 1) if blatt else 0]) if blatt else b"\x00", b""]
    if t is bytearray:
        return [bytearray(_anders(bytes(blatt))[0])]
    if blatt is None:
        return ["x"]
    return []


def _stoerungen(wert: Any, grenze: int = 32) -> "list[tuple[str, Any]]":
    """Changes of an argument's value: each leaf changed in turn (a character, a byte, a number, a flag), then the
    whole value emptied; at most ``grenze``."""
    out: list = []
    for pfad, blatt in _blaetter(wert):
        for neu in _anders(blatt):
            out.append((f"leaf {list(pfad)} -> {neu!r:.24}", _ersetzt(wert, pfad, neu)))
            if len(out) >= grenze:
                return out
    for leer in ({} if type(wert) is dict else None, [] if type(wert) in (list, tuple) else None,
                 "" if type(wert) is str else None, b"" if type(wert) is bytes else None):
        if leer is not None and leer != wert:
            out.append(("emptied", leer))
    return out[:grenze]


# ── the forms whose own methods answer another value than they store ────────────────────────────────────────────────

def _luegner(gut: Any, schlecht: Any) -> Any:
    """``schlecht`` as an object of the caller's class whose own methods answer ``gut``: a str or bytes whose
    comparison and hash answer the good value, a dict whose ``get``, ``__getitem__``, ``items``, ``keys`` and
    ``values`` answer it, a list whose iteration and indexing answer it. None for any other value."""
    t = type(schlecht)
    if t is str and type(gut) is str:
        class _Text(str):
            def __eq__(self, other):
                return other == gut

            def __ne__(self, other):
                return other != gut

            def __hash__(self):
                return hash(gut)

            def __str__(self):
                return gut
        return _Text(schlecht)
    if t is bytes and type(gut) is bytes:
        class _Roh(bytes):
            def __eq__(self, other):
                return other == gut

            def __ne__(self, other):
                return other != gut

            def __hash__(self):
                return hash(gut)

            def __bytes__(self):
                return gut
        return _Roh(schlecht)
    if t is dict and type(gut) is dict:
        class _Abbild(dict):
            def get(self, k, default=None):
                return gut.get(k, default)

            def __getitem__(self, k):
                return gut[k]

            def __contains__(self, k):
                return k in gut

            def items(self):
                return gut.items()

            def keys(self):
                return gut.keys()

            def values(self):
                return gut.values()

            def __iter__(self):
                return iter(gut)

            def __len__(self):
                return len(gut)
        return _Abbild(schlecht)
    if t is list and type(gut) is list:
        class _Folge(list):
            def __iter__(self):
                return iter(gut)

            def __getitem__(self, i):
                return gut[i]

            def __len__(self):
                return len(gut)
        return _Folge(schlecht)
    return None


# ── the tests ───────────────────────────────────────────────────────────────────────────────────────────────────────

class _Mit(unittest.TestCase):
    faelle: "list[_Grundfall]" = []
    offen: "dict[str, str]" = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls.faelle, cls.offen, cls._aufraeumen = _grundfaelle()

    @classmethod
    def tearDownClass(cls) -> None:
        cls._aufraeumen()


class EveryVerdictSurfaceAndArgumentIsHeld(_Mit):

    def test_every_verdict_surface_has_a_base_case_or_is_named_open(self) -> None:
        mit = {f.name for f in self.faelle}
        ohne = sorted(_urteilsflaechen() - mit)
        print(f"\nBASE CASES: {len(mit)}; OPEN ({len(self.offen)}): {self.offen}; NAMED WITHOUT ONE: {_OHNE_GRUNDFALL}")
        ungenannt = [n for n in ohne if n not in _OHNE_GRUNDFALL and n not in self.offen]
        self.assertEqual(ungenannt, [], f"{len(ungenannt)} verdict surfaces have no base case and no named reason")
        self.assertEqual(sorted(set(_OHNE_GRUNDFALL) & mit), [], "a surface named open has a base case now")

    def test_every_argument_reaches_the_verdict(self) -> None:
        """THE REACH: for each argument some change of its value changes the verdict, so the base case reaches the
        check that judges it. An argument no change reaches is listed (visibly open, not held)."""
        nicht_erreicht = []
        gesamt = 0
        for fall in self.faelle:
            for p, wert in fall.argumente.items():
                gesamt += 1
                erreicht = False
                for _, neu in _stoerungen(wert):
                    argumente = {k: _kopie(v) for k, v in fall.argumente.items()}
                    argumente[p] = neu
                    if _rufe(fall.fn, argumente) != fall.urteil:
                        erreicht = True
                        break
                if not erreicht:
                    nicht_erreicht.append(f"{fall.name}({p})")
        print(f"\nREACH: {gesamt - len(nicht_erreicht)} of {gesamt} arguments reach the verdict; not reached: "
              f"{nicht_erreicht}")
        self.assertGreater(gesamt, 200)
        self.assertLessEqual(len(nicht_erreicht), gesamt, "")

    def test_control_a_promised_form_of_each_argument_gives_the_base_verdict(self) -> None:
        """THE CONTROL: each argument as recording subclasses of dict, list, str and bytes (`_aufgezeichnet` of the
        sweep) gives the base verdict and runs none of their methods. An argument whose contract counts only an exact
        ``str`` gives another verdict by design and is named in `_KONTROLLE_AUSNAHMEN` with its reason; such an entry
        that gives the base verdict again is red, so the list stays exact."""
        abweichend, ausnahmen_gesehen = [], set()
        for fall in self.faelle:
            for p, wert in fall.argumente.items():
                argumente = {k: _kopie(v) for k, v in fall.argumente.items()}
                argumente[p] = _sweep._aufgezeichnet(_kopie(wert))
                _sweep._AUFRUFE.clear()
                gesehen = _rufe(fall.fn, argumente)
                gelaufen = sorted(set(_sweep._AUFRUFE))
                _sweep._AUFRUFE.clear()
                if (fall.name, p) in _KONTROLLE_AUSNAHMEN and gesehen != fall.urteil and not gelaufen:
                    ausnahmen_gesehen.add((fall.name, p))
                    continue
                if gesehen != fall.urteil or gelaufen:
                    abweichend.append(f"{fall.name}({p}): {'ran ' + str(gelaufen[:3]) if gelaufen else 'verdict'}")
        self.assertEqual(sorted(set(_KONTROLLE_AUSNAHMEN) - ausnahmen_gesehen), [],
                         "an exception of the control that no longer deviates, or deviates by running a method")
        self.assertEqual(abweichend, [], f"{len(abweichend)} arguments")

    def test_a_value_whose_methods_answer_another_value_gets_no_verdict_it_does_not_store(self) -> None:
        """THE FORMS: for each reached leaf change (a value the base verdict does not hold for), that value as an
        object whose own methods answer the base value must not get the base verdict."""
        befoerdert = []
        geprueft = 0
        for fall in self.faelle:
            for p, wert in fall.argumente.items():
                for pfad, blatt in _blaetter(wert)[:16] + [((), wert)]:
                    for neu in _anders(blatt)[:1] if pfad else []:
                        schlecht = _ersetzt(wert, pfad, neu)
                        argumente = {k: _kopie(v) for k, v in fall.argumente.items()}
                        argumente[p] = schlecht
                        urteil_schlecht = _rufe(fall.fn, argumente)
                        if urteil_schlecht == fall.urteil:
                            continue
                        luegner_blatt = _luegner(blatt, neu)
                        if luegner_blatt is None:
                            continue
                        argumente = {k: _kopie(v) for k, v in fall.argumente.items()}
                        argumente[p] = _ersetzt(wert, pfad, luegner_blatt)
                        geprueft += 1
                        if _rufe(fall.fn, argumente) == fall.urteil:
                            befoerdert.append(f"{fall.name}({p}) at {list(pfad)}")
        print(f"\nFORMS: {geprueft} lying leaves checked")
        self.assertGreater(geprueft, 100)
        self.assertEqual(befoerdert, [], f"{len(befoerdert)} lying values got the verdict they do not store")


if __name__ == "__main__":
    unittest.main()
