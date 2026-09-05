"""Jedes Erwartungs-Argument einer never-raise-Fläche ist am Eingang gefloort, nicht erst in der Rechnung.

DIE KLASSE (Deep-Gate 6.0.0, Lauf 3, Fund L3-600-04 P2; Ledger RT-05 ``keyword_rp_expectation_arg_int_str_cap_dos``,
bis dahin „noch nicht eingepflanzt"). ``verify_status_snapshot(now=…)`` ist der Relying-Party-Takt: der Wert kam vom
Aufrufer, wurde nirgends getypt und lief roh in ``iat <= now`` — ein String, eine Liste, Bytes oder ein Float hoben
einen rohen TypeError aus einer Fläche, deren Docstring „never crashes" verspricht. Die Fläche hatte ihr
PRIMÄRargument längst gefloort (ein Nicht-String-Token liefert ein Verdikt); die Klasse sind die
Keyword-Argumente, die der auto-enumerierte Riegel (``test_never_raise_surface_family_property``) per Konstruktion
nie setzt — er füttert Position 0, Parameter mit Default werden gar nicht erst gesetzt.

WAS DIESER TEST DAHER TUT: für jede Fläche, die ein RP-Kwarg trägt, wird ein GÜLTIGES Primärargument gebaut
(sonst wäre die Probe leer: ein leerer Stub kehrt um, bevor das Kwarg je gelesen wird) und JEDES Kwarg mit
feindlichen Werten gefüttert. Erlaubt ist ein Verdikt oder eine typisierte ``ProofBundleError``; verboten ist
jede rohe Ausnahme.

EHRLICHE GRENZE: die Population ist eine Fixture-Tabelle, keine Ableitung — ein gültiges Primärargument je
Fläche lässt sich nicht aus der Signatur erraten. Der Bodentest darunter hält die Tabelle gegen Kollaps, und der
Riegel darüber (``test_jede_rp_kwarg_flaeche_ist_in_der_tabelle``) leitet die Menge der Flächen mit
Erwartungs-Kwargs aus dem Paket ab und verlangt für jede eine Entscheidung: Fixture oder begründeter Ausschluss.
"""
from __future__ import annotations

import base64
import importlib
import inspect
import re
import unittest

import proofbundle as pb
from proofbundle import (anchors, checkpoint, decision, evalclaim, policy, renewal, statuslist,
                         tlogproof)
from proofbundle.renewal import ArchiveTimeStamp
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import ProofBundleError

RIESE = 10 ** 5000
FEINDLICH = ["x", b"1", [1], {"a": 1}, 1.5, float("nan"), RIESE, True, object(), ("t",), -1]
_ERLAUBT = (ProofBundleError, ValueError)
_ROH = (AttributeError, TypeError, RecursionError, KeyError, IndexError, OverflowError, UnicodeError)

# Erwartungs-Kwargs: Takt, Erwartungswert, Index, Schwelle, Anforderung — die Namen, unter denen ein Relying
# Party eine Vorgabe in die Prüfung reicht.
_KWARG_MUSTER = re.compile(r"^(now|expected_[a-z_]+|index|threshold|require[a-z_]*|allow_[a-z_]+|max_[a-z_]+"
                           r"|rp_trust|strict|policy|anchors|related|witness_vkeys|target_roots|evidence_resolver"
                           r"|verification_time|receipt_issuer_pubkey|issuer_pubkey)$")


def _fixtures():
    """(Flächen-Name, Aufruf(kwargs) mit gültigem Primärargument, Kwarg-Namen)."""
    signer = generate_signer()
    pub = signer.public_key().public_bytes_raw()
    bundle = emit_bundle(b'{"hello":"world"}', signer)
    token = statuslist.issue_status_list_token([0, 1], uri="https://s/l", signer=signer, iat=1, exp=10 ** 9, ttl=5)
    root = base64.b64decode(bundle["merkle"]["root_b64"])
    note = checkpoint.sign_checkpoint("log.example/x", bundle["merkle"]["tree_size"], root, signer, "log.example/x")
    log_vkey = checkpoint.vkey("log.example/x", pub)
    proof = tlogproof.tlog_proof_for_bundle(bundle, note)
    payload = base64.b64decode(bundle["payload_b64"])
    dec_env = decision.emit_decision_receipt(_PREDICATE, signer, strict=True)
    return [
        ("statuslist.verify_status_snapshot",
         lambda **kw: statuslist.verify_status_snapshot(token, **{"expected_uri": "https://s/l", "index": 0,
                                                                  "issuer_pubkey": pub, **kw}),
         ("now", "index", "expected_uri", "issuer_pubkey", "receipt_issuer_pubkey")),
        ("bundle.verify_bundle",
         lambda **kw: pb.verify_bundle(bundle, **kw),
         ("expected_aud", "expected_nonce", "expected_root_b64", "expected_tree_size")),
        ("anchors.verify_anchors",
         lambda **kw: anchors.verify_anchors([], **{"target_roots": {"receipt": b"\0" * 32}, **kw}),
         ("target_roots", "require", "require_target", "allow_pending", "now", "rp_trust")),
        ("anchors.verify_anchor",
         lambda **kw: anchors.verify_anchor({"type": "nope", "target": "receipt"},
                                            **{"target_roots": {"receipt": b"\0" * 32}, **kw}),
         ("target_roots", "now", "rp_trust")),
        ("decision.verify_decision_receipt",
         lambda **kw: decision.verify_decision_receipt(dec_env, pub, **kw),
         ("strict", "expected_audience", "expected_nonce", "policy", "anchors", "rp_trust",
          "require_derived_subject", "evidence_resolver", "related")),
        ("checkpoint.verify_witnessed_checkpoint",
         lambda **kw: checkpoint.verify_witnessed_checkpoint(note, log_vkey, [], **kw),
         ("threshold", "expected_origin")),
        ("tlogproof.verify_tlog_proof",
         lambda **kw: tlogproof.verify_tlog_proof(proof, payload, log_vkey, **kw),
         ("witness_vkeys", "threshold", "expected_origin")),
        ("evalclaim.check_freshness",
         lambda **kw: evalclaim.check_freshness({"timestamp": "2026-01-01T00:00:00Z"}, **kw),
         ("max_age_seconds", "now")),
        ("policy.evaluate_policy",
         lambda **kw: policy.evaluate_policy(bundle, pb.verify_bundle(bundle),
                                             {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p"}, **kw),
         ("now",)),
        ("renewal.verify_sequence",
         lambda **kw: renewal.verify_sequence([[ArchiveTimeStamp(hash_alg="sha256", covered_digest="ab" * 32,
                                                                 time=1)]], ["ab" * 32], **kw),
         ("authority_keys", "anchor_verifier", "allow_unauthenticated_anchor", "require_pq",
          "require_current_hash", "rp_trust", "require_external_token", "known_newest_token_digest")),
    ]


class TypbodenAmEingang(unittest.TestCase):

    def test_kein_rp_kwarg_hebt_eine_rohe_ausnahme(self):
        entkommen = []
        for name, ruf, kwargs in _fixtures():
            for kw in kwargs:
                for wert in FEINDLICH:
                    try:
                        ruf(**{kw: wert})
                    except _ERLAUBT:
                        pass
                    except _ROH as exc:
                        entkommen.append(f"{name}({kw}={type(wert).__name__}): roh {type(exc).__name__}: {exc}"[:200])
                    except Exception as exc:  # noqa: BLE001 — unklassifiziert wird GEMELDET, nicht geschluckt
                        entkommen.append(f"{name}({kw}={type(wert).__name__}): UNKLASSIFIZIERT "
                                         f"{type(exc).__name__}: {exc}"[:200])
        self.assertEqual(entkommen, [], "rohe Ausnahmen an RP-Kwargs:\n  " + "\n  ".join(entkommen))

    def test_der_alte_fund_ist_ein_benanntes_verdikt(self):
        """L3-600-04 wörtlich: now='x' liefert ein fail-closed Verdikt, das den Grund nennt — kein
        stilles fresh=None, das sich wie ‚keine Schranke vorhanden' liest."""
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        token = statuslist.issue_status_list_token([0], uri="https://s/l", signer=signer, iat=1, exp=10 ** 9, ttl=5)
        for now in ("x", [1], b"1", 1.5, RIESE, True):
            with self.subTest(now=type(now).__name__):
                r = statuslist.verify_status_snapshot(token, expected_uri="https://s/l", index=0, issuer_pubkey=pub,
                                                      now=now)
                self.assertIs(r["ok"], False)
                self.assertIn("now", r["detail"])
        heil = statuslist.verify_status_snapshot(token, expected_uri="https://s/l", index=0, issuer_pubkey=pub, now=2)
        self.assertIs(heil["ok"], True)
        self.assertIs(heil["fresh"], True)

    def test_die_tabelle_ist_nicht_leer(self):
        self.assertGreaterEqual(sum(len(k) for _, _, k in _fixtures()), 25)

    def test_jede_rp_kwarg_flaeche_ist_in_der_tabelle(self):
        """DER RIEGEL GEGEN STILLES ALTERN: die Flächen mit Erwartungs-Kwargs werden aus dem Paket ABGELEITET.
        Jede muss entweder eine Fixture haben oder hier mit Grund ausgeschlossen sein."""
        gedeckt = {name for name, _, _ in _fixtures()}
        offen = []
        for modul in ("bundle", "anchors", "decision", "outcome", "statuslist", "checkpoint", "tlogproof",
                      "evalclaim", "policy", "trust_pack", "evidence_pack", "kbjwt", "renewal",
                      "verification_summary", "relation_statement", "run_ledger"):
            mod = importlib.import_module(f"proofbundle.{modul}")
            for fname, fn in inspect.getmembers(mod, inspect.isfunction):
                if fn.__module__ != mod.__name__ or not fname.startswith(("verify_", "evaluate_", "check_")):
                    continue
                params = inspect.signature(fn).parameters
                if not any(_KWARG_MUSTER.match(p) and v.default is not inspect.Parameter.empty
                           for p, v in params.items()):
                    continue
                key = f"{modul}.{fname}"
                if key in gedeckt or key in _AUSGESCHLOSSEN:
                    continue
                offen.append(key)
        self.assertEqual(offen, [], "Flächen mit Erwartungs-Kwargs ohne Fixture und ohne begründeten Ausschluss: "
                         f"{offen}")


# Ausschlüsse mit Grund — jeder Eintrag ist eine Entscheidung, keine Bequemlichkeit.
_AUSGESCHLOSSEN = {
    # explizite Ausnahme-Variante derselben Fläche; identische Kwargs, dokumentiert als raise-Pfad
    "decision.verify_decision_receipt_or_raise": "Raise-Variante von verify_decision_receipt, gleiche Kwargs",
    # braucht ein Outcome-Fixture mit Trust-Pack (Lane KRYPTO, L1-600-02) — wird dort mit der keyId-Bindung geprüft
    "outcome.verify_outcome_receipt": "Fixture liegt in der keyId-Bindungs-Lane (L1-600-02)",
    "outcome.verify_outcome_receipt_or_raise": "Raise-Variante, siehe oben",
    # trust_pack.verify_trust_pack(now=datetime): Kwarg ist ein datetime, kein RP-Skalar; Typboden vorhanden
    # (tests/test_trust_pack*.py), Fixture-Bau braucht einen signierten Pack — bewusst nicht doppelt gebaut
    "trust_pack.verify_trust_pack": "now ist datetime-typisiert und dort gefloort (eigene Tests)",
    "evidence_pack.verify_evidence_pack": "rp_trust/now: dict-Kwargs mit _as_dict-Boden (r5-Klassenfix)",
    "kbjwt.verify_key_binding": "expected_aud/expected_nonce werden nur verglichen, nie gerechnet (== auf Fremdwert)",
    "renewal.evaluate_renewal_policy": "now/policy: Magnituden- und Typboden in test_render_safe_untrusted_int",
    "evalclaim.verify_prereg": "nimmt PFAD + Claim, kein Erwartungs-Kwarg im RP-Sinn",
    "evalcard.verify_evaluation_card": "wie verify_prereg",
    "policy.evaluate_decision_policy": "Kwargs sind Konfiguration (signer_public_key_b64, anchor_status), r5-Klassenfix",
    "relation_statement.verify_relation_statement": "Kwargs sind Umschlag-Konfiguration, r7-Residuen abgedeckt",
    "run_ledger.verify_run_ledger": "strict/now: Konfigurations-Kwargs, eigene Tests",
    "verification_summary.verify_verification_summary": "strict: bool-Konfiguration",
    "checkpoint.verify_cosignature": "keine Erwartungs-Kwargs (nur zwei Pflichtargumente)",
    "checkpoint.verify_checkpoint": "keine Erwartungs-Kwargs",
    "evalclaim.check_freshness_policy": "Politik-Objekt, kein RP-Skalar",
}


_PREDICATE = {
    "schemaVersion": "0.1.0", "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000000",
    "decisionType": "preActionAuthorization", "decidedAt": "2026-01-01T00:00:00Z",
    "decisionMaker": {"id": "https://example.org/gate/v1", "version": {"proofbundle": "x"}},
    "agent": {"id": "agent://example/agent", "version": "0"}, "principal": {"id": "workload://example/p"},
    "proposedAction": {"actionType": "tool.call", "target": {"name": "mcp://x", "uri": "mcp://x"},
                       "method": "POST", "parametersDigest": {"sha256": "0" * 64}},
    "inputSnapshot": [{"name": "input", "uri": "urn:proofbundle:input:0", "digest": {"sha256": "0" * 64},
                       "mediaType": "application/json"}],
    "policyBoundary": {"policyEngine": "opa", "policyId": "https://example.org/policy/v1",
                       "policyDigest": {"sha256": "0" * 64}, "decisionPath": "data.x.allow"},
    "evidenceRefs": [], "decision": {"verdict": "DENY", "reasonCodes": ["x"], "humanReadableSummary": "",
                                     "obligations": [], "allowedScope": []},
    "notChecked": [{"field": "x", "reason": "t", "impact": ""}],
    "decisionChangeConditions": [{"conditionType": "additionalApproval", "description": "",
                                  "requiredEvidenceType": "approvalReceipt"}],
    "privacy": {"rawInputsIncluded": False, "redactionProfile": "https://example.org/r/v1", "erased": [],
                "masked": []},
}


if __name__ == "__main__":
    unittest.main()
