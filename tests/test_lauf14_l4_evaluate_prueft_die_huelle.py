"""Lauf 14, Linse L4, F1 (11.09.2026): `load_policy` weist einen unbekannten Schluessel auf JEDER
Ebene ab ("a typo that silently weakens a policy is impossible") — aber nur der Aufrufer, der
`load_policy` ruft, bekam diese Garantie. Die drei Auswerte-Funktionen, die jede verify_*-Flaeche
tatsaechlich ruft (`evaluate_policy`, `evaluate_decision_policy`, `relation.evaluate_relations_policy`)
lasen ihre Schalter per `.get(name)` und pruefen die Huelle selbst nie.

Gemessen am Kopf f6c5c8a: `{"signature": {"require_expected_signerr": True}}` (ein r zu viel) ergab
`policy_ok: True, checks: []` fuer ein Bundle, dessen Signierer der Text "any-attacker-key-at-all"
ist; korrekt geschrieben ergab dieselbe Policy `policy_ok: False` (unerfuellbar, fail-closed).
`{"reject_superseeded": True}` (ein e zu viel) liess eine attached Supersession unbeanstandet.

Klasse: ein `require_*`/`reject_*`-Schalter, dessen ABWESENHEIT der laxe Pfad ist, verliert bei
einem Tippfehler lautlos genau die Bindung, die er herstellen sollte. Dieselbe Klasse schloss
Lauf 13 im Rust-Zweitverifizierer (`policy_huelle_pruefen`). Fix: EINE Huellenpruefung
(`policy._huelle_pruefen`), die `load_policy` UND die drei Auswerter rufen — keine zweite Liste.
"""
from __future__ import annotations

import pytest

from proofbundle import policy, relation
from proofbundle.policy import PolicyError, evaluate_decision_policy, evaluate_policy, load_policy


class _R:
    ok = True
    checks: list = []


_BUNDLE = {"schema": "proofbundle/v1",
           "signature": {"alg": "ed25519", "public_key_b64": "any-attacker-key-at-all"}, "merkle": {}}
_KEY = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="   # ein kanonischer, hoher Ed25519-Punkt
_CP = {"origin": "example.org/log", "root": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
       "treeSize": 1, "hashAlg": "sha256-rfc6962", "checkpointSigner": "n+abcd1234+AAAA",
       "signature": "AAAA"}

# Je Ebene: (Beschreibung, Policy MIT Tippfehler). Der Rest der Policy ist jeweils korrekt.
_TIPPFEHLER = [
    ("oben", {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p", "allowed_isuers": []}),
    ("signature", {"signature": {"require_expected_signerr": True}}),
    ("merkle", {"merkle": {"require_authenticated_rot": True}}),
    ("merkle.trusted_checkpoints[]", {"merkle": {"trusted_checkpoints": [dict(_CP, validUntl="2030-01-01T00:00:00Z")]}}),
    ("sd_jwt", {"sd_jwt": {"require_nonc": True}}),
    ("status", {"status": {"reject_self_isued": True}}),
    ("assurance", {"assurance": {"minimum_levl": "self_attested"}}),
    ("anchors", {"schema": "proofbundle/trust-policy/v0.2", "anchors": {"require_ancor": "rfc3161"}}),
    ("relations", {"schema": "proofbundle/trust-policy/v0.2", "relations": {"reject_superseeded": True}}),
    ("relations.relation_signer[]", {"schema": "proofbundle/trust-policy/v0.2",
                                     "relations": {"relation_signer": {"supersedes": {"mode": "same-key", "keyz": []}}}}),
    ("decision_receipt", {"schema": "proofbundle/trust-policy/v0.2", "decision_receipt": {"require_audienc": True}}),
    ("decision_receipt.trusted_decision_makers[]",
     {"schema": "proofbundle/trust-policy/v0.2",
      "decision_receipt": {"trusted_decision_makers": [{"public_key_b64": _KEY, "kidd": "a"}]}}),
    ("allowed_issuers[]", {"allowed_issuers": [{"public_key_b64": _KEY, "issuerr": "a"}]}),
]


@pytest.mark.parametrize("ebene, pol", _TIPPFEHLER, ids=[e for e, _ in _TIPPFEHLER])
def test_evaluate_policy_weist_einen_tippfehler_auf_jeder_ebene_ab(ebene, pol):
    r = evaluate_policy(_BUNDLE, _R(), pol)
    assert r["policy_ok"] is False, f"{ebene}: ein Tippfehler darf nie policy_ok=True ergeben"
    assert "unknown field" in r["reason"]


@pytest.mark.parametrize("ebene, pol", _TIPPFEHLER, ids=[e for e, _ in _TIPPFEHLER])
def test_evaluate_decision_policy_weist_denselben_tippfehler_ab(ebene, pol):
    r = evaluate_decision_policy({"predicate": {}}, {}, pol, signer_public_key_b64=_KEY)
    assert r["policy_ok"] is False
    assert r["signer_trusted"] is False
    assert any("unknown field" in e for e in r["errors"])


def test_der_urspruengliche_fall_kippt_nicht_mehr_nach_gruen():
    typo = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
            "signature": {"require_expected_signerr": True}}
    korrekt = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
               "signature": {"require_expected_signer": True}}
    assert evaluate_policy(_BUNDLE, _R(), typo)["policy_ok"] is False
    assert evaluate_policy(_BUNDLE, _R(), korrekt)["policy_ok"] is False


def test_evaluate_relations_policy_weist_einen_tippfehler_ab():
    lineage = {"edges": [], "supersededByAttached": "superseded_by_attached: attached receipt abc… declares supersedes"}
    korrekt = relation.evaluate_relations_policy({"reject_superseded": True}, lineage, successor_key_b64=None)
    assert korrekt and korrekt[0]["code"] == relation.CODE_LINEAGE_REQUIREMENT_FAILED
    typo = relation.evaluate_relations_policy({"reject_superseeded": True}, lineage, successor_key_b64=None)
    assert typo, "der Tippfehler darf die beabsichtigte Sperre nicht lautlos abschalten"
    assert typo[0]["code"] == relation.CODE_LINEAGE_REQUIREMENT_FAILED
    assert "unknown field" in typo[0]["message"]
    innen = relation.evaluate_relations_policy(
        {"relation_signer": {"supersedes": {"mode": "same-key", "keyz": []}}}, lineage, successor_key_b64=None)
    assert innen and "unknown field" in innen[0]["message"]


def test_positivkontrolle_korrekt_geschriebene_policies_bleiben_unveraendert():
    r = evaluate_policy(_BUNDLE, _R(), {"signature": {"allowed_algs": ["ed25519"]}})
    assert r["policy_ok"] is True and r["checks"][0]["name"] == "policy:signature_alg"
    r = evaluate_decision_policy({"predicate": {}}, {}, {"signature": {"allowed_algs": ["ed25519"]}},
                                 signer_public_key_b64=_KEY)
    assert r["policy_ok"] is None
    assert relation.evaluate_relations_policy({"reject_superseded": False}, {"edges": []}, successor_key_b64=None) == []


def test_load_policy_und_evaluate_teilen_eine_regel():
    with pytest.raises(PolicyError, match="unknown field"):
        load_policy({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                     "signature": {"require_expected_signerr": True}})
    assert policy._huelle_pruefen.__doc__
