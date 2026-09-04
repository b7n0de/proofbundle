"""v0.1 ist semantisch EINGEFROREN — Owner-Entscheid 31.08.2026.

DER KONFLIKT, den dieser Entscheid aufloest: die Haertungsforderung lautete "observedAt in Tier 1
verbieten". Umgesetzt haette sie ein bereits VEROEFFENTLICHTES Receipt ungueltig gemacht, dessen
observedAt eine Owner-Anordnung desselben Tages ausdruecklich verlangt hatte. Beide Regeln waren
richtig und kreuzten sich an einem Feld.

DER SCHNITT: kein rueckwirkendes Verbot, sondern eine explizit versionierte v0.2. Ein Verifier,
der "nur Receipts nach Datum X" ablehnte, muesste ausgerechnet an einer nicht bezeugten Zeit
entscheiden, welche Semantik gilt — die Version steht deshalb im predicateType.

Getestet sind hier die Versions- und Kompatibilitaetsfaelle 1 bis 3 des Entscheids.
"""
from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, dsse

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()


def _pred(observed=None) -> dict:
    return {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                           "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T20:00:00Z", "observedAt": observed},
        "limitations": ["l"],
    }


def _lauf(observed=None):
    p = _pred(observed)
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    return AR.verify_agent_review(env, PK, strict=True,
                                  expected_subject_digest=AR._subject_digest(p))


# ── Test 1 des Entscheids: bestehende v0.1-Receipts bleiben verifizierbar ──────────────────────

def test_ein_v01_receipt_mit_observedAt_bleibt_gueltig():
    """DER KERN DES EINFRIERENS. Waere hier ok=False, haetten wir ein veroeffentlichtes Receipt
    rueckwirkend gebrochen — genau das, was der Entscheid ausschliesst."""
    r = _lauf("2026-08-31T15:45:00Z")
    assert r["ok"] is True, r["errors"]
    assert r["crypto_ok"] is True and r["structure_ok"] is True


# ── Test 2: derselbe Fall liefert den Legacy-Code ──────────────────────────────────────────────

def test_derselbe_fall_traegt_den_stabilen_legacy_code():
    r = _lauf("2026-08-31T15:45:00Z")
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" in r["advisory_codes"]
    assert r["reason_codes"] == [], "ein Hinweis gehoert nicht unter die Fehlgruende"
    assert r["time_semantics"] == "LEGACY_V0_1"
    assert r["observed_time_assurance"] == "SELF_DECLARED_OR_UNKNOWN"
    assert any("LEGACY_SELF_DECLARED_OBSERVED_AT" in w for w in r["warnings"])


def test_der_hinweis_nimmt_dem_wert_die_kraft_und_sagt_das_auch():
    """Ein Code allein aendert nichts; der Text muss dem Leser sagen, was der Wert NICHT darf.
    Sonst ist der Hinweis eine Etikette und keine Grenze."""
    w = " ".join(_lauf("2026-08-31T15:45:00Z")["warnings"]).lower()
    for wort in ("freshness", "ttl", "currentness", "self-declaration"):
        assert wort in w, f"der Hinweis nennt {wort!r} nicht"


# ── Test 3: ohne observedAt kein Hinweis ───────────────────────────────────────────────────────

@pytest.mark.parametrize("observed", [None])
def test_ohne_observedAt_bleibt_der_hinweis_aus(observed):
    """DIE GEGENRICHTUNG. Ohne sie bestuende Test 2 auch, wenn der Code IMMER gesetzt wuerde —
    dann waere er kein Signal, sondern Rauschen."""
    r = _lauf(observed)
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" not in r["advisory_codes"]
    assert "LEGACY_SELF_DECLARED_OBSERVED_AT" not in r["reason_codes"]
    assert r["observed_time_assurance"] == "ABSENT"
    assert not any("LEGACY_SELF_DECLARED" in w for w in r["warnings"])
    assert r["ok"] is True


def test_time_semantics_steht_auch_ohne_observedAt():
    """v0.1 IST v0.1, unabhaengig davon ob das Feld belegt ist. Die Einordnung haengt an der
    Version, nicht am Feldwert — genau die Trennung, die der Entscheid verlangt."""
    assert _lauf(None)["time_semantics"] == "LEGACY_V0_1"


# ── reason_code bleibt die ABLEITUNG aus der Liste, kein zweites Feld ──────────────────────────

def test_der_fatale_code_steht_in_der_liste_UND_im_einzelfeld():
    """Zwei getrennt gepflegte Felder fuer dieselbe Groesse waeren die naechste Drift. Der fatale
    Code wird deshalb in die Liste geschrieben und daraus abgeleitet."""
    r = AR.verify_agent_review({"payload": "nicht-base64!!", "payloadType": "x",
                                "signatures": [{"sig": "x"}]}, PK)
    assert r["ok"] is False
    if r.get("reason_code") == "internal_error":
        assert "internal_error" in r["reason_codes"]


def test_ein_nicht_blockierender_code_macht_ok_nicht_falsch():
    """Die Unterscheidung, an der alles haengt: LEGACY_… ist ein HINWEIS, internal_error ein
    BEFUND. Wer beide gleich behandelt, bricht das Einfrieren durch die Hintertuer."""
    r = _lauf("2026-08-31T15:45:00Z")
    assert r["advisory_codes"] == ["LEGACY_SELF_DECLARED_OBSERVED_AT"]
    assert r["reason_codes"] == [], "ein Hinweis darf nicht unter den Fehlgruenden stehen"
    assert r.get("reason_code") is None, "ein Hinweis darf nicht als fataler Code erscheinen"
    assert r["ok"] is True


# ══ agent-review/v0.2 · Tests 4 bis 8 des Entscheids ═══════════════════════════════════════════

def _pred_v02(*, observedAt=None, timeClaims=None, observations=None) -> dict:
    p = {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                           "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64,
                           # v0.2 verlangt disclosureCoreDigest (P0.2). Der Wert ist hier ein
                           # Platzhalter — diese Datei prueft Zeitsemantik, nicht Digest-Bindung.
                           "disclosureCoreDigest": "e" * 64},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        # v0.2 verlangt limitationCodes (P0.4.6) — abgeleitet, nicht getippt.
        "limitationCodes": ["CURRENTNESS_UNKNOWN", "IDENTITY_UNBOUND", "NOT_QUALITY_ATTESTATION",
                            "TIME_SELF_DECLARED"],
        "times": {"declaredAt": "2026-08-31T20:00:00Z", "observedAt": observedAt,
                  "signedAt": "2026-08-31T20:00:00Z"},
        "limitations": ["l"],
    }
    if timeClaims is not None:
        p["declaration"]["timeClaims"] = timeClaims
    if observations is not None:
        p["observations"] = observations
    return p


REVIEW_CLAIM = [{"kind": "reviewCompleted", "value": "2026-08-31T15:45:00Z",
                 "assertedBy": "ownerOrder", "assurance": "selfDeclared"}]


def _lauf_v02(p, *, typ=None, policy=None):
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": typ or AR.AGENT_REVIEW_PREDICATE_TYPE_V02, "predicate": p}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    return env, AR.verify_agent_review_v02(env, PK, strict=True,
                                           expected_subject_digest=AR._subject_digest(p),
                                           policy=policy)


# Test 6 zuerst — die Kontrolle. Ohne sie belegt jedes Rot darunter nichts.
def test_v02_mit_reviewCompleted_selfDeclared_wird_akzeptiert():
    """EIN NICHT GEFAHRENER POLICY-LAUF IST KEIN NICHTBESTEHEN (Teil A3, 6.0.0, korrigiert).

    Die erste Fassung dieses Tests drehte `ok` auf False, wenn keine Policy uebergeben wurde. Das
    war falsch, und der Kontrollfall in `test_automation_nie_nachsichtiger_als_ok` hat es gefangen:
    ein Beleg ohne uebergebene Policy stand auf ok=False bei LEERER Fehlerliste — eine Ablehnung
    ohne Grund. Das Haus fuehrt die Unterscheidung ausdruecklich ("ein FEHLENDES ok ... ist 'nicht
    anwendbar', nicht 'nicht bestanden'"), und die Policy-Achse haengt bereits in
    `automation_summary`.

    WAS BLEIBT, IST DIE SICHTBARKEIT — und die ist der eigentliche Gewinn von A3: ohne Policy
    traegt das Ergebnis den Code POLICY_NOT_EVALUATED und `policy_decision is None`. Eine relying
    party sieht damit, dass die Achse NICHT gefahren wurde, statt sie fuer bestanden zu halten.
    Blocken tut sie in `safeForAutomation`, nicht in `ok`.

    Die vier Zeitachsen unten sind von A3 unberuehrt.
    """
    _, r = _lauf_v02(_pred_v02(timeClaims=REVIEW_CLAIM))
    assert r["ok"] is True, f"ohne Policy darf kein Fehler erfunden werden: {r.get('errors')[:3]}"
    assert AR.POLICY_NOT_EVALUATED in (r.get("reason_codes") or []), (
        "die nicht gefahrene Achse MUSS sichtbar sein — sonst liest sie sich wie bestanden")
    assert ((r.get("automation") or {}).get("safeForAutomation")) is not True, (
        "ohne Policy darf eine Maschine NICHT handeln duerfen — hier blockt die Achse")
    assert r["event_time_status"] == "SELF_DECLARED"
    assert r["observation_time_status"] == "ABSENT"
    assert r["signature_time_status"] == "SELF_DECLARED"
    assert r["external_time_status"] == "NOT_EVALUATED", "externe Zeit nie aus einem Payloadfeld"
    assert r["policy_decision"] is None, "ohne benannte Policy darf es keine Zeitfreigabe geben"


# Test 4 — beim EMIT verweigert
def test_v02_tier1_mit_observedAt_wird_beim_emit_verweigert():
    fehler = AR.validate_agent_review_v02_predicate(_pred_v02(observedAt="2026-08-31T15:45:00Z"))
    assert any("observedAt" in f for f in fehler), fehler
    assert any("separately named observer" in f for f in fehler), fehler


# Test 5 — beim VERIFY abgelehnt, auch fremd signiert
def test_v02_tier1_mit_observedAt_wird_beim_verify_abgelehnt():
    """Ein fremder Emitter benutzt unseren Validator nicht. Die Sperre muss im Verifier stehen."""
    _, r = _lauf_v02(_pred_v02(observedAt="2026-08-31T15:45:00Z", timeClaims=REVIEW_CLAIM))
    assert r["ok"] is False and r["structure_ok"] is False
    assert any("observedAt" in e for e in r["errors"])


def test_v02_observedAt_MIT_benanntem_beobachter_ist_zulaessig():
    """Die Gegenrichtung: die Sperre gilt der TIER-1-Selbstauskunft, nicht der Beobachtung."""
    beob = [{"kind": "reviewEvidenceReceived", "observedAt": "2026-08-31T20:33:08Z",
             "observer": {"id": "https://example.invalid/witness/gha"},
             "assurance": "runnerObserved"}]
    fehler = AR.validate_agent_review_v02_predicate(
        _pred_v02(observedAt="2026-08-31T20:33:08Z", observations=beob, timeClaims=REVIEW_CLAIM))
    assert not any("observedAt" in f for f in fehler), fehler


def test_eine_beobachtung_ohne_benannten_beobachter_hebt_nichts_an():
    """Sonst waere `observations` nur ein anderes Wort fuer dieselbe Selbstauskunft."""
    achsen = AR._zeitachsen(_pred_v02(observations=[{"kind": "x", "observedAt": "2026-08-31T20:00:00Z"}],
                                      timeClaims=REVIEW_CLAIM))
    assert achsen["observation_time_status"] == "SELF_DECLARED"


def test_zwei_widersprechende_reviewzeiten_ergeben_CONFLICT():
    zwei = REVIEW_CLAIM + [{"kind": "reviewCompleted", "value": "2026-08-31T09:00:00Z",
                            "assertedBy": "ownerOrder", "assurance": "selfDeclared"}]
    assert AR._zeitachsen(_pred_v02(timeClaims=zwei))["event_time_status"] == "CONFLICT"


def test_eine_deklarierte_zeit_darf_keine_hoehere_sprosse_behaupten():
    """Wer mehr als selfDeclared behauptet, meint eine Beobachtung — und die gehoert woanders hin."""
    hoch = [{"kind": "reviewCompleted", "value": "2026-08-31T15:45:00Z",
             "assertedBy": "ownerOrder", "assurance": "independentlyWitnessed"}]
    fehler = AR.validate_agent_review_v02_predicate(_pred_v02(timeClaims=hoch))
    assert any("belongs in observations" in f for f in fehler), fehler


@pytest.mark.parametrize("fehlt", ["kind", "value", "assertedBy", "assurance"])
def test_eine_zeitaussage_ohne_quelle_ist_keine(fehlt):
    tc = dict(REVIEW_CLAIM[0])
    tc.pop(fehlt)
    fehler = AR.validate_agent_review_v02_predicate(_pred_v02(timeClaims=[tc]))
    assert any(fehlt in f for f in fehler), fehler


# Test 7 — der v0.1-Verifier verweigert v0.2, statt zu raten
def test_v01_verifier_verweigert_v02_statt_zu_raten():
    p = _pred_v02(timeClaims=REVIEW_CLAIM)
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V02, "predicate": p}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = AR.verify_agent_review(env, PK, strict=True, expected_subject_digest=AR._subject_digest(p))
    assert r["ok"] is False and r["predicate_type_ok"] is False
    assert "UNKNOWN_PREDICATE_VERSION" in r["reason_codes"]
    assert any("refuses" in e and "guessing" in e for e in r["errors"]), r["errors"]


# Test 8 — der v0.2-Verifier deutet v0.1 nicht still um
def test_v02_verifier_deutet_v01_nicht_still_um():
    p = _pred(observed="2026-08-31T15:45:00Z")
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": p}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = AR.verify_agent_review_v02(env, PK, strict=True, expected_subject_digest=AR._subject_digest(p))
    assert r["ok"] is False and "UNKNOWN_PREDICATE_VERSION" in r["reason_codes"]
    assert any("rewrite what that receipt meant" in e for e in r["errors"]), r["errors"]


# ── Der Hinweis reist nicht ueber die Versionsgrenze ───────────────────────────────────────────

@pytest.mark.parametrize("predicate_type,soll", [
    ("v0.1", True),
    ("v0.2", False),
    ("unbekannt", False),
])
def test_der_legacy_hinweis_gilt_nur_fuer_echte_v0_1_receipts(predicate_type, soll):
    """DER BEFUND (adversariale Linse, 02.09.2026): der Hinweis sagt woertlich „this v0.1
    receipt" — und erschien auch, wenn der `predicateType` v0.2 oder voellig unbekannt war.

    Seine ZWEI NACHBARN im selben `if isinstance(predicate, dict)`-Block waren an
    `predicate_type_ok` gebunden, dieser Append nicht. Das Modul verlangt an zwei Stellen
    ausdruecklich „KEIN RATEN UEBER VERSIONSGRENZEN"; hier wurde eine versionsspezifische Aussage
    ueber die Grenze getragen, in ein Feld, auf das Verbraucher verzweigen sollen.

    Ausnutzbarkeit gering (das Receipt faellt ohnehin), aber es ist eine falsche Aussage in einem
    maschinenlesbaren Feld — und der Fix hatte bis zu diesem Test keinen Waechter.
    """
    typen = {"v0.1": AR.AGENT_REVIEW_PREDICATE_TYPE,
             "v0.2": AR.AGENT_REVIEW_PREDICATE_TYPE_V02,
             "unbekannt": "https://example/unbekannt/v1"}
    p = _pred("2026-09-01T10:00:00Z")
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p),
                       "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": typen[predicate_type], "predicate": p}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = AR.verify_agent_review(env, PK, strict=True)
    da = "LEGACY_SELF_DECLARED_OBSERVED_AT" in r["advisory_codes"]
    assert da is soll, (
        f"predicateType={predicate_type}: advisory={r['advisory_codes']}, "
        f"predicate_type_ok={r['predicate_type_ok']} — ein v0.1-Satz ueber ein "
        f"{predicate_type}-Receipt ist eine falsche Aussage")


def test_v02_mit_der_standard_policy_faellt_eine_benannte_entscheidung():
    """MIT Policy faellt eine Entscheidung, und ihr Digest steht im Ergebnis.

    DER NAME SAGT JETZT, WAS DIE ZUSICHERUNG PRUEFT. Er hiess zuerst „wird akzeptiert" — und war
    damit staerker als sein eigener assert: geprueft wurde `policy_decision is not None`, und das
    ist bei `insufficient_evidence` genauso wahr. Das Praedikat hier traegt `coverage.status:
    UNKNOWN`, das die Standard-Policy ausdruecklich NICHT als Abdeckungsangabe gelten laesst — es
    wird also gerade nicht akzeptiert. Die Annahme steht im Test darunter, mit einem Praedikat,
    das sie wirklich erfuellt.
    """
    pol = AR.load_policy()
    assert pol["_digest"].startswith("sha256:"), pol.get("_digest")
    _, r = _lauf_v02(_pred_v02(timeClaims=REVIEW_CLAIM), policy=pol)
    assert r["policy_decision"] == "insufficient_evidence", (
        "coverage.status UNKNOWN ist keine Abdeckungsangabe, sondern deren Abwesenheit — "
        f"gemessen: {r['policy_decision']}")
    assert r["policy_name"] == AR.STANDARD_POLICY_NAME
    assert r["policy_digest"] == pol["_digest"], "der Digest der Policy gehoert ins Ergebnis"
    assert AR.POLICY_NOT_EVALUATED not in (r.get("reason_codes") or [])
    # DIE SPERRE HAENGT AN DER AUTOMATION, NICHT AN `ok` — und diese Zeile stand zuerst falsch.
    # `insufficient_evidence` heisst: die Policy LIEF und konnte nicht entscheiden. Das ist eine
    # Aussage ueber die Beweislage der Policy, nicht ueber die Stimmigkeit des Belegs; ein Beleg
    # wird nicht kaputt, weil eine fremde Erwartung an ihm nicht entscheidbar ist. „Nicht messbar
    # ist keine Freigabe" gilt trotzdem, nur ist die FREIGABE hier `safeForAutomation`:
    # gemessen sperrt sie mit dem Grund POLICY_FAILED. Wer beides an `ok` haengt, macht aus einer
    # unentscheidbaren Frage einen Defekt und verliert die Unterscheidung, die das Haus fuehrt.
    assert r["ok"] is True, f"unentscheidbar ist kein Defekt des Belegs: {r.get('errors')[:3]}"
    assert ((r.get("automation") or {}).get("safeForAutomation")) is False, (
        "eine nicht-akzeptierende Entscheidung darf keine Automation freigeben")
    assert "POLICY_FAILED" in ((r.get("automation") or {}).get("automationBlockers") or []), (
        "und der Grund muss benannt sein, sonst ist die Sperre nicht nachvollziehbar")


def test_v02_mit_genannter_abdeckung_wird_wirklich_akzeptiert():
    """DIE ECHTE GEGENRICHTUNG. Ohne sie waere die Verschaerfung nur eine Sperre: ein Verifizierer,
    der NIE akzeptiert, unterscheidet so wenig wie einer, der immer akzeptiert."""
    p = _pred_v02(timeClaims=REVIEW_CLAIM)
    # `knownGaps` statt `note`: der Validator sagt es woertlich — „an incomplete coverage that
    # names no gap cannot be checked against anything". Eine PARTIAL-Abdeckung ohne benannte
    # Luecke ist keine Angabe, sondern eine Andeutung.
    p["coverage"] = {"status": "PARTIAL", "knownGaps": ["nur eine Datei gelesen"]}
    p["limitationCodes"] = ["COVERAGE_PARTIAL", "IDENTITY_UNBOUND", "NOT_QUALITY_ATTESTATION",
                            "TIME_SELF_DECLARED"]
    _, r = _lauf_v02(p, policy=AR.load_policy())
    assert r["policy_decision"] == "accept", r.get("policy_reason")
    assert r["ok"] is True, r["errors"]
