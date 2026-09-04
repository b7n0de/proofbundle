"""Konformitaets-Vektoren fuer agent-review/v0.1

DIE FASSUNG STEHT HIER AUSDRUECKLICH, seit v0.2 die Vorgabe ist (6.0.0). Dieser Korpus IST der
v0.1-Bestand; ohne `legacy_v01=True` waere er beim naechsten Lauf still auf v0.2 gekippt und
haette zwanzig committete Falldateien geaendert — gegen die Zusage zwei Absaetze weiter unten,
dass ein Korpus, dessen Bytes sich bei jedem Lauf aendern, keiner ist. Die v0.2-Faelle bekommen
ihren eigenen Abschnitt, sie ersetzen diese nicht.

Nach dem Hausmuster von conformance/envelope_profile."""
import copy
import json
import os
import pathlib
import sys
sys.path.insert(0, "src")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from proofbundle import agent_review as AR

# Das Ziel ist ueberschreibbar, damit ein Test den Korpus NEBEN den echten erzeugen und beide
# bytegenau vergleichen kann. Ohne diesen Schalter muesste ein solcher Test in den echten Korpus
# schreiben — und genau das hat am 01.09.2026 einen von Hand nachgetragenen Fix (K-D, die fehlende
# expectedSubjectDigest-Erwartung) STILL GELOESCHT, weil die Aenderung am ERZEUGTEN Artefakt und
# nicht an seiner Quelle gemacht worden war. Ein Pruefwerkzeug, das seinen Prueflig veraendert,
# ist selbst ein Risiko.
ROOT = pathlib.Path(os.environ.get("AGENT_REVIEW_CORPUS_ROOT") or "conformance/agent_review")
# Deterministischer Schluessel: ein Vektorkorpus, dessen Bytes sich bei jedem Lauf aendern, ist
# kein Korpus — er waere bei jedem Regenerieren ein Diff ohne inhaltlichen Anlass.
sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
pk = sk.public_key().public_bytes_raw()

BODY = ("# Title\n\nSome PR text.\n\n" + AR.DISCLOSURE_BEGIN + "\n- **X:** y\n"
        + AR.DISCLOSURE_END + "\n\nTail.\n")
FINDINGS = [
    {"id": "F1", "severity": "high", "title": "unbalanced marker accepted",
     "disposition": "fixed", "fixCommit": "a" * 40},
    {"id": "F2", "severity": "low", "title": "wording too broad",
     "disposition": "dismissed", "reason": "covered by the limitations block"},
]
BASE = {
    "schemaVersion": "0.1.0",
    "reviewId": "agent-review-conformance-01",
    "subjectContext": {
        "kind": "githubPullRequest", "forge": "github.com",
        "repositoryId": "R_kgDOAbCdEf", "pullRequestNodeId": "PR_kwDOAbCdEf",
        "headSha": "b" * 40, "baseSha": "c" * 40,
        "reviewedDiffDigest": "d" * 64,
        "bodyCoreDigest": AR.body_core_digest(BODY),
    },
    "declaration": {
        "authoring": [{"assurance": "selfDeclared", "assertedBy": "an agent"}],
        "reviewRuns": [{"assurance": "selfDeclared", "assertedBy": "an agent, second pass"}],
        "findings": FINDINGS,
        "findingsTotal": len(FINDINGS),
        "findingsRoot": AR.findings_root(FINDINGS),
        "nonClaims": ["does not prove the named agent was involved"],
    },
    "coverage": {"status": "PARTIAL", "observedRuns": 2, "expectedRuns": None,
                 "knownGaps": ["runs outside this session are not visible"]},
    "times": {"declaredAt": "2026-08-31T17:00:00Z", "observedAt": None,
              "signedAt": "2026-08-31T17:00:01Z", "anchoredAt": None},
    "limitations": ["offline verification cannot establish currency"],
}

def schreibe(case_id, role, rule, expected, rationale, *, envelope=None, obj=None,
             input_name, params=None, attribution=None, spec_refs=None,
             predicate_version=None):
    d = ROOT / case_id
    d.mkdir(parents=True, exist_ok=True)
    payload = envelope if envelope is not None else obj
    (d / input_name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (d / "case.json").write_text(json.dumps({
        "caseId": case_id, "kind": "agent_review_predicate", "rule": rule, "role": role,
        "input": input_name,
        **({"predicateVersion": predicate_version} if predicate_version is not None else {}),
        "attribution": attribution or (
            "agent-review/v0.1 — built 31.08.2026 against the external adversarial read "
            "(18 findings). Rule ids are that read's finding ids."),
        "expected": expected,
        **({"params": params} if params is not None else {}),
        "specRefs": spec_refs or ["docs/AGENT_REVIEW_PREDICATE.md",
                                 "src/proofbundle/agent_review.py"],
        "rationale": rationale,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return d

# 1 — Positivkontrolle
env = AR.emit_agent_review(BASE, sk, legacy_v01=True)
schreibe("agent-review-positive-control-valid-self-declared", "positive_control", "F01",
         {"classification": "valid"},
         "A well-formed v0.1 receipt verifies and reports selfDeclared. If this vector ever fails, the "
         "emit or verify path changed shape and every counter-proof below becomes unreadable. It "
         "SUPPLIES the expected subject digest, because that is what a real relying party does: it "
         "knows which pull request it is looking at. Since the second review round, `ok` is only true "
         "when that question was actually asked — a receipt can be internally sound and still belong "
         "to something else, and a control that never asks would pass on the weaker statement.",
         envelope=env, input_name="envelope.json",
         params={"expectedSubjectDigest": AR._subject_digest(BASE)})

# 2 — Gegenprobe: Assurance hochgestuft
p = copy.deepcopy(BASE)
p["declaration"]["authoring"][0]["assurance"] = "independentlyWitnessed"
schreibe("agent-review-counter-proof-assurance-cannot-be-self-raised", "counter_proof", "F01",
         {"classification": "refused"},
         "The whole point of the predicate: a producer must not be able to label its own claim as "
         "independently witnessed. This is rejected at EMIT time, not merely reported at verify — a "
         "receipt that cannot be produced cannot be shown to anyone.",
         obj=p, input_name="predicate.json")

# 3 — Gegenprobe: findingsRoot deckt die Liste nicht mehr
p = copy.deepcopy(BASE)
p["declaration"]["findings"] = FINDINGS[:1]
env3 = AR.emit_agent_review(p, sk, legacy_v01=True)   # Erzeugen erlaubt: die Root ist dann schlicht falsch
schreibe("agent-review-counter-proof-findings-root-covers-the-list", "counter_proof", "F09",
         {"classification": "invalid"},
         "Removing a finding after the root was taken must be detectable. A receipt that reports "
         "'3 findings, 2 fixed' without a root binding is an aggregate anyone can rewrite.\n\n"
         "NACHTRAG 01.09.2026, Tiefen-Gate 5.1.0: dieser Fall KONNTE NICHT KIPPEN. Ohne "
         "params.expectedSubjectDigest ist subject_expectation=not_supplied, damit ok=False fuer "
         "JEDE Eingabe, damit ist die Klassifikation immer die erwartete 'invalid' — der Fall "
         "bestand auch mit abgeschalteter findingsRoot-Pruefung, und die ganze Strecke blieb rc=0. "
         "Zwei unabhaengige Linsen haben das mit je eigenen Mutanten gemessen. F09 war zudem die "
         "einzige Regel MIT Gegenbeweis und OHNE Positivkontrolle, es gab also keinen zweiten "
         "Faenger. Die Erwartung ist derselbe Wert, den die zwei Geschwister-Faelle bereits "
         "tragen; damit faellt der Fall wieder auf SEINER eigenen Achse.",
         envelope=env3, input_name="envelope.json",
         params={"expectedSubjectDigest": AR._subject_digest(BASE)})

# 4 — Gegenprobe: anchoredAt ohne Beleg
p = copy.deepcopy(BASE)
p["times"]["anchoredAt"] = "2026-08-31T17:00:02Z"
schreibe("agent-review-counter-proof-anchored-time-needs-evidence", "counter_proof", "F06",
         {"classification": "refused"},
         "A signature proves the signed bytes contain a time value, not that the value is externally "
         "true. v0.1 carries no anchor evidence, so it refuses the claim instead of passing it through.",
         obj=p, input_name="predicate.json")

# 5 — Gegenprobe: COMPLETE ohne genannte Erwartung
p = copy.deepcopy(BASE)
p["coverage"] = {"status": "COMPLETE", "observedRuns": 2}
schreibe("agent-review-counter-proof-complete-needs-an-expectation", "counter_proof", "F07",
         {"classification": "refused"},
         "Without a stated expectation, 'complete' means 'I saw everything I happened to see' and "
         "cannot be falsified. Unobserved work must appear as a gap, never as a zero count.",
         obj=p, input_name="predicate.json")

# 6 — Gegenprobe: Receipt auf einen anderen PR kopiert
p = copy.deepcopy(BASE)
p["subjectContext"]["pullRequestNodeId"] = "PR_kwDOZZZZZZ"
env6 = AR.emit_agent_review(p, sk, legacy_v01=True)
schreibe("agent-review-counter-proof-receipt-does-not-travel-between-subjects", "counter_proof", "F02",
         {"classification": "invalid"},
         "A valid signature on the wrong object is the failure mode this binding exists for. Verified "
         "against the original subject digest, this receipt must fail — it is cryptographically sound "
         "and bound to something else.",
         envelope=env6, input_name="envelope.json",
         params={"expectedSubjectDigest": AR._subject_digest(BASE)})

# 7 — Gegenprobe: duplizierter Offenlegungsblock
schreibe("agent-review-counter-proof-duplicate-disclosure-block-fails-closed", "counter_proof", "F03",
         {"classification": "refused"},
         "An attacker who may append a second block could otherwise choose which one defines the "
         "digest. Two blocks is not a body we can reduce to one canonical form, so the digest is "
         "refused rather than guessed.",
         obj={"body": BODY + AR.render_disclosure_block(BASE)}, input_name="body.json")

# 8 — Positivkontrolle: Block neu gerendert, Digest stabil
blk = AR.render_disclosure_block(BASE, receipt_digest="e" * 64)
neu = BODY[:BODY.index(AR.DISCLOSURE_BEGIN)] + blk + BODY[BODY.index(AR.DISCLOSURE_END) + len(AR.DISCLOSURE_END):]
schreibe("agent-review-positive-control-rerendered-block-keeps-body-core", "positive_control", "F03",
         {"bodyCoreStable": True},
         "Re-rendering the machine-managed block from the same canonical receipt must not move the "
         "body core digest. If it did, every disclosure update would look like body tampering and the "
         "binding would be unusable in practice.",
         obj={"bodyBefore": BODY, "bodyAfter": neu}, input_name="bodies.json")


# 9 — Gegenprobe: die Luecken-Pflicht durch Weglassen abschalten
p = copy.deepcopy(BASE)
del p["declaration"]["findingsTotal"]
p["declaration"]["findings"] = FINDINGS[:1]
schreibe("agent-review-counter-proof-gap-duty-cannot-be-switched-off", "counter_proof", "F07",
         {"classification": "refused"},
         "THE ATTACK AN EXTERNAL REVIEW ACTUALLY RAN (31.08.2026) AND THAT SUCCEEDED. While "
         "findingsTotal was optional, a producer could list one finding of eight, omit the field, "
         "leave knownGaps empty — and the validator reported ZERO errors. A duty that switches off "
         "by omitting a field is not a duty. The field is now required.",
         obj=p, input_name="predicate.json")

# 10 — Gegenprobe: PARTIAL ohne benannte Luecke (Nachbar derselben Klasse)
p = copy.deepcopy(BASE)
p["coverage"] = {"status": "PARTIAL", "observedRuns": 2, "knownGaps": []}
schreibe("agent-review-counter-proof-partial-must-name-its-gap", "counter_proof", "F07",
         {"classification": "refused"},
         "The neighbour of the case above, closed in the same pass. COMPLETE had to state its "
         "expectation; PARTIAL had to state nothing at all and was therefore just as unfalsifiable — "
         "'incomplete, but I will not say in what' is not a statement about coverage.",
         obj=p, input_name="predicate.json")

# 11 — Positivkontrolle: ohne Erwartung wird die Grenze GEMELDET, nicht verschwiegen
env11 = AR.emit_agent_review(BASE, sk, legacy_v01=True)
schreibe("agent-review-positive-control-absent-expectation-is-reported", "positive_control", "F02",
         {"subjectExpectation": "not_supplied"},
         "A CORRECTION TO A CLAIM WE MADE OURSELVES. We wrote that a receipt copied onto another "
         "pull request fails the subject check. It does not: derived and claimed both come from the "
         "same signed subjectContext, so they always agree unless someone hand-builds the statement. "
         "Without an expectation supplied from outside, this is a CONSISTENCY check, not a binding "
         "to the object the reader is looking at. The absence is now reported instead of passing "
         "silently.",
         envelope=env11, input_name="envelope.json")


# 12 — Gegenprobe: die EINFUEHRUNG des ersten Blocks bewegt den Digest sehr wohl
roh = "# Title\n\nSome PR text.\n\n### Agent review\n\n- Passes: 2\n"
schreibe("agent-review-counter-proof-introducing-the-first-block-moves-the-digest", "counter_proof",
         "F03", {"bodyCoreStable": False},
         "THE ORDERING DEFECT, FOUND WHILE ADDING A REAL DISCLOSURE LINE TO A LIVE PULL REQUEST "
         "(31.08.2026). Changing a block leaves the core digest alone; INTRODUCING the first one "
         "does not, because a body without a block and the same body with an empty one differ by "
         "the token's own bytes. A receipt emitted over the pre-block body binds a body that stops "
         "existing the moment its own disclosure line is added. This case pins the difference so "
         "nobody assumes the stable case covers both.",
         obj={"bodyBefore": roh,
              "bodyAfter": AR.prepare_body_for_disclosure(roh, anchor="### Agent review")},
         input_name="bodies.json")

# 13 — Positivkontrolle: prepare, dann replace — der Digest darf sich NICHT bewegen
vorbereitet = AR.prepare_body_for_disclosure(roh, anchor="### Agent review")
gefuellt = AR.replace_disclosure_block(
    vorbereitet, AR.DISCLOSURE_BEGIN + "\n- **Receipt:** sha256:" + "f" * 64 + "\n" + AR.DISCLOSURE_END)
schreibe("agent-review-positive-control-prepare-then-fill-keeps-the-digest", "positive_control",
         "F03", {"bodyCoreStable": True},
         "The correct order, pinned as a control. Prepare the body, take the digest over THAT, emit, "
         "then fill the prepared position. The last step cannot move the digest because the block's "
         "content is replaced by the token either way — which is the entire reason the markers "
         "exist. Without this control the counter-proof above could be satisfied by a verifier that "
         "simply reports instability for everything.",
         obj={"bodyBefore": vorbereitet, "bodyAfter": gefuellt}, input_name="bodies.json")


# 14 — Positivkontrolle: der ECHTE Emit-Verify-Roundtrip
#
# NACHGETRAGEN 01.09.2026. Dieser Fall wurde am selben Tag von Hand angelegt und stand danach auf
# der Platte UND im Manifest, aber NICHT hier — ein Neulauf des Generators haette ihn nicht
# erzeugt, und damit waere der Korpus nicht mehr aus seiner Quelle reproduzierbar gewesen. Die
# Gegenlese Runde 2 verlangt unter P0.5.1 ausdruecklich reproduzierbare Fixtures.
#
# Das Praedikat ist bewusst NICHT von BASE abgeleitet: es soll den positiven Zweig unabhaengig
# treffen, und ein Ableger haette dieselben Werte noch einmal behauptet statt sie zu pruefen.
ROUNDTRIP = {
    "coverage": {
        "knownGaps": [
            "nur ein Lauf erfasst"
        ],
        "status": "PARTIAL"
    },
    "declaration": {
        "authoring": [
            {
                "assertedBy": "agent",
                "assurance": "selfDeclared"
            }
        ],
        "findings": [
            {
                "disposition": "dismissed",
                "id": "F1",
                "reason": "im Kontext nicht anwendbar",
                "severity": "low",
                "title": "ein Fund"
            }
        ],
        "findingsRoot": "a9315babdef60590b291d47617a6dade99f407e3d66d5edf8e98a2d851e876e2",
        "findingsTotal": 1,
        "nonClaims": [
            "kein Nachweis von Unabhaengigkeit"
        ],
        "reviewRuns": []
    },
    "limitations": [
        "Tier 1, selbst deklariert, kein externer Zeuge"
    ],
    "reviewId": "roundtrip-positive-control",
    "schemaVersion": "0.1.0",
    "subjectContext": {
        "baseSha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "bodyCoreDigest": "2de5900a45b84d021dfb8cf9850be84c0c848f92bf780516ce9edf74383f7365",
        "forge": "github.com",
        "headSha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "kind": "githubPullRequest",
        "pullRequestNodeId": "PR_kwDOroundtrip",
        "repositoryId": "R_kgDOroundtrip",
        "reviewedDiffDigest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    },
    "times": {
        "declaredAt": "2026-09-01T09:00:00Z"
    }
}
schreibe("agent-review-positive-control-emit-verify-roundtrip", "positive_control", "PBF08",
         {"classification": "valid"},
         "OHNE DIESEN FALL MISST DIE UMSTELLUNG NICHTS, und das ist gemessen: alle fuenf bisherigen predicate.json-Faelle erwarten `refused`, also wurde der `valid`-Zweig nie erreicht. Ein eingepflanzter Defekt, der die Validierung besteht und erst im Verifier faellt (Statement mit falschem Subject-Digest), liess die Strecke gruen — mit der Umstellung UND ohne sie. Dieser Fall fuehrt den positiven Roundtrip: das Praedikat wird mit dem deterministischen Korpus-Schluessel wirklich EMITTIERT und das erzeugte Envelope danach verifiziert. `valid` heisst hier also 'erzeugt und wieder gelesen', nicht 'bestand die Validierung'.",
         obj=ROUNDTRIP, input_name="predicate.json", params={},
         attribution="agent-review/v0.1 — ergaenzt 01.09.2026 nach der Gegenlese Runde 2 (N06 / P0.5): die Strecke rief fuer Praedikat-Faelle den VALIDATOR, nicht den Erzeuger.",
         spec_refs=["docs/AGENT_REVIEW_PREDICATE.md", "src/proofbundle/agent_review.py", "conformance/run_conformance.py"])


# ── Test 19: Supersession ───────────────────────────────────────────────────────────────────────
# Die Gegenlese Runde 2 fuehrt Test 19 ZWEIMAL als "WIDERLEGT als gefahrene Mutation": der
# Erstanwendungsbericht nannte ihn gefahren, und in der vollstaendigen Fall-Liste existierte
# ueberhaupt kein Supersessions-Fall. Diese drei schliessen das.
#
# Der Angreiferschluessel ist ebenso deterministisch wie der Korpusschluessel und ausdruecklich
# NICHT der unsere — ein Uebernahmeversuch, der mit unserem Schluessel signiert, waere kein
# Uebernahmeversuch, sondern wir selbst.
angreifer_sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))

alt = copy.deepcopy(BASE)
alt["reviewId"] = "agent-review-conformance-01-erste-fassung"
env_alt = AR.emit_agent_review(alt, sk, legacy_v01=True)
digest_alt = AR.receipt_digest(env_alt)

neu_p = copy.deepcopy(BASE)
neu_p["reviewId"] = "agent-review-conformance-01-zweite-fassung"
neu_p["supersession"] = {"supersedes": [
    {"priorDigest": {"sha256": digest_alt},
     "reason": "die erste Fassung zaehlte einen Fund doppelt"}]}
env_neu = AR.emit_agent_review(neu_p, sk, legacy_v01=True)
digest_neu = AR.receipt_digest(env_neu)

# 15 — Positivkontrolle: die Kette benennt genau einen aktuellen Beleg
schreibe("agent-review-positive-control-supersession-names-the-current-receipt", "positive_control",
         "F15", {"currentReceipt": digest_neu},
         "Ohne diese Kontrolle misst die Gegenprobe darunter nichts: ein Resolver, der IMMER "
         "None liefert, bestuende jeden Fall, der nur Abwehr prueft. Zwei Belege, der zweite "
         "benennt den ersten als ueberholt — genau einer darf danach aktuell sein, und es muss "
         "der zweite sein. Ein ueberholtes Receipt wird dabei nicht ungueltig, es ist nur nicht "
         "mehr der Stand, auf den ein oeffentlicher Verweis zeigen soll.",
         obj={"envelopes": [env_alt, env_neu]}, input_name="chain.json")

# 16 — Gegenprobe: ein fremd signierter Umschlag darf die Kette NICHT uebernehmen
uebernahme = copy.deepcopy(BASE)
uebernahme["reviewId"] = "uebernahme-versuch"
uebernahme["supersession"] = {"supersedes": [
    {"priorDigest": {"sha256": digest_alt},
     "reason": "behauptet, unseren Beleg zu ersetzen"}]}
env_fremd = AR.emit_agent_review(uebernahme, angreifer_sk, legacy_v01=True)
schreibe("agent-review-counter-proof-a-foreign-key-cannot-supersede-our-receipt", "counter_proof",
         "F15", {"unverifiedSupersessionClaim": AR.receipt_digest(env_fremd)},
         "DER ANGRIFF, DEN DER RESOLVER ABWEHREN MUSS. Ein Angreifer mit EIGENEM Schluessel legt "
         "einen Umschlag dazu, der unseren Beleg als ueberholt benennt. Wuerde die Ordnung vor "
         "der Signaturpruefung entstehen, zeigte `current` danach auf SEIN Receipt und unseres "
         "stuende unter `corrected` — bei gueltiger Signatur, denn seine ist gueltig, nur nicht "
         "unsere. Der Laeufer prueft deshalb jeden Umschlag SELBST und uebergibt nur die "
         "bestandenen; der fremde faellt heraus und darf danach nichts mehr korrigieren.\n\n"
         "DIE ACHSE IST BEWUSST NICHT `current`. Gemessen 01.09.2026: nach der Abwehr sind ZWEI "
         "Belege unkorrigiert, also meldet der Resolver ehrlich `current=None` statt zu raten — "
         "und genau dasselbe kaeme heraus, wenn er Supersession gar nicht ansaehe. Ein Fall auf "
         "`current` bestuende also auch bei einem blinden Resolver. Die unterscheidende Aussage "
         "ist der GEMELDETE Anspruch: er belegt, dass der Versuch gesehen und verworfen wurde. "
         "Zusaetzlich wird geprueft, dass gar nichts korrigiert wurde.",
         obj={"envelopes": [env_alt, env_fremd]}, input_name="chain.json")

# 17 — Gegenprobe: ein ueberholter Vorgaenger, der nicht mehr vorliegt, bricht die Kette
schreibe("agent-review-counter-proof-a-superseded-predecessor-must-still-be-present", "counter_proof",
         "F15", {"chainIntegrity": False},
         "Verschwindet der ueberholte Beleg, ist die Korrektur nicht mehr nachvollziehbar: der "
         "Leser sieht nur noch die neue Fassung und kann nicht pruefen, WAS korrigiert wurde. "
         "Jedes einzelne Stueck bleibt dabei kryptografisch gueltig — die Kette ist trotzdem "
         "kaputt, und das ist die Aussage, die `integrity_ok` traegt und `crypto_ok` nicht.",
         obj={"envelopes": [env_neu]}, input_name="chain.json")

(ROOT / "publickey.hex").write_text(pk.hex() + "\n", encoding="utf-8")
print(f"{len(list(ROOT.glob('*/case.json')))} Vektoren geschrieben nach {ROOT}")

# ══ v0.2 ════════════════════════════════════════════════════════════════════════════════════════
# Teil A5 des Auftrags QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01. Diese sechs Vektoren waren zuerst
# VON HAND angelegt — der Riegel `tests/test_korpus_stammt_aus_seinem_generator.py` hat das gefangen
# und zu Recht: ein Fall, den kein Generator erzeugt, ist nicht reproduzierbar, und der Korpus
# behauptet dann eine Herkunft, die er nicht hat. Jeder Fall unten ist die GRUNDFORM plus GENAU EINE
# benannte Mutation; die Mutation steht sichtbar da, statt in einer abgelegten Datei zu verschwinden.
V02_BASE = {
    "coverage": {"knownGaps": ["nur eine Datei gelesen"], "status": "PARTIAL"},
    "declaration": {
        "authoring": [{"assertedBy": "x", "assurance": "selfDeclared"}],
        "findings": [], "findingsTotal": 0, "nonClaims": ["n"], "reviewRuns": [],
    },
    "limitationCodes": ["COVERAGE_PARTIAL", "CURRENTNESS_UNKNOWN", "IDENTITY_UNBOUND",
                        "NOT_QUALITY_ATTESTATION", "TIME_SELF_DECLARED"],
    "limitations": ["selbsterklaert, nicht unabhaengig bezeugt"],
    "reviewId": "ar-v02-konformitaet",
    "schemaVersion": "0.1.0",
    "subjectContext": {
        "baseSha": "b" * 40,
        "bodyCoreDigest": "d" * 64,
        "disclosureCoreDigest": "e" * 64,
        "forge": "github", "headSha": "a" * 40,
        "kind": "githubPullRequest",
        "pullRequestNodeId": "P", "repositoryId": "R",
        "reviewedDiffDigest": "c" * 64,
    },
    "times": {"declaredAt": "2026-09-04T00:00:00Z", "observedAt": None,
              "signedAt": "2026-09-04T00:00:00Z"},
}
_V02_ATTR = ("agent-review/v0.2 — gebaut 04.09.2026 zu Teil A5 des Auftrags "
             "QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01.")

def _v02(**mutation):
    """Grundform plus benannte Mutation. `None` als Wert ENTFERNT den Schluessel — ein fehlendes
    Feld ist eine andere Aussage als ein leeres, und mehrere dieser Gegenproben pruefen genau das."""
    p = copy.deepcopy(V02_BASE)
    for pfad, wert in mutation.items():
        ziel, *rest = pfad.split("__")
        if rest:
            if wert is None: p[ziel].pop(rest[0], None)
            else: p[ziel][rest[0]] = wert
        elif wert is None: p.pop(ziel, None)
        else: p[ziel] = wert
    return p

def _mit_fund(fix_commit):
    f = [{"disposition": "fixed", "fixCommit": fix_commit, "id": "F1", "severity": "low", "title": "t"}]
    return _v02(declaration__findings=f, declaration__findingsTotal=1,
                declaration__findingsRoot=AR.findings_root(f))

schreibe("agent-review-v02-positive-control-emitter-default-is-v02", "positive_control", "A1",
         {"classification": "valid"},
         "Die Vorgabe des Emitters ist v0.2 (A1). Faellt dieser Vektor, hat sich die Vorgabe "
         "gedreht oder die v0.2-Form geaendert — beides ist ein Bruch, den jede der vier "
         "Gegenproben unten unlesbar machen wuerde, weil sie alle auf dieser Grundform stehen.",
         obj=V02_BASE, input_name="predicate.json", attribution=_V02_ATTR, predicate_version="v0.2",
         spec_refs=["Auftrag QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01, Teil A1"])

schreibe("agent-review-v02-counter-proof-coverage-partial-must-name-its-gap", "counter_proof",
         "A5/A3", {"classification": "refused"},
         "PARTIAL ohne knownGaps wird ABGELEHNT: eine unvollstaendige Abdeckung, die keine Luecke "
         "nennt, ist keine Angabe, sondern das Wort 'unvollstaendig'. Eine relying party kann "
         "daraus nicht ableiten, WAS ungeprueft blieb — und genau das ist die einzige Information, "
         "die ein PARTIAL ueberhaupt traegt.",
         obj=_v02(coverage={"status": "PARTIAL"}), input_name="predicate.json",
         attribution=_V02_ATTR, predicate_version="v0.2", spec_refs=["Auftrag QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01, Teil A3/A5"])

schreibe("agent-review-v02-counter-proof-disclosure-core-digest-is-required", "counter_proof",
         "A5/P0.2", {"classification": "refused"},
         "Ohne disclosureCoreDigest ist der sichtbare Offenlegungsblock unverbindlich: eine "
         "Aenderung von selfDeclared auf independent im PR-Text bliebe unbemerkt, weil der Beleg "
         "den Text nicht bindet. Der Digest ist die Bindung — fehlt er, beweist das Receipt etwas "
         "ueber ein Predicate und nichts ueber das, was ein Mensch liest.",
         obj=_v02(subjectContext__disclosureCoreDigest=None), input_name="predicate.json",
         attribution=_V02_ATTR, predicate_version="v0.2", spec_refs=["Gegenlesung Runde 2, P0.2"])

schreibe("agent-review-v02-counter-proof-limitation-codes-are-required", "counter_proof",
         "A5/P0.4.6", {"classification": "refused"},
         "v0.2 verlangt limitationCodes. Ohne sie kann eine relying party den Beleg nicht gegen "
         "eine Policy halten, ohne ihn zu LESEN — und Prosa maschinell auszuwerten heisst, die "
         "Einschraenkung zu raten. Die Codes sind der maschinenlesbare Teil; `limitations` bleibt "
         "die menschenlesbare Begleitung, nie ihr Ersatz.",
         obj=_v02(limitationCodes=None), input_name="predicate.json",
         attribution=_V02_ATTR, predicate_version="v0.2", spec_refs=["Gegenlesung Runde 2, P0.4.6"])

schreibe("agent-review-v02-counter-proof-fixcommit-must-be-the-full-sha", "counter_proof", "A4",
         {"classification": "refused"},
         "Ein gekuerzter fixCommit wird ABGELEHNT (A4). Sieben Zeichen sind eine Suchanfrage, keine "
         "Angabe: sie binden nichts, solange nicht feststeht, in welchem Repository und zu welchem "
         "Zeitpunkt sie eindeutig waren. Der Beleg soll ohne Rueckfrage lesbar sein.",
         obj=_mit_fund("a1b2c3d"), input_name="predicate.json",
         attribution=_V02_ATTR, predicate_version="v0.2", spec_refs=["Auftrag QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01, Teil A4"])

schreibe("agent-review-v02-positive-control-fixcommit-full-sha-is-accepted", "positive_control", "A4",
         {"classification": "valid"},
         "DIE GEGENRICHTUNG zu A4. Ohne sie waere die Regel nur eine Sperre, und ein Validator, der "
         "JEDEN fixCommit ablehnt, bestuende die Gegenprobe daruber ebenfalls. Erst das Paar zeigt, "
         "dass die Regel die LAENGE prueft und nicht das Vorhandensein des Feldes.",
         obj=_mit_fund("f" * 40), input_name="predicate.json",
         attribution=_V02_ATTR, predicate_version="v0.2", spec_refs=["Auftrag QITEM-PB-AGENT-REVIEW-V02-RELEASE-600-01, Teil A4"])
