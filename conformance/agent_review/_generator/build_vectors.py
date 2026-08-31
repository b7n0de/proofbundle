"""Konformitaets-Vektoren fuer agent-review/v0.1 — nach dem Hausmuster von conformance/envelope_profile."""
import copy
import json
import pathlib
import sys
sys.path.insert(0, "src")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from proofbundle import agent_review as AR

ROOT = pathlib.Path("conformance/agent_review")
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
             input_name, params=None):
    d = ROOT / case_id
    d.mkdir(parents=True, exist_ok=True)
    payload = envelope if envelope is not None else obj
    (d / input_name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (d / "case.json").write_text(json.dumps({
        "caseId": case_id, "kind": "agent_review_predicate", "rule": rule, "role": role,
        "input": input_name,
        "attribution": "agent-review/v0.1 — built 31.08.2026 against the external adversarial read "
                       "(18 findings). Rule ids are that read's finding ids.",
        "expected": expected,
        **({"params": params} if params else {}),
        "specRefs": ["docs/AGENT_REVIEW_PREDICATE.md", "src/proofbundle/agent_review.py"],
        "rationale": rationale,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return d

# 1 — Positivkontrolle
env = AR.emit_agent_review(BASE, sk)
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
env3 = AR.emit_agent_review(p, sk)   # Erzeugen erlaubt: die Root ist dann schlicht falsch
schreibe("agent-review-counter-proof-findings-root-covers-the-list", "counter_proof", "F09",
         {"classification": "invalid"},
         "Removing a finding after the root was taken must be detectable. A receipt that reports "
         "'3 findings, 2 fixed' without a root binding is an aggregate anyone can rewrite.",
         envelope=env3, input_name="envelope.json")

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
env6 = AR.emit_agent_review(p, sk)
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
env11 = AR.emit_agent_review(BASE, sk)
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

(ROOT / "publickey.hex").write_text(pk.hex() + "\n", encoding="utf-8")
print(f"{len(list(ROOT.glob('*/case.json')))} Vektoren geschrieben nach {ROOT}")
