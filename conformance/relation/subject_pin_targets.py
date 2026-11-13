"""Rebuilds the attached targets of relation/target-subject-ambiguous and relation/target-subject-missing.

WHY (deep gate 6.6.0 at d8881edc, finding Z4): since 6.6.0 an attached `--with-related` receipt counts as verified only
when its predicate passes the structure check of its own type. Both cases attached a target whose decision predicate
was a skeleton (`note` and `schemaVersion` only), written when the attachment reader did not look at the predicate.
Under the new rule that skeleton alone made the target malformed, so the ambiguous case no longer reached the
subject pin it exists for, and the missing case reached its expected code for a second reason. The targets now carry
a valid decision predicate, the parent's own predicate without `relationships` and with its own `decisionId`, so each
case tests its subject axis and nothing else: two subjects (ambiguous) and none (missing). The subjects, the declared
`targetSubjectDigest` pins and every expectation in `case.json` stay as they were.

THE KEY is a fixed test key, the SHA-256 of a label below written out as its seed, not a secret, so the files can be
rebuilt byte for byte; the earlier throwaway key was not kept. Parent and target share it, as before. Run from the
repository root:

    PYTHONPATH=src python conformance/relation/subject_pin_targets.py
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import anchors, dsse
from proofbundle.decision import DECISION_RECEIPT_PREDICATE_TYPE, emit_decision_receipt, validate_decision_predicate

HIER = Path(__file__).resolve().parent
INTOTO = "application/vnd.in-toto+json"
#: The seed is written out, so this shipped tool loads no key material from outside it: the sdist guard in
#: tests/test_sdist_ohne_signierwerkzeug.py exempts only a seed spelled out in the source. It is the SHA-256 of
#: ETIKETT, which the check below holds, so the key and the files it signed stay the same.
ETIKETT = b"proofbundle conformance relation target-subject-pin test key"
SAAT = (b"\xb4\xb3\x4f\x24\x35\x46\x6c\x66\x8f\xa6\xd0\x91\x35\xe5\xfb\x90"
        b"\x12\x27\x5c\x22\x39\x12\x64\x5d\x33\xeb\xb9\xda\x0b\x57\x94\x32")
SCHLUESSEL = Ed25519PrivateKey.from_private_bytes(SAAT)
SUBJEKTE = {
    "target-subject-ambiguous": [{"digest": {"sha256": "a" * 64}, "name": "s1"},
                                 {"digest": {"sha256": "b" * 64}, "name": "s2"}],
    "target-subject-missing": [],
}


def _schreibe_json(pfad: Path, wert, einrueckung: int) -> None:
    pfad.write_text(json.dumps(wert, indent=einrueckung, ensure_ascii=False) + "\n", encoding="utf-8")


def baue(fall: str) -> None:
    if hashlib.sha256(ETIKETT).digest() != SAAT:
        raise SystemExit("the written-out seed is not the SHA-256 of ETIKETT")
    ordner = HIER / fall
    eltern = json.loads(dsse.load_payload(json.loads((ordner / "receipt.json").read_text(encoding="utf-8"))))
    praedikat = copy.deepcopy(eltern["predicate"])
    ziel = {k: v for k, v in copy.deepcopy(praedikat).items() if k != "relationships"}
    ziel["decisionId"] = "d-target-" + fall.removeprefix("target-")
    fehler = validate_decision_predicate(ziel, strict=False)
    if fehler:
        raise SystemExit(f"{fall}: the target predicate is not valid: {fehler}")
    aussage = {"_type": "https://in-toto.io/Statement/v1", "subject": SUBJEKTE[fall],
               "predicateType": DECISION_RECEIPT_PREDICATE_TYPE, "predicate": ziel}
    koerper = rfc8785.dumps(aussage)
    ziel_umschlag = dsse.sign_envelope(koerper, SCHLUESSEL, payload_type=INTOTO)
    wurzel = anchors.statement_content_root(koerper).hex()
    (kante,) = praedikat["relationships"]
    kante["targetReceiptDigest"]["digest"] = wurzel
    eltern_umschlag = emit_decision_receipt(praedikat, SCHLUESSEL, strict=False)
    pub = base64.b64encode(SCHLUESSEL.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")
    _schreibe_json(ordner / "related_r0.json", ziel_umschlag, 1)
    _schreibe_json(ordner / "receipt.json", eltern_umschlag, 1)
    (ordner / "pub.b64").write_text(pub, encoding="ascii")
    fallbeschreibung = json.loads((ordner / "case.json").read_text(encoding="utf-8"))
    fallbeschreibung["relatedPubs"] = [pub]
    _schreibe_json(ordner / "case.json", fallbeschreibung, 2)
    print(fall, "target content root", wurzel)


if __name__ == "__main__":
    for fall in sys.argv[1:] or sorted(SUBJEKTE):
        baue(fall)
