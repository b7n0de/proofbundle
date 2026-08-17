#!/usr/bin/env python3
"""Der Vor-Tag-Audit-Eintrag als SIGNIERTE Attestierung — Prüferseite (ADR 0008).

WARUM. `pre_tag_audit_gate.py` beantwortet "lief der adversariale Audit für DIESES Release" durch
eine Textsuche in Repo-Dateien. Am 2026-08-16 hat eine **Dokumentations-Bearbeitung** das Tor
erfüllt: ein Messbericht zitierte zwei Sätze, die das Tor als Attestierung liest, und die Suite
meldete daraufhin grün — für ein Release ohne Audit-Eintrag. Die Antwort darauf ist nicht das
nächste Wort in einer Verneinungsliste (eine Sperrliste über einem offenen Alphabet, CWE-184),
sondern eine andere ART von Beleg: eine Signatur kann eine Doku-Bearbeitung nicht erzeugen.

WAS HIER IST UND WAS NICHT. Dies ist die **Prüferseite** und bewusst nur sie. Der Schritt, der die
Attestierung in CI ausstellt, ändert `release.yml` — den Publish-Pfad des Owners und damit eine
Einbahntür. ADR 0008: erst der Prüfer, dann die Workflow-Änderung als gegengelesener Diff gegen
einen bereits bestehenden Prüfer.

ZWEI VERTRAUENSDOMÄNEN, GETRENNT (ADR 0008). Der öffentliche CI-Weg ist Sigstore/keyless über
`actions/attest` — dort ist GitHub ohnehin die Wurzel, weil es baut und veröffentlicht. Dieser
Prüfer hier ist der **offline, abhängigkeitsfreie** Weg: eine DSSE-Hülle über einer in-toto-Aussage,
verifiziert mit proofbundles EIGENEN Primitiven. Kein Netz, kein neues Paket — und damit das
stärkste Dogfood, das dieses Projekt haben kann: sein Release-Tor wird von ihm selbst geprüft.

DIE FORM FOLGT VSA, DER TYP NICHT. SLSA definiert die Verification Summary Attestation
(`https://slsa.dev/verification_summary/v1`) für genau diese Aussageform — Prüfer, Zeit, Politik,
Ergebnis. Ihre Felder und ihre Anleitung sind aber über SLSA-STUFEN definiert; für Urteile außerhalb
dieses Rahmens gibt sie keine. Ihren Typ zu benutzen hieße, die Autorität eines Standards für eine
Aussage zu borgen, die er nicht definiert. in-toto sieht eigene Prädikat-Typen ausdrücklich vor.

EHRLICHE GRENZE, die mitfährt: eine Signatur bindet Identität, Zeit und Gegenstand an eine Aussage.
Ob die Aussage WAHR ist, bleibt eine Frage an den Prozess, der sie erzeugt hat — dieselbe Grenze,
die PR #139 über seine Zeile ausspricht. Dieser Prüfer macht einen Eintrag fälschungssicher, nicht
richtig.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

PREDICATE_TYPE = "https://b7n0de.com/attestation/pre-tag-audit/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Der Gegenstand ist der COMMIT, nicht das Rad: der Audit läuft VOR dem Tag, das Rad gibt es dann
# noch nicht. Die Build-Provenance deckt das Rad weiterhin — zwei Gegenstände, zwei Attestierungen.
SUBJECT_DIGEST_KEY = "gitCommit"

_HEX40 = re.compile(r"\A[0-9a-f]{40}\Z")
_SEMVERISH = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*\Z")


def build_statement(*, commit: str, version: str, verifier_id: str, time_verified: str,
                    policy_uri: str, result: str = "PASSED",
                    subject_name: str = "git+https://github.com/b7n0de/proofbundle") -> dict:
    """Die in-toto-Aussage, die signiert wird. Reine Funktion, damit ein Test sie ohne CI baut."""
    if result not in ("PASSED", "FAILED"):
        raise ValueError("result must be PASSED or FAILED (VSA's two-valued shape, deliberately "
                         "no third value: 'partially' would be read as a pass)")
    if not _HEX40.match(commit or ""):
        raise ValueError("commit must be a full 40-hex git commit id — an abbreviated one is "
                         "ambiguous and an attestation must not be")
    if not _SEMVERISH.match(version or ""):
        raise ValueError(f"version {version!r} is not a release version")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {SUBJECT_DIGEST_KEY: commit}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "verifier": {"id": verifier_id},
            "timeVerified": time_verified,
            "policy": {"uri": policy_uri},
            "verificationResult": result,
            "releaseVersion": version,
        },
    }


def sign_statement(statement: dict, signer, *, keyid: "str | None" = None) -> dict:
    """Die Aussage in eine DSSE-Hülle legen — dieselben Primitive wie `export_eval_result_dsse`.

    Bewusst hier und nicht in der Bibliothek: das ist Release-Werkzeug dieses Projekts, keine
    öffentliche Fähigkeit von proofbundle. Die Bibliotheksfläche bleibt unverändert — dieses
    Release hat ihre Ausgabeform schon dreimal erweitert, und jede Erweiterung ist eine Zusage.
    """
    from proofbundle import dsse                                   # noqa: PLC0415
    from proofbundle.intoto import (INTOTO_STATEMENT_PAYLOAD_TYPE,  # noqa: PLC0415
                                    LEGACY_CONTENT_ROOT_ALG, _serialize_statement)

    body = _serialize_statement(statement, LEGACY_CONTENT_ROOT_ALG)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE,
                              keyid=keyid)


def verify(envelope: dict, public_key: bytes, *, expected_version: str,
           expected_commit: str) -> dict:
    """Prüft eine signierte Vor-Tag-Attestierung gegen Version UND Commit.

    FAIL-CLOSED und in EINER Richtung lesbar: `ok` ist nur True, wenn die Signatur verifiziert, der
    Prädikat-Typ exakt der erwartete ist, das Ergebnis PASSED lautet, und Version wie Commit exakt
    stimmen. Jede Teilprüfung steht einzeln im Ergebnis — ein Aufrufer soll unterscheiden können,
    WORAN es lag, ohne den Text zu lesen. Das ist dieselbe Eigenschaft, die dieses Release für
    `--expected-origin` und für `threshold` nachgetragen hat: die Ausgabe berichtet die FRAGE, nicht
    nur die Antwort.

    Die Vergleiche sind EXAKT. Ein Präfix, eine andere Groß-/Kleinschreibung, ein angehängtes
    Zeichen sind ein Fehlschlag — geprüft vom geteilten Beinahe-Treffer-Korpus, nicht bloß gegen
    einen völlig fremden Wert (ein Vergleich, der nur gegen Fremdes getestet ist, kann nicht zeigen,
    dass er exakt ist).
    """
    from proofbundle.intoto import verify_eval_result_dsse   # noqa: PLC0415

    aus: dict = {"ok": False, "signature_ok": False, "predicate_type_ok": False,
                 "result_ok": False, "version_ok": False, "commit_ok": False,
                 "expected_version": expected_version, "expected_commit": expected_commit,
                 "observed_version": None, "observed_commit": None, "observed_result": None,
                 "observed_predicate_type": None, "reason": None}
    try:
        # ZWEI FRAGEN, ZWEI ANTWORTEN. `verify_eval_result_dsse` FALTET die Typpruefung in sein
        # `ok` (gemessen 2026-08-16: fremder Typ -> ok=False, obwohl die Signatur einwandfrei ist).
        # Wer dieses `ok` als `signature_ok` uebernimmt, macht "Signatur kaputt" von "Signatur gut,
        # Typ fremd" ununterscheidbar — genau der Fehlermodus, den dieses Release an zwei anderen
        # Stellen geschlossen hat. Deshalb wird der kryptographische Teil mit
        # `expected_predicate_type=None` erfragt und der Typ danach SELBST verglichen.
        # Gefunden von der eigenen Ruecknahme-Probe: `predicate_type_ok` liess sich aus der
        # Konjunktion entfernen, ohne dass ein Test rot wurde.
        roh = verify_eval_result_dsse(envelope, public_key, expected_predicate_type=None)
    except Exception as exc:                                  # noqa: BLE001
        # Nie ein roher Traceback aus einer fremden Datei — fail-closed mit benanntem Grund.
        aus["reason"] = f"envelope could not be verified: {type(exc).__name__}: {exc}"
        return aus
    aus["signature_ok"] = bool(roh.get("ok"))
    aus["observed_predicate_type"] = roh.get("predicate_type")
    aus["predicate_type_ok"] = roh.get("predicate_type") == PREDICATE_TYPE
    stmt = roh.get("statement") or {}
    pred = stmt.get("predicate") or {} if isinstance(stmt, dict) else {}
    if not isinstance(pred, dict):
        pred = {}
    aus["observed_result"] = pred.get("verificationResult")
    aus["observed_version"] = pred.get("releaseVersion")
    subj = stmt.get("subject") if isinstance(stmt, dict) else None
    if isinstance(subj, list) and subj and isinstance(subj[0], dict):
        dig = subj[0].get("digest")
        if isinstance(dig, dict):
            aus["observed_commit"] = dig.get(SUBJECT_DIGEST_KEY)
    aus["result_ok"] = aus["observed_result"] == "PASSED"
    aus["version_ok"] = aus["observed_version"] == expected_version
    aus["commit_ok"] = aus["observed_commit"] == expected_commit
    aus["ok"] = all((aus["signature_ok"], aus["predicate_type_ok"], aus["result_ok"],
                     aus["version_ok"], aus["commit_ok"]))
    if not aus["ok"] and aus["reason"] is None:
        fehlt = [k for k in ("signature_ok", "predicate_type_ok", "result_ok",
                             "version_ok", "commit_ok") if not aus[k]]
        aus["reason"] = "failed: " + ", ".join(fehlt)
    return aus


def main(argv: "list[str] | None" = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--envelope", type=Path, required=True, help="the DSSE envelope (JSON)")
    p.add_argument("--pubkey-hex", required=True, help="the Ed25519 public key, hex")
    p.add_argument("--expected-version", required=True)
    p.add_argument("--expected-commit", required=True, help="full 40-hex commit id")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    try:
        env = json.loads(a.envelope.read_text(encoding="utf-8"))
        pub = bytes.fromhex(a.pubkey_hex)
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    res = verify(env, pub, expected_version=a.expected_version,
                 expected_commit=a.expected_commit)
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        print(f"[pre-tag-attestation] ok={res['ok']}"
              + (f"  ({res['reason']})" if res.get("reason") else ""))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
