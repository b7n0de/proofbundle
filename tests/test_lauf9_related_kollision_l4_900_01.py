"""L4-900-01 (P0, deep gate Lauf 9): der Aufloeser darf eine Kollision nicht still ueberschreiben.

DER DEFEKT, gemessen am Kopf 8626618f33bd: `cli._load_related` legte angehaengte Ziele unter dem
content root ihres SIGNIERTEN PAYLOADS ab — ein Schluessel, der aus dem angehaengten Material
ABGELEITET ist — und der Wert traegt ein Verifikationsurteil. Zwei Anhaenge mit demselben Payload
und verschiedenen Umschlaegen kollidierten, und die zuletzt gelesene Kopie ersetzte die fruehere.

WIRKUNG: eine angehaengte Kopie mit VERFAELSCHTER SIGNATUR loeschte eine gueltige, verifizierte
Ruecknahme. `decision verify --with-related good.json` endete mit exit 3 und
safeForAutomation=False; dieselbe Aufrufung mit zusaetzlich `--with-related bad.json` endete mit
exit 0, safeForAutomation=TRUE und lineage.supersededByAttached=None. Wer eine Datei ANHAENGEN
kann, hob damit eine Ruecknahme auf, ohne einen einzigen Schluessel zu brechen.

DIE EIGENSCHAFT, die hier gehalten wird, ist REIHENFOLGEUNABHAENGIGKEIT: fuer jede Permutation der
angehaengten Pfade ist das Urteil dasselbe. Ein Duplikat, das im Verifikationsergebnis
widerspricht, wird GENANNT statt still aufgeloest.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def _fall(tmp: Path):
    from proofbundle import anchors, dsse
    from proofbundle.decision import emit_decision_receipt
    from proofbundle.emit import generate_signer
    from proofbundle.relation_statement import emit_relation_statement

    sk = generate_signer()
    pub = base64.b64encode(sk.public_key().public_bytes_raw()).decode()
    basis = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    env_dec = emit_decision_receipt({**basis, "decisionId": "d-l4-900"}, sk, strict=True)
    root = anchors.statement_content_root(dsse.load_payload(env_dec)).hex()
    (tmp / "d.json").write_text(json.dumps(env_dec), encoding="utf-8")
    env_r = emit_relation_statement({
        "schemaVersion": "0.1.0", "statementId": "urn:uuid:r-l4-900",
        "relationships": [{"relation": "retracts",
                           "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                                                   "digest": root}}]}, sk)
    (tmp / "good.json").write_text(json.dumps(env_r), encoding="utf-8")
    (tmp / "good2.json").write_text(json.dumps(env_r), encoding="utf-8")
    kaputt = json.loads(json.dumps(env_r))
    roh = bytearray(base64.b64decode(kaputt["signatures"][0]["sig"]))
    roh[0] ^= 0xFF
    kaputt["signatures"][0]["sig"] = base64.b64encode(bytes(roh)).decode()
    (tmp / "bad.json").write_text(json.dumps(kaputt), encoding="utf-8")
    (tmp / "p.json").write_text(json.dumps({
        "schema": "proofbundle/trust-policy/v0.2", "policy_id": "l4-900",
        "policyPurpose": "decision", "relations": {"reject_superseded": True},
        "decision_receipt": {"trusted_decision_makers": [
            {"id": "https://example.org/decision-platform/proofbundle-gate/v1",
             "public_key_b64": pub}]}}), encoding="utf-8")
    return pub


def _lauf(tmp: Path, pub: str, anhaenge: list[str]):
    cmd = [sys.executable, "-m", "proofbundle.cli", "decision", "verify", str(tmp / "d.json"),
           "--pub", pub, "--policy", str(tmp / "p.json"), "--json"]
    for a in anhaenge:
        cmd += ["--with-related", str(tmp / a)]
    r = subprocess.run(cmd, capture_output=True, text=True,
                       env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin"})
    try:
        return r.returncode, json.loads(r.stdout), r.stderr
    except ValueError:
        return r.returncode, None, r.stderr


class KollisionUeberschreibtNichtStill(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = Path(tempfile.mkdtemp(prefix="l4_900_01_"))
        self.pub = _fall(self.tmp)

    def test_die_echte_ruecknahme_blockt(self):
        """Ausgangslage: OHNE Anhang-Duplikat blockt die Ruecknahme. Ohne diese Zeile misst der
        Test nur, dass irgendetwas nicht durchgeht."""
        rc, j, _ = _lauf(self.tmp, self.pub, ["good.json"])
        self.assertEqual(rc, 3)
        self.assertFalse(j["automation"]["safeForAutomation"])
        self.assertIsNotNone(j["lineage"].get("supersededByAttached"))

    def test_kaputte_kopie_loescht_die_ruecknahme_nicht(self):
        """DER DEFEKT: vor dem Fix exit 0 und safeForAutomation TRUE."""
        rc, j, err = _lauf(self.tmp, self.pub, ["good.json", "bad.json"])
        self.assertNotEqual(rc, 0, "eine kaputte Kopie darf die Ruecknahme nicht aufheben")
        if j is not None:
            self.assertFalse(j["automation"]["safeForAutomation"])
        else:
            self.assertIn("content root", err)

    def test_reihenfolgeunabhaengig(self):
        """Die EIGENSCHAFT: jede Permutation ergibt dasselbe Urteil."""
        rc_a, _, _ = _lauf(self.tmp, self.pub, ["good.json", "bad.json"])
        rc_b, _, _ = _lauf(self.tmp, self.pub, ["bad.json", "good.json"])
        self.assertEqual(rc_a, rc_b, "das Urteil haengt an der Reihenfolge der Anhaenge")

    def test_gegenrichtung_identische_kopien_bleiben_gueltig(self):
        """Zweimal dieselbe gueltige Datei anzuhaengen ist harmlos und muss weiter blocken —
        sonst waere der Fix ein Denial statt einer Haertung."""
        rc, j, _ = _lauf(self.tmp, self.pub, ["good.json", "good2.json"])
        self.assertEqual(rc, 3)
        self.assertIsNotNone(j["lineage"].get("supersededByAttached"))

    def test_gegenrichtung_ohne_anhang_unveraendert(self):
        """Ganz ohne Anhang bleibt alles wie vorher. `lineage` ist dann GAR NICHT da (None) —
        gemessen, nicht angenommen: der erste Entwurf dieses Tests griff blind auf j["lineage"]
        zu und starb an einem AttributeError, den ich zuerst dem Produktivcode zuschrieb."""
        rc, j, _ = _lauf(self.tmp, self.pub, [])
        self.assertEqual(rc, 0)
        self.assertIsNone((j.get("lineage") or {}).get("supersededByAttached"))


if __name__ == "__main__":
    unittest.main()
