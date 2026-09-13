"""ABSENT and REJECTED are different states, and a gate must decide on a field, never on prose.

THE CLASS (deep gate 2026-09-05, finding L5-G6-01, P2). C12.1 narrows "no receipt binds this tree" to
NOT_APPLICABLE on a pull request — a receipt binds a TREE, and a work branch's tree stops existing at
the merge (owner decision 2026-08-30, card OA-4a8daddb55). That narrowing read its condition off a
SUBSTRING of the gate's prose reason:

    if _laeuft_auf_pull_request() and "no valid pre-tag audit RECEIPT" in (r.get("reason") or ""):

and that sentence opens the reason for BOTH absence and rejection. Measured on HEAD 049b3195 with
GITHUB_EVENT_NAME=pull_request and a receipt planted under audit_artifacts/600/:

    untrusted signer          -> C12.1 NOT_APPLICABLE_BEFORE_TAG   (gate itself: ok=False, rejected)
    tampered signature        -> C12.1 NOT_APPLICABLE_BEFORE_TAG
    copied v5.0.0 receipt     -> C12.1 NOT_APPLICABLE_BEFORE_TAG
    unreadable JSON           -> C12.1 NOT_APPLICABLE_BEFORE_TAG   (candidate silently skipped)

Four known-bad artefacts inherited the leniency built for absence, and the whole matrix exited 0.

THE PROPERTY: the gate reports a typed ``state`` in {absent, rejected, verified, not_determinable};
C12.1 narrows ONLY on ``absent``; an unreadable candidate is ``rejected``, never invisible. The prose is
for readers and may be reworded without touching a verdict.

This file REPLACES the source-text assertion the finding names as a vacuous seam
(``'"no valid pre-tag audit RECEIPT" in' in quelle``): a test that greps the implementation for the
string it is supposed to have stopped using cannot notice when the string is right and the BEHAVIOUR
is wrong. What is asserted here is behaviour, over all four rejected shapes.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import sys
import subprocess
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, REPO / rel)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tree(version: str = "6.0.0", anker: str | None = None) -> pathlib.Path:
    """Ein MESSBARER Baum: ein echtes git-Repo mit einem Commit, nicht nur ein Ordner.

    WARUM DAS SEIT 2026-09-07 NOETIG IST, und es ist eine Entwertung, die ICH verursacht habe.
    `verify_receipt` weist seit `1d124e0` jede ERWARTETE Digest-Angabe ab, die keine sha256-Form hat
    — der Riegel gegen den bindbaren Ersatzwert. In einem Ordner OHNE git kann das Tor den Baum
    nicht messen, setzt `"unknown"` ein, und diese Formpruefung zuendet dann VOR Schema, Version und
    Bindung. Gemessen von einer Gegenlesung: der Fall `wrong_version` starb danach am Formgrund
    statt am Versionsvergleich, und mit stillgelegtem Versionsvergleich blieb dieselbe Testmethode
    GRUEN — sie war fuer die entfernte Pruefung blind geworden.

    Die Zusicherung dieser Datei (der Zustand ist `rejected`, nicht `absent`) galt weiterhin; die
    UNTERSCHEIDUNGSKRAFT der einzelnen Formen war weg. Ein Riegel, dessen Faelle alle aus demselben
    Grund rot sind, prueft eine Form, nicht vier. Ein echtes Repo stellt den Zustand von vorher her,
    ohne die Formpruefung aufzuweichen.
    """
    d = pathlib.Path(tempfile.mkdtemp(prefix="l5g601_"))
    (d / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    if anker is not None:
        (d / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (d / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(anker + "\n",
                                                                          encoding="utf-8")
    for args in (["init", "-q"], ["add", "-A"],
                 ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "basis"]):
        subprocess.run(["git", "-C", str(d), *args], check=True, capture_output=True, timeout=60)
    return d


def _plant(repo: pathlib.Path, token: str, name: str, content: str) -> None:
    scoped = repo / "audit_artifacts" / token
    scoped.mkdir(parents=True, exist_ok=True)
    (scoped / name).write_text(content, encoding="utf-8")


def _keypaar():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, base64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _signed_receipt(priv=None, **over) -> str:
    """Eine formal gueltige, signierte Quittung. OHNE `priv` ein frischer Schluessel (die
    'untrusted signer'-Form); MIT `priv` der Schluessel, den der Baum als Anker fuehrt — dann faellt
    die Quittung an der Eigenschaft, die der Fall im Namen traegt, und an keiner davor."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes
    if priv is None:
        priv = Ed25519PrivateKey.generate()
    rc = {"schema": RECEIPT_SCHEMA, "version": "6.0.0", "subject_tree_digest": "x" * 64,
          "gate_source_digest": "y" * 64, "audit_command": "pytest", "audit_exit_code": 0,
          "audit_output_digest": "z" * 64, "runner_identity": "test",
          "produced_at": "2026-09-05T00:00:00Z"}
    rc.update(over)
    rc["signer_pubkey"] = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    rc["signature"] = base64.b64encode(priv.sign(canonical_bytes(rc))).decode()
    return json.dumps(rc)


class TheGateReportsATypedState(unittest.TestCase):
    def setUp(self):
        self.pta = _load("pta_l5g601", "scripts/pre_tag_audit_gate.py")
        self.addCleanup(lambda: sys.modules.pop("pta_l5g601", None))

    def test_absent_is_absent(self):
        d = _tree()
        r = self.pta.evaluate(d, "6.0.0")
        self.assertEqual(r["state"], "absent", r)
        self.assertFalse(r["ok"])

    def test_every_rejected_shape_reports_rejected(self):
        """The four shapes the gate measured as NOT_APPLICABLE. Each must now be `rejected` — UND JEDE
        AUS IHREM EIGENEN GRUND.

        DIE ZWEITE ZUSICHERUNG IST NEU (2026-09-07) und sie repariert eine Blindheit, die aelter ist
        als der Anlass, aus dem sie gefunden wurde. Gemessen: mit stillgelegtem Versionsvergleich,
        stillgelegtem Schema-Vergleich und stillgelegter Vertrauensanker-Pruefung blieb diese Methode
        DREIMAL gruen — `assertEqual(state, "rejected")` ist erfuellt, sobald IRGENDEINE Pruefung
        zuschlaegt, und in einem Baum ohne Anker schlug immer dieselbe zuerst zu. Vier Faelle, ein
        Grund: der Riegel prueft eine Form, nicht vier.

        Damit jeder Fall an SEINER Eigenschaft faellt, fuehrt der Baum jetzt den Vertrauensanker, und
        die Quittung von `wrong_version` ist mit genau diesem Schluessel signiert. Ohne das kaeme sie
        nie bis zum Versionsvergleich.
        """
        import hashlib

        from pre_tag_receipt_lib import subject_tree_digest
        priv, pub = _keypaar()
        # Reihenfolge in `verify_receipt`: Form -> Schema -> Version -> Baum -> Gate-Quelle ->
        # audit_exit -> Anker -> Signierer -> Signatur. Damit ein Fall an SEINER Eigenschaft faellt,
        # muss alles DAVOR stimmen. `untrusted_signer` braucht deshalb den echten Baum- und
        # Gate-Digest; `wrong_version` nicht, weil die Version vor beiden geprueft wird.
        gate_src = hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()
        shapes = {
            "unreadable_json": ("{ this is not json", "unreadable", None, False),
            "not_an_object": ("[1, 2, 3]", "not a JSON object", None, False),
            "untrusted_signer": (None, "not in the trusted set", pub, True),
            "wrong_version": (None, "version", pub, False),
            # FUENFTER FALL, nachgetragen 2026-09-07: ohne ihn ueberlebt die Mutation, die die
            # Vertrauensanker-Pruefung ganz stilllegt — gemessen. `untrusted_signer` faellt am
            # SIGNIERER, und der wird NACH dem Anker geprueft; ein Baum mit Anker erreicht die
            # Ankerpruefung also nie im Fehlerfall. Der Fall ohne Anker schliesst die Luecke.
            "kein_vertrauensanker": (None, "no trusted signing key pinned", None, True),
        }
        for label, (content, grundstueck, anker, echte_digests) in shapes.items():
            with self.subTest(shape=label):
                d = _tree(anker=anker)
                if content is None:
                    ueber = {"version": "5.0.0"} if label == "wrong_version" else {}
                    if echte_digests:
                        ueber["subject_tree_digest"] = subject_tree_digest(d)
                        ueber["gate_source_digest"] = gate_src
                    # untrusted_signer: FREMDER Schluessel bei gesetztem Anker; wrong_version: der
                    # Ankerschluessel selbst, damit die Version der erste Fehlschlag ist.
                    content = _signed_receipt(None if echte_digests else priv, **ueber)
                _plant(d, "600", "receipt.json", content)
                r = self.pta.evaluate(d, "6.0.0")
                self.assertEqual(r["state"], "rejected",
                                 f"{label}: state={r['state']!r} — a known-bad artefact reads as absence")
                self.assertFalse(r["ok"])
                self.assertTrue(r["rejected_receipts"],
                                f"{label}: the candidate was skipped instead of rejected")
                gruende = " | ".join(x.get("reason", "") for x in r["rejected_receipts"])
                self.assertIn(grundstueck, gruende,
                              f"{label}: abgelehnt, aber NICHT an der eigenen Eigenschaft — "
                              f"erwartet ein Grund mit {grundstueck!r}, bekommen: {gruende[:200]}")

    def test_an_unreadable_candidate_is_named_not_skipped(self):
        """The specific hole: `continue` past an unparseable file left `rejected_receipts` EMPTY, so the
        prose fell back to the absence wording word for word."""
        d = _tree()
        _plant(d, "600", "receipt.json", "{ this is not json")
        r = self.pta.evaluate(d, "6.0.0")
        self.assertEqual(len(r["rejected_receipts"]), 1, r)
        self.assertIn("unreadable", r["rejected_receipts"][0]["reason"].lower())

    def test_an_unreadable_version_is_its_own_state(self):
        """Three states, and the third is not a pass: without a version the gate does not know what it
        is judging, and `not_determinable` must never inherit the absence leniency."""
        d = pathlib.Path(tempfile.mkdtemp(prefix="l5g601_nov_"))
        r = self.pta.evaluate(d)
        self.assertEqual(r["state"], "not_determinable", r)
        self.assertFalse(r["ok"])


class C121NarrowsOnlyOnAbsence(unittest.TestCase):
    """The DECISION RULE itself, over the full state x event matrix — the table the substring hid."""

    def setUp(self):
        self.acm = _load("acm_l5g601", "scripts/audit_candidate_matrix.py")
        self.addCleanup(lambda: sys.modules.pop("acm_l5g601", None))
        self._old_event = os.environ.get("GITHUB_EVENT_NAME")

        class _FakeGate:
            verdict: dict = {}

            @staticmethod
            def evaluate(_repo, version=None):  # noqa: ARG004
                return _FakeGate.verdict
        self.fake = _FakeGate
        sys.modules["pre_tag_audit_gate"] = _FakeGate
        self.addCleanup(lambda: sys.modules.pop("pre_tag_audit_gate", None))

    def tearDown(self):
        if self._old_event is None:
            os.environ.pop("GITHUB_EVENT_NAME", None)
        else:
            os.environ["GITHUB_EVENT_NAME"] = self._old_event

    def _verdict(self, state: str, ok: bool, event: str | None):
        self.fake.verdict = {
            "ok": ok, "state": state,
            # The prose deliberately keeps the sentence the old rule keyed on, for EVERY state: if the
            # implementation still read the substring, this matrix would go red.
            "reason": ("no valid pre-tag audit RECEIPT binds tree abc + version 6.0.0. "
                       "1 candidate receipt(s) rejected: ['untrusted signer']"),
        }
        if event is None:
            os.environ.pop("GITHUB_EVENT_NAME", None)
        else:
            os.environ["GITHUB_EVENT_NAME"] = event
        return self.acm.c12_1_pretag_audit()

    def test_the_full_state_by_event_matrix(self):
        na, fail, pas = self.acm.NOT_APPLICABLE, self.acm.FAIL, self.acm.PASS
        cases = [
            # (state, ok, event, expected verdict)
            ("absent", False, "pull_request", na),
            ("absent", False, "pull_request_target", na),
            ("absent", False, None, fail),
            ("absent", False, "push", fail),
            ("rejected", False, "pull_request", fail),      # THE FINDING
            ("rejected", False, "push", fail),
            ("not_determinable", False, "pull_request", fail),
            ("verified", True, "pull_request", pas),
            ("verified", True, None, pas),
        ]
        for state, ok, event, expected in cases:
            with self.subTest(state=state, event=event):
                verdict, detail = self._verdict(state, ok, event)
                self.assertEqual(verdict, expected,
                                 f"state={state} event={event}: got {verdict} ({detail[:90]})")

    def test_a_gate_without_the_state_field_fails_closed(self):
        """An older/foreign gate object carries no `state`. Missing is not absent: FAIL."""
        self.fake.verdict = {"ok": False, "reason": "no valid pre-tag audit RECEIPT binds tree abc"}
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        verdict, _detail = self.acm.c12_1_pretag_audit()
        self.assertEqual(verdict, self.acm.FAIL)

    def test_META_the_prose_rule_would_fail_this_matrix(self):
        """PLANT-AND-MUST-CATCH, stated as a fact about the fixture rather than by editing the source:
        every verdict above carries the same prose sentence, so a substring rule cannot distinguish the
        rows — it would return NOT_APPLICABLE for the four rejected ones and the matrix would be red."""
        self.fake.verdict = {"ok": False, "state": "rejected",
                             "reason": "no valid pre-tag audit RECEIPT binds tree abc"}
        os.environ["GITHUB_EVENT_NAME"] = "pull_request"
        verdict, _ = self.acm.c12_1_pretag_audit()
        self.assertEqual(verdict, self.acm.FAIL,
                         "the substring is present and the state says rejected — a prose rule reads "
                         "NOT_APPLICABLE here, and that is the defect")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
