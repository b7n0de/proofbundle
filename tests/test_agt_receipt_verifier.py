"""Conformance for the offline AGT governance-receipt verifier.

THE VECTORS ARE REAL. The five receipts in ``tests/vektoren/agt_receipts/`` were produced by AGT's
OWN signer at commit ``a917ad4ac04aff11a5e9e21f6a26b91642b750cd`` (2026-09-24), from the package
``agent-governance-python/agentmesh-integrations/mcp-receipt-governed`` (MIT, Copyright (c)
Microsoft Corporation), whose own suite runs 81 green. They are not hand-written JSON that happens
to match what we expect, which is the failure mode this file exists to avoid: a verifier tested
only against fixtures made by the same reading it implements proves that the reading is
self-consistent and nothing more.

WHAT THE DIVERGENCE CASE IS FOR. AGT documents its canonicalization as "RFC 8785 JCS canonical
JSON" and implements ``json.dumps(sort_keys=True, …)``. Those disagree on ``timestamp``, which
every receipt carries as a float. A verifier built from the documentation rejects valid receipts.
The case below pins that measurement, so the day AGT switches to real JCS this file goes red and
names the reason instead of the verifier silently starting to fail in the field.
"""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from proofbundle.adapters.agt_receipt import (
    AGT_CANONICAL_FORM,
    AGTReceiptError,
    canonical_payload,
    exit_code,
    payload_hash,
    verify_agt_receipt,
    verify_agt_receipt_chain,
)

VEKTOREN = Path(__file__).resolve().parent / "vektoren" / "agt_receipts"


def lade(name: str) -> dict:
    return json.loads((VEKTOREN / f"{name}.json").read_text(encoding="utf-8"))


class DieFuenfLagen(unittest.TestCase):
    """The five situations the order named: allow, deny, sealed, tampered, wrong key."""

    def test_allow_verifiziert(self):
        e = verify_agt_receipt(lade("01_allow"))
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(e), 0)

    def test_deny_verifiziert(self):
        """A deny receipt is not a failure. It proves the block happened."""
        r = lade("02_deny")
        self.assertEqual(r["cedar_decision"], "deny")
        e = verify_agt_receipt(r)
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])

    def test_extern_autorisiert_mit_vertrauter_liste(self):
        r = lade("03_extern_autorisiert")
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])

    def test_fang_manipuliert_faellt(self):
        """`cedar_decision` was flipped deny→allow AFTER signing. The signature must not hold."""
        e = verify_agt_receipt(lade("04_manipuliert"))
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1, "a broken signature is a crypto failure, not a policy one")
        sig = [c for c in e.checks if c.name == "signature"]
        self.assertEqual(len(sig), 1)
        self.assertIs(sig[0].ok, False)

    def test_fang_falscher_schluessel_faellt(self):
        """Signed with one key, the receipt names another. The verdict must not accept it."""
        e = verify_agt_receipt(lade("05_falscher_schluessel"))
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)


class DieAutorisierungWirdNichtVerschenkt(unittest.TestCase):
    """An external authorization is only accepted against a relying party's own key list."""

    def test_fang_ohne_vertrauensliste_keine_annahme(self):
        """WITHOUT a list the authorization is NOT evaluated — and that is not a pass.

        This is the check that keeps `ok` honest: a caller who forgets the list must not read the
        verdict as "the authorizer was trusted".
        """
        e = verify_agt_receipt(lade("03_extern_autorisiert"))
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 3, "crypto is sound, the relying-party requirement is not met")
        vertraut = [c for c in e.checks if c.name == "external-authorization-trusted"]
        self.assertEqual(len(vertraut), 1)
        self.assertIn("NOT evaluated", vertraut[0].detail)

    def test_fang_fremder_schluessel_nicht_auf_der_liste(self):
        e = verify_agt_receipt(lade("03_extern_autorisiert"), trusted_authorizer_keys=["aa" * 32])
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 3)

    def test_fang_autorisierer_gleich_signierer_wird_abgelehnt(self):
        """A second signature from the SAME key adds no independent party."""
        r = lade("03_extern_autorisiert")
        r["authorizer_public_key"] = r["signer_public_key"]
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["signer_public_key"]])
        self.assertIs(e.ok, False)
        treffer = [c for c in e.checks if c.name == "authorizer-key-distinct"]
        self.assertTrue(treffer and "same key" in treffer[0].detail)

    def test_der_pruefname_behauptet_nicht_mehr_als_er_misst(self):
        """An independent review found the earlier name claiming independence it cannot measure.

        Two distinct keys are two keys, not two organizations: an admin key and a service key of
        the same operator satisfy every check here. AGT's own proposal says the same. The check is
        therefore named for what it measures.
        """
        r = lade("03_extern_autorisiert")
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        namen = {c.name for c in e.checks}
        self.assertIn("authorizer-key-distinct", namen)
        self.assertNotIn("external-authorization", namen,
                         "a bare 'external-authorization' verdict would sound like independence")

    def test_gegenrichtung_eine_wache_die_alles_ablehnt_faellt_hier_auf(self):
        """WITHOUT THIS CASE a verifier that NEVER accepts would pass every catch above."""
        r = lade("03_extern_autorisiert")
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertTrue(e.ok, "a correctly authorized receipt with a trusted key must be accepted")


class DieKanonformIstDieGESIGNTEUndNichtDieDOKUMENTIERTE(unittest.TestCase):
    """The measurement that decides how this verifier reads a receipt at all."""

    def test_die_gesignte_form_ist_sortkeys_json_nicht_rfc8785(self):
        r = lade("01_allow")
        agt = canonical_payload(r)
        self.assertEqual(payload_hash(r), r["payload_hash"],
                         "the receipt's own payload_hash matches the sort_keys form")
        try:
            import rfc8785
        except ImportError:
            self.skipTest("rfc8785 not installed; the divergence cannot be measured here")
        daten = json.loads(agt.decode())
        jcs = rfc8785.dumps(daten)
        self.assertNotEqual(
            agt, jcs,
            "if these ever become equal, AGT switched to real RFC 8785 and this verifier must "
            "follow — that is what this case is here to catch")

    def test_die_benannte_form_steht_im_urteil(self):
        """A verdict that does not name WHICH canonical form it used cannot be checked."""
        e = verify_agt_receipt(lade("01_allow"))
        sig = [c for c in e.checks if c.name == "signature"][0]
        self.assertIn(AGT_CANONICAL_FORM, sig.detail)


class DieKette(unittest.TestCase):

    def test_kette_ueber_die_drei_gueltigen(self):
        r1, r2, r3 = lade("01_allow"), lade("02_deny"), lade("03_extern_autorisiert")
        e = verify_agt_receipt_chain(
            [r1, r2, r3], trusted_authorizer_keys=[r3["authorizer_public_key"]])
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])

    def test_fang_gebrochenes_kettenglied(self):
        r1, r2 = lade("01_allow"), lade("02_deny")
        r2["parent_receipt_hash"] = "00" * 32
        e = verify_agt_receipt_chain([r1, r2])
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)

    def test_fang_leere_kette_ist_kein_sauberes_urteil(self):
        """A measurement over nothing looks exactly like a measurement that found nothing."""
        e = verify_agt_receipt_chain([])
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)


class UnlesbaresIstKeinFehlgeschlagenesPruefen(unittest.TestCase):
    """Malformed input is a NAMED finding with exit 2, not a crash and not a signature failure.

    The first version let the low-level helper raise through the verify surface so the two could be
    told apart. The house type-confusion gate refused that, and it was right: a verifier that
    crashes on a broken document does not judge, and a caller who forgets one `except` reads a
    crash as nothing at all. Both properties are kept instead of traded — `canonical_payload` still
    raises, because it is a helper and a caller asking for bytes must get bytes or an error, while
    the verify surfaces catch it and record `readable`.
    """

    def test_der_helfer_wirft_weiterhin(self):
        with self.assertRaises(AGTReceiptError):
            canonical_payload(["nicht", "ein", "objekt"])
        r = lade("01_allow")
        del r["args_hash"]
        with self.assertRaises(AGTReceiptError):
            canonical_payload(r)

    def test_fang_die_pruefflaeche_wirft_NICHT(self):
        """never-raise at the verify surface, over every shape a caller can hand in."""
        for eingabe in (None, [], ["a"], "text", 7, {}, {"agent_did": "x"}):
            with self.subTest(eingabe=repr(eingabe)[:24]):
                e = verify_agt_receipt(eingabe)          # must not raise
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 2, "unreadable input is exit 2, never 1")
                self.assertEqual(e.checks[0].name, "readable")

    def test_fang_die_kette_bricht_nicht_ab(self):
        """An unreadable link is a finding; the remaining receipts still get a verdict."""
        e = verify_agt_receipt_chain([{"kaputt": True}, lade("01_allow")])
        self.assertIs(e.ok, False)
        namen = [c.name for c in e.checks]
        self.assertTrue(any(n.endswith("chain-link") for n in namen),
                        "the chain must still report the link it could not check")

    def test_gegenrichtung_ein_vollstaendiges_receipt_wirft_nicht(self):
        canonical_payload(lade("01_allow"))


class DasVokabularWirdNichtStillUmgedeutet(unittest.TestCase):
    """The proposal says permit/deny, the implementation says allow/deny. We do not bridge that."""

    def test_fang_permit_wird_nicht_als_allow_gelesen(self):
        r = lade("01_allow")
        r["cedar_decision"] = "permit"
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, False)
        vok = [c for c in e.checks if c.name == "decision-vocabulary"][0]
        self.assertIs(vok.ok, False)
        self.assertIn("permit/deny", vok.detail, "the verdict must NAME why the two disagree")


if __name__ == "__main__":
    unittest.main()


class DieKetteNimmtJedeFormEntgegenOhneTypeError(unittest.TestCase):
    """Found by the house type-confusion gate on this very module, not by reading the code.

    `not receipts` is True for `[]` and for `0` and `False` alike, so a truthy non-sequence such as
    `True` or `-1` slipped past the emptiness check and died on `enumerate` with a bare TypeError.
    The gate measured it: "TypeError on payload True: 'bool' object is not iterable". Checking the
    shape before the emptiness is the fix, and this case pins the order.
    """

    def test_fang_wahrheitswert_und_zahl_werfen_nicht(self):
        for eingabe in (True, -1, 9223372036854775808, "text", {"a": 1}, None):
            with self.subTest(eingabe=repr(eingabe)[:20]):
                e = verify_agt_receipt_chain(eingabe)        # must not raise
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 2)

    def test_gegenrichtung_eine_echte_liste_wird_weiterhin_gepruft(self):
        """WITHOUT THIS CASE a shape check that refuses everything would pass the catch above."""
        r1, r2 = lade("01_allow"), lade("02_deny")
        e = verify_agt_receipt_chain([r1, r2])
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])



class DerKettenpraefixWirdAlsPraefixAbgestreift(unittest.TestCase):
    """An independent review called the earlier `split("] ", 1)[-1]` broken. It was not.

    Measured: with maxsplit=1 that call returns everything after the FIRST "] ", which for
    "[0] weird] name" is "weird] name" — the correct name. The review had read it as taking the
    LAST segment. The residual fragility was real though: an UNPREFIXED name containing "] " would
    still have been cut, so the prefix is now matched as a prefix instead of being inferred from a
    separator that may also occur inside a name.
    """

    def test_fang_ein_unpraefixierter_name_mit_klammer_bleibt_ganz(self):
        from proofbundle.adapters.agt_receipt import _blanker_name
        self.assertEqual(_blanker_name("signature] x"), "signature] x")

    def test_das_kettenpraefix_faellt_weg(self):
        from proofbundle.adapters.agt_receipt import _blanker_name
        self.assertEqual(_blanker_name("[0] chain-link"), "chain-link")
        self.assertEqual(_blanker_name("[12] readable"), "readable")

    def test_gegenrichtung_ein_name_ohne_praefix_bleibt_unveraendert(self):
        """WITHOUT THIS CASE a stripper that removes anything in brackets would pass above."""
        from proofbundle.adapters.agt_receipt import _blanker_name
        self.assertEqual(_blanker_name("signature"), "signature")
        self.assertEqual(_blanker_name("[abc] signature"), "[abc] signature")


class EntfernbareBelegeDuerfenEinUrteilNichtVERBESSERN(unittest.TestCase):
    """Codex on this branch, and it is the most serious finding the verifier has had.

    The authorization fields sit OUTSIDE the signed payload. Setting exactly the three the first
    detector read — authorizer_id, authorization_signature, authorizer_public_key — to null left
    assurance_level="externally_authorized", authorization_expires_at and authorization_nonce
    standing, kept signature and payload hash valid, and turned a receipt this verifier had
    REJECTED into one it ACCEPTED. Measured before the fix: ok=False exit=3 became ok=True exit=0.

    THE CLASS is a partial-shape detector over a field set an attacker can choose from: whichever
    subset the detector does not read is the subset that can be stripped. The fix reads the whole
    set and demands completeness once any member appears.
    """

    def _r(self):
        return json.loads(json.dumps(lade("03_extern_autorisiert")))

    def test_fang_die_drei_felder_des_alten_detektors(self):
        r = self._r()
        for f in ("authorizer_id", "authorization_signature", "authorizer_public_key"):
            r[f] = None
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, False, "stripping evidence must not produce a clean verdict")
        self.assertEqual(exit_code(e), 1, "a stripped authorization is structural, not a policy miss")

    def test_fang_jede_einzelne_luecke(self):
        """THE PROPERTY over the whole field set, not over the three that were reported."""
        for feld in ("authorizer_id", "authorization_signature", "authorizer_public_key",
                     "authorization_expires_at", "authorization_nonce"):
            with self.subTest(feld=feld):
                r = self._r()
                r[feld] = None
                e = verify_agt_receipt(r, trusted_authorizer_keys=[r.get("authorizer_public_key") or "x"])
                self.assertIs(e.ok, False, f"a receipt missing {feld} must not verify")

    def test_fang_assurance_level_allein_verlangt_vollstaendigkeit(self):
        """A receipt CLAIMING external authorization owes one, whatever else was stripped."""
        r = lade("01_allow")
        r["assurance_level"] = "externally_authorized"
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)

    def test_gegenrichtung_die_heile_autorisierung_verifiziert_weiterhin(self):
        """WITHOUT THIS CASE a completeness rule that refuses everything would pass above."""
        r = self._r()
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertTrue(e.ok, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(e), 0)


class StrukturIstExitEinsUndNichtExitDrei(unittest.TestCase):
    """Exit 3 states "crypto sound but a relying-party requirement unmet". A receipt broken on its
    own must not borrow that code, because no relying party asked for anything."""

    def test_fang_nur_authorizer_id_angehaengt(self):
        r = lade("01_allow")
        r["authorizer_id"] = "did:key:claim"
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1, "incomplete metadata is structural")

    def test_fang_autorisierer_gleich_signierer_ist_struktur(self):
        r = lade("03_extern_autorisiert")
        r["authorizer_public_key"] = r["signer_public_key"]
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["signer_public_key"]])
        self.assertEqual(exit_code(e), 1)

    def test_gegenrichtung_die_vertrauensliste_bleibt_exit_drei(self):
        """The ONE relying-party matter keeps exit 3, or the distinction would be gone."""
        r = lade("03_extern_autorisiert")
        e = verify_agt_receipt(r, trusted_authorizer_keys=["aa" * 32])
        self.assertEqual(exit_code(e), 3, "an untrusted authorizer IS a relying-party requirement")
