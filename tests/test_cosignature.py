"""C2SP tlog-cosignature (Ed25519 cosignature/v1) — green roundtrip + red matrix (v1.2)."""
import base64
import hashlib
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import checkpoint as cp
from proofbundle import generate_signer
from proofbundle.errors import BundleFormatError

TS = 1_780_000_000
ROOT = hashlib.sha256(b"leaf").digest()
ORIGIN = "example.com/log"


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _witnessed(n_witnesses=1):
    log_key = generate_signer()
    note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
    log_vkey = cp.vkey(ORIGIN, _raw_pub(log_key))
    witnesses = []
    for i in range(n_witnesses):
        wk = generate_signer()
        wname = f"witness{i}.example.com/w"
        note = cp.cosign_checkpoint(note, wk, wname, TS + i)
        witnesses.append((wname, wk, cp.cosign_vkey(wname, _raw_pub(wk))))
    return note, log_vkey, witnesses


class TestCosignRoundtrip(unittest.TestCase):
    def test_green_single_witness(self):
        note, log_vkey, [(wname, _, wvkey)] = _witnessed(1)
        res = cp.verify_cosignature(note, wvkey)
        self.assertTrue(res["ok"])
        self.assertEqual(res["timestamp"], TS)
        self.assertEqual(res["origin"], ORIGIN)
        self.assertEqual(res["tree_size"], 7)
        self.assertEqual(res["root"], ROOT)
        # the log's own signature still verifies alongside the cosignature
        self.assertTrue(cp.verify_checkpoint(note, log_vkey)["ok"])

    def test_green_witnessed_quorum(self):
        note, log_vkey, witnesses = _witnessed(3)
        wvkeys = [w[2] for w in witnesses]
        res = cp.verify_witnessed_checkpoint(note, log_vkey, wvkeys, threshold=2)
        self.assertTrue(res["ok"])
        self.assertTrue(res["log_ok"])
        self.assertTrue(res["witnesses_ok"])
        self.assertEqual(sum(1 for r in res["witnesses"].values() if r["ok"]), 3)

    def test_signed_message_framing(self):
        # The signed message is exactly: "cosignature/v1\ntime <ts>\n" + note body.
        note_text = cp.checkpoint_note(ORIGIN, 7, ROOT)
        msg = cp._cosigned_message(note_text, TS)
        self.assertTrue(msg.startswith(b"cosignature/v1\ntime %d\n" % TS))
        self.assertTrue(msg.endswith(note_text.encode("utf-8")))

    def test_key_id_domain_separation(self):
        # Witness key ID (0x04) must differ from the log key ID (0x01) for the SAME key+name:
        # a log key can never masquerade as a witness.
        key = generate_signer()
        pub = _raw_pub(key)
        self.assertNotEqual(cp.key_id(ORIGIN, pub), cp.cosign_key_id(ORIGIN, pub))


class TestCosignAdversarial(unittest.TestCase):
    def test_red_timestamp_tamper(self):
        note, _, [(wname, _, wvkey)] = _witnessed(1)
        lines = note.rstrip("\n").split("\n")
        payload = base64.b64decode(lines[-1].split(" ")[2])
        ts = int.from_bytes(payload[4:12], "big") + 1
        tampered_payload = payload[:4] + ts.to_bytes(8, "big") + payload[12:]
        lines[-1] = f"{cp.EM_DASH} {wname} " + base64.b64encode(tampered_payload).decode()
        self.assertFalse(cp.verify_cosignature("\n".join(lines) + "\n", wvkey)["ok"])

    def test_red_note_body_tamper(self):
        note, _, [(_, _, wvkey)] = _witnessed(1)
        tampered = note.replace("\n7\n", "\n8\n")
        self.assertFalse(cp.verify_cosignature(tampered, wvkey)["ok"])

    def test_red_wrong_witness_key(self):
        note, _, _ = _witnessed(1)
        other = generate_signer()
        other_vkey = cp.cosign_vkey("witness0.example.com/w", _raw_pub(other))
        self.assertFalse(cp.verify_cosignature(note, other_vkey)["ok"])

    def test_red_log_vkey_is_not_a_witness_vkey(self):
        # Type confusion: a 0x01 log vkey must be rejected by the cosignature verifier.
        note, log_vkey, _ = _witnessed(1)
        with self.assertRaises(BundleFormatError):
            cp.verify_cosignature(note, log_vkey)

    def test_red_quorum_not_met(self):
        note, log_vkey, witnesses = _witnessed(1)
        stranger = generate_signer()
        stranger_vkey = cp.cosign_vkey("stranger.example.com/w", _raw_pub(stranger))
        res = cp.verify_witnessed_checkpoint(note, log_vkey, [witnesses[0][2], stranger_vkey],
                                             threshold=2)
        self.assertFalse(res["ok"])
        self.assertTrue(res["log_ok"])
        self.assertFalse(res["witnesses_ok"])

    def test_red_same_witness_not_double_counted(self):
        note, log_vkey, [(_, _, wvkey)] = _witnessed(1)
        res = cp.verify_witnessed_checkpoint(note, log_vkey, [wvkey, wvkey], threshold=2)
        self.assertFalse(res["ok"], "one witness listed twice must not satisfy threshold=2")

    def test_red_one_key_under_two_names_not_a_quorum(self):
        # HIGH (release review): quorum counts DISTINCT KEY MATERIAL, not names — one physical key registered
        # under two names must NOT satisfy threshold=2 (C2SP: distinct keys per cosigner).
        log_key = generate_signer()
        note = cp.sign_checkpoint(ORIGIN, 7, ROOT, log_key, ORIGIN)
        log_vkey = cp.vkey(ORIGIN, _raw_pub(log_key))
        sole = generate_signer()
        note = cp.cosign_checkpoint(note, sole, "witnessA.example.com/w", TS)
        note = cp.cosign_checkpoint(note, sole, "witnessB.example.com/w", TS + 1)
        vkeys = [cp.cosign_vkey("witnessA.example.com/w", _raw_pub(sole)),
                 cp.cosign_vkey("witnessB.example.com/w", _raw_pub(sole))]
        res = cp.verify_witnessed_checkpoint(note, log_vkey, vkeys, threshold=2)
        self.assertFalse(res["witnesses_ok"], "one key under two names must not satisfy threshold=2")
        self.assertFalse(res["ok"])

    def test_red_log_signature_still_required(self):
        # Witnesses do not REPLACE the log signature: quorum met + wrong log key → fail.
        note, _, [(_, _, wvkey)] = _witnessed(1)
        wrong_log = generate_signer()
        wrong_log_vkey = cp.vkey(ORIGIN, _raw_pub(wrong_log))
        res = cp.verify_witnessed_checkpoint(note, wrong_log_vkey, [wvkey], threshold=1)
        self.assertFalse(res["ok"])
        self.assertFalse(res["log_ok"])
        self.assertTrue(res["witnesses_ok"])

    def test_red_oversized_signature_blob(self):
        # Blob length is exactly keyID[4]+ts[8]+sig[64]=76; a trailing extra byte must fail.
        # (Also holds via verify_ed25519's hard 64-byte signature length check — pinned here.)
        note, _, [(wname, _, wvkey)] = _witnessed(1)
        lines = note.rstrip("\n").split("\n")
        payload = base64.b64decode(lines[-1].split(" ")[2]) + b"\x00"
        lines[-1] = f"{cp.EM_DASH} {wname} " + base64.b64encode(payload).decode()
        self.assertFalse(cp.verify_cosignature("\n".join(lines) + "\n", wvkey)["ok"])

    def test_fremde_origin_unter_vertrautem_schluessel_wird_nur_mit_bindung_gefangen(self):
        """Der Schluessel bindet die ORIGIN-ZEILE NICHT — gemessen, nicht angenommen.

        `sign_checkpoint` nimmt origin und Signaturnamen GETRENNT (C2SP laesst das zu: ein
        Betreiber darf einen Schluessel fuer mehrere Baeume fuehren). Eine Note, deren
        origin-Zeile einen FREMDEN Baum nennt, verifiziert deshalb unter dem VERTRAUTEN vkey
        und liefert dessen root und tree_size aus. Wer nur den Schluessel pinnt, hat also
        NICHT gepinnt, WELCHER Baum spricht. Genau das schliesst expected_origin.
        """
        log_key = generate_signer()
        fremd = cp.sign_checkpoint("evil.example/other-tree", 7, ROOT, log_key, ORIGIN)
        log_vkey = cp.vkey(ORIGIN, _raw_pub(log_key))
        wk = generate_signer()
        fremd = cp.cosign_checkpoint(fremd, wk, "witness0.example.com/w", TS)
        wvkeys = [cp.cosign_vkey("witness0.example.com/w", _raw_pub(wk))]

        ohne = cp.verify_witnessed_checkpoint(fremd, log_vkey, wvkeys, threshold=1)
        self.assertTrue(ohne["log_ok"], "Vorbedingung: ohne Bindung geht die fremde Note DURCH — "
                                        "faellt das hier, misst der Test die Bedrohung nicht mehr")
        self.assertEqual(ohne["expected_origin"], None)

        mit = cp.verify_witnessed_checkpoint(fremd, log_vkey, wvkeys, threshold=1,
                                             expected_origin=ORIGIN)
        self.assertFalse(mit["log_ok"], "eine Note fuer einen FREMDEN Baum darf unter dem "
                                        "vertrauten Schluessel nicht als unsere durchgehen")
        self.assertFalse(mit["ok"])
        # Die Zeugen sind davon unberuehrt: der Fehlschlag ist dem LOG zuzurechnen, nicht ihnen.
        self.assertTrue(mit["witnesses_ok"])
        self.assertEqual(mit["origin"], "evil.example/other-tree")
        self.assertEqual(mit["expected_origin"], ORIGIN)

    def test_expected_origin_wird_EXAKT_verglichen(self):
        """Kein Beinahe-Treffer wird als die erwartete origin akzeptiert.

        Korpus aus `tests/_beinahe_treffer.py` — dieselbe Quelle wie kbjwt, statuslist, intoto,
        evalclaim und policy. Faengt jede Lockerung des Vergleichs (startswith, casefold,
        strip, `in`) an EINER Stelle statt in sechs Kopien.
        """
        from _beinahe_treffer import pruefe_exakt  # noqa: PLC0415

        note, log_vkey, [(_, _, wvkey)] = _witnessed(1)
        pruefe_exakt(
            lambda v: cp.verify_witnessed_checkpoint(note, log_vkey, [wvkey], threshold=1,
                                                     expected_origin=v)["log_ok"],
            ORIGIN, self)

    def test_red_bad_inputs(self):
        note, _, [(_, wk, _)] = _witnessed(1)
        with self.assertRaises(BundleFormatError):
            cp.cosign_checkpoint(note, wk, "bad name with spaces", TS)
        with self.assertRaises(BundleFormatError):
            cp.cosign_checkpoint(note, wk, "w.example/w", -1)
        with self.assertRaises(BundleFormatError):
            cp.cosign_checkpoint(note, wk, "w.example/w", 2**63)
        with self.assertRaises(BundleFormatError):
            cp.verify_witnessed_checkpoint(note, "x", [], threshold=0)


if __name__ == "__main__":
    unittest.main()
