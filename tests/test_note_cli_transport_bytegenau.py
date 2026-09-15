"""CLI-Transport bytegenau — Review Runde 2, Framing Auflage A3 (2026-09-05).

FUND. ``_open_input`` oeffnete den Text-Zweig bisher mit ``open(path, encoding="utf-8")``: kein
``newline=`` (Vorgabe ``None``) schaltet Pythons UNIVERSELLE Zeilenumwandlung ein, die JEDES
``\\r\\n``/``\\r`` beim Lesen STILL zu ``\\n`` macht, und kein ``errors=`` (Vorgabe ``strict``) laesst ein
ungueltiges UTF-8-Byte mit einer ROHEN ``UnicodeDecodeError`` AN DER OEFFNUNGSSTELLE scheitern — BEVOR
``checkpoint._split_signed_note`` je eine Zeile sieht. Beides ist eine STILLE zweite Drahtform derselben
Datei, erzeugt an der Dekodierstelle statt am gemeinsamen Parser — genau die Klasse, die
L1-600-NOTE-FRAMING-01 schliesst, nur eine Schicht davor.

DER FIX sitzt in ``cli._open_input`` (``newline=""`` erhaelt jedes ``\\r``/``\\r\\n`` byte-genau,
``errors="surrogateescape"`` macht ein ungueltiges Byte zu GENAU EINEM einsamen Surrogaten, das
``_split_signed_note`` laengst typisiert ablehnt — ``_SURROGAT_RE``). Gemessen wird hier mit ROHEN BYTES
(``open(path, "wb")``), NICHT mit Zeichenketten: eine in-memory ``str`` kann Pythons
Textmodus-Normalisierung nicht zeigen, nur eine echte Datei auf der Platte kann das. Beide CLI-Wege:
``verify --trusted-checkpoint`` und ``verify-proof``.

ANTITAUTOLOGIE: jeder Fund traegt eine Gegenprobe mit der Oeffnung VOR diesem Fix (``_vorfix_open_input``)
— sie MUSS die Note anders behandeln, sonst wuerde der Fix-Test nichts binden.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import stat as _stat
import tempfile
import unittest
from unittest import mock

from proofbundle import checkpoint as cp
from proofbundle import cli
from proofbundle import tlogproof
from proofbundle.cli import main
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError


def _vorfix_open_input(path, *, binary: bool = False):
    """Die Oeffnung VOR diesem Fix, Zeichen fuer Zeichen wie sie vor der Auflage A3 stand — NUR fuer
    den Antitautologie-Nachweis via ``mock.patch.object``, nie im Produktionscode aufgerufen."""
    if not isinstance(path, (str, bytes, os.PathLike)):
        raise BundleFormatError(f"input path must be a path, got {type(path).__name__} (fail-closed)")
    st = os.stat(path)
    if not _stat.S_ISREG(st.st_mode):
        raise BundleFormatError("input path is not a regular file (fail-closed: FIFO/device/socket refused)")
    return open(path, "rb") if binary else open(path, encoding="utf-8")


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class _Aufbau:
    """Echtes Bundle, echte signierte Note, echter tlog-proof — ueber die Emitter des Repos."""

    def __init__(self, d):
        self.signer = generate_signer()
        self.origin = "cli.example/transport"
        self.payload = b"punkt5 cli-transport payload"
        self.bundle = emit_bundle(self.payload, self.signer)
        self.root = base64.b64decode(self.bundle["merkle"]["root_b64"])
        self.tree_size = self.bundle["merkle"]["tree_size"]
        self.note = cp.sign_checkpoint(self.origin, self.tree_size, self.root, self.signer, self.origin)
        self.vkey = cp.vkey(self.origin, self.signer.public_key().public_bytes_raw())
        self.bpath = os.path.join(d, "bundle.json")
        with open(self.bpath, "w", encoding="utf-8") as f:
            json.dump(self.bundle, f)
        self.proof_text = tlogproof.tlog_proof_for_bundle(self.bundle, self.note)
        self.ppath = os.path.join(d, "payload.bin")
        with open(self.ppath, "wb") as f:
            f.write(self.payload)


class OpenInputBewahrtRohbytesUnitEbene(unittest.TestCase):
    """Unit-Ebene, ohne CLI-Dispatch: ``_open_input``/``_read_capped`` selbst normalisieren nicht."""

    def test_crlf_bleibt_crlf(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.txt")
            with open(p, "wb") as f:
                f.write(b"a\r\nb\r\nc\n")
            with cli._open_input(p) as h:
                data = cli._read_capped(h)
            self.assertEqual(data, "a\r\nb\r\nc\n", "CRLF wurde an der Oeffnungsstelle normalisiert")

    def test_ungueltiges_utf8_byte_wird_ein_einsames_surrogat_keine_rohe_ausnahme(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.txt")
            with open(p, "wb") as f:
                f.write(b"a\xffb\n")
            with cli._open_input(p) as h:
                data = cli._read_capped(h)   # darf NICHT roh mit UnicodeDecodeError scheitern
            self.assertEqual(len(data), 4)
            self.assertTrue("\ud800" <= data[1] <= "\udfff", repr(data))

    def test_vorfix_oeffnung_normalisiert_crlf_still_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.txt")
            with open(p, "wb") as f:
                f.write(b"a\r\nb\n")
            with _vorfix_open_input(p) as h:
                data = cli._read_capped(h)
            self.assertEqual(data, "a\nb\n", "Vorbedingung: die alte Oeffnung normalisiert CRLF — "
                                              "faellt das, misst der Fix-Test die Klasse nicht mehr")

    def test_vorfix_oeffnung_scheitert_roh_an_ungueltigem_utf8_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.txt")
            with open(p, "wb") as f:
                f.write(b"a\xffb\n")
            with self.assertRaises(UnicodeDecodeError):
                with _vorfix_open_input(p) as h:
                    cli._read_capped(h)


class VerifyTrustedCheckpointRohbytes(unittest.TestCase):
    """Erster CLI-Weg: ``verify --trusted-checkpoint``."""

    def test_crlf_note_wird_abgelehnt_nicht_still_als_kanonisch_angenommen(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            npath = os.path.join(d, "checkpoint_crlf.txt")
            with open(npath, "wb") as f:
                f.write(a.note.replace("\n", "\r\n").encode("utf-8"))
            rc, out, err = _run(["verify", a.bpath, "--trusted-checkpoint", npath,
                                 "--checkpoint-vkey", a.vkey])
            self.assertEqual(rc, 2, out + err)   # malformed — NICHT rc=0 (still als kanonisch angenommen)
            self.assertIn("control character", err)

    def test_crlf_note_ist_ohne_den_fix_still_angenommen_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            npath = os.path.join(d, "checkpoint_crlf.txt")
            with open(npath, "wb") as f:
                f.write(a.note.replace("\n", "\r\n").encode("utf-8"))
            with mock.patch.object(cli, "_open_input", _vorfix_open_input):
                rc, out, err = _run(["verify", a.bpath, "--trusted-checkpoint", npath,
                                     "--checkpoint-vkey", a.vkey])
            self.assertEqual(rc, 0, "Vorbedingung: ohne den Fix verifiziert die CRLF-Note still — "
                                    f"faellt das, misst der obige Test die Klasse nicht mehr\n{out}{err}")

    def test_ungueltiges_utf8_byte_ist_malformed_nicht_roher_codec_fehler(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            raw = a.note.encode("utf-8")
            bad = raw[:-1] + b"\xff" + raw[-1:]   # das signierte Schluss-LF bleibt erhalten
            npath = os.path.join(d, "checkpoint_badutf8.txt")
            with open(npath, "wb") as f:
                f.write(bad)
            rc, out, err = _run(["verify", a.bpath, "--trusted-checkpoint", npath,
                                 "--checkpoint-vkey", a.vkey])
            self.assertEqual(rc, 2, out + err)
            self.assertNotIn("codec can't decode", err, "rohe Codec-Meldung — die Bytes scheiterten an "
                                                        "der Oeffnungsstelle, nicht am typisierten Parser")
            self.assertIn("not valid UTF-8", err)

    def test_ungueltiges_utf8_byte_scheitert_ohne_den_fix_roh_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            raw = a.note.encode("utf-8")
            bad = raw[:-1] + b"\xff" + raw[-1:]
            npath = os.path.join(d, "checkpoint_badutf8.txt")
            with open(npath, "wb") as f:
                f.write(bad)
            with mock.patch.object(cli, "_open_input", _vorfix_open_input):
                rc, out, err = _run(["verify", a.bpath, "--trusted-checkpoint", npath,
                                     "--checkpoint-vkey", a.vkey])
            self.assertEqual(rc, 2, out + err)
            self.assertIn("codec can't decode", err, "Vorbedingung: ohne den Fix ist es eine rohe Codec-"
                                                     f"Meldung — faellt das, misst der obige Test die "
                                                     f"Klasse nicht mehr\n{out}{err}")


class VerifyProofRohbytes(unittest.TestCase):
    """Zweiter CLI-Weg: ``verify-proof``. Nur der EINGEBETTETE Checkpoint (nach der ersten Leerzeile
    des tlog-proof) wird mutiert — die AEUSSERE Trennung des Proofs ist die Regel jenes Formats, nicht
    die der Note, und bleibt hier unangetastet, damit genau die Note-Rahmungsklasse gemessen wird."""

    def _mutiere_eingebetteten_checkpoint(self, proof_text, wandeln):
        kopf, checkpoint = proof_text.split("\n\n", 1)
        return kopf + "\n\n" + wandeln(checkpoint)

    def test_crlf_im_eingebetteten_checkpoint_wird_abgelehnt(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            mutiert = self._mutiere_eingebetteten_checkpoint(a.proof_text, lambda c: c.replace("\n", "\r\n"))
            ppath = os.path.join(d, "proof_crlf.tlogproof")
            with open(ppath, "wb") as f:
                f.write(mutiert.encode("utf-8"))
            rc, out, err = _run(["verify-proof", ppath, "--payload-file", a.ppath, "--log-vkey", a.vkey])
            self.assertEqual(rc, 1, out + err)   # verify_tlog_proof: never-raise, ok=False -> exit 1
            self.assertNotIn("=> OK", out)

    def test_crlf_im_eingebetteten_checkpoint_ist_ohne_den_fix_still_angenommen_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            mutiert = self._mutiere_eingebetteten_checkpoint(a.proof_text, lambda c: c.replace("\n", "\r\n"))
            ppath = os.path.join(d, "proof_crlf.tlogproof")
            with open(ppath, "wb") as f:
                f.write(mutiert.encode("utf-8"))
            with mock.patch.object(cli, "_open_input", _vorfix_open_input):
                rc, out, err = _run(["verify-proof", ppath, "--payload-file", a.ppath, "--log-vkey", a.vkey])
            self.assertEqual(rc, 0, "Vorbedingung: ohne den Fix verifiziert der CRLF-Proof still — "
                                    f"faellt das, misst der obige Test die Klasse nicht mehr\n{out}{err}")
            self.assertIn("=> OK", out)

    @staticmethod
    def _proof_mit_kaputtem_byte_im_checkpoint(proof_text):
        """Reines Byte-Handwerk: EIN ungueltiges UTF-8-Byte kurz vor dem signierten Schluss-LF des
        EINGEBETTETEN Checkpoints, die aeussere tlog-proof-Rahmung (MAGIC, index, erste Leerzeile)
        bleibt unangetastet."""
        kopf, checkpoint = proof_text.split("\n\n", 1)
        raw_checkpoint = checkpoint.encode("utf-8")
        bad_checkpoint = raw_checkpoint[:-1] + b"\xff" + raw_checkpoint[-1:]
        return kopf.encode("utf-8") + b"\n\n" + bad_checkpoint

    def test_ungueltiges_utf8_byte_im_eingebetteten_checkpoint_ist_malformed_nicht_roher_codec_fehler(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            raw = self._proof_mit_kaputtem_byte_im_checkpoint(a.proof_text)
            ppath = os.path.join(d, "proof_badutf8.tlogproof")
            with open(ppath, "wb") as f:
                f.write(raw)
            rc, out, err = _run(["verify-proof", ppath, "--payload-file", a.ppath, "--log-vkey", a.vkey])
            self.assertEqual(rc, 1, out + err)   # verify_tlog_proof: never-raise, ok=False -> exit 1
            self.assertNotIn("codec can't decode", out + err)
            self.assertIn("not valid UTF-8", out + err)

    def test_ungueltiges_utf8_byte_scheitert_ohne_den_fix_roh_antitautologie(self):
        with tempfile.TemporaryDirectory() as d:
            a = _Aufbau(d)
            raw = self._proof_mit_kaputtem_byte_im_checkpoint(a.proof_text)
            ppath = os.path.join(d, "proof_badutf8.tlogproof")
            with open(ppath, "wb") as f:
                f.write(raw)
            with mock.patch.object(cli, "_open_input", _vorfix_open_input):
                rc, out, err = _run(["verify-proof", ppath, "--payload-file", a.ppath, "--log-vkey", a.vkey])
            # Vorbedingung: ohne den Fix ist es eine ROHE UnicodeDecodeError (ValueError) an der
            # Oeffnungsstelle, von _cmd_verify_proofs eigenem except gefangen — exit 2 statt des
            # typisierten Bibliotheksverdikts (exit 1). Faellt das, misst der obige Test die Klasse nicht mehr.
            self.assertEqual(rc, 2, out + err)
            self.assertIn("codec can't decode", out + err, f"Vorbedingung verletzt\n{out}{err}")


if __name__ == "__main__":
    unittest.main()
