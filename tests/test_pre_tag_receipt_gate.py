"""Gate-2 qualification (makellose-500 Phase 3, reviewer F6): the pre-tag audit gate must grant ok=true
ONLY for a SIGNED, TREE-BOUND receipt, and reject every counter-example — a bare prose line, a receipt
bound to a different tree/version, an unsigned one, and one signed by an untrusted key.

Generator-hardened: each rejection is a PROPERTY of verify_receipt, exercised by mutating exactly one
binding of an otherwise-valid receipt. A positive control (the untouched receipt verifies) guards
against the guard degrading into a constant reject."""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, verify_receipt  # noqa: E402

# 64 statt 40 seit 2026-09-07: 40 ist die Laenge einer git-SHA-1, `subject_tree_digest` ist ein
# sha256. `verify_receipt` weist eine Nicht-sha256-Erwartung jetzt ab, damit ein Ersatzwert des
# Aufrufers ("unknown") nicht bindbar ist — die alte Vorgabe haette diese Pruefung als erste
# ausgeloest und die Positivkontrolle unecht rot gemacht.
_TREE = "a" * 64
_GATE = "b" * 64
_VER = "5.0.0"


def _keypair():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    return priv, base64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _valid_receipt(priv, pub_b64):
    r = {
        "schema": RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
        "gate_source_digest": _GATE, "audit_command": "pytest -q + type_confusion_gate --strict",
        "audit_exit_code": 0, "audit_output_digest": "c" * 64, "runner_identity": "ci",
        "produced_at": "2026-08-26T21:00:00Z",
    }
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub_b64
    return r


def _check(receipt, trusted, **over):
    kw = dict(trusted_pubkeys=trusted, expected_version=_VER,
              subject_tree_digest=_TREE, gate_source_digest=_GATE)
    kw.update(over)
    return verify_receipt(receipt, **kw)


class TestPreTagReceiptGate:
    def test_positive_control_a_valid_receipt_verifies(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub])
        assert ok, reason

    def test_bare_line_is_not_a_receipt(self):
        # P6: a prose 'pre-tag-adversarial-audit: RUN | version=5.0.0' is not a dict receipt at all.
        ok, _ = _check("pre-tag-adversarial-audit: RUN | version=5.0.0", ["x"])
        assert not ok

    def test_wrong_tree_rejected(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub], subject_tree_digest="d" * 64)
        assert not ok and "tree" in reason.lower()

    def test_wrong_version_rejected(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub], expected_version="4.9.9")
        assert not ok and "version" in reason.lower()

    def test_wrong_gate_source_rejected(self):
        priv, pub = _keypair()
        ok, _ = _check(_valid_receipt(priv, pub), [pub], gate_source_digest="e" * 64)
        assert not ok

    def test_failed_audit_rejected(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["audit_exit_code"] = 1
        r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
        ok, _ = _check(r, [pub])
        assert not ok

    def test_no_trusted_key_fails_closed(self):
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [])
        assert not ok and "trust" in reason.lower()

    def test_untrusted_signer_rejected(self):
        priv, pub = _keypair()
        _, other_pub = _keypair()
        ok, _ = _check(_valid_receipt(priv, pub), [other_pub])  # signer's key not in the trusted set
        assert not ok

    def test_forged_resign_by_untrusted_key_rejected(self):
        # An attacker re-signs a tree-correct receipt with THEIR key and lists their pubkey — but their
        # key is not pinned as trusted, so it is rejected. This is the whole point of the trust anchor.
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        forger, forger_pub = _keypair()
        r["signature"] = base64.b64encode(forger.sign(canonical_bytes(r))).decode()
        r["signer_pubkey"] = forger_pub
        ok, _ = _check(r, [pub])  # only the honest key is trusted
        assert not ok

    def test_tampered_signature_rejected(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["audit_command"] = "rm -rf /  # tampered after signing"
        ok, _ = _check(r, [pub])  # signature no longer matches the canonical bytes
        assert not ok

    def test_missing_signed_field_is_error_not_short_message(self):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        del r["subject_tree_digest"]
        with pytest.raises(ValueError):
            canonical_bytes(r)
        ok, _ = _check(r, [pub])
        assert not ok


class TestErsatzwertIstNichtBindbar:
    """Fund 1 der adversarialen Gegenlesung vom 2026-09-07.

    Das Tor MUSS urteilen koennen, auch wenn es den Baum nicht messen kann — dafuer setzt es
    ``"unknown"`` (`_gate_tree_digest`) bzw. ``"unreadable"`` (`_gate_source_digest`) ein. Genau
    dieser Ersatzwert ging bis heute ungeprueft in einen Gleichheitsvergleich gegen ein Feld, das der
    Gepruefte selbst schreibt. Eine mit dem LEGITIMEN Schluessel signierte Quittung, die woertlich
    ``subject_tree_digest: "unknown"`` traegt, verifizierte deshalb IMMER — unabhaengig davon, wie
    der Baum aussah. Kein Exploit ohne Schluessel, aber ein Vergleich, dessen Ergebnis der Beleg
    selbst bestimmen konnte.

    Gepruefte Eigenschaft: nicht "der Wortlaut unknown wird abgelehnt" (das waere eine Liste, die
    beim naechsten Ersatzwert zu kurz ist), sondern "eine Erwartung, die keine sha256-Form hat, kann
    NIE binden". Beide Digest-Felder, weil beide einen Ersatzwert haben.
    """

    _ERSATZ = ["unknown", "unreadable", "unmeasurable", "", "a" * 40, "A" * 64, "g" * 64,
               " " + "a" * 63, "a" * 65, None, 0]

    @pytest.mark.parametrize("ersatz", _ERSATZ)
    def test_kein_sha256_als_erwarteter_baum_digest_bindet(self, ersatz):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["subject_tree_digest"] = ersatz          # der Beleg TRAEGT den Ersatzwert
        r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
        ok, reason = _check(r, [pub], subject_tree_digest=ersatz)
        assert not ok, f"der Ersatzwert {ersatz!r} war bindbar — der Beleg bestimmte den Vergleich"
        assert "sha256" in reason, reason

    @pytest.mark.parametrize("ersatz", _ERSATZ)
    def test_kein_sha256_als_erwarteter_gate_digest_bindet(self, ersatz):
        priv, pub = _keypair()
        r = _valid_receipt(priv, pub)
        r["gate_source_digest"] = ersatz
        r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
        ok, reason = _check(r, [pub], gate_source_digest=ersatz)
        assert not ok, f"der Ersatzwert {ersatz!r} war bindbar"
        assert "sha256" in reason, reason

    def test_die_pruefung_lehnt_nicht_alles_ab(self):
        # Die Gegenprobe zur Gegenprobe: eine echte sha256-Erwartung verifiziert weiterhin. Ohne
        # diese Zeile waere die neue Formpruefung von einem konstanten Nein nicht zu unterscheiden.
        priv, pub = _keypair()
        ok, reason = _check(_valid_receipt(priv, pub), [pub])
        assert ok, reason

    def test_die_EIGENSCHAFT_statt_der_liste(self):
        """Die Liste oben ist eine Liste. Diese Zusicherung ist die Eigenschaft.

        GEMESSEN AM 2026-09-07 von einer Gegenlesung, und der Befund sass: ersetzt man die
        Formpruefung durch genau die WORTLAUT-BLOCKLISTE, die der Commit als "beim naechsten
        Ersatzwert stillschweigend zu kurz" verwirft, bleiben alle 35 Faelle GRUEN. Die Klasse
        dokumentierte die Eigenschaft und band sie nicht — sie pruefte elf aufgezaehlte Werte, und
        elf aufgezaehlte Werte faengt eine Blockliste genauso.

        Hier werden die Werte ERZEUGT, nicht getippt: aus Bausteinen, die kein Aufzaehler kennen
        kann. Ein kuenftiger Ersatzwert ("unmeasured", "n/a", "ERROR", was auch immer) faellt in
        dieselbe Menge. Deterministisch geseedet, damit ein Fehlschlag reproduzierbar ist.
        """
        import random
        import string

        rng = random.Random(20260907)
        hexziffern = "0123456789abcdef"
        erzeugt: list[str] = []
        for _ in range(60):
            # falsche Laenge, richtige Zeichen
            n = rng.choice([0, 1, 39, 40, 63, 65, 128])
            erzeugt.append("".join(rng.choice(hexziffern) for _ in range(n)))
        for _ in range(60):
            # richtige Laenge, falsche Zeichen — an zufaelliger Stelle
            s = list("".join(rng.choice(hexziffern) for _ in range(64)))
            s[rng.randrange(64)] = rng.choice(string.ascii_uppercase + "ghijklmnopqrstuvwxyz"
                                              + " \t\n-_+!/:.")
            erzeugt.append("".join(s))
        for _ in range(20):
            # freie Woerter, wie ein Ersatzwert aussieht, den heute niemand kennt
            erzeugt.append("".join(rng.choice(string.ascii_lowercase + "_-")
                                   for _ in range(rng.randrange(1, 20))))

        priv, pub = _keypair()
        durchgerutscht = []
        for wert in erzeugt:
            r = _valid_receipt(priv, pub)
            r["subject_tree_digest"] = wert
            r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
            ok, _grund = _check(r, [pub], subject_tree_digest=wert)
            if ok:
                durchgerutscht.append(wert)
        assert not durchgerutscht, (
            f"{len(durchgerutscht)} von {len(erzeugt)} erzeugten Nicht-sha256-Werten waren bindbar, "
            f"darunter {durchgerutscht[:3]!r} — die Pruefung haengt an einer Liste, nicht an der Form")

        # Anti-Paritaet: der Generator muss auch echte Digests erzeugen koennen, sonst prueft er
        # nur, dass alles abgelehnt wird.
        echte = ["".join(rng.choice(hexziffern) for _ in range(64)) for _ in range(5)]
        for wert in echte:
            r = _valid_receipt(priv, pub)
            r["subject_tree_digest"] = wert
            r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
            ok, grund = _check(r, [pub], subject_tree_digest=wert)
            assert ok, f"ein gueltiger sha256 {wert[:12]}… wurde abgelehnt: {grund}"


class TestUnlesbarerBaumLaesstDasTorUrteilen:
    """Die Regression, die dieser Commit mitbringt und hier festnagelt.

    ``subject_tree_digest`` warf zuerst ``SystemExit``. Das ist eine ``BaseException`` — der einzige
    Aufrufer im Tor faengt ``except Exception`` und sah sie nie. Fuenf Negativtests, die das Tor
    gegen einen belegfreien Nicht-git-Ordner fahren, starben am Prozessabbruch, statt ein ``ok=False``
    zu bekommen: ein Riegel, der nicht mehr ablehnt, sondern stirbt.
    """

    def test_ein_nicht_git_ordner_wirft_einen_mit_except_exception_fangbaren_fehler(self):
        import tempfile  # noqa: PLC0415

        from pre_tag_receipt_lib import BaumNichtLesbar, subject_tree_digest  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            try:
                d = subject_tree_digest(Path(td))
            except Exception as e:  # noqa: BLE001 — genau das ist die gepruefte Eigenschaft
                assert isinstance(e, BaumNichtLesbar), f"falscher Typ: {type(e).__name__}"
                return
            pytest.fail(f"ein Nicht-git-Ordner lieferte einen Digest: {d!r}")
