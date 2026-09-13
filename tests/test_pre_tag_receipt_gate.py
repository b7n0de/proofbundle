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


class TestQuittungsMusterIstAnDieWurzelVerankert:
    """Linse 2 des deep gate (Lauf 5, 2026-09-07) — REJECT mit ausgefuehrtem Exploit.

    ``subject_tree_digest`` schliesst die Quittung aus der Bindung aus, weil sie in dem Baum liegt,
    den sie bindet. Der Ausschluss lief ueber ``_RECEIPT_MUSTER.search(zeile)`` auf die GANZE
    ``ls-tree``-Zeile (``<mode> <type> <sha>\\t<pfad>``), und das Muster hatte keinen Anker am
    Pfadanfang. Jede Datei IRGENDWO im Baum, deren Pfad so endet, fiel damit still aus dem Digest —
    gemessen: eine committete ``src/proofbundle/audit_artifacts/1/pre_tag_receipt_v1.json`` liess
    den Digest BYTEIDENTISCH und das Tor weiter ``verified``, ohne dass jemand neu signiert haette.

    Der Nachbar in derselben Funktion (``MUTABLE_EVIDENCE_RELS`` via ``endswith("\\t" + pfad)``) war
    seit je verankert. Diese Faelle binden die Eigenschaft, nicht den einen Pfad.
    """

    @staticmethod
    def _repo(tmp_path):
        import subprocess  # noqa: PLC0415
        def git(*a):
            r = subprocess.run(["git", "-C", str(tmp_path), *a], capture_output=True, text=True)
            assert r.returncode == 0, f"git {a}: {r.stderr}"
        git("init", "-q")
        git("config", "user.email", "t@t.t")
        git("config", "user.name", "t")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "x.py").write_text("x = 1\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "basis")
        return git

    @staticmethod
    def _lege_an(tmp_path, git, rel: str):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('{"schema": "erfunden"}\n', encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", f"add {rel}")

    def test_eine_quittungsfoermige_datei_unter_src_faellt_NICHT_aus_der_bindung(self, tmp_path):
        """DIE ZUSICHERUNG. Der Exploit-Pfad muss den Digest bewegen."""
        from pre_tag_receipt_lib import subject_tree_digest  # noqa: PLC0415
        git = self._repo(tmp_path)
        vorher = subject_tree_digest(tmp_path)
        self._lege_an(tmp_path, git, "src/proofbundle/audit_artifacts/1/pre_tag_receipt_v1.json")
        nachher = subject_tree_digest(tmp_path)
        assert nachher != vorher, (
            "Eine committete Datei unter src/ hat den subject_tree_digest NICHT bewegt, weil ihr "
            "Pfadende dem Quittungsmuster entspricht. Damit darf sich nach dem Signieren beliebiger "
            "Inhalt an dieser Stelle aendern, ohne die Quittung zu brechen — der Ausschluss ist "
            "eine Pfadgrenze, und eine ungeankerte Suche bindet keine Grenze.")

    def test_ANTI_PARITAET_die_echte_quittung_faellt_weiterhin_heraus(self, tmp_path):
        """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Muster, das NIE trifft —
        dann enthielte der Digest die Quittung selbst und koennte nie berechnet werden."""
        from pre_tag_receipt_lib import subject_tree_digest  # noqa: PLC0415
        git = self._repo(tmp_path)
        vorher = subject_tree_digest(tmp_path)
        self._lege_an(tmp_path, git, "audit_artifacts/600/pre_tag_receipt_v6.0.0.json")
        assert subject_tree_digest(tmp_path) == vorher, (
            "Die echte Quittung an ihrem vorgesehenen Ort bewegt den Digest — dann bindet sie sich "
            "selbst und ist zirkulaer, also nie verifizierbar. Der Ausschluss muss GENAU hier "
            "greifen und nur hier.")

    def test_die_EIGENSCHAFT_statt_des_einen_pfades(self, tmp_path):
        """Die Faelle oben sind zwei Pfade. Das hier ist die Eigenschaft: NUR eine Datei direkt
        unter ``audit_artifacts/<token>/`` an der Wurzel faellt heraus, jede tiefer geschachtelte
        Wiederholung desselben Namens nicht. Erzeugt statt getippt, damit ein Praefix, an das heute
        niemand denkt, in dieselbe Menge faellt."""
        from pre_tag_receipt_lib import subject_tree_digest  # noqa: PLC0415
        git = self._repo(tmp_path)
        praefixe = ["src", "tests", "scripts/unter", "docs/a/b", "src/proofbundle/audit_artifacts",
                    "a", "audit_artifacts/600/nested"]
        durchgerutscht = []
        for n, praefix in enumerate(praefixe):
            vorher = subject_tree_digest(tmp_path)
            self._lege_an(tmp_path, git,
                          f"{praefix}/audit_artifacts/{600 + n}/pre_tag_receipt_v6.0.{n}.json")
            if subject_tree_digest(tmp_path) == vorher:
                durchgerutscht.append(praefix)
        assert not durchgerutscht, (
            f"{len(durchgerutscht)} von {len(praefixe)} Praefixen fielen still aus der Bindung: "
            f"{durchgerutscht}. Der Ausschluss haengt dann am Pfad-ENDE statt an der Pfadgrenze.")


class TestDerVertrauensankerKommtAusDemCommittetenBaum:
    """DER SCHWERSTE FUND DES RIEGEL-SWEEPS (Owner-Auftrag 2026-09-07, P0) — eine geschlossene
    Sicherheitsluecke, die von NICHTS festgehalten wurde.

    `load_trusted_pubkeys` liest den Vertrauensanker seit dem 2026-08-27 mit
    `git show HEAD:audit_artifacts/pre_tag_trusted_pubkeys.txt` statt aus dem Arbeitsbaum. Der
    eigene Docstring nennt den Grund: die Quittung bindet den COMMITTETEN Baum, also muss der
    Anker aus demselben Baum kommen — sonst schmuggelt ein schmutziger Checkout einen Schluessel
    ein (uncommittet, also ausserhalb des Digests) und beglaubigt sich selbst.

    GEMESSEN 2026-09-07: KEIN Test unterscheidet die beiden Lesarten. Jede Fixture im Korpus
    committet den Anker, bevor sie misst — damit ist Arbeitsbaum-Inhalt gleich HEAD-Inhalt in
    jedem einzelnen Fall, und der Unterschied ist unsichtbar. Baut man die Funktion auf
    Arbeitsbaum-Lesen zurueck, bleiben 64 Faelle gruen.

    DER ANGRIFF WURDE GEFAHREN, nicht nur beschrieben: frisches Repo, ein legitimer Schluessel
    committet; danach ein Angreifer-Schluessel UNCOMMITTET in die Arbeitsbaumdatei; der Angreifer
    signiert ein Receipt auf den unveraenderten committeten Baum. Original: `ok=False, "receipt
    signer_pubkey is not in the trusted set"`. Zurueckgebaut: `ok=True, "verified"`.

    Diese Faelle binden die Lesart selbst. Faellt jemand beim Aufraeumen auf die Arbeitsbaumdatei
    zurueck — der kuerzere, naheliegendere Weg —, faellt hier etwas, statt dass 64 gruene Tests
    eine offene Tuer bescheinigen.
    """

    _LEGIT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    _ANGREIFER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="

    @staticmethod
    def _repo_mit_anker(tmp_path, anker_inhalt: str):
        import subprocess  # noqa: PLC0415

        def git(*a):
            r = subprocess.run(["git", "-C", str(tmp_path), *a], capture_output=True, text=True)
            assert r.returncode == 0, f"git {a}: {r.stderr}"

        git("init", "-q")
        git("config", "user.email", "t@t.t")
        git("config", "user.name", "t")
        (tmp_path / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (tmp_path / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            anker_inhalt, encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "anker")
        return git

    def test_ein_UNCOMMITTETER_schluessel_im_arbeitsbaum_wird_NICHT_vertraut(self, tmp_path):
        """DIE ZUSICHERUNG, und sie ist der gefahrene Angriff in einer Zeile."""
        from pre_tag_receipt_lib import load_trusted_pubkeys  # noqa: PLC0415
        self._repo_mit_anker(tmp_path, self._LEGIT + "\n")
        # Der Angreifer haengt seinen Schluessel an — OHNE zu committen. Der committete Baum, den
        # die Quittung bindet, bleibt dabei byteidentisch.
        (tmp_path / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._LEGIT + "\n" + self._ANGREIFER + "\n", encoding="utf-8")

        vertraut = load_trusted_pubkeys(tmp_path)
        assert self._ANGREIFER not in vertraut, (
            "Ein UNCOMMITTETER Schluessel aus dem Arbeitsbaum steht in der Vertrauensmenge. Damit "
            "kann ein schmutziger Checkout eine Quittung selbst beglaubigen, die den SAUBEREN "
            "committeten Baum bindet — der Digest bewegt sich nicht, weil die Aenderung nie "
            "committet wurde. Genau diese Luecke wurde am 2026-08-27 geschlossen; dieser Fall ist "
            f"der Riegel dagegen. Gelesen wurde: {vertraut}")
        assert vertraut == [self._LEGIT], (
            f"Der committete Anker wird nicht mehr richtig gelesen: {vertraut}. Der Riegel darf den "
            f"legitimen Schluessel nicht mitnehmen — sonst ist er kein Riegel, sondern ein Ausfall.")

    def test_ANTI_PARITAET_ein_COMMITTETER_zweitschluessel_wird_sehr_wohl_vertraut(self, tmp_path):
        """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einer Funktion, die IMMER nur
        den ersten Schluessel liefert oder gar nichts — dann waere der Anker nicht gehaertet,
        sondern kaputt, und eine legitime Schluesselrotation unmoeglich."""
        from pre_tag_receipt_lib import load_trusted_pubkeys  # noqa: PLC0415
        git = self._repo_mit_anker(tmp_path, self._LEGIT + "\n")
        (tmp_path / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._LEGIT + "\n" + self._ANGREIFER + "\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "zweiter schluessel, diesmal COMMITTET")

        vertraut = load_trusted_pubkeys(tmp_path)
        assert vertraut == [self._LEGIT, self._ANGREIFER], (
            f"Ein COMMITTETER zweiter Schluessel fehlt in der Vertrauensmenge: {vertraut}. Der "
            f"Unterschied, den dieser Riegel macht, ist committet gegen uncommittet — nicht "
            f"'ein Schluessel gegen zwei'.")

    def test_der_anker_wird_aus_DEM_ref_gelesen_das_die_quittung_bindet(self, tmp_path):
        """Die dritte Seite derselben Eigenschaft: der Anker haengt am REF, nicht an der Gegenwart.

        Der Docstring der Funktion sagt, das Tor loese den Digest aus DEMSELBEN `HEAD` auf. Dieser
        Fall haelt fest, dass `ref` wirklich durchschlaegt: gegen den ELTERN-Commit gelesen, darf
        der spaeter hinzugefuegte Schluessel nicht erscheinen.
        """
        from pre_tag_receipt_lib import load_trusted_pubkeys  # noqa: PLC0415
        git = self._repo_mit_anker(tmp_path, self._LEGIT + "\n")
        (tmp_path / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
            self._LEGIT + "\n" + self._ANGREIFER + "\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-qm", "zweiter schluessel")

        assert load_trusted_pubkeys(tmp_path, ref="HEAD~1") == [self._LEGIT], (
            "Gegen HEAD~1 gelesen erscheint ein Schluessel, den es dort noch nicht gab — dann liest "
            "die Funktion nicht das uebergebene ref, und die Bindung an den Baum der Quittung ist "
            "eine Behauptung statt eines Mechanismus.")
