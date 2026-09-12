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

import ast
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


def _tree(version: str = "6.0.0", anker: str | None = None, *, git: bool = True) -> pathlib.Path:
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
    if not git:
        # OHNE git kann das Tor den Baum nicht messen und setzt `unknown` ein. Genau dieser Fall
        # gehoert in die Matrix: der Ersatzwert darf nicht bindbar sein (Gegenlesung 2026-09-07,
        # Fund 1) — und ohne einen Fall, der ihn faehrt, ist der Riegel dagegen ungemessen.
        return d
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


#: JEDER ABLEHNUNGSGRUND VON `verify_receipt` BEKOMMT EINEN FALL — und ein Riegel haelt das
#: fest (``test_jede_ablehnungsstelle_hat_einen_fall``). Die Tabelle stand bis zum 12.09.2026
#: INNERHALB der Testmethode und trug fuenf Formen; gemessen hat `verify_receipt` ZWOELF Stellen,
#: die mit ``return False`` enden. Vier davon waren gefahren.
#:
#: DAS IST DIE KLASSE, NICHT DIE INSTANZ (Posten 72, Bahn proofbundle): der Auftrag nannte drei
#: fehlende Formen (``wrong_exit_code``, ``wrong_schema``, ``stale_gate_source_digest``). Gemessen
#: fehlten ACHT. Wer nur die drei nachtraegt, hat die Aufzaehlung verlaengert und die Luecke
#: gelassen — die naechste neue Pruefstufe in `verify_receipt` waere wieder ungedeckt, und niemand
#: wuerde es bemerken. Deshalb zaehlt der Riegel die Stellen an der QUELLE und verlangt je Stelle
#: einen Fall oder eine ausgeschriebene Ausnahme.
#:
#: REIHENFOLGE IST DIE HALBE MIETE. `verify_receipt` prueft: Digest-Form -> Schema -> Version ->
#: Baum -> Gate-Quelle -> audit_exit -> Anker -> Signierer -> Signatur. Damit ein Fall an SEINER
#: Eigenschaft faellt, muss alles DAVOR stimmen — deshalb tragen die spaeten Faelle echte Digests
#: und den Ankerschluessel.
SHAPES: dict[str, dict] = {
    # — vor `verify_receipt`, im Lader des Tors ————————————————————————————————————————————————
    "unreadable_json": {"roh": "{ this is not json", "grund": "unreadable", "anker": "KEIN"},
    "not_an_object": {"roh": "[1, 2, 3]", "grund": "not a JSON object", "anker": "KEIN"},
    # — Digest-Form: der Ersatzwert eines nicht messbaren Baums darf nicht bindbar sein ——————————
    "gate_kann_baum_nicht_messen": {"grund": "is not a sha256", "git": False,
                                    "echte_digests": False},
    # — Schema —————————————————————————————————————————————————————————————————————————————————
    "wrong_schema": {"grund": "unknown schema", "echte_digests": False,
                     "felder": {"schema": "b7n0de.fremdes_schema.v9"}},
    # — Version ————————————————————————————————————————————————————————————————————————————————
    "wrong_version": {"grund": "!= release", "echte_digests": False,
                      "felder": {"version": "5.0.0"}},
    # — Baumbindung ————————————————————————————————————————————————————————————————————————————
    "wrong_tree_digest": {"grund": "does not bind THIS tree",
                          "nach_dem_signieren": lambda rc: rc.__setitem__(
                              "subject_tree_digest", "a" * 64)},
    # — Gate-Quelle ————————————————————————————————————————————————————————————————————————————
    "stale_gate_source_digest": {"grund": "gate_source_digest does not match",
                                 "nach_dem_signieren": lambda rc: rc.__setitem__(
                                     "gate_source_digest", "b" * 64)},
    # — Ausgang des Audits —————————————————————————————————————————————————————————————————————
    "wrong_exit_code": {"grund": "did not succeed",
                        "felder": {"audit_exit_code": 1}},
    # — Vertrauensanker: ohne Anker faellt es HIER, nicht am Signierer ——————————————————————————
    "kein_vertrauensanker": {"grund": "no trusted signing key pinned", "anker": "KEIN"},
    # — Signierer ——————————————————————————————————————————————————————————————————————————————
    "untrusted_signer": {"grund": "not in the trusted set", "fremder_signierer": True},
    # — Signatur: drei Formen, drei Gruende —————————————————————————————————————————————————————
    "keine_signatur": {"grund": "carries no signature",
                       "nach_dem_signieren": lambda rc: rc.pop("signature", None)},
    "tampered_signature": {"grund": "does not verify over the canonical",
                           "nach_dem_signieren": lambda rc: rc.__setitem__(
                               "signature", base64.b64encode(b"\x00" * 64).decode())},
    # ZWEI Faelle, weil die Stufe an der ZEICHENZAHL haengt und nicht an der Gueltigkeit
    # (Fremdfamilien-Gegenlesung 12.09.2026, Fund 1 — halb zutreffend, hier nachgemessen):
    # `base64.b64decode` verwirft Nicht-Alphabet-Zeichen still. `'!!!kein-base64!!!'` behaelt zehn
    # gueltige Zeichen und wirft `Incorrect padding` (Stufe 11); `'!!!!'` behaelt null und wirft
    # NICHT — die Signatur ist dann leer und faellt erst an Stufe 12. Ein Fall allein liesse
    # offen, welche der beiden Stufen er misst, und ein Zeichen mehr oder weniger verschoebe ihn
    # still auf die andere.
    "signatur_ist_kein_base64": {"grund": "signature check errored",
                                 "nach_dem_signieren": lambda rc: rc.__setitem__(
                                     "signature", "!!!kein-base64!!!")},
    "signatur_leer_nach_dem_saeubern": {"grund": "does not verify over the canonical",
                                        "nach_dem_signieren": lambda rc: rc.__setitem__(
                                            "signature", "!!!!")},
}

#: Stellen, die ueber `pre_tag_audit_gate.evaluate` NICHT erreichbar sind — mit Grund, nie stumm.
AUSGENOMMEN: dict[str, str] = {
    "receipt is not an object": (
        "Das Tor prueft die Objektform SELBST, bevor es `verify_receipt` ruft, und meldet dabei "
        "'not a JSON object'. Diese Stelle ist damit eine zweite Verteidigung fuer einen "
        "Direktaufruf der Bibliothek, ueber das Tor aber unerreichbar — der Fall `not_an_object` "
        "faehrt die vorgelagerte Pruefung und belegt, dass der Kandidat nicht stumm uebersprungen "
        "wird."),
}


def _statischer_text(knoten) -> str:
    """Nur die KONSTANTEN Teile eines Grundes — Platzhalter tragen keine Zusicherung."""
    return " ".join(k.value for k in ast.walk(knoten)
                    if isinstance(k, ast.Constant) and isinstance(k.value, str))


def _ablehnungsstellen(quelle: str, fname: str) -> tuple[list[tuple[int, str]], list[str]]:
    """Jede Stelle, an der `fname` ablehnt — plus die Ausgaenge, die dieser Zaehler NICHT lesen kann.

    ZWEI Rueckgaben, und die zweite ist der Fix zu Fund 2 der Gegenlesung: die erste Fassung
    matchte ausschliesslich `return False, "<text>"` INNERHALB der Funktion. Gemessen mit drei
    gepflanzten Formen — `raise`, `r = (False, ...); return r`, und eine ausgelagerte
    Modul-Hilfsfunktion — blieb sie dreimal gruen, weil sie die Stellen schlicht nicht sah.
    Ein Zaehler, der eine Form nicht kennt, meldet sie als NICHT VORHANDEN; das ist derselbe
    Fehler wie „nicht gemessen heisst in Ordnung".

    Gezaehlt wird jetzt ueber `verify_receipt` UND jede Modulfunktion, die es ruft. Jeder Ausgang,
    der kein `return True, ...` und keine lesbare `return False, "<text>"`-Form ist, landet in der
    zweiten Liste und macht den Riegel rot.
    """
    baum = ast.parse(quelle)
    nach_name = {n.name: n for n in baum.body if isinstance(n, ast.FunctionDef)}
    fn = nach_name[fname]
    # WELCHE gerufene Funktion ist eine PRUEFSTUFE? Die, die ein URTEIL zurueckgibt — also
    # irgendwo `return <bool>, <...>`. `canonical_bytes` wird auch gerufen, serialisiert aber nur
    # und wirft bei kaputter Eingabe; ihr `raise` ist kein Ablehnungsgrund, sondern der Fehlerpfad,
    # den `verify_receipt` in seinem try/except zu Stufe 11 macht. Die erste Fassung dieses Fixes
    # zog sie mit hinein und wurde sofort rot — an einer Stelle, die keine Pruefung ist.
    # Gemessen an der EIGENSCHAFT, nicht an der Aufrufbeziehung.
    def _faellt_ein_urteil(knoten) -> bool:
        return any(isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple)
                   and len(r.value.elts) == 2 and isinstance(r.value.elts[0], ast.Constant)
                   and isinstance(r.value.elts[0].value, bool)
                   for r in ast.walk(knoten))

    gerufen = {k.func.id for k in ast.walk(fn)
               if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in nach_name
               and _faellt_ein_urteil(nach_name[k.func.id])}
    stellen: list[tuple[int, str]] = []
    unlesbar: list[str] = []
    for name in [fname, *sorted(gerufen)]:
        ziel = nach_name[name]
        for node in ast.walk(ziel):
            if isinstance(node, ast.Raise):
                unlesbar.append(f"{name}:{node.lineno} raise")
                continue
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            wert = node.value
            if not isinstance(wert, ast.Tuple) or len(wert.elts) != 2:
                unlesbar.append(f"{name}:{node.lineno} return {type(wert).__name__}")
                continue
            erst = wert.elts[0]
            if not isinstance(erst, ast.Constant) or not isinstance(erst.value, bool):
                unlesbar.append(f"{name}:{node.lineno} return ({type(erst).__name__}, ...)")
                continue
            if erst.value is False:
                stellen.append((node.lineno, _statischer_text(wert.elts[1])))
    return stellen, unlesbar


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
        for label, fall in SHAPES.items():
            with self.subTest(shape=label):
                grundstueck = fall["grund"]
                d = _tree(anker=fall.get("anker", pub) if fall.get("anker") != "KEIN" else None,
                          git=fall.get("git", True))
                content = fall.get("roh")
                if content is None:
                    ueber = dict(fall.get("felder") or {})
                    if fall.get("echte_digests", True):
                        ueber["subject_tree_digest"] = subject_tree_digest(d)
                        ueber["gate_source_digest"] = gate_src
                    # untrusted_signer: FREMDER Schluessel bei gesetztem Anker; alle anderen der
                    # Ankerschluessel selbst, damit der Fall an SEINER Stufe faellt und an keiner davor.
                    content = _signed_receipt(None if fall.get("fremder_signierer") else priv, **ueber)
                    if fall.get("nach_dem_signieren"):
                        rc = json.loads(content)
                        fall["nach_dem_signieren"](rc)
                        content = json.dumps(rc)
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

    def test_jede_ablehnungsstelle_hat_einen_fall(self):
        """DER KLASSEN-RIEGEL: die Grundgesamtheit kommt aus der QUELLE, nicht aus dieser Datei.

        Ein Testsatz, der eine Liste von Formen aufzaehlt, ist genau so vollstaendig wie die Liste
        — und die veraltet still, sobald jemand `verify_receipt` um eine Pruefung erweitert. Diese
        Methode zaehlt deshalb per `ast` jede Stelle, die mit ``return False, <grund>`` endet, und
        verlangt je Stelle entweder einen gefahrenen Fall (sein ``grund``-Stueck kommt im
        statischen Text vor) oder einen Eintrag in `AUSGENOMMEN` mit ausgeschriebener Begruendung.

        Gemessen am 12.09.2026: ZWOELF Stellen, vier gefahren. Der Auftrag nannte drei fehlende;
        es waren acht. Genau deshalb steht hier eine Messung und keine Liste.

        Die Gegenrichtung wird mitgeprueft: ein ``grund``-Stueck, das auf KEINE Stelle passt,
        beschreibt eine Pruefung, die es nicht (mehr) gibt — ein Fall, der ins Leere zielt, ist
        gruen aus dem falschen Grund.
        """
        quelle = (REPO / "scripts" / "pre_tag_receipt_lib.py").read_text(encoding="utf-8")
        stellen, unanalysierbar = _ablehnungsstellen(quelle, "verify_receipt")
        self.assertGreaterEqual(len(stellen), 12,
                                f"nur {len(stellen)} Ablehnungsstellen gefunden — misst der Zaehler "
                                "ueberhaupt noch die richtige Funktion?")
        # FAIL-CLOSED AUF DIE FORM, die der Zaehler NICHT lesen kann (Fremdfamilien-Gegenlesung
        # 12.09.2026, Fund 2, P1 — nachgemessen mit drei gepflanzten Formen, alle drei blieben
        # gruen). Ein Ausgang, den der Riegel nicht analysieren kann, ist NICHT dasselbe wie kein
        # Ausgang: er wird gemeldet, statt still zu fehlen.
        self.assertEqual(unanalysierbar, [],
                         f"Ausgaenge, die dieser Zaehler nicht lesen kann: {unanalysierbar}. Ein "
                         "raise, eine Rueckgabe ueber eine Variable oder eine ausgelagerte "
                         "Pruefung ist eine Ablehnungsstelle wie jede andere — sie braucht "
                         "entweder eine lesbare Form oder einen eigenen Fall.")

        gruende = {label: f["grund"] for label, f in SHAPES.items()}
        ungedeckt = [(zeile, text[:70]) for zeile, text in stellen
                     if not any(g in text for g in gruende.values())
                     and not any(a in text for a in AUSGENOMMEN)]
        self.assertEqual(ungedeckt, [],
                         "Ablehnungsstellen ohne gefahrenen Fall und ohne begruendete Ausnahme — "
                         f"{ungedeckt}. Jede neue Pruefung in verify_receipt braucht eine Form in "
                         "SHAPES, sonst ist sie ungemessen.")
        blind = [g for g in gruende.values() if not any(g in text for _z, text in stellen)
                 and g not in ("unreadable", "not a JSON object")]
        self.assertEqual(blind, [],
                         f"diese Grund-Stuecke treffen KEINE Stelle in verify_receipt: {blind} — "
                         "ein Fall, der ins Leere zielt, ist gruen aus dem falschen Grund")
        # DIE ZUORDNUNG MUSS EINDEUTIG SEIN (Gegenlesung Fund 3, P2 — nachgemessen: eine zweite
        # Stelle mit demselben Teilstueck galt als gedeckt, ohne dass sie je gefahren wurde).
        # Ein Teilstring-Treffer auf ZWEI Stellen heisst: ein Fall deckt eine Stelle ab, die er
        # nie betritt. Deshalb zaehlt hier, WIE VIELE Stellen jedes Stueck trifft.
        mehrdeutig = {label: [z for z, text in stellen if g in text]
                      for label, g in gruende.items()
                      if len([z for z, text in stellen if g in text]) > 1}
        self.assertEqual(mehrdeutig, {},
                         f"diese Grund-Stuecke treffen MEHRERE Stellen: {mehrdeutig} — dann gilt "
                         "eine ungefahrene Stelle als gedeckt, weil eine andere denselben Wortlaut "
                         "traegt. Das Stueck muss die Stelle eindeutig benennen.")

    def test_META_eine_neue_pruefstufe_ohne_fall_wird_gefangen(self):
        """PLANT-AND-MUST-CATCH fuer den Riegel selbst: eine gepflanzte Ablehnungsstelle, die kein
        Fall faehrt, MUSS auffallen. Ohne diese Probe waere der Riegel oben gruen, weil er nichts
        findet — und das ist von 'er findet nichts Falsches' nicht zu unterscheiden."""
        gepflanzt = 'return False, "eine brandneue Pruefung, die niemand faehrt"'
        fn = ast.parse("def verify_receipt():\n    " + gepflanzt + "\n").body[0]
        gruende = [f["grund"] for f in SHAPES.values()]
        texte = []
        for node in ast.walk(fn):
            if (isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple)
                    and isinstance(node.value.elts[0], ast.Constant)
                    and node.value.elts[0].value is False):
                texte.append(node.value.elts[1].value)
        self.assertTrue(texte, "die Pflanzprobe hat selbst nichts erzeugt")
        self.assertFalse(any(g in texte[0] for g in gruende),
                         "die gepflanzte Stufe waere von einem bestehenden Fall gedeckt — dann "
                         "misst der Riegel oben nicht, was er zu messen vorgibt")

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
