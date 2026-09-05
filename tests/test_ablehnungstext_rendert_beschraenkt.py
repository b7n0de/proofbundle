"""Der Ablehnungstext darf nicht härter scheitern als die Prüfung, die er erklärt.

DIE KLASSE (Deep-Gate 6.0.0, Lauf 3, Funde L2-BDOS-RENDER-NEIGHBOURS-01 P2, L3-600-01 P2, L3-600-03 P3;
Ledger-Klassen ``rejection_message_renders_caller_value_unbounded_on_never_raise_surface`` und die Render-Hälfte
von ``MAGNITUDEN-SCHRANKE-LEBT-IN-EINER-FUNKTION-STATT-IM-BUDGET``). Vier Stellen in ``bundle.py``
(``schema``, ``signature.alg``, ``merkle.hash_alg``, ``anchors[].target``), ``anchors.verify_anchor`` (``type``),
``hashalg.verify_dual_hash`` (Check-Name und Meldung) und ``_reject_unknown`` interpolierten einen vom Aufrufer
gelieferten Wert ROH in den Text der Ablehnung — ``{wert!r}`` bzw. ``sorted(extra)``. Auf dem direct-dict-Pfad
kann dieser Wert ein Integer mit 5000 Ziffern sein (CPythons int->str-Kappe, CVE-2020-10735: roher ValueError),
ein Tupel, das einen enthält, oder eine Schlüsselmenge gemischten Typs (roher TypeError aus ``sorted``). Die
Prüfung selbst hätte sauber abgelehnt; ihre ERKLÄRUNG stürzte ab — aus Flächen, deren Vertrag „typisiert oder
Verdikt, nie roh" lautet, und über ``decision.verify_decision_receipt(anchors=...)`` aus einer dokumentierten
never-raise-Fläche heraus.

DREI TEILE, weil einer nicht reicht (Muster des Hauses):

  1. VERHALTEN — die Reproducer des Gates, je Stelle: rot vor dem Fix, grün danach.
  2. MECHANISMUS — die Klasse ist an ZWEI Chokepoints geschlossen, nicht an neun Stellen: die
     Ganzzahl-Magnitude ist eine Dimension des Struktur-Budgets (``enforce_structural_budget`` weist einen
     Integer über ``int_bits`` ab, bevor irgendeine Meldung ihn rendert), und ``budget.render_safe`` /
     ``render_keys_safe`` sind der EINE beschränkte Renderer, der nie wirft. Der Riegel darunter prüft
     strukturell, dass kein ``sorted`` mehr über eine Fremdschlüsselmenge läuft.
  3. ANTI-TAUTOLOGIE — der Renderer wird mit feindlichen Werten gefüttert (rekursiv, riesig verschachtelt,
     bösartiges ``__repr__``), und ein gepflanzter roher Sortierer MUSS vom Riegel gefangen werden.

EHRLICHE GRENZE des Riegels: er erkennt die Form ``sorted(set(x) - …)`` / ``sorted(extra|unknown)`` im
Quelltext. Eine Interpolation ``{wert!r}`` prüft er NICHT strukturell — davon gibt es rund 190 im Paket, die
meisten über Werte, die ``loads_strict`` bereits auf 4300 Ziffern, ``json_depth`` und ``string_len`` begrenzt.
Der direct-dict-Pfad ist über den Budget-Chokepoint geschlossen; die verbleibende Lücke sind RP-Kwargs, die
ohne Budget interpoliert werden (die genannten sind umgestellt, siehe ``test_rp_kwarg_typboden_familie``).
"""
from __future__ import annotations

import ast
import pathlib
import unittest

import proofbundle as pb
from proofbundle import anchors, decision, hashalg
from proofbundle.budget import DEFAULT_BUDGET, render_keys_safe, render_safe
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError, ProofBundleError

QUELLE = pathlib.Path(pb.__file__).resolve().parent
RIESE = 10 ** 5000                      # > 4300 Ziffern UND > int_bits


def _bundle(**over):
    b = emit_bundle(b'{"hello":"world"}', generate_signer())
    b.update(over)
    return b


class DieAblehnungBleibtTypisiert(unittest.TestCase):
    """TEIL 1 — VERHALTEN. Jede Probe des Gates, je Stelle; der Ausgang ist typisiert oder ein Verdikt."""

    def test_verify_bundle_schema_riesig(self):
        with self.assertRaises(ProofBundleError):
            pb.verify_bundle(_bundle(schema=RIESE))

    def test_verify_bundle_signature_alg_riesig(self):
        b = _bundle()
        b["signature"]["alg"] = RIESE
        with self.assertRaises(ProofBundleError):
            pb.verify_bundle(b)

    def test_verify_bundle_merkle_hash_alg_riesig(self):
        b = _bundle()
        b["merkle"]["hash_alg"] = RIESE
        with self.assertRaises(ProofBundleError):
            pb.verify_bundle(b)
        with self.assertRaises(ProofBundleError):
            pb.recompute_merkle_root_b64(b)

    def test_verify_bundle_anchor_target_riesig(self):
        with self.assertRaises(ProofBundleError):
            pb.verify_bundle(_bundle(anchors=[{"target": RIESE}]))

    def test_verify_bundle_gemischte_schluessel(self):
        """Der L3-600-03-Fall: ``sorted`` über {5, "zzz"} hob einen rohen TypeError."""
        with self.assertRaises(BundleFormatError) as cm:
            pb.verify_bundle({**_bundle(), 5: 1, "zzz": 1})
        self.assertIn("unknown field(s)", str(cm.exception))
        self.assertIn("'zzz'", str(cm.exception))
        b = _bundle()
        b["signature"] = {**b["signature"], 7: 1, "zzz": 1}
        with self.assertRaises(BundleFormatError):
            pb.verify_bundle(b)

    def test_verify_anchor_typ_riesig_ist_typisiert(self):
        with self.assertRaises(ProofBundleError):
            anchors.verify_anchor({"type": RIESE, "target": "receipt"}, target_roots={"receipt": b"\0" * 32})

    def test_verify_anchor_typ_container_ist_verdikt(self):
        """Ein Container statt einer Zahl läuft am Budget vorbei und trifft die Render-Stelle direkt."""
        res = anchors.verify_anchor({"type": [[["tief"]] * 3] * 3, "target": "receipt"},
                                    target_roots={"receipt": b"\0" * 32})
        self.assertFalse(res["ok"])
        self.assertIn("no verifier registered", res["detail"])

    def test_verify_dual_hash_riesiger_schluessel(self):
        for digests in ({RIESE: "aa"}, {(RIESE,): "aa"}):
            with self.subTest(schluessel=type(next(iter(digests))).__name__):
                res = hashalg.verify_dual_hash(b"x", digests)
                self.assertFalse(res.ok)
                self.assertTrue(res.checks[0].name.startswith("hashalg:"))
                self.assertIn("bits>", res.checks[0].name)

    def test_verify_dual_hash_normaler_name_unveraendert(self):
        """ANTI-PARITÄT: der Check-Name eines echten Algorithmus ist byte-identisch zu vorher."""
        import hashlib
        res = hashalg.verify_dual_hash(b"x", {"sha256": hashlib.sha256(b"x").hexdigest(),
                                              "sha512": hashlib.sha512(b"x").hexdigest()})
        self.assertEqual([c.name for c in res.checks], ["hashalg:sha256", "hashalg:sha512"])
        self.assertTrue(res.ok)

    def test_decision_verify_mit_riesigem_ankertyp_liefert_verdikt(self):
        """Die öffentliche never-raise-Fläche: anchors_ok=False, nie eine rohe Ausnahme."""
        sig = generate_signer()
        env = decision.emit_decision_receipt(_PREDICATE, sig, strict=True)
        pub = sig.public_key().public_bytes_raw()
        r = decision.verify_decision_receipt(env, pub, anchors=[{"type": RIESE, "target": "statement"}])
        self.assertIs(r["anchors_ok"], False)
        self.assertFalse(r["ok"])
        self.assertTrue(any("anchor" in e for e in r["errors"]))

    def test_decision_validate_gemischte_schluessel(self):
        errs = decision.validate_decision_predicate({**_PREDICATE, 5: 1, "zzz": 1})
        self.assertTrue(any("unknown top-level field(s)" in e for e in errs))


class DerMechanismusSitztAmChokepoint(unittest.TestCase):
    """TEIL 2 — MECHANISMUS."""

    def test_struktur_budget_weist_riesige_integer_ab(self):
        from proofbundle._strict_json import enforce_structural_budget
        # DAS LABEL DARF NICHT DIE KLASSE AUSLOESEN, DIE DER TEST MISST. Die erste Fassung schrieb
        # `str(obj)[:20]` — und `str()` auf einem Dict, das RIESE traegt, hebt exakt den ValueError, gegen
        # den dieser Test steht. Ein Eigentor derselben Klasse, im Test statt im Code; deshalb hier ein
        # festes Label statt einer Wiedergabe des Wertes.
        for label, obj in (("Wert", {"schema": RIESE}), ("in Tupel", {"a": [1, {"b": (RIESE,)}]}),
                           ("als Schluessel", {RIESE: 1}), ("in Liste", [RIESE])):
            with self.subTest(fall=label):
                with self.assertRaises(ProofBundleError):
                    enforce_structural_budget(obj)

    def test_die_schranke_gilt_fuer_BEIDE_pfade_und_das_ist_die_entscheidung(self):
        """DIE VEREINHEITLICHUNG, benannt statt als Nebenwirkung mitgenommen.

        Der Fund betraf den direct-dict-Pfad. Die Schranke sitzt aber am gemeinsamen Chokepoint, also gilt
        sie auch für den DATEI-Pfad — und dort ist sie STRENGER als die Kappe des Parsers: ``int_bits``
        (8192 Bit) entspricht rund 2466 Dezimalziffern, CPythons ``int``/``str``-Kappe liegt bei 4300
        Ziffern. Ein Literal dazwischen wurde vorher geparst und wird jetzt typisiert abgewiesen.

        Das ist Absicht. Zwei Schranken für dieselbe Größe wären genau die Drift, die der Ledger-Eintrag
        ``MAGNITUDEN-SCHRANKE-LEBT-IN-EINER-FUNKTION-STATT-IM-BUDGET`` beschreibt: ``bundle._require_int``
        trug 8192 Bit seit L2-BDOS-01, die drei argument-nehmenden Flächen bekamen sie erst einen Monat
        später. Eine echte Baumgröße liegt unter 2**64, ein Zeitstempel unter 2**63; 8192 Bit sind
        astronomisch großzügig. Diese Zeile hält die Grenze fest, damit eine spätere Änderung sie nicht
        stillschweigend verschiebt.
        """
        from proofbundle._strict_json import loads_strict
        self.assertEqual(DEFAULT_BUDGET.int_bits, 8192)
        loads_strict('{"x": %s}' % ("9" * 2400))                     # unter der Schranke: geparst
        with self.assertRaises(ProofBundleError):
            loads_strict('{"x": %s}' % ("9" * 3000))                  # darüber: typisiert, vorher geparst
        with self.assertRaises(ProofBundleError):
            loads_strict('{"x": %s}' % ("9" * 4200))                  # unter der Parser-Kappe, über unserer

    def test_die_inklusionspruefung_hebt_keine_ausnahme(self):
        """Gegenprobe zur un-Gegenlesung: sie las den Wechsel auf ``merkle.verify_inclusion`` als möglichen
        Regressionspfad („ein ValueError wird nun vom äußeren except gefangen"). Gemessen gibt es diesen
        Pfad nicht — ``verify_inclusion`` fängt selbst und liefert ``False``. Der Wechsel ist damit auch
        in der Ausnahme-Achse verhaltensgleich, nicht nur im Verdikt."""
        from proofbundle import merkle
        for args in ((b"x", 5, 2, [], b"\0" * 32), (b"x", 0, 2, [b"\0" * 32] * 3, b"\0" * 32),
                     (b"x", 0, 8, [], b"\0" * 32), (b"x", 0, 1, [], "kein bytes"),
                     (b"x", "a", 1, [], b"\0" * 32), (b"x", 0, 1, "abc", b"\0" * 32)):
            with self.subTest(fall=str(args[1:3])):
                self.assertIs(merkle.verify_inclusion(*args), False)

    def test_struktur_budget_laesst_reale_integer_durch(self):
        """ANTI-PARITÄT: 2**64 (Baumgröße), 2**63-1 (Zeitstempel), bool — alles unter der Schranke."""
        from proofbundle._strict_json import enforce_structural_budget
        enforce_structural_budget({"tree_size": 2 ** 64, "ts": 2 ** 63 - 1, "flag": True,
                                   "knapp": 2 ** DEFAULT_BUDGET.int_bits - 1})

    def test_der_renderer_wirft_nie(self):
        class Boese:
            def __repr__(self):
                raise RuntimeError("boom")

        class BoeserTyp:
            @property
            def __class__(self):
                raise RuntimeError("auch das")

        rekursiv: list = []
        rekursiv.append(rekursiv)
        tief: dict = {}
        cur = tief
        for _ in range(5000):
            cur["a"] = {}
            cur = cur["a"]
        for wert in (RIESE, (RIESE,), {"a": [RIESE]}, Boese(), BoeserTyp(), rekursiv, tief,
                     "x" * 100_000, [RIESE] * 10_000, {i: i for i in range(10_000)}):
            with self.subTest(typ=type(wert).__name__):
                s = render_safe(wert)
                self.assertIsInstance(s, str)
                self.assertLessEqual(len(s), 512)
                self.assertNotIn("0" * 100, s)

    def test_der_renderer_ist_fuer_gewoehnliche_werte_byteidentisch(self):
        for wert in ("text", 1000, None, True, ("a", 1), ["b"], {"k": "v"}, 2 ** 64, b"bytes"):
            with self.subTest(wert=wert):
                self.assertEqual(render_safe(wert), repr(wert))
        self.assertEqual(render_safe("roh", quote=False), "roh")
        self.assertEqual(render_safe(7, quote=False), "7")

    def test_render_keys_safe_sortiert_gerendert(self):
        self.assertEqual(render_keys_safe({"b", "a"}), ["'a'", "'b'"])
        self.assertEqual(render_keys_safe({5, "zzz"}), ["'zzz'", "5"])
        self.assertEqual(render_keys_safe({RIESE}), ["<int, 16610 bits>"])
        self.assertEqual(render_keys_safe(5), ["<unrenderable keys>"])   # nicht iterierbar

    def test_kein_sorted_ueber_fremdschluessel_im_paket(self):
        """DER RIEGEL: die Form ``sorted(set(x) - …)`` / ``sorted(extra|unknown)`` darf im Paket nicht mehr
        vorkommen — jeder Fund ist eine Instanz der Klasse L3-600-03, nicht nur die eine in bundle.py."""
        funde = _rohe_sortierer(QUELLE)
        self.assertEqual(funde, [], "sorted() über eine ungerenderte Schlüsselmenge:\n  " + "\n  ".join(funde))


def _kwargs_namen(tree: ast.AST) -> set[str]:
    """Die ``**kwargs``-Parameter aller Funktionen einer Datei.

    WARUM DIESE AUSNAHME EINE EIGENSCHAFT IST UND KEINE NAMENSLISTE: Python garantiert, dass die Schlüssel
    eines ``**kw`` Strings sind — eine Menge daraus KANN nicht gemischt typisiert sein, und ``sorted``
    darüber kann strukturell nicht werfen. Der Riegel hat diese Stelle beim ersten Lauf gemeldet
    (``agent_review.verify_agent_review_any``), und die bequeme Antwort wäre gewesen, ihren Namen
    einzutragen. Ein Riegel, der je Fund um den gefundenen Namen wächst, misst am Ende die Liste seiner
    Funde statt eine Eigenschaft; also lernt er stattdessen die Regel, die den Fall wirklich erklärt.
    """
    namen = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.args.kwarg:
            namen.add(node.args.kwarg.arg)
    return namen


def _rohe_sortierer(wurzel: pathlib.Path) -> list[str]:
    """Alle ``sorted(...)``-Aufrufe, deren Argument eine Mengen-Differenz oder ein Name ``extra``/``unknown``
    ist — die Form, in der sieben Stellen die rohen Schlüssel ordneten. Modulqualifiziert und SORTIERT
    gemeldet (``ast.walk`` läuft in Breitensuche, die Fundreihenfolge wäre sonst nicht die Zeilenordnung)."""
    funde = []
    for p in sorted(wurzel.rglob("*.py")):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        kwargs_namen = _kwargs_namen(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "sorted"
                    and node.args):
                continue
            arg = node.args[0]
            roh = False
            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Sub):
                links = arg.left
                while isinstance(links, ast.BinOp) and isinstance(links.op, ast.Sub):
                    links = links.left
                if isinstance(links, ast.Call) and isinstance(links.func, ast.Name) and links.func.id == "set":
                    inner = links.args[0] if links.args else None
                    # `set(kw) - …` über einem **kwargs-Parameter: Schlüssel sind per Sprache str
                    roh = not (isinstance(inner, ast.Name) and inner.id in kwargs_namen)
            elif isinstance(arg, ast.Name) and arg.id in ("extra", "unknown"):
                roh = True
            if roh:
                funde.append(f"{p.relative_to(wurzel)}:{node.lineno}")
    return sorted(funde)


class DerRiegelKannRotWerden(unittest.TestCase):
    """TEIL 3 — ANTI-TAUTOLOGIE."""

    def test_ein_gepflanzter_roher_sortierer_wird_gefangen(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            wurzel = pathlib.Path(d)
            (wurzel / "opfer.py").write_text(
                "def f(obj, allowed):\n"
                "    extra = set(obj) - allowed\n"
                "    if extra:\n"
                "        raise ValueError(f'unknown {sorted(extra)}')\n"
                "def g(td):\n"
                "    return sorted(set(td) - {'a'})\n", encoding="utf-8")
            (wurzel / "sauber.py").write_text(
                "from x import render_keys_safe\n"
                "def f(obj, allowed):\n"
                "    return render_keys_safe(set(obj) - allowed)\n"
                "def h(xs):\n"
                "    return sorted(xs, key=str)\n"
                "def k(**kw):\n"
                "    return sorted(set(kw) - {'a'})\n", encoding="utf-8")
            funde = _rohe_sortierer(wurzel)
        # nur die beiden gepflanzten Stellen — die **kwargs-Form in sauber.py:7 ist KEIN Fund,
        # und die gerenderte Form ebenso wenig (sonst wäre der Riegel ein Dauer-Rot)
        self.assertEqual(funde, ["opfer.py:4", "opfer.py:6"])

    def test_die_verhaltensprobe_unterscheidet_den_alten_stand(self):
        """Ein Renderer, der die Magnitude NICHT kennt, würde für RIESE genau den rohen ValueError heben,
        den die Klasse beschreibt — die Probe misst also die Eigenschaft, nicht nur „kein Absturz"."""
        with self.assertRaises(ValueError):
            repr(RIESE)
        self.assertNotIn("0" * 50, render_safe(RIESE))


_PREDICATE = {
    "schemaVersion": "0.1.0", "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000000",
    "decisionType": "preActionAuthorization", "decidedAt": "2026-01-01T00:00:00Z",
    "decisionMaker": {"id": "https://example.org/gate/v1", "version": {"proofbundle": "x"}},
    "agent": {"id": "agent://example/agent", "version": "0"}, "principal": {"id": "workload://example/p"},
    "proposedAction": {"actionType": "tool.call", "target": {"name": "mcp://x", "uri": "mcp://x"},
                       "method": "POST", "parametersDigest": {"sha256": "0" * 64}},
    "inputSnapshot": [{"name": "input", "uri": "urn:proofbundle:input:0", "digest": {"sha256": "0" * 64},
                       "mediaType": "application/json"}],
    "policyBoundary": {"policyEngine": "opa", "policyId": "https://example.org/policy/v1",
                       "policyDigest": {"sha256": "0" * 64}, "decisionPath": "data.x.allow"},
    "evidenceRefs": [], "decision": {"verdict": "DENY", "reasonCodes": ["x"], "humanReadableSummary": "",
                                     "obligations": [], "allowedScope": []},
    "notChecked": [{"field": "x", "reason": "t", "impact": ""}],
    "decisionChangeConditions": [{"conditionType": "additionalApproval", "description": "",
                                  "requiredEvidenceType": "approvalReceipt"}],
    "privacy": {"rawInputsIncluded": False, "redactionProfile": "https://example.org/r/v1", "erased": [],
                "masked": []},
}


if __name__ == "__main__":
    unittest.main()
