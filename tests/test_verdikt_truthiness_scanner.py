"""A new site that reads `passed` as a truth value must become a finding, not a quiet regression.

WHY A SCANNER AND NOT ONLY THE PROPERTY TEST. `tests/test_das_verdikt_muss_ein_bool_sein.py` pins the
MONOTONICITY of the emit path, so a seventh site added behind one of the guarded entry points breaks it.
A site added somewhere ELSE — a new exporter, a new adapter, a CLI path — would not be behind those
entry points and the property test would stay green while the class came back. That is the shape the
sibling class already paid for: `_membership.py` says it in its own docstring, after this repository
fixed the same assumption three times at three call sites.

WHAT IT LOOKS FOR. A read of the literal key ``"passed"``, in a function that does not establish the
field's type, used in either of the two ways that DEPEND on that type:

1. AS A TRUTH VALUE -- wrapped in ``bool(...)``, an ``if``/``while`` condition, negated with ``not``, a
   ternary condition, an operand of ``and``/``or``, a comprehension guard.
2. PASSED THROUGH -- the value flows OUT of the function with its type unestablished: as a value in a
   dict literal, an element of a list/tuple/set, an argument to a call, or a returned expression.

THE SECOND KIND WAS ADDED AFTER IT COST A SITE, and that is the reason it is here rather than in the
list of known holes below. The first version of this file looked only for truthiness contexts and
therefore reported nothing about ``sdjwt_issue.issue_sd_jwt``, which did ``"passed": claim["passed"]``
into the always-open claims of an SD-JWT and then SIGNED them. No ``bool()``, no ``if`` -- and the worst
outcome of the six, because the artefact leaves the process with a valid signature over a value that is
not a verdict, and every downstream reader that tests truthiness reads it as a pass. A scanner that
models the class as "coercion" misses the case where the coercion happens in someone else's code.

Kind 2 deliberately does NOT include a comparison: ``claim["passed"] == True`` is type-safe (a string
is simply unequal) and flagging it would push authors toward the truthy form this file exists to
discourage.

ALIASING IS RESOLVED ONE LEVEL, and that closed a hole this file never stated. ``v = claim["passed"]``
followed by ``if v:`` escaped the first version completely: the truthiness test saw a bare ``Name`` and
the key-read test answered no. Measured 2026-09-24 on a planted case -- empty finding set. A single
assignment now carries the reference, in both directions: a read THROUGH the alias is found, and an
``isinstance(v, bool)`` ON the alias counts as establishing it (which is how
``evalclaim.eval_evidence_class`` is correctly quiet rather than a false red).

STATED REACH, AND IT IS A REAL HOLE, not a formality:

* A field read through a VARIABLE KEY (``schluessel = "passed"``; ``claim[schluessel]``) escapes it.
  This is the key being indirect, not the value; the alias resolution above does not reach it.
* TWO OR MORE levels of aliasing escape it (``a = claim["passed"]``; ``b = a``; ``if b:``).
* A DIFFERENT verdict-bearing field escapes it. The scanner knows one key name, not the concept.
* A truth-value read via ``operator.truth`` or ``filter`` escapes it.

So this is a guard against the shapes that occurred plus the two that measurement added, not a proof
that the class is gone. The honest protection is the pair: this scanner for new sites, the property test
for new paths behind old sites. The baseline below is a LIST OF KNOWN GAPS rather than a permission:
every entry names why it is allowed to stand, and an entry that no longer exists makes this file fail
rather than shrinking in silence.
"""
import ast
import pathlib
import unittest

QUELLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

#: The helpers that ESTABLISH the type. A function that calls one of these may then read the field
#: however it likes — that is the whole point of a shared predicate.
#:
#: `_require_export_fields` is in here because it CALLS `_require_bool_verdict` (intoto.py, measured
#: 2026-09-24), not because of its name. A name on this list that does not actually establish the type
#: would be the exact defect this file is about, one level up — so each entry is a measurement.
ETABLIERER = {"is_bool", "_require_bool_verdict", "_require_export_fields"}

#: Sites that read the field as a truth value and are allowed to, each with its reason. The key is
#: (relative path, enclosing definition) so a line shift does not break the file.
GRUNDLINIE = {
    ("intoto.py", "export_svr_dsse"):
        "runs AFTER decode_eval_claim, which now refuses a non-boolean `passed` at the verify "
        "boundary, so the value reaching this line is already a bool. Kept in the baseline rather "
        "than guarded twice, because a second check here would suggest the first one is not trusted.",
    ("hf_evals.py", "verify_eval_results_entry"):
        "calls decode_eval_claim(bundle) before reading the field, so the A-15 boundary has already "
        "refused a non-boolean. The `bool(...)` wrapper around it is redundant rather than wrong, and "
        "it is left alone because removing it is a separate change with its own measurement.",
    ("hf_evals.py", "to_eval_results_entry"):
        "same shape and same reason: decode_eval_claim runs first. Its own comment already states "
        "that argument for the comparator and the threshold, which is the sibling case of this one.",
    ("cli.py", "_cmd_show_eval"):
        "the ONLY site the pass-through kind added, and it is a display line. Two reasons, both "
        "measured: the claim comes from decode_eval_claim and the function returns 1 when that is "
        "None (cli.py:406), so the A-15 boundary has already typed the field; and the use is "
        "`_s(claim['passed'])` = `_safe_line(str(...))` into a printed line, which cannot turn a "
        "non-pass into a pass — a string verdict would be PRINTED as that string, which is honest "
        "output rather than a coerced one. It stays in the baseline instead of being guarded, because "
        "a guard here would suggest the decode boundary is not trusted.",
}

# THESE TWO ENTRIES ARRIVED BY A REVIEWER'S QUESTION, and they arrived together with a defect in this
# scanner. Asked to name a shape in this repository that carries a verdict and escapes the scan, the
# cross-reading pointed at `hf_evals.py`. Measured, it does not escape the scan; it escaped the
# GUARD, because `_etabliert_den_typ` accepted any `isinstance(..., bool)` in the enclosing function
# and both functions carry one about a different variable. The question was about that file and the
# answer was about this one.

# WHAT THIS BASELINE LOOKED LIKE FIRST, because the correction is the argument for the stale-entry
# case. It also carried ("evalclaim.py", "eval_evidence_class") with the reason that the function
# checks `isinstance(passed, bool)` inline. True, and therefore WRONG as a baseline entry: because it
# establishes the type, the scanner never flags it, so the entry named a gap that did not exist. A
# baseline that lists non-gaps grows into a list of permissions nobody re-reads.
# `test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt` caught it on the first run.


def _dateien() -> dict[str, str]:
    return {str(p.relative_to(QUELLE)): p.read_text(encoding="utf-8")
            for p in sorted(QUELLE.rglob("*.py"))}


def _schluesselbezug(knoten: ast.AST) -> tuple[str, str] | None:
    """(object source, key) for a read of a literal key, or None.

    NORMALISED ACROSS THE TWO SPELLINGS, and that is a CORRECTION this file's own anti-parity case
    forced. The first version compared the unparsed SOURCE of the two expressions, so
    `claim.get("passed")` in the guard and `claim["passed"]` in the read counted as different
    expressions and the guarded form was reported. They are the same field of the same object written
    two ways; comparing the spelling would have made this scanner reject the very shape it asks for.
    """
    if isinstance(knoten, ast.Subscript) and isinstance(knoten.slice, ast.Constant):
        return ast.unparse(knoten.value), knoten.slice.value
    if isinstance(knoten, ast.Call):
        f = knoten.func
        if (isinstance(f, ast.Attribute) and f.attr == "get" and knoten.args
                and isinstance(knoten.args[0], ast.Constant)):
            return ast.unparse(f.value), knoten.args[0].value
    return None


def _aliase(fn: ast.AST) -> dict[str, tuple[str, str]]:
    """Names bound ONCE to a keyed read: ``wert = claim.get("passed")`` -> {"wert": ("claim", "passed")}.

    A name assigned MORE THAN ONCE is dropped rather than kept with the first binding. Keeping it would
    let ``v = claim["passed"]`` followed by ``v = something_else`` claim a reference the value no longer
    has, which is a guess dressed as a measurement — and this file's whole subject is a check bound to a
    form instead of to the thing.
    """
    treffer: dict[str, tuple[str, str]] = {}
    mehrfach: set[str] = set()
    for k in ast.walk(fn):
        if isinstance(k, ast.Assign) and len(k.targets) == 1 and isinstance(k.targets[0], ast.Name):
            name = k.targets[0].id
            if name in treffer or name in mehrfach:
                mehrfach.add(name)
                treffer.pop(name, None)
                continue
            bezug = _schluesselbezug(k.value)
            if bezug is not None:
                treffer[name] = bezug
        elif isinstance(k, (ast.AugAssign, ast.AnnAssign)) and isinstance(k.target, ast.Name):
            mehrfach.add(k.target.id)
            treffer.pop(k.target.id, None)
    return treffer


def _bezug(knoten: ast.AST, aliase: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """(object source, key) for a direct keyed read OR for a name aliased to one."""
    direkt = _schluesselbezug(knoten)
    if direkt is not None:
        return direkt
    if isinstance(knoten, ast.Name):
        return aliase.get(knoten.id)
    return None


def _liest_passed(knoten: ast.AST, aliase: dict[str, tuple[str, str]] | None = None) -> bool:
    """Is this expression a read of the literal key ``passed``, directly or through one alias?"""
    b = _bezug(knoten, aliase or {})
    return b is not None and b[1] == "passed"


def _wahrheitswertig(baum: ast.AST) -> list[ast.AST]:
    """Every expression in `baum` that is used AS A TRUTH VALUE."""
    aus: list[ast.AST] = []
    for k in ast.walk(baum):
        if isinstance(k, (ast.If, ast.While)):
            aus.append(k.test)
        elif isinstance(k, ast.IfExp):
            aus.append(k.test)
        elif isinstance(k, ast.UnaryOp) and isinstance(k.op, ast.Not):
            aus.append(k.operand)
        elif isinstance(k, ast.BoolOp):
            aus.extend(k.values)
        elif (isinstance(k, ast.Call) and isinstance(k.func, ast.Name)
              and k.func.id == "bool" and k.args):
            aus.append(k.args[0])
        elif isinstance(k, ast.comprehension):
            aus.extend(k.ifs)
    return aus


def _durchgereicht(baum: ast.AST) -> list[ast.AST]:
    """Every expression in `baum` that LEAVES the function with its type unexamined.

    THE KIND THAT COST A SITE. ``issue_sd_jwt`` wrote ``"passed": claim["passed"]`` into a dict it then
    signed — a dict VALUE, and nothing a truthiness scan can see. The four shapes here are the ways a
    value gets out of a function: into a mapping, into a sequence, into a call, or as the return value.

    ``isinstance`` is excluded because a value handed to it is being examined, not passed on; that is the
    opposite of this kind. The ``ETABLIERER`` are excluded for the same reason.
    """
    aus: list[ast.AST] = []
    for k in ast.walk(baum):
        if isinstance(k, ast.Dict):
            aus.extend(w for w in k.values if w is not None)
        elif isinstance(k, (ast.List, ast.Tuple, ast.Set)):
            aus.extend(k.elts)
        elif isinstance(k, ast.Return) and k.value is not None:
            aus.append(k.value)
        elif isinstance(k, ast.Call):
            name = (k.func.id if isinstance(k.func, ast.Name)
                    else k.func.attr if isinstance(k.func, ast.Attribute) else "")
            if name in ETABLIERER or name == "isinstance":
                continue
            aus.extend(k.args)
            aus.extend(w.value for w in k.keywords)
    return aus


def _definitionen(baum: ast.Module) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [k for k in ast.walk(baum)
            if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _etabliert_den_typ(fn: ast.AST, ausdruck: ast.AST) -> bool:
    """Does this function establish the type OF THIS EXPRESSION?

    BOUND TO THE SAME EXPRESSION, and that is a CORRECTION of this scanner's first version, which
    fell into the class it exists against. It accepted ANY `isinstance(..., bool)` anywhere in the
    enclosing function, which is a FORM, not the property. Measured on 2026-09-24 in
    `src/proofbundle/hf_evals.py`: `verify_eval_results_entry` reads `bool(claim["passed"])` at line
    171 and carries `isinstance(_val, bool)` at line 149, about the PUBLISHED VALUE; the scanner read
    that as "the type is established" and reported nothing. `to_eval_results_entry` is the same shape
    at lines 241 and 213, where the checked name is `value`.

    So two real sites of this class were passing, for the reason the class is about: a check bound to
    a shape instead of to the thing. The reviewer asked one question about `hf_evals.py`, and
    following it found the defect in my own guard rather than in that file.

    `is_bool` and `_require_bool_verdict` still count wherever they appear, because both take the
    CLAIM and answer for its verdict field; there is no other expression they could be about.
    """
    aliase = _aliase(fn)
    ziel = _bezug(ausdruck, aliase)
    # EIN ETABLIERER, DESSEN RUECKGABEWERT WEGGEWORFEN WIRD, ETABLIERT NICHTS FUER EIN ZWEITES LESEN —
    # und diese Regel ist die Rechnung fuer einen Review-Fund vom 24.09.2026 (PR 257, P2), der eine
    # Annahme DIESER Datei widerlegt hat. `_schluesselbezug` normalisiert `claim.get("passed")` und
    # `claim["passed"]` zu einer Stelle, weil sie fuer ein dict dasselbe sind. Fuer eine UNTERKLASSE
    # sind sie es nicht: gemessen mit einem dict, dessen `get("passed")` True liefert, waehrend das
    # Element `"false"` ist, ging `_require_export_fields` durch (es prueft ueber `get`) und
    # `to_eval_result_predicate` gab die Zeichenkette aus (es las ueber `[]`). Der Scanner sah dort
    # nichts, weil er die Normalisierung fuer harmlos hielt.
    #
    # Die Normalisierung BLEIBT — ohne sie waere die geforderte Form selbst ein Befund. Was hinzukommt
    # ist der Unterschied zwischen PRUEFEN und WEITERGEBEN: wird der geprueften Wert nicht gebunden,
    # ist jedes spaetere Lesen ein ZWEITES Lesen, und ob die zwei Zugriffe uebereinstimmen, ist eine
    # Eigenschaft des uebergebenen Objekts und nicht des Codes.
    verworfen = {id(s.value) for s in ast.walk(fn) if isinstance(s, ast.Expr)}
    for k in ast.walk(fn):
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in ETABLIERER
                and id(k) not in verworfen):
            return True
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr in ETABLIERER and id(k) not in verworfen):
            return True
        # An inline `isinstance(<the same expression>, bool)` counts too: it establishes the same
        # thing, and demanding the shared helper would be a style rule dressed up as a safety one.
        # It must be the SAME FIELD OF THE SAME OBJECT, compared as (object source, key), so
        # `claim["passed"]` and `claim.get("passed")` count as one while `_val` and `value` do not.
        # RESOLVED THROUGH ONE ALIAS on both sides, which is how `eval_evidence_class` -- it assigns
        # `passed = claim.get("passed")` and then checks `isinstance(passed, bool)` -- is correctly
        # quiet. Without that resolution the widened scan would have reported a function that does
        # exactly the right thing, and a false red teaches readers to widen the baseline.
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "isinstance"
                and len(k.args) == 2 and isinstance(k.args[1], ast.Name)
                and k.args[1].id == "bool" and _bezug(k.args[0], aliase) == ziel):
            return True
    return False


def _stellen(quelltexte: dict[str, str] | None = None) -> dict[tuple[str, str], list[int]]:
    """(file, enclosing definition) -> line numbers, for every unguarded read of `passed`.

    Both kinds, in one set: a truthiness read and a pass-through are the same violated assumption, and
    reporting them separately would invite closing one list and calling the class handled.
    """
    texte = _dateien() if quelltexte is None else quelltexte
    if not texte:
        raise AssertionError("no source files read — an empty scan is not a clean one")
    gefunden: dict[tuple[str, str], list[int]] = {}
    for name, text in texte.items():
        baum = ast.parse(text)
        for fn in _definitionen(baum):
            aliase = _aliase(fn)
            for ausdruck in (*_wahrheitswertig(fn), *_durchgereicht(fn)):
                if _liest_passed(ausdruck, aliase) and not _etabliert_den_typ(fn, ausdruck):
                    gefunden.setdefault((name, fn.name), []).append(ausdruck.lineno)
    return gefunden


class TestKeineNeueUngeschuetzteStelle(unittest.TestCase):
    def test_keine_stelle_ausserhalb_der_grundlinie(self):
        ueberzaehlig = {k: v for k, v in _stellen().items() if k not in GRUNDLINIE}
        self.assertEqual(
            ueberzaehlig, {},
            "a truthy read of `passed` in a function that does not establish the type: "
            f"{ueberzaehlig}. Route it through `_require_bool_verdict`, or add it to GRUNDLINIE "
            "with the reason it may stand.")

    def test_die_grundlinie_traegt_keine_stelle_die_es_nicht_mehr_gibt(self):
        """A baseline entry for a site that is gone is a gap that quietly turned into a permission."""
        vorhanden = set(_stellen())
        veraltet = [k for k in GRUNDLINIE if k not in vorhanden]
        self.assertEqual(veraltet, [], f"GRUNDLINIE names sites that no longer read `passed` "
                                       f"truthily: {veraltet}. Remove them.")

    def test_jede_grundlinienzeile_traegt_eine_begruendung(self):
        for schluessel, grund in GRUNDLINIE.items():
            with self.subTest(stelle=schluessel):
                self.assertGreater(len(grund), 60,
                                   f"{schluessel} carries no real reason, so the baseline is a list "
                                   f"of exemptions rather than of known gaps")


class TestDerScannerFAENGTAuchWasErFangenSoll(unittest.TestCase):
    """ANTI-PARITY. A scanner that finds nothing on a planted defect proves nothing about the tree."""

    def test_eine_gepflanzte_ungeschuetzte_stelle_wird_gefunden(self):
        for quelle in (
            'def neu(claim):\n    if claim["passed"]:\n        return 1\n',
            'def neu(claim):\n    return bool(claim.get("passed"))\n',
            'def neu(claim):\n    return "a" if claim["passed"] else "b"\n',
            'def neu(claim):\n    if not claim.get("passed"):\n        return 0\n',
            'def neu(claim):\n    return claim["passed"] and 1\n',
        ):
            with self.subTest(quelle=quelle.splitlines()[1].strip()):
                gefunden = _stellen({"gepflanzt.py": quelle})
                self.assertIn(("gepflanzt.py", "neu"), gefunden,
                              f"the planted site was not found: {quelle!r}")

    def test_die_durchgereichte_form_wird_gefunden_DIE_DIE_SECHSTE_STELLE_WAR(self):
        """The shape `issue_sd_jwt` actually had, plus the other three ways a value leaves a function.

        The first case is the real one, written as it stood: a dict value that is then signed. No
        `bool()`, no `if` — and the first version of this scanner reported nothing for it.
        """
        for quelle in (
            'def neu(claim, signer):\n    offen = {"passed": claim["passed"]}\n'
            '    return signer.sign(offen)\n',
            'def neu(claim):\n    return [claim["passed"]]\n',
            'def neu(claim):\n    return claim.get("passed")\n',
            'def neu(claim):\n    return emit(claim["passed"])\n',
            'def neu(claim):\n    return emit(verdikt=claim["passed"])\n',
        ):
            with self.subTest(quelle=quelle.splitlines()[1].strip()):
                gefunden = _stellen({"gepflanzt.py": quelle})
                self.assertIn(("gepflanzt.py", "neu"), gefunden,
                              f"a pass-through of the unexamined field was not found: {quelle!r}")

    def test_die_alias_form_wird_gefunden_UND_WAR_EIN_UNGENANNTES_LOCH(self):
        """`v = claim["passed"]` then `if v:` — measured empty on the first version of this file.

        It was not even in the list of stated holes, which is the worse half: an unstated hole reads as
        a covered case. Both directions are pinned, because alias resolution that only finds and never
        exempts turns every correct local check into a false red.
        """
        for quelle, erwartet_fund in (
            ('def neu(claim):\n    v = claim["passed"]\n    if v:\n        return 1\n', True),
            ('def neu(claim):\n    v = claim.get("passed")\n    return bool(v)\n', True),
            ('def neu(claim):\n    v = claim["passed"]\n    return {"passed": v}\n', True),
            # exempted: the type is established ON THE ALIAS, which is what eval_evidence_class does
            ('def neu(claim):\n    v = claim.get("passed")\n'
             '    if not isinstance(v, bool):\n        raise ValueError\n    return {"passed": v}\n',
             False),
            # NOT exempted: the isinstance is about a DIFFERENT name, the hf_evals shape one level on
            ('def neu(claim, other):\n    v = claim["passed"]\n'
             '    if not isinstance(other, bool):\n        raise ValueError\n    if v:\n        return 1\n',
             True),
            # a name bound twice carries no reference any more, so the read is reported again
            ('def neu(claim, x):\n    v = claim["passed"]\n    v = x\n    if v:\n        return 1\n',
             False),
        ):
            with self.subTest(quelle=quelle.splitlines()[1].strip(), fund=erwartet_fund):
                gefunden = _stellen({"gepflanzt.py": quelle})
                self.assertEqual(("gepflanzt.py", "neu") in gefunden, erwartet_fund,
                                 f"alias handling wrong for {quelle!r}: {gefunden}")

    def test_ein_weggeworfener_rueckgabewert_etabliert_nichts_REVIEW_FUND(self):
        """Der Review-Fund vom 24.09.2026, als Fall: pruefen und weitergeben sind zwei Dinge.

        `_require_export_fields(claim)` als blosse Anweisung prueft ueber `get` und gibt seinen Befund
        weg; das spaetere `claim["passed"]` ist dann ein ZWEITES Lesen, und ob die zwei Zugriffe
        dasselbe liefern, ist eine Eigenschaft des uebergebenen Objekts. Gemessen mit einer
        dict-Unterklasse taten sie es nicht.
        """
        verworfen = ('def neu(claim):\n    _require_export_fields(claim)\n'
                     '    return {"passed": claim["passed"]}\n')
        gefunden = _stellen({"gepflanzt.py": verworfen})
        self.assertIn(("gepflanzt.py", "neu"), gefunden,
                      "ein Etablierer mit weggeworfenem Rueckgabewert wurde als Schutz gezaehlt")

    def test_ein_gebundener_rueckgabewert_etabliert_sehr_wohl(self):
        """Die Gegenrichtung: ohne sie wuerde die Regel oben jede Pruefung fuer wertlos erklaeren und
        die geforderte Form selbst zum Befund machen."""
        gebunden = ('def neu(claim):\n    v = _require_export_fields(claim)\n'
                    '    return {"passed": v}\n')
        self.assertEqual(_stellen({"gepflanzt.py": gebunden}), {})

    def test_eine_gepflanzte_GESCHUETZTE_stelle_wird_nicht_gemeldet(self):
        """The other direction: if the guarded form were also flagged, the scanner would say nothing
        about guarding and everything about the word `passed`."""
        for quelle in (
            'def neu(claim):\n    v = _require_bool_verdict(claim, wo="x")\n'
            '    if claim["passed"]:\n        return v\n',
            'def neu(claim):\n    if not is_bool(claim.get("passed")):\n        raise ValueError\n'
            '    return bool(claim["passed"])\n',
            'def neu(claim):\n    if not isinstance(claim.get("passed"), bool):\n        raise ValueError\n'
            '    return bool(claim["passed"])\n',
        ):
            with self.subTest(quelle=quelle.splitlines()[1].strip()):
                self.assertEqual(_stellen({"gepflanzt.py": quelle}), {})

    def test_ein_vergleich_ist_keine_coercion_und_wird_nicht_gemeldet(self):
        """`claim["passed"] == True` does not coerce, so flagging it would be a false red and would
        push authors toward the truthy form this scanner exists to discourage."""
        quelle = 'def neu(claim):\n    return claim["passed"] == True  # noqa: E712\n'
        self.assertEqual(_stellen({"gepflanzt.py": quelle}), {})

    def test_die_genannte_grenze_ein_variabler_schluessel_entgeht(self):
        """RECORDED AS A HOLE, with a case, rather than described in prose and forgotten."""
        quelle = 'def neu(claim):\n    k = "passed"\n    if claim[k]:\n        return 1\n'
        self.assertEqual(_stellen({"gepflanzt.py": quelle}), {},
                         "if this now FINDS the variable-key form, the docstring's stated hole is "
                         "closed and this case should become the positive assertion")

    def test_ein_leerer_baum_ist_ein_fehler_kein_sauberer_befund(self):
        with self.assertRaises(AssertionError):
            _stellen({})


if __name__ == "__main__":
    unittest.main()
