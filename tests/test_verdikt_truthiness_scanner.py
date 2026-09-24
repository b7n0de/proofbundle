"""A new site that reads `passed` as a truth value must become a finding, not a quiet regression.

WHY A SCANNER AND NOT ONLY THE PROPERTY TEST. `tests/test_das_verdikt_muss_ein_bool_sein.py` pins the
MONOTONICITY of the emit path, so a seventh site added behind one of the guarded entry points breaks it.
A site added somewhere ELSE — a new exporter, a new adapter, a CLI path — would not be behind those
entry points and the property test would stay green while the class came back. That is the shape the
sibling class already paid for: `_membership.py` says it in its own docstring, after this repository
fixed the same assumption three times at three call sites.

WHAT IT LOOKS FOR, stated narrowly so nobody reads it as more. A read of the literal key ``"passed"``
off a subscript or ``.get`` that is used as a TRUTH VALUE: wrapped in ``bool(...)``, used as an ``if``
or ``while`` condition, negated with ``not``, used as a ternary condition, or combined with
``and``/``or``. Those are the shapes the six measured sites actually had.

STATED REACH, AND IT IS A REAL HOLE, not a formality:

* A field read through a VARIABLE (``schluessel = "passed"``; ``claim[schluessel]``) escapes it.
* A DIFFERENT verdict-bearing field escapes it. The scanner knows one key name, not the concept.
* A truth-value read via ``operator.truth`` or ``filter`` escapes it.
* Equality comparisons (``claim["passed"] == True``) are NOT flagged, because they do not coerce.

So this is a guard against the shapes that occurred, not a proof that the class is gone. The honest
protection is the pair: this scanner for new sites, the property test for new paths behind old sites.
The baseline below is a LIST OF KNOWN GAPS rather than a permission: every entry names why it is
allowed to stand, and an entry that no longer exists makes this file fail rather than shrinking in
silence.
"""
import ast
import pathlib
import unittest

QUELLE = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

#: The helpers that ESTABLISH the type. A function that calls one of these may then read the field
#: however it likes — that is the whole point of a shared predicate.
ETABLIERER = {"is_bool", "_require_bool_verdict"}

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


def _liest_passed(knoten: ast.AST) -> bool:
    """Is this expression a read of the literal key ``passed``?"""
    bezug = _schluesselbezug(knoten)
    return bezug is not None and bezug[1] == "passed"


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
    ziel = _schluesselbezug(ausdruck)
    for k in ast.walk(fn):
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id in ETABLIERER:
            return True
        if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in ETABLIERER:
            return True
        # An inline `isinstance(<the same expression>, bool)` counts too: it establishes the same
        # thing, and demanding the shared helper would be a style rule dressed up as a safety one.
        # It must be the SAME FIELD OF THE SAME OBJECT, compared as (object source, key), so
        # `claim["passed"]` and `claim.get("passed")` count as one while `_val` and `value` do not.
        if (isinstance(k, ast.Call) and isinstance(k.func, ast.Name) and k.func.id == "isinstance"
                and len(k.args) == 2 and isinstance(k.args[1], ast.Name)
                and k.args[1].id == "bool" and _schluesselbezug(k.args[0]) == ziel):
            return True
    return False


def _stellen(quelltexte: dict[str, str] | None = None) -> dict[tuple[str, str], list[int]]:
    """(file, enclosing definition) -> line numbers, for every unguarded truthy read of `passed`."""
    texte = _dateien() if quelltexte is None else quelltexte
    if not texte:
        raise AssertionError("no source files read — an empty scan is not a clean one")
    gefunden: dict[tuple[str, str], list[int]] = {}
    for name, text in texte.items():
        baum = ast.parse(text)
        for fn in _definitionen(baum):
            for ausdruck in _wahrheitswertig(fn):
                if _liest_passed(ausdruck) and not _etabliert_den_typ(fn, ausdruck):
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
