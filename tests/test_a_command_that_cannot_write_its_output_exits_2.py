"""A command that cannot write its output file ends with exit 2 and a named line, never with a traceback.

SOURCE. Item 772 of the proofbundle lane, measured on main 862f263d with the interpreter of the project venv.
Eleven of the twelve output options of the CLI (`emit`, `emit-eval`, `intoto`, `svr`, `decision init` and
`emit`, `outcome init` and `emit`, `relation-statement init` and `emit`, `policy instantiate --output`) raised
`FileNotFoundError` for a path under a missing directory and `IsADirectoryError` for a directory out of `main`,
so the caller saw a traceback and exit 1, the code of a failed verification. `anchor upgrade` caught the error
and ended with exit 2, but when a declared calendar held a character UTF-8 cannot encode (an undecodable byte of
argv arrives as a lone surrogate) it had already opened the file and left a cut-off pack of 430 bytes behind.
`_resolve_signer` refuses a key file that cannot be written with exit 2; an output file now ends the same way,
through one writer, `cli._write_output`.

THREE PARTS. The first runs every output option against paths that cannot be written and holds exit 2, the line
that names the option, no traceback and nothing on stdout, and for `policy instantiate --json` the JSON error
object its help promises; the control runs each base with a writable path and holds what it writes. The second
holds the writer itself: content UTF-8 cannot encode neither creates nor truncates the file, and a device path is
written in place, not replaced. The third is the class guard. It reads cli.py for every write of these forms:
`open` and `io.open` with a write mode or a mode it cannot read, `<path>.open` likewise, `os.open` with a write
flag or flags it cannot read, `os.fdopen` with a write mode, `json.dump`, `write_text` and `write_bytes`. Each
must stand inside `_write_output`. A write of another form is outside what it reads, and so is the signing key
of `--new-key`, which `emit.save_signer` writes in another module (`_resolve_signer` refuses its errors with exit
2). And it reads every option whose value reaches `_write_output`: each is a case of the first part.
"""
from __future__ import annotations

import argparse
import ast
import base64
import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from proofbundle import cli, generate_signer
from proofbundle.cli import build_parser, main
from proofbundle.emit import save_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt

try:
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:
    _HAS_OTS = False

REPO = Path(__file__).resolve().parents[1]
CLI = REPO / "src" / "proofbundle" / "cli.py"
OTS = REPO / "tests" / "fixtures" / "ots"

#: The cases whose output option is read by its truth: an empty value prints to stdout, the documented default
#: (`_ERLAUBTE_WAHRHEITSLESUNGEN` in tests/test_an_option_given_an_empty_value_is_not_dropped.py), so the empty
#: path is no path that cannot be written for them.
_LEER_HEISST_STDOUT = frozenset({("decision init", "--out"), ("outcome init", "--out"),
                                 ("relation-statement init", "--out"), ("policy instantiate", "--output")})

#: The cases that need the [anchors] extra to reach the write.
_BRAUCHT_OTS = frozenset({("anchor upgrade", "--out")})


def _run(argv: list[str]) -> tuple:
    """Exit code, stdout and stderr of one run in this process. An exception that leaves `main` is the defect
    itself, so its type name stands where the exit code would."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = main(argv)
        except SystemExit as exc:
            rc = exc.code
        except Exception as exc:  # noqa: BLE001 - the escape is what the case measures
            rc = type(exc).__name__
    return rc, out.getvalue(), err.getvalue()


class _Eingaben:
    """One input of each kind the writing commands read, in a temporary directory."""

    def __init__(self, ordner: str) -> None:
        d = Path(ordner)
        self.ordner = d
        self.seed = str(d / "seed.key")
        save_signer(generate_signer(), self.seed)
        self.nutzlast = str(d / "payload.bin")
        Path(self.nutzlast).write_bytes(b"a payload")
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9",
            n=10, model_id="m", dataset_id="d", issuer="Lab", timestamp="2026-07-02T00:00:00Z")
        self.claim = str(d / "claim.json")
        Path(self.claim).write_text(json.dumps(claim), encoding="utf-8")
        self.receipt = str(d / "eval.json")
        Path(self.receipt).write_text(json.dumps(emit_eval_receipt(claim, generate_signer())), encoding="utf-8")
        self.dpred = str(REPO / "examples" / "decision_receipt_deny.json")
        self.opred = str(d / "outcome_predicate.json")
        Path(self.opred).write_text(json.dumps({
            "schemaVersion": "0.1.0", "outcomeId": "o1", "decisionRef": {"sha256": "e" * 64},
            "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "b" * 64},
            "status": "executed", "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}),
            encoding="utf-8")
        self.rpred = str(d / "relation_predicate.json")
        Path(self.rpred).write_text(json.dumps({
            "schemaVersion": "0.1.0", "statementId": "urn:uuid:output-write",
            "relationships": [{"relation": "retracts",
                               "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64},
                               "reasonCode": "withdrawal", "reason": "x", "declaredAt": "2026-09-29T00:00:00Z"}]}),
            encoding="utf-8")
        self.keyfile = str(d / "issuer.pub")
        pub = base64.b64encode(generate_signer().public_key().public_bytes_raw()).decode("ascii")
        Path(self.keyfile).write_text(pub + "\n", encoding="utf-8")

    def faelle(self) -> dict:
        """{(command, option): the argv of the command without the option}."""
        k = ["--key", self.seed]
        return {
            ("emit", "--out"): ["emit", "--payload-file", self.nutzlast] + k,
            ("emit-eval", "--out"): ["emit-eval", "--claim", self.claim] + k,
            ("intoto", "--out"): ["intoto", self.receipt] + k,
            ("svr", "--out"): ["svr", self.receipt] + k,
            ("decision init", "--out"): ["decision", "init"],
            ("decision emit", "--out"): ["decision", "emit", self.dpred] + k,
            ("outcome init", "--out"): ["outcome", "init"],
            ("outcome emit", "--out"): ["outcome", "emit", self.opred] + k,
            ("relation-statement init", "--out"): ["relation-statement", "init"],
            ("relation-statement emit", "--out"): ["relation-statement", "emit", self.rpred] + k,
            ("policy instantiate", "--output"): ["policy", "instantiate", "strict-eval-template-v1",
                                                 "--issuer-key", self.keyfile, "--policy-id", "org/output-write-v1"],
            ("anchor upgrade", "--out"): ["anchor", "upgrade", "--proof", str(OTS / "synthetic-upgraded-sha256.txt.ots"),
                                          "--target-file", str(OTS / "synthetic-upgraded-sha256.txt")],
        }

    def unschreibbare_pfade(self) -> dict:
        """{label: a path the command cannot write}, each a different reason of the operating system."""
        ordner = self.ordner / "a_directory"
        ordner.mkdir(exist_ok=True)
        datei = self.ordner / "a_regular_file"
        datei.write_text("x", encoding="utf-8")
        pfade = {"missing directory": str(self.ordner / "no_such_directory" / "out.json"),
                 "a directory": str(ordner),
                 "under a regular file": str(datei / "out.json")}
        gesperrt = self.ordner / "read_only_directory"
        gesperrt.mkdir(exist_ok=True)
        gesperrt.chmod(0o500)
        if not os.access(gesperrt, os.W_OK):   # a superuser writes there anyway, so the form is not measurable
            pfade["read-only directory"] = str(gesperrt / "out.json")
        return pfade


def _skip_ohne_ots(fall) -> bool:
    return fall in _BRAUCHT_OTS and not _HAS_OTS


class ACommandThatCannotWriteItsOutputExits2(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory(prefix="pb_output_write_")
        cls.e = _Eingaben(cls._td.name)

    @classmethod
    def tearDownClass(cls) -> None:
        (Path(cls._td.name) / "read_only_directory").chmod(0o700)
        cls._td.cleanup()

    def test_every_path_that_cannot_be_written_ends_with_exit_2_and_a_named_line(self) -> None:
        pfade = self.e.unschreibbare_pfade()
        for fall, basis in self.e.faelle().items():
            befehl, option = fall
            formen = dict(pfade)
            if fall not in _LEER_HEISST_STDOUT:
                formen["the empty path"] = ""
            for label, pfad in formen.items():
                with self.subTest(case=f"{befehl} {option}", path=label):
                    if _skip_ohne_ots(fall):
                        self.skipTest("NOT MEASURABLE here: needs proofbundle[anchors] (opentimestamps)")
                    rc, out, err = _run(basis + [option, pfad])
                    self.assertEqual(rc, 2, f"{befehl} {option} on {label}: {err[-300:]}")
                    self.assertNotIn("Traceback", err)
                    self.assertIn(f"ERROR: cannot write {option}: ", err)
                    self.assertEqual(out, "", "a command that wrote nothing claims nothing on stdout")

    def test_policy_instantiate_json_reports_the_failure_as_its_error_object(self) -> None:
        basis = self.e.faelle()[("policy instantiate", "--output")]
        for label, pfad in self.e.unschreibbare_pfade().items():
            with self.subTest(path=label):
                rc, out, err = _run(basis + ["--output", pfad, "--json"])
                self.assertEqual(rc, 2, err[-300:])
                bericht = json.loads(out)
                self.assertIs(bericht["ok"], False)
                self.assertTrue(bericht["error"].startswith("cannot write --output: "), bericht)
                self.assertNotIn("ERROR:", err, "with --json the error is the JSON object, not a stderr line")

    def test_control_each_base_writes_its_output(self) -> None:
        # Without this, a base that already fails before the write would make every case above pass for the
        # wrong reason; the content check holds that the one writer writes what the command wrote before.
        for fall, basis in self.e.faelle().items():
            befehl, option = fall
            with self.subTest(case=f"{befehl} {option}"):
                if _skip_ohne_ots(fall):
                    self.skipTest("NOT MEASURABLE here: needs proofbundle[anchors] (opentimestamps)")
                ziel = self.e.ordner / f"written_{befehl.replace(' ', '_')}.json"
                rc, _out, err = _run(basis + [option, str(ziel)])
                self.assertEqual(rc, 0, err[-300:])
                text = ziel.read_text(encoding="utf-8")
                obj = json.loads(text)
                # the templates, the policy and the pack keep non-ASCII text as it is, the signed outputs escape it
                ensure_ascii = not (befehl.endswith(" init") or befehl in ("anchor upgrade", "policy instantiate"))
                self.assertEqual(text, json.dumps(obj, indent=2, ensure_ascii=ensure_ascii) + "\n")

    def test_control_a_template_writes_what_it_prints(self) -> None:
        for befehl in ("decision", "outcome", "relation-statement"):
            with self.subTest(command=befehl):
                ziel = self.e.ordner / f"template_{befehl}.json"
                rc, gedruckt, _ = _run([befehl, "init"])
                self.assertEqual(rc, 0)
                self.assertEqual(_run([befehl, "init", "--out", str(ziel)])[0], 0)
                self.assertEqual(ziel.read_text(encoding="utf-8"), gedruckt)

    @unittest.skipUnless(_HAS_OTS, "NOT MEASURABLE here: needs proofbundle[anchors] (opentimestamps)")
    def test_anchor_upgrade_leaves_no_pack_when_a_declared_calendar_cannot_be_encoded(self) -> None:
        ziel = self.e.ordner / "pack_with_surrogate.json"
        basis = self.e.faelle()[("anchor upgrade", "--out")]
        rc, out, err = _run(basis + ["--calendar-declared", "https://x\udcff.example", "--out", str(ziel)])
        self.assertEqual(rc, 2, err[-300:])
        self.assertIn("ERROR: cannot write --out: ", err)
        self.assertFalse(ziel.exists(), "a pack that could not be written must not stand cut off")
        with self.subTest(control="the same calendar spelled in ASCII writes the pack"):
            self.assertEqual(_run(basis + ["--calendar-declared", "https://x.example", "--out", str(ziel)])[0], 0)
            self.assertTrue(ziel.exists())


class TheOneWriter(unittest.TestCase):

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory(prefix="pb_one_writer_")
        self.ordner = Path(self._td.name)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _schreibe(self, pfad, text: str) -> tuple[bool, str]:
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            ok = cli._write_output(str(pfad), text)
        return ok, err.getvalue()

    def test_content_utf8_cannot_encode_creates_no_file(self) -> None:
        ziel = self.ordner / "out.json"
        ok, err = self._schreibe(ziel, '{"x": "\udcff"}\n')
        self.assertIs(ok, False)
        self.assertIn("ERROR: cannot write --out: ", err)
        self.assertFalse(ziel.exists())

    def test_content_utf8_cannot_encode_leaves_an_existing_file_as_it_was(self) -> None:
        ziel = self.ordner / "out.json"
        ziel.write_text("before\n", encoding="utf-8")
        ok, _ = self._schreibe(ziel, '{"x": "\udcff"}\n')
        self.assertIs(ok, False)
        self.assertEqual(ziel.read_text(encoding="utf-8"), "before\n")

    def test_control_a_writable_path_is_written(self) -> None:
        ziel = self.ordner / "out.json"
        ok, err = self._schreibe(ziel, '{"x": "\u00e9"}\n')
        self.assertEqual((ok, err), (True, ""))
        self.assertEqual(ziel.read_text(encoding="utf-8"), '{"x": "\u00e9"}\n')

    @unittest.skipUnless(os.name == "posix" and os.path.exists(os.devnull), "needs a POSIX null device")
    def test_a_device_path_is_written_in_place(self) -> None:
        vorher = os.stat(os.devnull)
        ok, _ = self._schreibe(os.devnull, "{}\n")
        nachher = os.stat(os.devnull)
        self.assertIs(ok, True)
        self.assertTrue(stat.S_ISCHR(nachher.st_mode))
        self.assertEqual((nachher.st_ino, nachher.st_dev), (vorher.st_ino, vorher.st_dev))


# ── the class guard ───────────────────────────────────────────────────────────────────────────────

#: The one function in cli.py that may write a file.
_SCHREIBER = "_write_output"

#: The flags of `os.open` that write.
_SCHREIBFLAGS = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"})


def _modus_schreibt(modus: ast.AST | None) -> bool:
    """A mode writes when it is a string with w, a, x or +, or anything this guard cannot read."""
    if modus is None:
        return False
    if isinstance(modus, ast.Constant) and isinstance(modus.value, str):
        return any(c in modus.value for c in "wax+")
    return True


def _argument(knoten: ast.Call, stelle: int, name: str) -> ast.AST | None:
    if len(knoten.args) > stelle:
        return knoten.args[stelle]
    return next((k.value for k in knoten.keywords if k.arg == name), None)


def _ist_schreibaufruf(knoten: ast.Call) -> bool:
    f = knoten.func
    if isinstance(f, ast.Name):
        return f.id == "open" and _modus_schreibt(_argument(knoten, 1, "mode"))
    if not isinstance(f, ast.Attribute):
        return False
    traeger = f.value.id if isinstance(f.value, ast.Name) else None
    if f.attr in ("write_text", "write_bytes"):
        return True
    if f.attr == "dump" and traeger == "json":
        return True
    if f.attr == "fdopen" and traeger == "os":
        return _modus_schreibt(_argument(knoten, 1, "mode"))
    if f.attr == "open" and traeger == "os":
        flags = _argument(knoten, 1, "flags")
        namen = {n.attr for n in ast.walk(flags) if isinstance(n, ast.Attribute)} if flags is not None else set()
        lesbar = flags is not None and all(isinstance(n, (ast.Attribute, ast.Name, ast.BinOp, ast.BitOr, ast.Load))
                                           for n in ast.walk(flags))
        return not lesbar or bool(namen & _SCHREIBFLAGS)
    if f.attr == "open" and traeger in ("io", "builtins"):
        return _modus_schreibt(_argument(knoten, 1, "mode"))
    if f.attr == "open":   # a path object: its mode is the first argument
        return _modus_schreibt(_argument(knoten, 0, "mode"))
    return False


def _schreibstellen(quelle: str) -> list[tuple[str, int]]:
    """(innermost enclosing function, line) of every write this guard reads; `<module>` outside a function."""
    gefunden: list[tuple[str, int]] = []

    class _Besucher(ast.NodeVisitor):
        def __init__(self) -> None:
            self.stapel = ["<module>"]

        def visit_FunctionDef(self, knoten) -> None:
            self.stapel.append(knoten.name)
            self.generic_visit(knoten)
            self.stapel.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, knoten: ast.Call) -> None:
            if _ist_schreibaufruf(knoten):
                gefunden.append((self.stapel[-1], knoten.lineno))
            self.generic_visit(knoten)

    _Besucher().visit(ast.parse(quelle))
    return gefunden


def _ausgabeziele(quelle: str) -> set[str]:
    """The dest of every option whose value is the first argument of a call of `_write_output`."""
    ziele: set[str] = set()
    for knoten in ast.walk(ast.parse(quelle)):
        if not (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name) and knoten.func.id == _SCHREIBER
                and knoten.args):
            continue
        a = knoten.args[0]
        if isinstance(a, ast.Attribute) and isinstance(a.value, ast.Name) and a.value.id == "args":
            ziele.add(a.attr)
        elif (isinstance(a, ast.Call) and isinstance(a.func, ast.Name) and a.func.id == "getattr" and len(a.args) >= 2
              and isinstance(a.args[1], ast.Constant)):
            ziele.add(a.args[1].value)
        else:
            ziele.add(f"<unread: line {knoten.lineno}>")
    return ziele


def _optionen_mit_ziel(parser: argparse.ArgumentParser, ziele: set[str], pfad: tuple = ()) -> set[tuple[str, str]]:
    """(command, longest option string) of every option, in every subcommand, whose dest is in `ziele`."""
    gefunden: set[tuple[str, str]] = set()
    gesehen: set[int] = set()
    for aktion in parser._actions:
        if isinstance(aktion, argparse._SubParsersAction):
            for name, unter in aktion.choices.items():
                if id(unter) not in gesehen:
                    gesehen.add(id(unter))
                    gefunden |= _optionen_mit_ziel(unter, ziele, pfad + (name,))
        elif aktion.option_strings and aktion.dest in ziele:
            gefunden.add((" ".join(pfad), max(aktion.option_strings, key=len)))
    return gefunden


class EveryWriteOfTheCliGoesThroughTheOneWriter(unittest.TestCase):

    def test_every_write_stands_in_the_one_writer(self) -> None:
        fremd = [(f, z) for f, z in _schreibstellen(CLI.read_text(encoding="utf-8")) if f != _SCHREIBER]
        self.assertEqual(fremd, [], "a write outside `_write_output`: route it through the one writer")

    def test_control_the_one_writer_is_found(self) -> None:
        # Without this, a guard that reads no write at all would pass the case above.
        self.assertIn(_SCHREIBER, {f for f, _ in _schreibstellen(CLI.read_text(encoding="utf-8"))})

    def test_every_option_the_writer_reads_is_a_case(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            faelle = set(_Eingaben(td).faelle())
        ziele = _ausgabeziele(CLI.read_text(encoding="utf-8"))
        self.assertEqual(sorted(z for z in ziele if z.startswith("<unread")), [],
                         "a call of `_write_output` whose path this guard cannot trace to an option")
        self.assertEqual(_optionen_mit_ziel(build_parser(), ziele), faelle)

    def test_control_the_guard_finds_each_planted_write(self) -> None:
        gepflanzt = ("import io, json, os, pathlib\n"
                     "def _a(args):\n    open(args.out, 'w')\n"
                     "def _b(p):\n    with open(p, mode='ab') as h:\n        pass\n"
                     "def _c(p, m):\n    open(p, m)\n"
                     "def _d(p, o):\n    json.dump(o, p)\n"
                     "def _e(p):\n    pathlib.Path(p).write_text('x')\n"
                     "def _f(p):\n    pathlib.Path(p).open('x')\n"
                     "def _g(p):\n    os.open(p, os.O_WRONLY | os.O_CREAT)\n"
                     "def _h(fd):\n    os.fdopen(fd, 'r+')\n"
                     "def _i(p):\n    io.open(p, 'w')\n"
                     "def _j(p):\n    def inner():\n        p.write_bytes(b'')\n    return inner\n"
                     "def _write_output(p, t):\n    open(p, 'w')\n")
        self.assertEqual({f for f, _ in _schreibstellen(gepflanzt)},
                         {"_a", "_b", "_c", "_d", "_e", "_f", "_g", "_h", "_i", "inner", "_write_output"})

    def test_control_a_read_is_no_write(self) -> None:
        sauber = ("import os, pathlib\n"
                  "def _a(p):\n    open(p)\n    open(p, 'rb')\n    open(p, encoding='utf-8', newline='')\n"
                  "    pathlib.Path(p).open()\n    os.open(p, os.O_RDONLY | os.O_NOFOLLOW)\n    os.fdopen(3)\n")
        self.assertEqual(_schreibstellen(sauber), [])

    def test_control_an_untraced_writer_call_is_named(self) -> None:
        self.assertEqual(_ausgabeziele("def _a(args, p):\n    _write_output(args.out, 't')\n"
                                       "    _write_output(getattr(args, 'output', None), 't')\n"
                                       "    _write_output(p, 't')\n"),
                         {"out", "output", "<unread: line 4>"})


if __name__ == "__main__":
    unittest.main()
