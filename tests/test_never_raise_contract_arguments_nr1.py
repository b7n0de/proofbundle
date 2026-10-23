"""NR1 of 6.3.1: the never-raise surfaces of pull request 291 against the two inputs of its finding.

RESTRISIKO_620 records the finding: a dict holding a colliding key whose ``__eq__`` raises, or a value every special
method of which raises, let the caller's exception escape at 60 of the 133 surfaces the package documents as never
raising. Since deep gate run 6 (fda55f98) the reading at the call (`canonical._ein_stand`) copies every argument, so
such a value reaches no body; it becomes a stand-in, or the call is refused with a typed error. What still reaches a
body as the caller's object is the argument a contract hands on (``aussen``) and the argument a named reader reads
(``leser``). Measured at 22aa954e over the 137 surfaces of the family property, 43 such arguments: four let the
caller's exception escape.

* ``bundle.load_bundle(path)``, ``emit.load_signer(path)``, ``agent_review.load_policy(pfad)``: a path-like object
  whose ``__fspath__`` raises. The body opened the caller's object, so ``__fspath__`` ran in the body, once for the
  ``os.stat`` check and again for the ``open``.
* ``public_transparency.evaluate_public_transparency(consistency_result)``: the reader asked ``hasattr(value,
  "validate")`` outside its guard, so a ``__getattr__`` that raises escaped.

The fix reads a path-like object under a path contract once at the call (`canonical._pfad_gelesen`) and hands the body
the ``str`` or ``bytes`` it answered. The reader asks for ``validate`` inside its guard. The second half of the path fix
is a sibling the class search found: because the check and the open read ``__fspath__`` separately, a path-like that
answers a regular file first and a FIFO second made ``load_bundle`` hang at 22aa954e (measured: still running after
8 s), and one that answers another file second made it return that file's content.

A ``__fspath__`` that raises or answers no ``str`` or ``bytes`` makes the value one that is no path, and the body gets
what the contract hands on for any such value: the stand-in under a path, the caller's object under a path or an
object. At dfaa3079 the reading refused the call there instead (the lens on pull request 394, F2): the refusal came
before the body, so `prereg.verify_prereg` and `evalcard.verify_evaluation_card`, which give a verdict for a path they
cannot read, raised, and it was no class any of the functions with a path contract documents. At eca80693 the body got
the stand-in under a path or an object too, and a loaded log that also defines ``__fspath__`` lost its object arm (the
second lens on pull request 394, U3).

The class test below never reached the path of those two surfaces, because its stub gave ``{}`` for their ``claim``
and they returned before it (F7). The claim carries both digests now, and with it the class test is red on main
862f263d, where both let the caller's exception out. It accepts any ``ProofBundleError``, so it passes the refusal of
dfaa3079; the class `APathLikeThatIsNoPathIsAnsweredAsAValueThatIsNoPath` holds each answer itself.
"""
from __future__ import annotations

import ast
import inspect
import tempfile
import unittest
from pathlib import Path

import proofbundle
from proofbundle import agent_review, bundle, emit, evalcard, prereg, public_transparency, verifier_block
from proofbundle._membership import Fremdkoerper
from proofbundle.adapters import eee, inspect_ai, lm_eval, promptfoo, samples
from proofbundle.canonical import _ein_stand
from proofbundle.errors import BundleFormatError, ProofBundleError

import test_never_raise_surface_family_property as family


class CallerError(Exception):
    """The caller's own exception, raised by its own code."""


def _raise(*_a, **_k):
    raise CallerError("special method of the caller")


_SPECIAL = ["__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__hash__", "__bool__", "__len__",
            "__iter__", "__contains__", "__getitem__", "__str__", "__repr__", "__format__", "__bytes__", "__int__",
            "__float__", "__index__", "__enter__", "__exit__", "__getattr__", "__reduce__", "__reduce_ex__",
            "__copy__", "__deepcopy__", "__sizeof__", "__dir__", "__getstate__", "__setattr__", "__delattr__"]
#: The finding's second input: a value every special method of which raises the caller's exception.
Plain = type("Plain", (), {m: _raise for m in _SPECIAL})
#: The same, with a ``__fspath__`` that raises: a path-like object of the caller.
PathLike = type("PathLike", (Plain,), {"__fspath__": _raise})
#: The same as the caller's callable.
Callable_ = type("Callable_", (Plain,), {"__call__": _raise})


class LooksUpNothing:
    """An object whose every attribute lookup raises, ``__class__`` included."""

    def __getattribute__(self, _name):
        raise CallerError("__getattribute__ of the caller")


class _Key:
    armed = False

    def __init__(self, n):
        object.__setattr__(self, "n", n)

    def __hash__(self):
        return 7

    def __eq__(self, other):
        if _Key.armed:
            raise CallerError("__eq__ of a colliding key")
        return self is other


def colliding_dict():
    """The finding's first input: a dict holding two keys whose hashes collide and whose ``__eq__`` raises."""
    _Key.armed = False
    d = {_Key(1): "a", _Key(2): "b"}
    _Key.armed = True
    return d


INPUTS = {"path_like": PathLike, "callable": Callable_, "plain": Plain, "looks_up_nothing": LooksUpNothing,
          "colliding_dict": colliding_dict}


def _contract(fn):
    """The contract (``aussen``) and the named readers (``leser``) of the outermost reading at the call of ``fn``."""
    f = fn
    while f is not None:
        if getattr(f, "__ein_stand__", False):
            free = inspect.getclosurevars(f).nonlocals
            return dict(free.get("vertrag") or {}), sorted((free.get("leser") or {}).keys())
        f = getattr(f, "__wrapped__", None)
    return None, None


#: The ``claim`` of `prereg.verify_prereg` and `evalcard.verify_evaluation_card`, carrying the digest each reads, so
#: both reach the path. The family stub of a dict is ``{}``, and with it both returned before the path (F7).
_CLAIM = {"prereg_sha256": "00" * 32, "evaluation_card_sha256": "00" * 32}


def _call(fn, params, i, value):
    args, kwargs = [], {}
    for j, p in enumerate(params):
        if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
            continue
        if j == i:
            val = value
        elif p.default is not inspect.Parameter.empty:
            continue
        else:
            val = dict(_CLAIM) if p.name == "claim" else family._stub_for(p)
        if p.kind == p.KEYWORD_ONLY or j > i:
            kwargs[p.name] = val
        else:
            args.append(val)
    return fn(*args, **kwargs)


class EveryArgumentThatReachesABodyUncopied(unittest.TestCase):
    """The class: every argument of a never-raise surface that a contract hands on or a named reader reads."""

    def test_no_callers_exception_escapes_at_any_of_them(self):
        surfaces = family._discover_surfaces()
        self.assertGreaterEqual(len(surfaces), 133, "the population of the finding was 133 surfaces")
        seen = 0
        for mod, name, fn in surfaces:
            vertrag, leser = _contract(fn)
            self.assertIsNotNone(vertrag, f"{mod}.{name} has no reading at the call")
            params = list(inspect.signature(fn).parameters.values())
            for i, p in enumerate(params):
                if p.name not in vertrag and p.name not in leser:
                    continue
                seen += 1
                for label, make in INPUTS.items():
                    with self.subTest(surface=f"{mod}.{name}", argument=p.name, value=label):
                        try:
                            _call(fn, params, i, make())
                        except CallerError as escaped:
                            self.fail(f"the caller's exception escaped: {escaped}")
                        except family._ACCEPTED:
                            pass
        self.assertGreaterEqual(seen, 40, "measured at 22aa954e: 43 such arguments")


class APathIsReadOnceAtTheCall(unittest.TestCase):

    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = Path(self._dir.name)
        (self.dir / "a.json").write_text('{"a": 1}', encoding="utf-8")
        (self.dir / "b.json").write_text('{"b": 2}', encoding="utf-8")

    def tearDown(self):
        self._dir.cleanup()

    def test_the_three_loaders_refuse_a_raising_fspath_with_their_documented_error(self):
        for label, fn, documented in (("load_bundle", bundle.load_bundle, BundleFormatError),
                                      ("load_signer", emit.load_signer, BundleFormatError),
                                      ("load_policy", agent_review.load_policy, agent_review.AgentReviewError)):
            with self.subTest(surface=label):
                with self.assertRaises(documented):
                    fn(PathLike())

    def test_the_check_and_the_open_read_one_path(self):
        first, rest = str(self.dir / "a.json"), str(self.dir / "b.json")

        class Flip:
            calls = 0

            def __fspath__(self):
                Flip.calls += 1
                return first if Flip.calls == 1 else rest

        self.assertEqual(bundle.load_bundle(Flip()), {"a": 1})
        self.assertEqual(Flip.calls, 1, "the path is read once, at the call")

    def test_a_well_behaved_path_like_reads_as_before(self):
        class Plainly:
            def __fspath__(self):
                return str(self.dir_)

        p = Plainly()
        p.dir_ = self.dir / "a.json"
        self.assertEqual(bundle.load_bundle(p), {"a": 1})
        self.assertEqual(bundle.load_bundle(self.dir / "a.json"), {"a": 1})
        self.assertEqual(bundle.load_bundle(str(self.dir / "a.json")), {"a": 1})


class TheReadingOfAPath(unittest.TestCase):
    """The rule at the reading itself, on a function of this test that records what its body receives."""

    def test_the_body_gets_a_plain_str_or_bytes(self):
        received = []

        @_ein_stand(aussen={"p": "pfad"})
        def body(p):
            received.append(p)

        class Sub(str):
            def __eq__(self, other):
                raise CallerError("__eq__ of the caller's str")

            __hash__ = str.__hash__

        class GivesSub:
            def __fspath__(self):
                return Sub("x.json")

        class GivesBytes:
            def __fspath__(self):
                return b"y.json"

        class SubBytes(bytes):
            pass

        class GivesSubBytes:
            def __fspath__(self):
                return SubBytes(b"w.json")

        body(GivesSub())
        body(GivesBytes())
        body(GivesSubBytes())
        self.assertIs(type(received[0]), str)
        self.assertEqual(str.__str__(received[0]), "x.json")
        self.assertIs(type(received[1]), bytes)
        self.assertEqual(received[1], b"y.json")
        self.assertIs(type(received[2]), bytes)
        self.assertEqual(received[2], b"w.json")

    def test_a_path_or_an_object_is_read_the_same_way(self):
        received = []

        @_ein_stand(aussen={"p": "pfad_oder_objekt"})
        def body(p):
            received.append(p)

        class GivesStr:
            def __fspath__(self):
                return "z.eval"

        no_path = PathLike()
        body(GivesStr())
        body(no_path)
        body(object())
        self.assertIs(type(received[0]), str)
        # Under a path or an object, a value that is no path is the caller's object, as object() is.
        self.assertIs(received[1], no_path)
        self.assertIsNot(type(received[2]), Fremdkoerper)

    def test_an_fspath_that_answers_no_path_hands_the_body_a_stand_in(self):
        received = []

        @_ein_stand(aussen={"p": "pfad"})
        def body(p):
            received.append(p)

        class GivesInt:
            calls = 0

            def __fspath__(self):
                GivesInt.calls += 1
                return 3

        values = (PathLike(), GivesInt())
        for value in values:
            body(value)
        self.assertEqual(len(received), 2)
        for value, got in zip(values, received):
            with self.subTest(value=type(value).__name__):
                self.assertIsNot(got, value, "the body gets no object of the caller")
                self.assertIsInstance(got, Fremdkoerper)
                self.assertFalse(hasattr(type(got), "__fspath__"), "the stand-in is no path")
        self.assertEqual(GivesInt.calls, 1, "the path is read once, at the call")

    def test_a_recursion_error_is_raised_as_it_is(self):
        """The stack ran out in the caller's code: raised as it is, as the reading at the call raises it."""
        class Deep:
            def __fspath__(self):
                raise RecursionError("the stack ran out")

        with self.assertRaises(RecursionError):
            bundle.load_bundle(Deep())

    def test_the_refusal_names_no_value_of_the_caller(self):
        class Secretive:
            def __fspath__(self):
                raise CallerError("tok3n-in-the-callers-message")

        with self.assertRaises(ProofBundleError) as caught:
            bundle.load_bundle(Secretive())
        self.assertNotIn("tok3n", str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


_ZEIT = "2026-01-01T00:00:00Z"
#: Every function with a path contract, called with one value in its path argument and plausible other arguments.
_PATH_SURFACES = {
    "bundle.load_bundle": lambda p: bundle.load_bundle(p),
    "emit.save_signer": lambda p: emit.save_signer(emit.generate_signer(), p),
    "emit.load_signer": lambda p: emit.load_signer(p),
    "verifier_block.measure_build": lambda p: verifier_block.measure_build(p),
    "verifier_block.measure_vector_set": lambda p: verifier_block.measure_vector_set(p),
    "verifier_block.measure_verifier_block": lambda p: verifier_block.measure_verifier_block(conformance_dir=p),
    "adapters.inspect_ai.from_inspect_ai_log": lambda p: inspect_ai.from_inspect_ai_log(
        p, "acc", comparator=">=", threshold="0.5", timestamp=_ZEIT),
    "adapters.eee.from_eee_dataset": lambda p: eee.from_eee_dataset(p, comparator=">=", threshold="0.5"),
    "adapters.lm_eval.from_lm_eval_results": lambda p: lm_eval.from_lm_eval_results(
        p, "t", "acc", comparator=">=", threshold="0.5", timestamp=_ZEIT),
    "adapters.promptfoo.from_promptfoo_results": lambda p: promptfoo.from_promptfoo_results(
        p, comparator=">=", threshold="0.5", timestamp=_ZEIT),
    "adapters.samples.samples_from_lm_eval_jsonl": lambda p: samples.samples_from_lm_eval_jsonl(p),
    "adapters.samples.samples_from_promptfoo_results": lambda p: samples.samples_from_promptfoo_results(p),
    "evalcard.evaluation_card_hash": lambda p: evalcard.evaluation_card_hash(p),
    "evalcard.verify_evaluation_card": lambda p: evalcard.verify_evaluation_card(p, dict(_CLAIM)),
    "prereg.prereg_hash": lambda p: prereg.prereg_hash(p),
    "prereg.verify_prereg": lambda p: prereg.verify_prereg(p, dict(_CLAIM)),
    "agent_review.load_policy": lambda p: agent_review.load_policy(p),
}
#: The second path argument of a function in the table: answered the same way.
_FURTHER_PATH_ARGUMENTS = {
    "verifier_block.measure_verifier_block(package_dir)": lambda p: verifier_block.measure_verifier_block(package_dir=p),
}
#: The one function with a path contract this test does not call, and why.
_NOT_CALLED = {"anchors_chia_add.anchor_add": (
    "its path is the lock file around a Chia wallet call, and the module reads the path of the chia binary from "
    "CHIA_CLI when it is imported, so a call here would need that set before the package is imported. The second lens "
    "on pull request 394 measured it at eca80693 with CHIA_CLI pointing nowhere: each form answers as object() does.")}


def _path_contracts_in_the_source():
    """``module.function`` for every function of the package whose `_ein_stand` names a path contract, read from the
    source with `ast`, so a new one cannot sit outside the table above unnoticed."""
    wurzel = Path(proofbundle.__file__).parent
    gefunden = set()
    for datei in sorted(wurzel.rglob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        modul = ".".join(datei.relative_to(wurzel).with_suffix("").parts)
        for knoten in ast.walk(baum):
            if not isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deko in knoten.decorator_list:
                if not (isinstance(deko, ast.Call) and getattr(deko.func, "id", None) == "_ein_stand"):
                    continue
                for kw in deko.keywords:
                    if kw.arg == "aussen" and isinstance(kw.value, ast.Dict) and any(
                            isinstance(v, ast.Constant) and v.value in ("pfad", "pfad_oder_objekt")
                            for v in kw.value.values):
                        gefunden.add(f"{modul}.{knoten.name}")
    return gefunden


def _answer(fn, value):
    """What a function answers: a verdict with its ``ok``, an exception by its exact class, or a returned type."""
    try:
        r = fn(value)
    except CallerError as escaped:
        return ("the caller's exception", str(escaped))
    except Exception as exc:  # noqa: BLE001 - the answer is the class
        return ("raise", type(exc))
    if type(r) is dict and "ok" in r:
        return ("verdict", r["ok"])
    return ("return", type(r))


class APathLikeThatIsNoPathIsAnsweredAsAValueThatIsNoPath(unittest.TestCase):
    """The lens on pull request 394 (F2, F1, F7) at dfaa3079: a path-like whose ``__fspath__`` raises or answers no
    ``str`` or ``bytes`` was refused before the body, so `prereg.verify_prereg` and `evalcard.verify_evaluation_card`
    raised where they gave a verdict, and every function with a path contract raised the reading's own class instead
    of the one it documents. Each answers such a value now as it answers ``object()``, a value that is no path."""

    def test_the_table_holds_every_path_contract_of_the_source(self):
        self.assertEqual(_path_contracts_in_the_source(), set(_PATH_SURFACES) | set(_NOT_CALLED))

    def test_each_answers_a_path_like_that_is_no_path_as_it_answers_a_value_that_is_no_path(self):
        class Counted:
            calls = 0

        class Raises(Counted):
            def __fspath__(self):
                Counted.calls += 1
                raise CallerError("__fspath__ of the caller")

        class GivesInt(Counted):
            def __fspath__(self):
                Counted.calls += 1
                return 3

        class GivesNone(Counted):
            def __fspath__(self):
                Counted.calls += 1
                return None

        for name, fn in {**_PATH_SURFACES, **_FURTHER_PATH_ARGUMENTS}.items():
            no_path = _answer(fn, object())
            for make in (Raises, GivesInt, GivesNone):
                with self.subTest(surface=name, value=make.__name__):
                    Counted.calls = 0
                    self.assertEqual(_answer(fn, make()), no_path)
                    self.assertLessEqual(Counted.calls, 1, "the path is read once, at the call")

    def test_the_two_verdict_surfaces_give_their_verdict(self):
        class GivesInt:
            def __fspath__(self):
                return 3

        for name in ("prereg.verify_prereg", "evalcard.verify_evaluation_card"):
            for value in (PathLike(), GivesInt()):
                with self.subTest(surface=name, value=type(value).__name__):
                    self.assertEqual(_answer(_PATH_SURFACES[name], value), ("verdict", False))

    def test_a_loaded_log_that_is_also_path_like_keeps_its_object_arm(self):
        """``from_inspect_ai_log`` takes a path or a loaded log (``"pfad_oder_objekt"``). A loaded log whose
        ``__fspath__`` gives no path is no path, so it reaches the body as the object it is and is read as a log, as
        on main 862f263d. At eca80693 it reached the body as the stand-in and was refused (the second lens on pull
        request 394, U3). A loaded log whose ``__fspath__`` gives a path is read from that path since NR1; that is
        not this case."""
        from types import SimpleNamespace as NS
        metric = NS(value=0.9)
        score = NS(metrics={"accuracy": metric}, name="s", scorer="s", params={})

        class LoadedLog:
            eval = NS(task="t", model="m", dataset=NS(name="d"), revision=None, created=_ZEIT)
            results = NS(scores=[score], total_samples=1, completed_samples=1)
            calls = 0

        class Raises(LoadedLog):
            def __fspath__(self):
                LoadedLog.calls += 1
                raise CallerError("the log file handle is closed")

        class GivesInt(LoadedLog):
            def __fspath__(self):
                LoadedLog.calls += 1
                return 3

        def suite(log):
            claim, _ = inspect_ai.from_inspect_ai_log(log, "accuracy", comparator=">=", threshold="0.5",
                                                      timestamp=_ZEIT)
            return claim["suite"]

        self.assertEqual(suite(LoadedLog()), "t")
        for make in (Raises, GivesInt):
            with self.subTest(value=make.__name__):
                LoadedLog.calls = 0
                self.assertEqual(suite(make()), "t")
                self.assertEqual(LoadedLog.calls, 1, "the path is read once, at the call")


class TheReaderOfAConsistencyResult(unittest.TestCase):

    def test_an_object_that_cannot_be_asked_gets_a_verdict(self):
        for label, make in (("plain", Plain), ("looks_up_nothing", LooksUpNothing), ("callable", Callable_)):
            with self.subTest(value=label):
                verdict = public_transparency.evaluate_public_transparency("", {}, consistency_result=make())
                self.assertIs(type(verdict), dict)

    def test_none_and_an_object_without_validate_read_as_before(self):
        for value in (None, object()):
            with self.subTest(value=type(value).__name__):
                self.assertIs(type(public_transparency.evaluate_public_transparency(
                    "", {}, consistency_result=value)), dict)


if __name__ == "__main__":
    unittest.main()
