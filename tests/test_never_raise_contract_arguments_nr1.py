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
the ``str`` or ``bytes`` it answered; a ``__fspath__`` that raises refuses the call with a typed error. The reader asks
for ``validate`` inside its guard. The second half of the path fix is a sibling the class search found: because the
check and the open read ``__fspath__`` separately, a path-like that answers a regular file first and a FIFO second made
``load_bundle`` hang at 22aa954e (measured: still running after 8 s), and one that answers another file second made it
return that file's content.
"""
from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from proofbundle import agent_review, bundle, emit, public_transparency
from proofbundle.canonical import _ein_stand
from proofbundle.errors import ProofBundleError

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
            val = family._stub_for(p)
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

    def test_the_three_loaders_refuse_a_raising_fspath_with_a_typed_error(self):
        for label, fn in (("load_bundle", bundle.load_bundle), ("load_signer", emit.load_signer),
                          ("load_policy", agent_review.load_policy)):
            with self.subTest(surface=label):
                with self.assertRaises(ProofBundleError):
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

        body(GivesStr())
        self.assertIs(type(received[0]), str)
        with self.assertRaises(ProofBundleError):
            body(PathLike())

    def test_an_fspath_that_answers_no_path_refuses_the_call(self):
        @_ein_stand(aussen={"p": "pfad"})
        def body(p):
            raise AssertionError("the body must not run")

        class GivesInt:
            def __fspath__(self):
                return 3

        for value in (PathLike(), GivesInt()):
            with self.subTest(value=type(value).__name__):
                with self.assertRaises(ProofBundleError):
                    body(value)

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
