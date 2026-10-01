"""The gate before run 7, part one: no object of the caller reaches the body of a public function, except where the
argument's contract names it.

SOURCE. Deep gate run 6 at fda55f98 ended FIX_FIRST (L4-620v6-T15-LIVE-RELATED-01, three of three jurors P1): a
container the reading at the call could not copy stayed the caller's object, the body read it at body time, and a gc
callback of the caller gave `verify_decision_receipt` ok True and safeForAutomation True where both states give False.
RESTRISIKO_620.md carried three more of the same class as open P1 with a workaround: a memoryview the copy cannot
rebuild (V8-F2), an iterator or a generator read by the body after the other arguments were copied (V10-F1), and a value
of the caller's own class inside a copied container that decided `decision.action_outcome_proven` through its own
methods (V8, E10). The review before run 7 named the common cause: the reading falls back to handing on what it does
not know. The owner's choices of 2026-10-01 (card OA-73db31053a, form of the owner's addendum of 2026-10-01,
18:45 UTC): those entries are closed in 6.2.0, the forms each argument takes are set per argument and recursively,
bytes and callbacks stay where they are meant, a form 6.2.0 promises (a
tuple, a subclass of str, bytes, dict or list read by what it stores) stays unless it promotes a verdict, and check and
copy use the same captured representation.

THE PROPERTY. After the reading at the call (`canonical._ein_stand`), the arguments the body receives hold no object of
the caller: every container is a private copy, a promised subclass is its stored contents in a class of this package,
and every other object is refused with a typed error before the body runs. The one exception is an argument whose
contract hands the body an object of the caller as it is: a callback, a signer, a path, a clock, a class, a path or a loaded log (`_VERTRAG`). The test
reads the arguments the body would receive and stops the call there, so the body never runs: no placeholder argument
can end a call before the check it is meant to reach (F3 of the review), because the check measured here is the reading
itself.

THE DENOMINATOR. Every public function, classmethod and staticmethod of the package that carries the reading at its
call, from the modules that import here; every parameter of it that is neither positional-only nor variadic; every form
of `_formen`; four places: the argument itself, an item of a list, a value of a dict, an item of a tuple. The counts
are asserted, so a collapse of the denominator is red, and a parameter that is not swept is named in `_NICHT_GEFEGT`.

THE FORMS. A HOSTILE form must be refused or must not reach the body: an iterator, a generator, `map`, `chain`,
`reversed`, a memoryview no view of private bytes can take, a view of an OrderedDict, a mapping proxy over a Mapping that
is no dict, a dict or set whose keys meet as one in the copy or whose key is of a caller's class, a frozenset holding
an object of the caller, an object of the caller's class, a subclass of int or float, an IntEnum of the caller, a
Mapping that is no dict, a datetime with a tzinfo of the caller, a callable. A PROMISED form must be read and must not
reach the body as the caller's object: a subclass of str or bytes as a value, a subclass of dict or list, a dict keyed
by a subclass of str. A CONTROL must be read: a plain dict, list, tuple, set, frozenset of plain values, bytearray,
deque, OrderedDict, keys view and mapping proxy of a dict, a memoryview in format B, an aware datetime in UTC.

MEASURED when this file was added: at fda55f98 every hostile form reached the body at all 927 parameters in all four
places (19 parameters with a named reader of a Mapping excepted at the top level), 107456 hand-ons in 163152 calls. At
the local prototype of the class fix (`_StandUnkopierbar`, 2026-10-01) the containers the copy cannot hold were refused,
and 18 forms still reached every body.

WHAT THIS DOES NOT SEE. A value a callback of the caller returns is read where it returns
(tests/test_a_verdict_surface_holds_its_verdict_at_every_argument.py, the callback section); a form nested deeper than
one level is reached through the recursion of the reading, which the places above sample at one level; a parameter
whose name the contract lists is trusted to take what its kind names.
"""
from __future__ import annotations

import collections
import ctypes
import enum
import functools
import importlib
import inspect
import itertools
import sys
import types
import unittest
from collections import ChainMap, OrderedDict, UserDict, deque
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Callable

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle import canonical  # noqa: E402
from proofbundle.errors import ProofBundleError  # noqa: E402

#: Modules whose public functions take no caller's value to a verdict (as in
#: tests/test_a_verifier_reads_a_callers_value_once.py, `_AUSSERHALB`).
_AUSSERHALB = frozenset({"proofbundle.cli", "proofbundle.demo", "proofbundle.pytest_plugin", "proofbundle.inspect_hook"})


def _oeffentliche_module() -> "dict[str, Path]":
    paket = REPO / "src" / "proofbundle"
    module = {}
    for pfad in sorted(paket.rglob("*.py")):
        rel = pfad.relative_to(paket)
        if any(t.startswith("_") for t in rel.parts):
            continue
        module[".".join(("proofbundle",) + rel.with_suffix("").parts)] = pfad
    return module


def _flaechen() -> "list[tuple[str, Callable]]":
    """Every public function, classmethod and staticmethod that carries the reading at its call, as (name, callable),
    with the name relative to the package (``decision.verify_decision_receipt``)."""
    out = []
    for modul in sorted(_oeffentliche_module()):
        if modul in _AUSSERHALB:
            continue
        try:
            m = importlib.import_module(modul)
        except Exception:  # noqa: BLE001 - a module whose extra is missing; the count below holds the floor
            continue
        kurz = modul.removeprefix("proofbundle.")
        for name, wert in sorted(vars(m).items()):
            if name.startswith("_"):
                continue
            if callable(wert) and getattr(wert, "__ein_stand__", False) and getattr(wert, "__module__", None) == modul:
                out.append((f"{kurz}.{name}", wert))
            elif isinstance(wert, type) and wert.__module__ == modul:
                for mname, roh in sorted(vars(wert).items()):
                    if mname.startswith("_") or not isinstance(roh, (classmethod, staticmethod)):
                        continue
                    if getattr(roh.__func__, "__ein_stand__", False):
                        out.append((f"{kurz}.{name}.{mname}", getattr(wert, mname)))
    return out


def _parameter(fn: Callable) -> "tuple[list[str], list[str]]":
    """(the parameters the sweep passes by name, the ones it cannot: positional-only and variadic)."""
    gefegt, nicht = [], []
    for p in inspect.signature(fn).parameters.values():
        if p.name in ("self", "cls"):
            continue
        if p.kind in (p.POSITIONAL_ONLY, p.VAR_POSITIONAL, p.VAR_KEYWORD):
            nicht.append(p.name)
        else:
            gefegt.append(p.name)
    return gefegt, nicht


# ── the contract: where an object of the caller reaches the body as it is ───────────────────────────────────────────

_RUECKRUF = "callable"   # a callback: called as the caller's code (`canonical._draussen`), its answer read where it returns
_SIGNIERER = "signer"    # a signing key or a signer object: its own `sign` is the caller's code by contract
_SIGNIERER_JE_NAME = "signer map"   # a dict whose values are signers
_PFAD = "path"           # an operating system path: a str or an `os.PathLike`
_UHR = "clock"           # a `datetime` the body reads once (`canonical._zeitpunkt_von`)
_PFAD_ODER_LOG = "path or loaded log"   # a path, or the library object the file holds once loaded (an EvalLog)

#: (function, parameter) -> the kind of object of the caller its contract hands to the body as it is. Every other
#: parameter takes the copy of a reading and no object of the caller.
_VERTRAG: "dict[tuple[str, str], str]" = {
    ("anchors.register_anchor_type", "verifier"): _RUECKRUF,
    ("assurance.classify_digest_evidence", "evidence_resolver"): _RUECKRUF,
    ("assurance.classify_receiver_corroboration", "evidence_resolver"): _RUECKRUF,
    ("assurance.classify_receiver_corroboration", "independent_attestation_resolver"): _RUECKRUF,
    ("decision.verify_decision_receipt", "evidence_resolver"): _RUECKRUF,
    ("decision.verify_decision_receipt_or_raise", "evidence_resolver"): _RUECKRUF,
    ("outcome.verify_outcome_receipt", "evidence_resolver"): _RUECKRUF,
    ("outcome.verify_outcome_receipt", "receiver_attestation_resolver"): _RUECKRUF,
    ("outcome.verify_outcome_receipt_or_raise", "evidence_resolver"): _RUECKRUF,
    ("outcome.verify_outcome_receipt_or_raise", "receiver_attestation_resolver"): _RUECKRUF,
    ("renewal.verify_sequence", "anchor_verifier"): _RUECKRUF,
    ("agent_review.emit_agent_review", "signer"): _SIGNIERER,
    ("checkpoint.cosign_checkpoint", "witness_signer"): _SIGNIERER,
    ("checkpoint.cosign_checkpoint_mldsa", "witness_signer"): _SIGNIERER,
    ("checkpoint.sign_checkpoint", "signer"): _SIGNIERER,
    ("decision.emit_decision_receipt", "signer"): _SIGNIERER,
    ("dsse.sign_envelope", "signer"): _SIGNIERER,
    ("emit.emit_bundle", "signer"): _SIGNIERER,
    ("emit.save_signer", "key"): _SIGNIERER,
    ("evalclaim.emit_eval_receipt", "signer"): _SIGNIERER,
    ("evalclaim.issuer_fingerprint", "signer"): _SIGNIERER,
    ("experimental.enclave.issue_enclave_attestation", "signer"): _SIGNIERER,
    ("intoto.export_eval_result_dsse", "signer"): _SIGNIERER,
    ("intoto.export_intoto_dsse", "signer"): _SIGNIERER,
    ("intoto.export_svr_dsse", "signer"): _SIGNIERER,
    ("outcome.emit_outcome_receipt", "signer"): _SIGNIERER,
    ("pqsig.sign_mldsa", "private_key"): _SIGNIERER,
    ("relation_statement.emit_relation_statement", "signer"): _SIGNIERER,
    ("run_ledger.emit_run_ledger", "signer"): _SIGNIERER,
    ("sdjwt_issue.issue_sd_jwt", "signer"): _SIGNIERER,
    ("sdjwt_issue.issuer_matches", "signer"): _SIGNIERER,
    ("sdjwt_issue.present_with_key_binding", "holder_signer"): _SIGNIERER,
    ("statuslist.issue_status_list_token", "signer"): _SIGNIERER,
    ("verification_summary.emit_verification_summary", "signer"): _SIGNIERER,
    ("verifier_block.sign_test_result_statement", "signer"): _SIGNIERER,
    ("renewal.build_initial_sequence", "signers"): _SIGNIERER_JE_NAME,
    ("renewal.renew_hashtree", "signers"): _SIGNIERER_JE_NAME,
    ("renewal.renew_timestamp", "signers"): _SIGNIERER_JE_NAME,
    ("trust_pack.sign_trust_pack", "signers"): _SIGNIERER_JE_NAME,
    ("adapters.eee.from_eee_dataset", "source"): _PFAD,
    ("adapters.inspect_ai.from_inspect_ai_log", "path"): _PFAD_ODER_LOG,
    ("adapters.lm_eval.from_lm_eval_results", "path"): _PFAD,
    ("adapters.promptfoo.from_promptfoo_results", "path"): _PFAD,
    ("adapters.samples.samples_from_lm_eval_jsonl", "path"): _PFAD,
    ("adapters.samples.samples_from_promptfoo_results", "path"): _PFAD,
    ("agent_review.load_policy", "pfad"): _PFAD,
    ("anchors_chia_add.anchor_add", "lock_path"): _PFAD,
    ("bundle.load_bundle", "path"): _PFAD,
    ("emit.load_signer", "path"): _PFAD,
    ("emit.save_signer", "path"): _PFAD,
    ("evalcard.evaluation_card_hash", "card_path"): _PFAD,
    ("evalcard.verify_evaluation_card", "card_path"): _PFAD,
    ("prereg.prereg_hash", "protocol_path"): _PFAD,
    ("prereg.verify_prereg", "protocol_path"): _PFAD,
    ("verifier_block.measure_build", "package_dir"): _PFAD,
    ("verifier_block.measure_vector_set", "conformance_dir"): _PFAD,
    ("verifier_block.measure_verifier_block", "conformance_dir"): _PFAD,
    ("verifier_block.measure_verifier_block", "package_dir"): _PFAD,
    ("evalclaim.check_freshness", "now"): _UHR,
    ("policy.evaluate_policy", "now"): _UHR,
    ("policy.lint_policy", "now"): _UHR,
    ("policy.policy_expired", "now"): _UHR,
    ("policy.policy_not_yet_valid", "now"): _UHR,
    ("trust_pack.verify_trust_pack", "now"): _UHR,
}

#: Parameters the sweep cannot pass by name, each with its reason. Every other parameter is swept.
_NICHT_GEFEGT_GRUND = "positional-only or variadic: the reading reads it as part of ``args``/``kwargs`` like every argument"


# ── the forms ───────────────────────────────────────────────────────────────────────────────────────────────────────

class _Objekt:
    """An object of the caller's own class."""

    def __init__(self) -> None:
        self.teil = [1]


class _Spiegel(str):
    """Its own hash, so a caller's dict and set hold it beside the `str` it spells, and the copy reads both as one."""

    def __hash__(self) -> int:
        return 12345


class _Text(str):
    pass


class _Roh(bytes):
    pass


class _Zahl(int):
    pass


class _Komma(float):
    pass


class _Stufe(enum.IntEnum):
    EINS = 1


class _Zone(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "Z"


class _Abbild(Mapping):
    """A caller's Mapping that is no dict."""

    def __init__(self, d: dict) -> None:
        self._d = d

    def __getitem__(self, k: Any) -> Any:
        return self._d[k]

    def __iter__(self) -> Any:
        return iter(list(self._d))

    def __len__(self) -> int:
        return len(self._d)


_Paar = collections.namedtuple("_Paar", "a")

FEINDLICH, ZUGESAGT, KONTROLLE = "hostile", "promised", "control"


def _formen() -> "dict[str, tuple[Callable[[], Any], str, str]]":
    """name -> (factory, class, kind of object for the contract). Each call of the factory makes a fresh value."""
    def mv_byteorder():
        return memoryview((ctypes.c_uint16 * 2)(1, 2))

    def mv_released():
        m = memoryview(bytearray(b"ab"))
        m.release()
        return m
    return {
        "an iterator": (lambda: iter([1, 2]), FEINDLICH, "iterator"),
        "a generator": (lambda: (x for x in [1, 2]), FEINDLICH, "iterator"),
        "map": (lambda: map(int, [1, 2]), FEINDLICH, "iterator"),
        "itertools.chain": (lambda: itertools.chain([1], [2]), FEINDLICH, "iterator"),
        "reversed": (lambda: reversed([1, 2]), FEINDLICH, "iterator"),
        "a memoryview in format <H": (mv_byteorder, FEINDLICH, "buffer"),
        "a memoryview that is not C-contiguous": (lambda: memoryview(b"abcd")[::2], FEINDLICH, "buffer"),
        "a released memoryview": (mv_released, FEINDLICH, "buffer"),
        "a keys view of an OrderedDict": (lambda: dict.keys(OrderedDict(a=1)), FEINDLICH, "view"),
        "a mapping proxy over a Mapping that is no dict": (lambda: types.MappingProxyType(_Abbild({"a": 1})),
                                                           FEINDLICH, "view"),
        "a dict whose keys meet as one": (lambda: {"a": [1], _Spiegel("a"): [2]}, FEINDLICH, "container"),
        "a dict keyed by a namedtuple": (lambda: {_Paar(1): [1]}, FEINDLICH, "container"),
        "a dict keyed by an IntEnum": (lambda: {_Stufe.EINS: [1]}, FEINDLICH, "container"),
        "a dict keyed by an object": (lambda: {_Objekt(): [1]}, FEINDLICH, "container"),
        "a set whose items meet as one": (lambda: {"a", _Spiegel("a")}, FEINDLICH, "container"),
        "a set of an object": (lambda: {_Objekt()}, FEINDLICH, "container"),
        "a frozenset of an object": (lambda: frozenset({_Objekt()}), FEINDLICH, "object"),
        "an object of the caller": (_Objekt, FEINDLICH, "object"),
        "a subclass of int": (lambda: _Zahl(1), FEINDLICH, "object"),
        "a subclass of float": (lambda: _Komma(1.0), FEINDLICH, "object"),
        "an IntEnum of the caller": (lambda: _Stufe.EINS, FEINDLICH, "object"),
        "a UserDict": (lambda: UserDict({"a": [1]}), FEINDLICH, "mapping"),
        "a ChainMap": (lambda: ChainMap({"a": [1]}), FEINDLICH, "mapping"),
        "a Mapping that is no dict": (lambda: _Abbild({"a": [1]}), FEINDLICH, "mapping"),
        "a datetime with a tzinfo of the caller": (lambda: datetime(2026, 1, 1, tzinfo=_Zone()), FEINDLICH, "datetime"),
        "a callable": (lambda: (lambda *a, **k: True), FEINDLICH, "callable"),
        "a partial": (lambda: functools.partial(len), FEINDLICH, "callable"),
        "a subclass of str as a value": (lambda: _Text("x"), ZUGESAGT, "text"),
        "a subclass of bytes as a value": (lambda: _Roh(b"x"), ZUGESAGT, "text"),
        "a subclass of dict": (lambda: type("_D", (dict,), {})(a=[1]), ZUGESAGT, "container"),
        "a subclass of list": (lambda: type("_L", (list,), {})([1, [2]]), ZUGESAGT, "container"),
        "a dict keyed by a subclass of str": (lambda: {_Text("k"): [1]}, ZUGESAGT, "container"),
        "a dict": (lambda: {"a": [1]}, KONTROLLE, "container"),
        "a list": (lambda: [1, [2]], KONTROLLE, "container"),
        "a tuple": (lambda: (1, [2]), KONTROLLE, "container"),
        "a set": (lambda: {1, "a"}, KONTROLLE, "container"),
        "a frozenset of plain values": (lambda: frozenset({1, "a"}), KONTROLLE, "atom"),
        "a bytearray": (lambda: bytearray(b"ab"), KONTROLLE, "container"),
        "a deque": (lambda: deque([1, [2]]), KONTROLLE, "container"),
        "an OrderedDict": (lambda: OrderedDict(a=[1]), KONTROLLE, "container"),
        "a keys view of a dict": (lambda: {"a": [1]}.keys(), KONTROLLE, "view"),
        "a mapping proxy over a dict": (lambda: types.MappingProxyType({"a": [1]}), KONTROLLE, "view"),
        "a memoryview in format B": (lambda: memoryview(bytearray(b"ab")), KONTROLLE, "buffer"),
        "an aware datetime in UTC": (lambda: datetime(2026, 1, 1, tzinfo=timezone.utc), KONTROLLE, "atom"),
    }


def _orte(mache: Callable[[], Any]) -> "dict[str, Callable[[], Any]]":
    return {"the argument": mache, "an item of a list": lambda: [mache()],
            "a value of a dict": lambda: {"k": mache()}, "an item of a tuple": lambda: (mache(),)}


#: Which kinds of object the contract lets reach the body, at which place.
_ERLAUBT = {
    _RUECKRUF: {("the argument", "callable")},
    _SIGNIERER: {("the argument", k) for k in ("object", "callable", "iterator", "mapping", "datetime")},
    _SIGNIERER_JE_NAME: {("a value of a dict", k) for k in ("object", "callable", "iterator", "mapping", "datetime")},
    _PFAD: set(),
    _UHR: {("the argument", "datetime")},
    # The adapter reads a loaded inspect_ai log by its own model, a producer's source (`canonical`, contract kind
    # `pfad_oder_objekt`): an object or a mapping of the caller's reaches it as it is, a callable or an iterator does not.
    _PFAD_ODER_LOG: {("the argument", k) for k in ("object", "mapping")},
}

#: Types whose values are immutable and run only the interpreter's own code: shared between the caller and the copy
#: they decide nothing a caller can change.
_ATOME = (str, bytes, int, float, bool, type(None), complex, range, timedelta)


def _teile(wert: Any) -> "dict[int, Any]":
    """id -> object for every object reachable from ``wert`` through built-in containers, read by what each stores,
    exact atoms left out (they cannot change). A form that reaches the body is found by its id here."""
    out: dict = {}
    stapel = [wert]
    gesehen: set = set()
    while stapel:
        w = stapel.pop()
        if id(w) in gesehen:
            continue
        gesehen.add(id(w))
        t = type(w)
        if t in _ATOME:
            continue
        out[id(w)] = w
        if issubclass(t, dict):
            for k, v in list(dict.items(w)):
                stapel.append(k)
                stapel.append(v)
            continue
        for basis in (list, tuple, set, frozenset, deque):
            if issubclass(t, basis):
                stapel.extend(list(basis.__iter__(w)))
                break
    return out


def _unveraenderlich(wert: Any) -> bool:
    """A value the caller cannot change and whose reading runs no code of the caller: a frozenset of exact atoms, and
    an exact datetime whose tzinfo is None or the standard library's own `timezone`."""
    t = type(wert)
    if t is frozenset:
        return all(type(x) in _ATOME for x in frozenset.__iter__(wert))
    if t is datetime:
        return wert.tzinfo is None or type(wert.tzinfo) is timezone
    return False


class _Gestoppt(BaseException):
    """Ends a call after its reading, so its body never runs."""


def _gelesen_bei(fn: Callable, kwargs: dict) -> "tuple[str, Any]":
    """The call ``fn(**kwargs)`` up to its reading: ("read", (args, kwargs) the body would receive), ("refused",
    the type name of the typed refusal), or ("raised", the type name of anything else)."""
    gesehen: dict = {}
    original = canonical._gelesen

    def spion(namen, leser, args, kw, *weiter):
        gesehen["aus"] = original(namen, leser, args, kw, *weiter)
        raise _Gestoppt()
    canonical._gelesen = spion
    try:
        fn(**kwargs)
    except _Gestoppt:
        return "read", gesehen["aus"]
    except ProofBundleError as exc:
        return "refused", type(exc).__name__
    except Exception as exc:  # noqa: BLE001 - anything else is reported
        return "raised", type(exc).__name__
    finally:
        canonical._gelesen = original
    return "ran", None


def _fegen(flaechen: "list[tuple[str, Callable]]", formen: dict) -> "tuple[dict, int, int]":
    """(findings by (finding, form, place) -> [function(parameter)], calls, parameters)."""
    befunde: dict = collections.defaultdict(list)
    aufrufe = 0
    parameter = 0
    for name, fn in flaechen:
        gefegt, _ = _parameter(fn)
        for p in gefegt:
            parameter += 1
            art_des_vertrags = _VERTRAG.get((name, p))
            erlaubt = _ERLAUBT.get(art_des_vertrags, set())
            for form, (mache, klasse, art) in formen.items():
                for ort, bauen in _orte(mache).items():
                    wert = bauen()
                    gepflanzt = _teile(wert)
                    aufrufe += 1
                    lage, aus = _gelesen_bei(fn, {p: wert})
                    stelle = f"{name}({p})"
                    if lage == "refused":
                        if klasse != FEINDLICH:
                            befunde[("a promised or plain form is refused", form, ort)].append(stelle)
                        continue
                    if lage != "read":
                        befunde[(f"the reading {lage} {aus}", form, ort)].append(stelle)
                        continue
                    erreicht = _teile(aus)
                    durch = [o for i, o in gepflanzt.items() if i in erreicht and not _unveraenderlich(o)]
                    if not durch:
                        continue
                    if klasse == FEINDLICH and (ort, art) in erlaubt:
                        continue
                    befunde[("an object of the caller reaches the body", form, ort)].append(stelle)
    return befunde, aufrufe, parameter


def _bericht(befunde: dict, grenze: int = 3) -> str:
    zeilen = []
    for (was, form, ort), stellen in sorted(befunde.items()):
        zeilen.append(f"{len(stellen):4d}  {was}: {form}, {ort}, e.g. {', '.join(stellen[:grenze])}")
    return "\n".join(zeilen)


class NoObjectOfTheCallerReachesABody(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        cls.flaechen = _flaechen()

    def test_the_denominator_holds(self) -> None:
        """The floor of the sweep: a collapse of the discovery would make the property below pass vacuously."""
        parameter = sum(len(_parameter(fn)[0]) for _, fn in self.flaechen)
        self.assertGreaterEqual(len(self.flaechen), 300, f"the sweep reached {len(self.flaechen)} functions only")
        self.assertGreaterEqual(parameter, 900, f"the sweep reached {parameter} parameters only")

    def test_every_parameter_not_swept_is_positional_only_or_variadic(self) -> None:
        nicht = sorted(f"{name}({p})" for name, fn in self.flaechen for p in _parameter(fn)[1])
        for stelle in nicht:
            with self.subTest(parameter=stelle):
                pass   # named here so the report lists them; the reason is `_NICHT_GEFEGT_GRUND`
        self.assertLessEqual(len(nicht), 40, f"{len(nicht)} parameters are not swept: {nicht}")

    def test_the_contract_names_only_parameters_that_exist(self) -> None:
        vorhanden = {(name, p) for name, fn in self.flaechen for p in _parameter(fn)[0]}
        self.assertEqual(sorted(set(_VERTRAG) - vorhanden), [], "a contract entry names no parameter of the package")

    def test_no_object_of_the_caller_reaches_a_body(self) -> None:
        befunde, aufrufe, parameter = _fegen(self.flaechen, _formen())
        self.assertGreater(aufrufe, 100_000)
        if befunde:
            self.fail(f"{sum(len(v) for v in befunde.values())} findings in {aufrufe} calls over {parameter} "
                      f"parameters:\n{_bericht(befunde)}")

    def test_control_the_sweep_falls_when_the_copy_hands_a_list_on(self) -> None:
        """The sweep can fail: with the reading taught to leave a list as the caller's object, a plain list reaches
        the body and is found. Planted in both steps where a value is left: `_lies` reads no list, and, where the
        reading classifies what it does not read (`_art_des_blatts`), a list counts as an atom it hands on."""
        original = canonical._lies
        art_original = getattr(canonical, "_art_des_blatts", None)

        def ohne_listen(wert):
            return None if type(wert) is list else original(wert)

        def liste_als_atom(wert, typ):
            return "atom" if typ is list else art_original(wert, typ)
        canonical._lies = ohne_listen
        if art_original is not None:
            canonical._art_des_blatts = liste_als_atom
        try:
            befunde, _, _ = _fegen(self.flaechen[:5], {"a list": _formen()["a list"]})
        finally:
            canonical._lies = original
            if art_original is not None:
                canonical._art_des_blatts = art_original
        self.assertTrue(any(was == "an object of the caller reaches the body" for was, _, _ in befunde),
                        "the sweep did not see a list handed on")


if __name__ == "__main__":
    unittest.main()
