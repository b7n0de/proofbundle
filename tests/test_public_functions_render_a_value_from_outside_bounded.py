"""No public function lets a value from outside escape unrendered, five sibling-branch files aside.

THE CLASS, stated as the violated assumption: *a value that reaches a message, a subject name or a
serializer can be rendered.* It cannot always be. CPython caps int->str at 4300 digits
(CVE-2020-10735), so `str(10**5000)` raises ValueError; `repr` of a list nested deeper than the
interpreter's recursion guard raises RecursionError; `json.dumps` refuses a set or bytes with
TypeError; an object's own `__repr__` can raise anything. When such a value comes from outside (a
caller argument, a policy key or value, a receipt field) and is rendered without `budget.render_safe`
or serialized without a mapping to the module's typed error, the raw exception leaves a function
whose contract is a verdict or a typed refusal, or a never-raise verify surface answers
`internal_error`.

THE FAMILY IS DERIVED, NOT LISTED: every public function (no leading underscore, defined in the module
that holds it) of every module under `proofbundle`, but `cli` and `pytest_plugin` (`_EXCLUDED_MODULES`
says why). A function without parameters takes nothing from a caller and is left out by that rule.

THE SEEDS. `tests/fixtures/public_surface_seeds.json` holds, per family member, one or two calls the
suite itself makes to it from outside the package (recorded from the suite of d6d89763): the smallest
recorded call that returns, and the largest under 6,000 bytes. A function whose recorded calls all
refuse borrows a returning call of a sibling in its module. Values JSON cannot hold are written as
markers (`_decode`); a private key is written as the name of one of two fixed test keys, never as key
material, because this file ships in the sdist and must not read a key from a file. One entry is
written rather than recorded and says so in its `note`: the lineage value
`evaluate_relations_policy` renders under `reject_superseded`, which no recorded call reaches. A
function that needs a file, a key object or a callable is seeded in `_HAND_SEEDS`.
`test_every_family_member_is_seeded` is the forcing function: a new public function without a seed
or a named reason turns it red.

THE GENERATOR. Into every parameter of every seed, into every node of a dict or list argument (up to
150 nodes, evenly spaced), and as a new key of every dict in it (up to 50), it plants 10**5000,
-10**5000, a list too deep to render (`_DEPTH`, measured on the running interpreter), a tuple
holding 10**5000, a set, bytes, and an object whose `__repr__`, `__str__` and `__format__` raise
(keys: the hashable five). A new key is planted twice, once with the value 1 and once with a copy of
the dict's first value, so that it also reaches the code that reads an entry shaped like its siblings
(a relation name whose rule is an object). Each call must return an answer that is no
`internal_error`, or raise an exception class the package defines (or the builtin one its module
documents, `_DOCUMENTED_BUILTIN`), whose message renders.

WHAT A RAW RAISE IS, by kind:
* A CLASS ESCAPE: the planted object was rendered, the digit cap or the recursion limit was hit, or
  `json.dumps` refused the value. Never allowed, but for the five files another branch of the same
  release changes (`_SIBLING_BRANCH_FILES`), where the sites are an upper bound (`_SIBLING_BRANCH`).
* A WRONG TYPE IN A COMPUTATION (an AttributeError, a comparison TypeError, `open()` of an int, ...):
  outside this class, and pinned per function in `_WRONG_TYPE_GAPS`, by (innermost package function,
  exception). The pin is an upper bound always, and exact where every seed of the function returned
  at baseline, so a gap that closes has to leave the list.

MEASURED on d6d89763, the tree before this change, with CPython 3.10: 52 of 307 functions let a
planted value out raw or answered `internal_error`, in 2,237 of 54,785 calls, and 60 of the 313
cases this file has there are red (52 of them with class escapes, 5 with the raw raises of
`load_statement_strict`, `dsse.pae` and `build_verifier_block` only, and three meta tests). After
it: 0 of 309 functions, in 54,827 calls, on each of 3.10, 3.11, 3.12, 3.13 and 3.14.
The meta tests show that the generator catches a planted raw renderer and a planted raw serializer,
and that a generator with nothing to plant fails instead of passing.

HONEST LIMITS: a seed reaches the code its one or two calls reach, so a branch only other inputs take
is not measured; a parameter taken by `*args` or `**kwargs` is not planted into; a planted value
inside a tuple, a set or an object other than a dict or list is not reached; and `str(exc)` is asked of
a typed error, not of every answer a function returns.
"""
from __future__ import annotations

import base64
import binascii
import copy
import dataclasses
import importlib
import inspect
import itertools
import json
import pkgutil
import shutil
import signal
import socket
import traceback
import warnings
from pathlib import Path

import pytest

import proofbundle

REPO = Path(__file__).resolve().parents[1]
PKG = Path(proofbundle.__file__).resolve().parent
SEEDS = REPO / "tests" / "fixtures" / "public_surface_seeds.json"

#: Modules whose functions are not called by a caller of the library.
_EXCLUDED_MODULES = {
    "proofbundle.cli": "the command line: its functions take argv and print, and every library function "
                       "it calls is in the family",
    "proofbundle.pytest_plugin": "pytest hooks: pytest calls them with its own objects",
}

#: Five files another branch of the same release changes. A class escape whose innermost package frame
#: is in one of them is fixed there, and held here as an upper bound only.
_SIBLING_BRANCH_FILES = frozenset({"intoto.py", "_verdict.py", "sdjwt_issue.py", "canonical.py",
                                   "evalclaim.py"})

#: A module that documents a builtin exception as its refusal.
_DOCUMENTED_BUILTIN = {
    "proofbundle._wire_b64": (binascii.Error,),       # module docstring, EXCEPTIONS
    "proofbundle.adapters._provenance": (ValueError,),  # _als_text, add_provenance, bind_reported_version
}

#: Per-call time limit in seconds, and the functions with a shorter one because a planted number is
#: a loop bound there (outside this class; the timeout is pinned as a gap).
_TIME_LIMIT = 30.0
_SHORT_TIME_LIMIT = {
    "proofbundle.outcome.detect_outcome_sequence_gaps":
        (1.0, "range() between the smallest and largest planted sequence number: a compute bound"),
}

_MAX_NODES = 150
_MAX_DICTS = 50
_NEW_KEY = object()   # the last step of a path that plants a key with the value 1
_NEW_KEY_LIKE_A_SIBLING = object()   # ... a key with a copy of the first value beside it


# ── planted values ─────────────────────────────────────────────────────────────────────────────────
class _Rendered(Exception):
    """Raised by `_Hostile` when anything renders it."""


class _Hostile:
    """An object whose text forms raise: it stands for any value whose rendering is not safe."""

    def __repr__(self):
        raise _Rendered("__repr__ of a value from outside")

    def __str__(self):
        raise _Rendered("__str__ of a value from outside")

    def __format__(self, spec):
        raise _Rendered("__format__ of a value from outside")


def _deep(n: int) -> list:
    """A list nested `n` levels deep, built by a loop, so that building it never recurses."""
    wert: list = []
    for _ in range(n):
        wert = [wert]
    return wert


#: HOW DEEP IS TOO DEEP DEPENDS ON THE INTERPRETER, so the depth is measured here, not written down.
#: The recursion guard of `repr` and `json.dumps` is the Python recursion limit on 3.10 and 3.11, a
#: fixed C recursion limit on 3.12 and 3.13, and a limit derived from the C stack on 3.14. Measured on
#: 27.09.2026 (smallest refused depth, `repr` / `json.dumps`): 996 / 993 on 3.10.12 and 3.11.15,
#: 9,997 / 9,997 on 3.12.14, 9,998 / 9,998 on 3.13.15, 40,121 / 74,509 on 3.14.7. The fixed 3000 of
#: the first form was refused on 3.10 and 3.11 only, so on the CI interpreter (3.12) the
#: RecursionError half of the class was never exercised, and the meta test below was red there.
#:
#: The depth is 1.5 times the smallest depth `json.dumps` refuses (found to within 1/64 by
#: doubling and halving), a margin for a call site with more of the guard left than this import had
#: (one with less refuses earlier), and never below the 3000 the lens brief names. `repr` is then
#: asked once at that depth, and searched the same way only if it does not refuse there: its cost
#: grows with the square of the depth (`Py_ReprEnter` scans a list of the objects being rendered),
#: measured at 567 ms for a list 38,000 deep on 3.14.7, so a search over it costs seconds per
#: process. The search stops at `_DEPTH_CAP`; past it the meta test is red, not skipped. The meta
#: test asserts both refusals at the planted depth, in the process the sweep runs in.
_DEPTH_FLOOR = 3000
_DEPTH_CAP = 1 << 20


def _refused(render, n: int) -> bool:
    try:
        render(_deep(n))
    except RecursionError:
        return True
    return False


def _smallest_refused_depth(render) -> int | None:
    """A depth at which `render` raises RecursionError, at most 1/64 above the smallest one, or None
    when none up to `_DEPTH_CAP` does."""
    unten, oben = 0, 1
    while not _refused(render, oben):
        if oben >= _DEPTH_CAP:
            return None
        unten, oben = oben, min(2 * oben, _DEPTH_CAP)
    while oben - unten > max(1, oben // 64):
        mitte = (unten + oben) // 2
        unten, oben = (unten, mitte) if _refused(render, mitte) else (mitte, oben)
    return oben


def _with_margin(tiefe: int) -> int:
    return max(_DEPTH_FLOOR, (3 * tiefe + 1) // 2)


def _derive_depth() -> tuple[int, dict]:
    """(the planted depth, what was measured to choose it)."""
    json_tiefe = _smallest_refused_depth(json.dumps)
    gemessen: dict = {"json.dumps refuses at": json_tiefe}
    if json_tiefe is None:
        return _DEPTH_CAP, gemessen
    tiefe = _with_margin(json_tiefe)
    if _refused(repr, tiefe):
        gemessen["repr refuses at"] = f"<= {tiefe}"
        return tiefe, gemessen
    repr_tiefe = _smallest_refused_depth(repr)
    gemessen["repr refuses at"] = repr_tiefe
    return (_DEPTH_CAP if repr_tiefe is None else max(tiefe, _with_margin(repr_tiefe))), gemessen


_DEPTH, _REFUSED_AT = _derive_depth()

#: Every level of one chain `_DEPTH - 1` lists deep, outermost first, built once per process: built
#: per call, the planted list cost 2.8 ms on 3.12.14 and 13 ms on 3.14.7 (measured, build and free)
#: for each of about 7,000 plants a run makes. Every call gets a fresh outer list around the shared
#: chain, and before each hand-out the top `_KETTE_GEPRUEFT` levels and the innermost list are
#: checked and the chain rebuilt if a call changed them. A change deeper than that and above the
#: innermost list is not seen: that is the stated limit of the sharing.
_KETTE: list = []
_KETTE_GEPRUEFT = 4096


def _kette_intakt() -> bool:
    if len(_KETTE) != _DEPTH:
        return False
    for i in range(min(_KETTE_GEPRUEFT, _DEPTH - 1)):
        ebene = _KETTE[i]
        if type(ebene) is not list or len(ebene) != 1 or ebene[0] is not _KETTE[i + 1]:
            return False
    return type(_KETTE[-1]) is list and not _KETTE[-1]


def _planted_deep_list() -> list:
    """A fresh list `_DEPTH` levels deep: a new outer list around the shared chain."""
    if not _kette_intakt():
        ebenen: list = [[]]
        for _ in range(_DEPTH - 1):
            ebenen.append([ebenen[-1]])
        ebenen.reverse()
        _KETTE[:] = ebenen
    return [_KETTE[0]]


_VALUES = {
    "10**5000": lambda: 10**5000,
    "-10**5000": lambda: -10**5000,
    f"a list {_DEPTH} deep": _planted_deep_list,
    "a tuple holding 10**5000": lambda: (10**5000,),
    "a set": lambda: {1, 2},
    "bytes": lambda: b"x",
    "an object whose repr raises": _Hostile,
}
_KEYS = {k: _VALUES[k] for k in ("10**5000", "-10**5000", "a tuple holding 10**5000", "bytes",
                                 "an object whose repr raises")}


# ── the family ─────────────────────────────────────────────────────────────────────────────────────
#: Modules this environment cannot import, because an optional dependency is missing (the
#: `inspect_ai` hook without `inspect_ai`). Their functions are not measured here, and said so.
_UNIMPORTABLE: dict = {}


def _family() -> dict:
    familie = {}
    for m in pkgutil.walk_packages(proofbundle.__path__, "proofbundle."):
        if m.name in _EXCLUDED_MODULES:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                mod = importlib.import_module(m.name)
        except ImportError as exc:
            if (exc.name or "proofbundle").split(".")[0] == "proofbundle":
                raise
            _UNIMPORTABLE[m.name] = f"{type(exc).__name__}: {exc}"
            continue
        for name, obj in vars(mod).items():
            if not name.startswith("_") and inspect.isfunction(obj) and obj.__module__ == m.name:
                familie[f"{m.name}.{name}"] = obj
    return familie


_FAMILY = _family()


def _takes_something(fn) -> bool:
    return any(p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
               for p in inspect.signature(fn).parameters.values())


# ── seeds ──────────────────────────────────────────────────────────────────────────────────────────
_MARKERS = {"$bytes", "$bytearray", "$tuple", "$set", "$frozenset", "$ed25519_private",
            "$ed25519_public", "$object"}


#: The two private keys a seed can hold, written out here. A PRIVATE KEY IS NEVER READ FROM THE
#: CORPUS: this file ships in the sdist, and a shipped test that loads a private key from a file is a
#: signing path `tests/test_sdist_ohne_signierwerkzeug.py` refuses. The corpus names a key "a" or "b"
#: (a seed holds at most two, the two signers of a trust pack), and these constants stand for them.
_FIXED_SEED_A = bytes(range(32))
_FIXED_SEED_B = bytes(range(32, 64))


def _fixed_key(welcher: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if welcher == "b":
        return Ed25519PrivateKey.from_private_bytes(_FIXED_SEED_B)
    return Ed25519PrivateKey.from_private_bytes(_FIXED_SEED_A)


def _decode(o):
    """A fresh object for a seed value: every call gets its own, so a function that changes its
    argument cannot change the next call's."""
    if isinstance(o, list):
        return [_decode(v) for v in o]
    if not isinstance(o, dict):
        return o
    if o and next(iter(o)) in _MARKERS:
        marke, wert = next(iter(o.items()))
        if marke == "$bytes":
            return base64.b64decode(wert)
        if marke == "$bytearray":
            return bytearray(base64.b64decode(wert))
        if marke == "$tuple":
            return tuple(_decode(v) for v in wert)
        if marke == "$set":
            return {_decode(v) for v in wert}
        if marke == "$frozenset":
            return frozenset(_decode(v) for v in wert)
        if marke == "$ed25519_private":
            return _fixed_key(wert)
        if marke == "$ed25519_public":
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            return Ed25519PublicKey.from_public_bytes(bytes.fromhex(wert))
        modul, name = wert.rsplit(".", 1)
        assert modul.startswith("proofbundle"), wert
        return getattr(importlib.import_module(modul), name)(
            **{k: _decode(v) for k, v in o["fields"].items()})
    return {k: _decode(v) for k, v in o.items()}


_RECORDED = json.loads(SEEDS.read_text(encoding="utf-8"))

_TS = "2026-07-01T00:00:00Z"
_SALTS = {"model_salt": b"0" * 16, "dataset_salt": b"1" * 16}


def _fixture(tmp: Path, name: str, root: Path = REPO / "tests" / "fixtures") -> Path:
    """A copy of a test fixture under `tmp`, so that no call can change the original."""
    ziel = tmp / "fixtures" / Path(name).name
    ziel.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / name, ziel)
    return ziel


_FRESH = itertools.count()


def _fresh_path(tmp: Path, name: str) -> str:
    """A path no earlier call wrote to: a writer that creates its file is measured on every call."""
    ziel = tmp / "fresh" / f"{next(_FRESH)}-{name}"
    ziel.parent.mkdir(parents=True, exist_ok=True)
    return str(ziel)


def _test_key():
    return _fixed_key("a")


def _signer_file(tmp: Path):
    from proofbundle import emit
    pfad = _fresh_path(tmp, "signer.key")
    emit.save_signer(_test_key(), pfad)
    return [((pfad,), {})]


def _text_file(tmp: Path, name: str, text: str) -> Path:
    ziel = tmp / "files" / name
    ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text(text, encoding="utf-8")
    return ziel


def _recorded_args(qual: str, i: int = 0) -> tuple:
    seed = _RECORDED[qual][i]
    return tuple(_decode(seed["args"])), _decode(seed["kwargs"])


def _agt_authorized_receipt(tmp: Path):
    (receipt,), _k = _recorded_args("proofbundle.adapters.agt_receipt.payload_hash")
    receipt.update(authorizer_id="authorizer-1", authorization_expires_at="2026-12-31T00:00:00Z",
                   authorization_nonce="n-1")
    return [((receipt,), {})]


def _refusing_verifier(*_a, **_k) -> dict:
    return {"ok": False, "detail": "a verifier registered by the sweep"}


def _mldsa_key(tmp: Path):
    from proofbundle import pqsig
    try:
        return [((pqsig.generate_mldsa("mldsa65"), b"message"), {})]
    except Exception as exc:  # noqa: BLE001 - an optional backend; the case says it did not measure
        pytest.skip(f"no ML-DSA backend in this environment: {type(exc).__name__}")


def _issuer_claim(tmp: Path):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    key = _test_key()
    roh = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return [(({"issuer": "ed25519:" + base64.b64encode(roh).decode("ascii")}, key), {})]


def _disclosure_body(tmp: Path):
    from proofbundle import agent_review as AR
    body = AR.prepare_body_for_disclosure("A pull request body.\n")
    return [((body, f"{AR.DISCLOSURE_BEGIN}\nrendered\n{AR.DISCLOSURE_END}"), {})]


def _lm_eval_jsonl(tmp: Path):
    zeilen = [{"doc_id": i, "filter": "strict-match", "doc_hash": f"d{i}", "prompt_hash": f"p{i}",
               "target_hash": f"t{i}", "filtered_resps": [str(i)], "metrics": ["exact_match"],
               "exact_match": 1.0} for i in (2, 0, 1)]
    return [((_text_file(tmp, "samples.jsonl", "\n".join(json.dumps(z) for z in zeilen)),), {})]


def _emit_claim(tmp: Path):
    (claim, _signer), _k = _recorded_args("proofbundle.evalclaim.emit_eval_receipt")
    return [((claim, "sweep.receipt.json"), {})]


#: Seeds built at run time: a file, a key object or a callable, which the recording cannot hold, and a
#: function newer than the recording, with a call the suite makes to it (`is_int_member`, added with the
#: lens on e5b39b81; tests/test_membership_hashable_guard.py calls it so).
_HAND_SEEDS = {
    "proofbundle._membership.is_int_member": lambda tmp: [((2, (1, 2, 4, 8)), {}), ((True, (1, 2, 4, 8)), {})],
    "proofbundle._integration.emit_claim_receipt": _emit_claim,
    "proofbundle._integration.emit_enabled": lambda tmp: [((False,), {})],
    "proofbundle._schema_shapes.is_sha256_digest": lambda tmp: [(({"sha256": "0" * 64},), {})],
    "proofbundle.adapters.agt_receipt.canonical_authorization_payload": _agt_authorized_receipt,
    "proofbundle.adapters.inspect_ai.from_inspect_ai_log": lambda tmp: [(
        (_fixture(tmp, "inspect_logs/safety_refusal_demo.eval"), "accuracy"),
        dict(comparator=">=", threshold="0.00", timestamp=_TS, **_SALTS))],
    "proofbundle.adapters.lm_eval.from_lm_eval_results": lambda tmp: [(
        (_fixture(tmp, "lm_eval_arc_easy_real.json"), "arc_easy", "acc"),
        dict(comparator=">=", threshold="0.30", timestamp=_TS, **_SALTS))],
    "proofbundle.adapters.promptfoo.from_promptfoo_results": lambda tmp: [(
        (_fixture(tmp, "promptfoo_results_v3.json"),),
        dict(comparator=">=", threshold="0.50", timestamp=_TS, **_SALTS))],
    "proofbundle.adapters.samples.samples_from_lm_eval_jsonl": _lm_eval_jsonl,
    "proofbundle.adapters.samples.samples_from_promptfoo_results": lambda tmp: [(
        (_fixture(tmp, "promptfoo_results_v3.json"),), {})],
    "proofbundle.agent_review.replace_disclosure_block": _disclosure_body,
    "proofbundle.anchors.register_anchor_type": lambda tmp: [(("sweep-anchor/v1", _refusing_verifier), {})],
    "proofbundle._statement_payload.load_statement_strict": lambda tmp: [(
        (b'{"_type":"https://in-toto.io/Statement/v1"}',), {})],
    "proofbundle.bundle.load_bundle": lambda tmp: [(
        (str(_fixture(tmp, "example_bundle.json", REPO / "examples")),), {})],
    "proofbundle.emit.load_signer": _signer_file,
    "proofbundle.emit.save_signer": lambda tmp: [((_test_key(), _fresh_path(tmp, "signer.key")), {})],
    "proofbundle.evalclaim.load_claim_text": lambda tmp: [(('{"suite": "arc_easy", "n": 3}',), {})],
    "proofbundle.anchors_rootcommit.build_preimage": lambda tmp: [(
        ("example.org/log", "7", "ab" * 32, "0x" + "00" * 20), {})],
    "proofbundle.evalcard.evaluation_card_hash": lambda tmp: [(
        (_text_file(tmp, "card.md", "# An eval card\n"),), {})],
    "proofbundle.prereg.prereg_hash": lambda tmp: [((_text_file(tmp, "protocol.md", "# A protocol\n"),), {})],
    "proofbundle.pqsig.sign_mldsa": _mldsa_key,
    "proofbundle.sdjwt_issue.issuer_matches": _issuer_claim,
    "proofbundle.verifier_block.measure_vector_set": lambda tmp: [((REPO / "conformance",), {})],
}

#: Family members with parameters that are not planted into, each with the reason.
_NOT_SEEDED: dict = {}


def _seed_count(qual: str, tmp: Path) -> int:
    return len(_HAND_SEEDS[qual](tmp)) if qual in _HAND_SEEDS else len(_RECORDED[qual])


def _seed(qual: str, tmp: Path, nummer: int) -> tuple:
    """(args, kwargs, must_return) of seed `nummer` of `qual`, built fresh."""
    if qual in _HAND_SEEDS:
        a, k = _HAND_SEEDS[qual](tmp)[nummer]
        return a, k, True
    s = _RECORDED[qual][nummer]
    return tuple(_decode(s["args"])), _decode(s["kwargs"]), s["returns"] is True


_SEEDED = sorted(q for q, fn in _FAMILY.items()
                 if (q in _RECORDED or q in _HAND_SEEDS) and _takes_something(fn))


# ── one sweep ──────────────────────────────────────────────────────────────────────────────────────
class _Timeout(BaseException):
    """The per-call time limit ran out (a BaseException, so no `except Exception` swallows it)."""


def _alarm(_signum, _frame):
    raise _Timeout()


@dataclasses.dataclass
class _Report:
    qual: str
    calls: int = 0
    escapes: list = dataclasses.field(default_factory=list)
    sibling: set = dataclasses.field(default_factory=set)
    gaps: set = dataclasses.field(default_factory=set)
    baseline: list = dataclasses.field(default_factory=list)


#: Frames Python 3.12 inlines into the function around them (PEP 709). They are skipped, so that a
#: site reads the same on every interpreter the CI matrix runs.
_INLINED = frozenset({"<listcomp>", "<dictcomp>", "<setcomp>"})


def _site(exc: BaseException) -> str:
    """`file.py:function` of the innermost frame in the package, the site a raise is pinned by."""
    wo = "<outside the package>"
    for rahmen in traceback.extract_tb(exc.__traceback__):
        try:
            rel = Path(rahmen.filename).resolve().relative_to(PKG)
        except ValueError:
            continue
        if rahmen.name not in _INLINED:
            wo = f"{rel.as_posix()}:{rahmen.name}"
    return wo


def _message(exc: BaseException) -> str | None:
    try:
        return str(exc)
    except Exception:  # noqa: BLE001 - a message that does not render is the finding
        return None


def _class_escape(exc: BaseException) -> bool:
    if isinstance(exc, (_Rendered, RecursionError)):
        return True
    text = _message(exc) or ""
    return ((isinstance(exc, ValueError) and "integer string conversion" in text)
            or (isinstance(exc, TypeError) and "is not JSON serializable" in text))


def _typed(qual: str, exc: BaseException) -> bool:
    if type(exc).__module__.split(".")[0] == "proofbundle":
        return True
    return isinstance(exc, _DOCUMENTED_BUILTIN.get(qual.rsplit(".", 1)[0], ()))


def _internal_error(antwort) -> bool:
    try:
        if isinstance(antwort, dict):
            codes = antwort.get("reason_codes")
            return (antwort.get("reason_code") == "internal_error"
                    or (isinstance(codes, (list, tuple)) and "internal_error" in codes))
        return getattr(antwort, "reason_code", None) == "internal_error"
    except Exception:  # noqa: BLE001 - an answer that cannot be asked is judged elsewhere
        return False


def _call(fn, bound: inspect.BoundArguments, limit: float):
    """(answer, exception) of one call, under a time limit where the platform has one."""
    uhr = hasattr(signal, "setitimer")
    if uhr:
        vorher = signal.signal(signal.SIGALRM, _alarm)
        signal.setitimer(signal.ITIMER_REAL, limit)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return fn(*bound.args, **bound.kwargs), None
    except (Exception, SystemExit, _Timeout) as exc:  # noqa: BLE001 - every raise is judged
        return None, exc
    finally:
        if uhr:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, vorher)


def _nodes(o, pfad=(), tiefe=0):
    yield pfad
    if tiefe > 12:
        return
    if isinstance(o, dict):
        for k, v in list(o.items()):
            yield from _nodes(v, pfad + (k,), tiefe + 1)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _nodes(v, pfad + (i,), tiefe + 1)


def _at(o, pfad):
    for schritt in pfad:
        o = o[schritt]
    return o


def _spaced(liste: list, n: int) -> list:
    if len(liste) <= n:
        return liste
    schritt = len(liste) / n
    return [liste[int(i * schritt)] for i in range(n)]


def _label(pfad: tuple) -> str:
    def schritt(s) -> str:
        if s is _NEW_KEY:
            return "<a new key>"
        if s is _NEW_KEY_LIKE_A_SIBLING:
            return "<a new key, a sibling's value>"
        return repr(s) if isinstance(s, (str, int)) and len(str(s)) < 40 else "..."
    return "".join(f"[{schritt(s)}]" for s in pfad)


def _judge(rep: _Report, qual: str, wo: str, antwort, exc) -> None:
    if exc is None:
        if _internal_error(antwort):
            rep.escapes.append((wo, "internal_error answer", ""))
        return
    if isinstance(exc, _Timeout):
        rep.gaps.add(("<time limit>", "timeout"))
        return
    if _class_escape(exc):
        site = _site(exc)
        if site.split(":")[0] in _SIBLING_BRANCH_FILES:
            rep.sibling.add((site, type(exc).__name__))
        else:
            rep.escapes.append((wo, type(exc).__name__, site))
        return
    if _typed(qual, exc):
        if _message(exc) is None:
            rep.escapes.append((wo, f"{type(exc).__name__} whose message does not render", _site(exc)))
        return
    rep.gaps.add((_site(exc), type(exc).__name__))


def _sweep(qual: str, tmp: Path, values: dict | None = None, keys: dict | None = None) -> _Report:
    values = _VALUES if values is None else values
    keys = _KEYS if keys is None else keys
    fn = _FAMILY[qual]
    sig = inspect.signature(fn)
    limit = _SHORT_TIME_LIMIT.get(qual, (_TIME_LIMIT, ""))[0]
    rep = _Report(qual)
    params = [p for p in sig.parameters.values() if p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
    for nummer in range(_seed_count(qual, tmp)):
        args, kwargs, must_return = _seed(qual, tmp, nummer)
        antwort, exc = _call(fn, sig.bind(*args, **kwargs), _TIME_LIMIT)
        rep.baseline.append((must_return, exc))

        def frisch(p=None):
            a, k, _m = _seed(qual, tmp, nummer)
            argumente = dict(sig.bind(*a, **k).arguments)
            if p is not None and p.name not in argumente and p.default is not p.empty:
                argumente[p.name] = copy.deepcopy(p.default)   # never the function's own default
            return argumente

        for p in params:
            probe = frisch(p).get(p.name)
            ziele: list = [((), label) for label in values]
            if isinstance(probe, (dict, list)):
                knoten = _spaced([k for k in _nodes(probe) if k], _MAX_NODES)
                ziele += [(k, label) for k in knoten for label in values]
                dicts = _spaced([k for k in _nodes(probe) if isinstance(_at(probe, k), dict)], _MAX_DICTS)
                ziele += [(k + (_NEW_KEY,), label) for k in dicts for label in keys]
                ziele += [(k + (_NEW_KEY_LIKE_A_SIBLING,), label) for k in dicts if _at(probe, k)
                          for label in keys]
            for pfad, label in ziele:
                argumente = frisch(p)
                if not pfad:
                    argumente[p.name] = values[label]()
                elif pfad[-1] is _NEW_KEY:
                    _at(argumente[p.name], pfad[:-1])[keys[label]()] = 1
                elif pfad[-1] is _NEW_KEY_LIKE_A_SIBLING:
                    ziel = _at(argumente[p.name], pfad[:-1])
                    ziel[keys[label]()] = copy.deepcopy(next(iter(ziel.values())))
                else:
                    _at(argumente[p.name], pfad[:-1])[pfad[-1]] = values[label]()
                gebunden = inspect.BoundArguments(sig, {n: argumente[n] for n in sig.parameters
                                                        if n in argumente})
                rep.calls += 1
                antwort, exc = _call(fn, gebunden, limit)
                _judge(rep, qual, f"seed {nummer}, {p.name}{_label(pfad)}={label}", antwort, exc)
    return rep


def _absent_dependency(exc: BaseException | None) -> bool:
    """Did `exc` come from an optional dependency this environment lacks?

    An ImportError of a module outside the package, anywhere in the chain, and the one refusal the
    package raises for a missing backend without an ImportError behind it:
    `anchors_rootcommit._NoSigLib`, which `_keccak256` raises after it tried every keccak backend
    (its docstring: "raises _NoSigLib if none is available"). An ImportError of a `proofbundle`
    module is a defect of the package, never an absent dependency, and is not read as one."""
    while exc is not None:
        if isinstance(exc, ImportError):
            return (exc.name or "proofbundle").split(".")[0] != "proofbundle"
        if type(exc).__name__ == "_NoSigLib" and type(exc).__module__ == "proofbundle.anchors_rootcommit":
            return True
        exc = exc.__cause__ or exc.__context__
    return False


@pytest.fixture
def _quiet_world(tmp_path, monkeypatch):
    """No network, no chia binary, no writes outside `tmp_path`, and an anchor registry of its own."""
    from proofbundle import anchors, anchors_chia_add

    def _no_network(*_a, **_k):
        raise OSError("network disabled for the public surface sweep")

    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(anchors_chia_add, "_CHIA_BIN", str(tmp_path / "no-chia-binary"))
    monkeypatch.setattr(anchors, "_VERIFIERS", dict(anchors._VERIFIERS))
    for name in ("PROOFBUNDLE_EMIT", "PROOFBUNDLE_KEY", "PROOFBUNDLE_ANCHOR_LOCK_PATH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PROOFBUNDLE_OUT", str(tmp_path / "out"))
    monkeypatch.chdir(tmp_path)
    return tmp_path


# ── the pins ───────────────────────────────────────────────────────────────────────────────────────
# Keyed by the function without the `proofbundle.` prefix; each entry is "<innermost package function>
# <exception>". Measured on d6d89763 plus this change with CPython 3.10, 3.11, 3.12, 3.13 and 3.14 (the
# CI matrix): the gaps are the same on all five, with the planted list as deep as each interpreter
# needs (`_DEPTH`).

#: Class escapes whose innermost package frame is in one of the five files of the sibling branch
#: (`_SIBLING_BRANCH_FILES`). Fixed there; an upper bound here, never exact, so that branch landing
#: first turns nothing red.
_SIBLING_BRANCH: dict = {
    "_verdict.require_bool_verdict": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered",
    },
    "adapters.inspect_ai.from_inspect_ai_log": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
    },
    "adapters.lm_eval.from_lm_eval_results": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
    },
    "adapters.promptfoo.from_promptfoo_results": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
    },
    "evalclaim.build_eval_claim": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
        "evalclaim.py:build_eval_claim RecursionError", "evalclaim.py:build_eval_claim ValueError",
        "evalclaim.py:build_eval_claim _Rendered",
    },
    "evalclaim.canonicalize": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
    },
    "evalclaim.check_freshness": {"evalclaim.py:check_freshness ValueError"},
    "evalclaim.emit_eval_receipt": {
        "evalclaim.py:_reject_non_jcs RecursionError", "evalclaim.py:_reject_non_jcs ValueError",
    },
    "intoto.export_eval_result_dsse": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered", "intoto.py:_declare_content_root_alg RecursionError",
        "intoto.py:_declare_content_root_alg ValueError", "intoto.py:_declare_content_root_alg _Rendered",
        "intoto.py:resolve_subject RecursionError", "intoto.py:resolve_subject TypeError",
        "intoto.py:resolve_subject ValueError", "intoto.py:resolve_subject _Rendered",
    },
    "intoto.export_intoto_dsse": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered", "intoto.py:_declare_content_root_alg RecursionError",
        "intoto.py:_declare_content_root_alg ValueError", "intoto.py:_declare_content_root_alg _Rendered",
        "intoto.py:export_intoto_dsse RecursionError", "intoto.py:export_intoto_dsse TypeError",
        "intoto.py:export_intoto_dsse ValueError", "intoto.py:to_test_result_statement RecursionError",
        "intoto.py:to_test_result_statement ValueError", "intoto.py:to_test_result_statement _Rendered",
    },
    "intoto.export_svr_dsse": {
        "intoto.py:_declare_content_root_alg RecursionError",
        "intoto.py:_declare_content_root_alg ValueError", "intoto.py:_declare_content_root_alg _Rendered",
    },
    "intoto.resolve_subject": {
        "intoto.py:resolve_subject RecursionError", "intoto.py:resolve_subject TypeError",
        "intoto.py:resolve_subject ValueError", "intoto.py:resolve_subject _Rendered",
    },
    "intoto.svr_properties": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered",
    },
    "intoto.to_eval_result_predicate": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered",
    },
    "intoto.to_eval_result_statement": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered", "intoto.py:_declare_content_root_alg RecursionError",
        "intoto.py:_declare_content_root_alg ValueError", "intoto.py:_declare_content_root_alg _Rendered",
    },
    "intoto.to_intoto_statement": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered",
    },
    "intoto.to_test_result_statement": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered", "intoto.py:_declare_content_root_alg RecursionError",
        "intoto.py:_declare_content_root_alg ValueError", "intoto.py:_declare_content_root_alg _Rendered",
        "intoto.py:to_test_result_statement RecursionError",
        "intoto.py:to_test_result_statement ValueError", "intoto.py:to_test_result_statement _Rendered",
    },
    "intoto.verify_eval_result_dsse": {
        "intoto.py:_intoto_verify_result RecursionError", "intoto.py:_intoto_verify_result ValueError",
        "intoto.py:_intoto_verify_result _Rendered",
    },
    "intoto.verify_intoto_dsse": {
        "intoto.py:_intoto_verify_result RecursionError", "intoto.py:_intoto_verify_result ValueError",
        "intoto.py:_intoto_verify_result _Rendered",
    },
    "intoto.verify_svr_dsse": {
        "intoto.py:_intoto_verify_result RecursionError", "intoto.py:_intoto_verify_result ValueError",
        "intoto.py:_intoto_verify_result _Rendered",
    },
    "sdjwt_issue.issue_sd_jwt": {
        "_verdict.py:require_bool_verdict RecursionError", "_verdict.py:require_bool_verdict ValueError",
        "_verdict.py:require_bool_verdict _Rendered", "sdjwt_issue.py:_make_disclosure RecursionError",
        "sdjwt_issue.py:_make_disclosure TypeError", "sdjwt_issue.py:_make_disclosure ValueError",
        "sdjwt_issue.py:issue_sd_jwt RecursionError", "sdjwt_issue.py:issue_sd_jwt TypeError",
        "sdjwt_issue.py:issue_sd_jwt ValueError",
    },
    "sdjwt_issue.present_with_key_binding": {
        "sdjwt_issue.py:present_with_key_binding RecursionError",
        "sdjwt_issue.py:present_with_key_binding TypeError",
        "sdjwt_issue.py:present_with_key_binding ValueError",
    },
}

#: Raw raises OUTSIDE this class: a value of the wrong type used in a computation (a method it does
#: not have, a comparison or an arithmetic operation it does not support, `open()` or `len()` of an
#: int, `bytes + int`, a JSONDecodeError on bytes where text belongs), a third-party exception that
#: crossed unmapped (rfc8785's CanonicalizationError, urllib's URLError), and the one timeout
#: (`_SHORT_TIME_LIMIT`). Each is the next class to close, not this one. The pin is an upper bound, so a
#: new raw raise turns the case red, and exact wherever every seed of the function returned at
#: baseline, so a gap that closes must leave the list; a site in a sibling-branch file is upper bound
#: only.
_WRONG_TYPE_GAPS: dict = {
    "_strict_json.enforce_structural_budget": {"_strict_json.py:enforce_structural_budget AttributeError"},
    "_strict_json.loads_strict": {
        "_strict_json.py:loads_strict AttributeError", "_strict_json.py:loads_strict JSONDecodeError",
        "_strict_json.py:loads_strict TypeError",
    },
    "adapters._provenance.add_provenance": {"adapters/_provenance.py:add_provenance TypeError"},
    "adapters._provenance.bind_reported_version": {
        "adapters/_provenance.py:bind_reported_version AttributeError",
        "adapters/_provenance.py:bind_reported_version TypeError",
    },
    "adapters.agt_receipt.canonical_authorization_payload": {
        "adapters/agt_receipt.py:canonical_authorization_payload AttributeError",
    },
    "adapters.agt_receipt.exit_code": {"adapters/agt_receipt.py:exit_code AttributeError"},
    # The TypeError left with the lens on e5b39b81 (M1): `set(trusted_authorizer_keys)` hashed the
    # relying party's list, and a planted number, object or deep list raised there.
    "adapters.agt_receipt.verify_agt_receipt": {
        "adapters/agt_receipt.py:verify_agt_receipt OverflowError",
    },
    "adapters.agt_receipt.verify_agt_receipt_chain": {
        "adapters/agt_receipt.py:verify_agt_receipt_chain AttributeError",
    },
    "adapters.eee.from_eee_dataset": {
        "adapters/eee.py:_extract_score TypeError", "adapters/eee.py:_load TypeError",
        "adapters/eee.py:_pick_metric AttributeError", "adapters/eee.py:from_eee_dataset AttributeError",
        "adapters/eee.py:from_eee_dataset TypeError", "evalclaim.py:salted_commit TypeError",
    },
    "adapters.inspect_ai.from_inspect_ai_log": {
        "adapters/inspect_ai.py:from_inspect_ai_log TypeError", "evalclaim.py:salted_commit TypeError",
    },
    "adapters.lm_eval.from_lm_eval_results": {
        "adapters/lm_eval.py:_find_metric TypeError", "adapters/lm_eval.py:from_lm_eval_results TypeError",
        "adapters/lm_eval.py:from_lm_eval_results ValueError", "evalclaim.py:salted_commit TypeError",
    },
    "adapters.promptfoo.from_promptfoo_results": {
        "adapters/promptfoo.py:from_promptfoo_results TypeError", "evalclaim.py:salted_commit TypeError",
    },
    "adapters.samples.samples_from_lm_eval_jsonl": {
        "adapters/samples.py:samples_from_lm_eval_jsonl TypeError",
    },
    "adapters.samples.samples_from_promptfoo_results": {
        "adapters/samples.py:samples_from_promptfoo_results TypeError",
    },
    "agent_review.apply_time_evidence": {
        "agent_review.py:apply_time_evidence TypeError", "agent_review.py:apply_time_evidence ValueError",
    },
    "agent_review.emit_agent_review": {"dsse.py:sign_envelope AttributeError"},
    "agent_review.evaluate_time_policy": {"agent_review.py:evaluate_time_policy AttributeError"},
    "agent_review.findings_root": {"agent_review.py:findings_root TypeError"},
    "agent_review.prepare_body_for_disclosure": {"agent_review.py:prepare_body_for_disclosure TypeError"},
    "agent_review.receipt_digest": {"agent_review.py:receipt_digest AttributeError"},
    "agent_review.replace_disclosure_block": {
        "agent_review.py:replace_disclosure_block AttributeError",
        "agent_review.py:replace_disclosure_block TypeError",
    },
    "agent_review.resolve_receipt_chain": {
        "agent_review.py:receipt_digest AttributeError", "agent_review.py:resolve_receipt_chain TypeError",
    },
    "agent_review.validate_agent_review_predicate": {
        "agent_review.py:_validate_coverage TypeError", "agent_review.py:_validate_declaration TypeError",
    },
    "agent_review.validate_agent_review_v02_predicate": {
        "agent_review.py:validate_agent_review_predicate TypeError",
    },
    "anchors_chia.clvm_atom_hash": {"anchors_chia.py:_h TypeError"},
    "anchors_chia.leaf_node_hash": {"anchors_chia.py:_h TypeError"},
    "anchors_chia.merkle_root_from_layers": {
        "anchors_chia.py:_h TypeError", "anchors_chia.py:_hexatom ValueError",
        "anchors_chia.py:merkle_root_from_layers ValueError",
    },
    "anchors_chia_add.anchor_add": {
        "anchors_chia_add.py:anchor_add AttributeError", "anchors_chia_add.py:anchor_add TypeError",
        "anchors_chia_add.py:anchor_add ValueError",
    },
    "anchors_chia_add.export_anchor": {
        "anchors_chia_add.py:export_anchor OverflowError", "anchors_chia_add.py:export_anchor TypeError",
        "anchors_chia_add.py:export_anchor ValueError",
    },
    "anchors_ots.calendar_operators": {"anchors_ots.py:calendar_operators TypeError"},
    "anchors_rfc3161.create_rfc3161_anchor": {
        "anchors_rfc3161.py:create_rfc3161_anchor TypeError",
        "anchors_rfc3161.py:create_rfc3161_anchor URLError",
    },
    "anchors_rootcommit.eip191_recover_address": {
        "anchors_rootcommit.py:eip191_recover_address AttributeError",
        "anchors_rootcommit.py:eip191_recover_address TypeError",
    },
    "anchors_rootcommit.expected_key_id": {"anchors_rootcommit.py:expected_key_id TypeError"},
    "beacon.beacon_audit_challenge": {
        "beacon.py:beacon_nonce AttributeError", "beacon.py:beacon_nonce TypeError",
    },
    "beacon.beacon_nonce": {"beacon.py:beacon_nonce AttributeError", "beacon.py:beacon_nonce TypeError"},
    "budget.int_magnitude_ok": {"budget.py:int_magnitude_ok AttributeError"},
    "bundle.root_authenticity_summary": {"bundle.py:root_authenticity_summary AttributeError"},
    "canonical.canonicalize_statement": {"canonical.py:canonicalize_statement CanonicalizationError"},
    "canonical.statement_content_root": {"canonical.py:canonicalize_statement CanonicalizationError"},
    "cap1.load_cap1_document": {
        "_strict_json.py:loads_strict JSONDecodeError", "cap1.py:load_cap1_document ValueError",
    },
    "checkpoint.cosign_checkpoint": {"checkpoint.py:cosign_checkpoint AttributeError"},
    "checkpoint.sign_checkpoint": {"checkpoint.py:sign_checkpoint AttributeError"},
    "decision.emit_decision_receipt": {"dsse.py:sign_envelope AttributeError"},
    "decision.resolve_evidence_ref": {"decision.py:resolve_evidence_ref TypeError"},
    "dsse.sign_envelope": {"dsse.py:sign_envelope AttributeError"},
    "emit.emit_bundle": {
        "emit.py:emit_bundle AttributeError", "emit.py:emit_bundle TypeError",
        "merkle.py:leaf_hash TypeError",
    },
    "emit.load_signer": {"emit.py:load_signer FileNotFoundError"},
    "emit.save_signer": {"emit.py:save_signer AttributeError"},
    "evalcard.evaluation_card_hash": {"evalcard.py:evaluation_card_hash FileNotFoundError"},
    "evalclaim.build_eval_claim": {
        "evalclaim.py:build_eval_claim TypeError", "evalclaim.py:salted_commit AttributeError",
        "evalclaim.py:salted_commit TypeError",
    },
    "evalclaim.claim_warnings": {"evalclaim.py:claim_warnings AttributeError"},
    "evalclaim.emit_eval_receipt": {
        "emit.py:emit_bundle TypeError", "evalclaim.py:emit_eval_receipt TypeError",
        "evalclaim.py:emit_eval_receipt ValueError", "evalclaim.py:issuer_fingerprint AttributeError",
        "merkle.py:leaf_hash TypeError",
    },
    "evalclaim.eval_evidence_class": {"evalclaim.py:eval_evidence_class AttributeError"},
    "evalclaim.issuer_fingerprint": {"evalclaim.py:issuer_fingerprint AttributeError"},
    "evalclaim.load_claim_text": {"_strict_json.py:loads_strict JSONDecodeError"},
    "evalclaim.salted_commit": {
        "evalclaim.py:salted_commit AttributeError", "evalclaim.py:salted_commit TypeError",
    },
    "evidence_pack.build_evidence_pack": {
        "evidence_pack.py:build_evidence_pack TypeError",
        "evidence_pack.py:build_evidence_pack ValueError",
    },
    "experimental.enclave.issue_enclave_attestation": {
        "experimental/enclave.py:issue_enclave_attestation AttributeError",
    },
    "hashalg.compute_digest": {"hashalg.py:compute_digest TypeError"},
    "hashalg.compute_dual_hash": {
        "hashalg.py:compute_digest TypeError", "hashalg.py:compute_dual_hash TypeError",
    },
    "hf_evals.eval_results_yaml": {"hf_evals.py:eval_results_yaml TypeError"},
    "intoto.export_eval_result_dsse": {"dsse.py:sign_envelope AttributeError"},
    "intoto.export_intoto_dsse": {
        "dsse.py:sign_envelope AttributeError", "intoto.py:export_intoto_dsse TypeError",
    },
    "intoto.export_svr_dsse": {"dsse.py:sign_envelope AttributeError"},
    "intoto.resolve_subject": {"intoto.py:resolve_subject AttributeError"},
    "intoto.svr_properties": {"intoto.py:svr_properties AttributeError"},
    "intoto.to_eval_result_predicate": {"intoto.py:_commit_hex TypeError"},
    "intoto.to_eval_result_statement": {"intoto.py:_commit_hex TypeError"},
    "intoto.to_intoto_statement": {"intoto.py:_commit_hex TypeError"},
    "intoto.to_test_result_statement": {
        "intoto.py:_commit_hex TypeError", "intoto.py:to_test_result_statement TypeError",
        "intoto.py:to_test_result_statement ValueError",
    },
    "merkle.consistency_proof": {
        "merkle.py:_subproof TypeError", "merkle.py:consistency_proof TypeError",
        "merkle.py:consistency_proof ValueError", "merkle.py:leaf_hash TypeError",
    },
    "merkle.inclusion_proof": {
        "merkle.py:_inclusion TypeError", "merkle.py:inclusion_proof TypeError",
        "merkle.py:inclusion_proof ValueError", "merkle.py:leaf_hash TypeError",
    },
    "merkle.leaf_hash": {"merkle.py:leaf_hash TypeError"},
    "merkle.merkle_tree_hash": {"merkle.py:leaf_hash TypeError", "merkle.py:merkle_tree_hash TypeError"},
    "merkle.root_from_inclusion": {
        "merkle.py:_node_hash TypeError", "merkle.py:root_from_inclusion TypeError",
        "merkle.py:root_from_inclusion ValueError",
    },
    "outcome.detect_outcome_sequence_gaps": {
        "<time limit> timeout", "outcome.py:detect_outcome_sequence_gaps TypeError",
    },
    "outcome.emit_outcome_receipt": {"dsse.py:sign_envelope AttributeError"},
    "outcome.resolve_receiver_ref": {"outcome.py:resolve_receiver_ref TypeError"},
    "persample.build_sample_tree": {"persample.py:build_sample_tree TypeError"},
    "persample.catch_probability": {
        "persample.py:catch_probability OverflowError", "persample.py:catch_probability TypeError",
    },
    "persample.make_disclosure": {"persample.py:make_disclosure TypeError"},
    "persample.sample_opening": {
        "persample.py:sample_opening AttributeError", "persample.py:sample_opening TypeError",
    },
    "policy.evaluate_policy": {"policy.py:evaluate_policy AttributeError"},
    "policy.explain_policy": {"policy.py:explain_policy AttributeError"},
    "policy.lint_policy": {
        "policy.py:explain_policy AttributeError", "policy.py:policy_expired AttributeError",
    },
    "policy.policy_anchor_trust": {"policy.py:policy_anchor_trust AttributeError"},
    "policy.policy_expected_aud": {"policy.py:policy_expected_aud AttributeError"},
    "policy.policy_expired": {"policy.py:policy_expired AttributeError"},
    "policy.policy_not_yet_valid": {"policy.py:policy_not_yet_valid AttributeError"},
    "policy.policy_warnings": {"policy.py:_attributes_to_nobody AttributeError"},
    "policy_profiles.profile_path": {
        "policy_profiles.py:_strip_prefix AttributeError", "policy_profiles.py:_strip_prefix TypeError",
    },
    "policy_profiles.resolve_policy_source": {
        "policy_profiles.py:_strip_prefix TypeError",
        "policy_profiles.py:resolve_policy_source OverflowError",
        "policy_profiles.py:resolve_policy_source TypeError",
    },
    "pqsig.sign_mldsa": {"pqsig.py:sign_mldsa AttributeError", "pqsig.py:sign_mldsa TypeError"},
    "prereg.prereg_hash": {"prereg.py:prereg_hash FileNotFoundError"},
    "relation.verify_relationship_edges": {"relation.py:_dfs TypeError"},
    "relation_statement.emit_relation_statement": {"dsse.py:sign_envelope AttributeError"},
    "renewal.anchor_proof_digest": {"renewal.py:anchor_proof_digest AttributeError"},
    "renewal.build_initial_sequence": {"renewal.py:_validate_digests TypeError"},
    "renewal.last_ats": {"renewal.py:_newest TypeError"},
    "renewal.renew_hashtree": {
        "renewal.py:_all_ats TypeError", "renewal.py:_cover_prior_and_data AttributeError",
        "renewal.py:_newest TypeError", "renewal.py:_require_prior_anchor AttributeError",
        "renewal.py:_sign_ats_content AttributeError", "renewal.py:_validate_digests TypeError",
    },
    "renewal.renew_timestamp": {
        "renewal.py:_newest TypeError", "renewal.py:_require_prior_anchor AttributeError",
        "renewal.py:_sign_ats_content AttributeError", "renewal.py:renew_timestamp TypeError",
    },
    "run_ledger.emit_run_ledger": {"dsse.py:sign_envelope AttributeError"},
    "run_ledger.link_runs": {"run_ledger.py:link_runs TypeError"},
    "sdjwt_issue.issue_sd_jwt": {
        "sdjwt_issue.py:issue_sd_jwt AttributeError", "sdjwt_issue.py:issue_sd_jwt TypeError",
        "sdjwt_issue.py:issue_sd_jwt ValueError",
    },
    "sdjwt_issue.issuer_matches": {"sdjwt_issue.py:issuer_matches AttributeError"},
    "sdjwt_issue.present_with_key_binding": {
        "sdjwt_issue.py:present_with_key_binding AttributeError",
        "sdjwt_issue.py:present_with_key_binding TypeError",
        "sdjwt_issue.py:present_with_key_binding ValueError",
    },
    "statuslist.issue_status_list_token": {
        "statuslist.py:issue_status_list_token AttributeError",
        "statuslist.py:issue_status_list_token TypeError",
    },
    "subject_binding.nested_closure_violations": {
        "subject_binding.py:nested_closure_violations AttributeError",
        "subject_binding.py:nested_closure_violations TypeError",
    },
    "subject_binding.nested_type_violations": {
        "subject_binding.py:_has_type ValueError",
        "subject_binding.py:nested_type_violations AttributeError",
        "subject_binding.py:nested_type_violations TypeError",
    },
    "tlogproof.tlog_proof_for_bundle": {"tlogproof.py:tlog_proof_for_bundle TypeError"},
    "trust_pack.sign_trust_pack": {
        "trust_pack.py:sign_trust_pack AttributeError", "trust_pack.py:sign_trust_pack TypeError",
    },
    "verification_summary.emit_verification_summary": {"dsse.py:sign_envelope AttributeError"},
    "verifier_block.measure_build": {"verifier_block.py:measure_build TypeError"},
    "verifier_block.measure_vector_set": {"verifier_block.py:measure_vector_set TypeError"},
    "verifier_block.measure_verifier_block": {
        "verifier_block.py:measure_build TypeError", "verifier_block.py:measure_vector_set TypeError",
    },
    "verifier_block.sign_test_result_statement": {"dsse.py:sign_envelope AttributeError"},
}


# ── the tests ──────────────────────────────────────────────────────────────────────────────────────
def _assert_clean(rep: _Report) -> None:
    assert rep.calls > 0, f"{rep.qual}: no value was planted, so nothing was measured"
    for must_return, exc in rep.baseline:
        if must_return and exc is not None and not _absent_dependency(exc):
            raise AssertionError(f"{rep.qual}: a seed that returned when it was recorded now raises "
                                 f"{type(exc).__name__} ({_message(exc)!s:.200}); it no longer reaches "
                                 "the code behind the first check")
    assert not rep.escapes, (f"{rep.qual}: {len(rep.escapes)} of {rep.calls} calls escaped raw, "
                             f"first ones: {rep.escapes[:12]}")
    kurz = rep.qual.removeprefix("proofbundle.")
    neu = {f"{s} {e}" for s, e in rep.sibling} - _SIBLING_BRANCH.get(kurz, set())
    assert not neu, f"{rep.qual}: a class escape in a sibling-branch file that is not pinned: {sorted(neu)}"
    gesehen = {f"{s} {e}" for s, e in rep.gaps}
    neu = gesehen - _WRONG_TYPE_GAPS.get(kurz, set())
    assert not neu, (f"{rep.qual}: a raw raise outside the class that is not pinned: {sorted(neu)} "
                     "(a typed refusal is the fix; a pin is the last resort)")
    voll = all(must_return and exc is None for must_return, exc in rep.baseline)
    if voll:
        weg = {g for g in _WRONG_TYPE_GAPS.get(kurz, set())
               if g.split(":")[0] not in _SIBLING_BRANCH_FILES} - gesehen
        assert not weg, f"{rep.qual}: a pinned gap is gone; take it off the list: {sorted(weg)}"


@pytest.mark.parametrize("qual", _SEEDED)
def test_a_planted_value_leaves_the_function_typed(qual, _quiet_world):
    rep = _sweep(qual, _quiet_world)
    # A BARE INSTALL DEGRADES TO A CLEAN SKIP (N18, tests/test_bare_install_degrades_to_clean_skips.py).
    # A seed whose own call stops at an absent optional dependency never reaches the function's code,
    # so its planted calls measure the import, not the function: without `rfc3161-client`,
    # `create_rfc3161_anchor` answered every plant with ModuleNotFoundError, and without a keccak backend
    # `eip191_recover_address` with `_NoSigLib`, and both cases failed (a lens on e5b39b81, M5). Any seed
    # counts, not only one recorded as returning: the seed of `create_rfc3161_anchor` was recorded
    # refusing (no network), and it stops at the import before it gets there. Where the dependency is
    # present the seed's call gets past the import, and nothing is skipped.
    fehlt = [exc for _must_return, exc in rep.baseline if _absent_dependency(exc)]
    if fehlt:
        pytest.skip(f"{qual}: not measured here, an optional dependency is absent "
                    f"({type(fehlt[0]).__name__}: {_message(fehlt[0])!s:.160})")
    _assert_clean(rep)


def test_every_family_member_is_seeded():
    """The forcing function: every family member with a parameter has a seed or a named reason, and no
    seed or reason names a function that is not in the family."""
    mit_parametern = {q for q, fn in _FAMILY.items() if _takes_something(fn)}
    gedeckt = set(_RECORDED) | set(_HAND_SEEDS) | set(_NOT_SEEDED)
    assert sorted(mit_parametern - gedeckt) == [], "a public function without a seed or a reason"
    fort = {q for q in gedeckt - set(_FAMILY) if q.rsplit(".", 1)[0] not in _UNIMPORTABLE}
    assert sorted(fort) == [], "a seed or a reason for a function that is gone"
    assert not (set(_HAND_SEEDS) & set(_RECORDED)), "a function seeded twice"
    assert all(reason for reason in _NOT_SEEDED.values())


def test_the_family_is_derived_and_holds_every_surface_the_lens_named():
    """A derived family can shrink silently (a renamed module, an import that fails); the surfaces of
    the lens on d6d89763 must be in it, seeded, and the family must stay the size it was measured at."""
    assert len(_FAMILY) >= 300, len(_FAMILY)
    for qual in ("proofbundle.policy.evaluate_policy", "proofbundle.policy.evaluate_decision_policy",
                 "proofbundle.policy.lint_policy", "proofbundle.policy.explain_policy",
                 "proofbundle.relation.evaluate_relations_policy",
                 "proofbundle.agent_review.validate_statement_shape",
                 "proofbundle.agent_review.render_disclosure_line",
                 "proofbundle.agent_review.render_disclosure_block",
                 "proofbundle.trust_pack.verify_trust_pack",
                 "proofbundle.public_transparency.evaluate_public_transparency",
                 "proofbundle.sdjwt_vc.validate_vc_policy",
                 "proofbundle._statement_payload.load_statement_strict",
                 "proofbundle.dsse.sign_envelope", "proofbundle.verifier_block.build_verifier_block"):
        assert qual in _SEEDED, qual


def _raw_render(wert, quote=True, **_k):
    return repr(wert) if quote else str(wert)


def test_the_sweep_catches_a_planted_raw_renderer(monkeypatch, _quiet_world):
    """Plant and catch: with the bounded renderer of `policy` swapped for the raw one it replaced, the
    sweep of `evaluate_policy` reports class escapes. A sweep that stayed green here would be blind."""
    from proofbundle import policy
    monkeypatch.setattr(policy, "render_safe", _raw_render)
    rep = _sweep("proofbundle.policy.evaluate_policy", _quiet_world)
    assert rep.escapes, "a raw renderer went unseen"
    with pytest.raises(AssertionError):
        _assert_clean(rep)


def test_the_sweep_catches_a_planted_raw_serializer(monkeypatch, _quiet_world):
    """Plant and catch for the serializer half: `json.dumps` of an AGT receipt payload without the
    mapping to AGTReceiptError is reported."""
    from proofbundle.adapters import agt_receipt
    monkeypatch.setattr(agt_receipt, "_sortkeys_json",
                        lambda daten, was: json.dumps(daten, sort_keys=True).encode())
    rep = _sweep("proofbundle.adapters.agt_receipt.payload_hash", _quiet_world)
    assert any(e[1] in ("TypeError", "ValueError", "RecursionError") for e in rep.escapes), rep.escapes


def test_a_blind_sweep_is_not_a_pass(_quiet_world):
    """With nothing to plant the sweep makes no call, and that is a failure, not a green case."""
    rep = _sweep("proofbundle.policy.evaluate_policy", _quiet_world, values={}, keys={})
    assert rep.calls == 0
    with pytest.raises(AssertionError, match="nothing was measured"):
        _assert_clean(rep)


def test_the_planted_values_do_what_they_stand_for():
    """Each planted value breaks the naive rendering it stands for, so a green sweep means the code
    rendered it bounded, not that the value was harmless."""
    for label in ("10**5000", "-10**5000", "a tuple holding 10**5000"):
        with pytest.raises(ValueError, match="integer string conversion"):
            f"{_VALUES[label]()}"
    assert None not in _REFUSED_AT.values(), (
        f"no depth up to {_DEPTH_CAP} makes repr and json.dumps raise RecursionError here: {_REFUSED_AT}")
    assert _DEPTH_FLOOR <= _DEPTH < _DEPTH_CAP, (_DEPTH, _REFUSED_AT)
    tief = _VALUES[f"a list {_DEPTH} deep"]()
    assert tief is not _VALUES[f"a list {_DEPTH} deep"](), "every plant gets a list of its own"
    for render in (repr, json.dumps):
        with pytest.raises(RecursionError):
            render(tief)
    ebene, n = tief, 0
    while ebene:
        ebene, n = ebene[0], n + 1
    assert n == _DEPTH, (n, _DEPTH)
    _KETTE[_KETTE_GEPRUEFT // 2].append(0)       # a call that changes the shared chain ...
    assert _kette_intakt() is False
    assert _VALUES[f"a list {_DEPTH} deep"]()[0] is _KETTE[0] and _kette_intakt()   # ... gets it rebuilt
    for label in ("a set", "bytes"):
        with pytest.raises(TypeError, match="not JSON serializable"):
            json.dumps(_VALUES[label]())
    with pytest.raises(_Rendered):
        f"{_Hostile()!r}"
