"""Canonical Statement primitive — the one home for the universal content root (ADR 0002).

The *content root* of an in-toto Statement is ``SHA-256`` over the RFC-8785 (JCS) canonical bytes of the
**full** Statement (``_type``, ``subject``, ``predicateType``, ``predicate`` — never a predicate-only or
field-subset canonicalization) taken BEFORE signing. The signature bytes are NEVER part of the preimage, so
the root survives counter-signing, key rotation and multi-signature envelopes (proofbundle#7 consensus,
2026-07-10). ``contentRootAlg`` for this definition is ``jcs-sha256-v1`` (see ``CONTENT_ROOT_ALG``).

Two-part rule (ADR 0002):

* a PRODUCER emits its Statement canonically (``canonicalize_statement``) and signs exactly those bytes;
* a VERIFIER hashes the EXACT transmitted payload bytes and NEVER re-canonicalizes — a payload that deviates
  from its own canonical form is a fail-closed error the caller must reject.

``statement_content_root`` serves both sides from one definition: given a JSON object it canonicalizes then
hashes (producer); given raw ``bytes`` it hashes exactly those bytes (verifier). Both yield the SAME 32-byte
root when the producer emitted canonically — which is the whole point of a content root: a verifier that
passes the exact signed payload bytes reproduces the producer's root without trusting a re-serialization.

The RFC-8785 canonicalizer ships in the ``[eval]`` extra (``rfc8785``); it is imported LAZILY so the base
install and the plain no-anchor verify path stay dependency-free. A missing extra is a clear fail-closed
``CanonicalizerUnavailable``, never a raw ``ImportError``.

This module is intentionally tiny and dependency-light: it is the shared primitive that the decision-receipt
predicate (``decision.py``) and, across the 2.1.0 migration (ADR 0002), the eval-result / svr in-toto export
paths converge on. Providing it here does NOT change any released wire format — the migration of the released
``intoto`` export paths off ``json.dumps(sort_keys=True)`` is a separate T3 / SemVer owner-gated step.
"""
from __future__ import annotations

import gc
import hashlib
from datetime import datetime, timezone
from collections import OrderedDict
from collections.abc import Mapping
from typing import Any, Callable, Union

from ._membership import require_switch
from .errors import ProofBundleError

__all__ = ["CONTENT_ROOT_ALG", "STATEMENT_REQUIRED_KEYS", "CanonicalizerUnavailable",
           "canonicalize_statement", "statement_content_root"]

# The declared content-root algorithm this primitive computes (ADR 0002): SHA-256 over the RFC-8785 (JCS)
# canonical Statement bytes. A future algorithm MUST register its own distinct id — a verifier MUST NOT
# silently default a missing/unknown value, which is exactly where an algorithm-confusion attack would hide.
CONTENT_ROOT_ALG = "jcs-sha256-v1"

# The four keys of a full in-toto Statement v1. Passing a bare `predicate` where a full Statement is
# required would drop `subject` + `predicateType` and reopen the §2.1 context-confusion attack at the
# primitive level (ADR 0002 §2, full-Statement scope) — the opt-in `require_statement_shape` guard below
# fails closed on that. NOT enforced by default: some callers legitimately canonicalize a bare predicate
# for a subject-commitment digest (e.g. decision.build_decision_statement), which is a different operation.
STATEMENT_REQUIRED_KEYS = ("_type", "subject", "predicateType", "predicate")


class CanonicalizerUnavailable(ProofBundleError):
    """The RFC 8785 (JCS) canonicalizer extra is not installed, so a content root cannot be computed.

    Fail-closed: install ``proofbundle[eval]``. Callers that want a predicate-specific message (e.g.
    ``decision.py``'s ``DecisionReceiptError``) catch this and re-raise."""


def _require_statement_shape(obj: Any) -> None:
    """Fail closed unless ``obj`` is a full in-toto Statement OBJECT (the four ``STATEMENT_REQUIRED_KEYS``).

    Guards the §2.1 bug class at the primitive level: handing a bare ``predicate`` to a routine that expects
    a full Statement silently narrows the content-root scope (``subject`` + ``predicateType`` dropped). This
    is opt-in (``require_statement_shape=True``) precisely because a bare-predicate canonicalization is a
    legitimate, distinct operation elsewhere; enabling it by default would break those callers.

    The guard reads what the object stores and runs no code of the caller, like the budget and the
    copy after it (round 8): the object's own type decides, and the stored keys are compared by their
    characters, the keys the copy writes. Measured at 93b3c6f5 and on main 1e95b197, when the guard
    asked the object: a dict subclass whose `__contains__` always answered True passed it holding
    only a `predicate`, and a bare predicate was canonicalized. At c8205c18 it asked
    `isinstance(obj, Mapping)`, which reads `__class__`, and `dict.__contains__`, whose lookup compares
    a stored `str` subclass key through that key's own `__eq__`. A `Mapping` that is not a dict is
    refused here now; the budget refused it one step later before."""
    typ = type(obj)
    if not issubclass(typ, dict):
        raise ProofBundleError(
            "require_statement_shape: a full in-toto Statement (JSON object) is required, got "
            f"{_type_name(typ)}")
    vorhanden = {str.__str__(k) for k in list(dict.__iter__(obj)) if issubclass(type(k), str)}
    missing = [k for k in STATEMENT_REQUIRED_KEYS if k not in vorhanden]
    if missing:
        raise ProofBundleError(
            f"require_statement_shape: object is missing in-toto Statement key(s) {missing} — this looks "
            "like a bare predicate, not a full Statement (subject + predicateType would be dropped; "
            "ADR 0002 §2 full-Statement scope)")


def _plain_for_jcs(value: Any, key_error: Callable[[str], BaseException], wurzel: str = "") -> Any:
    """A copy of ``value`` that holds only plain JSON types: every string and key a plain ``str``.

    THE CLASS: a canonical serializer that reads a value through a method the caller's object can
    override. rfc8785 sorts object keys by ``key.encode("utf-16be")``, and a ``str`` subclass can
    override ``encode``. Measured at 6893586f with such a key in a claim's ``provenance``: an
    ``encode`` that raised LookupError or returned an int escaped ``emit_eval_receipt``, the eight
    producers and ``svr_properties`` as a raw exception, and one that returned other bytes for one
    key made the emitter sign a payload whose keys were not in canonical order. The same key in the
    ``harness`` argument of the two in-toto exporters did the same through
    ``canonicalize_statement``.

    Every other reader on the way reads the characters: the claim rule's regular expressions, the
    JSON encoders and the verify path's parser. ``str.__str__`` returns those characters as a plain
    ``str``, so the serializer reads what they read. That is why the copy is the fix and a wider
    ``except`` around the serializer is not: an except would turn the override into a refusal, and
    it would also swallow a real defect of the serializer.

    Containers are read once, by their STORED contents: through the base type's own methods
    (``dict.items``, ``list.__iter__``, ``tuple.__iter__``), never through a method a subclass can
    override (``items``, ``keys``, ``values``, ``__iter__``, ``__getitem__``). The two serializers
    do not share one reading of a subclass (measured on Python 3.10.12: ``json.dumps`` reads a dict
    subclass through ``items()``, ``rfc8785.dumps`` through ``dict()``, which calls ``keys()`` and
    ``__getitem__`` once ``__iter__`` is overridden, and both read a list subclass through
    ``__iter__``), so the copy reads the one thing no subclass can redirect, and both serializers
    then read the copy. Measured by lens run 5 at 5a21b199, where the copy read ``dict(value)``: a
    ``status`` holding a dict subclass whose ``__iter__`` is overridden and whose ``__getitem__``
    raises KeyError escaped ``issue_sd_jwt`` as a raw KeyError; c3ca546b signed its stored contents,
    and so does the copy now.

    THE COPY RUNS NO CODE OF THE CALLER (round 8, lens run 6 at c8205c18). Every value is read by
    its own type, ``type(value)``, which no object can redirect, and that type is asked with
    ``issubclass`` against one base type at a time. For a base type whose metaclass is ``type``
    itself, ``issubclass`` walks the type's MRO tuple by identity and calls no hook of the caller's
    metaclass (measured on Python 3.10.12 with a metaclass that defines ``__subclasscheck__``,
    ``__eq__`` and ``__name__``: none ran; ``str in type.__mro__`` would have run the metaclass's
    ``__eq__``). Containers are read with the base type's methods, and a ``str`` becomes the plain
    text it holds (``str.__str__``), so a ``str`` subclass is written as what it stores. ``bool``,
    None and an exact ``int`` or ``float`` are kept as they are. A SUBCLASS OF ``int`` OR ``float``
    IS REFUSED, with the reason `_plain_value.plain_json` gives: plain_json is the one copy rule of
    the 6.2.0 chain (PR 293, owner decision OA-c7d6ff7121), and this copy refuses every type it
    refuses. Rounds 8 to 12 read such a number as the value it stores (``int.__index__``,
    ``float.__float__``); that reading ran no code of the caller either, but it accepted a value the
    one rule refuses. EVERY OTHER TYPE IS REFUSED with ``key_error``: a set, a frozenset, bytes, a
    Decimal, an object whose ``__class__`` claims a JSON type, and a type whose metaclass hides its
    base from its MRO. Nothing is passed through to the serializer to judge. The refusal names the type
    through `_type_name`, which never raises (round 9): at ee489403 it raised a raw TypeError for a
    type whose metaclass hides ``type`` from its own MRO and for a type whose ``__name__`` is a
    ``str`` subclass that hides ``str``, so that refusal was a raw exception, at the emitter and
    through the structural budget at ``verify_intoto_dsse``, where c8205c18 gave EvalClaimError and
    ok=False. At 493c2f86 this paragraph did not hold for the keys of an OrderedDict, whose own
    order is read by hashing them (lens run 8, see the next paragraph); it holds since round 10.

    A dict is copied in its own order: an ``OrderedDict`` (and a subclass of it) in the order
    ``collections.OrderedDict``'s own ``__iter__`` gives, every other dict in its storage order
    (round 9). ``dict.items`` reads an OrderedDict's storage order, which ``move_to_end`` does not
    change, and at ee489403 the copy wrote that order: ``issue_sd_jwt`` signed an opening
    ``['identifier', 'salt_hex']`` for an OrderedDict whose own order is the reverse, and
    ``to_test_result_statement`` built another ``subject`` digest. The serializers that sort keys
    are unaffected; ``list()``, ``dict()`` of pairs and ``json.dumps`` without sorting read the
    order. That ``__iter__`` is C code of the standard library, but it hashes every key of the
    OrderedDict's own list to find its node. So an OrderedDict is read in its own order only when
    every key it stores is of type ``str`` itself and its list can hold nothing else; any other
    OrderedDict is refused, one with a ``str`` subclass key included (round 10, see
    `_in_eigener_reihenfolge`). A plain dict with ``str`` subclass keys is copied as before:
    ``dict.items`` hashes nothing. At 493c2f86 an OrderedDict key was refused only when its type's
    class dicts held a ``__hash__`` under a key of type ``str``, and a ``__hash__`` bound under a
    key that merely compares equal to that name ran inside the copy (lens run 8).

    What that closed, measured at c8205c18. The copy asked ``isinstance`` about every value that is
    not a JSON type, and ``isinstance`` reads ``__class__``, so the caller's ``__class__`` property
    ran inside the copy: an empty frozenset subclass that named its own type there and ``list``
    afterwards passed the copy unchanged, and rfc8785 then read it through its own ``__iter__``
    (``canonicalize_statement`` wrote 1035 bytes for 500 nested lists, and raised a raw
    RecursionError for 3000; at 93b3c6f5 and on main it was a BundleFormatError); a ``__class__``
    that raised RecursionError was reported as "nests too deep"; a ``__class__`` read inside the
    copy deepened a sibling that was not yet copied, so the written bytes exceeded the budget the
    statement had been checked against. An ``int`` or ``float`` subclass passed unchanged, and
    rfc8785 wrote it through its own ``__int__`` or ``__float__`` (an int holding 5 whose
    ``__int__`` returns -1 was written as -1) or raised what they raised; it is refused now (see
    above). A type whose metaclass
    returns ``[cls, object]`` from ``mro()`` is no dict to ``issubclass`` while ``json.dumps``, which
    tests the type's C flags, writes it as one through its own ``items()``: a ``status`` holding
    such a dict with the stored item {"a": 1} was signed as {"fremd": 99}. Such a type cannot be read
    as json reads it without calling that ``items()`` (``dict.items`` refuses it, because the base
    method's own type check walks the same MRO), so it is refused, not mirrored.

    A container that contains itself, or a value nested deeper than the interpreter recurses, raises
    ``key_error`` too, never a RecursionError. Measured at 5a21b199: a circular ``status`` raised
    RecursionError, where c3ca546b gave json's ``ValueError: Circular reference detected``.

    A key that is not a string raises ``key_error``, the refusal rfc8785 gives such a key; it gave
    it only when the key had no ``encode`` method, and raised a raw TypeError when it had one. Two
    keys whose characters are equal raise ``key_error`` too, because JSON has one key for both.

    ``key_error`` is called with the message and its result is raised, so it may be an exception
    class or a function that builds one with the caller's prefix. A refusal names where the value
    sits (``provenance.k``, ``ci95[0]``), starting at ``wurzel`` when the caller names the argument.
    """
    try:
        return _plain_value(value, set())
    except _Abweisung as abweisung:
        ort = wurzel + "".join(reversed(abweisung.pfad))
        if ort.startswith("."):
            ort = ort[1:]
        raise key_error(f"{ort}: {abweisung.grund}" if ort else abweisung.grund) from None
    except RecursionError as exc:
        # Only this copy's own recursion can raise it here: `_plain_value` calls `type`, `id`,
        # `issubclass`, the base types' own methods and `gc.get_referents` on the caller's objects,
        # and none of them runs code of the caller.
        # tests/test_every_producer_of_an_eval_claim_holds_the_one_rule.py plants recording
        # `__class__`, `__iter__`, `__len__`, `__index__` and the like, and a metaclass, and asserts
        # that not one of them is called.
        text = "the value nests too deep to serialize"
        raise key_error(f"{wurzel}: {text}" if wurzel else text) from exc


#: The getter behind ``type.__name__``, taken from ``type`` itself.
_TYPNAME = type.__dict__["__name__"]

#: What `_type_name` says for a type whose name cannot be read without running code of the caller.
_UNBENANNT = "<unnamed type>"


def _type_name(typ: type) -> str:
    """The name of ``typ`` for a message, read without running code of the caller. Never raises.

    ``type(x).__name__`` looks the attribute up on the type's metaclass first, and a metaclass that
    defines ``__name__`` as a property runs its own code there (measured on Python 3.10.12). The
    getter of ``type`` itself returns the name the type holds. A name that is a ``str`` subclass is
    read as its characters (``str.__str__``).

    TWO NAMES CANNOT BE READ THAT WAY, and each is ``<unnamed type>`` (round 9, lens run 7 at
    ee489403, where each raised a raw TypeError out of the refusal it was meant to explain): a type
    whose metaclass leaves ``type`` out of its MRO (the getter refuses it, because its own type check
    walks that MRO), and a name that is a ``str`` subclass whose metaclass leaves ``str`` out of its
    MRO (``str.__str__`` refuses it the same way). Both checks are ``issubclass`` against a base
    whose metaclass is ``type``, an identity walk of the MRO that calls no hook, so the answer
    agrees with the check the getter and ``str.__str__`` make.

    A type that carries the name of a built-in type and is not that type is named as such: a NumPy
    boolean's name is ``bool``, and a refusal read "a value of type bool is not a JSON value"."""
    if not issubclass(type(typ), type):
        return _UNBENANNT
    name = _TYPNAME.__get__(typ)
    if type(name) is not str:
        if not issubclass(type(name), str):
            return _UNBENANNT
        name = str.__str__(name)
    eingebaut = _EINGEBAUT.get(name)
    if eingebaut is not None and eingebaut is not typ:
        return f"{name} (not the built-in {name})"
    return name


#: The built-in types by name, for `_type_name`.
_EINGEBAUT = {t.__name__: t for t in (bool, int, float, str, list, tuple, dict, bytes, bytearray,
                                      set, frozenset, type(None), object)}


def _zeichen_von(wert: Any) -> Any:
    """The characters of a ``str`` as a plain ``str``, or None for a value that is no ``str``.

    For a caller's string that a check compares (round 10): the type is the object's own, asked
    with ``issubclass`` against ``str`` (an identity walk of its MRO), and a subclass is read with
    ``str.__str__``, so its ``__eq__``, ``__ne__``, ``__hash__``, ``encode`` and ``__str__`` never
    decide the comparison made with the result. No code of the caller runs. Measured at 493c2f86:
    ``evalclaim.decode_eval_claim(expected_context=...)`` returned the claim of a receipt bound to
    another context for a ``str`` subclass whose ``__ne__`` answers False, and so did an object of
    another type whose ``__ne__`` answers False."""
    typ = type(wert)
    if typ is str:
        return wert
    if issubclass(typ, str):
        return str.__str__(wert)
    return None


def _bytes_von(wert: Any) -> Any:
    """The bytes a ``bytes`` or ``bytearray`` holds, as plain ``bytes``, or None for any other value.

    The sibling of `_zeichen_von` for byte strings (round 12). The type is the object's own, asked
    with ``issubclass``, and the stored bytes are read through the base type's own slice, which
    copies what the object stores. ``bytes(x)`` calls a subclass's ``__bytes__``, ``b"\\x00" + x``
    calls its ``__radd__``, ``len(x)`` its ``__len__`` and a buffer read its ``__buffer__`` (3.12+),
    so none of them decides what a signature check, a hash or a comparison reads. No code of the
    caller runs."""
    typ = type(wert)
    if typ is bytes:
        return wert
    if issubclass(typ, bytes):
        return bytes.__getitem__(wert, slice(None))
    if issubclass(typ, bytearray):
        return bytes(bytearray.__getitem__(wert, slice(None)))
    return None


def _puffer_von(wert: Any) -> Any:
    """`_bytes_von`, and for a ``memoryview`` the bytes it views; None for any other value.

    For the surfaces that took any bytes-like value before round 12 because they read it through
    ``b"\\x00" + x`` or ``==`` (the Merkle leaf and node hashes, the DSSE body, the emitted payload,
    an anchor's expected root, a relying party's expected receiver key, a witness quorum's log key
    material). A plain copy must not narrow what they accept, so a ``memoryview`` stays a legitimate
    input there. ``memoryview`` cannot be subclassed, and its bytes are read by ``bytes.__add__``
    from the buffer it already holds, the operation those surfaces ran, so no code of the caller
    runs. A view that cannot be read so (released, or not contiguous: the concatenation raised
    TypeError for one) is None, refused like any other value. Surfaces that refused a ``memoryview``
    before keep `_bytes_von`."""
    roh = _bytes_von(wert)
    if roh is None and type(wert) is memoryview:
        try:
            roh = b"" + wert
        except (BufferError, TypeError, ValueError):
            return None
    return roh


#: The exact built-in scalar types (round 12): a value of one of them runs only the interpreter's own
#: comparison, so a check may compare it as it did. Any other type (a subclass, or an object whose
#: ``__class__`` claims one of them) is read by the helpers above or refused; ``isinstance`` would
#: read its ``__class__`` and accept a claim, so the guards after a copy ask ``type()``.
_EINGEBAUTE_SKALARE = (type(None), bool, int, float, str, bytes)


def _ganzzahl_von(wert: Any) -> Any:
    """``wert`` if it is an exact ``int``, or None for a bool, a subclass of ``int`` or any other value:
    the answer of `_plain_value.plain_int`, the one rule for a number (PR 293).

    For a caller's integer that a check compares or computes with (round 12). An ``int`` subclass
    answers comparisons and arithmetic through its own methods, and Python asks a subclass's
    reflected method first (``5 == x`` calls ``x.__eq__``). Round 12 read its stored value with
    ``int.__index__``; the one rule refuses it instead, so every caller treats it as it treats a
    value that is no integer. A bool is None here because every caller refuses it as a count, a
    size or an index."""
    return wert if type(wert) is int else None


def _zahl_von(wert: Any) -> Any:
    """``wert`` if it is an exact ``int``, ``float`` or ``bool``, or None for any other value, a
    subclass of ``int`` or ``float`` included (the one rule for a number, PR 293; round 12 read a
    subclass's stored value). A bool is kept as it is: it cannot be subclassed, so none of its
    methods is the caller's."""
    typ = type(wert)
    return wert if typ is int or typ is float or typ is bool else None


#: What `_feld_von` answers for a field the dict does not store.
_FEHLT = object()


def _feld_von(wert: Any, name: str, fehlt: Any = None) -> Any:
    """The value a dict STORES under the key whose characters are ``name`` (round 12), or ``fehlt``.

    ``dict.get(d, name)`` is not enough: when a stored key is a ``str`` subclass, the dict's own lookup
    compares it with ``name`` through that key's own ``__eq__`` (measured on Python 3.10.12 with a
    recording subclass). So the stored pairs are read through ``dict.items``, which hashes and compares
    nothing, and each key is compared by its characters. Two keys with the same characters are one
    JSON key; the copy refuses such a dict, and this read answers ``fehlt`` for it, so a surface that
    reads one field treats the field as absent rather than choosing one of two. A value that is no
    dict answers ``fehlt`` too."""
    if not issubclass(type(wert), dict):
        return fehlt
    gefunden = [v for k, v in list(dict.items(wert)) if _zeichen_von(k) == name]
    return gefunden[0] if len(gefunden) == 1 else fehlt


def _pruefkopie(wert: Any) -> Any:
    """For a validator (round 12): a caller's value as the plain copy of what it stores, so the
    judgment reads what the object holds and runs none of its methods. A dict or list is copied, a
    ``str`` subclass becomes the plain text it holds, a subclass of ``int`` or ``float`` is refused
    (the one copy rule, see `_plain_for_jcs`), and a tuple stays a tuple of plain values, so a validator that refused a tuple refuses it as before (a tuple INSIDE
    is read as the array JSON writes it, as the signer writes it). A value of any other type, and a
    container holding one, raises ValueError, which the validator returns as its finding: such a
    value is no JSON value, and an object whose ``__class__`` claims a JSON type would otherwise
    pass the validator's own ``isinstance`` and be read through its methods (`_eine_kopie`)."""
    kopie = _plain_for_jcs(wert, ValueError)
    return tuple(kopie) if issubclass(type(wert), tuple) else kopie


#: What `_zeitpunkt_von` answers for a clock that is no datetime: distinct from None, which means "no clock
#: given, take the current time".
KEIN_ZEITPUNKT = object()


def _zeitpunkt_von(wert: Any) -> Any:
    """A caller's clock read once (verify lane on pull request 312): None stays None, an aware ``datetime``
    of exactly that type becomes the plain UTC instant it names (its ``tzinfo`` is asked once, here), a naive
    one stays as it is, and anything else is ``KEIN_ZEITPUNKT``. A ``datetime`` subclass whose own reflected
    comparison answered made an expired trust pack unexpired; a comparison between plain datetimes runs no
    method of the caller."""
    if wert is None:
        return None
    if type(wert) is not datetime:
        return KEIN_ZEITPUNKT
    if wert.tzinfo is None:
        return wert
    try:
        utc = wert.astimezone(timezone.utc)
    except Exception:  # noqa: BLE001 - a tzinfo that cannot say its offset is no clock
        return KEIN_ZEITPUNKT
    return utc if type(utc) is datetime else KEIN_ZEITPUNKT


def _abbild_von(wert: Any) -> Any:
    """A mapping argument of an anchor verifier (``rp_trust``, ``frozen``) as the plain copy of what it
    stores, read once, or None when that is no JSON object (verify lane on pull request 312). A dict is
    copied by what it stores (`_plain_for_jcs`); a registered ``Mapping`` that is no dict is read through
    its own ``items()`` once, its only reading, and that is copied. A relying party's header map whose own
    ``get`` answered a header it does not store confirmed an OpenTimestamps proof."""
    if not issubclass(type(wert), dict):
        try:
            wert = dict(wert.items())
        except Exception:  # noqa: BLE001 - a mapping that cannot list its pairs is no mapping to read
            return None
    try:
        return _plain_for_jcs(wert, ValueError)
    except ValueError:
        return None


def _richtlinie_von(policy: Any) -> Any:
    """A verifier's ``policy`` argument as the plain copy of what it stores, or None when it is absent,
    no dict, or holds a value that is no JSON value (deep gate 6.2.0 at 2348f0a7, L4-620-01).

    The relations gate, the anchor obligation and the self-assertion gate of the three receipt
    verifiers read the caller's policy through its own ``get`` and ``__getitem__``, while
    `policy.evaluate_decision_policy` read the same policy by what it stores: a dict subclass whose own
    ``get`` answered the default hid a verified attached retraction and a relation-signer pin, and ok
    came out True. Every gate of a verifier now reads this one copy. The caller tells the three None
    cases apart by the argument's own type (``issubclass(type(policy), dict)``), never by ``isinstance``,
    which believes a ``__class__`` claim."""
    if policy is None or not issubclass(type(policy), dict):
        return None
    try:
        return _plain_for_jcs(policy, ValueError)
    except ValueError:
        return None


def _abschnitt_von(policy: Any, richtlinie: Any, name: str, fehlt: Any = None) -> Any:
    """One section of a verifier's ``policy``: from its plain copy (`_richtlinie_von`), or, when the policy
    as a whole holds a value that is no JSON value, the section as the dict stores it (`_feld_von`).
    ``fehlt`` is the answer for a section the policy does not hold; `_FEHLT` tells it apart from a section the
    policy holds as JSON null, which the loader refuses (the cross-check of 2026-09-29 on main 52231c95).

    The second reading is the one PR 300 relies on: a relations section that holds such a value is judged
    by the relations gate, which refuses it with its own code (``LINEAGE_REQUIREMENT_FAILED``). Without it,
    one unreadable value anywhere in the policy would hide the gate's named refusal behind a generic one
    (found by the full suite on the class fix, deep gate 6.2.0 at 2348f0a7). Neither reading runs a method
    of the caller's dict."""
    if richtlinie is not None:
        return _feld_von(richtlinie, name, fehlt)
    return _feld_von(policy, name, fehlt)


def _eine_kopie(wert: Any, fehler: Callable[[str], BaseException], was: str) -> Any:
    """For an emitter (round 12): a caller's predicate as the plain copy of what it stores, read ONCE
    before it is validated, hashed and signed, so the validator judges exactly what is signed. A
    JSON value that is no dict is copied as `_pruefkopie` copies it, for the emitter's own validator
    to refuse as it did. A value that is no JSON value, or a dict holding one, is the emitter's
    error, ``invalid <was>``: that includes an object that is no dict but claims one through
    ``__class__``, which the validator's ``isinstance`` would have accepted and read through its own
    ``get`` (measured on this tree before the change).

    THE CLASS AT THE EMITTERS. Every DSSE emitter validated the caller's dict through its own
    ``get`` and ``in`` and then signed the canonical bytes of what it stores (``canonicalize_statement``
    copies stored contents since round 8). Two readings: a dict subclass whose own ``get`` showed the
    validator a valid predicate got an invalid stored one signed."""
    kopie = _plain_for_jcs(wert, lambda text: fehler(f"invalid {was}: {text}"))
    return tuple(kopie) if issubclass(type(wert), tuple) else kopie


def _folge_von(wert: Any) -> list:
    """The items of a caller's list, tuple, set or frozenset, read once through the base type's own
    iteration (round 12), so a subclass's own ``__iter__``, ``__len__`` or ``__getitem__`` never
    decides which items a check sees. Any other iterable (a generator, a view) is read once with
    ``list()``, which is the only way to read it; a value that is not iterable raises what ``list()``
    raises, as before."""
    typ = type(wert)
    if issubclass(typ, list):
        return list(list.__iter__(wert))
    if issubclass(typ, tuple):
        return list(tuple.__iter__(wert))
    if issubclass(typ, set):
        return list(set.__iter__(wert))
    if issubclass(typ, frozenset):
        return list(frozenset.__iter__(wert))
    return list(wert)


def _flagge(wert: Any, name: str) -> bool:
    """A boolean keyword argument as the bool it is, or
    :class:`~proofbundle.errors.SwitchTypeError` (a ``ProofBundleError`` and a ``TypeError``) naming
    it and the type it got: `_membership.require_switch`, the one rule for a switch (PR 291).

    R-B4 at ``require_statement_shape`` (round 10, lens run 8 at 493c2f86, and on main): the flag
    was read by its truth, so a caller object's ``__bool__`` ran, what it raised escaped raw, and
    the string "false" switched the guard on. ``bool`` cannot be subclassed, so ``type(wert) is
    bool`` holds exactly for True and False, and nothing of the caller runs. The rule
    ``intoto._eigene_flagge`` holds for the caller-attested flags: a refusal, not a coercion. Until
    the chain carried PR 291 the refusal was this module's own ProofBundleError "must be True or
    False"."""
    require_switch(wert, name)
    return wert


class _Abweisung(Exception):
    """A refusal inside the copy. Each container on the way out adds where the value sat."""

    def __init__(self, grund: str) -> None:
        super().__init__(grund)
        self.grund = grund
        self.pfad: list = []


def _pfadteil(schluessel: str) -> str:
    """A key of the path in a message: escaped like a repr, and clipped."""
    text = repr(schluessel)[1:-1]
    return text if len(text) <= 40 else text[:37] + "..."


def _in_eigener_reihenfolge(wert: Any, paare: list) -> list:
    """The stored (key, value) pairs of the OrderedDict ``wert`` in its own order.

    ``collections.OrderedDict.__iter__``, the base method, walks the OrderedDict's own list of
    keys, which ``move_to_end`` reorders and ``dict.items`` does not see. It is C code of the
    standard library and runs no method a subclass overrides, but it hashes each key of that list
    to find its node, and a lookup compares that key with a stored key of equal hash. So before the
    list is read it is established, in two steps and without hashing, that nothing in it is an
    object whose hash or comparison is code of the caller (round 10).

    EVERY STORED KEY IS OF TYPE ``str`` ITSELF (``type(key) is str``), read from the stored pairs.
    The hash of an exact str is the interpreter's own. Any other key, a ``str`` subclass included,
    is refused with its type named. Round 9 decided instead whether a ``str`` subclass computes its
    own hash, by reading the class dicts of its MRO for an entry under a key of type ``str`` spelled
    "__hash__". CPython binds the hash slot by a dict lookup that compares keys by equality, so a
    class whose ``__hash__`` sits under a ``str`` subclass key spelled so, under a key of other
    characters whose own ``__eq__`` and ``__hash__`` claim the name, under a key that is no string,
    set with ``setattr`` over such a key, or inherited from such a base before ``str``, hashed
    through the caller's function while that reading called its hash ``str``'s own. Measured by lens
    run 8 at 493c2f86: the caller's hash ran in 28 of 28 entry and argument pairs, what it raised
    escaped raw, and ``canonicalize_statement`` returned output nested 502 deep against a budget of
    64, because the hash deepened a sibling the copy had not reached yet.

    THE LIST HOLDS NOTHING ELSE. An OrderedDict whose storage was written past its own methods
    (``dict.__delitem__``) keeps in its list a key object that the storage no longer holds, and the
    base method hashes it. Measured at 493c2f86 with every stored key an exact str: such a key's
    ``__hash__`` and ``__eq__`` ran, and a hash that raised escaped raw. The list cannot be read from
    Python without hashing, so what it can hold is bounded through the interpreter's own traversal,
    ``gc.get_referents`` (CPython's ``tp_traverse``: it names every key of the list, every stored
    value, the instance dict, the slots, and a subclass's own class, and calls no method of any of
    them; measured on Python 3.10.12, 3.11.15, 3.12.14, 3.13.15 and 3.14.7). Each object it
    names must be a ``str``, ``int``, ``float``, ``bool``, ``bytes`` or None (whose hash and
    comparison are the interpreter's own), a ``dict`` or a ``list`` (which have no hash and so
    cannot be a key), one of the stored values (as often as it is stored), or, once, the
    OrderedDict's own class when that is a subclass. Anything left over is refused, because it may
    be a key of the list. A subclass whose slot holds another object is refused by the same count;
    no reader here needs one.

    An OrderedDict whose own order names other keys than it stores (possible only by writing its
    storage past its own methods) is refused.

    Values are taken from the stored pairs, by the identity of their key, so the value copied is the
    stored one, as for every other dict."""
    for schluessel, _ in paare:
        if type(schluessel) is not str:
            raise _Abweisung(
                f"an OrderedDict key must be of type str, got {_type_name(type(schluessel))}: its own "
                "order is read by hashing its keys, and the hash of any other type can be code of the "
                "caller")
    offen: dict = {}
    for _, eintrag in paare:
        offen[id(eintrag)] = offen.get(id(eintrag), 0) + 1
    typ = type(wert)
    if typ is not OrderedDict:
        offen[id(typ)] = offen.get(id(typ), 0) + 1
    for bezug in gc.get_referents(wert):
        btyp = type(bezug)
        # By identity, one type at a time: `in` over a tuple of types would compare through the
        # metaclass of `btyp`, which can be the caller's.
        if (btyp is str or btyp is int or btyp is float or btyp is bool or btyp is bytes
                or bezug is None or btyp is dict or btyp is list):
            continue
        if offen.get(id(bezug), 0) > 0:
            offen[id(bezug)] -= 1
            continue
        raise _Abweisung(
            f"the OrderedDict holds an object of type {_type_name(btyp)} beside its stored items (in "
            "its own order or a slot), and its order cannot be read without hashing that object")
    nach_id = {id(schluessel): (schluessel, eintrag) for schluessel, eintrag in paare}
    try:
        reihe = list(OrderedDict.__iter__(wert))
    except (KeyError, RuntimeError):
        reihe = None
    if (reihe is None or len(reihe) != len(paare)
            or any(id(schluessel) not in nach_id for schluessel in reihe)):
        raise _Abweisung("the OrderedDict's own order does not name the keys it stores")
    return [nach_id[id(schluessel)] for schluessel in reihe]


def _plain_value(value: Any, offen: set) -> Any:
    """One level of `_plain_for_jcs`. `offen` holds the ids of the containers being copied above
    this one, so a container met again on its own path is a circle, and one met again beside
    itself (the same list twice in one object) is copied twice, as a serializer writes it.

    Each type is asked with its own `issubclass` call and not with a tuple of types: a tuple costs
    one more level of recursion depth per call (measured on Python 3.10.12: from the same caller, a
    copy of nested lists written with a tuple of types reached one level less), and the copy would
    then refuse a level that rfc8785 writes from the same caller. `bool` is final and None is the
    one NoneType, so both are asked by identity."""
    typ = type(value)
    if issubclass(typ, str):
        return str.__str__(value)
    if issubclass(typ, dict):
        if id(value) in offen:
            raise _Abweisung("the value contains itself (a circular reference)")
        offen.add(id(value))
        kopie: dict = {}
        paare = list(dict.items(value))
        # Its own order, not its storage order (round 9). Asked inline, so a plain dict costs no
        # frame, and the deepest dict the copy reads stays as deep as the serializer's.
        if typ is not dict and issubclass(typ, OrderedDict):
            paare = _in_eigener_reihenfolge(value, paare)
        for schluessel, eintrag in paare:
            if not issubclass(type(schluessel), str):
                raise _Abweisung("object keys must be strings")
            schluessel = str.__str__(schluessel)
            if schluessel in kopie:
                raise _Abweisung(f"object key {schluessel!r} appears twice")
            try:
                kopie[schluessel] = _plain_value(eintrag, offen)
            except _Abweisung as abweisung:
                abweisung.pfad.append("." + _pfadteil(schluessel))
                raise
        offen.discard(id(value))
        return kopie
    if issubclass(typ, list) or issubclass(typ, tuple):
        if id(value) in offen:
            raise _Abweisung("the value contains itself (a circular reference)")
        offen.add(id(value))
        # A loop, not a list comprehension: on Python 3.10 a comprehension is a function of its own and
        # cost a second frame per nesting level, so the copy refused lists nested half as deep as the
        # serializer reads (lens run 4 at c3ca546b: 497 levels here against 994 in rfc8785).
        basis = list if issubclass(typ, list) else tuple
        liste: list = []
        for eintrag in list(basis.__iter__(value)):
            try:
                liste.append(_plain_value(eintrag, offen))
            except _Abweisung as abweisung:
                abweisung.pfad.append(f"[{len(liste)}]")
                raise
        offen.discard(id(value))
        return liste
    if typ is bool or value is None or typ is int or typ is float:
        return value
    if issubclass(typ, int) or issubclass(typ, float):
        # The one copy rule (`_plain_value.plain_json`, PR 293): a subclass of int or float is
        # refused, not read, because its only reads are the caller's methods or a conversion the
        # caller controls. The reason is plain_json's.
        zahlbasis = "float" if issubclass(typ, float) else "int"
        raise _Abweisung(f"a value of type {_type_name(typ)} is a subclass of {zahlbasis}; a number must be an "
                         "exact int or float, so that no method of the caller's class decides its value")
    raise _Abweisung(f"a value of type {_type_name(typ)} is not a JSON value")


def canonicalize_statement(statement: Any, *, require_statement_shape: bool = False) -> bytes:
    """RFC-8785 (JCS) canonical bytes of a JSON in-toto Statement (or predicate) OBJECT.

    This is the producer-side canonicalization: the exact bytes to sign. It normalizes key order, number
    formatting and string escaping per RFC 8785, so two structurally-equal objects with different key
    insertion order produce byte-identical output. It does NOT hash and does NOT touch signatures.

    Uses the real ``rfc8785`` canonicalizer (the ``[eval]`` extra), lazily imported; a missing extra is a
    fail-closed ``CanonicalizerUnavailable``. Value errors from a non-JCS-able object (e.g. an unsafe float)
    propagate unchanged, exactly as calling ``rfc8785.dumps`` directly would.

    ``require_statement_shape=True`` (opt-in, default OFF) fails closed with ``ProofBundleError`` when
    ``statement`` is not a full in-toto Statement (the four ``STATEMENT_REQUIRED_KEYS``) — a guard against
    accidentally passing a bare ``predicate`` where the full-Statement scope is required (ADR 0002 §2). It is
    OFF by default because a bare-predicate canonicalization is a legitimate distinct operation (e.g. a
    subject-commitment digest); turning the check on by default would break those callers. The flag
    must be True or False; any other value is :class:`~proofbundle.errors.SwitchTypeError` before
    anything is read (round 10, `_flagge`: at 493c2f86 it was read by its truth).

    ORDER, unchanged: the shape guard, the structural budget, the one plain copy, the serializer on the
    copy. The guard and the budget read the statement before the copy, and that is safe because
    neither runs code of the caller (round 8): both read stored contents by the object's own type and
    the base types' methods, so they judge what the copy then holds. The copy runs no code of the
    caller either, so nothing the caller wrote runs between them and the serializer. That last part
    was false at 493c2f86: the copy read an OrderedDict's own order by hashing its keys, the hash of
    a ``str`` subclass key could be the caller's, and it deepened a sibling after the budget had
    judged the statement (lens run 8: output nested 502 deep against a budget of 64). Since round 10
    the copy refuses such an OrderedDict before it hashes anything (`_in_eigener_reihenfolge`). The
    budget stays before the copy because it bounds depth without recursing and gives this function's
    documented BundleFormatError for a statement nested past 64 levels, where a recursive copy would
    give its own refusal first."""
    require_statement_shape = _flagge(require_statement_shape, "require_statement_shape")
    if require_statement_shape:
        _require_statement_shape(statement)
    # adversarial re-audit round 5: bound nesting/node count BEFORE rfc8785.dumps recurses — a relying party that
    # calls this documented primitive (or statement_content_root) directly on a deeply-nested received JSON
    # object would otherwise get a raw RecursionError. The DSSE verify_* surfaces already re-parse via
    # loads_strict (json_depth-bounded) so they were safe; this closes the direct-primitive path. A legitimate
    # emit-side statement is shallow and well under the budget, so this never changes producer behaviour.
    # The budget reads a container by its stored contents, which is what `_plain_for_jcs` copies below
    # and the serializer writes. Measured at 93b3c6f5 and on main 1e95b197, when it read a dict through
    # `items()`: a dict subclass whose `items`, `values` and `keys` show nothing hid 500 nested lists
    # from the depth bound of 64 and got 1036 bytes written, and 2000 raised a raw RecursionError.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids an import cycle
    enforce_structural_budget(statement)
    try:
        import rfc8785  # noqa: PLC0415 — lazy: only the canonical/emit path pulls the JCS dependency
    except ImportError as exc:
        raise CanonicalizerUnavailable(
            "computing a Statement content root needs the RFC 8785 (JCS) canonicalizer — "
            "install proofbundle[eval]") from exc
    # A plain copy, so a key is sorted by its characters and not by its own `encode`, and a value is
    # written as what it holds (see `_plain_for_jcs`). A plain statement, which is every parsed one,
    # gives the same bytes as before.
    return rfc8785.dumps(_plain_for_jcs(statement, rfc8785.CanonicalizationError))


def statement_content_root(statement: Union[Mapping, list, bytes, bytearray], *,
                           require_statement_shape: bool = False) -> bytes:
    """The content root of a Statement: 32 raw SHA-256 bytes over its canonical Statement bytes (ADR 0002).

    Accepts either side of the two-part rule:

    * a JSON OBJECT (``Mapping`` / ``list``) — the PRODUCER path: canonicalize (RFC 8785) then SHA-256;
    * raw ``bytes`` — the VERIFIER path: SHA-256 over the EXACT payload bytes, NEVER re-canonicalized.

    Both return the SAME root when the producer emitted canonically, so a verifier that passes the exact
    signed payload bytes reproduces the producer's root without trusting a re-serialization. The preimage is
    the STATEMENT (pre-signature); signature/envelope bytes are never included, so the root is stable across
    counter-signing, key rotation and multi-signature envelopes.

    ``.hex()`` on the return value gives the 64-char hex digest used in ``evidenceRefs[].digest.sha256`` and
    a ``statement`` anchor's ``canonicalRoot``.

    ``require_statement_shape=True`` (opt-in, default OFF) guards the OBJECT (producer) path against a bare
    predicate (see ``canonicalize_statement``). It does NOT apply to the ``bytes`` (verifier) path — opaque
    transmitted bytes cannot be introspected, and their shape was fixed at produce time.

    The path is chosen by the object's own type, like the copy reads it (round 8). ``isinstance``
    reads ``__class__``, so an object whose ``__class__`` claimed ``bytes`` was hashed as whatever
    its ``__bytes__`` returned, and ``bytes()`` of a ``bytes`` subclass calls its ``__bytes__`` too.
    The stored bytes are read through the base type's own slice now. A ``Mapping`` that is not a dict
    was handed to ``canonicalize_statement``, whose budget refused it as not a JSON value; it is
    refused here now, with this function's own ProofBundleError.

    ``require_statement_shape`` must be True or False on both paths, and any other value is
    :class:`~proofbundle.errors.SwitchTypeError` before the path is chosen (round 10, `_flagge`). At 493c2f86 the object path
    read it by its truth, which ran a caller object's ``__bool__``, and the bytes path ignored it."""
    require_statement_shape = _flagge(require_statement_shape, "require_statement_shape")
    typ = type(statement)
    if issubclass(typ, bytes) or issubclass(typ, bytearray):
        # Verifier path: hash the exact transmitted payload bytes; do NOT re-canonicalize (DSSE rule). The
        # shape guard is not applicable to opaque bytes (documented) — the caller checked shape at produce.
        gespeichert: Any = statement
        roh = (bytes.__getitem__(gespeichert, slice(None)) if issubclass(typ, bytes)
               else bytes(bytearray.__getitem__(gespeichert, slice(None))))
        return hashlib.sha256(roh).digest()
    if issubclass(typ, dict) or issubclass(typ, list):
        # Producer path: canonicalize the object (optionally shape-guarded), then hash.
        return hashlib.sha256(
            canonicalize_statement(statement, require_statement_shape=require_statement_shape)).digest()
    raise ProofBundleError(
        "statement_content_root needs a JSON object (dict/list) to canonicalize or the exact payload "
        f"bytes; got {_type_name(typ)}")
