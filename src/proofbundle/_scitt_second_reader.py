"""The second reader of the ``scitt-ccf/v1`` profile: cbor2 reads bytes the strict pre-scan already accepted.

WHY A MODULE OF ITS OWN (owner answer B on card OA-c2b4d6d3e3, after the pattern of owner answer A on card
OA-f89b8d803d). The strict decoding rule of this repository (``tests/test_strict_decoding_guard.py``) allows a lax
decode site on a verify path only under a named reason. ``scitt_ccf`` decides with ``_cbor_prescan.scan``, which
refuses duplicate keys, bytes after the item, heads that are not in their shortest form, indefinite lengths and every
tag its policy does not allow; cbor2 then reads the same bytes and must read the same values (ADR 0009, Decision 13).
cbor2 decides nothing alone: a refusal of cbor2 or a value it reads otherwise is a refusal. The library is
referenced here and nowhere else in the reader, so the guard counts exactly these references, and every container
check here holds under cbor2 5 and cbor2 6, which returns a tuple and a frozendict under a tag.

The values of the pre-scan are ``list`` and ``dict`` by construction and its ``Tag`` is a frozen dataclass, so a check
that also names ``tuple`` or ``Mapping`` reads them as before.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ._cbor_prescan import Tag
from .errors import UnsupportedError


class ScittUnavailable(UnsupportedError):
    """The ``[scitt]`` extra is not installed, or its cbor2 lacks an option the profile needs."""

    status = "no_lib"


def library():
    """cbor2 with the strict options the profile needs, or ``ScittUnavailable``."""
    try:
        import cbor2  # noqa: PLC0415 - optional extra
    except ImportError as exc:
        raise ScittUnavailable("scitt-ccf needs the [scitt] extra: pip install 'proofbundle[scitt]'") from exc
    try:
        cbor2.loads(b"\xa0", allow_duplicate_keys=False, allow_indefinite=False)
    except TypeError as exc:
        raise ScittUnavailable("the installed cbor2 cannot reject duplicate keys and indefinite "
                               "lengths; the [scitt] extra pins the measured version") from exc
    return cbor2


def same(ours: Any, theirs: Any, tag_type: Any) -> bool:
    """Do the pre-scan and cbor2 read the same value? Container types differ by cbor2 version (list or tuple, dict
    or frozendict), so the comparison is by content, never by type name. ``tag_type`` is cbor2's ``CBORTag``."""
    if isinstance(ours, bool) or ours is None:
        return theirs is ours
    if isinstance(ours, int):
        return isinstance(theirs, int) and not isinstance(theirs, bool) and theirs == ours
    if isinstance(ours, (bytes, str)):
        return type(theirs) is type(ours) and theirs == ours
    if isinstance(ours, (list, tuple)):
        return (isinstance(theirs, (list, tuple)) and len(theirs) == len(ours)
                and all(same(a, b, tag_type) for a, b in zip(ours, theirs)))
    if isinstance(ours, (dict, Mapping)):
        try:
            keys = list(theirs.keys())
        except AttributeError:
            return False
        if len(keys) != len(ours) or any(k not in ours for k in keys if isinstance(k, (int, str))):
            return False
        return all(isinstance(k, (int, str)) and not isinstance(k, bool) and same(ours[k], theirs[k], tag_type)
                   for k in keys)
    if isinstance(ours, Tag):
        if ours.number == 1:
            # cbor2 turns tag 1 into a datetime (measured, 5.9.0 and 6.1.4); that is the one mapped position
            import datetime  # noqa: PLC0415
            if isinstance(ours.value, bool) or not isinstance(ours.value, int):
                return False
            return (isinstance(theirs, datetime.datetime) and theirs.tzinfo is not None
                    and theirs == datetime.datetime.fromtimestamp(ours.value, datetime.timezone.utc))
        return isinstance(theirs, tag_type) and theirs.tag == ours.number and same(ours.value, theirs.value, tag_type)
    return False


def disagreement(data: bytes, value: Any, *, max_depth: int) -> str | None:
    """None when cbor2 reads ``data`` as the pre-scan's ``value``, else why not. Raises ``ScittUnavailable``."""
    cbor2 = library()
    try:
        theirs = cbor2.loads(bytes(data), allow_duplicate_keys=False, allow_indefinite=False, max_depth=max_depth)
    except Exception as exc:  # noqa: BLE001 - any cbor2 refusal of bytes the pre-scan accepted is a disagreement
        return f"cbor2 refused what the pre-scan accepted: {type(exc).__name__}"
    if not same(value, theirs, cbor2.CBORTag):
        return "the pre-scan and cbor2 read different values"
    return None
