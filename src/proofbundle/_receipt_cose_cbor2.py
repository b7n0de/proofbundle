"""cbor2, the second reader of ``receipt_cose`` (EXPERIMENTAL, the ``[scitt]`` extra).

``receipt_cose`` judges every statement with a reader of its own, which keeps the kind of each data item and refuses
what is not in the core deterministic encoding. cbor2 judges no statement. It does two things, and both stand here so
that ``receipt_cose`` imports no CBOR library (``tests/test_strict_decoding_guard.py``):

* it is the module's requirement: without cbor2, or with a cbor2 that cannot refuse duplicate keys and indefinite
  lengths, ``check_statement`` returns ``no_lib`` and ``receipt_to_statement`` writes nothing;
* it reads back, as a second and foreign decoder in its strict mode, the bytes the forward direction has just written,
  before they are returned.

Under a tag cbor2 6 returns an array as a tuple and a map as a frozendict, where cbor2 5 returned a list and a dict.
Nothing here tests for either form: the read-back compares by equality, which holds for both.
"""
from __future__ import annotations

from typing import Any, Optional

__all__ = ["Missing", "strict_cbor2", "read_back_problem"]


class Missing(Exception):
    """cbor2 is not installed, or it lacks the strict options the read-back needs."""


def strict_cbor2() -> Any:
    """The cbor2 module, after a probe that it refuses duplicate keys and indefinite lengths; raises ``Missing``."""
    try:
        import cbor2  # noqa: PLC0415 - the [scitt] extra
    except ImportError:
        raise Missing("the [scitt] extra (cbor2) is not installed") from None
    try:
        cbor2.loads(b"\xa0", allow_duplicate_keys=False, allow_indefinite=False)
    except TypeError:
        raise Missing("this cbor2 cannot refuse duplicate keys and indefinite lengths; the [scitt] "
                      "extra pins the version the reader was measured with") from None
    return cbor2


def read_back_problem(data: bytes, protected_raw: bytes, protected: dict, tag: int) -> Optional[str]:
    """None when cbor2, in its strict mode, reads DATA as tag TAG whose first element is PROTECTED_RAW, and
    PROTECTED_RAW as PROTECTED; else why not. Raises ``Missing`` without the extra."""
    cbor2 = strict_cbor2()
    try:
        foreign = cbor2.loads(data, allow_duplicate_keys=False, allow_indefinite=False)
    except Exception as exc:  # noqa: BLE001 - any refusal of the decoder is a refusal to write
        return f"cbor2 does not read the written statement ({type(exc).__name__})"
    if not (isinstance(foreign, cbor2.CBORTag) and foreign.tag == tag and foreign.value[0] == protected_raw):
        return "the statement did not read back as written with cbor2"
    try:
        header = cbor2.loads(protected_raw, allow_duplicate_keys=False, allow_indefinite=False)
    except Exception as exc:  # noqa: BLE001 - any refusal of the decoder is a refusal to write
        return f"cbor2 does not read the written statement ({type(exc).__name__})"
    if header != protected:
        return "the statement did not read back as written with cbor2"
    return None
