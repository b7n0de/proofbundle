"""Reader of Certisyn's sealed containment records, format ``certisyn/containment-public/v1``.

SCOPE: INTEGRITY ONLY. An accepted pair proves that the record is the record that was sealed by the holder of the
pinned key. It does not say whether the result in the record is right; FORMAT.md section 7 leaves that to a
reproducible example and to an audit. Every result this module returns carries that scope.

The specification is FORMAT.md of the pilot pack in Certisyn-Inc/certisyn-drafts pull request 12 (commit 8c01cd7a,
directory interop/containment-pilot), copied unchanged into examples/certisyn_containment_pilot/pack/. Its section 6
names seven steps, and this module runs them in that order (``STEPS``):

  1. ``parse``           the record and the seal with the package's one strict JSON reader (``loads_strict``): a member
                         name repeated after unescaping, NaN, a lone surrogate and every other non-JSON are refusals
  2. ``schema``          ``schema`` is ``certisyn/containment-public/v1``
  3. ``result_digest``   SHA-256 over the RFC 8785 form of the record without ``result_digest`` equals it
  4. ``input_digest``    only when the input file is supplied: SHA-256 over its RFC 8785 form equals ``input_digest``
  5. ``seal_domain``     the seal's ``domain`` is ``certisyn/containment-seal/v1`` and its ``algorithm`` is ``ed25519``
  6. ``signed_message``  rebuilt from the record digest, equal to the seal's, and its SHA-256 equal to
                         ``signed_message_sha256``
  7. ``signature``       Ed25519 over the UTF-8 bytes of the seal's ``signed_message``, under the pinned key

RFC 8785 is the package's canonicalizer (``canonical.canonicalize_statement``), with the structural budget the
package applies before every canonicalization. FORMAT.md section 3 names the ECMAScript form, which RFC 8785 specifies.

THE KEY. The signature is checked under the key the caller passes as ``trusted_key``, the raw 32 bytes of the relying
party's trust configuration (``load_trusted_key`` reads the pack's KEY.json form), and through
``signature.verify_ed25519_pinned``, which refuses a malformed, non-canonical or small-order key before any arithmetic.
The key and the key_id printed inside a seal are informational (FORMAT.md section 5) and are never read.

EVERY FAILED STEP IS REPORTED. A step runs when what it reads is there: an unreadable record leaves the seal's own
steps running, so a refusal names each failure it reaches, not only the first. A step that could not run is
``not_reached``. An input that was not supplied is ``not_supplied``: the record can still be accepted, and the result
says that its input_digest was not recomputed.

NEVER RAISES on what a sender controls (record, seal, input) or on an unusable trusted key: each such case is a
refusal with its reason. ``load_trusted_key`` reads the caller's own configuration and raises ``ValueError``.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any

from ._strict_json import loads_strict
from .canonical import _ein_stand, canonicalize_statement
from .signature import ed25519_trust_anchor_weakness, plain_bytes, plain_text, verify_ed25519_pinned

__all__ = ["SCHEMA", "SEAL_DOMAIN", "SEAL_ALGORITHM", "SCOPE", "SCOPE_NOTE", "STEPS", "load_trusted_key",
           "verify_containment_record"]

SCHEMA = "certisyn/containment-public/v1"
SEAL_DOMAIN = "certisyn/containment-seal/v1"
SEAL_ALGORITHM = "ed25519"

#: What an accepted pair proves, and only that.
SCOPE = "integrity"
SCOPE_NOTE = ("integrity only: an accepted pair proves that the record is the record that was sealed by the holder of "
              "the pinned key; whether the result in the record is right is a separate question")

#: The seven steps of FORMAT.md section 6, in their order.
STEPS = ("parse", "schema", "result_digest", "input_digest", "seal_domain", "signed_message", "signature")


def _text(raw: Any, what: str) -> Any:
    """The JSON text of a file as the caller passed it, read once: ``bytes`` or ``str``, anything else refused."""
    data = plain_bytes(raw)
    if data is not None:
        return data
    text = plain_text(raw)
    if text is not None:
        return text
    raise ValueError(f"the {what} must be the bytes or the text of a JSON file, not {type(raw).__name__}")


def _parse(raw: Any, what: str) -> Any:
    return loads_strict(_text(raw, what))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonicalize_statement(value)).hexdigest()


def _is_str(value: Any) -> bool:
    return type(value) is str


@_ein_stand
def load_trusted_key(raw: Any) -> bytes:
    """The raw 32-byte Ed25519 key of a trust configuration in the pack's KEY.json form.

    Read strictly. ``algorithm`` must be ``ed25519`` and ``ed25519_pub_b64`` canonical base64 of 32 bytes. Where the
    configuration also carries ``ed25519_pub_hex`` or ``pub_sha256``, each must name the same key, so that a
    configuration that disagrees with itself is refused instead of read one way. A malformed, non-canonical or
    small-order key is refused. Raises ``ValueError`` (``BundleFormatError`` and ``BudgetExceeded`` from the strict
    reader are ``ProofBundleError``, which this module raises as ``ValueError`` too)."""
    try:
        config = _parse(raw, "trust configuration")
    except ValueError:
        raise
    except Exception as exc:  # noqa: BLE001 - the strict reader's own refusals, one class for the caller
        raise ValueError(f"the trust configuration is not readable JSON ({exc})") from None
    if type(config) is not dict:
        raise ValueError("the trust configuration is not a JSON object")
    if config.get("algorithm") != SEAL_ALGORITHM:
        raise ValueError(f"the trust configuration names the algorithm {config.get('algorithm')!r}, not ed25519")
    b64 = config.get("ed25519_pub_b64")
    if not _is_str(b64):
        raise ValueError("the trust configuration carries no ed25519_pub_b64 text")
    try:
        key = base64.b64decode(b64.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError):
        raise ValueError("ed25519_pub_b64 is not base64") from None
    if base64.b64encode(key).decode("ascii") != b64:
        raise ValueError("ed25519_pub_b64 is not the canonical base64 of its bytes")
    weakness = ed25519_trust_anchor_weakness(key)
    if weakness is not None:
        raise ValueError(f"the trusted key cannot stand as an Ed25519 trust anchor ({weakness})")
    if "ed25519_pub_hex" in config and config["ed25519_pub_hex"] != key.hex():
        raise ValueError("ed25519_pub_hex names another key than ed25519_pub_b64")
    if "pub_sha256" in config and config["pub_sha256"] != hashlib.sha256(key).hexdigest():
        raise ValueError("pub_sha256 is not the SHA-256 of the key")
    return key


@_ein_stand
def verify_containment_record(record: Any, seal: Any, *, trusted_key: Any, input_series: Any = None) -> dict:
    """Run the seven steps of FORMAT.md section 6 over a record and its seal; never raises.

    ``record``, ``seal`` and ``input_series`` are the bytes or the text of the files. ``trusted_key`` is the raw 32-byte
    Ed25519 key of the caller's trust configuration (``load_trusted_key``). The result is a dict: ``format``, ``scope``
    (``integrity``), ``scope_note``, ``outcome`` (``ACCEPT`` or ``REFUSE``), ``steps`` (each of ``STEPS`` with
    ``pass``, ``fail``, ``not_reached`` or, for the input, ``not_supplied``), ``failures`` (one entry with ``step`` and
    ``reason`` per failed check) and ``trusted_key_sha256`` (the key the signature was checked under, or None when the
    trusted key is unusable)."""
    steps: dict = {name: "not_reached" for name in STEPS}
    failures: list = []

    def fail(step: str, reason: str) -> None:
        failures.append({"step": step, "reason": reason})
        steps[step] = "fail"

    def passed(step: str) -> None:
        if steps[step] != "fail":
            steps[step] = "pass"

    def guarded(step: str, check: Any) -> None:
        try:
            check()
        except Exception as exc:  # noqa: BLE001 - never-raise is the promise of this surface
            fail(step, f"could not be evaluated ({type(exc).__name__}: {exc})")

    rec: Any = None
    sl: Any = None
    key = plain_bytes(trusted_key)

    # 1. parse
    def step_parse() -> None:
        nonlocal rec, sl
        for what, raw in (("record", record), ("seal", seal)):
            try:
                value = _parse(raw, what)
            except Exception as exc:  # noqa: BLE001 - every refusal of the strict reader is a failed step
                fail("parse", f"{what}: {exc}")
                continue
            if type(value) is not dict:
                fail("parse", f"{what}: not a JSON object")
                continue
            if what == "record":
                rec = value
            else:
                sl = value
        passed("parse")
    guarded("parse", step_parse)

    # 2. schema
    def step_schema() -> None:
        if rec.get("schema") == SCHEMA and _is_str(rec.get("schema")):
            passed("schema")
        else:
            fail("schema", f"the record schema is not {SCHEMA}")
    if rec is not None:
        guarded("schema", step_schema)

    # 3. result_digest
    def step_result_digest() -> None:
        body = {name: value for name, value in rec.items() if name != "result_digest"}
        claimed = rec.get("result_digest")
        if not _is_str(claimed):
            fail("result_digest", "the record carries no result_digest text")
        elif _digest(body) != claimed:
            fail("result_digest", "result_digest does not recompute from the record body")
        else:
            passed("result_digest")
    if rec is not None:
        guarded("result_digest", step_result_digest)

    # 4. input_digest
    def step_input_digest() -> None:
        try:
            value = _parse(input_series, "input")
        except Exception as exc:  # noqa: BLE001 - a refusal of the strict reader fails this step
            fail("input_digest", f"input: {exc}")
            return
        if rec is None:
            return
        claimed = rec.get("input_digest")
        if not _is_str(claimed) or _digest(value) != claimed:
            fail("input_digest", "input_digest does not recompute from the input file")
        else:
            passed("input_digest")
    if input_series is None:
        steps["input_digest"] = "not_supplied"
    else:
        guarded("input_digest", step_input_digest)

    # 5. seal_domain
    def step_seal_domain() -> None:
        if (sl.get("domain") == SEAL_DOMAIN and _is_str(sl.get("domain"))
                and sl.get("algorithm") == SEAL_ALGORITHM and _is_str(sl.get("algorithm"))):
            passed("seal_domain")
        else:
            fail("seal_domain", "the seal domain or algorithm is not the containment seal")
    if sl is not None:
        guarded("seal_domain", step_seal_domain)

    # 6. signed_message
    def step_signed_message() -> None:
        message = sl.get("signed_message")
        if not _is_str(message):
            fail("signed_message", "the seal carries no signed_message text")
            return
        if sl.get("signed_message_sha256") != hashlib.sha256(message.encode("utf-8")).hexdigest():
            fail("signed_message", "signed_message_sha256 does not recompute from signed_message")
        if rec is None:
            return
        digest = rec.get("result_digest")
        if not _is_str(digest) or message != f"{SEAL_DOMAIN}\n{SCHEMA}\n{digest}":
            fail("signed_message", "signed_message does not match the record digest")
            return
        passed("signed_message")
    if sl is not None:
        guarded("signed_message", step_signed_message)

    # 7. signature, under the pinned key only; an unusable trusted key fails this step whatever the seal holds
    usable = key is not None and ed25519_trust_anchor_weakness(key) is None

    def step_signature() -> None:
        message, signature_b64 = sl.get("signed_message"), sl.get("signature_b64")
        if not _is_str(message) or not _is_str(signature_b64):
            fail("signature", "the seal carries no signed_message or signature_b64 text")
            return
        try:
            signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        except (binascii.Error, UnicodeEncodeError):
            fail("signature", "signature_b64 is not base64")
            return
        if verify_ed25519_pinned(key, signature, message.encode("utf-8")):
            passed("signature")
        else:
            fail("signature", "the signature does not verify under the pinned key")
    if not usable:
        fail("signature", "the trusted key is not a usable Ed25519 trust anchor (raw 32 bytes, canonical, not of "
                          "small order)")
    elif sl is not None:
        guarded("signature", step_signature)

    accepted = (not failures and steps["input_digest"] in ("pass", "not_supplied")
                and all(steps[name] == "pass" for name in STEPS if name != "input_digest"))
    return {
        "format": SCHEMA,
        "scope": SCOPE,
        "scope_note": SCOPE_NOTE,
        "outcome": "ACCEPT" if accepted else "REFUSE",
        "steps": steps,
        "failures": failures,
        "trusted_key_sha256": hashlib.sha256(key).hexdigest() if usable else None,
    }
