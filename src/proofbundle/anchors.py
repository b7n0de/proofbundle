"""Generic external time-anchor layer for proofbundle receipts (EXPERIMENTAL; `[anchors]` extra).

An **anchor** is external evidence that a target existed at (or before) a time — something the receipt's
own Ed25519 + Merkle structure cannot establish on its own, because a self-emitted timestamp is only
producer-clock testimony. Three targets, **never mixed**:

* ``preRegistration`` — "the commitment existed BEFORE the run" (backdating protection; the point raised
  in in-toto/attestation#565).
* ``receipt`` — "the receipt existed from time T" (publication proof).
* ``statement`` — "this in-toto Statement's content existed from time T": the content root of a DSSE
  Statement (used by decision receipts). Anchor evidence for a statement's OWN content root is kept
  DETACHED (outside the signed bytes) — an anchor cannot live inside the bytes whose hash it commits
  without subset canonicalization, which is forbidden (proofbundle#7 consensus, 2026-07-10).

Each ``anchors[]`` entry is ``{type, target, canonicalRoot, proof, anchoredAt}``:

* ``type`` — ``rfc3161-tsa`` | ``opentimestamps`` | ``<extension>/vN``.
* ``target`` — ``receipt`` | ``preRegistration`` | ``statement`` (see above).
* ``canonicalRoot`` — base64 of the canonical root of the target: for ``receipt`` the RFC 8785 (JCS)
  sha256 of the receipt bundle; for ``preRegistration`` the sha256 of the raw protocol bytes (the
  receipt's ``prereg_sha256``); for ``statement`` the sha256 of the exact DSSE payload bytes
  (``statement_content_root``). The anchor timestamps THIS root.
* ``proof`` — base64 of the type-specific proof (an RFC 3161 token, an OpenTimestamps proof, ...).
* ``anchoredAt`` — RFC 3339 Z, INFORMATIVE only (the trusted time comes from the proof, not this field).

**Verify contract (fail-closed).** Missing/empty ``anchors`` → SKIP (never FAIL — consistent with
in-toto's Monotonic Principle: deny only when an attestation is present and wrong). Present → fail-closed:
a root mismatch, an unknown type, or a broken proof is a FAIL, never silent. ``require`` (CLI
``--require-anchor <type|any>``) turns "no verifying anchor" into a FAIL.

**Cross-target safety.** ``canonicalRoot`` is compared to the root of the anchor's OWN ``target`` — a
``preRegistration`` anchor can never validate a ``receipt`` target and vice versa (the roots differ).

**Lean core.** This module is pure dispatch + schema; the RFC 3161 / OpenTimestamps verifiers lazy-import
their libraries and are only needed with the ``[anchors]`` extra. The base install pulls only
``cryptography``; a bundle with no anchors verifies unchanged. Anchoring writes a NEW file — a network
error while stamping never corrupts the local receipt.
"""
from __future__ import annotations

import binascii
import functools
import hashlib
from typing import Callable, Optional

from .budget import render_keys_safe, render_safe
from .canonical import (_abbild_stand, _abbild_von, _bytes_von, _ein_stand, _feld_von, _folge_von,
                        _in_einem_zug, _plain_for_jcs, _puffer_von, _stand, _zeichen_von)
from .errors import BundleFormatError, ProofBundleError
from ._membership import is_member, require_switch, stored_str_items
from ._membership import type_name as _type_name  # the parameter of register_anchor_type is type_name
from ._wire_b64 import decode_b64

ANCHOR_TARGETS = ("receipt", "preRegistration", "statement")
_ANCHOR_KEYS = {"type", "target", "canonicalRoot", "proof", "anchoredAt", "frozen"}

# type name -> verifier callable:
#   (proof: bytes, canonical_root: bytes, *, frozen: dict, now: Optional[int]) -> {"ok": bool, "detail": str}
_VERIFIERS: dict[str, Callable] = {}

#: The flags of a verifier's result that count only as the exact True.
_RESULT_FLAGS = ("ok", "warn", "rp_trusted", "needs_rp_trust", "frozenEvidence")

#: The value types a carried ``trustedTime`` may hold, each by its exact type (the JSON scalars).
_TRUSTED_TIME_VALUE_TYPES = (str, int, float, bool, type(None))


def _refuse_unreadable_input(surface: Callable) -> Callable:
    """The fail-closed boundary of ``verify_anchor``, ``verify_anchors`` and ``receipt_canonical_root`` over what
    the caller hands in.

    They read caller objects: the anchor entries, the list holding them, ``require``, ``require_target`` and
    the receipt bundle.
    A key or a value there can run its own code while it is read (a ``str`` subclass whose ``__eq__`` raises
    as a key or as ``type``, a value whose ``__class__`` raises inside the structural budget's walk), and
    before round 5 that code's exception escaped them as a RuntimeError, and through the first two the
    never-raise ``verify_decision_receipt(anchors=...)`` (measured on 3d5b992a). Their documented refusal of
    malformed input is ``BundleFormatError``, so that is what any other exception becomes here, naming only
    its type (rendering it could run the caller's code again). A ``ProofBundleError`` (the documented typed
    refusals, ``SwitchTypeError`` among them) and a ``ValueError`` pass through unchanged. Nothing is ever
    promoted by this path: it raises."""

    @functools.wraps(surface)
    def guarded(*args, **kwargs):
        try:
            return surface(*args, **kwargs)
        except (ProofBundleError, ValueError):
            raise
        except Exception as exc:  # noqa: BLE001 - the boundary: anything else is unreadable input
            raise BundleFormatError(
                f"{surface.__name__} could not read its input: reading it raised an error of type "
                f"{_type_name(exc)} (a caller's object ran its own code, or the input is not JSON data); "
                "refused fail-closed") from exc
    return guarded


def _read_verifier_result(res: dict) -> dict:
    """The fields of a registered verifier's result that ``verify_anchor`` reports, read without running any
    code of the result: its keys only as exact ``str`` keys (:func:`_membership.stored_str_items`), each flag
    only as the exact ``True`` (``is``), ``status`` and ``detail`` only as exact ``str`` values, and
    ``trustedTime`` only as a dict whose exact-``str`` keys hold JSON scalars of their exact type, one of them a
    non-empty ``source``, carried as a plain copy. Whatever is not read that way is named in the detail.

    ``warn`` is the one flag a gate reads in both directions: beside ``ok`` True it RESTRICTS (a full anchor
    becomes a pending one), beside ``ok`` not True it PROMOTES (a failed anchor becomes a pending one, which
    ``allow_pending`` accepts). A ``warn`` that is no bool is read in the direction that grants nothing: as True
    beside ``ok`` True, as False otherwise (deep gate at 7409b123, L3-620-T2-01). Reading it only as the exact True
    made ``{"ok": True, "warn": "pending"}`` a full anchor; reading any other value as True would make
    ``{"ok": False, "warn": "false"}`` a pending one, which PR 291 fixed."""
    stored = stored_str_items(res)
    fields: dict = {"ok": stored.get("ok") is True}
    warn = stored.get("warn", False)
    fields["warn"] = warn if type(warn) is bool else fields["ok"]
    status = stored.get("status")
    if type(status) is str and status:
        fields["status"] = status
    else:
        fields["status"] = "pass" if fields["ok"] else ("warn" if fields["warn"] else "fail")
    detail = stored.get("detail")
    fields["detail"] = detail if type(detail) is str else ""
    for flag in ("rp_trusted", "needs_rp_trust", "frozenEvidence"):
        if flag in stored:
            fields[flag] = stored[flag] is True
    notes = []
    zurueckhaltend = fields["ok"] and "warn" in stored and type(stored["warn"]) is not bool
    not_bool = [flag for flag in _RESULT_FLAGS if flag in stored and type(stored[flag]) is not bool
                and not (flag == "warn" and zurueckhaltend)]
    if not_bool:
        notes.append(f"(the anchor verifier answered something other than True or False for "
                     f"{', '.join(not_bool)}; only the exact True counts)")
    if zurueckhaltend:
        notes.append("(the anchor verifier answered something other than True or False for warn beside ok True; "
                     "it is read as pending, never as a full anchor)")
    if status is not None and type(status) is not str:
        notes.append(f"(the anchor verifier's status was a value of type {_type_name(status)}, not a str, so the "
                     "status here is derived from ok and warn)")
    if detail is not None and type(detail) is not str:
        notes.append(f"(the anchor verifier's detail was a value of type {_type_name(detail)}, not a str, and is "
                     "not shown)")
    trusted_time = stored.get("trustedTime")
    if trusted_time is not None:
        plain = stored_str_items(trusted_time)
        source = plain.get("source")
        if (plain and len(plain) == dict.__len__(trusted_time) and type(source) is str and source
                and all(any(type(v) is t for t in _TRUSTED_TIME_VALUE_TYPES) for v in plain.values())):
            fields["trustedTime"] = plain
        else:
            notes.append("(the anchor verifier's trustedTime is not a dict of str keys holding JSON scalars with a "
                         "non-empty str source, and is not carried)")
    if notes:
        fields["detail"] = " ".join(([fields["detail"]] if fields["detail"] else []) + notes)
    return fields


def _as_dict(v):
    """adversarial re-audit r5 class-fix: Config-Sub-Feld als dict, sonst {} (schliesst das ``_as_dict(x.get(k))``-Loch)."""
    return v if isinstance(v, dict) else {}


def _as_list(v):
    return v if isinstance(v, (list, tuple)) else []


@_ein_stand
def register_anchor_type(type_name: str, verifier: Callable) -> None:
    """Register a verifier for an anchor ``type``. A third party ships its own type this way (see
    docs/ANCHORS.md). The verifier MUST be fail-closed: return ``{"ok": False, ...}`` on any doubt,
    never raise for an ordinary bad proof. The result must be a ``dict``; a dict subclass (an
    ``OrderedDict``, a ``defaultdict``) is read by what it stores, never through its own methods. ``ok``,
    ``rp_trusted``, ``needs_rp_trust`` and ``frozenEvidence`` count only as the exact ``True``:
    any other value, a truthy one included (``1``, ``"true"``, ``"false"``, a non-empty list), counts as
    False and the detail says so. ``warn`` beside an ``ok`` that is not the exact ``True`` counts the same way;
    beside ``ok`` True any ``warn`` but the exact ``False`` (or none) marks the anchor pending, never full, and the
    detail says so. A result that is not a dict is a failed anchor whose detail names the
    type returned. A key counts only when it is exactly a ``str`` (a key of another type, a ``str``
    subclass included, is not read, so its own ``__eq__`` can neither raise nor stand in for ``"ok"``);
    ``status`` and ``detail`` are read only as exact ``str`` values, and ``trustedTime`` only as a dict of
    exact-``str`` keys holding JSON scalars with a non-empty ``source``, carried as a plain copy. Nothing the
    result's objects could run is ever called while it is read."""
    if not type_name or not isinstance(type_name, str) or not callable(verifier):
        raise BundleFormatError("register_anchor_type needs a non-empty name and a callable verifier")
    _VERIFIERS[type_name] = verifier


@_ein_stand
def registered_anchor_types() -> tuple:
    _ensure_builtin_types()
    return tuple(sorted(_VERIFIERS))


def _ensure_builtin_types() -> None:
    """Lazily register the built-in anchor verifiers (rfc3161-tsa, opentimestamps). Each needs the
    ``[anchors]`` extra; if a library is absent the type stays UNREGISTERED — which the verify path
    treats as an unknown type → FAIL (fail-closed), exactly the behaviour we want without the extra."""
    if "rfc3161-tsa" not in _VERIFIERS:
        try:
            from . import anchors_rfc3161  # noqa: PLC0415
            _VERIFIERS["rfc3161-tsa"] = anchors_rfc3161.verify_rfc3161
        except Exception:   # extra missing / import failure → leave unregistered (fail-closed)
            pass
    if "opentimestamps" not in _VERIFIERS:
        try:
            from . import anchors_ots  # noqa: PLC0415
            _VERIFIERS["opentimestamps"] = anchors_ots.verify_opentimestamps
        except Exception:
            pass
    # chia-datalayer/v1: the first FIRST-PARTY extension anchor. Its offline Merkle verifier (level i) is
    # PURE SHA-256 — no Chia software, no extra — so it always registers (writing an anchor via anchor-add
    # needs the [chia] extra + a node, but VERIFYING one offline does not).
    if "chia-datalayer/v1" not in _VERIFIERS:
        try:
            from . import anchors_chia  # noqa: PLC0415
            _VERIFIERS[anchors_chia.ANCHOR_TYPE] = anchors_chia.verify_chia_datalayer
        except Exception:   # pragma: no cover - pure module, import should not fail
            pass


def _b64d(value, field: str) -> bytes:
    if not isinstance(value, str):
        raise BundleFormatError(f"anchor {field} must be a base64 string")
    try:
        return decode_b64(value)
    except (ValueError, binascii.Error) as exc:
        raise BundleFormatError(f"anchor {field} is not valid base64") from exc


@_ein_stand
@_refuse_unreadable_input
def receipt_canonical_root(bundle: dict) -> bytes:
    """The RFC 8785 (JCS) sha256 of the receipt bundle — the canonical root a ``receipt`` anchor stamps.
    Uses a real RFC 8785 canonicalizer (the ``[anchors]``/``[eval]`` extra); never a home-grown sort.

    Every ES256 signature in ``sd_jwt_vc.compact``, the issuer JWT's and a Key Binding JWT's, enters
    the root in its low-s spelling (finding D1, :func:`proofbundle.sdjwt.canonical_sd_jwt_compact`):
    ``verify_bundle`` accepts ``(r, s)`` and ``(r, n - s)``, and one receipt has one root. The bundle
    itself is not rewritten. Measured on 126ed1dc: a bundle and its twin gave two roots, so an
    anchor over one did not cover the other. An anchor stamped before this change over a bundle
    with a high ``s`` in one of those signatures no longer matches; measured on 2026-09-26, none of
    the JSON files tracked in this repository carries an ES256 ``sd_jwt_vc``."""
    try:
        import rfc8785  # noqa: PLC0415
    except ImportError as exc:   # pragma: no cover - guarded by the extra
        raise BundleFormatError(
            "receipt anchoring needs the RFC 8785 canonicalizer — install proofbundle[anchors]") from exc
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids an import cycle
    from .errors import ProofBundleError  # noqa: PLC0415
    try:
        # adversarial re-audit round 7: bound depth (<=64) / node count BEFORE rfc8785.dumps recurses — a deeply
        # nested bundle made rfc8785.dumps raise a raw RecursionError (a RuntimeError, NOT the ValueError arm
        # below, NOT a ProofBundleError, so it escaped this public verify-path primitive). This mirrors the
        # round-5 fix on the peer canonical.canonicalize_statement / statement_content_root.
        enforce_structural_budget(bundle)
        from .bundle import _canonical_signature_form  # noqa: PLC0415 - local import, as above
        return hashlib.sha256(rfc8785.dumps(_canonical_signature_form(bundle))).digest()
    except BundleFormatError:
        raise
    except (ProofBundleError, ValueError, RecursionError) as exc:
        # loads_strict admits NaN/Infinity and ints >= 2^53, but rfc8785.dumps rejects them (FloatDomainError /
        # IntegerDomainError, both ValueError); over-width trips BudgetExceeded (a ProofBundleError); a deep dict
        # that slips past the budget could still recurse. All map to the documented BundleFormatError, never raw.
        raise BundleFormatError(
            f"receipt is not RFC 8785 canonicalizable (fail-closed): {exc}") from exc


@_ein_stand
def prereg_canonical_root(prereg_sha256_hex: str) -> bytes:
    """The canonical root a ``preRegistration`` anchor stamps: the sha256 (raw bytes) of the eval
    protocol file, i.e. the receipt's ``prereg_sha256``."""
    # Read once (lens run 8 at fddc00f4, the sweep of finding A): the length check asked a `str`
    # subclass's `__len__`, and `bytes.fromhex` read its stored text, so a root of another length could
    # pass as a sha256.
    from .signature import plain_text  # noqa: PLC0415
    text = plain_text(prereg_sha256_hex)
    if text is None or len(text) != 64:
        raise BundleFormatError("prereg canonical root needs a 64-char hex sha256")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise BundleFormatError("prereg_sha256 is not valid hex") from exc


@_ein_stand
def statement_content_root(payload_bytes: bytes) -> bytes:
    """The content root a ``statement`` anchor stamps: SHA-256 over the EXACT DSSE payload bytes of an
    in-toto Statement (for a decision receipt, the RFC 8785 canonical statement bytes as signed).

    Deliberately hashes the exact transmitted bytes — the verifier NEVER re-canonicalizes (DSSE rule).
    The content root binds the CLAIM CONTENT, never the signature bytes, so it survives counter-signing,
    key rotation and multi-signature envelopes (b7n0de/proofbundle#7 consensus, 2026-07-10). The caller
    (verify_decision_receipt) has already fail-closed if the payload deviates from its own RFC 8785 form.

    Thin wrapper over the shared ``canonical.statement_content_root`` primitive (ADR 0002) so this anchor
    entry point and decision.py resolve the content root from ONE definition; the type-check stays here to
    keep the anchor-layer ``BundleFormatError`` contract (a non-bytes target is a fail-closed schema error,
    not a producer-side canonicalization)."""
    # The bytes it stores, by its own type (round 12): `bytes(x)` ran a `bytes` subclass's own
    # `__bytes__` (Python 3.11 and later), so the caller's code chose the bytes the root was taken over.
    roh = _bytes_von(payload_bytes)
    if roh is None:
        raise BundleFormatError("statement content root needs the raw payload bytes")
    from . import canonical  # noqa: PLC0415
    return canonical.statement_content_root(roh)


def _call_verifier(fn: Callable, proof: bytes, canonical_root: bytes, *,
                   frozen: dict, now: Optional[int], rp_trust: Optional[dict]) -> dict:
    """Dispatch to an anchor verifier, backward-compatibly. WP-A1 added the ``rp_trust`` kwarg (relying-
    party trust material); a third-party verifier registered before A-1 accepts only ``(proof, root, *,
    frozen, now)``. Pass ``rp_trust`` only when the verifier's signature accepts it (or takes ``**kwargs``),
    so pre-A1 extension verifiers keep working — they simply never see RP trust (their own trust model)."""
    import inspect  # noqa: PLC0415
    kw: dict = {"frozen": frozen, "now": now}
    try:
        params = inspect.signature(fn).parameters
        if "rp_trust" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            kw["rp_trust"] = rp_trust
    except (ValueError, TypeError):   # a builtin/C callable with no introspectable signature
        pass
    return fn(proof, canonical_root, **kw)


@_ein_stand(rp_trust=_abbild_stand)
@_refuse_unreadable_input
def verify_anchor(anchor: dict, *, target_roots: dict, now: Optional[int] = None,
                  rp_trust: Optional[dict] = None) -> dict:
    """Verify ONE anchor entry, fail-closed. ``target_roots`` maps a target name to its canonical root
    bytes (only the targets that exist for this receipt). ``rp_trust`` (WP-A1) is the relying-party trust
    material (TSA roots, Bitcoin block headers) — the ONLY source of trust for a confirmed time anchor;
    the bundle's own ``frozen`` block is evidence, never trust. Returns ``{ok, type, target, detail}``.

    A malformed entry raises ``BundleFormatError``, and so does an entry whose keys or values run code of
    their own that raises while they are read (:func:`_refuse_unreadable_input`); a registered verifier
    that raises, or whose result cannot be read, is a failed anchor, never an exception."""
    _ensure_builtin_types()
    return _eintrag_pruefen(_eintrag_lesen(anchor), wurzeln=_wurzeln_lesen(target_roots), now=now,
                            rp_trust=rp_trust, pruefer=_VERIFIERS)


#: The root a relying party supplied for a target when it is no bytes-like value: it equals no anchor's root.
_KEIN_PUFFER = object()


def _wurzeln_lesen(target_roots) -> dict:
    """The relying party's root per target, read once as the bytes each stores, before any verifier runs (deep
    gate at 7409b123, L1-620v2-T3-01). ``_feld_von`` reads what the dict stores and ``_puffer_von`` copies the bytes
    a root holds, so a verifier run for one anchor cannot move the root the next anchor is compared with. A target
    that is absent is absent here; a root that is no bytes-like value is `_KEIN_PUFFER`, which matches nothing, as
    the comparison with ``None`` did before. The three targets are one reading, with the collector paused
    (`canonical._in_einem_zug`), so a gc callback of the caller cannot pair the root of one target from before a change
    with the root of another from after it (the class of L4-620v5-T5-SECOND-READING-01)."""
    wurzeln: dict = {}
    with _in_einem_zug():
        for ziel in ANCHOR_TARGETS:
            wert = _feld_von(target_roots, ziel)
            if wert is not None:
                roh = _puffer_von(wert)
                wurzeln[ziel] = roh if roh is not None else _KEIN_PUFFER
    return wurzeln


def _eintrag_lesen(anchor) -> dict:
    """One anchor entry as the plain copy of what it stores, after the structural budget, or
    ``BundleFormatError``. `verify_anchors` reads every entry this way before the first verifier runs."""
    if not isinstance(anchor, dict):
        raise BundleFormatError("each anchor must be a JSON object")
    # Structural budget (deep gate wf_cfe249d0-ee8, finding L2-01, P1). A DIRECT-DICT surface — and a
    # narrow-looking one: ``_ANCHOR_KEYS`` bounds which FIELDS may appear, which is why this read as
    # already-guarded. It bounds the key set, not the value sizes. ``canonicalRoot`` and ``proof`` are
    # base64-decoded below with no length cap of their own, so a single 100 MB ``proof`` string is expanded
    # before any verifier is even chosen.
    #
    # The peer primitive in this same module (``receipt_canonical_root``) already applies this bound; the
    # entry point that actually receives third-party input did not. Raising matches this function's
    # convention: a malformed STRUCTURE raises BundleFormatError (see the guard above and ``_b64d``),
    # while a failed verification is reported in the ``out`` dict.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids an import cycle
    from .errors import ProofBundleError  # noqa: PLC0415
    try:
        enforce_structural_budget(anchor)
    except ProofBundleError as exc:
        raise BundleFormatError(f"anchor exceeds the verification budget (fail-closed): {exc}") from exc
    # ONE READING (round 12): after the budget, the anchor is read once into the plain copy of what it
    # stores, and every field below comes from the copy, so a dict subclass's own `get` cannot show
    # the key check one field set and the verifier another. An anchor holding a value that is no JSON
    # value is BundleFormatError, as a malformed structure is.
    return _plain_for_jcs(anchor, lambda text: BundleFormatError(f"anchor: {text}"))


def _eintrag_pruefen(anchor: dict, *, wurzeln: dict, now: Optional[int], rp_trust: Optional[dict],
                     pruefer: dict) -> dict:
    """The verdict on one anchor entry that `_eintrag_lesen` read, against the roots `_wurzeln_lesen` read, with
    the verifiers of ``pruefer``. It reads nothing of the caller's after the verifier call."""
    unknown = set(anchor) - _ANCHOR_KEYS
    if unknown:
        # deep gate 2026-09-05 (L3-600-03 class): name the keys rendered, never sort raw mixed-type keys
        raise BundleFormatError(f"anchor has unknown field(s) {render_keys_safe(unknown)}")
    atype = anchor.get("type")
    target = anchor.get("target")
    out = {"ok": False, "warn": False, "status": "fail", "type": atype, "target": target, "detail": ""}
    if target not in ANCHOR_TARGETS:
        out["detail"] = f"anchor target must be one of {ANCHOR_TARGETS}"
        return out
    anchored_at = anchor.get("anchoredAt")
    if anchored_at is not None and not isinstance(anchored_at, str):
        # WP-A7: anchoredAt is INFORMATIVE, but a non-string value is malformed input, not a
        # display nicety — fail closed like every other schema violation (detached anchors have no
        # JSON-schema layer in front of them).
        out["detail"] = "anchor anchoredAt must be an RFC 3339 string or null (informative only)"
        return out
    if not isinstance(atype, str) or not is_member(atype, pruefer):
        # Unknown type is a FAIL, not a SKIP — an anchor we cannot check must never pass silently.
        # deep gate 2026-09-05 (L2-BDOS-RENDER-NEIGHBOURS-01): `{atype!r}` rendered the untrusted value raw;
        # a huge int here tripped the int->str cap as a raw ValueError out of verify_anchor(s) and the public
        # never-raise decision.verify_decision_receipt(anchors=...). Bounded renderer, never raw.
        out["detail"] = (f"no verifier registered for anchor type {render_safe(atype)} "
                         "(install proofbundle[anchors] or register the extension type)")
        return out
    # The relying party's root by the bytes it stores, read through the base lookup (round 12): a dict
    # subclass's own `get` and a `bytes` subclass's own `__ne__` never decide the binding. A
    # `memoryview` root is compared by the bytes it views, as `!=` compared it before
    # (`canonical._puffer_von`); any other value never matches. Read once, before any verifier ran
    # (`_wurzeln_lesen`).
    expected_root = wurzeln.get(target)  # adversarial re-audit r5: target_roots kwarg (None/int) fail-closed
    if expected_root is None:
        out["detail"] = f"the receipt has no {target} target to anchor against"
        return out
    canonical_root = _b64d(anchor.get("canonicalRoot"), "canonicalRoot")
    if canonical_root != expected_root:
        # cross-target safety: a preRegistration anchor's root never equals the receipt root, and v.v.
        out["detail"] = f"canonicalRoot does not match the {target} root (cross-target or tampered)"
        return out
    proof = _b64d(anchor.get("proof"), "proof")
    # adversarial re-audit round 6 (defensive): `_as_dict(anchor.get("frozen"))` only replaces a FALSY non-dict; a
    # TRUTHY non-dict from an attacker bundle ("frozen":"x" / [...]) would reach a verifier's frozen.get(...).
    # The `except Exception` below already fail-closes that, but normalize any non-dict to {} up front so the
    # verifiers never see a wrong type.
    _frozen = anchor.get("frozen")
    if not isinstance(_frozen, dict):
        _frozen = {}
    # A registered verifier is the caller's code: it gets its own copy of `frozen` and `rp_trust`, so what it does to
    # them reaches no other reading of this call, and its result is read as one state (`canonical._stand`), so
    # what it does to that result after it returned reaches nothing either (verify lane V2 on 6d674973: a value a
    # caller's callable returns is a caller's value too).
    try:
        res = _stand(_call_verifier(pruefer[atype], proof, canonical_root,
                                    frozen=_stand(_frozen), now=now, rp_trust=_stand(rp_trust)))
    except Exception as exc:   # a verifier must be fail-closed; if it raises, treat as FAIL, never pass
        out["detail"] = f"anchor verifier error (fail-closed): {exc}"
        return out
    # A registered verifier is caller code (register_anchor_type is a public extension point), so each
    # verdict and flag of its result counts only as the exact True: bool(res.get("ok")) made {"ok": "false"}
    # a verified anchor, {"warn": "false"} turned a hard FAIL into a pending one, and a result that is not a
    # dict raised a raw AttributeError here. The result is a dict when its REAL type is one
    # (issubclass(type(res), dict), an identity walk of the MRO; isinstance would believe the object's own
    # __class__), and it is read ONCE, by what it stores (dict.get of the base type): an OrderedDict or a
    # defaultdict is read as the dict it is, and a subclass whose own get, __getitem__, __contains__ or
    # __missing__ answers True promotes nothing, because none of them runs. 3a8074fc refused every dict
    # subclass, so an OrderedDict with ok True, a verified anchor on main 31816e08, was a failed anchor whose
    # detail said "no result object" (measured). A result that is not a dict names its type in the detail
    # (read with type_name, which runs no code of the caller); the values are never rendered.
    if not issubclass(type(res), dict):
        out["detail"] = (f"the anchor verifier returned a value of type {_type_name(res)}, which is not a dict "
                         "(a dict whose ok is the exact True is required); not verified (fail-closed)")
        return out
    # Round 5 (review of c8865652, F1): the result was read with dict.get of the base type, which still
    # compared a stored key whose hash equals hash("ok") through the key's own __eq__, `status or ...` called
    # the status value's __bool__, and isinstance(tt, dict) read the trustedTime value's __class__. When one of
    # them raised, a RuntimeError escaped this function, verify_anchors and verify_decision_receipt(anchors=)
    # (measured on 3d5b992a), and a key whose __eq__ answered True stood in for "ok" and verified the anchor.
    # The fail-closed try ended at the verifier CALL above and did not cover the reading of its answer. Now
    # the reading runs no code of the result (_read_verifier_result), and it sits inside the boundary as
    # well: if it ever raised, the anchor stays failed and the detail names the error's type.
    #
    # WP-A1: the trust provenance is surfaced so the relying party can see WHY (and the require gate can only
    # count RP-trusted anchors). `rp_trusted` True → verified against RP-supplied trust material;
    # `needs_rp_trust` True → the proof exists but confirming it needs RP material (frozen is not trust);
    # `frozenEvidence` True → the bundle carried frozen material, reported but never trusted. WP-A2: the
    # structured trusted time is carried from the type verifier only when the proof genuinely carries it
    # (rfc3161 gen_time; a confirmed Bitcoin height), NEVER guessed, NEVER derived from anchoredAt.
    try:
        fields = _read_verifier_result(res)
    except Exception as exc:  # noqa: BLE001 - fail-closed: a result that cannot be read verifies nothing
        out["detail"] = (f"the anchor verifier's result could not be read (an error of type {_type_name(exc)}); "
                         "not verified (fail-closed)")
        return out
    out.update(fields)
    return out


@_ein_stand(rp_trust=_abbild_stand)
@_refuse_unreadable_input
def verify_anchors(anchors, *, target_roots: dict, require: Optional[str] = None,
                   require_target: Optional[str] = None,
                   allow_pending: bool = False, now: Optional[int] = None,
                   rp_trust: Optional[dict] = None) -> dict:
    """Verify a receipt's ``anchors``. Missing/empty → SKIP (unless ``require`` is set → FAIL). Present →
    fail-closed PASS/FAIL over every entry. ``require`` is ``None`` | ``'any'`` | a type string; when set,
    at least one anchor of that type (or any) must verify. Returns ``{status, detail, results}`` with
    ``status`` in {PASS, FAIL, WARN, SKIP}; when ``require`` is set the return ALSO carries
    ``require_met`` (bool) — the requirement verdict, kept SEPARATE from the aggregate ``status``.

    ``status`` is the INFORMATIVE aggregate over EVERY entry (a broken/unknown/unbound anchor makes it
    FAIL, never silent). ``require_met`` is the relying-party gate the CLI maps to the exit code: it is
    True iff at least one anchor of the required type actually verifies (``matched`` below). The two are
    deliberately distinct — an UNRELATED broken anchor must NOT fail a requirement that a DIFFERENT
    anchor satisfies, exactly as anchors are advisory-only when no requirement is set. So a receipt with
    a verifying required anchor AND an unrelated broken one reports ``require_met=True`` (→ exit 0) while
    ``status`` stays FAIL (the broken anchor is still surfaced). Basing the gate on the global ``status``
    was the WP4 aggregation bug this fixes.

    ``allow_pending`` (default ``False``) only changes what SATISFIES a ``require``: normally a
    PENDING/WARN anchor (e.g. an un-upgraded OpenTimestamps proof, or a level-i chia anchor) does NOT
    count as a verifying anchor, so ``--require-anchor`` demands a full external-time proof. With
    ``allow_pending=True`` (CLI ``--require-anchor … --allow-pending``) a pending anchor also satisfies
    the requirement — weaker, and the relying party opted into it explicitly. It never turns a broken
    anchor into a pass: a hard-failing anchor still aggregates to FAIL. ``allow_pending`` must be a
    bool: anything else raises :class:`~proofbundle.errors.SwitchTypeError` (a ``TypeError`` and a
    ``ProofBundleError``) naming the parameter and the type, before anything else is read. It was read
    by its truth, so ``allow_pending="false"`` let a pending anchor meet the requirement (measured at
    fa555f13 too, round 11, class B of lens run 10).

    Like :func:`verify_anchor`, it refuses input whose objects raise from their own code while they are read
    with ``BundleFormatError`` (:func:`_refuse_unreadable_input`), never with the caller's exception.

    EVERYTHING IS READ BEFORE THE FIRST VERIFIER RUNS (deep gate at 7409b123, L1-620v2-T3-01): every anchor
    entry into its plain copy (`_anker_lesen`), ``rp_trust`` into its plain copy, the relying party's roots and
    the registry of verifiers. Each entry was copied only when its turn came, so a registered verifier run for one
    anchor rewrote the next one, the root it was compared with or the header it was confirmed against. Each
    verifier gets a copy of ``rp_trust`` of its own. ``anchors`` is None or a list, and ``require`` and
    ``require_target`` are None or a string: a value of another type, a falsy one included (``0``, ``""``,
    ``{}``, ``()``), is refused, never read as no anchors or no requirement (L4-620b-01, the neighbour
    RESTRISIKO_620 named). An ``rp_trust`` that is no JSON object is refused once there is an anchor to judge."""
    require_switch(allow_pending, "allow_pending")
    # The requirements by their characters and the anchors through the list's own iteration, each
    # read once (round 12): a `str` subclass's own `__eq__` never matches a type or a target, and a
    # list subclass's own `__len__` and `__iter__` never decide which anchors are judged.
    # A value that is no string and not None is refused by its type, never asked through `==`, `bool()` or
    # `__iter__`: an object claiming str or list through `__class__` answered those itself.
    if require is not None:
        if _zeichen_von(require) is None:
            raise BundleFormatError(f"require must be an anchor type string, got {_type_name(require)}")
        require = _zeichen_von(require)
    if require_target is not None:
        if _zeichen_von(require_target) is None:
            raise BundleFormatError(
                f"require_target must be one of {ANCHOR_TARGETS}, got {_type_name(require_target)}")
        require_target = _zeichen_von(require_target)
    if anchors is not None and not issubclass(type(anchors), list):
        raise BundleFormatError("anchors must be a list")
    if require_target is not None and require_target not in ANCHOR_TARGETS:
        raise BundleFormatError(
            f"require_target must be one of {ANCHOR_TARGETS}, got {render_safe(require_target)}")
    return _anker_urteil(_anker_lesen(anchors, rp_trust), target_roots=target_roots, require=require,
                         require_target=require_target, allow_pending=allow_pending, now=now)


def _anker_lesen(anchors, rp_trust) -> tuple:
    """``anchors``, ``rp_trust`` and the registry of verifiers read once, before any caller code runs:
    ``(entries, rp_copy, verifiers)``, each entry the plain copy `_eintrag_lesen` makes, ``rp_copy`` the plain copy
    of ``rp_trust`` (`canonical._abbild_von`) or None, and ``verifiers`` a copy of the registry or None.
    `verify_anchors` calls it at once; `decision.verify_decision_receipt` calls it at its entry, before the
    evidence resolver runs, and keeps what it raises for the anchor step. None is no anchors; any other value that
    is no list is ``BundleFormatError``. ``rp_trust`` and the registry are read only when there is an entry to
    judge, so a call without anchors never refuses ``rp_trust``.

    THE REGISTRY IS READ HERE TOO (verify lens on the cross-check fix at bc3d275f, 2026-09-29): it was copied in
    `_anker_urteil`, which the decision verifier runs after the evidence resolver, so a resolver that called
    `register_anchor_type` for the anchor's type turned a failing anchor into a verifying one and ``ok`` and
    ``safeForAutomation`` True. The registry a verdict uses is the one that stood before any caller code ran.

    ALL OF IT IS ONE STATE (deep gate run 5 at d388ed3d, the sweep of L4-620v5-T5-SECOND-READING-01): the entries
    were copied one after another, and a gc callback of the caller that rewrote two of them while the copy was
    between them gave a list the caller never held. The whole reading runs with the collector paused
    (`canonical._in_einem_zug`)."""
    if anchors is None:
        return [], None, None
    if not issubclass(type(anchors), list):
        raise BundleFormatError("anchors must be a list")
    with _in_einem_zug():
        eintraege = [_eintrag_lesen(a) for a in _folge_von(anchors)]
        rp_kopie = None
        if eintraege and rp_trust is not None:
            rp_kopie = _abbild_von(rp_trust)
            if rp_kopie is None:
                raise BundleFormatError(f"rp_trust must be a JSON object, got a value of type "
                                        f"{_type_name(rp_trust)} or one holding a value that is no JSON value "
                                        "(fail-closed)")
        pruefer = None
        if eintraege:
            _ensure_builtin_types()
            pruefer = dict(_VERIFIERS)
        return eintraege, rp_kopie, pruefer


def _anker_urteil(gelesen: tuple, *, target_roots, require: Optional[str] = None,
                  require_target: Optional[str] = None, allow_pending: bool = False,
                  now: Optional[int] = None) -> dict:
    """The verdict of `verify_anchors` over what `_anker_lesen` read, the registry of verifiers included. The roots
    are read here, before the first verifier runs, and each verifier gets a copy of the relying party's trust
    material of its own, so nothing a verifier does reaches what the next one is judged by."""
    eintraege, rp_kopie, pruefer = gelesen
    if require_target is not None and not require:
        require = "any"   # a target requirement IS an anchor requirement (mirrors --anchor-type)
    if not eintraege:
        if require:
            return {"status": "FAIL", "require_met": False,
                    "detail": f"--require-anchor {require} set but the receipt has no anchors",
                    "results": []}
        return {"status": "SKIP", "detail": "no external time anchors present", "results": []}
    wurzeln = _wurzeln_lesen(target_roots)
    results = [_eintrag_pruefen(a, wurzeln=wurzeln, now=now, pruefer=pruefer,
                                rp_trust=None if rp_kopie is None else _plain_for_jcs(rp_kopie, ValueError))
               for a in eintraege]
    if require:   # a warn/pending/inclusion-only anchor never SATISFIES a requirement — only a full one
        want = None if require == "any" else require
        # WP-A1: matched = ok ∧ ¬warn ∧ type ∧ TARGET. Matching the type alone was a backdating
        # hole: a relying party demanding pre-registration evidence (--anchor-target
        # preRegistration) was satisfied by a RECEIPT anchor stamped today — existence-now proves
        # nothing about existence-before-the-run.
        def _target_ok(r):
            return require_target is None or r["target"] == require_target
        if allow_pending:
            matched = [r for r in results
                       if (r["ok"] or r["warn"]) and (want is None or r["type"] == want)
                       and _target_ok(r)]
        else:
            matched = [r for r in results
                       if r["ok"] and not r["warn"] and (want is None or r["type"] == want)
                       and _target_ok(r)]
        if not matched:
            tgt = f" with target {render_safe(require_target)}" if require_target is not None else ""
            detail = (f"--require-anchor {require}{tgt} (--allow-pending): no verifying or pending anchor of that type/target"
                      if allow_pending else
                      f"--require-anchor {require}{tgt}: no verifying anchor of that type/target")
            return {"status": "FAIL", "require_met": False, "detail": detail, "results": results}
    hard_fail = any(not r["ok"] and not r["warn"] for r in results)
    if hard_fail:
        status = "FAIL"                       # a broken/unbound/unknown anchor is never silent
    elif any(r["warn"] for r in results):
        status = "WARN"                       # e.g. a PENDING OpenTimestamps proof — not a full anchor yet
    else:
        status = "PASS"
    detail = f"{sum(r['ok'] for r in results)}/{len(results)} anchor(s) verified"
    out: dict = {"status": status, "detail": detail, "results": results}
    if require:   # reached here → `matched` is non-empty → the requirement IS met, regardless of an
        out["require_met"] = True   # UNRELATED anchor hard-failing (that stays advisory in `status`)
    return out
