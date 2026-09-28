"""Token Status List snapshot verification — offline revocation for receipts (v1.3).

Implements the verify side of IETF **Token Status List** (draft-ietf-oauth-status-list, draft-21,
in the RFC-Editor queue 2026-06 — the wire format is frozen; spec verified 2026-07-02 against the
datatracker). A Status List Token (SLT) is a signed JWT (`typ: "statuslist+jwt"`) whose payload
carries `sub` (the list URI), `iat`, optional `exp`/`ttl`, and `status_list: {bits, lst}` where
`lst` is base64url(zlib(DEFLATE(bit-array))) and `bits` ∈ {1, 2, 4, 8} is the per-token status
width. A Referenced Token (e.g. a proofbundle SD-JWT receipt) points into the list via its
`status.status_list.{idx, uri}` claim.

**The offline model — a bundled snapshot, staleness made explicit.** proofbundle never fetches.
The relying party supplies the SLT (obtained/bundled at emit time or refreshed out of band) plus
the status issuer's key. The verifier checks the SLT signature (EdDSA, consistent with the rest of
proofbundle), the `typ`, the `sub`↔`uri` match, decodes the bit array, and reads the status at
`idx`. Freshness (`iat`/`exp`/`ttl`) is REPORTED, and only JUDGED when the caller passes `now` —
an offline verifier has no trusted clock, so time policy stays the relying party's, stated
honestly instead of silently assumed.

The bundle format `proofbundle/v0.1` is UNCHANGED: the snapshot is a separate input, never a new
bundle field (old verifiers reject unknown fields by design — that guarantee is kept).
"""

from __future__ import annotations

import base64
import json
import zlib
from typing import Optional

from ._strict_json import loads_strict
from .budget import int_magnitude_ok, render_safe
from .canonical import (_EINGEBAUTE_SKALARE, _bytes_von, _ganzzahl_von, _pruefkopie, _type_name,
                        _zeichen_von)
from .errors import BundleFormatError, ProofBundleError
from .signature import verify_ed25519_pinned
from ._inflate import InflateCapExceeded, inflate_whole_stream
from ._wire_b64 import decode_b64url

__all__ = ["STATUS_LABELS", "verify_status_snapshot", "status_claim", "issue_status_list_token"]

# Registered status values (draft-ietf-oauth-status-list §7): the rest of the 1-byte space is
# application-specific; anything unknown is reported by numeric value.
STATUS_LABELS = {0x00: "VALID", 0x01: "INVALID", 0x02: "SUSPENDED"}
_ALLOWED_BITS = (1, 2, 4, 8)
# Decompression-bomb cap for the zlib status-list bit array (CWE-409). 64 MiB holds ~536M single-bit entries —
# far beyond any realistic revocation list — while bounding a malicious tiny-input → huge-output expansion.
_MAX_STATUS_LIST_BYTES = 64 * 1024 * 1024
TYP = "statuslist+jwt"


def _b64url_decode(s: str) -> bytes:
    # adversarial re-audit round 7: cap the raw segment length BEFORE decoding — base64-decoding an oversized
    # segment allocates before the caller's caps (which run on the DECODED value) can fire, a
    # memory-amplification DoS. Mirrors anchors_markovian's _MAX_PROOF_BYTES.
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415
    if len(s) > DEFAULT_BUDGET.input_bytes:
        raise BundleFormatError("base64 segment exceeds the input_bytes budget (pre-decode DoS guard)")
    raw = s.encode("ascii")
    return decode_b64url(raw)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def status_claim(uri: str, idx: int) -> dict:
    """The `status` claim a Referenced Token (receipt SD-JWT) carries to point into a list.

    Both values are read once (lens run 8, the sweep of finding B): the uri as the text it holds, the
    index as an exact `int`. The index check asked the caller's `__lt__` and the claim wrote the stored
    number; a subclass of `int` is refused, like every number a producer checks and writes."""
    from ._plain_value import plain_int  # noqa: PLC0415
    from .signature import plain_text  # noqa: PLC0415
    uri_text = plain_text(uri)
    if not uri_text:
        raise BundleFormatError("status list uri must be a non-empty string")
    index = plain_int(idx)
    if index is None or index < 0:
        raise BundleFormatError("status list index must be a non-negative integer")
    return {"status_list": {"idx": index, "uri": uri_text}}


def _status_at(bit_array: bytes, bits: int, idx: int) -> int:
    """Read the `bits`-wide status at token index `idx` (LSB-first within each byte, per spec)."""
    per_byte = 8 // bits
    byte_i, slot = divmod(idx, per_byte)
    if byte_i >= len(bit_array):
        raise BundleFormatError("status index is beyond the end of the status list")
    return (bit_array[byte_i] >> (slot * bits)) & ((1 << bits) - 1)


def verify_status_snapshot(status_list_token: str, *, expected_uri: str, index: int,
                           issuer_pubkey: bytes, now: Optional[int] = None,
                           receipt_issuer_pubkey: Optional[bytes] = None) -> dict:
    """Verify a Status List Token snapshot and read one token's status, fully offline.

    Checks, fail-closed: compact-JWS shape, `typ` == ``statuslist+jwt``, EdDSA signature under
    ``issuer_pubkey``, `sub` == ``expected_uri`` (a list for a different URI proves nothing),
    `bits` ∈ {1,2,4,8}, zlib decode, index in range. Freshness: `iat`/`exp`/`ttl` are returned;
    `fresh` is None unless ``now`` (POSIX seconds) is supplied, then it is
    ``iat <= now`` AND ``now < exp`` (if exp) AND ``now <= iat + ttl`` (if ttl).

    **Trust-anchor separation (v1.9.1, external review #8/#12):** a status list signed by the
    SAME key that signed the receipt carries no *independent* revocation assurance — the issuer
    simply attests its own "still valid" state, and can flip it at will. Pass
    ``receipt_issuer_pubkey`` (the bundle's signing key) and the result reports
    ``self_issued=True`` when the status issuer key equals it. This is REPORTED, not fatal — the
    relying party decides whether self-issued revocation is acceptable for its threat model (it
    often is not; a distinct, independently-operated status authority is the stronger anchor).

    Returns ``{ok, status, status_label, fresh, self_issued, iat, exp, ttl, detail}`` — ``ok``
    covers signature + structure + lookup; combining ``ok`` with ``fresh``/``self_issued`` is the
    caller's policy.
    """
    # explizite Annotation: der Result-Dict traegt bool (ok/self_issued), str (status_label/detail), int
    # (status/iat/exp/ttl) und None gemischt — ohne Annotation inferiert mypy nur 'str|bool|None' aus den
    # Init-Werten und lehnt die spaeteren int-Zuweisungen ab (CI-mypy-Fehler, kein Runtime-Bug).
    result: dict[str, str | bool | int | None] = {
        "ok": False, "status": None, "status_label": None, "fresh": None,
        "self_issued": None, "iat": None, "exp": None, "ttl": None, "detail": ""}
    if receipt_issuer_pubkey is not None:
        # hmac.compare_digest for a constant-time compare of the two public keys (defensive; the
        # values are public, but consistent with the codebase's compare discipline).
        import hmac as _hmac  # noqa: PLC0415
        # SYMMETRISCHER Typ-Guard: beide MUESSEN bytes/bytearray sein, sonst crasht bytes(str) mit TypeError
        # statt fail-closed (verify_status_snapshot deklariert 'never crashes'). Non-bytes receipt_issuer_pubkey
        # (str/int/list) → self_issued bleibt False (kein Crash, kein Fake-True).
        # Both keys by the bytes they store (round 12): `len()` and `bytes()` of a subclass are its own.
        _a, _b = _bytes_von(issuer_pubkey), _bytes_von(receipt_issuer_pubkey)
        result["self_issued"] = (_a is not None and _b is not None and len(_a) == len(_b)
                                 and _hmac.compare_digest(_a, _b))
    # deep gate 2026-09-05 (L3-600-04, RT-05 keyword_rp_expectation_arg_int_str_cap_dos): `now` is the relying
    # party's clock and was compared raw once the token carried exp/ttl — a str/list/bytes/float/huge-int `now`
    # raised a raw TypeError (or tripped the shift/render caps) out of a surface that declares 'never crashes'.
    # The floor sits at ENTRY, before any signature work: a malformed clock is a caller error, and the safe
    # direction is a fail-closed verdict that names it, never a silently unjudged freshness (fresh=None would
    # read as 'no bound to judge against', which is a different, honest state reserved for exp/ttl absence).
    # The clock as the integer it stores, read before it is judged (round 12): the magnitude check
    # below called its own `bit_length` and `isinstance` its `__class__` at cd5d39f4.
    if now is not None and (_ganzzahl_von(now) is None or not int_magnitude_ok(_ganzzahl_von(now))):
        # The refusal renders what the clock holds, never through its own methods (round 12): an exact
        # built-in as it is, a JSON value as its plain copy, anything else by its type name.
        gezeigt: object = now
        if type(now) not in _EINGEBAUTE_SKALARE:
            try:
                gezeigt = _pruefkopie(now)
            except ValueError:
                gezeigt = f"<{_type_name(type(now))}>"
        result["detail"] = ("status list now (relying-party clock) must be a POSIX-seconds integer within the "
                            f"magnitude budget, got {render_safe(gezeigt)} (fail-closed)")
        return result
    # One reading of each caller value, by what it holds (round 12): the clock and the index as the
    # integers they store (an `int` subclass answered `iat <= now` and chose the slot through its own
    # methods at cd5d39f4), the token as its characters, the expected uri as its characters.
    if now is not None:
        now = _ganzzahl_von(now)
    if _zeichen_von(status_list_token) is not None:
        status_list_token = _zeichen_von(status_list_token)
    if type(status_list_token) is not str:   # `type()`: a `__class__` claim is no str (round 12)
        # RE-TCE-06 (RE-GATE never-raise): a non-str token (int / None / list) must be a fail-closed verdict,
        # not a raw AttributeError from `.count(...)`. A garbage STRING already returns ok=False (lone
        # surrogate / bad shape), so a wrong-TYPE token must too — this surface declares "never crashes".
        result["detail"] = "status list token must be a string (non-str is malformed input, fail-closed)"
        return result
    if status_list_token.count(".") != 2:
        result["detail"] = "not a compact JWS"
        return result
    header_b64, payload_b64, sig_b64 = status_list_token.split(".")
    try:
        # WP-C1 (six-lens review, PROVEN differential): a duplicated status_list key in a SIGNED
        # token read VALID under a first-wins parser and INVALID under last-wins — the exact
        # revocation split-brain this gate exists to prevent.
        header = loads_strict(_b64url_decode(header_b64))
        payload = loads_strict(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except ProofBundleError as exc:  # incl. BudgetExceeded (RE-GATE never-raise) — a ProofBundleError sibling
        result["detail"] = f"malformed status list token: {exc}"
        return result
    except (ValueError, TypeError):
        result["detail"] = "malformed status list token"
        return result
    if not isinstance(header, dict) or not isinstance(payload, dict):
        result["detail"] = "malformed status list token"
        return result
    if header.get("typ") != TYP:
        result["detail"] = f"status list token typ must be '{TYP}'"
        return result
    if header.get("alg") != "EdDSA":
        result["detail"] = f"status list token alg {render_safe(header.get('alg'))} not supported (EdDSA only)"
        return result
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        # the status issuer key is the relying party's trust anchor: a low-order key verifies a signature
        # made with no private key, and a trusted key has exactly one encoding, so a low-order and a
        # non-canonical key are both refused before any arithmetic (Z195).
        sig_ok = verify_ed25519_pinned(issuer_pubkey, sig, signing_input)
    except ValueError:
        sig_ok = False
    if not sig_ok:
        result["detail"] = "status list token signature invalid"
        return result

    # The expected uri by its characters (round 12, O1's class). A supplied uri that is no string never
    # matches, even a token without `sub` (comparing None with None would); None is compared as before.
    _uri = _zeichen_von(expected_uri)
    if (expected_uri is not None and _uri is None) or payload.get("sub") != _uri:
        result["detail"] = "status list token sub does not match the referenced uri"
        return result
    iat, exp, ttl = payload.get("iat"), payload.get("exp"), payload.get("ttl")
    result["iat"], result["exp"], result["ttl"] = iat, exp, ttl
    if isinstance(iat, bool) or not isinstance(iat, int):
        result["detail"] = "status list token iat missing or not an integer"
        return result
    # v1.6 (external review): exp/ttl must be integers OR absent — a string "exp" that LOOKS
    # like an expiry but silently never enforces is a downgrade vector, not a tolerable input.
    for _name, _val in (("exp", exp), ("ttl", ttl)):
        if _val is not None and (isinstance(_val, bool) or not isinstance(_val, int)):
            result["detail"] = f"status list token {_name} must be an integer when present"
            return result

    sl = payload.get("status_list")
    if not isinstance(sl, dict):
        result["detail"] = "status_list claim missing"
        return result
    bits = sl.get("bits")
    if bits not in _ALLOWED_BITS:
        result["detail"] = f"status_list bits must be one of {_ALLOWED_BITS}"
        return result
    if not isinstance(sl.get("lst"), str):
        result["detail"] = "status_list lst missing"
        return result
    try:
        # BOUNDED decompression (release-review fix #7, CWE-409): a tiny zlib input can expand to gigabytes.
        # Cap the output and reject anything larger than a generous status-list size, instead of an unbounded
        # zlib.decompress() that a decompression-bomb could use to exhaust memory.
        # Deep gate Z195 (neighbour of L2-Z195-TOKEN-TRAILING-DATA-01): the output cap was the only check;
        # a truncated stream or bytes after its end were read as a bit array. `lst` is base64url(zlib(...)),
        # ONE complete stream, so both are refused here as the token refuses them.
        bit_array = inflate_whole_stream(_b64url_decode(sl["lst"]), _MAX_STATUS_LIST_BYTES)
    except InflateCapExceeded:
        result["detail"] = "status_list lst exceeds the maximum decompressed size"
        return result
    except (ValueError, TypeError, zlib.error, ProofBundleError):
        # LAUF 14 L2 F1, Nachbar (11.09.2026): _b64url_decode wirft bei einem Segment ueber dem
        # input_bytes-Deckel BundleFormatError — heute unerreichbar (lst stammt aus einem Payload,
        # dessen string_len-Budget enger ist), aber dieselbe except-Klasse wie in sdjwt: die Klausel
        # folgt dem Vertrag des Dekoders, nicht der Fehlerquelle von damals.
        result["detail"] = "status_list lst is not valid base64url(zlib(...))"
        return result
    index = _ganzzahl_von(index)
    if index is None or index < 0:
        result["detail"] = "status index must be a non-negative integer"
        return result
    try:
        status = _status_at(bit_array, bits, index)
    except ProofBundleError as exc:  # incl. BudgetExceeded (RE-GATE never-raise) — a ProofBundleError sibling
        result["detail"] = str(exc)
        return result

    result["ok"] = True
    result["status"] = status
    result["status_label"] = STATUS_LABELS.get(status, f"0x{status:02x}")
    if now is not None:
        # v1.6 (external review): a token with NEITHER exp NOR ttl is unbounded — "fresh
        # forever" was misleading (stale-snapshot replay). Without a bound, freshness CANNOT
        # be judged: fresh stays None and the relying party must impose its own max age.
        if exp is None and ttl is None:
            result["fresh"] = None
        else:
            fresh = iat <= now
            if exp is not None:
                fresh = fresh and now < exp
            if ttl is not None:
                fresh = fresh and now <= iat + ttl
            result["fresh"] = fresh
    result["detail"] = f"status {result['status_label']} at index {index}"
    return result


def issue_status_list_token(statuses: list, *, uri: str, signer, iat: int, bits: int = 1,
                            exp: Optional[int] = None, ttl: Optional[int] = None) -> str:
    """Issue a Status List Token (emit side, for tests/self-hosted lists). ``statuses`` is a list
    of small ints (< 2**bits); ``signer`` an Ed25519 private key; ``iat`` explicit POSIX seconds
    (the library never samples wall clocks for signatures). zlib level 9 per the spec's example.

    `bits`, `iat` and `statuses` are read once (lens run 8, the sweep of finding B): `bits` was checked
    through the caller's `__eq__` (tuple membership) and written as the stored number, and the status
    list was sized through `__len__` and walked through `__iter__`. Each number is an exact `int`."""
    # Each input by what it holds (round 12): the widths, the times, the uri and every status value
    # that are checked are the ones written and signed. At cd5d39f4 `len(statuses)` and the loop were
    # two readings of a list subclass, and an `int` subclass answered the range checks.
    from ._plain_value import plain_int, plain_list  # noqa: PLC0415
    bits_in = plain_int(bits)
    if bits_in is None or bits_in not in _ALLOWED_BITS:
        raise BundleFormatError(f"bits must be one of {_ALLOWED_BITS}")
    bits = bits_in
    if plain_int(iat) is None:
        raise BundleFormatError("iat must be a POSIX timestamp integer")
    # the stored items, without the list budget of `plain_json`: a status list is long by design. A
    # list or tuple is read from its storage, a `bytes` or `bytearray` (one status per byte) from its
    # storage too, and any other iterable once through its iterator, as before this change.
    from .signature import plain_bytes  # noqa: PLC0415
    stored = plain_list(statuses)
    if stored is None:
        raw = plain_bytes(statuses)
        if raw is not None:
            stored = list(raw)
        else:
            try:
                stored = list(statuses)
            except TypeError:
                raise BundleFormatError("statuses must be a sequence of small integers") from None
    statuses = stored
    uri = _zeichen_von(uri) if _zeichen_von(uri) is not None else uri
    if exp is not None:
        exp = _ganzzahl_von(exp) if _ganzzahl_von(exp) is not None else exp
    if ttl is not None:
        ttl = _ganzzahl_von(ttl) if _ganzzahl_von(ttl) is not None else ttl
    per_byte = 8 // bits
    arr = bytearray((len(statuses) + per_byte - 1) // per_byte)
    for i, s in enumerate(statuses):
        if plain_int(s) is None or not 0 <= s < (1 << bits):
            raise BundleFormatError(f"status value {s!r} does not fit in {bits} bit(s)")
        byte_i, slot = divmod(i, per_byte)
        arr[byte_i] |= s << (slot * bits)
    payload = {"sub": uri, "iat": iat,
               "status_list": {"bits": bits, "lst": _b64url(zlib.compress(bytes(arr), 9))}}
    if exp is not None:
        payload["exp"] = exp
    if ttl is not None:
        payload["ttl"] = ttl
    header = {"alg": "EdDSA", "typ": TYP}
    signing_input = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii")))
