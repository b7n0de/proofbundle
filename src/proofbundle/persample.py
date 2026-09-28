"""Per-sample receipts — a Merkle tree over individual eval samples, with salted selective
opening and an auditor spot-check protocol (v1.5).

This closes the THREAT_MODEL's named structural gap: an aggregate receipt cannot detect
per-sample sub-sampling or cherry-picking. Now the signed claim can carry a **samples root** —
an RFC 6962 SHA-256 Merkle tree head over one leaf per sample — so an auditor can challenge k
random indices and demand **openings** (disclosure + inclusion proof) that re-derive to the
committed root. Catching an m-fraction of manipulated samples with k challenges succeeds with
probability 1−(1−m)^k, independent of n (proof-of-retrievability bound, Ateniese/Juels–Kaliski
2007): k=300 → 95% at m=1%, k=459 → 99%.

Construction (deliberately assembled from shipped standards, nothing invented but the record
schema — design verified against TRUCE arXiv:2403.00393, RFC 9901, RFC 6962/9162, RFC 3797):
  - **Leaf** = RFC 6962 leaf hash (0x00 domain separation, via :mod:`proofbundle.merkle`) over
    the US-ASCII bytes of a base64url-encoded **disclosure** — RFC 9901's digest mechanic, so
    the verify path never canonicalizes JSON. A disclosure decodes to ``[salt_b64, record]``;
    the record MUST embed its own ``idx`` (replay guard: an opening cannot be presented at a
    different position) and records are committed in canonical order sorted by (id, epoch).
  - **Salts** are per-leaf and fresh (RFC 9901: one shared salt is burned by the first opening —
    eval verdicts have tiny answer spaces and fall to dictionary attack). They derive from ONE
    holder-kept 32-byte ``tree_secret`` via HMAC-SHA-256 as a PRF (RFC 2104/FIPS 198):
    ``salt_i = HMAC(tree_secret, "proofbundle/v2/leaf-salt" ‖ id ‖ 0x00 ‖ epoch)[:16]``.
    Disclosing one salt reveals nothing about siblings; full escrow = disclosing the secret.
    The secret NEVER appears in the receipt.
  - **Challenge** = ``SHA-256("proofbundle/v2/audit-challenge" ‖ root ‖ u64(n) ‖ u64(k) ‖
    nonce)``, expanded via HMAC-SHA-256 counter mode into u64 draws, mapped to [0, n) by
    **rejection sampling** (no modulo bias), duplicates skipped until k distinct indices.
    Modes: (a) *auditor nonce* (default for real audits) — fresh ≥128-bit nonce supplied AFTER
    the receipt is signed, grinding impossible; (b) *beacon* — a public-randomness pulse
    (drand/NIST) from after the signed timestamp, RFC 3797-style, publicly re-verifiable;
    (c) *self-challenge* (empty nonce) — sanity check ONLY: a producer unhappy with the
    deterministic indices can re-salt and re-root (grinding), escaping with ≈ g·(1−m/n)^k over
    g attempts. Stated here and in THREAT_MODEL, never papered over.

Contamination economics (stated honestly): every opened sample is burned for future evals.
Openings are auditor-directed and never enter the public receipt; k ≪ n keeps leakage bounded;
benchmark owners may include canary/watermarked items so leakage of opened samples into
training data is later detectable (DyePack arXiv:2505.23001).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import List, Optional, Sequence

from . import merkle
from ._strict_json import loads_strict
from .canonical import _ganzzahl_von, _plain_for_jcs
from .errors import BundleFormatError, ProofBundleError
from ._wire_b64 import decode_b64, decode_b64url

__all__ = ["LEAF_ALG", "derive_leaf_salt", "make_disclosure", "build_sample_tree",
           "sample_opening", "verify_sample_opening", "audit_challenge"]

LEAF_ALG = "sha256-rfc6962-sdjwt-v1"     # named in the claim so verifiers know the leaf mechanic
_SALT_DOMAIN = b"proofbundle/v2/leaf-salt"
_CHALLENGE_DOMAIN = b"proofbundle/v2/audit-challenge"
_SALT_BYTES = 16                          # 128 bit, RFC 9901 recommendation


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    # adversarial re-audit round 7: cap the raw segment length BEFORE decoding — base64-decoding an oversized
    # segment allocates before loads_strict's input_bytes cap (which runs on the DECODED value) can fire, a
    # memory-amplification DoS. Mirrors anchors_markovian's _MAX_PROOF_BYTES.
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    from .errors import BundleFormatError  # noqa: PLC0415
    if len(s) > DEFAULT_BUDGET.input_bytes:
        raise BundleFormatError("base64 segment exceeds the input_bytes budget (pre-decode DoS guard)")
    raw = s.encode("ascii")
    return decode_b64url(raw)


def derive_leaf_salt(tree_secret: bytes, sample_id, epoch: int = 1) -> bytes:
    """Per-leaf salt = HMAC-SHA-256(tree_secret, domain ‖ id ‖ 0x00 ‖ epoch)[:16].

    HMAC as a PRF: revealing one derived salt reveals nothing about any other. The 0x00
    separator prevents id/epoch ambiguity (id "1" epoch 12 vs id "11" epoch 2)."""
    # Read once (lens run 8, the sweep of finding B): the secret's length was checked through the
    # caller's `__len__` and keyed through its buffer, the epoch compared through `__lt__` and hashed
    # through `__str__`. The stored bytes and an exact `int` are checked and used.
    from ._plain_value import plain_int  # noqa: PLC0415
    if not issubclass(type(tree_secret), bytes):
        raise BundleFormatError("tree_secret must be at least 16 random bytes (32 recommended)")
    tree_secret = bytes.__getitem__(tree_secret, slice(None))
    if len(tree_secret) < 16:
        raise BundleFormatError("tree_secret must be at least 16 random bytes (32 recommended)")
    if plain_int(epoch) is None or epoch < 0:
        raise BundleFormatError("epoch must be a non-negative integer")
    msg = _SALT_DOMAIN + str(sample_id).encode("utf-8") + b"\x00" + str(epoch).encode("ascii")
    return hmac.new(tree_secret, msg, hashlib.sha256).digest()[:_SALT_BYTES]


def make_disclosure(record: dict, salt: bytes) -> str:
    """Encode one sample record as a disclosure: base64url(JSON [salt_b64, record]).

    The LEAF commits to the encoded ASCII string (RFC 9901 mechanic) — verification re-hashes
    the transported string and never needs JSON canonicalization. ``record`` must carry ``idx``
    (its committed position) — enforced here so no leaf can ever lack the replay guard.

    The record and the salt are read once (lens run 8, the sweep of finding B): the index was checked
    through the caller's `get` and the record written through its stored items, the salt's length
    through `__len__` and its bytes through the buffer. The plain copies are checked and written."""
    from ._plain_value import plain_int, plain_json  # noqa: PLC0415
    from .signature import plain_bytes  # noqa: PLC0415
    if not isinstance(record, dict):
        raise BundleFormatError("sample record must be a JSON object")
    record = plain_json(record, what="sample record", error=BundleFormatError)
    idx = plain_int(record.get("idx"))
    if idx is None or idx < 0:
        raise BundleFormatError("sample record must embed its committed index as 'idx' (int >= 0)")
    salt_bytes = plain_bytes(salt)
    if salt_bytes is None or len(salt_bytes) < _SALT_BYTES:
        raise BundleFormatError("per-leaf salt must be at least 16 bytes")
    salt = salt_bytes
    disclosure_json = json.dumps([_b64url(salt), record], sort_keys=True,
                                 separators=(",", ":"))
    return _b64url(disclosure_json.encode("utf-8"))


def _leaf_hash_of(disclosure_b64: str) -> bytes:
    """RFC 6962 leaf hash (0x00 domain separation) over the encoded disclosure's ASCII bytes."""
    return merkle.leaf_hash(disclosure_b64.encode("ascii"))


def build_sample_tree(records: Sequence[dict], tree_secret: bytes) -> dict:
    """Commit a full eval run's samples. Returns ``{root, root_b64, n, leaf_alg, disclosures}``.

    ``records`` must already be in canonical order (sort by (id, epoch) before calling — the
    producer has NO ordering freedom; the committed ``idx`` is assigned here, 0-based, and
    embedded into each record). Salts derive per leaf from ``tree_secret``. The caller keeps
    ``disclosures`` (holder-side material for openings) and the secret; the receipt only ever
    carries root + n + leaf_alg.
    """
    # THE RECORDS ARE READ ONCE (lens run 8, the sweep of finding B): the emptiness check asked the
    # caller's `__len__` and the loop its `__iter__`; each record was copied with `dict(rec)`, whose
    # nested values and numbers were then checked through their own methods (`int(epoch)` is the
    # caller's `__int__`) while the disclosure wrote their storage. One list, one plain copy per record.
    from ._plain_value import plain_json, plain_list  # noqa: PLC0415
    stored = plain_list(records)
    records = stored if stored is not None else list(records)
    if not records:
        raise BundleFormatError("cannot commit an empty sample set")
    disclosures: List[str] = []
    leaves: List[bytes] = []
    prev_key = None
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            raise BundleFormatError(f"record {i} is not a JSON object")
        rec = dict(plain_json(rec, what=f"record {i}", error=BundleFormatError))
        if "idx" in rec and rec["idx"] != i:
            raise BundleFormatError(
                f"record {i} carries idx={rec['idx']!r} — indices are assigned by the tree "
                "builder from canonical order, never by the caller")
        rec["idx"] = i
        # Enforce the documented canonical (id, epoch) order (release-review #7/#10): the producer has NO ordering
        # freedom, so reject records that are not already sorted — otherwise the invariant is only a comment. Compare
        # id by its NATIVE value (re-review fix: stringifying broke numeric order — "10" < "9" false-rejected every
        # eval with ≥10 int ids, exactly what the shipped adapters emit via sort by native int id). A type-rank keeps
        # int/str ids mutually comparable (all ints before all strs) without crashing on mixed types; epoch MUST be a
        # real int (a float/bool is rejected, not silently truncated — matches derive_leaf_salt's guard).
        epoch = rec.get("epoch", 1)
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise BundleFormatError(f"record {i} has a non-integer epoch {epoch!r}")
        idv = rec.get("id", i)
        key = (0 if (isinstance(idv, int) and not isinstance(idv, bool)) else 1, idv, epoch)
        if prev_key is not None and key < prev_key:
            raise BundleFormatError(
                f"record {i} breaks canonical (id, epoch) order — sort records before commitment")
        prev_key = key
        salt = derive_leaf_salt(tree_secret, rec.get("id", i), int(rec.get("epoch", 1)))
        d = make_disclosure(rec, salt)
        disclosures.append(d)
        leaves.append(d.encode("ascii"))
    root = merkle.merkle_tree_hash(leaves)
    return {"root": root, "root_b64": base64.b64encode(root).decode("ascii"),
            "n": len(leaves), "leaf_alg": LEAF_ALG, "disclosures": disclosures}


def sample_opening(disclosures: Sequence[str], index: int) -> dict:
    """Produce the opening for one committed sample: disclosure + RFC 6962 inclusion proof.

    The disclosures and the index are read ONCE (lens run 8 at fddc00f4, the sweep of finding B): the
    count came from the caller's `__len__`, the leaves from its `__iter__` and each disclosure's
    `encode`, and the written disclosure from its `__getitem__`, so a sequence could have a proof made
    over one list and a different disclosure written beside it."""
    from ._plain_value import plain_int, plain_list  # noqa: PLC0415
    from .signature import plain_text  # noqa: PLC0415
    stored = plain_list(disclosures)
    texts = []
    for i, d in enumerate(stored if stored is not None else list(disclosures)):
        text = plain_text(d)
        if text is None:
            raise BundleFormatError(f"disclosure {i} must be a string, got {type(d).__name__}")
        texts.append(text)
    n = len(texts)
    idx = plain_int(index)
    if idx is None or not 0 <= idx < n:
        raise BundleFormatError(f"index must be an integer in [0, {n})")
    leaves = [d.encode("ascii") for d in texts]
    proof = merkle.inclusion_proof(leaves, idx)
    return {"index": idx, "n": n, "disclosure": texts[idx],
            "proof_b64": [base64.b64encode(p).decode("ascii") for p in proof]}


def verify_sample_opening(opening: dict, root_b64: str, n: int) -> dict:
    """Verify one opening against the receipt's committed samples root — offline, fail-closed.

    Checks: the disclosure's leaf hash is included at ``opening.index`` in the tree of size
    ``n`` under ``root_b64`` (recomputed, never trusted), the disclosure decodes to
    ``[salt, record]``, and the record's embedded ``idx`` equals the proven index (replay
    guard). Returns ``{ok, record, salt_b64, detail}`` — the record is only meaningful when
    ``ok`` is True; plaintext that does not re-derive the committed leaf is never returned.
    """
    result = {"ok": False, "record": None, "salt_b64": None, "detail": ""}
    if not isinstance(opening, dict):
        raise BundleFormatError("opening must be a JSON object")
    # Structural budget (deep gate wf_cfe249d0-ee8, finding L2-01, P1). A DIRECT-DICT surface: the caller
    # hands over a parsed ``opening``, so loads_strict's input_bytes cap never runs and every other bound
    # below is inert against sheer size. Concretely, the proof list is base64-decoded IN FULL further down
    # before any per-element cap fires — an ``proof_b64`` of a million long strings is decoded first and
    # bounded afterwards, which is the wrong order.
    #
    # _b64url_decode already guards the DISCLOSURE segment (round 7), and that is exactly why this looked
    # covered: one segment was bounded, the container around it was not. The bound therefore goes on the
    # whole ``opening`` and it goes FIRST.
    #
    # Raising matches this function's own convention: a malformed STRUCTURE raises BundleFormatError here
    # (see the two guards around this one), while a failed VERIFICATION returns ok=False with a detail.
    # Over-budget is a structural refusal, not a verification outcome.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids a cycle
    try:
        enforce_structural_budget(opening)
    except ProofBundleError as exc:
        raise BundleFormatError(f"opening exceeds the verification budget (fail-closed): {exc}") from exc
    # ONE READING (round 12): after the budget, the opening is read once into the plain copy of what it
    # stores, and the index, the disclosure and the proof below come from that copy; the committed size
    # counts only as an exact int (a subclass of int is refused below, the one rule for a number of PR
    # 293; round 12 read the integer it stores). At cd5d39f4 each field was read through the opening's own `get`,
    # the proof cap counted its own `len()` and the loop read its own `__iter__`.
    opening = _plain_for_jcs(opening, lambda text: BundleFormatError(f"opening: {text}"))
    if _ganzzahl_von(n) is not None:
        n = _ganzzahl_von(n)
    index = opening.get("index")
    disclosure = opening.get("disclosure")
    proof_list = opening.get("proof_b64")
    if isinstance(index, bool) or not isinstance(index, int) \
            or not isinstance(disclosure, str) or not isinstance(proof_list, list):
        raise BundleFormatError("opening needs integer 'index', string 'disclosure', list 'proof_b64'")
    if type(n) is not int or not 0 <= index < n:   # `type()`: the size read above, or refused (round 12)
        result["detail"] = "index out of range for the committed tree size"
        return result
    # DIE GROESSE DER ZAHL, nicht nur ihr Typ (L2-BDOS-HUGEINT, Pre-Tag-Deep-Gate 2026-08-25).
    #
    # Die strukturelle Schranke oben sieht einen Skalar, und ein Skalar ist klein: `n = 2**1000000`
    # sind sieben Zeichen Quelltext. Die Bereichspruefung eine Zeile hoeher besteht er ebenfalls.
    # Erst der O(bit_length)-Schiebe-Loop in `verify_inclusion` bezahlt dafuer — gemessen 3,3 s bei
    # 2**300000, hochgerechnet rund 34 s bei 2**1000000, gegen 0,015 s auf dem Bundle-Pfad.
    #
    # Dieselbe Schranke wie `bundle._require_int` und dieselbe Quelle: `verify_inclusion` wuerde die
    # Zahl inzwischen selbst abweisen, aber diese Funktion soll ihr eigenes Urteil sprechen und nicht
    # von der Reihenfolge ihrer Aufrufe abhaengen.
    from .budget import int_magnitude_ok  # noqa: PLC0415 - lokaler Import wie die Nachbarn
    if not (int_magnitude_ok(n) and int_magnitude_ok(index)):
        result["detail"] = "committed tree size or index is implausibly large (fail-closed)"
        return result
    # DIE KAPPE VOR DER ARBEIT, DIE SIE BEGRENZT — Hausstandard des Budget-Moduls, Owner-Entscheid
    # 2026-08-18 zu PB-GLEICHE-KLASSE-BLEIBT-UMGEKEHRT-ENTSCHIEDEN-01 ("vereinheitlichen auf
    # Kappe-vor-Arbeit wie 2c52596").
    #
    # `merkle_path` (256) wird durchgesetzt, aber in `merkle.verify_inclusion` — also NACH der Zeile
    # darunter, die die GANZE proof-Liste dekodiert. Fuer einen Beweis, der die Kappe reisst und
    # darum niemals gueltig sein kann, wurde erst die volle Arbeit geleistet und danach abgelehnt.
    # Die strukturelle Schranke oben schliesst nur den UNBEGRENZTEN Fall; dazwischen blieb ein
    # Fenster bis 200000 Eintraege. Zwei Schranken, zwei verschiedene Groessen.
    #
    # DIE AUSNAHME DES OWNERS GREIFT HIER NICHT: die Kappe zaehlt Elemente, `len(proof_list)` ist
    # ohne das Dekodieren berechenbar und exakt gleich `len(proof)`.
    #
    # BEWUSSTE FOLGE, die diesen Commit beim ersten Mal (2c52596) zurueckgenommen hat: eine Eingabe,
    # die GLEICHZEITIG ueber der Kappe liegt UND kaputtes base64 traegt, bekam vorher einen
    # Format-Fehler (CLI-Exit 2) und bekommt jetzt ein Verdikt (Exit 1). Das Verdikt selbst aendert
    # sich nicht — ungueltig bleibt ungueltig —, nur die Fehlerklasse. Der Owner hat das entschieden.
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids an import cycle
    if len(proof_list) > DEFAULT_BUDGET.merkle_path:
        result["detail"] = (f"audit path has {len(proof_list)} steps (> merkle_path="
                            f"{DEFAULT_BUDGET.merkle_path}) — refused before decoding")
        return result
    try:
        proof = [decode_b64(p) for p in proof_list]
        root = decode_b64(root_b64)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError("opening proof/root is not valid base64") from exc

    try:
        disclosure_bytes = disclosure.encode("ascii")
    except UnicodeEncodeError:
        # 6-lens gate L3-01: a non-ASCII / surrogate disclosure passed the isinstance(str) structural guard but
        # can never re-derive the ASCII-committed leaf, so the correct fail-closed answer on this public
        # never-raise surface is ok=False, not a raw UnicodeEncodeError traceback to a relying party.
        result["detail"] = "disclosure is not ASCII, cannot bind to the samples root"
        return result
    if not merkle.verify_inclusion(disclosure_bytes, index, n, proof, root):
        result["detail"] = "inclusion proof does not bind this disclosure to the samples root"
        return result

    try:
        # WP-C1 (six-lens review): the committed record is attacker-supplied verify-path input —
        # a duplicated key ({"idx":0,...,"verdict":"PASS","verdict":"FAIL"}) parsed last-wins while
        # the LEAF committed the raw string; strict parse keeps one parse = one truth.
        parsed = loads_strict(_b64url_decode(disclosure))
    except ProofBundleError as exc:  # incl. BudgetExceeded (RE-GATE never-raise) + BundleFormatError (dup key)
        result["detail"] = f"disclosure rejected: {exc}"
        return result
    except (ValueError, TypeError):
        result["detail"] = "disclosure is not valid base64url(JSON)"
        return result
    if not (isinstance(parsed, list) and len(parsed) == 2 and isinstance(parsed[0], str)
            and isinstance(parsed[1], dict)):
        result["detail"] = "disclosure must decode to [salt_b64, record]"
        return result
    salt_b64, record = parsed
    if record.get("idx") != index:
        result["detail"] = (f"replay guard: record idx {record.get('idx')!r} does not match the "
                            f"proven position {index}")
        return result

    result.update(ok=True, record=record, salt_b64=salt_b64,
                  detail=f"sample {index} of {n} opens against the committed root")
    return result


def audit_challenge(root, n: int, k: int, nonce: bytes = b"") -> List[int]:
    """Derive k distinct audit indices in [0, n) from the committed root — deterministic,
    re-verifiable by anyone with the same inputs.

    ``nonce`` modes (see module docstring): auditor-supplied (default for audits — arrives
    after signing, no grinding), a public beacon pulse, or empty (self-challenge sanity mode
    ONLY — grinding by re-salting is possible and documented). Index mapping uses rejection
    sampling over u64 draws — zero modulo bias by construction.
    """
    # Bug-hunt follow-up (3.6.2): audit_challenge is a typed-error helper — bad input must raise the typed
    # BundleFormatError, never a RAW binascii.Error / OverflowError / TypeError. root/n/nonce are all derived
    # from a receipt-controlled field (n mirrors verify_sample_opening's tree size), so a hostile receipt could
    # otherwise crash the auditor's process: a non-base64 root (binascii.Error), an n >= 2**64 that overflows
    # n.to_bytes(8) (OverflowError), or a non-bytes nonce (TypeError on the concatenation).
    # EACH VALUE IS READ ONCE (lens run 8 at fddc00f4, the sweep of findings A and D): the length and
    # range checks asked a subclass's `__len__` and comparisons, and the seed read its buffer and its
    # `to_bytes`, so the checked root, size and count were not the ones the challenge was derived from.
    from ._plain_value import plain_int  # noqa: PLC0415
    from .signature import plain_bytes, plain_text  # noqa: PLC0415
    root_text = plain_text(root)
    if root_text is not None:
        try:
            root = decode_b64(root_text)
        except (ValueError, TypeError) as exc:   # binascii.Error is a ValueError subclass
            raise BundleFormatError("root must be valid base64 (or the raw 32-byte samples root)") from exc
    elif issubclass(type(root), bytes):
        root = bytes.__getitem__(root, slice(None))
    if type(root) is not bytes or len(root) != 32:
        raise BundleFormatError("root must be the 32-byte samples root (or its base64)")
    n_int, k_int = plain_int(n), plain_int(k)
    if n_int is None or not 0 < n_int < (1 << 64):
        raise BundleFormatError("n must be a positive integer below 2**64 (a samples tree size)")
    if k_int is None or not 0 < k_int <= n_int:
        raise BundleFormatError("k must be an integer in [1, n]")
    nonce_bytes = plain_bytes(nonce)
    if nonce_bytes is None:
        raise BundleFormatError("nonce must be bytes")
    n, k = n_int, k_int
    seed = hashlib.sha256(_CHALLENGE_DOMAIN + root + n.to_bytes(8, "big")
                          + k.to_bytes(8, "big") + nonce_bytes).digest()
    chosen: List[int] = []
    seen = set()
    counter = 0
    while len(chosen) < k:
        block = hmac.new(seed, counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
        for off in range(0, 32, 8):
            idx = _map_draw(int.from_bytes(block[off:off + 8], "big"), n)
            if idx is None or idx in seen:
                continue
            seen.add(idx)
            chosen.append(idx)
            if len(chosen) == k:
                break
    return chosen


def _map_draw(v: int, n: int) -> Optional[int]:
    """Map one u64 draw to [0, n) by rejection sampling — or None if rejected.

    Accept iff ``v < ⌊2^64/n⌋·n`` (the largest multiple of n below 2^64), else redraw: zero
    modulo bias by construction (Romailler; same 'simple discard' method as FIPS 186-5).
    Isolated as a pure function because the rejection branch fires with probability
    (2^64 mod n)/2^64 (~1e-19 for small n) — it can only be TESTED in isolation, never
    observed through the full challenge path."""
    limit = (2**64 // n) * n
    if v >= limit:
        return None
    return v % n


def catch_probability(m_fraction: float, k: int) -> float:
    """PoR bound: probability that k challenges catch an m-fraction of bad samples,
    1 − (1 − m)^k — independent of n. (k=300 → ~0.95 at m=0.01; k=459 → ~0.99.)"""
    if not 0 <= m_fraction <= 1 or k < 0:
        raise BundleFormatError("m_fraction in [0,1], k >= 0")
    return 1.0 - (1.0 - m_fraction) ** k
