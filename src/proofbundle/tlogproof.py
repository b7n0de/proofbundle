"""C2SP tlog-proof — a portable, offline-verifiable transparency-log proof file (v1.3).

A tlog-proof composes, in one line-oriented text file (extension ``.tlog-proof``): the entry's
index, an RFC 6962 Merkle inclusion proof, and — verbatim — a tlog-checkpoint signed by the log
and optionally cosigned by witnesses. Because it verifies against a fixed set of trust anchors
(log key, witness keys, a k-of-n policy) it behaves like a detached signature — C2SP calls these
*transparent signatures*. Spec verified 2026-07-02 against C2SP/C2SP tlog-proof.md (format string
``c2sp.org/tlog-proof@v1``; the spec file is on main, not yet version-tagged — pinned here).

Byte-exact rules (the ones that bite):
  - Line 1 MUST be exactly ``c2sp.org/tlog-proof@v1``.
  - Line 2 MAY be ``extra <base64>`` (STANDARD RFC 4648 §4 base64). Omitted when absent — never
    an empty ``extra``. The extra data is **unauthenticated**: it exists to carry data needed to
    reconstruct the leaf hash; a verifier MUST NOT trust it.
  - Next line: ``index <decimal>`` — zero-based entry index, ASCII decimal, no leading zeros
    (a lone ``0`` is allowed).
  - Then zero or more non-empty lines: the inclusion-proof hashes, one standard-base64 SHA-256
    hash (32 bytes) per line, ordered from the leaf's sibling upward (RFC 6962 §2.1.1).
  - Then ONE empty line, then the signed checkpoint **verbatim** (which itself contains its own
    empty-line separator and signature/cosignature lines) — so the proof-vs-checkpoint split is
    the FIRST empty line, never the last.

Verification (spec steps, all offline):
  1. compute the leaf hash — application-specific; for proofbundle the leaf is the exact payload
     bytes, hashed with RFC 6962 ``leaf_hash`` (0x00 prefix), same as ``verify_bundle``;
  2. the checkpoint origin is acceptable and the log signature verifies (tlog-checkpoint);
  3. cosignatures verify per witness policy (k-of-n over DISTINCT witness names; Ed25519
     cosignature/v1 and ML-DSA-44 both accepted via :mod:`proofbundle.checkpoint`);
  4. the inclusion proof binds the leaf hash at ``index`` to the checkpoint's root at its size.
  Cosignature timestamps are verified-then-ignored (spec: application policy may add constraints;
  an offline verifier has no trusted clock, so freshness stays the relying party's call).
"""

from __future__ import annotations

import base64
import hmac
from typing import Optional, Sequence

from . import merkle
from .checkpoint import verify_checkpoint, witness_quorum
from .errors import BundleFormatError, ProofBundleError

__all__ = ["MAGIC", "format_tlog_proof", "parse_tlog_proof", "tlog_proof_for_bundle",
           "verify_tlog_proof"]

MAGIC = "c2sp.org/tlog-proof@v1"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise BundleFormatError(f"{what} is not valid standard base64") from exc


def format_tlog_proof(index: int, inclusion_proof: Sequence[bytes], signed_checkpoint: str,
                      extra: Optional[bytes] = None) -> str:
    """Serialize a tlog-proof. ``signed_checkpoint`` is a complete signed note (log signature,
    optionally cosignatures) included verbatim; it must end with a newline."""
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise BundleFormatError("tlog-proof index must be a non-negative integer")
    if not signed_checkpoint.endswith("\n"):
        raise BundleFormatError("signed checkpoint must end with a newline")
    if "\n\n" not in signed_checkpoint:
        raise BundleFormatError("signed checkpoint is missing its note/signature separator")
    lines = [MAGIC]
    if extra is not None:
        lines.append(f"extra {_b64(extra)}")
    lines.append(f"index {index}")
    for h in inclusion_proof:
        if len(h) != 32:
            raise BundleFormatError("inclusion proof hashes must be 32-byte SHA-256 values")
        lines.append(_b64(h))
    return "\n".join(lines) + "\n\n" + signed_checkpoint


def parse_tlog_proof(text: str) -> dict:
    """Parse a tlog-proof into ``{extra, index, proof, checkpoint}``. Strict, fail-closed:
    unknown leading lines, bad base64, bad index formatting or a missing separator are
    ``BundleFormatError`` — never a crash, never a silent skip."""
    if not isinstance(text, str):
        # Berkeley re-gate round 7: honor the "never a crash" contract for a direct caller — a non-str (None
        # from a mis-wired caller) previously raised a raw TypeError from the `in` test below.
        raise BundleFormatError("tlog-proof text must be a string (non-str is malformed, fail-closed)")
    if "\n\n" not in text:
        raise BundleFormatError("tlog-proof has no empty-line separator before the checkpoint")
    head, checkpoint = text.split("\n\n", 1)
    lines = head.split("\n")
    if not lines or lines[0] != MAGIC:
        raise BundleFormatError(f"tlog-proof must start with {MAGIC!r}")
    pos = 1
    extra: Optional[bytes] = None
    if pos < len(lines) and lines[pos].startswith("extra "):
        extra = _b64d(lines[pos][len("extra "):], "extra data")
        pos += 1
    if pos >= len(lines) or not lines[pos].startswith("index "):
        raise BundleFormatError("tlog-proof is missing the index line")
    index_s = lines[pos][len("index "):]
    # isascii() before isdigit() (release-review #7): str.isdigit() is True for Unicode digits (e.g. '²' U+00B2,
    # Arabic-Indic), which int() would then reject or mis-parse — mirror checkpoint.py's ASCII-only guard.
    if not (index_s.isascii() and index_s.isdigit()) or (index_s != "0" and index_s.startswith("0")):
        raise BundleFormatError("tlog-proof index must be ASCII decimal with no leading zeros")
    # Bound the digit count BEFORE int() (6-lens review, CWE-674/CVE-2020-10735): Python caps int()<->str
    # at 4300 digits and raises a raw ValueError above it, which this pre-auth parser would surface as an
    # uncaught traceback. A real log index fits in far fewer than 20 digits (2**64 ~ 20 digits).
    if len(index_s) > 20:
        raise BundleFormatError("tlog-proof index is implausibly large (fail-closed)")
    pos += 1
    proof = []
    for line in lines[pos:]:
        if not line:
            raise BundleFormatError("unexpected empty line inside the inclusion proof")
        h = _b64d(line, "inclusion proof hash")
        if len(h) != 32:
            raise BundleFormatError("inclusion proof hashes must decode to 32 bytes")
        proof.append(h)
    if not checkpoint.endswith("\n") or "\n\n" not in checkpoint:
        raise BundleFormatError("embedded checkpoint is malformed")
    return {"extra": extra, "index": int(index_s), "proof": proof, "checkpoint": checkpoint}


def tlog_proof_for_bundle(bundle: dict, signed_checkpoint: str,
                          extra: Optional[bytes] = None) -> str:
    """Build a tlog-proof from a proofbundle's own ``merkle`` object plus a signed checkpoint
    over the SAME root/size. No-Fake guard: the checkpoint's tree size and root MUST match the
    bundle's merkle fields — a proof whose checkpoint disagrees with its bundle is refused at
    build time rather than left to fail at verify time."""
    mk = bundle.get("merkle")
    if not isinstance(mk, dict):
        raise BundleFormatError("bundle has no merkle object")
    note_text = signed_checkpoint.split("\n\n", 1)[0].split("\n")
    if len(note_text) < 3:
        raise BundleFormatError("signed checkpoint note must have at least 3 lines")
    if note_text[1] != str(mk.get("tree_size")):
        raise BundleFormatError("checkpoint tree size does not match the bundle's merkle.tree_size")
    if note_text[2] != mk.get("root_b64"):
        raise BundleFormatError("checkpoint root does not match the bundle's merkle.root_b64")
    proof = [_b64d(p, "merkle.inclusion_proof_b64[]") for p in mk.get("inclusion_proof_b64", [])]
    return format_tlog_proof(mk["leaf_index"], proof, signed_checkpoint, extra=extra)


def _tlog_failclosed(detail: str) -> dict:
    """RE-GATE never-raise: a fail-closed tlog-proof verdict (ok=False, every sub-verdict False) for
    malformed / type-confused untrusted input — the SAME dict shape as a full run, never a raw exception."""
    # 6-lens gate L3-01: "witnesses" must be a DICT to match the happy path (witness_quorum returns a name->
    # verdict dict). It was [] here, so a CLI/RP formatter doing res["witnesses"].items()/.values() on a fail-
    # closed verdict crashed with a raw AttributeError. Empty dict = same shape, still fail-closed (no witnesses).
    return {"ok": False, "log_ok": False, "witnesses_ok": False, "inclusion_ok": False,
            "origin": None, "tree_size": None, "root": None, "index": None, "witnesses": {},
            "detail": detail}


def verify_tlog_proof(text: str, leaf_data: bytes, log_vkey: str,
                      witness_vkeys: Sequence[str] = (), *, threshold: int = 0,
                      expected_origin: "str | None" = None) -> dict:
    """Verify a tlog-proof offline against explicit trust anchors.

    ``leaf_data`` is the exact logged entry (for proofbundle receipts: the payload bytes); its
    RFC 6962 leaf hash is recomputed here, never taken from the file. ``threshold`` witnesses
    (distinct names, from ``witness_vkeys``) must have valid cosignatures; ``threshold=0`` means
    no witness requirement (log signature only). Returns ``{ok, log_ok, witnesses_ok,
    inclusion_ok, origin, tree_size, root, index, witnesses}`` — every sub-verdict reported,
    ``ok`` is their conjunction (fail-closed).
    """
    # RE-GATE never-raise (breadth sweep): this dict-returning verify surface must return a fail-closed
    # verdict for malformed / type-confused untrusted input, never a raw exception — a non-str `text` crashed
    # parse_tlog_proof with a raw TypeError, and a bad threshold raised BundleFormatError. Both fail-closed.
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
        return _tlog_failclosed("witness threshold must be a non-negative integer")
    if not isinstance(text, str):
        return _tlog_failclosed("tlog-proof text must be a string (non-str is malformed, fail-closed)")
    try:
        parsed = parse_tlog_proof(text)
    except (ProofBundleError, ValueError, TypeError) as exc:
        # Berkeley re-gate round 3: catch the BASE ProofBundleError so any sibling (BudgetExceeded / an
        # UnsupportedError from a future parse step) maps to the same fail-closed verdict, never a raw escape.
        return _tlog_failclosed(f"malformed tlog-proof (fail-closed): {exc}")
    checkpoint = parsed["checkpoint"]

    # Bug-hunt follow-up (3.6.2): parse_tlog_proof only frames the checkpoint (endswith newline + an internal
    # blank line) — it does NOT validate the note interior. An attacker-supplied checkpoint with a non-base64
    # root / <3 lines / an over-long tree_size flows through to verify_checkpoint (and witness_quorum), which
    # raise BundleFormatError on a valid log_vkey — a RAW exception out of this documented never-raise surface
    # (crash/DoS for a direct API integrator). Wrap ALL remaining steps and catch the BASE ProofBundleError
    # (not just BundleFormatError, so no sibling escapes — repo lesson never_raise_fix_must_wrap_all_and_catch_base).
    try:
        log_res = verify_checkpoint(checkpoint, log_vkey)       # step 2: log signature
        # origin acceptance (release-review fix #5): the log signature alone does not bind the checkpoint ORIGIN
        # line; a relying party that knows which log it expects passes expected_origin to reject a validly-signed
        # checkpoint from a DIFFERENT origin than intended. Default None = origin not constrained (documented).
        log_ok = bool(log_res["ok"]) and (expected_origin is None or log_res["origin"] == expected_origin)
        # step 3 — witness quorum via the SHARED helper (dedup by KEY MATERIAL, not name): a single key under N
        # names must NOT satisfy threshold>1. Reuses checkpoint.witness_quorum so this reimplementation cannot
        # drift from verify_witnessed_checkpoint's hardening again (release-review CRITICAL fix).
        witnesses_ok, witnesses = witness_quorum(checkpoint, witness_vkeys, threshold)

        inclusion_ok = False                                     # steps 1 + 4
        if 0 <= parsed["index"] < log_res["tree_size"]:
            try:
                computed = merkle.root_from_inclusion(
                    parsed["index"], log_res["tree_size"], merkle.leaf_hash(leaf_data), parsed["proof"])
                inclusion_ok = hmac.compare_digest(computed, log_res["root"])
            except ValueError:
                inclusion_ok = False
    except (ProofBundleError, ValueError, TypeError, KeyError) as exc:
        return _tlog_failclosed(f"malformed embedded checkpoint (fail-closed): {exc}")

    return {"ok": log_ok and witnesses_ok and inclusion_ok,
            "log_ok": log_ok, "witnesses_ok": witnesses_ok, "inclusion_ok": inclusion_ok,
            "origin": log_res["origin"], "tree_size": log_res["tree_size"],
            "root": log_res["root"], "index": parsed["index"], "witnesses": witnesses}
