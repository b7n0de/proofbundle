"""rootcommit/v1 + rootcommit/v2-sig — a second, independent proofbundle verifier for
MarkovianProtocol's `tlog-bitcoin-anchor` `rootcommit` format.

Where `anchors_ots.py` reproduces the base `ots/v1` fixture (timestamp over the checkpoint NOTE BODY),
this module reproduces the stronger `rootcommit` fixture (Bitcoin timestamp over a DOMAIN-SEPARATED
PREIMAGE that folds the checkpoint's Merkle root together with an operator wallet address):

    preimage = tag "\\n" "origin=" origin "\\n" "size=" size "\\n" "root=" root "\\n" "wallet=" wallet "\\n"
    commitment = SHA-256(preimage_bytes)          # the OpenTimestamps proof commits `commitment`

It is a SECOND implementation of Colin's spec (rootcommit/SPEC.md, rootcommit/SPEC_SIG.md): it rebuilds
the preimage from the checkpoint's own (origin, size, root) plus the wallet carried in the anchor line's
opaque, recomputes `commitment` itself, and reuses proofbundle's own OpenTimestamps binding verifier to
check the proof commits exactly that commitment. With the OTS proof HELD FIXED (the conformance-vector
case) mutating the root OR the wallet breaks the binding — the wallet-tamper rejection is the property the
base `ots/v1` layer does not have. (An attacker who controls the WHOLE opaque can of course substitute a
matching forged proof for their own (root, wallet); see the consumer contract below on why binding alone is
not an anchoring claim.)

CONSUMER CONTRACT (Berkeley-hardened) — the top-level `reject` boolean encodes the BINDING outcome ONLY.
A relying party MUST NOT read `reject is False` as "Bitcoin-anchored" or "signature-valid":
  - temporal: `reject is False` includes status "pending" (an offline-forgeable PendingAttestation), so a
    genuine Bitcoin anchor needs `ots_ok is True` / status "confirmed" (which requires a relying-party block
    header, WP-A1). Binding is not anchoring.
  - signature (v2-sig): without the optional [rootcommit] backend `sig_ok` is None and the signature is NOT
    enforced (v2-sig degrades to v1 binding), so signature assurance requires `sig_ok is True`, never merely
    `reject is False`.
  - multiplicity: more than one rootcommit anchor on one checkpoint is rejected (status "multiple_anchors")
    and `known_anchors` is the REAL count, so a prepended forged anchor cannot silently mis-attribute a wallet.

Dependency split (honest): the v1 verifier and the v2-sig BINDING check need only stdlib SHA-256 plus the
already-optional `opentimestamps` (proofbundle[anchors]). Only the v2-sig SIGNATURE check (EIP-191
`personal_sign` recovery to the bound address, secp256k1 + keccak-256) needs an extra crypto library; it is
imported lazily and, if absent, reported as status `no_sig_lib` (never a silent pass, never a hard import
error at module load).
"""
from __future__ import annotations

import hashlib
from typing import Optional

# --- spec constants (rootcommit/SPEC.md §"Anchor line", SPEC_SIG.md §"Anchor line opaque") ---
KEY_NAME = "markovianprotocol.com/bitcoin-anchor"
SIG_TYPE = 0xFF                                    # rides as an unassigned c2sp signed-note signature type
ID_V1 = "markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
ID_V2SIG = "markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"
TAG_V1 = ID_V1                                      # preimage line 1 == the v1 id
V2SIG_MESSAGE_TAG = ID_V2SIG                        # EIP-191 message tag (SPEC_SIG §"The signature")
_ANCHOR_PREFIX = f"— {KEY_NAME} "              # "— <keyname> " (U+2014 EM DASH), one anchor per line


def expected_key_id(identifier: bytes) -> bytes:
    """Spec key ID = SHA-256(<key name> || 0x0A || 0xff || <identifier>)[:4]."""
    return hashlib.sha256(KEY_NAME.encode() + b"\x0a" + bytes([SIG_TYPE]) + identifier).digest()[:4]


def parse_checkpoint_head(text: str) -> Optional[tuple[str, str, str]]:
    """(origin, size, root) as the verbatim first three lines of the checkpoint note body, or None. The
    body is everything before the blank-line separator; `root` is the 3rd line copied byte-for-byte (no
    base64 round-trip, per SPEC §"Preimage"). never-raise (Berkeley class RT-04): non-str untrusted input
    returns None (-> the verify surfaces report a stable malformed_checkpoint verdict), never a raw exception."""
    if not isinstance(text, str):
        return None
    parts = text.split("\n\n", 1)
    lines = parts[0].splitlines()
    if len(lines) < 3:
        return None
    return lines[0], lines[1], lines[2]


def build_preimage(origin: str, size: str, root: str, wallet: str, *, tag: str = TAG_V1) -> bytes:
    """The frozen 5-line preimage (SPEC §"Preimage — frozen byte layout"), LF-terminated, trailing \\n."""
    return (f"{tag}\norigin={origin}\nsize={size}\nroot={root}\nwallet={wallet}\n").encode("utf-8")


def _iter_our_anchor_opaques(text: str, want_id: str):
    """Yield the `opaque` bytes of every well-formed anchor line under our key name whose decoded
    (keyID, sig-type, identifier) match `want_id`. Data extraction + identity only (no crypto here);
    unknown ids / grease lines are skipped (forward-compat: unknown signatures MUST be ignored)."""
    import base64  # noqa: PLC0415
    parts = text.split("\n\n", 1)
    if len(parts) < 2:
        return
    want = want_id.encode()
    for line in parts[1].splitlines():
        if not line.startswith(_ANCHOR_PREFIX):
            continue
        try:
            payload = base64.b64decode(line.split(" ", 2)[2])
            kid, stype, idlen = payload[:4], payload[4], payload[5]
            ident, opaque = payload[6:6 + idlen], payload[6 + idlen:]
        except Exception:
            continue
        if stype == SIG_TYPE and ident == want and kid == expected_key_id(ident):
            yield opaque


def _parse_opaque_v1(opaque: bytes) -> Optional[tuple[str, bytes]]:
    """v1 opaque = 0x01 || wlen(1) || wallet_ascii[wlen] || ots_proof_bytes → (wallet, ots) or None."""
    if len(opaque) < 2 or opaque[0] != 0x01:
        return None
    wlen = opaque[1]
    if len(opaque) < 2 + wlen:
        return None
    return opaque[2:2 + wlen].decode("ascii", "replace"), opaque[2 + wlen:]


def _parse_opaque_v2sig(opaque: bytes) -> Optional[tuple[str, bytes, bytes]]:
    """v2-sig opaque = 0x02 || wlen(1) || wallet_ascii || 0x41 || sig(65) || ots → (wallet, sig, ots)."""
    if len(opaque) < 2 or opaque[0] != 0x02:
        return None
    wlen = opaque[1]
    off = 2 + wlen
    if len(opaque) < off + 1 + 65 or opaque[off] != 0x41:   # 0x41 == 65, the fixed sig length marker
        return None
    wallet = opaque[2:off].decode("ascii", "replace")
    sig = opaque[off + 1:off + 1 + 65]
    ots = opaque[off + 1 + 65:]
    return wallet, sig, ots


def _binding_status(ots: bytes, commitment: bytes, *, frozen: dict, rp_trust: Optional[dict]) -> dict:
    """Reuse proofbundle's own OTS binding verifier: the proof must commit EXACTLY `commitment`.
    unbound/malformed → the preimage (root or wallet) does not match the timestamp → reject."""
    from proofbundle.anchors_ots import verify_opentimestamps  # noqa: PLC0415
    return verify_opentimestamps(ots, commitment, frozen=frozen, rp_trust=rp_trust)


def verify_rootcommit_v1(checkpoint_text: str, *, frozen: Optional[dict] = None,
                         rp_trust: Optional[dict] = None) -> dict:
    """Second-implementation verify of a rootcommit/v1 anchor on a checkpoint. Returns
    {known_anchors, binding, reject, status, detail, commitment}. binding is True iff proofbundle's own
    OTS verifier confirms the proof commits our independently rebuilt SHA-256(preimage); any tamper of
    root or wallet makes commitment differ → status 'unbound' → reject. Offline (no relying-party Bitcoin
    header) a genuine proof is honestly not-a-pass on temporal confirmation but the BINDING still holds."""
    frozen = frozen or {}
    head = parse_checkpoint_head(checkpoint_text)
    if head is None:
        return {"known_anchors": 0, "binding": False, "reject": True, "status": "malformed_checkpoint",
                "detail": "checkpoint note body has fewer than 3 lines"}
    origin, size, root = head
    opaques = list(_iter_our_anchor_opaques(checkpoint_text, ID_V1))
    known = len(opaques)                               # the REAL count, never a hardcoded literal
    if known == 0:
        return {"known_anchors": 0, "binding": False, "reject": False, "status": "no_known_anchor",
                "detail": "no rootcommit/v1 anchor of our identifier present (forward-compat ignore)"}
    if known > 1:
        # The anchor rides as a 0xff unknown c2sp signed-note signature that stock tooling ignores and that
        # does NOT sign the note body (SPEC.md), so an attacker can PREPEND a second rootcommit anchor with a
        # different wallet without invalidating the genuine witness cosignatures. Attributing to any single
        # wallet would be an order-dependent spoof -> fail closed on ambiguous multiplicity (never pick [0]).
        return {"known_anchors": known, "binding": False, "reject": True, "status": "multiple_anchors",
                "detail": f"{known} rootcommit/v1 anchors present; ambiguous wallet attribution, rejected"}
    parsed = _parse_opaque_v1(opaques[0])
    if parsed is None:
        return {"known_anchors": known, "binding": False, "reject": True, "status": "bad_opaque",
                "detail": "rootcommit/v1 opaque is not 0x01 || wlen || wallet || ots"}
    wallet, ots = parsed
    commitment = hashlib.sha256(build_preimage(origin, size, root, wallet)).digest()
    b = _binding_status(ots, commitment, frozen=frozen, rp_trust=rp_trust)
    bound = b["status"] not in ("unbound", "malformed", "no_lib")
    return {"known_anchors": known, "binding": bound, "reject": not bound,
            "status": b["status"], "detail": b.get("detail", ""),
            "commitment": commitment.hex(), "wallet": wallet, "ots_ok": b.get("ok", False)}


def _keccak256(data: bytes) -> bytes:
    """keccak-256 (Ethereum's pre-standard padding, NOT SHA3-256). Lazily import a backend; raises
    _NoSigLib if none is available so v2-sig signature verification degrades honestly to 'no_sig_lib'.
    pycryptodome ships under the `Crypto` namespace, pycryptodomex under `Cryptodome` (already present
    transitively via opentimestamps); both expose the identical keccak API."""
    try:
        from eth_hash.auto import keccak  # noqa: PLC0415
        return keccak(data)
    except Exception:
        pass
    for modname in ("Cryptodome.Hash.keccak", "Crypto.Hash.keccak"):
        try:
            mod = __import__(modname, fromlist=["new"])
            h = mod.new(digest_bits=256)
            h.update(data)
            return h.digest()
        except Exception:
            continue
    raise _NoSigLib("no keccak-256 backend (need eth-hash or pycryptodome[x])")


class _NoSigLib(RuntimeError):
    pass


def eip191_recover_address(message: str, sig65: bytes) -> Optional[str]:
    """EIP-191 personal_sign recovery → EIP-55 address, or None on malformed input. Raises _NoSigLib if
    no secp256k1 recovery backend is installed (caller maps that to status 'no_sig_lib'). The message is
    the frozen v2-sig message (tag + '\\n' + commitment_hex); recovery == the bound wallet is the proof."""
    if len(sig65) != 65:
        return None
    body = message.encode("utf-8")
    digest = _keccak256(b"\x19Ethereum Signed Message:\n" + str(len(body)).encode() + body)
    # Accepted `v` encodings are EIP-191 personal_sign only: 27/28 (canonical) or raw 0/1 (some libs). An
    # EIP-155 chain-encoded v (chainId*2+35+recid) or the ~2^-127 canonical recid 2/3 falls through to reject
    # (sig_mismatch), which is fail-closed (never a false-accept); personal_sign never emits those, so this
    # is correct for rootcommit/v2-sig. Pinned explicitly for any future reuse of this helper.
    v = sig65[64]
    rec_id = v - 27 if v in (27, 28) else v
    if rec_id not in (0, 1):
        return None
    try:
        from ecdsa import SECP256k1, VerifyingKey  # noqa: PLC0415
        from ecdsa.util import sigdecode_string  # noqa: PLC0415
    except ImportError as exc:
        raise _NoSigLib("no secp256k1 recovery backend (need ecdsa)") from exc
    try:
        # recover both candidate public keys from (r||s) over the keccak digest; pick by the recovery id.
        candidates = VerifyingKey.from_public_key_recovery_with_digest(
            sig65[:64], digest, curve=SECP256k1, sigdecode=sigdecode_string, allow_truncate=True)
        if rec_id >= len(candidates):
            return None
        pub64 = candidates[rec_id].to_string()          # uncompressed x||y (64 bytes), no 0x04 prefix
        # lowercase 0x-address; the caller compares case-insensitively, so no EIP-55 checksum is needed
        return "0x" + _keccak256(pub64)[-20:].hex()
    except Exception:
        return None


def verify_rootcommit_v2sig(checkpoint_text: str, *, frozen: Optional[dict] = None,
                            rp_trust: Optional[dict] = None) -> dict:
    """Second-implementation verify of a rootcommit/v2-sig anchor. Adds the wallet EIP-191 signature over
    `commitment` on top of the v1 binding. Returns {known_anchors, binding, sig_ok, reject, status, ...}.
    binding is dep-free (OTS commit check); sig_ok needs a secp256k1+keccak backend and is None
    (status 'no_sig_lib') if none is installed — never a silent pass."""
    frozen = frozen or {}
    head = parse_checkpoint_head(checkpoint_text)
    if head is None:
        return {"known_anchors": 0, "binding": False, "sig_ok": None, "reject": True,
                "status": "malformed_checkpoint"}
    origin, size, root = head
    opaques = list(_iter_our_anchor_opaques(checkpoint_text, ID_V2SIG))
    known = len(opaques)                               # the REAL count, never a hardcoded literal
    if known == 0:
        return {"known_anchors": 0, "binding": False, "sig_ok": None, "reject": False,
                "status": "no_known_anchor"}
    if known > 1:
        # same multiplicity spoof as v1 (a prepended 0xff anchor does not invalidate the checkpoint) -> fail
        # closed rather than attribute to opaques[0].
        return {"known_anchors": known, "binding": False, "sig_ok": None, "reject": True,
                "status": "multiple_anchors",
                "detail": f"{known} rootcommit/v2-sig anchors present; ambiguous attribution, rejected"}
    parsed = _parse_opaque_v2sig(opaques[0])
    if parsed is None:
        return {"known_anchors": known, "binding": False, "sig_ok": None, "reject": True, "status": "bad_opaque"}
    wallet, sig, ots = parsed
    commitment = hashlib.sha256(build_preimage(origin, size, root, wallet, tag=TAG_V1)).digest()
    b = _binding_status(ots, commitment, frozen=frozen, rp_trust=rp_trust)
    bound = b["status"] not in ("unbound", "malformed", "no_lib")
    # signature: EIP-191 recover over (tag + '\n' + commitment_hex) must equal the bound wallet (dep-gated)
    sig_ok: Optional[bool] = None
    sig_status = "not_checked"
    try:
        message = f"{V2SIG_MESSAGE_TAG}\n{commitment.hex()}"
        recovered = eip191_recover_address(message, sig)
        sig_ok = recovered is not None and recovered.lower() == wallet.lower()
        sig_status = "sig_ok" if sig_ok else "sig_mismatch"
    except _NoSigLib:
        sig_status = "no_sig_lib"          # honest: cannot verify the signature without a backend
    reject = (not bound) or (sig_ok is False)
    return {"known_anchors": known, "binding": bound, "sig_ok": sig_ok, "reject": reject,
            "status": b["status"], "sig_status": sig_status, "commitment": commitment.hex(),
            "wallet": wallet, "ots_ok": b.get("ok", False)}
