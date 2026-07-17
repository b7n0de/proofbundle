# Calendar independence of the OpenTimestamps anchor

Reviewer question this answers, stated before the audit asks it: OpenTimestamps' public calendars are
donation-financed (about USD 300 per month, operated by Peter Todd and by Eternity Wall). Does that
funding fragility weaken a proofbundle receipt? The four facts below are the honest, bounded answer.

## The four facts

1. **Verifying an upgraded proof is calendar-independent.** Once an OpenTimestamps proof is upgraded (it
   carries the Bitcoin block-header path), verifying it needs no calendar and no account, only a Bitcoin
   header for the attested height. `proofbundle anchor verify-pack` performs exactly this check offline,
   with no network of any kind.

2. **Calendar fragility affects only stamping availability, never the verifiability of existing proofs.**
   A calendar that is offline or defunded can refuse to stamp NEW roots; it cannot alter or revoke a
   proof already committed in Bitcoin, because Bitcoin proof-of-work protects the binding (a hostile
   calendar can withhold, it cannot forge). Default redundancy is broad: the client submits to three
   calendar endpoints across at least two independent operators and requires at least two to reply, so
   any single calendar can be down with no effect.

3. **Verification presupposes a Bitcoin header source, and we say so.** Confirming an upgraded proof
   needs the block's Merkle root for the attested height, supplied by the relying party from their own
   pruned Bitcoin node or a trusted checkpoint they ship (`--bitcoin-header` / policy
   `anchors.bitcoin_block_headers`). This is a documented, honest assumption, not a hidden one. The
   bundle's own frozen header is producer-controlled evidence and is never trusted, so a producer cannot
   self-certify a backdated header.

4. **RFC 3161 stands ready as an immediate, legally recognized second anchor.** An RFC 3161 timestamp
   from a qualified Time-Stamping Authority is centralized and trust-bearing, the opposite trade-off to
   OpenTimestamps; under eIDAS (Regulation 910/2014, Article 41) a qualified timestamp carries a legal
   presumption of time across the EU. It complements the trust-minimized Bitcoin anchor, it does not
   replace it (`docs/ANCHORS.md`, the `rfc3161-tsa` type).

## How redundancy is surfaced (embedded but unverified)

The redundancy figure this tool reports (`operatorRedundancy`) is derived from what the proof itself
carries (its retained pending attestations), but it is NOT a cryptographic guarantee: a
`PendingAttestation` URI is unauthenticated and can be constructed offline by a producer, so the figure is
an embedded-but-unverified transparency hint, not audit evidence. The cryptographic guarantees are only the
structural binding of the proof to the canonical root and the Bitcoin confirmation against a relying-party
header. After a proof is upgraded it retains no pending attestation, so it honestly shows
`operatorRedundancy: 0`: the calendar set that carried the stamp is no longer recoverable from the proof,
and we do not reconstruct it from testimony. Calendars a producer records via
`anchor upgrade --calendar-declared <url>` are stored as documentation with
`declaredCalendarsVerified: false` and are likewise not audit evidence. The operator label behind a calendar
URL is a bare-hostname heuristic, not a verified-independent-entity claim: it does not resolve the
public-suffix boundary, so two operators under one ccSLD (a `co.uk` or `com.au` host) can be undercounted
as one. For an independence claim, pin the operators you trust rather than relying on the label.

## What this does not claim

The remaining assumption is the Bitcoin header's trustworthiness: a relying party who runs their own
node removes it; one who accepts a shipped checkpoint relies on whoever curated it. OpenTimestamps
attests existence before a Bitcoin block time (median-time-past semantics), not second-accurate ordering.
None of this is a statement about the correctness of the timestamped content: a receipt attests
authorship, integrity and a point in time, never the truth of what was timestamped.

## Where to check this in code

- `proofbundle anchor upgrade` / `verify-pack` / `inspect` (CLI surface, `src/proofbundle/cli.py`)
- `src/proofbundle/evidence_pack.py` (self-contained pack build + offline verify, no socket)
- `src/proofbundle/anchors_ots.py` (`verify_opentimestamps`, `calendar_uris`, never-trust-own-frozen)
- `tests/test_ots_calendar_hardening.py` (outage, collusion/backdating, pending-never-pass, redundancy)
- the ripemd160-free confirmed-path fixture `tests/fixtures/ots/synthetic-upgraded-sha256.txt.ots`
