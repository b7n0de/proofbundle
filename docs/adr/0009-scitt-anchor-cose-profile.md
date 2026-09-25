# ADR 0009: The `scitt-ccf` anchor, a narrow COSE profile over measured bytes

- **Status:** proposed. Fixes the profile, the four values, the trust interface, the error states
  and the test classes for the 6.4.0 anchor type `scitt-ccf`. Builds nothing under `src/`; the
  implementation is a separate work package. Eight questions are left to the owner at the end.
- **Date:** 2026-09-25
- **Deciders:** proofbundle maintainer
- **Builds on:** ADR 0006 (anchor longevity, SCITT raised in rank), ADR 0007 (the algorithm label
  lives inside the signed bytes), the anchor layer in `src/proofbundle/anchors.py`
  (`register_anchor_type`, `rp_trust`, `allow_pending`, `trustedTime`), and the measurements in
  `tools/scitt_ccf_external/` (this ADR's evidence), `tools/scitt_ccf_datahash_vector/` and
  `tools/scitt_ccf_merkle_lesarten/`.

## Context, measured, not assumed

proofbundle verifies evidence offline. 6.4.0 adds an anchor type that verifies a SCITT
Transparent Statement carrying a receipt from a CCF based Transparency Service: a COSE_Sign1
statement whose payload is the digest of a proofbundle target, registered on a ledger, with the
ledger's signed inclusion proof in its unprotected header. Such an anchor says "these bytes were
registered on that service", from a party the producer does not control.

Four different digests meet in that object, and three of them are 32-byte SHA-256 values that look
alike in a log line. Mixing any two of them is the defect this ADR exists to prevent, so they get
names first and rules second.

What was measured before writing this, on 2026-09-25 (all in `tools/scitt_ccf_external/README.md`,
`recompute_result.json`, `reader_crosscheck.json`):

- Four real transparent statements with -05 receipts were recomputed offline: data-hash, leaf,
  Merkle root and the ES384 receipt signature over the recomputed root. Three were registered on a
  CCF based test service (issuer `mst-test-scitt-verifier.confidential-ledger.azure.com`, from
  https://github.com/microsoft/scitt-verifier, MIT); one on the production Microsoft Signing
  Transparency ledger (issuer `esrp-cts-db.confidential-ledger.azure.com`, from the test data of
  https://github.com/microsoft/scitt-ccf-ledger, MIT), and that one is an RFC 9995 hash envelope.
  All four verify with the trust material published beside them. The control's values equal the
  upstream project's own pinned values.
- The data-hash input rule was measured by holding eight candidate byte strings against the
  receipt's data-hash. One byte string matches in all four; described as spliced or as
  re-encoded it is the same bytes for these inputs (see Decision 3).
- No real statement found is a proofbundle anchor: the production hash envelope uses SHA-384 and
  its artifact is unpublished, the others are not hash envelopes. An end-to-end v1 control on real
  bytes is therefore NOT MEASURED (Q6).
- The leaf rule of draft -05 was held against the two literal readings of -04: only the -05 form
  verifies against a real receipt.
- cbor2 5.9.0 and 6.1.4 and pycose 1.1.0 were run against the same bytes; their version facts
  below are measured, and read at source where stated.

## Decision

### 1. Profile and version

`scitt-ccf` profile **v1** verifies:

- a Transparent Statement per RFC 9943 whose Signed Statement is an RFC 9995 COSE Hash Envelope,
  COSE_Sign1 per RFC 9052, with receipts per RFC 9942 under label 394;
- receipts of the verifiable data structure `CCF_LEDGER_SHA256` with the requested value **2**, per
  **draft-ietf-scitt-receipts-ccf-profile-05**, working group source at the tag of that name,
  commit `e729c2ec037ac763d0cf422bb58a219f8d6a02f4` (2026-09-23),
  https://github.com/ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile/blob/e729c2ec037ac763d0cf422bb58a219f8d6a02f4/draft-ietf-scitt-receipts-ccf-profile.md
  (22426 B, sha256 `7efdb7aa934ab0cfc1093e99932f7d2efd39bb66f5bf43594806d7b282ca0077`, retrieved
  2026-09-25);
- inclusion proofs only. Consistency proofs (vdp key -2, new in -05) are reported as present and
  not evaluated in v1.

The value 2 is a requested assignment (`TBD_1`), not yet made by IANA (-05, section "Description
of the Confidential Consortium Framework Ledger Verifiable Data Structure"). If IANA assigns a
different value, that is a new profile version, not a silent widening of v1.

The published RFC texts and the IETF archive copy of -05 were NOT MEASURED here: `www.ietf.org`,
`datatracker.ietf.org` and `www.rfc-editor.org` are blocked by the egress policy of the
environment this ADR was written in. The working group sources named in
`tools/scitt_ccf_external/README.md` were read instead. RFC sections are therefore cited by their
title in those sources; the one section number given (RFC 9943 section 6.3) is marked as not
re-read.

### 2. The four values, kept apart

| # | name | what it is | computed from | who defines the rule |
|---|---|---|---|---|
| 1 | hash envelope payload | the digest of the proofbundle target: the anchor's `canonicalRoot` | the target (receipt JCS root, `prereg_sha256`, statement content root) | RFC 9995: label 258 hash algorithm, 259 preimage content type, 260 location; label 3 forbidden |
| 2 | local ToBeSigned ID | an identifier for what the statement's signer signed | the RFC 9052 Sig_structure of the statement | proofbundle, a local rule, versioned (`tbs-id/v1`, see Q4) |
| 3 | CCF data-hash | the third component of the CCF leaf | the registered signed statement bytes | the Transparency Service; measured, Decision 3 |
| 4 | CCF Merkle root | the root the receipt signs | the inclusion proof: leaf and path | draft -05 |

Rules:

- Value 1 must equal the anchor's `canonicalRoot` byte for byte, and 258 must be `-16`
  (SHA-256), because every canonical root the anchor layer produces is SHA-256.
- **Value 2 never replaces value 3.** Value 2 identifies content, value 3 identifies registered
  bytes. Measured with a synthetic probe (key generated there): one ToBeSigned signed twice with
  ECDSA P-256 gives equal value 2 and different value 3, both signatures valid. A receipt for one
  of those statements is not a receipt for the other. Value 3 is always recomputed from the
  statement bytes; no cache, index or shortcut may stand in for it with value 2.
- Value 3 is never read from the receipt and trusted. It is recomputed from the statement and
  compared with the leaf's data-hash.
- Value 4 is never read from anywhere. It is computed from the proof and is the detached payload
  of the receipt signature. A receipt that carries an attached payload is outside the profile,
  even if that payload equals the computed root (-05, section "CCF Inclusion Proof Signature":
  MUST be detached).

### 3. The data-hash input rule, as measured

Measured on four registered statements, one of them from the production ledger
(`tools/scitt_ccf_external/README.md`, section "THE MEASURED DATA-HASH INPUT RULE"): value 3 is

    SHA-256( d2 84 || protected bstr as served || a0 || payload bstr as served || signature bstr as served )

- the unprotected header is **cleared** to the empty map `a0`;
- the tag 18 (`d2`) is **included**;
- the payload is **embedded** and taken as served;
- the outer array is definite (`84`).

Not matching, measured: the file as served, the same bytes untagged, with the payload replaced by
nil, the ToBeSigned bytes, the payload alone, the protected header alone.

This agrees with the service code read at source (scitt-ccf-ledger `app/src/main.cpp` at
`00101f769d872711356e080fbb089ac48589c60a`, CCF 7.0.17 `src/crypto/cose.cpp`, retrieved 2026-09-25)
and with the architecture text "the unprotected header of a Signed Statement MUST be set to an empty
map before the Signed Statement can be included in a Statement Sequence" (WG source of RFC 9943 at
`ba7d23d40557f0206735592036532414139d9a57`, section "Registration of Signed Statements"; the task
cites it as RFC 9943 section 6.3, NOT MEASURED against the published RFC).

Where the measurement stops, and what v1 does about it:

| input form | data-hash rule | v1 |
|---|---|---|
| tagged, definite, shortest-form heads, embedded payload | measured | accepted |
| untagged | CCF 7.0.17 refuses it at registration (source); NOT MEASURED on a service | outside profile |
| payload detached (nil) | NOT MEASURED | outside profile |
| indefinite lengths or non-shortest heads | NOT MEASURABLE without registering such a statement; spliced and re-encoded bytes would differ | refused by the pre-scan |
| other unprotected parameters besides 394 | the code empties the whole map; the measured statements carry only 394, so NOT MEASURED | accepted, with the whole map cleared |

Requiring shortest-form, definite encoding is what makes the spliced rule and the re-encoded rule
the same bytes, measured equal on all four statements. Widening v1 to any row marked NOT MEASURED
needs a registered statement of that form first (see Q6).

### 4. The leaf and the root

    leaf = SHA-256( internal-transaction-hash || SHA-256(UTF-8(internal-evidence)) || data-hash )
    for [left, h] in path:  node = SHA-256(h || node) if left else SHA-256(node || h)

per -05, section "Transaction Components" and "Inclusion Proof Verification Algorithm". Measured
against a real receipt: this form verifies; `SHA-256(CBOR(ccf-leaf))` (the -04 reading of section
2.1) and the raw concatenation without the inner hash do not. Sizes per the -05 CDDL:
`internal-transaction-hash` and `data-hash` exactly 32 bytes, `internal-evidence` a text string of
1 to 1024 bytes, every path element `[bool, bstr .size 32]`. When a receipt carries more than one
inclusion proof, every proof must compute the same root.

### 5. Trust interface: `rp_trust` only

Trust comes from the relying party through `rp_trust`, as for every anchor type since WP-A1
(`docs/ANCHORS.md`, "Trust model"). The shape proposed for 6.4.0:

- `rp_trust["scitt_ccf_services"]`: a mapping from the receipt issuer (the CWT `iss` claim, label 1
  inside label 15 of the receipt's **protected** header, compared as an exact string) to a
  COSE_KeySet, as served by the service's `/.well-known/scitt-keys` and pinned by the relying
  party. CLI and policy spellings follow the existing `--trusted-tsa-root` /
  `anchors.trusted_tsa_roots` pattern and are fixed in the implementation.
- `rp_trust["scitt_statement_keys"]`, optional: keys the relying party accepts for the statement
  signer (see Q3).

Never a trust source, each named because each is present in real evidence:

| material | where it is found | role in v1 |
|---|---|---|
| `kid` of the receipt | receipt protected header | selects candidate keys **within** the issuer's RP key set; RFC 9052, section "Common COSE Header Parameters" (WG source): kid values are hints and not unique, so every RP key with that kid is tried. Measured: `hex(SHA-256(SPKI))` equals the kid on every -05 receipt, test service and production; reported, not required |
| algorithm labels in a key set or trust store | RP material | never used; measured: the production trust store labels its P-384 keys `ES256` while the receipts they verify say ES384 |
| keys embedded in the statement or receipt | any header | ignored for trust |
| `x5chain` certificates | statement protected header (measured: a four-certificate chain in the control) | used only to report a consistency check of the statement signature, labelled as such; never trust |
| the anchor's `frozen` field | the bundle | evidence (`frozenEvidence`), never trust; a producer may freeze the key set it used, and it is reported next to the RP result |
| `anchoredAt` | the anchor entry | informative only |

A receipt whose issuer has no RP key set, or whose kid selects no RP key, is `needs_rp_trust`:
not verified, not failed, and never satisfying.

The authenticity of a key set against its live service is the relying party's work. For the
measured evidence it was NOT MEASURED (service host blocked); the pinned set is authenticated by
its GitHub commit only (`tools/scitt_ccf_external/README.md`, "TRUST MATERIAL").

### 6. Algorithm and key binding

- The algorithm is read from the protected header of the object it signs, never from the key set,
  the unprotected header or a default (ADR 0007, rule 2).
- v1 accepts ES256 (-7) with P-256 and ES384 (-35) with P-384 for receipts, measured ES384 on all
  real receipts; for statements additionally PS256 (-37) and PS384 (-38), measured on the control
  and on the production statement. An algorithm and
  key that do not belong together (ES384 label on a P-256 key, an EC label on an RSA key) is
  `signature_invalid`, not a fallback. Any other algorithm is `outside_profile`, never "invalid".
- ECDSA signatures are the raw `r || s` of the curve's length; any other length is invalid.
- PS256 and PS384 use MGF1 with the same hash and a salt length equal to the hash length.
- The algorithm label of a key set or trust store is never read. Measured on the production trust
  store: every entry says `"signatureAlgorithm": "ES256"`, every key is P-384, and the receipts
  those keys verify say ES384 in their protected header. A verifier that took the label would
  fail or, worse, pick a hash by it.
- external_aad is the empty byte string by profile. The adapter takes no external_aad argument,
  so an unknown AAD cannot silently become an empty one. Measured: one byte `00` as AAD makes the
  real receipt fail.

### 7. crit and header uniqueness

From the WG source of RFC 9052 (`cose-wg/cose-rfc8152bis`, commit
`3fa9e3c34a3419cd40586a389f2a5d55bc8f8f1e`, file `draft-ietf-cose-rfc8152bis-struct.xml`,
sha256 `7484e39b0a9a7c81e0e1723c7ac8139258616dc6b82ecf023c2a2bad4adc459c`, retrieved 2026-09-25).
Section "Header Parameters": labels in each map MUST be unique, and a repeated label MUST reject
the message as malformed; applications SHOULD verify that a label does not occur in both buckets.
Section "Common COSE Header Parameters": `crit` MUST be in the protected bucket, is a non-empty
array, and a listed label that is absent from the protected bucket is a fatal error.

v1 turns the SHOULD into a MUST: a label in both buckets is `malformed`. `crit` in the unprotected
bucket, an empty `crit`, a listed label absent from the protected bucket, or a listed label v1 does
not process is `outside_profile`. No real receipt measured carries `crit`.

### 8. Resource, tag and encoding limits

The measurement shows cbor2 alone cannot enforce these (Decision 13). So a narrow structural
pre-scan of our own runs before any decoding library sees the bytes, and it also yields the byte
spans value 3 is computed from:

| limit | v1 value | measured reference |
|---|---|---|
| proof bytes after base64 | 64 KiB | largest real statement 6145 B |
| nesting depth | 16 | real statements: well below |
| receipts per statement | 8 | real: 1 or 2 |
| inclusion proofs per receipt | 8 | real: 1 |
| path length | 64 | real: 4, 5, 8 |
| `internal-evidence` | 1..1024 bytes UTF-8 | -05 CDDL; real: 72, 76 and 77 bytes |
| lengths | definite only | real: all definite |
| heads | shortest form only | real: all shortest |
| tags | 18 at the top of the statement and at the top of each receipt; 1 only around an integer CWT time claim (4, 5, 6) in the statement's protected CWT map (Q8); nowhere else | real: 18 in all; tag 1 around `iat` in two statements, one of them the production statement |
| simple values | false, true, null; no floats | real: no floats |
| map keys | integer or text string, unique | real: yes |
| trailing bytes | none, in the statement, each receipt and each inclusion proof | real: none |

The values in the v1 column are proposals the implementation pins in one place; the measured
column is why they are not tighter or looser. The tag 1 allowance is the one place where a real
production statement forced the profile wider than a clean reading of RFC 8392 would (NumericDate
is the untagged form there); the claim stays informative and never becomes `trustedTime`.

### 9. Error states, a closed set

Each receipt gets exactly one of these, and the anchor entry reports `confirmed` if at least one
receipt is `confirmed`; otherwise the first state in this order across its receipts:

| status | meaning | `ok` | `warn` |
|---|---|---|---|
| `malformed` | the pre-scan or the COSE structure refused the bytes | False | False |
| `outside_profile` | readable, but not scitt-ccf v1 (untagged, detached statement payload, not a hash envelope, 258 not SHA-256, label 3 present, unprocessed crit, vds not 2, attached receipt payload, no inclusion proof, unsupported algorithm) | False | False |
| `unbound` | value 1 differs from `canonicalRoot` | False | False |
| `statement_signature_invalid` | an RP statement key was supplied and the statement signature fails with it | False | False |
| `root_mismatch` | inclusion proofs of one receipt compute different roots | False | False |
| `signature_invalid` | an RP key was selected and the receipt signature fails over value 4, including algorithm and key mismatch | False | False |
| `receipt_not_bound` | the receipt signature is valid, but the leaf's data-hash differs from value 3 recomputed from this statement | False | False |
| `needs_rp_trust` | no RP key set for the issuer, or no RP key for the kid | False | False |
| `confirmed` | profile satisfied, see Decision 10 | True | False |

`warn` is never set by `scitt-ccf`. A CCF receipt exists only after commit, so v1 has no pending
state. Per-entry fields follow the existing contract: `rp_trusted` when a signature was checked with
RP material, `needs_rp_trust`, `frozenEvidence`.

One receipt that fails next to one that is `confirmed` does not veto the entry; it is reported. The
unprotected header that carries receipts is covered by no signature, so anyone handling the file can
append one (the argument of the scitt-verifier corpus, `corpus/README.md` at the pinned commit). This
is the same separation `verify_anchors` already keeps between `require_met` and `status`. See Q5.

### 10. Result semantics: three separate results

| result | holds when | real example where it differs from the next |
|---|---|---|
| **readable** | the proof passes the pre-scan and parses as a tagged COSE_Sign1 with at least one receipt that parses under the -05 CDDL | `tampered-statement.cose`: readable, signature not valid. Not readable, real: `cts-hashv-cwtclaims-b64url.cose`, whose receipt is the legacy two-element form |
| **signature valid** | a receipt's ES256/ES384 signature verifies over its computed root with a key selected from the RP key set of its issuer | `payload-tampered.cose`: signature valid, profile not satisfied, because the receipt belongs to another statement |
| **profile satisfied** | signature valid, and for that receipt: vds 2, payload detached, all proofs one root, leaf data-hash equals value 3, the statement is a v1 hash envelope whose value 1 equals `canonicalRoot`, crit and header rules hold, and a supplied RP statement key verifies the statement | receipt side, real: the control and `uvm_0.2.10.cose` (production). Statement side: no real statement is a proofbundle anchor, so the end-to-end control is synthetic until Q6 is answered |

Only "profile satisfied" sets the anchor's `ok`. The three are reported side by side, never folded
into one boolean, because each alone has a real counterexample in the measured evidence. Carrying
them through `verify_anchor` needs an additive field there; that is implementation work under
`src/`, not part of this ADR.

### 11. Missing input or missing trust never satisfies

- `allow_pending` counts entries with `ok` or `warn` (`verify_anchors`). `scitt-ccf` never sets
  `warn`, so a missing receipt, a detached payload, missing trust or an unknown issuer cannot
  satisfy `--require-anchor`, with or without `--allow-pending`. A regression case pins this, next
  to its control, when the type is built.
- A statement without receipts is `malformed`: a Signed Statement is not a Transparent Statement.
- An empty RP key set is missing trust, not trust in nothing.

### 12. No trusted time from `anchoredAt`, and none from the receipt in v1

`anchoredAt` stays informative, as for every anchor type. v1 sets no `trustedTime` at all. The
receipt's protected CWT `iat` is signed by the service key and is reported as `receiptIat`,
informative, with its source named. What clock stands behind it is NOT MEASURED. Whether a later
profile may lift it into `trustedTime` is Q2.

### 13. CBOR and COSE libraries: the chosen direction, confirmed and corrected

The chosen direction was cbor2 in the optional extra with duplicate keys rejected and limits set, a
narrow COSE_Sign1 profile adapter of our own, signatures via `cryptography`, pycose only as a
comparison in tests. Core dependencies stay `cryptography` and `rfc8785`.

Confirmed:

- Signatures with `cryptography` verify every real statement and receipt measured (50.0.1).
- A narrow adapter of our own is needed; no measured library gives the byte spans and the checks
  above.
- cbor2 can reject duplicate keys and indefinite lengths, from 6.1.0 and 6.0.0 on respectively
  (changelog read at source, see below; measured on 6.1.4).

Corrected by measurement (`reader_crosscheck.json`, 2026-09-25, CPython 3.11.15):

- cbor2 decodes the tag 1 of the production statement to a `datetime` (both versions), while the
  pre-scan sees an integer under tag 1. A differential between the two readers must map exactly
  that one position and nothing else; one more argument in Q1.
- "Limits set" is not enough. cbor2 5.9.0 and 6.1.4 both interpret tags 1, 2, 28/29, 256/25 and
  55799 by default (datetime, bignum, shared and string references resolved, 55799 dropped).
  `tag_hook` is not called for tag 2 (measured on both versions). Refusing such a tag needs a
  `semantic_decoders` entry for it (6.x only, measured for tag 2), which makes a denylist over a
  list that belongs to the library. Hence the own pre-scan with an allowlist (Decision 8).
- `cbor2.loads` ignores trailing bytes in both versions; the position after the first item must be
  checked, or the pre-scan does it.
- cbor2 accepts non-shortest heads (`18 01` reads as 1); the pre-scan refuses them.
- In 6.x the content of a tag is a `tuple` and a nested map a `frozendict`, where 5.9.0 gave `list`
  and `dict`. A type check on `list` or `dict` without an else branch is exactly the defect class
  `AGENTS.md` names; the adapter must branch on the property, not the container type.
- pycose 1.1.0 cannot read back a message it wrote itself under cbor2 6.1.4
  (`TypeError: Bytes cannot be decoded as COSE message`; cause measured: it checks
  `isinstance(cose_obj, list)` and gets a `tuple`). Under cbor2 5.9.0 it works and verifies all
  three real test-service receipts over our recomputed roots. So pycose cannot share an environment with a
  cbor2 that rejects duplicate keys. As a comparison it needs its own environment pinned to cbor2
  5.9.0, or it is dropped (Q7).

Version facts, read at source on 2026-09-25:

- cbor2 6.1.4, uploaded 2026-08-01, MIT, requires Python >= 3.10: https://pypi.org/pypi/cbor2/json.
  From `docs/versionhistory.rst` in the source repository linked from https://pypi.org/project/cbor2/
  (head `7f84e3da1b60dcdd696c0d4bbcc7d4b9d0b4a2ff`, 2026-09-21): 5.9.0 (2026-03-22) added
  `max_depth`, default 400 (CVE-2026-26209); 6.0.0 (2026-04-28) replaced the Python and C
  implementations with one in Rust, added `allow_indefinite` and `semantic_decoders`, changed the
  `tag_hook` and `object_hook` signatures, dropped Python 3.9; 6.1.0 (2026-05-12) added
  `allow_duplicate_keys`, default True; 6.1.4 fixed, among others, an indefinite-length map whose
  break follows a key without value being accepted.
- pycose 1.1.0, uploaded 2023-12-15, BSD 3-Clause, `requires_dist` names `cbor2` without a bound:
  https://pypi.org/pypi/pycose/json. The source repository linked from
  https://pypi.org/project/pycose/ has its last commit on 2025-10-09
  (`1458ddf14efffbd00bc4052d9026b63da725098e`) and no tag after `v1.1.0`.

So the extra, if cbor2 stays in it, is qualified at 6.1.4 with `allow_duplicate_keys=False`,
`allow_indefinite=False`, a `max_depth` equal to the pre-scan's, and only after the pre-scan passed;
cbor2 then serves as the second reader whose decoded values must equal the pre-scan's. The pin
form is Q1b.

### 14. Python and Rust

`tools/pb_verify_rs` does not verify external anchors today (`src/main.rs`, comment on
`verify_bundle`: anchors are a documented pending slice). A `scitt-ccf` anchor changes no crypto
verdict and no exit code of a bundle without `--require-anchor`, as for every anchor type (SPEC
section 7i), so it introduces no Python and Rust divergence on the verdicts the Rust side
computes. When the Rust anchor slice is built, the byte vectors of Decision 3 and the probes of
`tools/scitt_ccf_external/` are its parity cases.

## Test classes

Each class has an unchanged control case that must pass before any of its negative cases counts.
"Real" means the fetched bytes of `tools/scitt_ccf_external/`; "synthetic" means bytes made by the
test with a key it generates, and says so.

| class | property | control (unchanged) | negative cases, each a single change |
|---|---|---|---|
| structure | a COSE_Sign1 is a tag 18 array of exactly four elements of the right types, in the statement and in every receipt; the inclusion proof is `bstr .cbor {1: leaf, 2: path}` with -05 sizes | real `transparent-statement.cose`, receipt side confirmed | real legacy receipt `cts-hashv-cwtclaims-b64url.cose` (two elements: `malformed`); three or five elements; protected not a bstr; unprotected not a map; signature not a bstr; leaf of two components; 31-byte data-hash; empty or 1025-byte evidence; path element `[1, h]` instead of `[true, h]`; no receipt; receipt array empty |
| unique headers | a label occurs once per map and in one bucket only; hash envelope labels in their bucket | real control | duplicate label in the protected map (spliced bytes); same label in both buckets; 258 in unprotected; 259 or 260 in unprotected; label 3 in either bucket; duplicate key in CWT claims, in `vdp`, in the inclusion proof map, in the key set |
| crit | crit is protected, non-empty, lists only present labels v1 processes | real control (no crit) | crit in unprotected; empty crit; crit listing an absent label; crit listing a present label v1 does not process |
| resource and tag limits | the pre-scan refuses before any library decodes | real control within all limits; real `uvm_0.2.10.cose` with its tag 1 around `iat` accepted | each limit of Decision 8 exceeded by one; tag 1 around a non-time claim, around a float, or in a receipt; tags 2, 24, 28/29, 256/25, 55799 and an unregistered tag at depth 1 and inside a receipt; indefinite outer array (the `D` vector of `tools/scitt_ccf_datahash_vector/`); non-shortest head; one trailing byte after the statement, after a receipt, after an inclusion proof; a float |
| signed bytes kept original | the protected header, payload and signature bytes that enter Sig_structure and value 3 are the bytes as served, never re-encoded from decoded values | real control | the protected map re-encoded with reordered keys (signature must fail, value 3 must change); one bit of the signature element (measured: value 3 no longer matches) |
| external inputs | unknown is not empty | real control, AAD empty by profile, payload embedded | AAD `00` (measured: receipt fails); statement payload nil (outside profile, reported as missing, not as empty); embedded empty payload `h''` (unbound, a different state); receipt with an attached payload equal to the root (outside profile) |
| algorithm and key binding | the protected alg, the RP key type and curve belong together | real control ES384 over P-384; real production receipt verified with a store entry labelled `ES256` (label ignored) | ES384 label with a P-256 RP key; ES256 label with a P-384 key; an EC label with an RSA key; an unsupported alg (outside profile, not invalid); ECDSA signature of wrong length; PS256 with a different salt length (synthetic) |
| identity and cache | value 2 never stands in for value 3; key identity is the RP key, not the kid | real control | synthetic: one ToBeSigned signed twice (measured: value 2 equal, value 3 different), the receipt of the first moved to the second must be `receipt_not_bound`; a second RP key under the same kid for another issuer must not be selected; a cached verdict for one proof must not be returned for a proof with equal value 2 and different bytes |
| receipt verification | leaf per -05, fold, one root, detached payload, vds 2, signature over value 4 | real control, `cbor-header.cose`, `nested-sign1.cose`, and the production `uvm_0.2.10.cose` | one path bit flipped (measured: fails); one path left flag flipped; leaf by the -04 reading of 2.1 (measured: fails); evidence not hashed (measured: fails); vds 1; two inclusion proofs with different roots; key set of another service (`needs_rp_trust`, measured); no key set (`needs_rp_trust`, measured); `tampered-statement.cose` (`signature_invalid`) |
| crossed statement and receipt | a valid receipt proves nothing about another statement | real control | real `payload-tampered.cose` (measured: signature valid, not bound); the control's receipt moved into `cbor-header.cose`; `appended-receipt.cose` (one confirmed and one failing receipt: entry confirmed, failure reported); a statement whose value 1 is the root of another target (`unbound`) |

"Real control" is the receipt side on the real bytes. Where a class checks the statement side as
well (unique headers, external inputs, crossed), its control is a synthetic hash envelope over a
proofbundle root with a synthetic receipt, until an own registration exists (Q6a). Real statement
side cases: `hash-envelope.cose` (value 1 matches its artifact, SHA-256, not registered) and
`uvm_0.2.10.cose` (registered, 258 = SHA-384: `outside_profile` for v1).

A class is complete when its control passes and each negative case fails for the stated reason,
not merely fails. The probes in `recompute.py` already show, on the real bytes, that each
measured comparison fails once.

## Consequences

- 6.4.0 gets one new optional-extra dependency at most (cbor2, Q1). The base install and every
  bundle without a `scitt-ccf` anchor verify unchanged.
- The profile is deliberately narrower than what services may register. A statement registered in
  a form v1 refuses is reported as `outside_profile`, not as forged; widening needs a measurement
  first.
- Trust setup becomes the relying party's work for each service it accepts: which issuer, which
  key set, pinned how. The anchor layer already asks the same for TSA roots and Bitcoin headers.
- `verify_anchor` needs an additive pass-through for the three results and `receiptIat`; that is
  the one change in `src/proofbundle/anchors.py` this design implies.
- The byte vectors and probes in `tools/scitt_ccf_external/` are fetched, not vendored. Tests that
  need them either fetch in a job with network or use synthetic bytes; that choice is part of the
  implementation package.

## What this ADR does not claim

It does not claim that a `confirmed` anchor makes any recorded number true, or that the statement
signer is who they say. It proves that these statement bytes, whose payload is the target's digest,
were registered on a service whose key the relying party chose to trust, at a ledger position the
service signed. It does not claim the service is honest, that its ledger is consistent over time
(consistency proofs are not evaluated in v1), or that the key set is current.

## Open questions for the owner

Q1. Type name and cbor2 pin.
  a) type string `scitt-ccf`, profile version inside the verifier; cbor2 `>=6.1.4,<7`
  b) type string `scitt-ccf/v1` (precedent `chia-datalayer/v1`); cbor2 pinned to the measured
     `==6.1.4`, each bump measured, as the `inspect` extra does
  c) `scitt-ccf/v1`, and no cbor2: the own pre-scan reader is the only reader, the extra adds no
     CBOR dependency

Q2. Time from the receipt.
  a) v1 sets no `trustedTime`; `receiptIat` is informative (proposed above)
  b) v1 lifts the signed `iat` into `trustedTime` with source `scitt_ccf_receipt_iat`
  c) postpone until the clock behind `iat` is measured on a service

Q3. The statement signer.
  a) not required; checked only when the relying party supplies statement keys, and then binding
     (proposed above)
  b) always required: without RP statement keys the anchor is `needs_rp_trust`
  c) never checked in v1

Q4. The local ToBeSigned ID (value 2).
  a) `tbs-id/v1 = SHA-256(Sig_structure)`, external_aad empty
  b) domain-separated: `SHA-256("proofbundle/scitt-tbs-id/v1" || 0x00 || Sig_structure)`, so it
     can never equal a plain SHA-256 another tool computes
  c) no value 2 in 6.4.0 at all; introduce it when a consumer needs it

Q5. Several receipts in one statement.
  a) at least one confirmed receipt confirms the entry; the others are reported (proposed above)
  b) any receipt whose issuer the relying party trusts must also be confirmed
  c) exactly one receipt allowed in v1

Q6. Closing the NOT MEASURED rows of Decision 3, and the missing end-to-end control.
  a) run a local scitt-ccf-ledger in virtual mode (no account; see
     `tools/scitt_ccf_external/README.md`), register a v1 hash envelope over a real proofbundle
     root as the end-to-end control, and detached, untagged, indefinite and non-shortest
     statements, then decide
  b) keep v1 narrow and leave the rows open
  c) ask the working group to state the data-hash input in the profile draft

Q7. pycose as comparison.
  a) a separate test environment pinned to cbor2 5.9.0 and pycose 1.1.0
  b) drop pycose; keep the recorded run in `reader_crosscheck.json` as the comparison
  c) replace it with another independent implementation, for example the Rust verifier of
     `microsoft/scitt-verifier`, run offline on the same bytes

Q8. Tag 1 around CWT time claims in the statement's protected header (seen on the production
  statement).
  a) allowed only there, integer content, informative, never `trustedTime` (proposed above)
  b) refused: proofbundle producers must not emit it, and statements that carry it are
     `outside_profile`
  c) allowed anywhere in the statement's protected header

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
