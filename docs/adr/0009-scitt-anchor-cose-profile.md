# ADR 0009: The `scitt-ccf` anchor, a narrow COSE profile over measured bytes

- **Status:** proposed. Fixes the profile, the four values, the trust interface, the error states
  and the test classes for the 6.4.0 anchor type `scitt-ccf/v1`. The owner answered Q1 to Q8 and
  N1 to N6 on 2026-09-25 (section "Owner answers"); the reader, the statement signature and the receipt
  verification are built under `src/` as `proofbundle.scitt_ccf` behind the `[scitt]` extra
  (work packages AP2 to AP4). It is not registered as an anchor type and no verify path reaches it;
  that is AP5, after 6.3.0. One new question is left to the owner at the end.
- **Date:** 2026-09-25 (first version and two owner-answer revisions)
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
- No real statement found publicly is a proofbundle anchor: the production hash envelope uses
  SHA-384 and its artifact is unpublished, the others are not hash envelopes. So, on the owner's
  answer to Q6, one was made: a hash envelope over the root of `examples/example_bundle.json`,
  registered on a local scitt-ccf-ledger in virtual mode, with seven other forms beside it
  (Decision 3). It confirms end to end and is committed as
  `tests/fixtures/scitt_ccf/local_ledger_control.json`.
- microsoft/scitt-verifier (Rust, pinned at `bd6fb8ba79dbb521257b7f09682c03c6681dc3d0`) was run
  offline on the same bytes as `proofbundle.scitt_ccf`: 58 values agree, 0 differ
  (`tools/scitt_ccf_external/rust_crosscheck.json`, owner answer Q7 c).
- The leaf rule of draft -05 was held against the two literal readings of -04: only the -05 form
  verifies against a real receipt.
- cbor2 5.9.0 and 6.1.4 and pycose 1.1.0 were run against the same bytes; their version facts
  below are measured, and read at source where stated.

## Decision

### 1. Profile and version

The type string is `scitt-ccf/v1` (owner answer Q1 b; precedent `chia-datalayer/v1`). Profile
**v1** verifies:

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
| 2 | local ToBeSigned ID | an identifier for what the statement's signer signed | the RFC 9052 Sig_structure of the statement | no API in 6.4.0 (owner answer Q4 c); a measured quantity in `tools/scitt_ccf_external` only |
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

Measured on four statements others registered, one of them from the production ledger
(`tools/scitt_ccf_external/README.md`, section "THE MEASURED DATA-HASH INPUT RULE"), and on eight
forms registered here on a local ledger (below): value 3 is

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

What the service does with other forms, measured on 2026-09-25 by registering them
(`tools/scitt_ccf_external/local_ledger_probe.py`, `local_ledger_result.json`; scitt-ccf-ledger
built from `docker/Dockerfile` at `00101f769d872711356e080fbb089ac48589c60a`, CCF 7.0.17, RPM
sha256 `789d00bed342b08e468a7397f103881df5b6a75c09f3ccc507e2b78a4735fc2e`, virtual mode, one node,
opened with the repository's own `scitt governance local_development`; two runs with fresh keys,
same outcome):

| form submitted | the service | data-hash equals | v1 on what the service serves back |
|---|---|---|---|
| control: tagged, definite, shortest, embedded payload, empty unprotected | accepted | SHA-256 of the submitted bytes | confirmed end to end |
| payload detached (nil) | refused: "Detached or empty payloads are not supported" | n/a | outside profile |
| untagged | refused: "COSE_Sign1 is not tagged" | n/a | outside profile |
| outer array indefinite (`9f ... ff`) | refused: "Signature verification failed" | n/a | refused by the pre-scan |
| payload as an indefinite-length byte string | refused: "Detached or empty payloads are not supported" | n/a | refused by the pre-scan |
| signature head non-shortest (`59 00 40`) | accepted, **stored re-encoded** in shortest form | the service's re-encoded bytes, **not** the submitted ones | confirmed (the stored form is shortest) |
| unprotected map carrying label 99 | accepted, stored with the map **emptied** | the emptied form | confirmed |
| alg -7 as `38 06` inside the protected header | accepted, protected header **kept as sent** | the submitted bytes | **refused by the pre-scan** (see new question N1) |

Three facts follow, each measured, not read from code:

- the service hashes its own re-serialisation, not the submitted bytes: the control, the
  non-shortest signature head and the extra unprotected parameter, three submissions, carry **one**
  data-hash
- the protected header is opaque to that re-serialisation: a non-shortest integer inside it survives
- the whole unprotected map is cleared, not only label 394

v1 therefore reads the statement **as the service serves it back**, and requires it to be tagged,
definite and shortest-form, which is what makes the spliced rule and the re-encoded rule the same
bytes (measured equal on all twelve statements that confirm). The one form the service accepts
and v1 refuses is a non-shortest integer inside the protected header.

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
(`docs/ANCHORS.md`, "Trust model"). As built in `proofbundle.scitt_ccf`:

- `rp_trust["scitt_ccf_services"]`: a mapping from the receipt issuer (the CWT `iss` claim, label 1
  inside label 15 of the receipt's **protected** header, compared as an exact string) to a list of
  keys. A key is SubjectPublicKeyInfo DER bytes or `{"spki": bytes, "kid": bytes}`;
  `load_cose_keyset` turns a COSE_KeySet, as served by the service's `/.well-known/scitt-keys` and
  pinned by the relying party, into that form. CLI and policy spellings are AP5.
- `rp_trust["scitt_statement_keys"]`: keys the relying party accepts for the statement signer,
  **always required** (owner answer Q3 b). Without them the entry is `needs_rp_trust`. If keys are
  given and none verifies the statement, including a key of the wrong type or curve, it is
  `statement_signature_invalid`.
- Which statement key is tried (owner answer N4 b): statements carry no kid (none measured does),
  so the statement's **protected** `x5chain` selects. Only an RP statement key equal to the key of
  its end-entity certificate is tried, compared as keys (both sides re-encoded as SPKI DER, so a
  compressed and an uncompressed point are one key). No such key is `needs_rp_trust`: a key the
  relying party rotated away is missing trust, not a failed signature. A selected key that does
  not verify is `statement_signature_invalid`, and no other key is tried. The certificate is never
  trust. Measured on 2026-09-25: all eight real statements the reader reads carry a protected
  `x5chain` of 2 to 4 certificates (seven third-party, four of them one statement and its mutants,
  and the local-ledger control), and each verifies under its end-entity key except
  `payload-tampered.cose`.
- The shape comes from RFC 9360, read in its WG source (https://github.com/cose-wg/X509 at
  `4228b190f3682cf21e45ffb8037158ed97d1f743`, `draft-ietf-cose-x509.md`, which is
  draft-ietf-cose-x509-08, sha256 `10dd06b1960d081b11247ab45c0d029ba0f477d000380ada8b3471c746150b3d`,
  retrieved 2026-09-25; the published RFC text NOT MEASURED, rfc-editor.org is blocked in this
  environment): `COSE_X509 = bstr / [ 2*certs: bstr ]`, the certificates are untrusted input, and
  the end-entity certificate MUST be integrity protected. So a protected `x5chain` of another shape,
  or whose end-entity certificate is not DER X.509, is `malformed`; an end-entity key the
  cryptography library cannot load matches no RP key (`needs_rp_trust`); and an `x5chain` in the
  unprotected bucket selects nothing. A statement without a protected `x5chain` has every RP
  statement key tried, as before; none measured is such a statement (new question N7).
- Malformed relying-party entries are skipped and reported in `ignored_trust`; they can only ever
  be absent trust, never trust.

Never a trust source, each named because each is present in real evidence:

| material | where it is found | role in v1 |
|---|---|---|
| `kid` of the receipt | receipt protected header | selects candidate keys **within** the issuer's RP key set; RFC 9052, section "Common COSE Header Parameters" (WG source): kid values are hints and not unique, so every RP key with that kid is tried. Measured: `hex(SHA-256(SPKI))` equals the kid on every -05 receipt, test service and production; reported, not required |
| algorithm labels in a key set or trust store | RP material | never used; measured: the production trust store labels its P-384 keys `ES256` while the receipts they verify say ES384 |
| keys embedded in the statement or receipt | any header | ignored for trust |
| `x5chain` certificates | statement protected header (measured: 2 to 4 certificates in every real statement) | the end-entity certificate's key selects among the RP statement keys (owner answer N4 b); never trust; the unprotected bucket selects nothing |
| the anchor's `frozen` field | the bundle | evidence (`frozenEvidence`), never trust; a producer may freeze the key set it used, and it is reported next to the RP result |
| `anchoredAt` | the anchor entry | informative only |

A receipt whose issuer has no RP key set, or whose kid matches no RP key of that issuer (the key's
own kid, or `hex(SHA-256(SPKI))` when it has none), is `needs_rp_trust`: not verified, not failed,
and never satisfying. A key the relying party trusts for one issuer is never selected for
another.

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
| tags | 18 at the top of the statement and at the top of each receipt; 1 only around an integer CWT time claim (4, 5, 6) in the statement's protected CWT map (owner answer Q8 a); nowhere else | real: 18 in all; tag 1 around `iat` in two statements, one of them the production statement; a nested tag-18 COSE_Sign1 inside a protected header (`nested-sign1.cose`) is refused |
| simple values | false, true, null; no floats | real: no floats |
| map keys | integer or text string, unique | real: yes |
| trailing bytes | none, in the statement, each receipt and each inclusion proof | real: none |

The values in the v1 column are pinned in `proofbundle.scitt_ccf` (`MAX_STATEMENT_BYTES`,
`MAX_DEPTH`, `MAX_RECEIPTS`, `MAX_INCLUSION_PROOFS`, `MAX_PATH`, `MAX_EVIDENCE_BYTES`) and in
`proofbundle._cbor_prescan`; each is tested at L and L+1. The measured column is why they are not
tighter or looser. Owner answer N1 a: a non-shortest head stays refused everywhere, also inside the
protected bstr, where the local ledger accepted one and kept it as sent (Decision 3); one wire form
per statement leaves no reader differential to reason about. The tag 1 allowance is the one place where a real
production statement forced the profile wider than a clean reading of RFC 8392 would (NumericDate
is the untagged form there); the claim stays informative and never becomes `trustedTime`.

### 9. Error states, a closed set

Each receipt gets exactly one of these, and the anchor entry reports `confirmed` if the statement
side holds and at least one receipt is `confirmed`; otherwise the first state in this order across
the statement side and its receipts (`STATUS_ORDER` in `proofbundle.scitt_ccf`):

| status | meaning | `ok` | `warn` |
|---|---|---|---|
| `no_lib` | the `[scitt]` extra is not installed, or its cbor2 lacks the strict options | False | False |
| `malformed` | the pre-scan or the COSE structure refused the bytes; a protected `x5chain` that is not `COSE_X509` or whose end-entity certificate is not DER X.509; also a statement with no receipt | False | False |
| `outside_profile` | readable, but not scitt-ccf v1 (untagged, detached statement payload, not a hash envelope, 258 not SHA-256, label 3 present, unprocessed crit, vds not 2, attached receipt payload, no inclusion proof, unsupported algorithm) | False | False |
| `unbound` | value 1 differs from `canonicalRoot` | False | False |
| `statement_signature_invalid` | the statement signature fails with every RP statement key tried: the one the protected `x5chain` selects, or all of them when there is none | False | False |
| `root_mismatch` | inclusion proofs of one receipt compute different roots | False | False |
| `signature_invalid` | an RP key was selected and the receipt signature fails over value 4, including algorithm and key mismatch | False | False |
| `receipt_not_bound` | the receipt signature is valid, but the leaf's data-hash differs from value 3 recomputed from this statement | False | False |
| `needs_rp_trust` | no RP statement key, no RP statement key equal to the protected `x5chain`'s end-entity key, no RP key set for the receipt's issuer, or no RP key for its kid | False | False |
| `confirmed` | profile satisfied, see Decision 10 | True | False |

`warn` is never set by `scitt-ccf`. A CCF receipt exists only after commit, so v1 has no pending
state. Per-entry fields follow the existing contract: `rp_trusted` when a signature was checked with
RP material, `needs_rp_trust`, `frozenEvidence`.

One receipt that fails next to one that is `confirmed` does not veto the entry; it is reported. The
unprotected header that carries receipts is covered by no signature, so anyone handling the file can
append one (the argument of the scitt-verifier corpus, `corpus/README.md` at the pinned commit). This
is the same separation `verify_anchors` already keeps between `require_met` and `status` (owner
answer Q5 a).

### 10. Result semantics: three separate results

| result | holds when | real example where it differs from the next |
|---|---|---|
| **readable** | the proof passes the pre-scan and parses as a tagged COSE_Sign1 with at least one receipt that parses under the -05 CDDL | `tampered-statement.cose`: readable, signature not valid. Not readable, real: `cts-hashv-cwtclaims-b64url.cose`, whose receipt is the legacy two-element form |
| **signature valid** | a receipt's ES256/ES384 signature verifies over its computed root with a key selected from the RP key set of its issuer | `payload-tampered.cose`: signature valid, profile not satisfied, because the receipt belongs to another statement |
| **profile satisfied** | signature valid, and for that receipt: vds 2, payload detached, all proofs one root, leaf data-hash equals value 3, the statement is a v1 hash envelope whose value 1 equals `canonicalRoot`, crit and header rules hold, and an RP statement key verifies the statement | end to end, real: the local-ledger control in `tests/fixtures/scitt_ccf/local_ledger_control.json`. Receipt side, real: the test-service control and `uvm_0.2.10.cose` (production) |

Only "profile satisfied" sets the anchor's `ok`. The three are reported side by side, never folded
into one boolean, because each alone has a real counterexample in the measured evidence. Carrying
them through `verify_anchor` needs an additive field there; that is implementation work under
`src/`, not part of this ADR.

### 11. Missing input or missing trust never satisfies

- `allow_pending` counts entries with `ok` or `warn` (`verify_anchors`). `scitt-ccf` never sets
  `warn`, so a missing receipt, a detached payload, missing trust or an unknown issuer cannot
  satisfy `--require-anchor`, with or without `--allow-pending`. The results of
  `proofbundle.scitt_ccf` carry no `warn` field at all (pinned by
  `tests/test_scitt_ccf_profile.py`); the `allow_pending` regression case against `verify_anchors`
  belongs to AP5, where the type is registered.
- A statement without receipts is `malformed`: a Signed Statement is not a Transparent Statement.
- An empty RP key set is missing trust, not trust in nothing.

### 12. No trusted time from `anchoredAt`, and none from the receipt in v1

`anchoredAt` stays informative, as for every anchor type. v1 sets no `trustedTime` at all. The
receipt's protected CWT `iat` is signed by the service key and is reported as `receiptIat`,
informative, with its source named (`receipt_iat` in `proofbundle.scitt_ccf`). What clock stands
behind it is NOT MEASURED. Owner answer Q2 a: v1 lifts nothing into `trustedTime`.

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
  that one position and nothing else, which is how it is built.
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
  5.9.0, or it is dropped; the owner dropped it (Q7 c).

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

As built (owner answer Q1 b): `pyproject.toml` declares `scitt = ["cbor2==6.1.4"]`, and `dev`
carries the same pin so CI runs the reader's tests; `test` does not, so the sdist run of `[test]`
shows the suite without the extra. cbor2 is called with `allow_duplicate_keys=False`,
`allow_indefinite=False` and a `max_depth` two above the pre-scan's, and only after the pre-scan
passed; its decoded values must equal the pre-scan's, compared by content, with tag 1 mapped to the
`datetime` cbor2 makes of it and nothing else mapped. A cbor2 without the strict options is refused
at run time (`no_lib`). pycose is not used at all (owner answer Q7 c); its place as the comparison is
taken by the Rust verifier of microsoft/scitt-verifier, Decision 14.

### 14. Python and Rust

`tools/pb_verify_rs` does not verify external anchors today (`src/main.rs`, comment on
`verify_bundle`: anchors are a documented pending slice). A `scitt-ccf` anchor changes no crypto
verdict and no exit code of a bundle without `--require-anchor`, as for every anchor type (SPEC
section 7i), so it introduces no Python and Rust divergence on the verdicts the Rust side
computes. When the Rust anchor slice is built, the byte vectors of Decision 3 and the probes of
`tools/scitt_ccf_external/` are its parity cases. The two new `verify_` surfaces are registered as
`PENDING` in `scripts/rust_parity_registry.json` and stay so until AP5 registers the anchor type
(owner answer N5 a).

A foreign Rust reader was run instead, on the owner's answer to Q7: microsoft/scitt-verifier 0.4.0
at `bd6fb8ba79dbb521257b7f09682c03c6681dc3d0`, built with `cargo build --release --locked`, run
offline with local key sets on the twelve real statements (`tools/scitt_ccf_external/rust_crosscheck.py`,
2026-09-25). Compared per receipt and statement: Merkle root, leaf data-hash, recomputed data-hash,
receipt signature validity, binding, kid binding. 58 values agree, 0 differ, 9 not comparable,
all nine where v1 refuses a form scitt-verifier reads (the nested tag-18 statement, the
non-shortest protected header, the legacy receipt, and two kid bindings not reported for an
invalid signature). Verdicts differ by design and are recorded, not compared: scitt-verifier
appraises a signer chain and a policy, v1 requires a hash envelope over a proofbundle root.

### 15. Consistency receipts (-05 section 4), beside the anchor, not in it

A consistency receipt relates two roots of one ledger; it proves nothing about a statement, so it
never enters the anchor verdict. `proofbundle.scitt_ccf.verify_consistency_receipt` checks one
against an older root the caller already verified (typically `merkle_root` of a `confirmed`
inclusion receipt) and that receipt's issuer, with its own closed status set,
`CONSISTENCY_STATUS_ORDER`, the first that applies deciding:

| status | rule |
|---|---|
| `consistency_proof_missing` | no `vdp`, no -2, or an empty -2 (4.1, 4.2) |
| `consistency_payload_attached` | the newer root is not detached (4.1) |
| `consistency_newer_roots_differ` | two proofs, or a proof and an inclusion proof beside it, compute different newer roots (4.1, section 5) |
| `consistency_anchor_not_canonical` | a proof starts with a left sibling, so its anchor is not the one section 4 requires |
| `consistency_older_root_mismatch` | no proof recomputes the older root (4.2) |
| `consistency_issuer_mismatch` | the older root came from another service's receipt; not a rule of -05 |
| `signature_invalid`, `needs_rp_trust` | as for inclusion receipts, over the newer root |

`malformed` and `outside_profile` keep their meaning; the protected header rules are those of
inclusion receipts, as 4.1 says. Two of these go further than the 4.2 pseudo-code. That code accepts
a receipt with a corrupted second proof, and one whose anchor lies below the section 4 anchor. Both
were measured on the local ledger and in every tree pair up to 257 leaves, and they are refused here
because 4 and 4.1 say MUST. The measurement, the third-party RFC 9162 oracle
(transparency-dev/merkle at `fbbcd741`) and the questions for the working group are in
`tools/scitt_ccf_external/SECTION4_WGLC.md`. No service measured emits a consistency receipt, so the
real vector (`tests/fixtures/scitt_ccf/local_ledger_consistency.json`) is the service's own
signature over the newer root with a proof computed from the ledger's leaves.

## Test classes

Each class has an unchanged control case that must pass before any of its negative cases counts.
"Real" means bytes a CCF service produced: the committed local-ledger vector
(`tests/fixtures/scitt_ccf/local_ledger_control.json`, our own registration, the one end-to-end
control CI runs, owner answer N2 a) or the third-party bytes committed as JSON fixtures beside it
(`third_party_scitt_verifier.json`, `third_party_scitt_ccf_ledger.json`, owner answer N3 b: every
entry labelled "third-party bytes" with its source at the pinned commit and its licence, MIT, whose
text each file carries; written by `tools/scitt_ccf_external/fetch_external.py --write-fixtures`;
`PROVENANCE.json` names the origin of every file in the directory). "Synthetic" means bytes made by
the test with a key it generates, and says so.

Where they are, as built: `tests/test_scitt_ccf_profile.py` (every class below, the synthetic
control and the real local-ledger control, 104 cases), `tests/test_cbor_prescan.py` (the pre-scan
alone, standard library, 44 cases), `tests/test_scitt_ccf_without_extra.py` (the `no_lib` refusal,
runs with and without cbor2, 6 cases), `tests/test_scitt_ccf_external_bytes.py` (the committed
third-party bytes, 12 cases: the labels and pins in both environments, the reader cases with the
extra).

| class | property | control (unchanged) | negative cases, each a single change |
|---|---|---|---|
| structure | a COSE_Sign1 is a tag 18 array of exactly four elements of the right types, in the statement and in every receipt; the inclusion proof is `bstr .cbor {1: leaf, 2: path}` with -05 sizes | real `transparent-statement.cose`, receipt side confirmed | real legacy receipt `cts-hashv-cwtclaims-b64url.cose` (two elements: `malformed`); three or five elements; protected not a bstr; unprotected not a map; signature not a bstr; leaf of two components; 31-byte data-hash; empty or 1025-byte evidence; path element `[1, h]` instead of `[true, h]`; no receipt; receipt array empty |
| unique headers | a label occurs once per map and in one bucket only; hash envelope labels in their bucket | real control | duplicate label in the protected map (spliced bytes); same label in both buckets; 258 in unprotected; 259 or 260 in unprotected; label 3 in either bucket; duplicate key in CWT claims, in `vdp`, in the inclusion proof map, in the key set |
| crit | crit is protected, non-empty, lists only present labels v1 processes | real control (no crit) | crit in unprotected; empty crit; crit listing an absent label; crit listing a present label v1 does not process |
| resource and tag limits | the pre-scan refuses before any library decodes | real control within all limits; real `uvm_0.2.10.cose` with its tag 1 around `iat` accepted | each limit of Decision 8 exceeded by one; tag 1 around a non-time claim, around a float, or in a receipt; tags 2, 24, 28/29, 256/25, 55799 and an unregistered tag at depth 1 and inside a receipt; indefinite outer array (the `D` vector of `tools/scitt_ccf_datahash_vector/`); non-shortest head; one trailing byte after the statement, after a receipt, after an inclusion proof; a float |
| signed bytes kept original | the protected header, payload and signature bytes that enter Sig_structure and value 3 are the bytes as served, never re-encoded from decoded values | real control | the protected map re-encoded with reordered keys (signature must fail, value 3 must change); one bit of the signature element (measured: value 3 no longer matches) |
| external inputs | unknown is not empty | real control, AAD empty by profile, payload embedded | AAD `00` (measured: receipt fails); no AAD parameter on any entry point; statement payload nil (outside profile, reason "detached"); embedded empty payload `h''` (outside profile, its own reason "32 bytes, not 0"); receipt with an attached payload equal to the root (outside profile); `canonical_root` not 32 bytes (unbound) |
| algorithm and key binding | the protected alg, the RP key type and curve belong together | real control ES384 over P-384; real production receipt verified with a store entry labelled `ES256` (label ignored) | ES384 label with a P-256 RP key; ES256 label with a P-384 key; an EC label with an RSA key; an unsupported alg (outside profile, not invalid); ECDSA signature of wrong length; PS256 with a different salt length (synthetic) |
| identity and cache | value 2 never stands in for value 3; key identity is the RP key, not the kid | real control | synthetic: one ToBeSigned signed twice (measured: value 2 equal, value 3 different), the receipt of the first moved to the second must be `receipt_not_bound`; a second RP key under the same kid for another issuer must not be selected; a cached verdict for one proof must not be returned for a proof with equal value 2 and different bytes |
| receipt verification | leaf per -05, fold, one root, detached payload, vds 2, signature over value 4 | real control, `cbor-header.cose`, `nested-sign1.cose`, and the production `uvm_0.2.10.cose` | one path bit flipped (measured: fails); one path left flag flipped; leaf by the -04 reading of 2.1 (measured: fails); evidence not hashed (measured: fails); vds 1; two inclusion proofs with different roots; key set of another service (`needs_rp_trust`, measured); no key set (`needs_rp_trust`, measured); `tampered-statement.cose` (`signature_invalid`) |
| statement key selection | the protected `x5chain` selects among RP statement keys, never trust (N4 b) | synthetic chain naming the signer among two RP keys; real: three third-party statements (PS256, PS384) and the local-ledger control | RP holds only another key (`needs_rp_trust`, real and synthetic); chain names key A, key B signed, RP holds both (`statement_signature_invalid`, B not tried); chain names an untrusted key (`needs_rp_trust`); single-certificate form; RP key as a compressed point (confirms); `x5chain` only unprotected (selects nothing); a statement kid (selects nothing); end-entity key of an unknown algorithm (`needs_rp_trust`); `x5chain` an int, text, map, null, empty array, one-element array, a non-bstr element, a junk certificate (each `malformed`); real `payload-tampered.cose` under its selected key (`statement_signature_invalid`) |
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

- 6.4.0 gets one new optional-extra dependency, cbor2 pinned at 6.1.4 (Q1 b). The base install and
  every bundle without a `scitt-ccf/v1` anchor verify unchanged; `proofbundle.scitt_ccf` imports
  without the extra and refuses with `no_lib`.
- The profile is deliberately narrower than what services may register. A statement registered in
  a form v1 refuses is reported as `outside_profile` or `malformed`, never as forged; widening needs
  a measurement first. Measured instances today: a nested tag-18 statement in a protected header,
  a non-shortest integer inside a protected header (N1), the legacy two-element receipt.
- Trust setup becomes the relying party's work for each service it accepts: which issuer, which
  key set, pinned how. The anchor layer already asks the same for TSA roots and Bitcoin headers.
- `verify_anchor` needs an additive pass-through for the three results and `receipt_iat`; that is
  the one change in `src/proofbundle/anchors.py` this design implies, and it belongs to AP5.
- The statements and key sets of the two MIT sources are committed as labelled JSON fixtures
  (N3 b), 40091 B and 27683 B; the ccf-profile sample stays fetch-only, its terms are the IETF's.
  The one real end-to-end control is our own registration, committed as a test fixture (N2 a).

## What this ADR does not claim

It does not claim that a `confirmed` anchor makes any recorded number true, or that the statement
signer is who they say. It proves that these statement bytes, whose payload is the target's digest,
were registered on a service whose key the relying party chose to trust, at a ledger position the
service signed. It does not claim the service is honest, or that the key set is current. It does not
claim that the ledger is consistent over time: the anchor verdict evaluates no consistency proof, and
the separate consistency verifier of Decision 15 relates two roots only for a caller that holds them.

## Owner answers (2026-09-25)

| question | answer | where it stands now |
|---|---|---|
| Q1 type name and cbor2 pin | b | type string `scitt-ccf/v1`; `scitt = ["cbor2==6.1.4"]`, every bump measured |
| Q2 time from the receipt | a | no `trustedTime`; `receipt_iat` informative |
| Q3 statement signer | b | always required; without RP statement keys `needs_rp_trust` |
| Q4 local ToBeSigned ID | c | no API in 6.4.0; a measured quantity in `tools/scitt_ccf_external` only |
| Q5 several receipts | a | one confirmed receipt confirms the entry, the others are reported |
| Q6 the unmeasured forms | a | measured on a local ledger, Decision 3; the end-to-end control exists |
| Q7 comparison | c | microsoft/scitt-verifier run offline on the same bytes, Decision 14 |
| Q8 tag 1 | a | allowed only around an integer CWT time claim of the statement's protected header |
| N1 non-shortest integer inside the protected header | a | refused everywhere, Decision 8 |
| N2 the local-ledger vector | a | kept as the one real end-to-end control CI runs; 9753 B (the question said 9849 B, which was wrong) |
| N3 third-party real bytes in CI | b | committed as JSON fixtures, each entry labelled third-party bytes with source and licence, section "Test classes" |
| N4 statement key selection | b | the protected `x5chain` selects, never trust, Decision 5 |
| N5 Rust parity of the two new surfaces | a | `PENDING` until AP5, Decision 14 |
| N6 unsigned agent commits | a | accepted as Unverified; a process question, not part of this profile |

## New questions for the owner

N7. A v1 statement without a protected `x5chain`. None measured is one; today every RP statement
  key is tried for it, so for such a statement a rotated-away key still reads as
  `statement_signature_invalid`.
  a) keep it: without a selector every trusted key is tried, and one must verify
  b) require a protected `x5chain` in v1, a statement without one is `outside_profile`
  c) also accept a protected `x5t` (label 34) as the selector, and measure a statement carrying one
     first

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
