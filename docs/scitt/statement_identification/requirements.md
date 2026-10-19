# Statement identification in SCITT: requirements

Version 3, 27 September 2026, after an external review of version 2. The version history is at the
end.

This is proposed input to the SCITT statement-identification discussion at IETF 127, following the Chair's request of 22 September 2026. We ask for an unambiguous reference-matching rule, interpretation independent of the carrying statement's application payload, and matching independent of a particular registration. These are proposed goals, not existing WG consensus.

We distinguish a statement reference from a Transparency Service's entry identifier and from a Receipt. No common format, header parameter or relationship vocabulary is proposed for standardization. The accompanying package uses local conventions and synthetic signed fixtures to illustrate selected properties.

Sources are classified as follows:

- CITATION: a statement in a named source, with its section or message.
- OWN MEASUREMENT: a reproducible observation, with the object and method identified.
- ASSESSMENT: our reasoning or proposed requirement, not a result established by a citation or measurement.
- NOT MEASURED or UNAVAILABLE TO THE AUTHOR: a stated evidence limit, with its date and reason.

The package is in [`package/`](package/README.md); the sources, text positions and measurements
behind this text are in the [evidence appendix](#appendix-evidence).

## A1. A reference has an unambiguous target and matching rule

Given a reference and a candidate Signed Statement, a verifier can determine whether they match under a specified identification scheme. The scheme states which differences preserve identity, including differences in signatures, headers and encodings. For a digest-based scheme it also defines the hash algorithm, input bytes and encoding. These definitions may be supplied by a profile rather than repeated in each reference.

The issuer/subject pair groups related statements but does not select an individual statement from that group. The package illustrates selecting `01` rather than `03`, which shares its issuer and subject. Its choice of ToBeSigned is one illustrative matching rule, not a definition of Signed Statement identity established by the architecture.

Acceptance: two implementations using the same scheme agree on matching and non-matching candidate vectors. Missing inputs or unsupported rules cannot produce a successful match. A ToBeSigned scheme must specify external_aad and the source of any detached payload.

## A2. A reference can be read without interpreting the carrier's payload

A verifier can locate and interpret a reference without interpreting the application payload of the Signed Statement carrying it. Recomputing a target digest may still require the target's payload bytes.

This is our proposed scope. Without it, extracting a reference may require payload-specific parsing or decryption of the carrier. It does not follow that encrypted target statements cannot be referenced.

Acceptance: reference extraction uses the same procedure across different carrier payload formats. The package demonstrates this for text and JSON carriers, using a local protected-header convention.

## A3. Matching a statement reference is independent of registration

Proposed requirement: matching a reference to a candidate does not depend on registration with a particular Transparency Service or on a particular insertion event. Service-local entry identifiers and Receipts may coexist with this reference and may differ.

This is one proposed answer to the Chair's open question. A log-dependent identifier does not by itself prevent offline verification. Our requested property is independence from registration context, not a claim that other identification models cannot work.

Acceptance: supplied references and candidates can be matched without a service query or a service-specific insertion identifier. The package demonstrates this local matching operation.

## A4. Acceptance test for A3

Under the same identification scheme, registration in either of two Transparency Services preserves the identity defined by A1. The test must distinguish identity-bearing changes from changes the scheme explicitly excludes.

No two-service registration has been measured here. The package instead applies two local transformations to `01`, each on its own: with tag 18 kept, one unprotected parameter is added; separately, tag 18 is removed and nothing else changes. In each, signature verification and exact ToBeSigned equality survive, while the whole-object digest changes. The untagged result is a generic COSE case, not an RFC 9943 Signed Statement, which requires tag 18 (RFC 9943 section 6.1). A CCF transaction ID is scoped to its ledger and does not itself supply a cross-log statement identity.

This paragraph describes the package's checker as changed after the external review; the review's
wording described one combined transformation (tag removed and a parameter added together), which
is what the checker at `fb1c1786` did.

## A5. Receipt-verification dependency

Where identification depends on a leaf hash or Receipt, the selected VDS specification must define the entry-to-leaf transformation, serialization and tree hashing sufficiently for independent implementations to reproduce the result.

This is a dependency of such identification schemes and of interoperable Receipt verification, not a fifth independent requirement on every statement reference. RFC 9942 distinguishes VDS algorithms. The CT and CCF constructions cited here differ; that difference does not establish ambiguity in either construction. The accompanying package does not test leaf hashing or Receipts.

Context: RFC 9942 sections 4.1 and 4.2 (verifiable data structures and their proofs) and section
5.2.1 (the verification procedure of a VDS algorithm); the receipt framework does not require
different VDS algorithms to produce identical roots. The constructions compared are in the appendix.

## Authentication boundary

When a Signed Statement asserts a reference, the reference and the information needed to interpret it must be bound to that signed assertion. The package illustrates this using a protected header; that is not a proposed standardized placement.

A successful reference match does not establish signature validity, issuer trust, the truth of the payload or registration. Those are separate verification results.

## Outside the scope of these requirements

- Defining a new relationship vocabulary. Applications may use existing vocabularies to describe why one statement refers to another.
- Interpreting the application relationship. Matching need not interpret whether a statement audits, corrects or supersedes its target. The reference's target and matching rule must still be defined.
- Requiring human-readable identifiers.
- Requiring a retrieval location. Matching supplied candidate bytes is required; discovery and retrieval are separate concerns. Locators are not prohibited.

These are proposed scope choices. Our 22 September message explicitly excludes a new relationship vocabulary; the Chair's separation of registration policy from identification does not itself establish the other exclusions.

## Appendix: evidence

### Sources

| Source | Revision or location | How it was read |
|---|---|---|
| The Chair's message to scitt@ietf.org | 22 September 2026, 18:23:02Z, https://mailarchive.ietf.org/arch/msg/scitt/BPmxsdV7RDQx3qxgdCjOUwuFNZU/ | quotation and time from our record; checked against the archive by the external review |
| Our message to scitt@ietf.org | 22 September 2026, 17:38:11Z, https://mailarchive.ietf.org/arch/msg/scitt/Ti1WqhU4VVaZnzJbrBDeQlb6byY/ | our record; the time as the archive gives it, per the external review |
| RFC 9943 | sections 3, 5, 6, 6.1, 6.3, 9.2, 9.5 | the quotations below were read by us in the editor's copy (row below); the external review confirmed them substantively in the published RFC, and that section 6.1 requires tag 18 |
| draft-ietf-scitt-architecture | last submitted revision -22, 10 October 2025 (Datatracker, per the external review); last tag in the repository `draft-ietf-scitt-architecture-11`, `4ad18b4a` (3 March 2025); editor's copy on main at `ba7d23d4` (17 October 2025), rendered text on gh-pages at `2fa18686` | git clone of `ietf-wg-scitt/draft-ietf-scitt-architecture` |
| draft-ietf-scitt-architecture, before and after Reg_Info was removed | `628504c6` (23 October 2023) and `8413f94d` (1 December 2023, "Remove Reg_Info") | same clone |
| RFC 9052 | sections 4.3 (externally supplied data), 4.4 (Sig_structure) and 9 (CBOR encoding restrictions) | read in its source, `draft-ietf-cose-rfc8152bis-struct.xml` in `cose-wg/cose-rfc8152bis` at `3fa9e3c3` (5 September 2022); the section list follows the external review |
| RFC 9942 | sections 4.1, 4.2 and 5.2.1 | cited as context for A5 as the external review names them; not read by us |
| RFC 6962, section 2.1, and RFC 9162, section 2.1.1 | the leaf (0x00) and interior node (0x01) prefixes | confirmed against the published texts by the external review. Read by us earlier in `google/certificate-transparency-rfcs`: `rfc6962.txt` at `7338d9aa` (SHA-256 `08fdf31c...`) and, for RFC 9162, its last draft `draft-ietf-trans-rfc6962-bis-42.txt` (SHA-256 `a76720ac...`) |
| draft-ietf-scitt-receipts-ccf-profile-05 and -04 | tags at `e729c2ec` (23 September 2026) and `54f887f0` (24 June 2026) | git clone of `ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile`; the external review confirmed sections 2.1 and 2.2 of the published -05 |
| draft-ietf-scitt-scrapi-11 | tag at `eaa56243` (24 June 2026), section 2.4 "Resolve Receipt" | git clone of `ietf-wg-scitt/draft-ietf-scitt-scrapi` |
| COSE Header Parameters, private-use range | integer labels below -65536 | read by us in `draft-ietf-cose-msg.xml` (the source of RFC 8152) in `cose-wg/cose-spec` at `5bc5c34b`, line 3847; the external review confirmed it in the current IANA registry |
| microsoft/scitt-ccf-ledger, sigstore/rekor, transparency-dev/tessera | `00101f76` (24 September 2026), `904bbccc` (24 September 2026), `262505df` (25 September 2026) | git fetch and shallow clones |

Access, as dated provenance: on 27 September 2026, between 14:40Z and 15:00Z, www.rfc-editor.org,
datatracker.ietf.org, www.ietf.org and www.iana.org could not be reached from the environment in
which version 2 was measured, so version 2 read drafts and repository copies. The external review of
the same day checked the published texts; its results are cited in the table.

### Text positions of version 2

OWN MEASUREMENT, 27 September 2026. Positions are the section and line of the Markdown source (`md`)
and, for the architecture editor's copy, the line of the rendered text (`txt`).

- Architecture at `628504c6`, section 6.1 "Signed Statement Envelope", md line 728: the Registration
  Policy header (temporary label 393) has the examples "the sequence number of signed statements on a
  `CWT_Claims Subject`, Issuer metadata, or a reference to other Transparent Statements (e.g., augments,
  replaces, new-version, CPE-for)"; md lines 752 to 757 hold the `Reg_Info` CDDL. The published -04,
  section 6.1, has the extension point and these examples without a common digest-reference
  representation (CITATION, checked by the external review).
- `8413f94d` removes `Reg_Info`. Occurrences of `Reg_Info`, `register_by`, `sequence_no`, `issuance_ts`,
  `no_replay` and of augments, replaces, new-version and CPE-for: 0 in every tagged revision from -05 to
  -11 and in the editor's copy. The commit shows the removal, not why it was made.
- Editor's copy `ba7d23d4`, section 3, md line 450, txt lines 562 to 565: the Subject is "an identifier,
  defined by the Issuer, which represents the organization, device, user, entity, or Artifact about
  which Statements (and Receipts) are made and by which a logical collection of Statements can be
  grouped."
- Section 6, md line 668, txt lines 929 to 930: "The `iss` and `sub` Claims, within the `CWT Claims`
  protected header, are used to identify the Artifact the Statement pertains to."
- Section 6.3, md line 821, txt lines 1163 to 1164: "An Issuer that knows of a changed state of quality
  for an Artifact, SHOULD Register a new Signed Statement, using the same `15` CWT `iss` and `sub`
  Claims."
- Section 9.2, md line 974, txt lines 1376 to 1378: "A registered Statement may be superseded by a
  subsequently submitted Signed Statement from the same Issuer, with the same subject in the `CWT
  Claims` protected header."
- Section 3, md line 441, txt lines 556 to 557: "The Statement is considered opaque to Transparency
  Service, and MAY be encrypted." Section 9.5, md line 1011, txt lines 1436 to 1437: "The payload media
  type ('content type') is included in the COSE envelope header."
- Section 3, md lines 462 to 463: "A Transparent Statement remains a valid Signed Statement and may be
  registered again in a different Transparency Service." Section 5, md line 528: "Each Transparency
  Service produces a Receipt, which may be aggregated in a single Transparent Statement, demonstrating
  the Signed Statement was registered by multiple Transparency Services." Section 6.3, md line 816:
  "However, the unprotected header of a Signed Statement MUST be set to an empty map before the Signed
  Statement can be included in a Statement Sequence."
- A search of the editor's copy for "identifier", "digest", "hash", "Statement ID", "Entry ID" and
  "reference" finds no text that defines an identifier for a statement or the bytes a digest of a
  statement covers. Of the ten sentences cited in version 2, eight are also in -11, on other lines,
  and two are not.

So the issuer and subject group statements and are not a unique identifier of each statement;
changed or superseding statements can keep that pair, and other signed contents can tell them apart
(ASSESSMENT, confirmed substantively against RFC 9943 by the external review).

### Implementation readings

OWN MEASUREMENT of source code at the named commits; they do not establish the behaviour of two
running services.

- scitt-ccf-ledger `00101f76`: the entry handle is the CCF transaction ID, `view.seqno`, of the
  transaction that completed the registration, scoped to its ledger. `app/src/operations_endpoints.h`
  line 204 sets `completion_tx = tx_id`, line 139 returns it as `entry_id`, lines 420 to 424 return it as
  `Location: https://{host}/entries/{entry_id}`; `app/src/main.cpp` line 461 serves `/entries/{txid}`.
  Two ledgers can allocate the same numerical pair. An entry handle does not preclude a separate
  portable statement identity.
- sigstore/rekor `904bbccc`: `pkg/sharding/sharding.go` lines 36 to 40 define an entry ID as a tree ID
  followed by a UUID; `pkg/api/entries.go` line 138 sets the UUID to the RFC 6962 leaf hash of the stored
  entry, and lines 350 to 360 answer an entry added again with 409 Conflict and the existing entry ID.
  That path concerns a canonicalized entry in the relevant tree; it is not global de-duplication and not
  a statement about raw submitted COSE bytes.
- transparency-dev/tessera `262505df`: `entry.go` lines 65 to 71 give each entry an `Identity`, SHA-256
  over its bytes (`lifecycle.go` lines 102 to 105), and an RFC 6962 leaf hash; the index is assigned
  later. It illustrates these distinct roles; it is not a SCITT interoperability measurement.
- draft-ietf-scitt-scrapi-11, section 2.4, md line 564: "Resolve Receipt" resolves "the Receipt for a
  given `EntryID`"; the draft does not specify a universal statement-ID derivation.

### The earlier four-envelope record

CITATION of our own record: commit `c0455e0`, dated 4 September 2026 by its commit metadata. Its
records support four encodings of one COSE_Sign1 of 165 bytes (tagged, definite lengths), 203 bytes
(an unprotected header added), 164 bytes (untagged) and 166 bytes (an indefinite-length outer array),
with a Sig_structure of 109 bytes, and they record the successful regeneration of B's signature. The
record provides no separate direct A/B comparison of the ToBeSigned bytes. The package's checker now
performs such comparisons directly on its own fixtures.

### Leaf hashing, the context of A5

OWN MEASUREMENT, 27 September 2026:

- draft-ietf-scitt-receipts-ccf-profile-05 at `e729c2ec`, section 2.1, md line 123:
  `MTH({d[0]}) = HASH(d[0]).`; md line 130: `MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),`. No 0x00 and
  no 0x01 prefix. Section 2.2, md lines 161 to 163: `d[i] = internal-transaction-hash ||
  HASH(internal-evidence) || data-hash`; md line 158: the `ccf-leaf` CBOR array "is not what is hashed
  into the tree". -04 at `54f887f0` has the same tree hash and no serialization of d[i].
- RFC 6962 section 2.1 and RFC 9162 section 2.1.1: `MTH({d(0)}) = SHA-256(0x00 || d(0))` and
  `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))`, confirmed against the published texts by
  the external review.
- `tests/test_merkle_zwei_lesarten_vektoren.py`, run on 27 September 2026 at `31816e08`: 6 passed; the
  external review reran it with the same result. Over five entries the RFC 6962 construction gives a root
  beginning `72458930...`; feeding the already leaf-hashed entries through the tree function again
  gives `b3ee65c5...` (`tools/measurements/merkle_two_readings.py`, which exits 1 when it reports
  different roots). This confirms the numerical contrast between two constructions, not two legitimate
  readings of the CCF definition; the CT and CCF constructions differ, and that difference does not
  establish ambiguity in either.

### NOT MEASURED

- The behaviour of any running Transparency Service: nothing was registered anywhere, and no Receipt
  was constructed or verified.
- RFC 9942: its sections are cited as the external review names them and were not read by us.
- The date on which `c0455e0` was first published; its commit is dated 4 September 2026.

## Version history

- Version 1, 23 September 2026: five requirements and four non-requirements.
- Version 2, 27 September 2026 (commit `fb1c1786`): the same, with the text positions and
  implementation readings that could be measured.
- Version 3, 27 September 2026: after an external review of version 2 ("use after changes"). The
  introduction, the origin classes, A1 to A5, the authentication boundary and the scope section are the
  review's replacement text; its factual corrections are applied; the evidence moved into this
  appendix; A4 describes the package's checker as changed after the review.
