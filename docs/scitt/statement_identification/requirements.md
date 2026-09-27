# Statement identification in SCITT: requirements

Version 2, 27 September 2026. Version 1 (23 September 2026) stated the five requirements and the
four non-requirements below; this version keeps them and adds the text positions and implementation
readings that could be measured, each with its source, commit and date.

This is input to the SCITT agenda item on statement identification for IETF 127. On 22 September
2026 at 18:23:02Z Jon Geater asked on scitt@ietf.org: "On statement IDs please bring all
requirements you may have for statement identification", and raised the question "whether or not
the statement ID should be cryptographically derived from its log insertion". It lists requirements
for a reference to a statement; it proposes no format, no header parameter and no vocabulary.
A small package that shows the requirements on real bytes is in [`package/`](package/README.md).

## Origin classes

Every requirement and every supporting fact names where it comes from.

- **OWN MEASUREMENT**: measured by us; the tool, the object measured (with commit or revision) and
  the time are named.
- **CITATION**: stated in a named document or message; the section or message and its date are
  named.
- **ASSESSMENT**: our reasoning. It is marked as such and is not counted as a requirement.
- **NOT MEASURED** / **NOT MEASURABLE**: stated where a fact is missing, with the reason.

## Sources measured for this version

All read on 27 September 2026 between 14:40Z and 15:00Z.

| Source | Revision | How it was read |
|---|---|---|
| draft-ietf-scitt-architecture, editor's copy | main at `ba7d23d4` (17 October 2025); rendered text on the gh-pages branch at `2fa18686`, SHA-256 of the text `edb2327d...` | git clone of `ietf-wg-scitt/draft-ietf-scitt-architecture` |
| draft-ietf-scitt-architecture, last tagged revision | tag `draft-ietf-scitt-architecture-11`, `4ad18b4a` (3 March 2025) | same clone |
| draft-ietf-scitt-architecture, before and after Reg_Info was removed | `628504c6` (23 October 2023) and `8413f94d` (1 December 2023, "Remove Reg_Info") | same clone |
| RFC 9943 | NOT MEASURABLE: www.rfc-editor.org, datatracker.ietf.org and www.ietf.org are denied by the network policy of the environment this was measured in | none |
| draft-ietf-scitt-receipts-ccf-profile-05 and -04 | tags at `e729c2ec` (23 September 2026) and `54f887f0` (24 June 2026) | git clone of `ietf-wg-scitt/draft-ietf-scitt-receipts-ccf-profile` |
| RFC 6962 | the copy `rfc6962.txt` in the authors' repository `google/certificate-transparency-rfcs` at `7338d9aa`, added in `0f28ddc` (14 June 2013), SHA-256 `08fdf31c...`; not compared with the RFC Editor's copy (denied, see above) | git clone |
| RFC 9162 | NOT MEASURABLE (denied, see above). Its last draft, `draft-ietf-trans-rfc6962-bis-42.txt` (31 August 2021), from the same repository, SHA-256 `a76720ac...`, is read instead and named as such | git clone |
| draft-ietf-scitt-scrapi | tag `draft-ietf-scitt-scrapi-11` at `eaa56243` (24 June 2026) | git clone of `ietf-wg-scitt/draft-ietf-scitt-scrapi` |
| RFC 9052, section 4.4 | NOT MEASURABLE (denied, see above). Its source, `draft-ietf-cose-rfc8152bis-struct.xml` in `cose-wg/cose-rfc8152bis` at `3fa9e3c3` (5 September 2022), is read instead | git clone |
| COSE Header Parameters, private-use range | `draft-ietf-cose-msg.xml` (the source of RFC 8152) in `cose-wg/cose-spec` at `5bc5c34b`, section "COSE Header Parameters Registry", line 3847; the IANA registry itself NOT MEASURABLE (www.iana.org denied) | git clone |
| microsoft/scitt-ccf-ledger | `00101f76` (24 September 2026) | git fetch of that commit |
| sigstore/rekor | `904bbccc` (24 September 2026) | shallow git clone |
| transparency-dev/tessera | `262505df` (25 September 2026) | shallow git clone |

Positions in a draft are given as section number and line of the Markdown source (`md`); for the
architecture editor's copy also as line of the rendered text (`txt`). Positions differ between
revisions: of the ten architecture sentences cited below, eight are also in -11, on other lines,
and two are not in -11 at all.

## A1. A reference identifies named bytes, not an object

A reference to a statement names a sequence of bytes and says which bytes its digest covers: for
example the ToBeSigned value of a COSE_Sign1 (RFC 9052 section 4.4) or the whole COSE_Sign1 bytes.

Origin: **CITATION**. draft-ietf-scitt-architecture-04, section 6.1 (the `Reg_Info` CDDL and the
examples "augments, replaces, new-version, CPE-for"), defines no common reference format and does not
say which bytes a digest covers; RFC 9943 has neither `Reg_Info` nor those terms, `sub` remains the
link to the artifact, and extensions are allowed. Both read on 22 September 2026.

**OWN MEASUREMENT**, the architecture source:

- At `628504c6` (23 October 2023), section 6.1 "Signed Statement Envelope", md line 728: the
  Registration Policy header (temporary label 393) has the examples "the sequence number of signed
  statements on a `CWT_Claims Subject`, Issuer metadata, or a reference to other Transparent
  Statements (e.g., augments, replaces, new-version, CPE-for)"; md lines 752 to 757 hold the
  `Reg_Info` CDDL. Neither says which bytes a reference covers.
- `8413f94d` (1 December 2023) removes `Reg_Info`. Occurrences of `Reg_Info`, `register_by`,
  `sequence_no`, `issuance_ts`, `no_replay` and of augments, replaces, new-version and CPE-for: 0 in
  every tagged revision from 05 to -11 and in the editor's copy.
- Editor's copy `ba7d23d4`, section 3 "Terminology", md line 450, txt lines 562 to 565: the Subject
  is "an identifier, defined by the Issuer, which represents the organization, device, user, entity,
  or Artifact about which Statements (and Receipts) are made and by which a logical collection of
  Statements can be grouped."
- Section 6 "Signed Statements", md line 668, txt lines 929 to 930: "The `iss` and `sub` Claims,
  within the `CWT Claims` protected header, are used to identify the Artifact the Statement pertains
  to."
- Section 6.3 "Registration of Signed Statements", md line 821, txt lines 1163 to 1164: "An Issuer
  that knows of a changed state of quality for an Artifact, SHOULD Register a new Signed Statement,
  using the same `15` CWT `iss` and `sub` Claims."
- Section 9.2 "Accuracy of Statements", md line 974, txt lines 1376 to 1378: "A registered Statement
  may be superseded by a subsequently submitted Signed Statement from the same Issuer, with the same
  subject in the `CWT Claims` protected header." This sentence is not in -11.
- A search of the editor's copy for "identifier", "digest", "hash", "Statement ID", "Entry ID" and
  "reference" finds no text that defines an identifier for a statement or says which bytes a digest
  of a statement covers. "Identifiable" occurs in section 3 (md line 426, the definition of a Signed
  Statement), section 4 (md line 477), section 9 (md line 955) and section 10.1 (md line 1080),
  each time without saying how a statement is identified.

So the issuer and the subject identify an artifact and a collection of statements; by the text above
two statements from the same issuer about the same subject are expected, and nothing in the document
tells them apart. The package shows two such statements, `01` and `03`, and two references that
name exactly one of them.

If this is not met, a verifier holding a reference cannot tell which of several statements with the
same issuer and subject it names, or cannot recompute the digest because it does not know which
bytes were hashed.

## A2. The reference is readable without knowing the payload format

A verifier reads a reference without parsing the payload of the statement that carries it.

Origin: **CITATION**, our post to scitt@ietf.org of 22 September 2026, 17:38Z, and the examples in
that thread (64 encodings under one signature; the CBAP-1 example).

**OWN MEASUREMENT**, editor's copy `ba7d23d4`:

- Section 3 "Terminology", md line 441, txt lines 556 to 557: "The Statement is considered opaque to
  Transparency Service, and MAY be encrypted." This sentence is also in -11 (section 3, md line 433).
- Section 9.5 "Implications of Media-Type Usage", md line 1011, txt lines 1436 to 1437: "The payload
  media type ('content type') is included in the COSE envelope header." Not in -11.
- The header, in contrast to the payload, has one format for every statement: the protected header is
  a CBOR map in a byte string covered by the signature (RFC 9052 section 4.4; read in the source named
  above, xml lines 757 to 798).

The package carries its references in the protected header. `02` has a `text/plain` payload, `03` a
JSON payload, and `verify.py` reads the reference the same way in both without reading either
payload.

If this is not met, a transparency service or a verifier must understand every payload format in
use to follow a reference, and a statement with an encrypted or unknown payload cannot be referred to
at all.

## A3. The identity of a statement is not bound to exactly one log

The bytes that identify a statement, and so the digest in a reference, do not depend on a particular
transparency service or on the position at which a transparency service recorded it.

Origin: **CITATION** for the question: Jon Geater on scitt@ietf.org, 22 September 2026, 18:23:02Z,
"whether or not the statement ID should be cryptographically derived from its log insertion".
**ASSESSMENT** for the consequence: an identity derived from one log's insertion can be checked only
against that log, and a statement registered in two logs then has two identities.

**OWN MEASUREMENT**, editor's copy `ba7d23d4`:

- Section 3 "Terminology", md lines 462 to 463, txt lines 580 to 584: "The Receipt is stored in the
  unprotected header of COSE Envelope of the Signed Statement. A Transparent Statement remains a valid
  Signed Statement and may be registered again in a different Transparency Service." Also in -11
  (section 3, md lines 449 to 450).
- Section 5 "Architecture Overview", md line 528, txt lines 714 to 717: "Each Transparency Service
  produces a Receipt, which may be aggregated in a single Transparent Statement, demonstrating the
  Signed Statement was registered by multiple Transparency Services." Also in -11 (md line 516).
- Section 6.3, md line 816, txt lines 1154 to 1156: "However, the unprotected header of a Signed
  Statement MUST be set to an empty map before the Signed Statement can be included in a Statement
  Sequence." Also in -11 (section 6.2, md line 754).

**OWN MEASUREMENT**, how public implementations derive the identifier of a recorded entry, read in
their source:

- scitt-ccf-ledger `00101f76`: the entry ID is the CCF transaction ID (view and sequence number) of
  the transaction that recorded the statement. `app/src/operations_endpoints.h` line 204 sets
  `completion_tx = tx_id`, line 139 returns it as `entry_id`, and lines 420 to 424 return it as
  `Location: https://{host}/entries/{entry_id}`; `app/src/main.cpp` line 461 serves
  `/entries/{txid}`. The identifier is derived from the log position.
- sigstore/rekor `904bbccc`: `pkg/sharding/sharding.go` lines 36 to 40 define an entry ID as a tree
  ID (8 bytes, hex) followed by a UUID (32 bytes, hex); `pkg/api/entries.go` line 138 sets the UUID
  to the RFC 6962 leaf hash of the stored entry. When the same entry is added again, lines 350 to 360
  return 409 Conflict with the existing entry ID, whose UUID is again the RFC 6962 leaf hash
  (line 351). The UUID is derived from the entry's bytes, the
  prefix from the log.
- transparency-dev/tessera `262505df`: `entry.go` lines 65 to 71 give every entry an `Identity`,
  SHA-256 over the entry's bytes (`lifecycle.go` lines 102 to 105), documented at lines 44 to 45 as
  usable to de-duplicate entries, and a leaf hash, the RFC 6962 leaf hash of the same bytes; the index
  is assigned by the log. The identity is derived from the entry's bytes, not from the log.
- draft-ietf-scitt-scrapi-11 `eaa56243`: section 2.4 "Resolve Receipt", md line 564, resolves "the
  Receipt for a given `EntryID`"; `EntryID` or "entry ID" occurs in six lines of the document, and none
  defines how it is derived.

NOT MEASURED: what any of these services returns when the same statement is registered with two
different services; the readings above are of source code, not of running services.

If this is not met, a reference made in one transparency service cannot be checked by a relying party
that uses another one, or none, and the same statement registered twice has two identities.

## A4. The same statement in two transparency services has the same identity

Origin: **ASSESSMENT**, derived from A3 and kept as its test.

NOT MEASURED: how existing implementations behave when the same statement is registered with two
transparency services. The source readings under A3 give the derivations: an identifier from the CCF
transaction ID differs between two ledgers by construction; an identity from a digest of the recorded
bytes (Rekor's UUID, Tessera's `Identity`) is the same in two services only if both record the same
bytes. By section 6.3 of the architecture (md line 816) the unprotected header is set to an empty map
before inclusion, but the tag, the length encodings and the choice of the bytes to record remain
open, so equal statements can still be recorded as different bytes (**ASSESSMENT**).

Related measurement, **CITATION** of our own record: commit `c0455e0`, published 25 September 2026
in a public repository, four encodings of the same COSE_Sign1 (tagged with definite lengths, 165
bytes; with an unprotected header, 203 bytes; untagged, 164 bytes; with an indefinite-length outer
array, 166 bytes) give a Sig_structure of 109 bytes each; the ToBeSigned bytes were confirmed
byte-equal for the first, third and fourth, the second was not reproduced again. That record is not
re-read here. On that basis we proposed that, for identifiers derived from a log, registrations with
identical ToBeSigned bytes be treated as registrations of the same statement. That is a proposal,
not consensus.

**OWN MEASUREMENT** with the package (27 September 2026): `verify.py` re-envelopes statement `01`
without tag 18 and with a parameter added to its unprotected header after signing; the signature
still verifies, the SHA-256 of the ToBeSigned value is unchanged, and the SHA-256 of the whole
COSE_Sign1 changes (330 bytes before, 354 after).

If this is not met, a relying party that finds the same statement through two transparency services
cannot tell that it is the same statement, and a reference written against one service does not
resolve in the other.

## A5. The leaf hash function is unambiguous

A verifier that recomputes a root from a statement and a proof computes the leaf hash the way the
transparency service computed it, from the text of the specification alone.

Origin: **OWN MEASUREMENT**, 22 September 2026, of draft-ietf-scitt-receipts-ccf-profile-04, section
2.1, against RFC 6962, section 2.1; the -05 revision was measured again on 26 September 2026.

**OWN MEASUREMENT**, 27 September 2026:

- draft-ietf-scitt-receipts-ccf-profile-05 at `e729c2ec`, section 2.1 "Merkle Tree Shape", md line
  123, Figure 2 "Merkle Tree Hash of a Single Entry": `MTH({d[0]}) = HASH(d[0]).` No 0x00 prefix.
  Md line 130, Figure 3 "Recursive Merkle Tree Hash":
  `MTH(D_n) = HASH(MTH(D[0:k]) || MTH(D[k:n])),`. No 0x01 prefix for interior nodes either.
- The same draft, section 2.2 "Transaction Components", md lines 161 to 163, Figure 5 "Transaction
  Serialization": `d[i] = internal-transaction-hash || HASH(internal-evidence) || data-hash`; md line
  158 states that the `ccf-leaf` CBOR array "is not what is hashed into the tree". This closes the
  question whether the leaf is hashed as a CBOR array or as the concatenation of its three parts.
- -04 at `54f887f0`, section 2.1, md line 126: the same `MTH({d[0]}) = HASH(d[0]).`; -04 has no
  serialization of d[i], the figure -05 adds as Figure 5.
- RFC 6962, section 2.1 "Merkle Hash Trees" (line 207 of the copy named above), line 233:
  `MTH({d(0)}) = SHA-256(0x00 || d(0)).`; line 239:
  `MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n])),`.
- draft-ietf-trans-rfc6962-bis-42 (read in place of RFC 9162), section 2.1.1 "Definition of the
  Merkle Tree" (line 375), line 401: `MTH({d[0]}) = HASH(0x00 || d[0]).`; line 407:
  `MTH(D_n) = HASH(0x01 || MTH(D[0:k]) || MTH(D[k:n])),`. That RFC 9162 section 2.1.1 reads the
  same is NOT MEASURED.
- The test `tests/test_merkle_zwei_lesarten_vektoren.py` in this repository, run on 27 September
  2026 at `31816e08`: 6 passed. It pins the root of the RFC 6962 reading, which this implementation
  follows, and the root of the doubly hashed reading, and they differ
  (`tools/measurements/merkle_two_readings.py`: `72458930...` against `b3ee65c5...`).

Limit: this is a measurement of document texts and of this implementation. It is not a claim about
CCF, and no vector in this repository is a CCF conformance vector.

If this is not met, two verifiers following the same specification compute different roots for the
same entries, and one of them rejects every valid receipt.

## Not required of a reference

- **A new relationship vocabulary.** A reference says which bytes it names, not how the referring
  statement relates to them. Origin: **CITATION**, our post to scitt@ietf.org of 22 September 2026.
- **A meaning of the relationship.** Origin: **CITATION**, Jon Geater on scitt@ietf.org in the same
  thread: "Registration Policies and Statement identification/linking are separate topics" (the
  time of that message is not recorded here).
- **Human readability.** Origin: **ASSESSMENT** (version 1, 23 September 2026).
- **Resolvability.** A reference need not say where the referenced bytes can be fetched. Origin:
  **ASSESSMENT** (version 1, 23 September 2026).

The package follows all four: its reference is `[digest algorithm, covered bytes, digest]` in a
private-use header parameter; the audit and the correction say in words in their payloads why they
refer to `01`, and no check reads those words.

## NOT MEASURED, NOT MEASURABLE

- The text of RFC 9943, RFC 9162, RFC 9052 and the IANA COSE registries: not reachable from the
  measuring environment (network policy); drafts and repository copies were read instead, and each is
  named above as what it is.
- The number of the last submitted revision of draft-ietf-scitt-architecture: the repository tags
  stop at -11; the Datatracker is not reachable.
- The behaviour of any running transparency service; nothing was registered anywhere.
- The mailing-list messages cited: taken from our own record, not re-read here.
