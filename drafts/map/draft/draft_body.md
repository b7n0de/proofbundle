---
title: Citing Signed Evaluation Receipts from Existing Envelopes
abbrev: Evaluation Receipt Mappings
docname: draft-gruszka-evaluation-receipt-mappings-01
v: 3
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
  - evaluation
  - receipt
  - DSSE
  - in-toto
  - SCITT
  - COSE
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: K. Gruszka
    name: Konrad Gruszka
    organization: b7n0de
    email: kontakt@b7n0de.com
    country: Germany
normative:
  RFC2119:
    title: "Key words for use in RFCs to Indicate Requirement Levels"
    author:
      - ins: S. Bradner
    date: 1997-03
    seriesinfo:
      BCP: "14"
      RFC: "2119"
    target: https://www.rfc-editor.org/info/rfc2119
  RFC8174:
    title: "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words"
    author:
      - ins: B. Leiba
    date: 2017-05
    seriesinfo:
      BCP: "14"
      RFC: "8174"
    target: https://www.rfc-editor.org/info/rfc8174
  RECEIPTS:
    title: "Signed Evaluation Receipts"
    author:
      - ins: K. Gruszka
    date: 2026-10
    seriesinfo:
      Internet-Draft: draft-gruszka-signed-evaluation-receipts-01
    target: https://datatracker.ietf.org/doc/draft-gruszka-signed-evaluation-receipts/
  DSSE:
    title: "DSSE: Dead Simple Signing Envelope, protocol specification, version 1.0.2"
    author:
      - org: Secure Systems Lab
    date: 2024-05-28
    target: https://github.com/secure-systems-lab/dsse/blob/v1.0.2/protocol.md
  RFC9052:
    title: "CBOR Object Signing and Encryption (COSE): Structures and Process"
    author:
      - ins: J. Schaad
    date: 2022-08
    seriesinfo:
      STD: "96"
      RFC: "9052"
    target: https://www.rfc-editor.org/info/rfc9052
  RFC9053:
    title: "CBOR Object Signing and Encryption (COSE): Initial Algorithms"
    author:
      - ins: J. Schaad
    date: 2022-08
    seriesinfo:
      RFC: "9053"
    target: https://www.rfc-editor.org/info/rfc9053
  RFC9995:
    title: "CBOR Object Signing and Encryption (COSE) Hash Envelope"
    author:
      - ins: O. Steele
      - ins: S. Lasker
      - ins: H. Birkholz
    date: 2026-07
    seriesinfo:
      RFC: "9995"
    target: https://www.rfc-editor.org/info/rfc9995
  RFC9597:
    title: "CBOR Web Token (CWT) Claims in COSE Headers"
    author:
      - ins: M. Prorock
      - ins: O. Steele
      - ins: R. Mahy
      - ins: H. Birkholz
    date: 2024-07
    seriesinfo:
      RFC: "9597"
    target: https://www.rfc-editor.org/info/rfc9597
  RFC9864:
    title: "Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)"
    author:
      - ins: M. B. Jones
      - ins: O. Steele
    date: 2025-10
    seriesinfo:
      RFC: "9864"
    target: https://www.rfc-editor.org/info/rfc9864
  RFC9679:
    title: "CBOR Object Signing and Encryption (COSE) Key Thumbprint"
    author:
      - ins: K. Isobe
      - ins: H. Tschofenig
      - ins: O. Steele
    date: 2024-12
    seriesinfo:
      RFC: "9679"
    target: https://www.rfc-editor.org/info/rfc9679
  RFC3986:
    title: "Uniform Resource Identifier (URI): Generic Syntax"
    author:
      - ins: T. Berners-Lee
      - ins: R. Fielding
      - ins: L. Masinter
    date: 2005-01
    seriesinfo:
      STD: "66"
      RFC: "3986"
    target: https://www.rfc-editor.org/info/rfc3986
  RFC8949:
    title: "Concise Binary Object Representation (CBOR)"
    author:
      - ins: C. Bormann
      - ins: P. Hoffman
    date: 2020-12
    seriesinfo:
      STD: "94"
      RFC: "8949"
    target: https://www.rfc-editor.org/info/rfc8949
  RFC9360:
    title: "CBOR Object Signing and Encryption (COSE): Header Parameters for Carrying and Referencing X.509 Certificates"
    author:
      - ins: J. Schaad
    date: 2023-02
    seriesinfo:
      RFC: "9360"
    target: https://www.rfc-editor.org/info/rfc9360
  RFC5280:
    title: "Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile"
    author:
      - ins: D. Cooper
      - ins: S. Santesson
      - ins: S. Farrell
      - ins: S. Boeyen
      - ins: R. Housley
      - ins: W. Polk
    date: 2008-05
    seriesinfo:
      RFC: "5280"
    target: https://www.rfc-editor.org/info/rfc5280
  RFC8017:
    title: "PKCS #1: RSA Cryptography Specifications Version 2.2"
    author:
      - ins: K. Moriarty
        role: editor
      - ins: B. Kaliski
      - ins: J. Jonsson
      - ins: A. Rusch
    date: 2016-11
    seriesinfo:
      RFC: "8017"
    target: https://www.rfc-editor.org/info/rfc8017
  DIDX509:
    title: "did:x509 Method Specification, method version 0 (status: draft)"
    author:
      - ins: M. Riechert
      - ins: A. Delignat-Lavaud
    date: 2026-10-06
    target: https://github.com/microsoft/did-x509/blob/054f1f6e364580c42fad862747903f2a6ee19976/specification.md
  CPB:
    title: "Canonicalization Declaration for SCITT Signed Statements"
    author:
      - ins: S. Mih
      - ins: A. Sokolov
    date: 2026-09-11
    seriesinfo:
      Internet-Draft: draft-mih-sokolov-scitt-payload-binding-05
    target: https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/05/
  PRML:
    title: "PRML: Pre-Registered ML Manifest Specification, Version 0.1"
    author:
      - ins: C. Öztürk
        role: editor
    date: 2026-05-01
    target: https://spec.falsify.dev/v0.1
  INTOTO-STATEMENT:
    title: "in-toto Attestation Framework: Statement layer, v1 (release v1.2.0)"
    author:
      - org: in-toto project
    date: 2026-03-18
    target: https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/statement.md
  INTOTO-RD:
    title: "in-toto Attestation Framework: ResourceDescriptor field type, v1 (release v1.2.0)"
    author:
      - org: in-toto project
    date: 2026-03-18
    target: https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/resource_descriptor.md
  INTOTO-DIGESTSET:
    title: "in-toto Attestation Framework: DigestSet field type, v1 (release v1.2.0)"
    author:
      - org: in-toto project
    date: 2026-03-18
    target: https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/digest_set.md
  VSA:
    title: "SLSA Verification Summary Attestation (VSA), version 1"
    author:
      - org: OpenSSF SLSA project
    target: https://slsa.dev/spec/v1.2/verification_summary
informative:
  RFC6979:
    title: "Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)"
    author:
      - ins: T. Pornin
    date: 2013-08
    seriesinfo:
      RFC: "6979"
    target: https://www.rfc-editor.org/info/rfc6979
  RFC3552:
    title: "Guidelines for Writing RFC Text on Security Considerations"
    author:
      - ins: E. Rescorla
      - ins: B. Korver
    date: 2003-07
    seriesinfo:
      BCP: "72"
      RFC: "3552"
    target: https://www.rfc-editor.org/info/rfc3552
  RFC7942:
    title: "Improving Awareness of Running Code: The Implementation Status Section"
    author:
      - ins: Y. Sheffer
      - ins: A. Farrel
    date: 2016-07
    seriesinfo:
      BCP: "205"
      RFC: "7942"
    target: https://www.rfc-editor.org/info/rfc7942
  RFC9942:
    title: "CBOR Object Signing and Encryption (COSE) Receipts"
    author:
      - ins: O. Steele
      - ins: H. Birkholz
      - ins: A. Delignat-Lavaud
      - ins: C. Fournet
    date: 2026-06
    seriesinfo:
      RFC: "9942"
    target: https://www.rfc-editor.org/info/rfc9942
  RFC9943:
    title: "An Architecture for Trustworthy and Transparent Digital Supply Chains"
    author:
      - ins: H. Birkholz
      - ins: A. Delignat-Lavaud
      - ins: C. Fournet
      - ins: Y. Deshpande
      - ins: S. Lasker
    date: 2026-06
    seriesinfo:
      RFC: "9943"
    target: https://www.rfc-editor.org/info/rfc9943
  STATEMENT-ID:
    title: "Requirements and Test Cases for Identifying SCITT Signed Statements"
    author:
      - ins: K. Gruszka
    date: 2026-10
    seriesinfo:
      Internet-Draft: draft-gruszka-scitt-statement-identification-01
    target: https://datatracker.ietf.org/doc/draft-gruszka-scitt-statement-identification/
  CAPSULE:
    title: "An Agent Action Capsule Profile for SCITT"
    author:
      - ins: S. Mih
    date: 2026-09-26
    seriesinfo:
      Internet-Draft: draft-mih-scitt-agent-action-capsule-05
    target: https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/05/
  PRML-PROFILE:
    title: "A SCITT Profile for Pre-Run Evaluation Criteria (PRML)"
    author:
      - ins: C. Öztürk
    date: 2026-09-11
    seriesinfo:
      Internet-Draft: draft-ozturk-scitt-prml-profile-00
    target: https://datatracker.ietf.org/doc/draft-ozturk-scitt-prml-profile/00/
  ABAK:
    title: "Claim-Preserving Exchange of AI Evaluation Evidence"
    author:
      - ins: A. T. Abak
    date: 2026-09-23
    seriesinfo:
      Internet-Draft: draft-abak-ai-evaluation-claim-preservation-00
    target: https://datatracker.ietf.org/doc/draft-abak-ai-evaluation-claim-preservation/00/
  INTOTO-ENVELOPE:
    title: "in-toto Attestation Framework: Envelope layer, v1 (release v1.2.0)"
    author:
      - org: in-toto project
    date: 2026-03-18
    target: https://github.com/in-toto/attestation/blob/v1.2.0/spec/v1/envelope.md
  TEST-RESULT:
    title: "in-toto Attestation Framework: Test Result predicate, v0.1 (release v1.2.0)"
    author:
      - org: in-toto project
    date: 2026-03-18
    target: https://github.com/in-toto/attestation/blob/v1.2.0/spec/predicates/test-result.md

--- abstract

A Signed Evaluation Receipt records one evaluation result as signed
payload bytes B. This document describes how existing envelopes cite such
a receipt by the SHA-256 digest of B, and how a DSSE envelope carries B
with the receipt's own signature. It fixes those bytes and a
matching rule, maps the parts of a receipt onto DSSE, the in-toto Statement
with the test-result predicate and the SLSA Verification Summary
Attestation, shows that the signature of a receipt is already a valid DSSE
signature, gives a SCITT Signed Statement that names a receipt only by its
digest, in a key profile and a certificate profile, declares the receipt digest as an artifact type
for typed digest references, and relates a receipt to a pre-run criteria set
written in PRML. It defines no new format and no new predicate.

--- middle

# Introduction

A Signed Evaluation Receipt (receipt) {{RECEIPTS}} holds one assertion, whether
a threshold held for a metric of a test suite, as payload bytes B. B is signed
with Ed25519 over a pre-authentication encoding with a fixed type. A receipt
carries no inclusion proof and does not prove registration with a Transparency
Service. In SCITT, transparency additionally requires registering a Signed
Statement that names the receipt and verifying the resulting SCITT Receipt
({{cose}}).

Other parties will want to refer to a receipt from the envelopes they already
use: a DSSE envelope, an in-toto Statement, a SLSA Verification Summary, or a
SCITT Signed Statement. This document is the third part of one line of work:
{{STATEMENT-ID}} asks how a signed statement is named unambiguously,
{{RECEIPTS}} fixes the bytes of a receipt, and this document shows how existing
envelopes cite such a receipt by digest.

It also relates a receipt to a criteria set fixed before the run in PRML
{{PRML}} ({{prml}}), and says where it meets the requirements of {{ABAK}} for
exchanging evaluation evidence ({{abak}}).

This document defines no second receipt format, no new in-toto predicate and no
new COSE header parameter. What a receipt does not prove stays unproven when an
envelope cites it ({{non-claims}}).

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

The terms receipt, B, Issuer, Receiver and type are used as in {{RECEIPTS}}.
The type is the fixed string

~~~
application/vnd.signed-evidence.eval-receipt+json
~~~

The type identifies B ({{RECEIPTS}} Section 10.1). The receipt object uses the
same fixed string as its schema discriminator, but is a different JSON
representation.

Receipt digest:
: SHA-256 over B ({{digest}}).

Citation:
: A hash algorithm and a digest value that an envelope carries to name a
  receipt.

Citing envelope:
: An in-toto Statement or a COSE Signed Statement that carries a citation. A
  DSSE envelope carries B itself, not a citation ({{dsse}}).

# The Receipt Digest {#digest}

## Definition {#digest-definition}

The receipt digest is SHA-256 over B, the payload bytes of the receipt as
defined in {{RECEIPTS}} Section 3.4: the bytes that steps 1 to 3 of
{{RECEIPTS}} Section 5 obtain from `payload_b64`. A candidate for which one of
those steps fails has no B, even if a lenient decoder would produce bytes from
it (cases C6 and C7). It is not computed over the receipt bytes or over
PAE(type, B). An envelope that carries the
digest as text uses its 64 lowercase hexadecimal digits; one that carries it as
bytes uses the 32 bytes. This document defines no other hash algorithm.

## Why B {#why-b}

The digest runs over B for two reasons.

* B is what is signed. The signing input PAE(type, B) depends on B alone,
  because the type is fixed ({{RECEIPTS}} Section 4.2). A digest over B
  therefore names exactly the signed content; a digest over the signing input
  would carry no further information.
* The receipt bytes are not stable. The receipt object around B is not
  canonicalized, and its key hint is not signed. Vectors P1, P4 and P6 of
  {{RECEIPTS}} are three different receipt byte strings that all verify and
  all carry the same B (cases C1 to C3 of {{cases}}). A digest over the
  receipt bytes would give one signed statement three names, and it would
  change whenever the receipt object is written again. In-toto resource
  descriptors and the COSE Hash Envelope each name content by the digest of
  its bytes, and a DSSE envelope carries the bytes themselves.

The price of this choice: the receipt digest identifies the signed content, not
the signature and not the key. Two receipts with the same B under different
keys have the same digest. The `iss` and `kid` of a citing Signed Statement
({{signed-statement}}) identify its signer, which need not be the receipt
signer. This mapping does not encode a constraint on the receipt signer. A
Receiver verifies the cited receipt under the receipt key it fixed
independently.

## Matching Rule {#matching}

Given a citation and a candidate receipt, the result is computed as follows.

1. If the citation's algorithm is not SHA-256, or its value is not 32 bytes (64
   lowercase hexadecimal digits in text form), the result is INDETERMINATE.
   SHA-256 is named `sha256` as the key of an in-toto digest set {{INTOTO-DIGESTSET}}, -16 as the
   value of COSE header parameter 258, and `sha-256` as the algorithm label of
   the examples ({{examples}}); each name counts only in its own carrier, and
   names are compared exactly, so `SHA256` is none of them. A typed digest
   reference names it `SHA-256` ({{typed-reference}}). A digest set with several
   entries is matched on its `sha256` entry alone; this document does not judge
   the other entries. This is narrower than the matching guidance of
   {{INTOTO-DIGESTSET}}, under which two digest sets match if any acceptable
   field matches: here a digest set without a `sha256` entry gives
   INDETERMINATE, and one whose `sha256` entry passes step 1 but differs from
   SHA-256 over B gives NO_MATCH, whatever its other entries are.
2. If steps 1 through 3 of {{RECEIPTS}} Section 5 do not all complete
   successfully, including when processing stops at a resource limit, B is not
   obtained and the result is INDETERMINATE.
3. Otherwise the result is MATCH when SHA-256 over B equals the cited value,
   and NO_MATCH when it does not.

A MATCH establishes neither that the candidate verifies, nor who signed it, nor
that its assertion is true. A Receiver that relies on a cited receipt runs the
full procedure of {{RECEIPTS}} Section 5 under a key it fixed. Case C5 is a
candidate that matches and fails that procedure at step 11.

@@CASES_TABLE@@

## Against the Identification Requirements {#requirements}

{{STATEMENT-ID}} proposes requirements A1 to A5 for references to signed
statements. This section checks the receipt digest against them. It is the
author's analysis, not a conformance claim.

A1, unambiguous target and matching rule:
: The scheme names the hash algorithm (SHA-256), the input bytes (B, as steps 1 to
  3 of {{RECEIPTS}} Section 5 obtain it from `payload_b64`) and the encoding (64 lowercase hexadecimal digits or 32
  bytes). {{matching}} is the matching rule. An unsupported algorithm or a
  candidate without B gives INDETERMINATE, never MATCH (C6 to C8). Identity is
  preserved under every difference outside B that leaves steps 1 to 3 of
  {{RECEIPTS}} Section 5 succeeding: the receipt's whitespace and
  escapes, its key hint, and its signature value. In the
  terms of {{STATEMENT-ID}} Section 5 the receipt digest is a digest of the
  payload. Because the type is fixed and nothing else enters the signature, it
  also determines the signing input; neither names the signer.

A2, readable without interpreting the carrier's payload:
: In the COSE Hash Envelope of {{signed-statement}} the citation is read from
  header parameters 258 and 259 and the payload, as {{RFC9995}} defines them,
  without interpreting application content. In an in-toto Statement the
  citation lies inside the predicate, which is the Statement's application
  content; a reader has to know the predicate to find it. A2 is met by the
  first and not by the second.

A3, matching independent of registration:
: B does not change when the receipt is registered anywhere or its object is
  written again. Cases C2 and C3 carry other receipt bytes and still match.

A4, acceptance test for A3:
: Cases C2 and C3 apply local changes that a re-encoding may cause (another
  JSON escape, a key hint left out), and the result stays MATCH. This is not
  a measurement of registration in two services.

A5, receipt-verification dependency:
: Matching does not depend on a leaf hash or a COSE Receipt. A receipt has no
  inclusion proof of its own; a Transparency Service that registers a
  statement naming it fixes its own leaf construction, and matching does not
  use it.

# Mapping to Existing Envelopes {#mapping}

{{mapping-table}} shows, for each part of a receipt, where it has a place in three
envelopes and what that envelope does not have: DSSE {{DSSE}}, the in-toto
Statement v1 {{INTOTO-STATEMENT}} with the test-result predicate v0.1
{{TEST-RESULT}} (test-result in the table), and the SLSA Verification Summary
Attestation v1 {{VSA}} (VSA). "None" means that the envelope has no field for
it. This document defines no predicate of its own.

| Receipt part | Envelope | Field there, or what is missing |
|---|---|---|
| B | DSSE | `payload`, base64 of B |
| | test-result | none; a Statement that restates the members is other bytes |
| | VSA | none; `inputAttestations[].digest` names B by its digest |
| type | DSSE | `payloadType` |
| | test-result | none; the Statement's envelope carries an in-toto type |
| | VSA | `inputAttestations[].mediaType` |
| `signature.sig` | DSSE | `signatures[].sig`, the same bytes (vector M1) |
| | test-result | none; the Statement's envelope carries a new signature |
| | VSA | none; the VSA is signed by its verifier |
| `signature.alg` | DSSE | none; DSSE names no signature algorithm |
| | test-result, VSA | none |
| `signature.key` | DSSE | `keyid`, optional and not signed |
| | test-result, VSA | none |
| `passed` | DSSE | inside B |
| | test-result | `result` PASSED or FAILED; WARNED has no receipt counterpart |
| | VSA | none; `verificationResult` is the verifier's result |
| payload `schema` | DSSE | inside B |
| | test-result | none; `predicateType` names test-result, not the payload schema |
| | VSA | none |
| `suite`, `suite_version` | DSSE | inside B |
| | test-result | no field of its own; `configuration` or `url` can name the suite |
| | VSA | none |
| `metric`, `comparator`, `threshold`, `score`, `n` | DSSE | inside B |
| | test-result, VSA | none |
| `criteria_digest`, when present | DSSE | inside B |
| | test-result, VSA | none |
| `model_id_commit`, `dataset_id_commit`, `commit_alg` | DSSE | inside B |
| | test-result | none; `subject` wants a digest of the artifact, and a commitment is not one |
| | VSA | none; `subject` and `resourceUri` name the verified artifact |
| `timestamp` | DSSE | inside B |
| | test-result | none |
| | VSA | none; `timeVerified` is the verifier's time |
{: #mapping-table title="Receipt parts in three envelopes"}

In the other direction, a receipt has no counterpart for the required VSA
fields `verifier`, `resourceUri`, `policy` and `verifiedLevels`, for its
optional `timeVerified`, or for the `subject` of an in-toto Statement.

## DSSE {#dsse}

The signature of a receipt is a valid DSSE signature without any new signature.
DSSE {{DSSE}} signs PAE(payloadType, payload) with the same pre-authentication
encoding that {{RECEIPTS}} Section 4.1 defines. The envelope

~~~
{"payloadType": <type>, "payload": <base64 of B>,
 "signatures": [{"sig": <the receipt's signature.sig>}]}
~~~

therefore verifies as DSSE under the Issuer's key when `payloadType` is exactly
the type and `payload` decodes to B. Vector M1 ({{examples}}) gives the bytes;
its signature is the signature of vector P1 of {{RECEIPTS}}, byte for byte. M1
leaves out `keyid`, which DSSE treats as an optional, unauthenticated hint.

A successful DSSE signature check alone is not a receipt verdict. DSSE also
requires a supported `payloadType` and parsing the authenticated payload
according to that type. To obtain a receipt verdict, a Receiver decodes the
payload and the selected signature once, uses those same bytes to construct the
receipt object with canonical base64 as required by {{RECEIPTS}} Section 3.1,
and runs {{RECEIPTS}} Section 5 under its independently selected receipt
verification key.

The signature is expected to be valid as DSSE only under this `payloadType`,
because Ed25519 binds the exact signing input; this is not measured beyond
sample types. Vector N7 of {{RECEIPTS}} shows the converse for the receipt
itself: its signature, made over PAE with the type
`application/vnd.example.other+json`, fails under the fixed type.

## in-toto Statement with test-result {#test-result}

The test-result predicate {{TEST-RESULT}} records `result` (PASSED, WARNED or
FAILED), `configuration` (a required list of resource descriptors), `url`, and
the lists `passedTests`, `warnedTests` and `failedTests`. A Statement
{{INTOTO-STATEMENT}} that restates a receipt maps `passed` to `result` PASSED
or FAILED. No member of the predicate carries the metric, the comparator, the
threshold, the score, the sample count or the timestamp; `passedTests` and
`failedTests` are lists of test names, not a count. The Statement's `subject`
names the tested artifact by digest; a commitment is not a digest of the
artifact's bytes, so the model commitment cannot stand as `subject` without
changing what `subject` means.

Such a Statement is a new statement by whoever signs its envelope
{{INTOTO-ENVELOPE}}. It does not carry the receipt's signature and the
predicate has no member for the evidence a result rests on. This document
therefore does not cite receipts from test-result; the mapping states what a
party loses when it restates a receipt in that form.

## SLSA Verification Summary {#vsa}

A Verification Summary Attestation {{VSA}} states that a verifier verified an
artifact against a policy. Its `inputAttestations` is a list of resource
descriptors {{INTOTO-RD}}, each of which carries a digest of the attestation it names. A
verifier that used a receipt as evidence when it verified an artifact, for
example the evaluated model, and verified the receipt under {{RECEIPTS}}
Section 5, cites the receipt there; the artifact itself is the VSA's
`subject`:

~~~
{"digest": {"sha256": "<receipt digest, 64 hex digits>"},
 "mediaType": "application/vnd.signed-evidence.eval-receipt+json"}
~~~

The `mediaType` identifies B. `verificationResult`
is the verifier's result under its policy, not the receipt's `passed`: a
receipt that verifies and records `passed` false (vector P2 of {{RECEIPTS}})
can be the input of a VSA whose `verificationResult` is PASSED, when the
verifier's policy asks only for a valid receipt.

# COSE and SCITT {#cose}

A Signed Evaluation Receipt is not a COSE Receipt. Its format is JSON with
Ed25519 over PAE, not COSE; it carries no inclusion proof, and no Transparency
Service or Registration Policy {{RFC9943}} takes part in making it. In SCITT,
a Transparency Service registers a Signed Statement and returns a COSE Receipt
{{RFC9942}} proving its inclusion.

Two existing constructions carry the receipt digest without a new field: a
typed digest reference ({{typed-reference}}) and a Signed Statement whose
payload is the digest ({{signed-statement}}). Both name the receipt; neither
carries it.

## A Typed Digest Reference {#typed-reference}

{{CPB}} Section 8 defines a typed digest reference with the members `type`,
`purpose`, `digest_alg` and `digest`, and leaves the declaration of artifact
types to the profiles that accept them ({{CPB}} Section 8.1). This document
declares one artifact type for the receipt digest:

* `type` is `application/vnd.signed-evidence.eval-receipt+json`, the type,
  which identifies B;
* there is one digest context, so `purpose` is absent;
* the context has no purpose label, so a reference that carries `purpose` is
  Unresolved ({{CPB}} Section 8.1);
* the canonicalization algorithm is `as-transmitted` ({{CPB}} Section 4.4),
  with the byte-boundary selector {{RECEIPTS}} Section 3.4, "The Bytes B";
* the hash function is SHA-256, and `digest_alg` is exactly `SHA-256`;
* `digest` is the receipt digest as its 64 lowercase hexadecimal digits, a
  text value; in the `cpb-refs` header parameter of {{CPB}} Section 8.3 it is
  a text string.

A reference under this declaration can stand in the `cpb-refs` header
parameter of a Signed Statement, or in a payload that carries references in
its own serialization, for example in the `references` of {{CAPSULE}}. A
verifier obtains B by steps 1 to 3 of {{RECEIPTS}} Section 5, computes
SHA-256 over it and compares the hexadecimal text. A candidate without B
cannot be obtained as the cited artifact, which {{CPB}} Section 8.1 calls
Unresolved; it corresponds to INDETERMINATE in {{matching}}. For a reference
under this declaration, a `digest_alg` other than `SHA-256`, a `digest` that is
not a text value of 64 lowercase hexadecimal digits, and a `digest` that differs
from SHA-256 over B are Failed ({{CPB}} Section 8.1); the matching rule of
{{matching}} gives INDETERMINATE for the first two and NO_MATCH for the third,
because it also reads citations outside a typed digest reference. Vectors R1 to
R6 ({{reference-vectors}}) give a reference in each of these states. A consuming
profile that does not name this declaration by normative reference leaves
every such reference Unresolved ({{CPB}} Section 8.1); no profile names it at
the time of writing.

Only the digest crosses, as for the Signed Statement below. A reference that
is Verified shows that the cited bytes are B; it does not show that the
receipt verifies, who signed it, or that its assertion is true ({{CPB}}
Section 8.5).

## A Signed Statement that Cites a Receipt {#signed-statement}

A Signed Statement that cites a receipt is a COSE_Sign1 {{RFC9052}} with CBOR
tag 18 in the form of a COSE Hash Envelope {{RFC9995}}. It has one of two
profiles, which differ in how the statement names its signer. In the key
profile, `kid` names an Ed25519 statement key that the Receiver has configured
for the issuer. In the certificate profile, the protected header carries an
X.509 certificate chain {{RFC9360}} whose last certificate is a trust anchor
that the Receiver has configured for a did:x509 issuer {{DIDX509}}. The labels
of the protected header select the profile (step 2 of {{check-statement}}).
Vector M2 ({{examples}}) is a statement in the key profile, vector X1 one in the
certificate profile.

Both profiles share these rules:

* The protected header holds exactly the parameters of its profile, given
  below, and no other. Three of them are the same in both profiles:
  * 15 (CWT Claims) {{RFC9597}}: a map with exactly 1 (`iss`), whose form
    each profile gives, and 2 (`sub`), the text value of `model_id_commit` of
    B;
  * 258 (payload hash algorithm): -16 (SHA-256);
  * 259 (preimage content type): the type, as a text string.
* The unprotected header is the empty map.
* The payload is the receipt digest, 32 bytes.
* The COSE_Sign1, its protected header included, is encoded with the core
  deterministic encoding of {{RFC8949}} Section 4.2.1.

Key profile. The protected header holds exactly the five parameters 1, 4, 15,
258 and 259:

* 1 (alg): -19, Ed25519 as fully specified in {{RFC9864}}, or -8, EdDSA
  {{RFC9053}}. A party that makes a statement MUST write -19. A Receiver MUST
  accept both values and applies every other check of {{check-statement}} to
  either; under the Ed25519 statement keys that step 3 selects, both values
  select the same signature algorithm. Changing alg changes the protected
  header bytes and requires a new signature ({{alg-choice}});
* 4 (kid): the COSE Key Thumbprint {{RFC9679}} with SHA-256 of the statement
  key, a byte string of 32 bytes. For an Ed25519 public key x, kid is SHA-256
  over the core-deterministically encoded COSE_Key map `{1: 1, -1: 6, -2: x}`;
  no optional COSE_Key parameter enters the thumbprint;
* 15 (CWT Claims): `iss` is an absolute URI ({{RFC3986}} Section 4.3) that
  names the party that makes the statement.

Its form is fixed, so that one receipt digest, one statement key, one issuer
and one algorithm value give one byte string.

Certificate profile. The protected header holds exactly the six parameters 1,
4, 15, 33, 258 and 259:

* 1 (alg): -7, ECDSA with SHA-256 ({{RFC9053}} Section 2.1); the signature is
  r and s, 32 bytes each, under the P-256 public key of the leaf certificate
  ({{alg-choice}});
* 4 (kid): SHA-256 over the DER encoding of the SubjectPublicKeyInfo
  {{RFC5280}} of the leaf certificate, a byte string of 32 bytes;
* 15 (CWT Claims): `iss` is a did:x509 identifier {{DIDX509}} of exactly the
  form `did:x509:0:sha256:` F `::eku:` O, where F is SHA-256 over the DER bytes
  of the last certificate of x5chain, encoded in base64url without padding (43
  characters), and O is an object identifier in dotted decimal form: the first
  arc is 0, 1 or 2, it is followed by one or more further arcs, the arcs are
  separated by full stops, and each arc is a decimal number without leading
  zeros;
* 33 (x5chain) {{RFC9360}}: an array of exactly two byte strings, each a
  DER-encoded X.509 certificate {{RFC5280}}: first the leaf certificate, whose
  P-256 public key verifies the statement signature, then the trust anchor
  certificate, whose RSA public key signed the leaf certificate with
  sha256WithRSAEncryption (RSASSA-PKCS1-v1_5 with SHA-256, {{RFC8017}}).

This profile names one trust anchor and no intermediate certificate. An
x5chain array with more or fewer than two elements, an x5chain that is a single
byte string, and an iss with a predicate other than one eku give outside_profile
in step 2 of {{check-statement}}. Certificate contents, key restrictions and
their bindings are checked in step 3, which gives untrusted_key when one of
those checks fails. An ECDSA signature depends on a per-signature nonce, so one
statement in this profile can have more than one byte string; the vectors use
the deterministic nonce of {{RFC6979}}, which a Receiver does not check.

The value of `sub` is a choice of this example; the receipt digest does not
depend on it. The key that signs a statement and the receipt key can be the
same key or different keys. The statement carries its own signature over its own
Sig_structure; it is not the receipt's signature, even when one key makes both.
Registering M2 or X1 with a Transparency Service yields a COSE Receipt for that
statement, not for the evaluation receipt.

### Making a Statement {#make-statement}

A party makes a statement for a receipt only after the receipt has passed the
verification procedure of {{RECEIPTS}} Section 5 under a key that party fixed.
A receipt that fails it gives no statement. The party computes the receipt
digest over B, takes `sub` from the `model_id_commit` of B, writes the
protected header of one profile, signs the Sig_structure of {{RFC9052}} Section
4.4 with an empty external_aad, under the statement key in the key profile and
under the private key of the leaf certificate in the certificate profile, and
encodes the COSE_Sign1.

### Checking a Statement {#check-statement}

The Receiver holds the statement, a candidate receipt, its independently
selected receipt verification key, and configured pairs. A pair for the key
profile is an issuer URI with an Ed25519 statement key; a pair for the
certificate profile is a did:x509 identifier with a trust anchor certificate.
The received iss value does not establish either association. It applies the following steps in order. The first step that fails gives the status named in
it, and the statement is refused; only a statement that passes every step is
accepted. A Receiver that stops because it reached a resource limit, in any
step, reports a resource-limit error; that is no status, and the statement is
not accepted.

1. If the bytes are not one CBOR data item in the deterministic encoding, if
   the item is not a COSE_Sign1, or if its protected header is not a map in
   the deterministic encoding, the status is malformed. A data item that is
   well-formed but not valid under {{RFC8949}} Section 5.3.1, such as a text
   string that is not valid UTF-8 or a map with duplicate keys, is malformed;
   two keys are duplicates only when they are equal under the key equivalence
   of {{RFC8949}} Section 5.6.1, so the integer 1 and true are two keys and 0.0
   and -0.0 are one. For the choices that {{RFC8949}} Section 4.2.2 leaves to a
   protocol, step 1 uses these: a NaN is in the deterministic encoding only as
   the half-precision quiet NaN 0xf97e00, and any other encoding of a NaN is
   malformed; no tag adds a rule of its own, so the content of a tag, a bignum
   included, is checked like any other data item. Step 1 does not check whether
   the content of a tag inside
   the COSE_Sign1 is valid for that tag ({{RFC8949}} Section 5.3.2); the data
   items inside a tag are checked like any other data item. For step 1, the
   COSE_Sign1 check concerns only the outer tag, the four-element array and its
   element types:
   a wrapping in a CBOR tag other than 18 is not a COSE_Sign1 and is malformed,
   and an otherwise valid COSE_Sign1 without a tag goes on to step 2 and is
   outside_profile there. The protected-header byte string is decoded as a
   CBOR map, with the empty byte string treated as an empty map ({{RFC9052}}
   Section 3), which fails in step 2. CBOR validity and deterministic encoding
   are checked before step 2. Header label types are checked only in step 2; a
   header label that is not a label of either profile gives outside_profile if
   step 1 succeeds.
2. A Transparent Statement {{RFC9943}} carries COSE Receipts {{RFC9942}} in
   its unprotected header under label 394. If the unprotected header holds
   label 394 and no other label, and the value of 394 is an array of one or
   more byte strings, the Receiver removes label 394 and applies the rest of
   this step and the following steps with the empty unprotected header; the
   protected header, the payload and the signature stay as they are. These
   steps do not read the receipts.

   The labels of the protected header select the profile: exactly the integer
   labels 1, 4, 15, 258 and 259 select the key profile, and exactly the integer
   labels 1, 4, 15, 33, 258 and 259 select the certificate profile. If the item
   is not tagged 18, the unprotected header is not empty, or the labels select
   neither profile, the status is outside_profile.

   In both profiles, kid is a byte string of 32 bytes; 15 is a map with exactly
   the integer labels 1 (iss) and 2 (sub), both text strings; 258 is the
   integer -16; and 259 is the type as a text string. In the key profile, alg
   is the integer -19 or -8, and iss is an absolute URI. In the certificate
   profile, alg is the integer -7, iss has the syntactic form given in
   {{signed-statement}}, and x5chain is an array of exactly two byte strings.
   This step checks only the syntax of iss and the container form of x5chain;
   the certificate contents, key properties, and the bindings of iss and kid
   are checked in step 3. A violation of these structural rules, a detached
   payload, a payload that is not 32 bytes, or a signature that is not 64 bytes
   gives outside_profile. sub MUST match sha256: followed by exactly 64
   lowercase hexadecimal digits; otherwise the status is outside_profile.
   Step 7 compares sub byte for byte with model_id_commit of B.
3. Key profile. A configured pair counts only if its statement key is 32
   octets and its point A meets rules 1 and 2 of {{RECEIPTS}} Section 4.4: A
   is a canonical encoding of a point of order L. A point of small order or of
   mixed order does not count. If no configured pair that counts has both an
   issuer URI exactly equal to iss and a statement key whose SHA-256 COSE Key
   Thumbprint equals kid, the status is untrusted_key. Subsequent signature
   verification uses only keys selected by this pairwise match.

   Certificate profile. A configured pair counts only if its identifier is
   exactly equal to iss, its trust anchor certificate is byte for byte the
   second certificate of x5chain, and F of iss is SHA-256 over that
   certificate. The status is untrusted_key if no configured pair counts, or if
   any of the following does not hold: both certificates are DER-encoded X.509
   certificates; the public key of the trust anchor is an RSA key with a
   modulus of at least 2048 bits; the leaf certificate is signed by that key
   with sha256WithRSAEncryption; the issuer name of the leaf certificate is
   byte for byte the subject name of the trust anchor; the extended key usage
   of the leaf certificate contains O of iss; the public key of the leaf
   certificate is a P-256 key; and kid is SHA-256 over its
   SubjectPublicKeyInfo. This step is not certification path validation
   ({{RFC5280}} Section 6) and does not resolve iss as a DID: it evaluates no
   validity period, revocation status, name constraint, certificate policy or
   other extension. {{DIDX509}} requires path validation for resolution. An
   application that additionally performs path validation reports its result
   separately from the status of this procedure and may refuse to use a
   statement whose status is accepted.
4. Key profile. If the signature does not meet the four rules of {{RECEIPTS}}
   Section 4.4 under a key that step 3 selected, with the Sig_structure of
   {{RFC9052}} Section 4.4 in place of PAE(type, B) in rule 4, the status is
   signature_invalid.

   Certificate profile. Read r and s as unsigned big-endian integers from the
   first and the last 32 bytes of the signature. If r or s is not in the range
   1 to n-1, where n is the order of the P-256 base point, or the signature is
   not a valid ECDSA signature with SHA-256 over the Sig_structure under the
   public key of the leaf certificate, the status is signature_invalid.
5. Run the verification procedure of {{RECEIPTS}} Section 5 under the
   Receiver's receipt key. Continue to step 6 only if it returns PASS. If it
   returns FAIL, the status is receipt_not_verified. If it stops with a
   resource-limit error, propagate that error and stop without accepting the
   statement.
6. If the payload is not the receipt digest of the candidate, the status is
   digest_mismatch.
7. If `sub` is not the `model_id_commit` of B, the status is subject_mismatch.

If every step passes, the status is accepted. Vector M2 with vector P1 of
{{RECEIPTS}} is accepted, and {{status-vectors}} gives a statement for each
other status. Vector X1 with P1 is accepted under the certificate pair of
{{certificate-vectors}}, and X2 to X6 fail at steps 2, 3 and 4 in the
certificate profile. Vectors T1 to T5 ({{transparent-vectors}}) are
Transparent Statements: T1 and T2 are accepted, and T3 to T5, whose
unprotected headers hold more than the receipts or the receipts in another
form, are outside_profile.

Steps 1 to 4 do not use the receipt. For the key profile, a general COSE
verifier that implements the statement's alg value checks the signature under
the rules of its own Ed25519 implementation, which can accept a signature that
step 4 refuses, for example one whose R is a point of small order. For either
profile, a COSE signature check alone does not apply steps 5 to 7, and its
success does not show that the statement cites a receipt that verifies.

### What Crosses and What Is Lost {#crossing}

| Receipt | Signed Statement |
|---------|------------------|
| B | only its receipt digest, as the payload |
| `model_id_commit` of B | `sub` (2) of the CWT Claims |
| the type | parameter 259 |
| the other members of B (`schema`, `suite`, `suite_version`, `metric`, `comparator`, `threshold`, `score`, `passed`, `n`, `dataset_id_commit`, `commit_alg`, `timestamp`), including `criteria_digest` when present | not carried; named only through the digest |
| the receipt's signature and its key hint | not carried |
| (none) | `iss`, `kid`, `alg` and, in the certificate profile, `x5chain`: the statement of the party that signs it |
{: #crossing-table title="What a Signed Statement carries of a receipt"}

A Receiver that relies on the assertion of a receipt needs the receipt itself;
the statement only names it.

### Choice of alg {#alg-choice}

In the key profile, value -19 is the fully specified Ed25519 identifier of
{{RFC9864}}, which sets the polymorphic EdDSA identifier -8 of {{RFC9053}} to
Deprecated. A party that
makes a statement therefore writes -19 only. Every Receiver accepts -8 as well,
for statements made before a producer moved to -19 and for general COSE
verifiers that implement -8 but not -19 ({{impl}}), so that one statement gives
one status. -8 names EdDSA for any curve; step 3 of {{check-statement}} counts
only Ed25519 statement keys, so a statement with -8 under any other key is
untrusted_key. Vector S1 ({{status-vectors}}) is M2 with alg -8, signed again
under the same key; it is accepted.

The certificate profile fixes -7. {{RFC9864}} also sets -7 to Deprecated and
registers -9 (ESP256) for ECDSA with SHA-256 on P-256. The certificate profile
describes the form that was registered and verified in the measurements of
{{impl}}, and that form carries -7; a statement with -9 is outside the
certificate profile (vector X2). -7 does not name a curve; step 3 counts only a
P-256 leaf key, so -7 selects one signature algorithm here.

The payload follows the pattern of the hash-only mode of {{PRML-PROFILE}}: the
32 raw octets of a SHA-256, carried as a byte string and not as hexadecimal
text. That profile leaves open how a verifier tells such a payload from a full
one, and names a COSE header parameter that declares the digest algorithm as
one candidate. Header parameters 258 and 259 of {{RFC9995}}, used here, are
such a declaration.

# Criteria Sets in PRML {#prml}

PRML {{PRML}} serializes an evaluation claim fixed before the run: a metric, a
comparator, a threshold, a dataset content hash and a seed, in canonical YAML
whose SHA-256 is the manifest hash. A receipt records one result after the run.
A receipt names a criteria set at most through its optional `criteria_digest`
({{RECEIPTS}} Section 3.5). When the criteria set is a PRML manifest, the bytes
that PRML fixes for it are its canonical bytes, whose SHA-256 is the manifest
hash, and `criteria_digest` over them is `sha256:` followed by the manifest
hash. {{prml-table}} maps the members of a PRML
manifest, version 0.1, onto a receipt.

| PRML | Receipt | Lost or changed |
|---|---|---|
| `version` | none | which PRML rules apply |
| `claim_id` | none | the claim and its amendment chain; only one manifest is named, by `criteria_digest` |
| `created_at` | none | `timestamp` is when the Issuer states the evaluation ran, not when the criteria were written |
| `metric` | `metric` | nothing when the string is copied exactly |
| `comparator` | `comparator` | `==` has no counterpart; such a claim has no receipt |
| `threshold` | `threshold` | a number becomes a decimal string; the rule below compares values |
| `dataset.id`, `dataset.hash` | `dataset_id_commit` | the content hash; the receipt commits to an identifier with a salt, not to the content |
| `seed` | none | the seed |
| `producer` | none | the producer; the receipt names no issuer, the Receiver fixes the key |
| `model` | `model_id_commit` | the clear identifier; checking an opening requires the salt and identifier |
| `prior_hash`, `metric_args`, `code`, `notes` | none | all of them |
| none | `suite`, `suite_version`, `score`, `passed`, `n`, `timestamp` | a manifest has no result |
{: #prml-table title="A PRML manifest and a receipt"}

A Receiver that holds a receipt and a PRML manifest compares them as follows
and reports the two results separately.

1. Run the procedure of {{RECEIPTS}} Section 5 under the Receiver's receipt
   key. Continue only if it returns PASS. If it returns FAIL, do not perform
   the comparison. If it stops with a resource-limit error, propagate that
   error and stop without reporting binding or agreement results.
2. The manifest is canonicalized as {{PRML}} Section 3 requires, and its
   manifest hash is computed. A manifest that PRML rejects is not compared.
3. Binding. The result is BOUND when the receipt carries `criteria_digest`
   and it equals `sha256:` followed by the manifest hash, and UNBOUND
   otherwise.
4. Agreement. The result is AGREE when `metric` is the same string in both,
   `comparator` is the same and is not `==`, and the receipt's `threshold`
   and the manifest's threshold are the same decimal number, the manifest's
   value read as the decimal that its canonical rendering denotes (so `0.8`
   in the manifest and `0.800` in the receipt agree, and
   `0.80000000000000001` in the receipt does not). Otherwise it is DIFFER.

BOUND says that the Issuer states this result belongs to that manifest; AGREE
says that the two documents state the same metric, comparator and threshold.
Neither result shows that the manifest existed before the run, which needs a
time-anchored record of the manifest, such as a registration under
{{PRML-PROFILE}}, and evidence of when the run began. Neither shows that the
dataset with the manifest's content hash was the one evaluated, or that the
seed was used.

# Relation to Claim-Preservation Requirements {#abak}

{{ABAK}} states format-neutral requirements for converting and consuming
evaluation evidence. This document addresses parts of these requirements for
the conversions it describes; the correspondences below are not a conformance
claim. {{mapping-table}} and {{prml-table}} name what each envelope or
document loses, in the sense of its requirement R-CP-9.
{{matching}} gives INDETERMINATE when B cannot be obtained or the algorithm is
unknown, never a match (R-CP-8, R-CP-10). {{non-claims}} keeps the result of a
verifier or of a registration apart from the receipt's `passed`, and claims no
order of criteria and run (R-CP-5, R-CP-11). It does not meet the requirements
on coverage and attempts (R-CP-6) or on records of a mapping instance
(R-CP-1): a receipt has no field for them, and this document defines none.

# What Is Not Proven {#non-claims}

The list of {{RECEIPTS}} Section 6 applies unchanged to a cited receipt. It is
repeated here word for word; its one cross-reference is written as a reference
to Section 5 of {{RECEIPTS}}.

@@NON_CLAIMS@@

Each envelope adds what it does not prove:

* A citation. A MATCH does not show that the candidate verifies, who signed it,
  or that its assertion is true (case C5). The digest names B; it names
  neither a signature nor a key.
* DSSE. A successful DSSE signature check authenticates PAE(type, B) under the
  selected key. A receipt verdict additionally requires the verification
  profile and all checks of {{RECEIPTS}} Section 5. The unauthenticated `keyid`
  is only a key-selection hint.
* in-toto test-result. A Statement that restates a receipt is the statement of
  its signer. It does not show that a receipt exists, and its `result` does not
  show that the receipt's `passed` is true; both are statements.
* SLSA VSA. A VSA shows that its verifier states that it verified its subject
  under its policy, with the cited receipt among its inputs. `verificationResult` is not `passed`, and the VSA
  does not make the receipt's assertion true. The digest in
  `inputAttestations` names B, not the signature or the key the verifier used.
* SCITT Signed Statement and COSE Receipt. The Hash Envelope carries only the
  digest. Its registration shows that a Transparency Service registered a
  statement naming that digest under its Registration Policy. It does not show
  that a receipt with that B exists or that it verifies, and `sub` binds
  nothing beyond the commitment it repeats.
* Typed digest reference. A Verified reference shows that the cited bytes are
  B, nothing about the signature, the key or the assertion.
* PRML. BOUND and AGREE ({{prml}}) do not show that the criteria were fixed
  before the run.

No envelope in this document carries sample data: a receipt commits to no
sample result ({{RECEIPTS}} Section 6), and a citation names only B.

# Security Considerations {#security}

This section follows the guidance of {{RFC3552}}. The attacker can read,
create, modify, replay and reorder receipts and citing envelopes, and controls
every input except the Receiver's choice of verification key.

Collisions. A citation names B only as well as SHA-256 resists collisions and
second preimages.

Signer not bound. The receipt digest does not name a key. An attacker who
signs the same B with its own key produces a receipt that matches every
citation of B. It fails verification under the Receiver's key ({{why-b}}).

Signature reuse across envelopes. By design the signature of a receipt is a
valid DSSE signature under `payloadType` equal to the type ({{dsse}}). A DSSE
consumer that accepts that `payloadType` holds the B and the signature of a
receipt, and applies {{RECEIPTS}} Section 5 before it relies on them. Under any other `payloadType` the signature is
expected to be invalid ({{dsse}}). It is not a COSE signature, because COSE signs a Sig_structure and not
PAE.

Digest confusion. For one receipt, the receipt digest, the SHA-256 of the
receipt bytes and the SHA-256 of a DSSE envelope are three different values. A
Receiver compares only the receipt digest with a citation. {{examples}} lists
the first two for vector P1 and the third for M1. The
type identifies B, but a receipt object carries the same string as its
`schema`: a Receiver that fetches a receipt object for
a citation takes B from it by steps 1 to 3 of {{RECEIPTS}} Section 5 and
compares the digest of that B, never the digest of the object.

Algorithm. Only SHA-256 is defined. A citation with another algorithm gives
INDETERMINATE (case C8), so it cannot be satisfied by a weaker digest.

Receipts not read. Step 2 of {{check-statement}} removes the receipts of a
Transparent Statement without reading them; vector T1 carries a receipt made
for another statement and is accepted. An accepted status therefore says
nothing about registration. A Receiver that relies on registration verifies
each receipt under {{RFC9942}} with a Transparency Service key that it fixed
itself. It fixes the key, not the issuer name in the receipt: two instances of
a Transparency Service can carry the same issuer name and differ only in their
keys ({{impl}}).

Digest not checked by registration alone. The Signed Statement carries a
digest, not B. Registration under a Transparency Service's policy does not by
itself establish that the payload equals SHA-256 over B; {{impl}} records the
registration of a statement whose payload was not that digest. The Receiver
recomputes the receipt digest in step 6 of {{check-statement}}.

Configured trust. A Receiver trusts a statement key or a trust anchor because
it configured it. In the certificate profile, the procedure checks the leaf
under the configured anchor but evaluates no validity period or revocation
status. A compromised leaf key can therefore continue to pass this procedure
while the configured pair remains. Additional path validation or other
acceptance policy can refuse its use separately. Removing a configured pair
makes statements that would pass step 2 and whose only matching pair was
removed fail at step 3 with untrusted_key.

# Privacy Considerations

The receipt digest lets anyone who holds a candidate B confirm it. B carries
salted commitments, so B cannot be guessed without them; a party that knows
them can test guesses for the remaining members, such as score and threshold.
A citation registered with a Transparency Service publishes the digest for as
long as that service keeps its log. The `sub` of M2 repeats the model
commitment of B in clear; registered, it links every receipt and statement
that commit to the same model identifier with the same salt ({{RECEIPTS}}
Section 9). The same holds for a `criteria_digest` that a receipt carries.

# IANA Considerations

This document has no IANA actions.

# Implementation Status {#impl}

This section records the status of known implementations at the time of
writing, following {{RFC7942}}, and is to be removed before publication.

The examples of {{examples}} were produced by a generator script whose two runs
are byte-identical, and checked by a separate script that re-derives every
value of {{examples}} from the bytes: the match result of every case, with its
own implementation of steps 1 to 3 of {{RECEIPTS}} Section 5; the status of M2,
of every status vector and of every certificate-profile vector, with its own
implementation of the steps of {{check-statement}} in both profiles; and the
state of every typed digest reference.

An implementation of both directions of the key profile of
{{signed-statement}}, the open-source package proofbundle (module `receipt_cose`, experimental), reproduces M2 byte
for byte from vector P1 of {{RECEIPTS}} and returns each status of
{{check-statement}} for a set of 49 statements and 6 receipts. M2 and the
status vectors of {{status-vectors}} are, byte for byte, statements of that set,
made independently by the generator of {{examples}}. It writes -19
only and reads -8 only under an Ed25519 statement key. Measured on 2026-10-08
with these pinned versions: pycose 1.1.0 (with cbor2 5.9.0) and go-cose v1.3.0
verified the statement with alg -8, refused the same statement with one
signature bit changed, and reported alg -19 (vector M2) as an unknown
algorithm; microsoft/scitt-verifier 0.4.0 evaluated the signature of neither
statement (its result for both was cannot-evaluate, with the statement
signature not evaluated). The certificate profile and the typed digest
references of {{typed-reference}} are implemented only by the scripts of
{{examples}}.

Registration with a Transparency Service was measured on 2026-10-10 with a
local instance of microsoft/scitt-ccf-ledger at commit 00101f76 (CCF 7.0.17,
virtual mode); no hosted service took part. No statement in the exact form of
the key profile was registered: the service refused its https issuer
("CWT_Claims issuer is unsupported") with alg -19 and with alg -8, and, under a
did:x509 issuer with x5chain, refused alg -19 ("COSE algorithm -19 is not
supported") and an Ed25519 key with alg -8 ("Unsupported key type"). A
statement in the form of the certificate profile, with an RSA-3072 test root, a
P-256 test leaf and alg -7, was registered, and microsoft/scitt-verifier 0.4.0
verified the Transparent Statement it returned offline, with the network
unavailable, under a policy that fixed the receipt issuer, the statement issuer
and the statement subject and compared the payload with SHA-256 over B. The
steps of {{check-statement}}, applied on 2026-10-11 to the registered statement
under the certificate pair of its test root, give accepted, and so they do for
the Transparent Statement that the service returned for it.

In the same measurement the service registered a statement whose payload was
not SHA-256 over the B it named, and two local instances of the service carried
the same receipt issuer name (127.0.0.1:8000) and differed only in their
service keys. microsoft/scitt-verifier 0.4.0 reported a receipt taken from
another entry, a receipt with one byte changed and a receipt of the other
instance as cannot-evaluate (exit status 3), not as untrusted (exit status 1);
this document maps no verdict of another tool to a status of
{{check-statement}}. scitt-verifier 0.4.0 did not anchor a chain whose leaf
certificate was signed with ECDSA (exit status 3) and verified the chain with
an RSA root. Vector T2 is the Transparent Statement that a local instance of
the same service returned on 2026-10-11 for X1: X1 with one receipt under label
394, byte for byte.

The signature of M2 (alg -19) is checked from the text alone, without a COSE
library: a script written from the texts of this document and of {{RECEIPTS}}
builds the Sig_structure by hand and verifies the signature over it with a
general Ed25519 implementation (its checks M2-17 and M2-18).

--- back

# Examples {#examples}

@@APPENDIX@@

# Open Items (to be removed before publication)
{:numbered="false"}

* References. The in-toto references are pinned to release v1.2.0 of the
  in-toto Attestation Framework.
* The draft names of {{RECEIPTS}} and {{STATEMENT-ID}} are to be updated once
  those documents are published.
* The artifact-type declaration of {{typed-reference}} is named by no
  consuming profile yet.
* Whether the certificate profile also admits alg -9 (ESP256) of {{RFC9864}}
  ({{alg-choice}}).
* Whether the certificate profile admits an intermediate certificate or an
  anchor key other than RSA. It requires exactly two certificates and an RSA
  root because that is the form measured to work: the offline verifier named in
  {{impl}} did not anchor a chain whose leaf certificate was signed with ECDSA,
  and verified the chain with an RSA root.
