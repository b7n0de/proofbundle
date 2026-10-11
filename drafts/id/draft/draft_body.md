---
title: Requirements and Test Cases for Identifying SCITT Signed Statements
abbrev: Identifying SCITT Signed Statements
docname: draft-gruszka-scitt-statement-identification-01
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
  - SCITT
  - COSE
  - statement identification
  - reference
  - transparency
stand_alone: yes
pi: [toc, sortrefs, symrefs]
author:
  - ins: K. Gruszka
    name: Konrad Gruszka
    organization: b7n0de
    email: kontakt@b7n0de.com
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
  RFC8032:
    title: "Edwards-Curve Digital Signature Algorithm (EdDSA)"
    author:
      - ins: S. Josefsson
      - ins: I. Liusvaara
    date: 2017-01
    seriesinfo:
      RFC: "8032"
    target: https://www.rfc-editor.org/info/rfc8032
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
  RFC9052:
    title: "CBOR Object Signing and Encryption (COSE): Structures and Process"
    author:
      - ins: J. Schaad
    date: 2022-08
    seriesinfo:
      STD: "96"
      RFC: "9052"
    target: https://www.rfc-editor.org/info/rfc9052
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
  RFC9864:
    title: "Fully-Specified Algorithms for JSON Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE)"
    author:
      - ins: M.B. Jones
      - ins: O. Steele
    date: 2025-10
    seriesinfo:
      RFC: "9864"
    target: https://www.rfc-editor.org/info/rfc9864
informative:
  SCITT-CHAIRS-20260922:
    title: "[SCITT] Re: SCITT WG: IETF 127 Agenda Planning"
    author:
      - ins: J. Geater
    date: 2026-09-22
    target: https://mailarchive.ietf.org/arch/msg/scitt/BPmxsdV7RDQx3qxgdCjOUwuFNZU/
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
  RFC9162:
    title: "Certificate Transparency Version 2.0"
    author:
      - ins: B. Laurie
      - ins: E. Messeri
      - ins: R. Stradling
    date: 2021-12
    seriesinfo:
      RFC: "9162"
    target: https://www.rfc-editor.org/info/rfc9162
  I-D.mih-sokolov-scitt-payload-binding:
    title: "Canonicalization Declaration for SCITT Signed Statements"
    author:
      - ins: S. Mih
      - ins: A. Sokolov
    date: 2026-09-11
    seriesinfo:
      Internet-Draft: draft-mih-sokolov-scitt-payload-binding-05
    target: https://datatracker.ietf.org/doc/draft-mih-sokolov-scitt-payload-binding/05/
  I-D.nobuo-scitt-protected-object-binding:
    title: "SCITT Statement Relationship and Protected Object Binding"
    author:
      - ins: N. Aoki
    date: 2026-07-06
    seriesinfo:
      Internet-Draft: draft-nobuo-scitt-protected-object-binding-00
    target: https://datatracker.ietf.org/doc/draft-nobuo-scitt-protected-object-binding/00/
  I-D.ietf-scitt-scrapi:
    title: "Supply Chain Integrity, Transparency, and Trust (SCITT) Reference APIs"
    author:
      - ins: H. Birkholz
      - ins: J. Geater
      - ins: A. Delignat-Lavaud
    date: 2026-06-26
    seriesinfo:
      Internet-Draft: draft-ietf-scitt-scrapi-11
    target: https://datatracker.ietf.org/doc/draft-ietf-scitt-scrapi/11/

--- abstract

This document describes proposed requirements and test cases for identifying
SCITT Signed Statements. It distinguishes reference matching from statement
retrieval, signature verification, issuer authorization, and evidence of
registration. It examines how alternative identification schemes treat changes
to statement encodings and registration context. The requirements are input to
technical discussion and do not represent working group consensus. This document
does not define a common reference format, allocate a COSE header parameter, or
establish a relationship vocabulary. Its examples illustrate selected properties
rather than demonstrate interoperability between deployed transparency services.

--- middle

# Introduction

A Transparency Service in the Supply Chain Integrity, Transparency, and Trust
(SCITT) architecture {{RFC9943}} registers Signed Statements and returns
Receipts. Applications increasingly need to refer to a specific Signed Statement:
an audit statement that refers to the statement it audited, a correction that
refers to the statement it corrects, an evidence bundle that lists the statements
it was built from. For such a reference to be usable, two implementations given
the reference and a candidate statement must reach the same conclusion about
whether they match.

This is harder than hashing some bytes. The same logical Signed Statement can be
re-encoded, can gain or lose an unprotected header, and can be registered in more
than one Transparency Service, each producing its own entry handle and Receipt. A
reference that is meant to survive those changes must say exactly which
differences preserve identity and which do not, and must be interpretable without
first understanding the application payload of the statement that carries it.

The need is not specific to any one product. On 22 September 2026 one of the SCITT
working group chairs asked on the scitt@ietf.org list, "On statement IDs please
bring all requirements you may have for statement identification", and raised as
an open question "whether or not the statement ID should be cryptographically
derived from its log insertion or not" {{SCITT-CHAIRS-20260922}}. The chair added that it has "pros and cons" and "will need real engagement to get right". This document is input to that discussion.

This document states proposed requirements (Section 4), compares candidate
identification objects (Section 5), and works through a small set of fully
explained test cases (Section 6). It takes a position, independence of the
reference-matching result from any particular registration, and argues it with
use and trade-offs rather than asserting it as settled. It does not propose a
wire format, a COSE header parameter, or a relationship vocabulary for
standardization.

# Conventions, Terminology and Scope

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

This document uses the SCITT terms Signed Statement, Transparency Service and
Receipt as defined in {{RFC9943}}. It adds the following working terms and keeps
them apart deliberately:

Statement reference:
: Data that designates a target Signed Statement together with the rule by which a
  candidate is judged to be that target.

Identification scheme:
: The rule a reference is read under: which bytes are covered, which differences
  preserve identity, and, for a digest-based scheme, the hash algorithm and the
  exact input bytes.

Reference matching:
: The operation of deciding, given a reference and a candidate statement, whether
  the candidate is the reference's target under the named scheme.

Entry handle (Locator):
: A Transparency-Service-local identifier of a registration, such as an entry
  identifier returned by an API {{I-D.ietf-scitt-scrapi}}. It locates an entry in
  one service; it is not a portable statement identity.

Registration evidence:
: A Receipt {{RFC9942}} that a statement was registered. It is distinct from a
  reference match.

Matching a reference is not the same as retrieving a statement, verifying its
signature, authorizing its Issuer, or proving it was registered. Keeping these
apart is the central discipline of this document.

## Relationship to existing SCITT work

This document is a requirements and test-case text, not a new mechanism. The
following work is adjacent; the References identify the revisions used.

The architecture {{RFC9943}} defines the Signed Statement envelope: Section 6.1
requires CBOR tag 18, and Section 6.3 requires the unprotected header to be an
empty map before a statement is included in a Statement Sequence. It defines the
statement, not a portable identifier for one statement or the bytes a statement
digest covers.

The Receipts document {{RFC9942}} defines Verifiable Data Structures and their
proofs; its Section 4.4.1 gives the registration requirements for a VDS, and its
Section 5.2.1 is the RFC9162_SHA256 Receipt of Inclusion. Identity through a
Receipt is scoped to a log and a VDS construction, and Section 4.4.1 leaves each
VDS to define its own encoding and proofs.

The payload-binding draft {{I-D.mih-sokolov-scitt-payload-binding}} gives, in its
Section 8, a general typed-digest-reference information model (type, purpose,
digest_alg, digest) in which a carried digest and a recomputed digest are
comparable only under one established referenced-artifact digest context, and in
Sections 5 and 7 a derived identifier and a statement-to-Receipt binding. This
document asks the narrower question of the concrete context a SCITT Signed
Statement reference needs.

The protected-object-binding draft {{I-D.nobuo-scitt-protected-object-binding}}
defines Statement References, Receipt References and Relationship Edges with an
initial relationship vocabulary (for example describes, measures, authorizes,
supersedes and revokes); it couples identification with that vocabulary,
whereas this document keeps matching separate from the relationship it carries.

In SCRAPI {{I-D.ietf-scitt-scrapi}} Section 2.4, a GET on /entries/ followed by an
EntryID answers with the Receipt (200), with 204 while registration is still
running, or with 404; that EntryID is an API locator for one service, not a
portable, registration-independent statement identity.

The SCITT charter (charter-ietf-scitt-01, last updated 2026-03-18, retrieved 2026-10-10) lists among its non-goals to "define data formats for payload
content" and asks the group to "reuse existing work from IETF WGs such as COSE
and RATS, as appropriate". Where a statement-identification requirement or a
small profile belongs is itself an open question (Section 10).

# Use Cases

The following cases need different identification properties; they motivate the
requirements without selecting a scheme.

1. Audit reference. An auditor registers a statement that refers to the statement
   it audited. A reader must match the reference to the audited statement even if
   the audited statement has since been re-registered elsewhere.
2. Correction reference. An Issuer registers a later statement that corrects an
   earlier one, keeping the same subject. The subject groups the two; the
   reference must still select the specific earlier statement, not merely the
   subject.
3. Offline evidence bundle. A bundle lists the statements it was built from and is
   checked by a relying party that holds the bytes but queries no service. Matching
   must not require a service round-trip.
4. Cross-service presence. The same statement is registered in two Transparency
   Services. A reference that is meant to be portable must designate the same
   statement across both, distinguishing identity-bearing changes from encoding
   changes the scheme excludes.

# Proposed Requirements

These requirements are proposed input, not working group consensus. They are
taken from an existing requirements note (see Section 11) and are stated here with
their differing roles made explicit: A1 and A2 are properties of a reference, A3
is a design position, A4 is its acceptance test, and A5 is a conditional
dependency of schemes that rely on a Receipt, not a fifth independent rule on
every reference.

The BCP 14 keywords in A1 to A5 address a future identification scheme or
profile; they are not obligations this document places on an existing protocol.
Where a requirement restates an existing obligation it says so and cites it: the
CBOR tag 18 of {{RFC9943}} Section 6.1, the empty unprotected header of
{{RFC9943}} Section 6.3, and the VDS registration requirements of {{RFC9942}}
Section 4.4.1 are existing obligations this document relies on, not new ones.

## A1. A reference has an unambiguous target and matching rule

Given a reference and a candidate Signed Statement, a verifier can decide whether
they match under a named identification scheme. The scheme states which
differences preserve identity, including differences in signatures, headers and
encodings. For a digest-based scheme it also defines the hash algorithm, the input
bytes, and their encoding. These definitions MAY be supplied by a profile rather
than repeated in each reference.

The Issuer and Subject pair groups related statements but does not select an
individual statement from that group ({{RFC9943}} Section 6 uses `iss` and `sub`
to identify the Artifact; the architecture defines no statement identifier). Acceptance: two implementations
using the same scheme agree on matching and non-matching candidate vectors;
missing inputs or unsupported rules cannot produce a successful match; a
ToBeSigned scheme must specify `external_aad` and the source of any detached
payload.

## A2. A reference can be read without interpreting the carrier's payload

A verifier can locate and interpret a reference without interpreting the
application payload of the Signed Statement that carries it. Recomputing a target
digest MAY still require the target's payload bytes; that is a property of the
target, not of reading the reference from the carrier. This is a proposed scope
choice: without it, extracting a reference could require payload-specific parsing
or decryption of the carrier.

## A3. Matching a statement reference is independent of registration

Proposed requirement: matching a reference to a candidate does not depend on
registration with a particular Transparency Service or on a particular insertion
event. Service-local entry handles and Receipts may coexist with the reference and
may differ.

This is one proposed answer to that open question. It is a design position,
argued from the offline-bundle and cross-service use cases, not a claim that a
log-derived identifier cannot work. A log-dependent identifier does not by itself
prevent offline verification when the needed bytes, keys and trust anchors are
already held; the property asked for here is independence from the registration
context, not offline capability in general (Section 5.2).

## A4. Acceptance test for A3

Under the same identification scheme, registration in either of two Transparency
Services preserves the identity A1 defines. The test must distinguish
identity-bearing changes from changes the scheme explicitly excludes. No
two-service registration is measured in this document (Section 6 and Section 11);
the illustrative cases instead apply local transformations that a registration may
cause (an added unprotected parameter; a changed outer encoding) and show which
leave the chosen identity unchanged. The tag-removal case (C9) is a negative format
control, not evidence of successful registration in two services.

## A5. Receipt-verification dependency

Where identification depends on a leaf hash or a Receipt, the selected Verifiable
Data Structure specification MUST define the entry-to-leaf transformation,
serialization and tree hashing sufficiently for independent implementations to
reproduce the result. This is a dependency of such schemes and of interoperable
Receipt verification, not a fifth independent requirement on every reference.
{{RFC9942}} Section 4.4.1 states that "Each VDS specification applying for
inclusion in this registry MUST define how to encode the VDS identifier and its
Proof Types in CBOR" and that "Each specification MUST define how to produce and
consume the supported Proof Types"; its Section 5.2.1 is the Receipt of Inclusion
of the specific RFC9162_SHA256 construction, which begins "In a signed proof, the
payload is the Merkle Tree root that corresponds to the log at size tree-size".
Different VDS constructions differ in their leaf and node hashing (for example the 0x00/0x01 prefixes of {{RFC9162}} Section 2.1.1); that difference does not make either
construction ambiguous. This document does not test leaf hashing or Receipts.

# Design Alternatives and Trade-offs

The central design decision is not the hash algorithm but the identification
object: which differences count as identity-changing. The following is the
authors' analysis of candidate objects; it is not a selection.

| Identification object | Possible benefit | Price to be settled |
|-----------------------|------------------|---------------------|
| Whole transmitted object bytes | Simple exact byte identity | Transport or envelope changes produce different values even when other checks still pass |
| An explicitly defined canonical object encoding | Equal treatment of selected encoding variants | Extra rules, cost, and the risk of diverging normalization |
| The COSE signing input ToBeSigned | Binds to the actually signed content and its signature context | Does not itself identify the signature value or the unprotected envelope; external inputs must be available and fixed |
| The payload only | Fits when the content, not the signed assertion, is meant | Issuer, header and signature differences are not necessarily distinguished |
| A VDS leaf or service entry | Close tie to a concrete registration | Depends on the VDS construction or the service context |

For COSE, {{RFC9052}} Section 4.3 (externally supplied data) and Section 4.4 (the
Sig_structure) are the relevant definitions, and Section 9 constrains the CBOR
encoding. A successful signature verification does not by itself fix which
universal statement identity an application should use.

## The ToBeSigned object, as used in the examples

The examples in Section 6 use SHA-256 over ToBeSigned, the Sig_structure
`["Signature1", body_protected, external_aad, payload]` of {{RFC9052}} Sections
4.4 and 9, with the payload embedded. The scheme names `external_aad` as an
explicit input: it is the empty byte string unless a specific case states
otherwise, and a case that signs over a non-empty `external_aad` lists those
exact bytes (Appendix A) and applies them to both matching and signature
verification. The `body_protected` value is the original protected-header byte
string, not a decoded and re-encoded map. This object names a class of signed inputs: it excludes the
signature value, the unprotected header and the outer wrapper, so changes confined
to those parts preserve it, and it does not normalize the bytes inside the
protected header or payload. It is used here as one illustrative rule. This
document does not propose it as the statement identity defined by the architecture;
{{RFC9943}} defines no such identity, and a later profile is free to choose a
different object.

## Offline is not the same as registration-independent (A3)

A scheme can be checked offline when the needed bytes, keys and trust assumptions
are already held; a service-dependent identifier is not online merely because it
is service-dependent. A3 therefore argues for independence from the registration
context, not for a blanket impossibility of offline checking of other models.

# Conformance and Illustrative Test Cases

Each check is reported on separate axes: `ref_usable` indicates whether the reference is well-formed and
compatible with the named scheme; `match` is MATCH or NO_MATCH when the comparison can be completed, and
INDETERMINATE when the reference is unusable or a required input is absent; `sig_valid` indicates whether
the candidate's signature verifies under the stated key; and `is_scitt` indicates whether the candidate is
a tagged COSE_Sign1 ({{RFC9943}} Section 6.1 requires CBOR tag 18). A match establishes
none of signature validity, issuer trust, payload truth, or registration.

A candidate is read as a COSE_Sign1 ({{RFC9052}} Section 4.2), bare or with tag
18: an array of exactly four elements: the protected header, a byte string that
is empty or encodes one map; the unprotected header, a map; the payload, a byte string or nil; and the
signature, a byte string. For these illustrative axes, this read check covers
only the outer tag, the array shape, the stated element types and the basic CBOR
validity rules below. It does not validate header labels or header parameter
semantics. The `is_scitt` axis reports this structural check with tag 18, not
complete conformance to the SCITT envelope profile. The candidate and its
protected header are each one
CBOR data item that is well-formed and valid under {{RFC8949}} Section 5.3.1:
every text string is valid UTF-8, and no map holds two keys that are
equal under the key equivalence of {{RFC8949}} Section 5.6.1, so that the
integer 1 and true are two keys and 0.0 and -0.0 are one. Whether the content
of a tag inside the COSE_Sign1 is valid for that tag ({{RFC8949}} Section 5.3.2)
is not checked; the
data items inside a tag are checked like any other data item. The deterministic
encoding is not required. A candidate
that breaks any of this, for example with a text string that is not valid UTF-8
in either header, is not a statement: its `is_scitt` is False and its
`sig_valid` is None, not evaluated; its `match` is NO_MATCH under a usable
reference and INDETERMINATE under an unusable one.

The `sig_valid` axis is computed with one rule for every case. `n*P` is the
point P multiplied by the integer n. A is the 32-byte public key of the stated
key, derived from its seed in Appendix A.2 as in {{RFC8032}} Section 5.1.5; R is
the first and S the second 32 bytes of the 64-byte signature, S read as a
little-endian integer; `B'` is the base point and L the order of `B'`
({{RFC8032}} Section 5.1); and ToBeSigned is the object of Section 5.1 of this document with
the case's `external_aad` and payload. `sig_valid` is True if and only if all
four rules hold:

1. A and R are canonical encodings: decoding each as in {{RFC8032}} Section 5.1.3
   succeeds.
2. A and R have order L: `L*A` and `L*R` are the neutral element, and A and R
   are not the neutral element.
3. S is below L.
4. With k = SHA-512(R || A || ToBeSigned) read as a little-endian integer and
   reduced modulo L, the cofactorless equation `S*B' = R + k*A` holds. R enters
   the hash exactly as received, A as its 32-byte encoding.

After the candidate passes the read checks above, a signature that is not 64
bytes gives `sig_valid` False. Otherwise, if the payload is absent and not
supplied, there is no ToBeSigned and `sig_valid` is None, not evaluated (C8).
Otherwise, evaluate the four rules above.

Because A and R have order L, the cofactorless equation of rule 4 and the
cofactored equation `8*S*B' = 8*R + 8*k*A` of {{RFC8032}} Section 5.1.7 accept
exactly the same signatures. This document defines individual verification
only. A randomized batch result MUST NOT substitute for checking all four rules
for each signature. Case C11 has an R
of mixed order, for which the two equations differ; rule 2 refuses it before
either is checked. The rule fixes the `sig_valid` axis of these cases only; the
`match` axis does not depend on it.

The cases use three synthetic signed statements about one subject and the
reference between them, under the ToBeSigned scheme of Section 5.1. Each case is
checked against the reference digest given in Appendix A.1. The full bytes,
keys and per-case results are in Appendix A; the keys are pure test keys. The
fixtures use the fully specified Ed25519 algorithm (COSE algorithm -19); the source
package uses EdDSA (-8). Identification is independent of the signature algorithm.

@@CASES_TABLE@@

The following cases illustrate the scope and limits of the chosen identity rule. Case C5 adds one unprotected parameter
after signing: the ToBeSigned digest and the signature are unchanged while the
whole-object digest changes, so a whole-bytes identifier and a ToBeSigned
identifier disagree exactly where a registration may rewrite the envelope. C9
reports MATCH under the illustrative ToBeSigned rule and is_scitt = False because
tag 18 is absent; it is a negative format control, not evidence of successful
registration in two services. Case C8 withholds a detached payload: a missing
input yields INDETERMINATE, never a match. Case C6 replaces the signature with one
from another key over the same signing input: the ToBeSigned reference still
matches, but the signature does not verify under the stated key, which is why the
two axes are reported separately.

An empty check set is not a PASS: a case for which no axis could be evaluated is
reported as INDETERMINATE, not as a match.

# Security Considerations

This section considers the attacker and the risks this work raises, in the spirit
of {{RFC3552}}. A successful reference match is not a trust decision. It does not
establish that the candidate's signature is valid, that its Issuer is authorized,
that its payload is true, or that it was registered. Relying parties MUST keep
these results separate and MUST NOT treat a match as any of them. Collapsing them
into a single boolean is the main foreseeable misuse.

The identification object determines the attack surface. A whole-bytes identifier
changes under any envelope rewrite, so a party expecting stability may fail to
match a legitimately re-registered statement. A ToBeSigned identifier is stable
across such rewrites but, by construction, does not distinguish two objects that
share a signing input and differ only in the signature value or unprotected
header; a party that needs to pin the exact signature instance needs a
whole-object identifier instead. A scheme MUST state `external_aad` and the source
of any detached payload; a missing input MUST NOT silently become an empty input
or a successful match, and a mismatch between a scheme's declared algorithm and a
reference's algorithm MUST NOT fall back silently.

Tag discipline matters: a generic COSE_Sign1 without CBOR tag 18 is not a SCITT
Signed Statement ({{RFC9943}} Section 6.1), and a test that drops the tag MUST NOT
be presented as a valid SCITT case. A stable reference shows only that a
designated statement exists and matches; it does not show that no newer relevant
statement has appeared, so a reference match MUST NOT be read as current validity
or as completeness of a history.

A verifier that recomputes a target digest reads externally supplied bytes; large,
deeply nested, or cyclically referenced inputs can exhaust resources. An
implementation should bound the input size and nesting it will process rather than
hashing unbounded input, and should treat a set of references as a list to check,
not a graph to traverse.

Digest-based identification depends on the collision and second-preimage
resistance of the selected hash algorithm.

# Privacy Considerations

A stable, portable reference is a correlator. The same identifier appearing in two
contexts links them. Schemes and deployments SHOULD consider whether a reference
needs to be stable across services at all, and whether salted or context-scoped
references are more appropriate where linkage is a concern. The subject identifier
in a statement groups statements about one Artifact and is itself a correlator
independent of the reference scheme.

A digest is not by itself a confidentiality mechanism. When the covered content is
drawn from a small or well-known set of possibilities, a party that holds the
reference can confirm a guess by hashing each candidate and comparing, even if the
target statement is never disclosed. A scheme that intends a reference to hide its
target needs enough entropy in the covered content (for example a salt) that this
guessing attack is infeasible.

# IANA Considerations

This document has no IANA actions. It allocates no COSE header parameter and
defines no registry. The COSE header label -70001 used by the examples in
Appendix A is in the Private Use range of the COSE Header Parameters registry
(integer values less than -65536); it is a local convention of the example
package, not a requested or assigned value.

# Open Questions

Concrete feedback is sought on the following.

1. The identification object. Should a SCITT statement reference bind to
   ToBeSigned, to a canonical object encoding, to the whole object bytes, or to a
   VDS leaf; and should the choice be fixed by the architecture or left to
   profiles?
2. Registration derivation. That open question stands: should a statement
   identifier be cryptographically derived from its log insertion, and what are the
   trade-offs against a registration-independent identifier (A3)?
3. Venue. Whether statement-identification requirements, or a small profile, belong
   in the SCITT architecture, in a Receipts or payload-binding document, or in a
   separate document; the charter's payload-format non-goal (Section 2.1) bears on
   this.
4. Relationship vocabulary. This document deliberately excludes one; whether the
   identification work needs any relationship terms at all is open.

# Implementation Status

This section is given per {{RFC7942}} and is to be removed by the RFC Editor before
publication.

An open-source project, proofbundle, carries the requirements note this document
is drawn from and a small synthetic example package, at commit
eb1b7eeb28a4f77a4fe9fb1eadc21be0fb03746d (files
docs/scitt/statement_identification/requirements.md and the package under
docs/scitt/statement_identification/package/). That package signs three synthetic
statements and checks the ToBeSigned references between them offline with a CBOR
library and a general cryptography library. The illustrative examples here sign
with the fully-specified Ed25519 algorithm -19 of {{RFC9864}}; the package at that
commit uses EdDSA -8, which {{RFC9864}} lists as deprecated, and the ToBeSigned
identification does not depend on the signature algorithm. The three example
signatures were decoded and verified independently in this work by decoding the
COSE_Sign1 with a CBOR library and verifying the Ed25519 signature over the
Sig_structure with a general cryptography library. pycose 1.1.0, the COSE library
present in the run environment, cannot decode algorithm -19; no other independent
COSE library was available, so whether a second COSE library decodes and verifies
-19 was not tested. The examples were generated and checked with cbor2 5.4.6 and cryptography 41.0.7. The illustrative cases of Section 6 and Appendix A were
generated and checked in this work; the fixtures are synthetic and the keys are
test keys.

One own measurement motivates the choice of hash input under A1 and is reported
here as a measured fact, not an endorsement. Against a locally run transparency
ledger (microsoft/scitt-ccf-ledger at commit 00101f76, CCF 7.0.17), of 62
registered rows, 39 had a SHA-256 of the submitted bytes that differed from the
data-hash in the returned Receipt, because the service sets the unprotected header
to an empty map and rewrites the outer encoding before inclusion. This measurement
shows why a reference scheme must specify whether it covers submitted bytes or the
representation included in the Statement Sequence; it does not by itself show that
the identifier depends on the service or insertion event. The
corpus matrix is in the proofbundle repository at
tools/scitt_ccf_external/differential_corpus_round3/README.md (freeze commit
c5ff0a72e28aa087eecd3e2b426577be3cf2a80f) and the replay at
tools/scitt_ccf_external/replay_earlier_build/results_table.md (commit
3ca368164b68a09a863f7ec12b2f9fa1b21123ec). Only the repository evidence is cited
here.

This information is given per {{RFC7942}} and does not constitute endorsement.

--- back

# Illustrative Test Cases: Bytes and Keys

All byte strings are hex. Each of the three base statements is a tagged COSE_Sign1 (first byte 0xd2, CBOR tag 18) signed with
the fully-specified Ed25519 algorithm (COSE algorithm -19, {{RFC9864}}). The private-use label carries a list of references; in these
examples the list holds exactly one, the array `[-16, "ToBeSigned", digest]`, which
references statement 01, and the digest is SHA-256 over the ToBeSigned of statement
01. The test keys are pure test keys given as fixed seeds
and MUST NOT be used for any real statement.

@@CASES_APPENDIX@@

# Acknowledgments
{:numbered="false"}

The author used AI tools to help draft this document and to generate and
cross-check its examples. The author reviewed the entire text and is responsible
for it.

Citing adjacent work in the References does not imply that its authors endorse this
document.

# Provenance
{:numbered="false"}

The requirements in Section 4 are drawn from the requirements note at the commit cited in
Section 11. The illustrative cases in Appendix A were generated for this document; Section 11 separately
identifies the sources of the reported measurement.

# Open Items (to be removed before publication)
{:numbered="false"}

* Reference verification. The references were checked against the published documents on 2026-10-10;
  re-check at submission time, including whether {{I-D.ietf-scitt-scrapi}} has been published as an RFC,
  and run idnits with network access.
* List note. If the observation note behind Open Question 2 is published on the
  SCITT list before submission, add its archive link to the Implementation Status
  section.
