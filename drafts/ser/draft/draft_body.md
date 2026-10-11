---
title: Signed Evaluation Receipts
abbrev: Signed Evaluation Receipts
docname: draft-gruszka-signed-evaluation-receipts-01
v: 3
category: info
submissiontype: IETF
ipr: trust200902
area: Security
keyword:
  - evaluation
  - receipt
  - Ed25519
  - canonical JSON
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
  RFC8032:
    title: "Edwards-Curve Digital Signature Algorithm (EdDSA)"
    author:
      - ins: S. Josefsson
      - ins: I. Liusvaara
    date: 2017-01
    seriesinfo:
      RFC: "8032"
    target: https://www.rfc-editor.org/info/rfc8032
  RFC6234:
    title: "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)"
    author:
      - ins: D. Eastlake 3rd
      - ins: T. Hansen
    date: 2011-05
    seriesinfo:
      RFC: "6234"
    target: https://www.rfc-editor.org/info/rfc6234
  RFC8785:
    title: "JSON Canonicalization Scheme (JCS)"
    author:
      - ins: A. Rundgren
      - ins: B. Jordan
      - ins: S. Erdtman
    date: 2020-06
    seriesinfo:
      RFC: "8785"
    target: https://www.rfc-editor.org/info/rfc8785
  RFC4648:
    title: "The Base16, Base32, and Base64 Data Encodings"
    author:
      - ins: S. Josefsson
    date: 2006-10
    seriesinfo:
      RFC: "4648"
    target: https://www.rfc-editor.org/info/rfc4648
  RFC8259:
    title: "The JavaScript Object Notation (JSON) Data Interchange Format"
    author:
      - ins: T. Bray
        role: editor
    date: 2017-12
    seriesinfo:
      STD: "90"
      RFC: "8259"
    target: https://www.rfc-editor.org/info/rfc8259
  RFC7493:
    title: "The I-JSON Message Format"
    author:
      - ins: T. Bray
        role: editor
    date: 2015-03
    seriesinfo:
      RFC: "7493"
    target: https://www.rfc-editor.org/info/rfc7493
  RFC3339:
    title: "Date and Time on the Internet: Timestamps"
    author:
      - ins: G. Klyne
      - ins: C. Newman
    date: 2002-07
    seriesinfo:
      RFC: "3339"
    target: https://www.rfc-editor.org/info/rfc3339
  RFC6838:
    title: "Media Type Specifications and Registration Procedures"
    author:
      - ins: N. Freed
      - ins: J. Klensin
      - ins: T. Hansen
    date: 2013-01
    seriesinfo:
      BCP: "13"
      RFC: "6838"
    target: https://www.rfc-editor.org/info/rfc6838
  RFC6839:
    title: "Additional Media Type Structured Syntax Suffixes"
    author:
      - ins: T. Hansen
      - ins: A. Melnikov
    date: 2013-01
    seriesinfo:
      RFC: "6839"
    target: https://www.rfc-editor.org/info/rfc6839
informative:
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
  DSSE:
    title: "DSSE: Dead Simple Signing Envelope, protocol specification, version 1.0.2"
    author:
      - org: Secure Systems Lab
    date: 2024-05-28
    target: https://github.com/secure-systems-lab/dsse/blob/v1.0.2/protocol.md
  TAMING:
    title: "Taming the Many EdDSAs"
    author:
      - ins: K. Chalkias
      - ins: F. Garillot
      - ins: V. Nikolaenko
    date: 2020
    seriesinfo:
      "Security Standardisation Research (SSR 2020), LNCS": "12529"
    target: https://eprint.iacr.org/2020/1244
  I-D.farley-acta-signed-receipts:
    title: "Signed Decision Receipts for Machine-to-Machine Access Control"
    author:
      - ins: T. Farley
    date: 2026-08-29
    seriesinfo:
      Internet-Draft: draft-farley-acta-signed-receipts-03
    target: https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/03/
  I-D.chueayen-attestation-receipts:
    title: "Enforcement Attestation Receipts for AI Inference Decisions"
    author:
      - ins: A. Chueayen
    date: 2026-09-20
    seriesinfo:
      Internet-Draft: draft-chueayen-attestation-receipts-03
    target: https://datatracker.ietf.org/doc/draft-chueayen-attestation-receipts/03/
  I-D.marques-asqav-compliance-receipts:
    title: "Compliance Profile of Signed Action Receipts for AI Agents"
    author:
      - ins: J. A. Gomes Marques
    date: 2026-09-21
    seriesinfo:
      Internet-Draft: draft-marques-asqav-compliance-receipts-09
    target: https://datatracker.ietf.org/doc/draft-marques-asqav-compliance-receipts/09/
  I-D.abak-ai-evaluation-claim-preservation:
    title: "Claim-Preserving Exchange of AI Evaluation Evidence"
    author:
      - ins: A. T. Abak
    date: 2026-09-23
    seriesinfo:
      Internet-Draft: draft-abak-ai-evaluation-claim-preservation-00
    target: https://datatracker.ietf.org/doc/draft-abak-ai-evaluation-claim-preservation/00/
  I-D.ozturk-scitt-prml-profile:
    title: "A SCITT Profile for Pre-Run Evaluation Criteria (PRML)"
    author:
      - ins: C. Öztürk
    date: 2026-09-11
    seriesinfo:
      Internet-Draft: draft-ozturk-scitt-prml-profile-00
    target: https://datatracker.ietf.org/doc/draft-ozturk-scitt-prml-profile/00/
  PRML:
    title: "PRML: Pre-Registered ML Manifest Specification, Version 0.1"
    author:
      - ins: C. Öztürk
        role: editor
    date: 2026-05-01
    target: https://spec.falsify.dev/v0.1

--- abstract

This document defines a Signed Evaluation Receipt: one JSON object that
records one evaluation result, whether a stated threshold held for a stated
metric of a stated test suite, and signs it with Ed25519 over a
domain-separated encoding of its canonical bytes. A receipt shows who signed
the recorded bytes. It does not show that the recorded result is true. A
receipt does not prove registration with a Transparency Service. In SCITT,
transparency additionally requires registering a Signed Statement carrying the
receipt or its digest with a Transparency Service and verifying the resulting
SCITT Receipt. Registration and verification of the resulting SCITT Receipt
are outside this document.

--- middle

# Introduction

Evaluation results for software and models are often reported as numbers in
documents, dashboards or logs. A reader who receives such a number later has
no means to tell whether the bytes they see are the bytes the reporting party
produced. This document defines a small, fixed format that gives that means
and nothing more.

A Signed Evaluation Receipt (receipt) holds exactly one assertion: for a named
test suite and metric, whether the score met a threshold under a stated
comparator. The model and the dataset are named only through salted
commitments. The assertion is serialized with the JSON Canonicalization Scheme
{{RFC8785}}, and the resulting bytes are signed with Ed25519 {{RFC8032}} over a
pre-authentication encoding that binds a fixed type.

A receipt establishes integrity and origin: the holder of the signing key
signed exactly these bytes. It does not establish truth. {{non-claims}} lists
what a receipt does not prove, and that list is part of the definition. A
receipt carries no inclusion proof and names no log. A receipt does not prove
registration with a Transparency Service. In SCITT {{RFC9943}}, transparency
additionally requires registering a Signed Statement carrying the receipt or its
digest with a Transparency Service and verifying the resulting SCITT Receipt.
Registration and verification of the resulting SCITT Receipt are outside this
document.

The receipt is the smallest unit in a line of work: one document asks how a
signed statement is named unambiguously, this document fixes the bytes of a
receipt, and a companion document describes how existing envelopes cite such a
receipt by digest. This document defines no envelope mapping and no transport.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{RFC2119}} {{RFC8174}}
when, and only when, they appear in all capitals, as shown here.

Issuer:
: The party that creates and signs a receipt.

Receiver:
: The party that verifies a receipt. The Receiver fixes the verification key
  before verification, by means outside this document.

Payload:
: The JSON object that holds the assertion ({{payload}}).

B:
: The RFC 8785 byte string of the Payload. B is what is signed (through
  PAE).

PAE:
: The pre-authentication encoding of {{pae}}.

Commitment:
: A string that binds an identifier without revealing it ({{commitments}}).

# Receipt Format {#format}

## The Receipt Object {#receipt-object}

A receipt is one JSON text {{RFC8259}} that is an I-JSON message {{RFC7493}}:
UTF-8 without a byte order mark, no string (member names included) that
contains a surrogate or noncharacter code point ({{RFC7493}} Section 2.1), no
duplicate member names at any level, and nothing before or after the JSON text
other than insignificant whitespace ({{RFC8259}} Section 2). Member names are
compared after
unescaping ({{RFC8259}} Section 8.3), and so are string values: the receipt
object is not canonicalized, so `\/` and `/` are the same character. Its
top-level value is an object with exactly these members:

schema:
: The type of {{type}}, as a string.

payload_b64:
: The base64 encoding of B ({{RFC4648}} Section 4, with padding). It MUST be
  the canonical encoding: re-encoding the decoded bytes yields the same string
  ({{RFC4648}} Section 3.5).

signature:
: An object with exactly the members `alg` and `sig`, or exactly `alg`,
  `sig` and `key`. `alg` is the string `ed25519`; `sig` is the canonical base64
  encoding, as for `payload_b64`, of the 64-byte Ed25519 signature; `key`, when
  present, is the canonical base64 encoding, as for `payload_b64`, of a 32-byte
  Ed25519 public key and is only a hint ({{verification}}).

The receipt object has no number member. The number rules of I-JSON are not
checked when the receipt is parsed: a number where a string belongs fails the
step that checks that member.

The receipt names no trust instance: it carries no certificate, no address from
which a key could be fetched, and no list of trusted parties.

## The Payload {#payload}

The Payload is a JSON object with exactly the members of Table 1.
`criteria_digest` is the only optional member: a Payload either has it or not,
and has no member that Table 1 does not list. The Type column states every
constraint a member has except two: the pattern `sha256:` followed by 64
lowercase hexadecimal digits that the commitments of {{commitments}} and
`criteria_digest` ({{criteria}}) share, and the agreement of `passed` with the
comparison. A member that violates its row fails step 6 of {{verification}}, a
commitment or a `criteria_digest` without that pattern fails step 7, and a
`passed` that disagrees fails step 8.

| Member | Type | Meaning |
|---|---|---|
| schema | string, exactly the payload schema identifier below | version of the payload format |
| suite | non-empty string | name of the test suite |
| suite_version | non-empty string | version of the test suite |
| metric | non-empty string | name of the metric |
| comparator | string, one of `>=`, `>`, `<=`, `<` | how the score is compared with the threshold |
| threshold | decimal string | the threshold the score is compared with |
| score | decimal string | the score the Issuer reports |
| passed | `true` or `false` | whether `score comparator threshold` holds |
| n | integer from 1 to 2^53 - 1 | number of samples the Issuer reports; not checked against anything |
| model_id_commit | string | commitment ({{commitments}}) to the model identifier |
| dataset_id_commit | string | commitment ({{commitments}}) to the dataset identifier |
| commit_alg | string, exactly `sha256-salted-v1` | the commitment construction |
| timestamp | string, a timestamp as defined below | when the Issuer states the evaluation ran |
| criteria_digest | string; OPTIONAL | digest ({{criteria}}) of the criteria set the Issuer states this result belongs to |

The payload schema identifier is

~~~
https://signed-evidence.org/eval-receipt/v1
~~~

In this document a digit is one of the ASCII digits 0 to 9 (0x30 to 0x39); no
other Unicode digit counts. A lowercase hexadecimal digit is a digit or one of
the ASCII letters a to f (0x61 to 0x66). A non-empty string has at least one character. A
decimal string is an optional minus sign, then either the digit 0 or a digit
from 1 to 9 followed by any digits, then optionally a full stop followed by one
or more digits; it has no exponent and no plus sign. A timestamp is a UTC
date-time of {{RFC3339}} in exactly this form, with an uppercase `T` and `Z`:

~~~
YYYY-MM-DDTHH:MM:SSZ
~~~

The date exists in the proleptic Gregorian calendar: the day of the month is
at most the maximum that {{RFC3339}} Section 5.7 gives for its month and year,
under the leap-year rule of {{RFC3339}} Appendix C, so the year 0000 exists and
is a leap year; the hour is 00 to 23, the minute 00 to 59 and the second 00 to
59. A timestamp has no fractional seconds and no offset other than `Z`, and
this format does not represent a leap second. `passed` MUST equal the result of comparing `score` with
`threshold` under `comparator` as exact decimal numbers. The Payload thus
carries one assertion, and a Receiver can check that its parts agree with each
other; it cannot check that they agree with any evaluation.

The version of the format lives in the `schema` identifier. A later version
uses a different identifier under

~~~
https://signed-evidence.org/eval-receipt/
~~~

## Salted Commitments {#commitments}

`sha256-salted-v1` is defined as follows. The Issuer takes a salt of exactly 16
bytes from a cryptographically secure random source and keeps it. The
commitment is the string `sha256:` followed by the 64 lowercase hexadecimal
digits of SHA-256 over the salt bytes immediately followed by the UTF-8 bytes
of the identifier. There is no separator and no length prefix. SHA-256 is the
hash function specified in {{RFC6234}}. A Receiver
checks only the pattern `sha256:` followed by 64 lowercase hexadecimal digits;
it can check the binding only when the Issuer discloses salt and identifier.
Reusing the same salt and identifier produces the same commitment across
receipts. Fresh salts avoid this equality link but do not make receipts
unlinkable, because verification keys and other shared values may still link
them ({{privacy}}).

## The Bytes B {#bytes}

B is the serialization of the Payload under {{RFC8785}}. For a valid Payload
that means: members sorted by name, no insignificant whitespace, the integer
`n` as its decimal digits, and strings with the escaping of {{RFC8785}}
Section 3.2.2.2. A Receiver MUST reject payload bytes that are not their own
RFC 8785 serialization, so that exactly one B exists for each Payload. The
check (step 5 of {{verification}}) runs before the member checks of step 6,
so it applies RFC 8785 in full, including the number serialization of its
Section 3.2.2.3: a B that carries `1.0`, `1e0` or 9007199254740993 is not its
own serialization.

## The Criteria Digest {#criteria}

`criteria_digest` is OPTIONAL. When present, it is the string `sha256:`
followed by the 64 lowercase hexadecimal digits of SHA-256 over the bytes of a
criteria set, exactly as the publisher of that criteria set fixed them. A
criteria set is any document that states how an evaluation is to be judged,
for example its metric, comparator and threshold; this document defines no
format and no canonical form for it. A Receiver checks only the pattern (step 7
of {{verification}}). It can check the binding only when it holds the bytes of
the criteria set, by computing SHA-256 over them. What the member does not show
is part of {{non-claims}}.

As an informative example, the profile of {{I-D.ozturk-scitt-prml-profile}}
carries in its hash mode the 32 octets of SHA-256 over the canonical bytes of a
criteria set written in {{PRML}} as the payload of a Signed Statement. When the
bytes of the criteria set are those canonical bytes, the 64 hexadecimal digits
of `criteria_digest` are those 32 octets written in lowercase hexadecimal.

# Signature {#signature}

## Pre-Authentication Encoding {#pae}

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

SP is the byte 0x20. LEN(x) is the number of bytes of x as ASCII decimal
digits without leading zeros. `type` is the UTF-8 string of {{type}}, `body`
is B. "DSSEv1" is the six ASCII bytes of that literal. This is the
pre-authentication encoding of DSSE {{DSSE}}; it is defined here so that this
document can be implemented without it.

## The Type {#type}

The type is the fixed string

    application/vnd.signed-evidence.eval-receipt+json

It enters every signature. It MUST NOT change for this format, because a
change would invalidate every signature made under it; a new format uses a new
type. The string is a media type name in the vendor tree ({{RFC6838}}
Section 3.2) with the `+json` structured syntax suffix ({{RFC6839}}
Section 3.1). It is the same string that a DSSE envelope would carry as
`payloadType`.

## Signing {#signing}

The signature is Ed25519 as defined in {{RFC8032}} Section 5.1, in its pure
form, without context and without prehashing (not Ed25519ctx, not Ed25519ph):

    sig = Ed25519-Sign(secret key, PAE(type, B))

## Verification Profile {#profile}

Ed25519 implementations differ on inputs that RFC 8032 leaves to choice
{{TAMING}}. A Receiver MUST use this profile. In it, `x*P` is the scalar
multiplication of the point P by the integer x, `B'` is the base point, and L
is the order of `B'` ({{RFC8032}} Section 5.1).

1. The public key A and the signature's first half R MUST be canonical
   encodings: decoding as in {{RFC8032}} Section 5.1.3 succeeds. That decoding
   rejects a y-coordinate that is not below p and the encoding of x = 0 with
   the sign bit set.
2. A and R MUST have order L: `L*A` and `L*R` are the neutral element, and A
   and R are not the neutral element.
3. The scalar S, the second half of the signature read as a little-endian
   integer, MUST be below L ({{RFC8032}} Section 5.1.7).
4. With k = SHA-512(R || A || PAE(type, B)) read as a little-endian integer
   reduced modulo L, the equation `S*B' = R + k*A` MUST hold (the cofactorless
   equation). In the hash input, R and A are the 32-byte encodings exactly as
   received: the first 32 bytes of the 64-byte signature and the verification
   key.

A signature that fails any rule is invalid. The rules are checked in the
order given, and within rules 1 and 2 the key before R. Because A and R have
order L, the cofactorless equation of rule 4 and the cofactored equation
`8*S*B' = 8*R + 8*k*A` of {{RFC8032}} Section 5.1.7 accept exactly the same
signatures. This specification defines individual verification only. A
randomized batch result MUST NOT substitute for checking all four rules for
each signature. A Receiver MUST NOT leave out any of the four rules.

# Verification Procedure {#verification}

Input: the receipt bytes and the verification key that the Receiver fixed. The
verification-key input is exactly 32 octets containing the compressed
Edwards-point encoding of A defined by {{RFC8032}} Section 5.1.2. Any textual or
file representation used to supply those octets is outside this specification.
The steps are evaluated in order; the result is PASS only when every step
succeeds, and the first step that fails gives FAIL. String values are compared
after unescaping. A Receiver that stops because it reached a resource limit
({{security}}) reports a resource-limit error; that is neither PASS nor the FAIL
of one of the steps below.

1. Parse the receipt as one I-JSON text ({{receipt-object}}). A byte order
   mark, bytes that are not UTF-8, a surrogate or noncharacter code point,
   duplicate member names at any level, anything before or after the JSON
   text other than insignificant whitespace ({{RFC8259}} Section 2), a
   top-level value that is not an object with
   exactly the members `schema`, `payload_b64` and `signature`, or a
   `signature` that is not an object with exactly `alg` and `sig` or exactly
   `alg`, `sig` and `key`: FAIL.
2. `schema` is not the type of {{type}}: FAIL.
3. `payload_b64` is not a string of the base64 alphabet with padding, or not
   the canonical encoding of the bytes it decodes to: FAIL. Otherwise those
   bytes are B.
4. B is not one I-JSON text whose value is an object, under the rules of step
   1 (byte order mark, UTF-8, surrogates and noncharacters, duplicate names as
   in {{RFC7493}} Section 2.3, which {{RFC8785}} Section 3.1 requires of its
   input, trailing data): FAIL. Numbers are not judged
   here: each is read as an IEEE 754 double, rounded to nearest with ties to
   even and overflowing to infinity, and a number that so has no finite
   double, such as `1e400`, fails step 5.
5. B is not the RFC 8785 serialization of the value parsed in step 4 ({{bytes}}):
   FAIL. This step alone would also reject every B that step 4 rejects for
   a byte order mark, duplicate names or trailing data; step 4 is kept so that
   every Receiver reports the same failing step.
6. The Payload's member set differs from {{payload}} (every member of Table 1,
   with `criteria_digest` optional), or a member violates its
   row of Table 1 (its type, the `schema` and `commit_alg` values, a non-empty
   string, the comparator set, the decimal grammar, the range of `n`, the
   timestamp form): FAIL.
7. A commitment, or `criteria_digest` when present, is not `sha256:` followed
   by 64 lowercase hexadecimal digits: FAIL.
8. `passed` differs from the comparison of `score` with `threshold`: FAIL.
9. `signature.alg` is not the string `ed25519`, or `signature.sig` is not a
   string that is the canonical base64 encoding of exactly 64 bytes: FAIL.
10. `signature.key` is present and is not a string that is the canonical base64
    encoding of the verification key: FAIL. A key in the receipt is only a hint.
11. The signature is invalid under the profile of {{profile}} for the
    verification key and PAE(type, B) with the fixed type: FAIL. A signature
    made over PAE with another type fails here.

Table 2 lists every vector of {{vectors}} with the step at which it fails
first; each of the eleven steps is the first failing step of at least one
vector. A vector shows the first failing step under in-order evaluation;
it does not show that a later step would also reject it. Of the profile, the
vectors cover rule 1 for the key (N18) and for R (N17), rule 2 for the key
(N12, and N61 for a key of mixed order) and for R (N16, and N59 for an R of
mixed order), rule 3 (N6) and rule 4 (N7). No vector isolates rule 1
from rule 2. Rule 1 rejects 40 encodings that a decoder reducing y modulo p
would try (y from p to p + 18 with either sign bit, and x = 0 with the sign
bit set); read by such a decoder, 14 of them give no point, 6 give points of
small order and 20 give points of mixed order. None of these 26 points has
order L, so a Receiver without rule 1 would still reject each of them under
rule 2; N17 and N18 use y = p + 1, which such a decoder reads as the neutral
element. P6 has no key hint, so step 10 has nothing to compare. N61 uses the
mixed-order test key, the issuer's public point plus a point of order 8, with a
signature that satisfies the cofactorless equation; only rule 2 rejects it.
Its expected result is FAIL at step 11, rule 2 for the verification key. N59
uses the issuer test key and an R of mixed order, the point `r*B'` plus the same
point of order 8, with `S = r + k*a mod L`; the cofactored equation holds and the
cofactorless one does not, and rule 2 rejects R before rule 4 is reached. P9 and N51 to N55 pin rules that no other vector
reaches: the year 0000 (P9), ASCII digits (N51), a number without a finite
double (N52), the key before R in rules 1 and 2 (N53, N54), and no number rule
at step 1 (N55). N56 writes `n` as `1800.0`, which a Receiver that skipped the
number serialization of RFC 8785 would accept. P10 carries the optional
`criteria_digest`; N57 gives it uppercase hexadecimal digits and N58 the value
null. The receipts without the member are the other positive vectors. P12 is
the receipt of P1 followed by a line feed, insignificant whitespace that step 1
admits. N60 is B of P1 followed by a line feed, signed anew: step 4 admits the
line feed under the rules of step 1, and step 5 rejects B, because its RFC 8785
serialization has no insignificant whitespace. P13 is a line feed followed by
the receipt of P1, insignificant whitespace before the JSON text that step 1
admits.

@@VECTORS_TABLE@@

# What a Receipt Does Not Prove {#non-claims}

Verification establishes that the receipt passes the format, consistency and
signature checks in {{verification}} under the Receiver's selected key. It does
not establish that the Issuer's claims are true.
In particular:

* The score can be false. The evaluation can be wrong, badly designed or not
  run at all; the receipt records what the Issuer states.
* The run need not have been the only run. An Issuer can evaluate many times
  and record only the run it prefers.
* The Issuer can lie. A valid signature binds the statement to the key, not to
  the truth.
* A receipt does not show that it was published, logged or shown to anyone
  else. A receipt does not prove registration with a Transparency Service. In
  SCITT, transparency additionally requires registering a Signed Statement
  carrying the receipt or its digest with a Transparency Service and verifying
  the resulting SCITT Receipt. Registration and verification of the resulting
  SCITT Receipt are outside this document.
* The receipt bytes are not a stable name for the receipt. Only B is signed;
  the receipt object around it is not canonicalized, and its key hint can be
  present or absent. A party that cites a receipt cites SHA-256 over B.
* A commitment is computationally binding under the collision resistance of
  SHA-256. A Receiver can check a claimed opening only after receiving the salt
  and identifier. Hiding depends on keeping an unpredictable salt secret.
* The timestamp is the Issuer's statement, not a time attested by another
  party.
* The receipt says nothing about individual samples: `n` is the Issuer's
  statement, and no sample result is committed or can be disclosed against the
  receipt. A sample-level audit is outside this document and is left to a
  separate document.
* A receipt does not show that the threshold was fixed before the run.
* `criteria_digest` binds only the Issuer's statement that this result belongs
  to the criteria set with that digest. It shows neither that the criteria set
  existed before the run nor that the metric, comparator and threshold in it
  equal those in the receipt.
* Even with salt and identifier disclosed, the receipt does not show that the
  named model or dataset was the one actually evaluated.
* A receipt does not show where B came from. B carries no reference to another
  receipt or record that it was made from, for example when an Issuer
  translates the result of another format into a receipt; this format has no
  member for it.

# Related Work {#related}

The following individual drafts also define signed receipts; each sentence
states a difference in construction as read on 2026-10-10.

* {{I-D.farley-acta-signed-receipts}} records access control decisions,
  serializes them with RFC 8785, makes Ed25519 mandatory to implement, permits
  ES256 and recommends ML-DSA-65, and offers an optional commitment mode that
  places salted field values in a Merkle tree hashed as in Certificate
  Transparency ({{RFC9162}} Section 2.1.1).
* {{I-D.chueayen-attestation-receipts}} records AI inference decisions in a
  closed set of twelve required members, the signature among them, and three
  optional members, signed with Ed25519, under a canonicalization that, by its own statement, differs from
  RFC 8785 only in forbidding numbers that RFC 8785 writes in exponential
  notation.
* {{I-D.marques-asqav-compliance-receipts}} profiles action receipts with
  RFC 8785, requires ML-DSA-65 for new issuance, accepts Ed25519 only under a
  separately selected historical format, and requires a hash chain between
  receipts.

None of the three, as read on that date, has a member for an evaluation
threshold. Two further individual drafts concern evaluation evidence without
defining a signed result:

* {{I-D.abak-ai-evaluation-claim-preservation}} states format-neutral
  requirements for converting and consuming evaluation evidence so that
  claim-relevant loss stays visible; it defines no wire format, while this
  document defines one signed format for one result.
* {{I-D.ozturk-scitt-prml-profile}} carries pre-run evaluation criteria in the
  format of {{PRML}} as a SCITT Signed Statement, in full or as the 32-octet
  SHA-256 of their canonical bytes; it records criteria before a run, while a
  receipt records one result after it and names such criteria at most by
  `criteria_digest` ({{criteria}}).

# Security Considerations {#security}

This section follows the guidance of {{RFC3552}}. The attacker considered can
read, create, modify, replay and reorder receipts, and controls every input
except the Receiver's choice of verification key.

Forgery. Without the secret key an attacker cannot produce a receipt that
verifies under the Receiver's key, given the security of Ed25519. The Receiver
fixes the key out of band; a key carried in the receipt is only compared with
it and never used on its own. A Receiver that took the key from the receipt
would accept any receipt from anyone.

Domain separation. The signature covers PAE(type, B), not B alone. A signature
made by the same key for another purpose over the same bytes, or over the same
bytes under another type, does not verify as a receipt, and a receipt
signature does not verify as a signature over B in another protocol that also
signs with PAE under a different type. The type is fixed ({{type}}) so that
this separation does not depend on a value the attacker controls.

Ambiguous bytes. Duplicate member names (also when they differ only in
escapes), trailing data, a byte order mark, surrogate or noncharacter code
points, non-canonical base64 and payload bytes that are not their own RFC 8785
form, for example a number written as `1800.0`, would let two parsers see different
content behind one signature. The procedure of {{verification}} rejects each
of them, so that one B has one meaning. The receipt object around B is not
canonical and not signed ({{non-claims}}).

Ed25519 edge cases. Implementations of Ed25519 differ in whether they accept a
non-reduced S, non-canonical point encodings, points of small or mixed order, and whether
they use the cofactored or the cofactorless equation {{TAMING}}. A receipt
format whose verdict depends on the library would let one Receiver accept what
another rejects. The profile of {{profile}} fixes each choice. Vector N12 shows
why rule 2 refuses points of small order: with the neutral element as
verification key, `R = S*B'` satisfies the cofactorless equation for every
message. N61 and N59 show why rule 2 requires order L: under a key or with an R
of mixed order the cofactored and the cofactorless equation can disagree
(N59), and a verifier that does not check the order accepts N61 under either
equation. In the measurements of {{impl}}, the plain Ed25519 verification of
a general library accepted the signatures of vectors N12, N16, N18 and N61
and rejected those of N6, N17 and N59; the profile of {{profile}} rejects
all seven. A Receiver that relies on
a library verdict alone therefore does not implement this format.

Resource limits. This document defines no universal input-size limit.
Oversized inputs, long strings and deeply nested invalid JSON can exhaust
memory or processing time before verification completes. Implementations
SHOULD apply documented resource limits before and during processing of
untrusted input. Reaching a limit MUST NOT produce PASS and is reported as a
resource-limit error, not as a completed format or signature verdict under
{{verification}}.

Commitments. A commitment with a short or guessable salt can be tested against
candidate identifiers. The salt is therefore 16 bytes from a cryptographically
secure source and stays with the Issuer.

Criteria digest. `criteria_digest` binds the bytes of a criteria set, not a
time. Whoever wants to show that the criteria set existed before the run needs
an anchor outside the receipt, for example the digest of the criteria set
registered with a Transparency Service before the run began. The member also
carries weight only when the Receiver compares it with bytes of the criteria
set that it obtained independently of the state it checks: criteria bytes
taken from the same place as the result can have been changed together with
it, and their digest then matches.

Replay. A receipt is a static statement, not an authentication token. Showing a
valid receipt proves nothing about the party that shows it.

Key compromise. A compromised key can sign receipts with any content. This
document defines no revocation; a Receiver that needs it uses means outside this
document.

# Privacy Considerations {#privacy}

Model and dataset identifiers appear only as salted commitments. Reusing the
same salt and identifier produces the same commitment across receipts. Fresh
salts avoid this equality link but do not make receipts unlinkable, because
verification keys and other shared values may still link them: identical
suite, metric and timestamp values link receipts, and so does the same
`criteria_digest`. Disclosing salt and identifier to one Receiver discloses
them to everyone that Receiver passes them on to.

# IANA Considerations {#iana}

This document has no IANA actions. Registering the media type of
{{iana-media-type}} in the vendor tree goes directly to IANA ({{RFC6838}}
Section 3.2) and is not an action of this document.

## Media Type Registration Template {#iana-media-type}

The following template for application/vnd.signed-evidence.eval-receipt+json
is the one for its registration in the vendor tree; it is given for
information.

This media type identifies the canonical payload bytes B defined in {{bytes}}.
It does not identify the receipt object of {{receipt-object}}, which may be
transferred as application/json. The receipt object's schema member remains the
fixed format discriminator defined in {{type}}.

Type name:
: application

Subtype name:
: vnd.signed-evidence.eval-receipt+json

Required parameters:
: N/A

Optional parameters:
: N/A

Encoding considerations:
: Binary. The representation is B, a UTF-8 JSON text in the canonical form
  defined in {{bytes}}, without a byte order mark.

Security considerations:
: B is data and contains no active content: it carries no directive and
  nothing a recipient executes. B is not compressed. A receipt that carries B
  gives integrity and origin of B only under a key the Receiver fixed before
  verification, and only with the procedure of {{verification}}; a key named
  in the receipt is never used on its own. B gives no confidentiality: its
  members are readable by anyone who holds it, and model and dataset
  identifiers appear in it only as salted commitments ({{commitments}},
  {{privacy}}). Parsing untrusted input needs documented resource limits;
  reaching a limit is not a verdict. See {{security}} of this document.

Interoperability considerations:
: When processing completes without a resource-limit error, the procedure of
  {{verification}} and the signature profile of {{profile}} determine the
  verdict and first failing step on the vectors of {{vectors}}. The type string enters
  every signature ({{type}}).

Published specification:
: This document.

Applications that use this media type:
: Issuers and Receivers of evaluation payloads, including DSSE envelopes that
  carry B and digest references that identify B.

Fragment identifier considerations:
: As specified for the `+json` structured syntax suffix in {{RFC6839}}
  Section 3.1. This document defines no fragment identifier of its own.

Additional information:
: Deprecated alias names for this type: N/A. Magic number(s): N/A. File
  extension(s): N/A. Macintosh file type code(s): N/A.

Person & email address to contact for further information:
: Konrad Gruszka <kontakt@b7n0de.com>

Intended usage:
: COMMON

Restrictions on usage:
: N/A

Author:
: Konrad Gruszka

Change controller:
: Konrad Gruszka <kontakt@b7n0de.com>

# Implementation Status {#impl}

This section records the status of known implementations at the time of
writing, following {{RFC7942}}, and is to be removed before publication.

The vectors of {{vectors}} were produced by a generator script whose two runs
are byte-identical, and verified by two verifiers: one written by the author of
the generator, and one written from the text of this document alone, without
access to the generator. Both verifiers reach the expected verdict and the expected first failing step
on every vector. An implementation of this format in the proofbundle project, behind an
explicit option and with these vectors as conformance tests, is under way on a
work branch and not released. That implementation refuses a verification key
that rule 1 of {{profile}} rejects or that is a point of small order, as in
vectors N12, N18, N53 and N54, already when the Receiver fixes it and before it
reads any receipt; the verdict stays FAIL. A key of mixed order, as in N61, it
refuses at step 11.

In the measurements behind {{vectors}}, the plain Ed25519 verification of
pyca/cryptography 41.0.7 accepted the signatures of vectors N12 (small-order
key), N16 (small-order R), N18 (non-canonical key) and N61 (mixed-order key),
and rejected those of N6 (S not below L), N17 (non-canonical R) and N59
(mixed-order R).

In a local measurement on 2026-10-10, a receipt made from the result of a test
run was checked by the implementation named above and by the verifier written
from the text of this document alone. Both passed it, and both refused the
same receipt with one byte of B changed, at step 11.

--- back

# Test Vectors {#vectors}

Vector identifiers are labels: a P vector expects PASS, an N vector expects FAIL,
and gaps in the numbering carry no meaning.

@@VECTORS_APPENDIX@@

# Open Items (to be removed before publication)
{:numbered="false"}

* References. Every reference is to be re-checked against the published
  documents at submission time.
* Implementation status. To be updated with the conformance result of the
  implementation named in {{impl}}.
