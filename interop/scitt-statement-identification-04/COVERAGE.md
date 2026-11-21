# Checks of Section 6 and the cases that exercise them

This is Table 3 of draft-gruszka-scitt-statement-identification-04. Every check that Section 6 of the draft places on a verifier is listed with the cases that exercise it; a check without a case says why.

## Reference (ref_usable)

| Check | Cases |
|---|---|
| one well-formed CBOR data item | C24 |
| valid under RFC 8949 Section 5.3.1 | C25 (UTF-8); two equal map keys could only stand in an element whose type already makes the reference not well-formed |
| nothing after the data item | C16 |
| an array of exactly three elements | C26 |
| alg is an integer | C27 |
| alg names one of the eight hash functions | none: an alg outside this set cannot equal -16 or -44, the algorithms of the implemented named schemes used by these cases; C10 already exercises algorithm mismatch |
| scheme is a text string | C28 |
| digest is a byte string | C29 |
| digest has the output length of the hash function | C13 |
| alg equals that of the named scheme | C10 |
| scheme equals that of the named scheme | C14 |
| the deterministic encoding is not required | C51 |

## Candidate (is_scitt)

| Check | Cases |
|---|---|
| one well-formed CBOR data item | C52 |
| nothing after the data item | C30 |
| bare or with tag 18 | C9 (bare), C31 (tag 17) |
| an array of exactly four elements | C17 |
| protected header is a byte string | C32 |
| protected header is empty or encodes one map | C33 (empty), C34 (an array), C35 (two data items) |
| unprotected header is a map | C36 |
| payload is a byte string or nil | C8 and C23 (nil), C37 (a text string) |
| signature is a byte string | C38 |
| text strings are valid UTF-8, in either header | C39 (unprotected), C40 (protected) |
| no two map keys are equal under RFC 8949 Section 5.6.1 | C41 (1 and 1), C42 (1 and 1.0), C43 (1 and true), C44 (0.0 and -0.0), C45 and C46 (NaN), C47 (arrays), C53 (maps), C54 (tags) |
| the content of a tag is not checked for that tag | C48 |
| header labels and header parameter semantics are not validated | C42 (a label 1.0), C43 (a label true), C45 (two NaN labels) |
| the deterministic encoding is not required | C12 |

## Signature (sig_valid)

| Check | Cases |
|---|---|
| a signature that is not 64 bytes gives False | C21 |
| no ToBeSigned gives None | C8, C22 |
| rule 1 for R | C18, whose R rule 2 refuses as well; no case can separate the two rules for R, because an R that only rule 1 refuses would encode a point r*B' with y below 19, and finding such an r is infeasible |
| rule 1 for A | none: A is the issuer key of Appendix A.2 in every case |
| rule 2 for R | C11 (mixed order), C19 (neutral element) |
| rule 2 for A | none: A is the issuer key of Appendix A.2 in every case |
| rule 3 | C20 |
| rule 4, the cofactorless equation | C6; C7 and C8 in their variants |
| a batch result does not replace the four rules | none: each case checks one signature |

## Match (match)

| Check | Cases |
|---|---|
| the digest of ToBeSigned is compared with the reference | C1 to C4, C7; C50 (SHA-512) |
| a missing input gives INDETERMINATE | C8, C22 |
| an unusable reference gives INDETERMINATE | C10, C13, C14, C16, C24 to C29 |
| a candidate that is not a statement | C17 (usable reference), C49 (unusable reference) |
| a supplied detached payload takes the place of nil | C23 and its variant |
| a supplied detached payload is not used when the payload is embedded | the variant of C1 |

## Result

| Check | Cases |
|---|---|
| a named scheme the verifier does not implement gives UNSUPPORTED | C15 |
| an empty check set is INDETERMINATE, not a match | none: ref_usable and is_scitt are computed for every input under a scheme the verifier implements, so no case has an empty check set |
| a result states the profile under which its sig_valid was computed | none: a case gives the expected axes, not the form of a report |

Assisted by little helpers.
