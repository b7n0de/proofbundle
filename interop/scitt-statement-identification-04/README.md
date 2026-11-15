# Cases of draft-gruszka-scitt-statement-identification-04

This folder holds the 54 illustrative cases of draft-gruszka-scitt-statement-identification-04, C1 to C54, as files a checker can read, and check_cases.py, which recomputes the result of Section 6 for each case with the Python standard library and compares it with the result the draft gives. The draft is at https://www.ietf.org/archive/id/draft-gruszka-scitt-statement-identification-04.txt (SHA-256 c76e5c50aa9f8ebe4e8071c4735034e41836fffbfefbcc0bba6b6daff4028a6b). Nothing here adds a rule to the draft.

Cases C1 to C14 are those of draft-gruszka-scitt-statement-identification-03, with the same inputs and expected results; their files differ from those in interop/scitt-statement-identification-03 only in the member draft. Cases C15 to C54 are new in -04, for checks of Section 6. COVERAGE.md is Table 3 of the draft: every check of Section 6, the cases that exercise it, and why six checks have no case.

## Where the bytes come from

draft-gruszka-scitt-statement-identification-04.txt in this folder is that text, unmodified. tools/build_cases.py reads it and stops unless its SHA-256 is the one above. It takes every byte string from the hex of Appendix A and every change value from the words of Appendix A.3 and Section 6; the only constants in its code are those of the CBOR and COSE encodings and the DER prefix of an Ed25519 SubjectPublicKeyInfo. It applies to a base statement of Appendix A.1 the change each case of Appendix A.3 states, and stops unless the result has exactly the length and the SHA-256 the case gives. Cases C24 to C48 and C51 to C54 state their change as bytes at offsets of statement 01 or of the reference of Appendix A.1, with the old bytes where they are short; the script reads every such change, stops unless the old bytes stand at their offset, and applies the changes from the last offset back. Where a case gives new signature bytes, it also checks them against the words of the case: in C18 that R encodes y = p + 1, in C19 that R is the encoding of the neutral element, in C20 that R is unchanged and S is the S of statement 01 plus L, and in C33 that the new signature verifies under the issuer key. The reference of C50 is checked against SHA-512 over the ToBeSigned of statement 01. It reads the expected result from Table 2 of Section 6 and from the measured line of each case and stops unless both agree, and it reads from Section 6 which case names another scheme, which case names an external_aad it does not supply, and which case is supplied with a detached payload. It also checks the reference digest of Appendix A.1 against the ToBeSigned of statement 01, each kid of Appendix A.2 against the key derived from its seed, and the signatures of the three base statements. python3 tools/build_cases.py draft-gruszka-scitt-statement-identification-04.txt OUT_DIR writes cases/, base_statements.json and test_keys.json of this folder byte for byte.

## Case files

Each file cases/<id>.json has the members id, draft, source, requirement, what_it_shows (from Table 2), derivation (the words of Appendix A.3 for the case), inputs and expected, and for C1, C7, C8, C11, C19, C20 and C23 variants. Every byte string is an object with base64, sha256 and length.

inputs holds candidate, reference, scheme, external_aad, detached_payload and stated_key. scheme is the named scheme of Section 6: alg -16 and name "ToBeSigned"; alg -44 in C10 and C50; alg -16 and name "WholeBytes" in C15, a scheme the draft does not define. external_aad is the empty byte string except in C7, which gives its bytes, and in C22, where it is null: the case names the external_aad of C7 and does not supply it. detached_payload is null except in C23, where it is the payload of statement 01. stated_key is the issuer key of Appendix A.2 by its 32-byte public key.

expected holds ref_usable, match, is_scitt and sig_valid, and a sig_valid of null means not evaluated; in C15 it is the string "UNSUPPORTED" in place of the axes, because a named scheme the verifier does not implement gives no axes. A variant is a further result Appendix A.3 states in words: it changes external_aad or detached_payload, or, in C11, C19 and C20, the rules sig_valid is computed under, and gives only the axes the draft states for it. A variant with a rule left out describes a verifier that does not claim the profile sid-ed25519-strict; it is not a result under it.

base_statements.json holds statements 01, 02 and 03 and the reference of Appendix A.1. test_keys.json holds the two keys of Appendix A.2 as the draft gives them: PURE TEST KEYS given as fixed seeds. They MUST NOT be used for any real statement.

## Running the check

python3 check_cases.py prints one line per case and per variant and exits with 0 only if every check matches; with --cases DIR it reads the case files of another folder. It implements the ToBeSigned scheme of Section 5.1 with the hash functions Section 6 names; a case file that names any other scheme gives UNSUPPORTED. An external_aad or a detached payload given as null is not supplied, and where it is needed, match is INDETERMINATE and sig_valid null. Measured with Python 3.10.12 on Linux: 63 of 63 checks match, 54 cases and 9 variants.

The checker reads Section 6 as its docstring states. One choice is its own and reaches none of the 54 cases: CBOR nested deeper than 200 levels or longer than 1 MiB ends the run with an error instead of a result. No input of the cases is longer than 450 bytes or nests deeper than seven levels, counted as Section 6 states.

## Adding a use case

Open a pull request that adds a folder use-cases/<name>/ with its own case files, its own expected results and a README that says what the case shows and where its bytes come from. The files under cases/, C1 to C54, stay as they are. A case that fits the four axes of Section 6 under the ToBeSigned scheme can use the form above and is checked with python3 check_cases.py --cases use-cases/<name>; a case that needs another scheme or other results describes them in its README.

## Files and licence

Check the files with sha256sum -c MANIFEST.sha256. The draft text is an IETF document, copied in full and without modification; it is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) and not to LICENSE. Every other file is under the licence in LICENSE. The byte strings and keys of the case files come from Appendix A of the draft, whose author, the copyright holder named in LICENSE, grants them under LICENSE in addition to the licences the IETF Trust grants for the draft.

Assisted by little helpers.
