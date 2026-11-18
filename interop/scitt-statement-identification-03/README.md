# Cases of draft-gruszka-scitt-statement-identification-03

This folder holds the 14 illustrative cases of draft-gruszka-scitt-statement-identification-03, C1 to C14, as files a checker can read, and check_cases.py, which recomputes the four axes of Section 6 for each case with the Python standard library and compares them with the axes the draft gives. The draft is at https://www.ietf.org/archive/id/draft-gruszka-scitt-statement-identification-03.txt (SHA-256 9176957ab9f3a4f4daca9dde67b3bcbb812417697f20e813c3ef3102c85bd95c). Nothing here adds a rule to the draft.

## Where the bytes come from

draft-gruszka-scitt-statement-identification-03.txt in this folder is that text, unmodified. tools/build_cases.py reads it and stops unless its SHA-256 is the one above. It takes every byte string from the hex of Appendix A and every change value from the words of Appendix A.3 and Section 6; the only constants in its code are those of the CBOR and COSE encodings and the DER prefix of an Ed25519 SubjectPublicKeyInfo. It applies to a base statement of Appendix A.1 the change each case of Appendix A.3 states, and stops unless the result has exactly the length and the SHA-256 the case gives. It reads the expected axes from Table 2 of Section 6 and from the measured line of each case and stops unless both agree. It also checks the reference digest of Appendix A.1 against the ToBeSigned of statement 01, each kid of Appendix A.2 against the key derived from its seed, and the signatures of the three base statements. python3 tools/build_cases.py draft-gruszka-scitt-statement-identification-03.txt OUT_DIR writes cases/, base_statements.json and test_keys.json of this folder byte for byte.

## Case files

Each file cases/<id>.json has the members id, draft, source, requirement, what_it_shows (from Table 2), derivation (the words of Appendix A.3 for the case), inputs and expected, and for C1, C7, C8 and C11 variants. Every byte string is an object with base64, sha256 and length.

inputs holds candidate, reference, scheme, external_aad, detached_payload and stated_key. scheme is the named scheme of Section 6, alg -16 and name "ToBeSigned", or alg -44 in C10. external_aad is empty except in C7. detached_payload is null when no detached payload is supplied. stated_key is the issuer key of Appendix A.2 by its 32-byte public key.

expected holds ref_usable, match, is_scitt and sig_valid; a sig_valid of null means not evaluated. A variant is a further result Appendix A.3 states in words: it changes external_aad or detached_payload, or, in C11, the rules sig_valid is computed under, and gives only the axes the draft states for it.

base_statements.json holds statements 01, 02 and 03 and the reference of Appendix A.1. test_keys.json holds the two keys of Appendix A.2 as the draft gives them: PURE TEST KEYS given as fixed seeds. They MUST NOT be used for any real statement.

## Running the check

python3 check_cases.py prints one line per case and per variant and exits with 0 only if every check matches; with --cases DIR it reads the case files of another folder. It implements the ToBeSigned scheme of Section 5.1 only: a case file that names another scheme is reported as an error, not as a result. An external_aad or a detached payload given as null is not supplied, and where it is needed, match is INDETERMINATE and sig_valid null. Measured with Python 3.10.12 on Linux: 19 of 19 checks match, 14 cases and 5 variants.

The checker reads Section 6 as its docstring states. Two choices are its own and reach none of the 14 cases: a reference alg names a hash function when it is one of the eight hash algorithms of RFC 9054, each with a fixed output length, and CBOR nested deeper than 200 levels or longer than 1 MiB ends the run with an error instead of a result.

## Adding a use case

Open a pull request that adds a folder use-cases/<name>/ with its own case files, its own expected results and a README that says what the case shows and where its bytes come from. The files under cases/, C1 to C14, stay as they are. A case that fits the four axes of Section 6 under the ToBeSigned scheme can use the form above and is checked with python3 check_cases.py --cases use-cases/<name>; a case that needs another scheme or other results describes them in its README.

## Files and licence

Check the files with sha256sum -c MANIFEST.sha256. The draft text is an IETF document, copied in full and without modification; it is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info) and not to LICENSE. Every other file outside independent/ is under the licence in LICENSE. The folder independent/oga/ holds a second reader of the 14 cases by Toshikatsu Oga (The HORIZONs Co., Ltd.), kept as received; its files are under the LICENSE in that folder, and its README says how the reader was written and where its limits are. The byte strings and keys of the case files come from Appendix A of the draft, whose author, the copyright holder named in LICENSE, grants them under LICENSE in addition to the licences the IETF Trust grants for the draft.

Assisted by little helpers.
