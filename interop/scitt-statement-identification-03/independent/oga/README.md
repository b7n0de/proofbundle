# A second reader of the 14 cases, by Toshikatsu Oga (The HORIZONs Co., Ltd.)

This folder holds the code and the results of an independent reader of the 14 cases of
draft-gruszka-scitt-statement-identification-03, written by Toshikatsu Oga (The HORIZONs Co., Ltd.) and sent to the
author of the draft on 12 November 2026. The six files are kept byte for byte as they were received. Their SHA-256 are
listed in MANIFEST.sha256 of the parent folder. They are under the MIT licence in LICENSE of this folder, with its
copyright line, and not under the LICENSE of the parent folder.

## How the reader was written

As its author describes it, the reader was written from the text of -03 only
(SHA-256 9176957ab9f3a4f4daca9dde67b3bcbb812417697f20e813c3ef3102c85bd95c), with the README of the parent folder for
the file format. Its author did not read or run check_cases.py or tools/build_cases.py of the parent folder. It uses
the Python standard library only, with its own CBOR reader and its own Ed25519 arithmetic from RFC 8032.

## Its two limits

- 19 of 19 agree with the case files: 14 cases and 5 variants, on every axis each one states. This is a result on the
  published cases and says nothing beyond them.
- The reader was blind to the code of this repository, not to the expected axes: Table 2 and the measured lines of
  Appendix A.3 are in the text it was written from.

## The files

- sid_axes.py, run_sid.py, compare_sid.py, mutants_sid.py: the reader and its scripts, as received.
- verdicts.json: the axes of the reader, computed with every expected member removed and frozen before they were
  compared. Its SHA-256 is c59d24f985579c82ad887cde9a96dd5c50be9ce3c03e6028238846b456b592d8, the value its author gave.
- mutants_01.jsonl: the axes of the reader for 988 single-byte mutants of statement 01, as its author describes it.

run_sid.py holds, as hex, the secret key of TEST 1 of RFC 8032 Section 7.1, for a self-test of its Ed25519
arithmetic. It is the test key published in the RFC, not a secret. A secret scanner may still report it.

## Two known limits of its CBOR reader

Its author agreed to this note and confirmed both limits on 15 November 2026, each with the smallest case. The six
files above are unchanged. The automated review on pull request 520 found both places in sid_axes.py:

- Line 81 joins the chunks of an indefinite-length text string before line 88 checks UTF-8, so the reader accepts
  7f61c361bcff: two chunks, 61 c3 and 61 bc, each invalid alone, that together encode U+00FC. RFC 8949 Section 3.2.3
  makes such a string invalid, because the bytes of one code point cannot be spread between chunks.
- Line 149 gives every NaN map key the same comparison value, so the reader rejects a2f97e0000f97e0100, a map with two
  half-precision NaN keys whose significands differ, as a duplicate key. Under RFC 8949 Section 5.6.1 the two keys are
  distinct, so the map is valid.

Neither path is taken by the 14 cases or by the 988 mutants, so the results for them above do not depend on these
limits.

Assisted by little helpers.
