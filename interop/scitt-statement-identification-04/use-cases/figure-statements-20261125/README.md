# Use case: 716 figure statements of one publisher, and one it signed by mistake

This folder holds third-party statements, read with the statement-identification reader of this repository. They are figure statements that Ziya Yetiş publishes at financeratecalc.com under draft-yetis-scitt-figure-receipts (https://datatracker.ietf.org/doc/draft-yetis-scitt-figure-receipts/). They are here with his permission of 25 November 2026, credited to him. Nothing here adds a rule to draft-gruszka-scitt-statement-identification.

## What the case shows

The publisher lists, for each of 716 figures, every digest it has issued, under the ToBeSigned scheme of Section 5.1 of the draft. Each of the 716 statements matches the reference its list gives, and its ES256 signature verifies under the publisher's key.

One version of one statement, served at 08:27:33 UTC on 25 November 2026, lacked its limits member. Its signature verifies under the same key, and it does not match the reference of its figure. Its digest was not on the list that morning. At sequence 3 the list carries it, marked as issued in error, before the statement in force. A relying party that uses the list does not accept it as a statement of the publisher. A match and a valid signature together do not show that the publisher stands behind a statement.

## Where the bytes come from

All files were fetched over HTTPS on 25 November 2026 and are kept as fetched.

- statements/: the 716 statements, one per figure, fetched from 08:25:09 to 08:33:29 UTC. For metro-gap-fort-wayne-in-2025 the file is the version that two fetches at 08:34 UTC returned, the one the list names.
- negative/metro-gap-fort-wayne-in-2025-20261125T082733Z.cose: the version of that statement fetched at 08:27:33 UTC, 2792 bytes, SHA-256 19e971239d3c9548c6091b7184211c90be3a24d7f629556bd8c99ae9e5e7a175.
- lists/statement-digests-20261125T082243Z.json: the list https://financeratecalc.com/transparency/statement-digests.json as fetched at 08:22:43 UTC, before the digest of the negative case was on it.
- lists/statement-digests-sequence-3.json: the same list at sequence 3, fetched at 21:46:08 UTC. Its previous_sha256 chains it to sequence 2.
- statement-key.json: the publisher's key, fetched at 08:38:44 UTC from https://financeratecalc.com/transparency/statement-key.json, key_id 07e9b801b771c9ea.

## Running the check

From the repository root, PYTHONPATH=src python3 interop/scitt-statement-identification-04/use-cases/figure-statements-20261125/check_figure_statements.py prints one line per check and exits with 0 only if every check gives its expected result. The match axis comes from proofbundle.scitt_statement_id with the scheme ToBeSigned, alg -16 and an empty external_aad. That reader checks Ed25519 only, so the ES256 signature is checked separately in check_figure_statements.py with cryptography, against the key in statement-key.json. tests/test_interop_figure_statements_use_case.py runs the check and three counter-checks.

## Files and licence

Check the files with sha256sum -c MANIFEST.sha256 in this folder. The statements, the two lists and the key are the publisher's, included with his permission. They are not under the LICENSE of the parent folder. check_figure_statements.py, this README and MANIFEST.sha256 are under that LICENSE.

Assisted by little helpers.
