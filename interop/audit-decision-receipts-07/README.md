# Starter cases for draft-gruszka-audit-decision-receipts-07

This folder holds 37 cases for checking a verifier of draft-gruszka-audit-decision-receipts-07 in an afternoon. Each case is one vector of the test package that Appendix A.5 of the draft names, the archive draft-gruszka-audit-decision-receipts-07-test-vectors.tar.gz with SHA-256 8704d61f1ff29f5619ad3ecb20866cbb213a57dfb03149aedea8c4b1b48bf818 and 159 vectors. The case keeps the identifier of the vector, its input bytes are those of the package byte for byte, and its expected result is the one the package gives. Nothing here adds a rule to the draft.

## What a verifier needs

A verifier implements Section 3.1 to Section 3.4 with the field rules of Section 3.8. K1 to K3 also need the third check of Section 3.5 over the receipts an Auditor holds, and F10 needs item 1 and item 2 of Section 4 for a relying party. The first and second checks of Section 3.5 have no case here, because the package has no vector for them. Step 5 of Section 3.2 computes the content root and cannot fail on its own.

## Case files

Each file cases/<id>.json has the members id, draft, source (the appendix or the test package), derivation (how the vector is built from another one, as the package describes it), procedure, inputs and expected. Every byte string is an object with base64, sha256 and length, and a verifier decodes base64 and works on those bytes, not on a parsed copy. In inputs, T is the evaluation time of Section 3.1 and trust_policy maps each Ed25519 public key, as base64 of its 32 bytes, to the identifiers it may sign for, under decision for decision receipts and under outcome for outcome receipts. decision holds the envelope of the decision receipt, its public_key, expected_decision_maker, expected_audience, expected_nonce and action_bytes. case is approval, declined or executed and selects the case of Section 3.3. approval_record holds the bytes of Case 1. outcome is null for a decision receipt alone, and otherwise holds the outcome envelope, its public_key, expected_executor and effect_bytes. held_receipts lists the receipts an Auditor holds for the third check of Section 3.5, each with its envelope and with public_key, the expected signing key under which the Auditor checks it. consumption_state is the current consumption state of a relying party, a JSON array of approval identities as Appendix A.5 gives c1. A null member is an input that is not given. V3-seq carries the member sequence with runId "r1" and seq 1 in its outcome payload, as its bytes show.

## Calling a verifier

Run python3 run_cases.py -- COMMAND ARGS with the command of your verifier, for example python3 run_cases.py -- ./my-verifier. It reads the cases in cases/ next to it. For each case the script runs the command with the path of the case file as its last argument and reads the first line of standard output. That line is one JSON object such as {"result": "fail", "step": "3.4 step 1"}. result is pass, fail, refuse or auditor-fail. refuse means the receipt passes and the relying party refuses it under Section 4, auditor-fail means the receipt passes and the third check of Section 3.5 fails. step is null for pass and otherwise one of "3.2 step 1" to "3.2 step 10", "3.3 case 1" to "3.3 case 3", "3.4 step 1" to "3.4 step 7", "3.5 third check" or "4 item N", where N is the item of Section 4 on which the refusal rests. A failure of the decision receipt inside Case 3 is named by its step of Section 3.2, a failure of the outcome envelope by step 1 of Section 3.4.

## What counts as a match

A case matches when result equals expected.result and, unless the expected result is pass, step equals expected.step. The script prints one line per case and exits with 0 only if every case matches. With --accept-reject it only asks whether the verifier accepts exactly the cases whose expected result is pass. The exit code of the verifier is not used.

## Measured with

run_cases.py ran under Python 3.11.18, with the Go verifier of the test package, built with Go 1.24.7 on linux/amd64, and with proofbundle 6.4.0 and 6.5.0 from PyPI, called with the commands of Appendix A.3.

## Files and licence

Check the files with sha256sum -c MANIFEST.sha256. All keys are the published test keys of the draft and are not for real receipts. The folder is under the licence in LICENSE.

Assisted by little helpers.
