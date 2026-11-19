# SER -04, the result of the verifier from the text for each vector

Generated from `ser_lauf.json`; `tests/test_ser04_verifier_from_text.py` renders it again from a fresh run and compares.

| Vector | Label | Expected | Expected first failing step | Verifier | Verifier first failing step |
|---|---|---|---|---|---|
| P1 | pass | PASS | all | PASS | all |
| P2 | recorded-failure | PASS | all | PASS | all |
| P4 | escaped-receipt-string | PASS | all | PASS | all |
| P6 | no-key-hint | PASS | all | PASS | all |
| P7 | comparator-le | PASS | all | PASS | all |
| P8 | exact-decimal | PASS | all | PASS | all |
| P9 | year-0000 | PASS | all | PASS | all |
| P10 | criteria-digest | PASS | all | PASS | all |
| P12 | receipt-trailing-whitespace | PASS | all | PASS | all |
| P13 | receipt-leading-whitespace | PASS | all | PASS | all |
| N1 | no-duplicate-names | FAIL | 4 | FAIL | 4 |
| N2 | receipt-schema | FAIL | 2 | FAIL | 2 |
| N3 | no-trailing-data | FAIL | 4 | FAIL | 4 |
| N4 | commitment-pattern | FAIL | 7 | FAIL | 7 |
| N5 | jcs-form | FAIL | 5 | FAIL | 5 |
| N6 | s-less-than-L | FAIL | 11 (profile 3) | FAIL | 11 (profile 3) |
| N7 | pae-type | FAIL | 11 (profile 4) | FAIL | 11 (profile 4) |
| N9 | key-hint | FAIL | 10 | FAIL | 10 |
| N10 | payload-schema | FAIL | 6 | FAIL | 6 |
| N11 | result-consistency | FAIL | 8 | FAIL | 8 |
| N12 | small-order-key | FAIL | 11 (profile 2, key) | FAIL | 11 (profile 2, key) |
| N13 | canonical-base64 | FAIL | 3 | FAIL | 3 |
| N14 | receipt-duplicate-names | FAIL | 1 | FAIL | 1 |
| N15 | signature-alg | FAIL | 9 | FAIL | 9 |
| N16 | small-order-R | FAIL | 11 (profile 2, R) | FAIL | 11 (profile 2, R) |
| N17 | noncanonical-R | FAIL | 11 (profile 1, R) | FAIL | 11 (profile 1, R) |
| N18 | noncanonical-key | FAIL | 11 (profile 1, key) | FAIL | 11 (profile 1, key) |
| N19 | receipt-trailing-data | FAIL | 1 | FAIL | 1 |
| N20 | receipt-member-set | FAIL | 1 | FAIL | 1 |
| N21 | signature-member-set | FAIL | 1 | FAIL | 1 |
| N22 | receipt-duplicate-after-unescaping | FAIL | 1 | FAIL | 1 |
| N23 | receipt-bom | FAIL | 1 | FAIL | 1 |
| N24 | payload-not-base64 | FAIL | 3 | FAIL | 3 |
| N25 | signature-length | FAIL | 9 | FAIL | 9 |
| N26 | signature-canonical-base64 | FAIL | 9 | FAIL | 9 |
| N30 | commit-alg | FAIL | 6 | FAIL | 6 |
| N31 | payload-member-missing | FAIL | 6 | FAIL | 6 |
| N32 | payload-member-extra | FAIL | 6 | FAIL | 6 |
| N33 | payload-member-type | FAIL | 6 | FAIL | 6 |
| N34 | decimal-grammar | FAIL | 6 | FAIL | 6 |
| N35 | n-at-least-1 | FAIL | 6 | FAIL | 6 |
| N36 | timestamp-calendar | FAIL | 6 | FAIL | 6 |
| N37 | timestamp-leap-second | FAIL | 6 | FAIL | 6 |
| N38 | comparator-set | FAIL | 6 | FAIL | 6 |
| N39 | non-empty-string | FAIL | 6 | FAIL | 6 |
| N40 | payload-utf8 | FAIL | 4 | FAIL | 4 |
| N41 | payload-lone-surrogate | FAIL | 4 | FAIL | 4 |
| N42 | payload-noncharacter | FAIL | 4 | FAIL | 4 |
| N43 | payload-bom | FAIL | 4 | FAIL | 4 |
| N44 | receipt-utf8 | FAIL | 1 | FAIL | 1 |
| N45 | receipt-lone-surrogate | FAIL | 1 | FAIL | 1 |
| N46 | receipt-noncharacter | FAIL | 1 | FAIL | 1 |
| N48 | comparator-gt | FAIL | 8 | FAIL | 8 |
| N49 | comparator-lt | FAIL | 8 | FAIL | 8 |
| N50 | n-below-2-53 | FAIL | 6 | FAIL | 6 |
| N51 | ascii-digits | FAIL | 6 | FAIL | 6 |
| N52 | number-without-double | FAIL | 5 | FAIL | 5 |
| N53 | key-before-R-rule-1 | FAIL | 11 (profile 1, key) | FAIL | 11 (profile 1, key) |
| N54 | key-before-R-rule-2 | FAIL | 11 (profile 2, key) | FAIL | 11 (profile 2, key) |
| N55 | receipt-number-at-step-2 | FAIL | 2 | FAIL | 2 |
| N56 | number-serialization | FAIL | 5 | FAIL | 5 |
| N57 | criteria-digest-pattern | FAIL | 7 | FAIL | 7 |
| N58 | criteria-digest-type | FAIL | 6 | FAIL | 6 |
| N59 | mixed-order-R | FAIL | 11 (profile 2, R) | FAIL | 11 (profile 2, R) |
| N60 | payload-trailing-whitespace | FAIL | 5 | FAIL | 5 |
| N61 | mixed-order-key | FAIL | 11 (profile 2, key) | FAIL | 11 (profile 2, key) |

66 of 66 vectors give the expected result and first failing step.
