# A fresh challenge set for a second implementation of SER -02

The 66 vectors of Appendix A of draft-gruszka-signed-evaluation-receipts-02 are public together with their expected
results. A submission that reports 66 of 66 therefore shows only that it can read Appendix A. Each submission
answers a challenge set of its own instead, generated for it and never published. The comparison reads the
submission's answers and runs no foreign code.

## The two calls

Python 3, standard library only.

```
./pruefmenge_erzeugen <kennung> [--anzahl N]
./pruefmenge_vergleichen <kennung> <answers.jsonl> [--json auswertung.json]
```

`pruefmenge_erzeugen` creates the folder `$SER_PRUEFMENGE_ORDNER/<kennung>` (default `~/ser_pruefmengen/<kennung>`).

| File | Stays or goes out | Content |
| --- | --- | --- |
| `seed.hex` | stays | 32 bytes from `os.urandom`, mode 0600 |
| `challenge.jsonl` | goes out | `{"id": "c001", "receipt_b64": "...", "key_b64": "..."}` per line |
| `expected.jsonl` | stays | `{"id", "verdict", "step", "detail"}` per line |
| `befunde.jsonl` | stays | entries the two verifiers disagreed on, left out of the set |
| `bauarten.jsonl` | stays | the kind of each entry |
| `erzeugung.json` | stays | counts and SHA-256 digests |

A second call with the same name reads `seed.hex` again and writes the same bytes. A call with another count refuses
to overwrite `challenge.jsonl`. The name `anhang-a` is reserved.

`pruefmenge_vergleichen` compares `answers.jsonl` with `expected.jsonl`. It reports:

- the agreement in verdict, step and profile rule, overall and per expected answer;
- each deviation, with its id and both answers;
- missing, duplicate and foreign ids, and broken lines.

`pruefmenge_vergleichen anhang-a results.jsonl` compares a `results.jsonl` for Appendix A in the same form.

| Exit | Meaning |
| --- | --- |
| 0 | The answer is complete and readable, whatever the number of deviations. |
| 1 | Ids are missing, duplicate or foreign, or a line is broken. |
| 2 | The call cannot run. |

## How a set is made

A set is fixed by the seed, the count (200 by default) and the name. The same three give byte-identical files.

- Every set has its own test issuer key, a second key, a key of mixed order, and salts.
- About a third of the entries are valid. About an eighth are valid receipts with one byte changed.
- The rest mix all eleven steps of Section 5 and the four rules of the verification profile, including:
  - edge cases of the RFC 8785 number form;
  - keys of small order and of mixed order;
  - non-canonical point encodings and S not below L.
- No entry equals a vector of Appendix A byte for byte.

## Where the expected answers come from

Both verifiers of this draft compute the expected answer of each entry:

- `examples/check_receipts.py`, written by the generator's author;
- `independent/verify_from_text.py`, written from the text alone.

An entry on which they differ in verdict, first failing step, or profile rule is left out of the set and recorded in
`befunde.jsonl` as a finding on the text. Entries that hit a resource limit of the verifiers are left out as well,
because the draft fixes no limit values.

## Tests

```
python3 -m unittest test_pruefmenge
```

The contract tests check that:

- both verifiers, answering as submitters, reach 100 percent;
- an answer of PASS for everything, the Appendix A results in order, and a mixed answer file fall clearly short;
- missing and duplicate ids are found;
- the same seed gives the same bytes, and another seed gives different bytes.

Keys and seeds in the tests are test material only.
