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
| `bauarten.jsonl` | stays | the kind of each entry, and for an entry with two faults the later one |
| `erzeugung.json` | stays | counts and SHA-256 digests |

A second call with the same name reads `seed.hex` again and writes the same bytes. A call with another count refuses
to overwrite `challenge.jsonl`. The name `anhang-a` is reserved.

`pruefmenge_vergleichen` compares `answers.jsonl` with `expected.jsonl`. It reports:

- the agreement in verdict, step and detail, overall and per expected answer;
- the agreement in the verdict alone, and in the profile rule alone (without the key or R) for step 11;
- each deviation, with its id and both answers;
- missing, duplicate and foreign ids, and broken lines.

The comparison reads at most 10 MB (10 000 000 bytes) of the answer file. A larger file gives exit 2, is not read
further, and produces no report.

The answer file is foreign input, and the comparison reads each line on its own. A line is a broken line when it:

- is not UTF-8;
- is not one JSON text;
- names a member twice;
- nests deeper than the parser can follow.

Ids and details from the answer file appear in the report JSON-escaped to ASCII. The text report names at most 20
ids or lines per list, and `--json` names all of them.

For step 11, `detail` names the profile rule. Where the rule checks the key or R, it names that too: `profile 1,
key`, `profile 1, R`, `profile 2, key`, `profile 2, R`, `profile 3`, `profile 4`. Full agreement needs that label.
Neither the case of ASCII letters nor space or tab around the comma counts as a deviation. Any other difference
does, including space at either end and any character outside ASCII.

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
  - non-canonical point encodings and S not below L;
  - entries with two faults. The earlier step decides; within step 11 the earlier rule decides, and within rules 1
    and 2 the key comes before R. An implementation that checks in another order answers these differently.
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
