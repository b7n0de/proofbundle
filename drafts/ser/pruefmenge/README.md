# A fresh challenge set for a second implementation of SER -02

The 66 vectors of Appendix A of draft-gruszka-signed-evaluation-receipts-02 are public together with their expected
results. A submission that reports 66 of 66 therefore shows only that it can read Appendix A. Each submission
answers a challenge set of its own instead, generated for it and never published. The comparison reads the
submission's answers and runs no foreign code.

## The two calls

Python 3, standard library only.

```
./pruefmenge_erzeugen <kennung> [--anzahl N]
./pruefmenge_vergleichen <kennung> <answers.jsonl> --summe <sha256> [--json auswertung.json]
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

The call prints the name and the SHA-256 of `challenge.jsonl`; both go out with the file, and the submission's
reply names them again. Before writing, the generator checks the envelope of its set: unique string ids, canonical
base64 with padding, and keys that decode to exactly 32 bytes.

A second call with the same name reads `seed.hex` again and writes the same bytes. A call with another count refuses
to overwrite `challenge.jsonl`. The name `anhang-a` is reserved.

`pruefmenge_vergleichen` takes the name and the SHA-256 from the submission's reply and checks both against the
set in the folder. If either does not match, the answers are not compared (exit 1); without `--summe` the call does
not run (exit 2).

### The result contract (prompt item 7)

Each line of `answers.jsonl` is one JSON object with exactly the fields `id`, `verdict`, `step` and `detail`:

| verdict | step | detail |
| --- | --- | --- |
| `PASS` | null | null |
| `FAIL` | integer 1 to 10 | null |
| `FAIL` | 11 | one of `profile 1, key`, `profile 1, R`, `profile 2, key`, `profile 2, R`, `profile 3`, `profile 4` |
| `ERROR` | null | `resource-limit` or `execution-error` |

Each expected entry falls into exactly one class, and the classes add up to the number of entries:

| Class | Meaning |
| --- | --- |
| voll gleich | all four fields are the same strings as expected |
| Formabweichung | outside the contract, but equal to the expected answer after the normalisation table below; never agreement, never a deviation in content |
| inhaltliche Abweichung | in the contract, and different from the expected answer |
| ERROR resource-limit, ERROR execution-error | not answered; never agreement, never a deviation |
| Formfehler | outside the contract and not a form deviation: no SER result |
| fehlt | no line for the entry |

The normalisation table (`NORMALISIERUNG` in `pruefmenge.py`) applies only to an object with exactly the four fields.
It changes nothing else:

| Field | Rule |
| --- | --- |
| verdict | space and tab at either end removed; ASCII letters upper case |
| detail | space and tab at either end removed; a run of space and tab becomes one space; ASCII letters lower case, only an r at the end becomes R; a missing comma, or space around the comma before key or R, becomes a comma and one space |
| verdict, detail | a value with a character outside ASCII is not normalised |
| id, step | never normalised |

The report also gives the agreement in the verdict alone, and in the profile rule alone (without the key or R) for
step 11.

### The envelope of the answer

These are execution errors of the submission, not SER results:

- missing, duplicate, foreign or reordered ids;
- another line count than the set;
- a byte order mark;
- an empty line;
- a broken line: not UTF-8, not one JSON text, a member named twice, nesting deeper than the parser can follow, or no
  string id.

Such a run is evaluated only as far as its lines go, and no missing answer is filled in.

The comparison reads at most 10 MB (10 000 000 bytes) of the answer file. A larger file gives exit 2, is not read
further, and produces no report. Ids and answers from the answer file appear in the report JSON-escaped to ASCII.
The text report names at most 20 ids or lines per list, and `--json` names all of them.

`pruefmenge_vergleichen anhang-a results.jsonl` compares a `results.jsonl` for Appendix A in the same form.

| Exit | Meaning |
| --- | --- |
| 0 | The envelope is complete, whatever the classes of the entries. |
| 1 | The envelope has an execution error, or name or sum do not match the set. |
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

Their labels become answers through an explicit table (`ABBILDUNG` in `pruefmenge.py`); a label that is not in
the table is an error, and no expected answer is ERROR. An entry on which they differ in verdict, first failing
step, or profile rule is left out of the set and recorded in
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
- the result contract, the normalisation, the mapping and both envelopes hold (Nachtrag 2);
- the same seed gives the same bytes, and another seed gives different bytes.

Keys and seeds in the tests are test material only.
