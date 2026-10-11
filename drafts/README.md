# Sources of the three Internet-Drafts, revision -01

| Folder | Draft |
|---|---|
| `ser/` | draft-gruszka-signed-evaluation-receipts-01 |
| `map/` | draft-gruszka-evaluation-receipt-mappings-01 |
| `id/` | draft-gruszka-scitt-statement-identification-01 |

Each folder holds:

- `draft/draft_body.md` and `draft/build_draft.py`: the kramdown-rfc source; `build_draft.py` fills the tables
  and appendices from the vectors or cases of `examples/`, so the bytes in the draft are the bytes of the run.
- `examples/`: the generator of the vectors or cases, the file it writes, and (ser, map) the draft's own checker.
- `independent/` (ser, map) or `recheck/` (id): a checker written from the text of the draft alone. It reads the
  built plain text in `draft/` and recomputes every vector from it.

The submitted -00 are not here; they are in the IETF archive and stay unchanged.

## Build

```
tools/build.sh <ser|map|id> <document date YYYY-MM-DD> <output folder>
```

Needs Python 3 with cbor2 and cryptography, kramdown-rfc and xml2rfc; idnits 3 runs if `IDNITS` names it.
Each step runs twice and the two outputs are compared byte for byte. The document date is set only by the build
on the day of submission. The checker of `map` also reads the plain text of `ser`, so `ser` is built first.

Then the checkers from the text:

```
(cd ser/independent && python3 verify_from_text.py)
(cd map/independent && python3 check_from_text.py)
(cd id/recheck && python3 recheck_from_text.py ../draft/draft-gruszka-scitt-statement-identification-01.txt)
```

Test keys and test certificates in these folders are test material only; they must not be used for anything else.
