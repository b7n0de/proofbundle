# Two transparency services, one statement reference: a lab measurement

Measured on 12 November 2026 on one Linux machine, against draft-gruszka-scitt-statement-identification-03. The
question: when the same signed statement is registered with two independently developed open-source Transparency
Services, does the reference of Section 6 of -03 (ToBeSigned scheme, alg -16, external_aad empty), computed from what
each service returns, equal the reference computed from the submitted bytes? And does either service find an entry by
such a reference?

## The two services

| | microsoft/scitt-ccf-ledger | vcon-dev/scittles |
|---|---|---|
| Commit | 6531df8a31ca563951a3a21813b9dc1abf9dd8bb (main, 11 November 2026) | 6653ab2da4ef5cebf5a02688be124c5759087b30 (main, 18 April 2026) |
| Version | 0.21.0-15-g6531df8, CCF 7.0.24 | 0.1.0 (pyproject.toml) |
| Licence | `MIT` | `MIT` |
| Code | C++ application on CCF | Python, FastAPI, pycose, SQLite |
| Image | built from docker/Dockerfile unchanged, sha256:e668939d772d2b480aca5322bf257e1257535c8948ff12f099dea8865e29e0c6 | built from its Dockerfile unchanged, sha256:ef1dbb2eb648d3f48af0822eea2ca6075a281934c620caab91deccf3714f6bf3 |
| Configuration | one node, docker/dev-config.tmpl.json; governance with pyscitt `local_development` (unauthenticated, policy: a CWT issuer is present) | defaults, a fresh database per container |
| Registration | POST /entries?waitForCommit=true | POST /entries |
| Statement returned by | GET /entries/{txid}/statement | GET /signed-statements/{entry id} |

The two code bases are by different organisations and in different languages. For this lab the registration,
verification and retrieval paths of both were read; the rest of either code base was not.

**Deviation for scittles.** Built on 12 November from its own Dockerfile, scittles refuses every statement with "Bytes
cannot be decoded as COSE message". Its dependency `cbor2>=5.6.0` is open above and resolves to cbor2 6.2.1, which
returns the content of a CBOR tag as a tuple; pycose 1.1.0 accepts only a list (`measurement/scittles_cause.txt`). The
comparison therefore uses a variant with cbor2 5.9.0 and no other change (`tools/variant_cbor2_5/Dockerfile`, image
sha256:77e9212bec1a687c75e993a640e183dc9d14f8cae442dfe23442efa2e0e22941; the `pip freeze` of both images differs in
that line only). The run of scittles as built is kept as well.

## The statements

Test statements only, with test keys from fixed seeds. No account, no hosted service.

- **R**: the candidates of the 14 cases of interop/scitt-statement-identification-03 at commit
  30c93494ac70ed01f802ee5bd276528b9f34bcbe, byte for byte. C1, C10, C13 and C14 have the same candidate bytes, so 11
  byte strings were submitted.
- **D1 to D6**: derived from base statements 01, 02 and 03 of that folder so that the ledger can accept them: same
  payload and content type, CWT Claims with the sub of the base statement and a did:x509 issuer of a test CA, an x5chain
  [leaf, root] in the protected header, no kid, an empty unprotected header, tag 18, signed again with the leaf key.

| | from | alg | note |
|---|---|---|---|
| D1 | 01 | -7 (ES256) | |
| D2 | 02 | -8 (EdDSA) | |
| D3 | 03 | -8 (EdDSA) | |
| D4 | 01 | -8 (EdDSA) | same payload as D1 |
| D5 | 01 | -19 (Ed25519) | the algorithm of the cases |
| D6 | 01 | -7 (ES256) | the bytes of D1 with one entry in the unprotected header, not signed again (as C5) |

The test CA, the leaf certificates, every statement and its reference from the submitted bytes are in `statements/`.
The ES256 signature of D1 is not deterministic; a new run of the generator writes other D1 bytes.

## Result

The table is built from the run records by `tools/summarize.py` (`measurement/result_table.md`).

| statement | ledger | scittles as built | scittles with cbor2 5.9.0, fresh database each | scittles with cbor2 5.9.0, one database |
|---|---|---|---|---|
| D1 | registered; unprotected header changed; reference equal | refused | registered; bytes unchanged; reference equal | registered; bytes unchanged; reference equal |
| D2 | registered; unprotected header changed; reference equal | refused | registered; bytes unchanged; reference equal | registered; bytes unchanged; reference equal |
| D3 | registered; unprotected header changed; reference equal | refused | registered; bytes unchanged; reference equal | registered; bytes unchanged; reference equal |
| D4 | registered; unprotected header changed; reference equal | refused | registered; bytes unchanged; reference equal | refused: already registered |
| D5 | refused: COSE algorithm -19 is not supported | refused | refused: unknown COSE algorithm -19 | refused: unknown COSE algorithm -19 |
| D6 | registered; unprotected header changed; reference equal | refused | registered; bytes unchanged; reference equal | refused: already registered |
| C1 to C7, C10 to C14 | refused: CWT_Claims issuer is unsupported | refused | refused: unknown COSE algorithm -19 | refused: unknown COSE algorithm -19 |
| C8 | refused: detached or empty payloads are not supported | refused | refused: unknown COSE algorithm -19 | refused: unknown COSE algorithm -19 |
| C9 | refused: COSE_Sign1 is not tagged | refused: not tagged | refused: not tagged | refused: not tagged |

**Where both services registered the same statement** (D1, D2, D3, and D4 and D6 with a fresh scittles database), the
reference from the statement the ledger returned, the reference from the statement scittles returned and the reference
from the submitted bytes are equal. For D1 all three are
68be9ac5b1207175ea0d41400d855e56d218b6a013f95858084030ca7a4d57bb.

**Deviations, with cause.**

- The ledger replaces the unprotected header with an array of its receipts under label 394, so the bytes it returns
  differ from the submitted bytes; the protected header, payload and signature are unchanged. For D6 the submitted
  unprotected entry is not kept.
- scittles returns the submitted bytes unchanged.
- The entry identifiers differ: the ledger uses a transaction identifier (D1: 2.13), scittles the SHA-256 of the payload
  (D1: 2f869df86acd0dd1c8a2960aacee8ecacb9edaf3097ee5078ccef37c067ad18c). Two statements over one payload therefore have
  one scittles identifier: in one database D4 and D6 are refused as already registered after D1.
- Receipts differ in form: the ledger's is ES384 with verifiable data structure 2 (CCF), the scittles receipt ES256 with
  structure 1 (RFC 9162). Both were fetched and parsed, not verified.
- Neither service accepts the case candidates. The ledger requires a did:x509 issuer in CWT Claims, a tag and an
  attached payload, and accepts -7 and -8 but not -19. scittles with pycose 1.1.0 does not know -19 and requires a tag.

**Lookup by the reference.** For every statement a service registered, the lab asked each retrieval path of that
service with the -03 reference and, for comparison, with the SHA-256 of the submitted bytes. No path found an entry.

| service | path | looked up by | found | not found | status |
|---|---|---|---|---|---|
| ledger | /entries/{x}, /entries/{x}/statement, /operations/{x} | -03 reference | 0 | 15 | 400 Invalid transaction ID |
| ledger | same | SHA-256 of the submitted bytes | 0 | 15 | 400 |
| scittles, fresh database each | /entries/{x}, /signed-statements/{x} | -03 reference | 0 | 10 | 404 |
| scittles, fresh database each | same | SHA-256 of the submitted bytes | 0 | 10 | 404 |
| scittles, one database | same | -03 reference | 0 | 6 | 404 |
| scittles, one database | same | SHA-256 of the submitted bytes | 0 | 6 | 404 |

The ledger retrieves entries by transaction identifier only; its index endpoint GET /entries/txIds was removed in
commit dcd78d9 ("Remove the indexing strategies and GET /entries/txIds (#476)"). scittles retrieves by its own entry
identifier.

## What this shows and what it does not

Shown: two independently developed services, given the same statement, keep its protected header, payload and
signature, so that the reference of -03 computed from what either returns is the same.

Not shown:

- an implementation of the reference rule by anyone other than the author (the reference was computed with
  check_cases.py of the -03 folder);
- verification of either service's receipts;
- registration of the case candidates themselves;
- lookup of an entry by the reference in either service;
- interoperability of services in deployment.

## Proposal for Section 11 of -04

> On 12 November 2026 a lab measurement registered the same test statements with two independently developed
> open-source services on one machine: microsoft/scitt-ccf-ledger at commit 6531df8a (CCF 7.0.24) and vcon-dev/scittles
> at commit 6653ab2d. The statements were derived from statements 01 to 03 of Appendix A, signed again with test keys
> and given what the ledger requires (a did:x509 issuer in CWT Claims and an x5chain). Both services refused the case
> candidates themselves, for reasons of profile: issuer form, algorithm -19, a missing tag, a detached payload. For each
> statement both services registered, the ToBeSigned reference of Section 6, computed from the statement each service
> returned, equalled the reference computed from the submitted bytes. The ledger replaced the unprotected header with
> its receipts and kept the protected header, payload and signature; scittles returned the submitted bytes. Neither
> service found an entry by the reference: the ledger retrieves entries by transaction identifier and scittles by the
> SHA-256 of the payload. scittles as built from its repository that day refused every statement because an unpinned
> dependency had moved; the measurement used cbor2 5.9.0 in place of 6.2.1 and no other change. This shows that two
> services keep the signing input so that the same reference arises. It does not show an implementation of the
> reference rule by anyone other than the author, verification of either service's receipts, or lookup by the
> reference. The record is in the proofbundle repository under interop/scitt-two-services-lab.

## How it was run

The scripts are those of the lab, with the lab's absolute paths; read them as the record of the run.

1. `tools/build.sh` builds both images with a rootless Docker daemon; `tools/build_variant.sh` builds the scittles
   variant.
2. `tools/make_statements.py <folder -03> <out>` writes the statements (`statements/`).
3. `tools/run_ledger.sh` starts one ledger node, runs the governance in a container and runs `tools/lab_client.py`
   against it. `tools/run_scittles.sh [name] [image]` runs one fresh scittles container per statement and one container
   for all statements.
4. `tools/summarize.py` builds the table.

`tools/run_all.sh` runs the four steps in order, as it was run for this record on 12 November 2026.

The full output of each run is in `measurement/`: the client output (`output.txt`), the run record (`result.json`), the
bodies the services returned, the governance log, the build log and the `pip freeze` of both scittles images. The
ledger's node log, its workspace, which holds the generated member key of the test node, and the container logs of
scittles are not included.

## Files and licence

Check the files with `sha256sum -c MANIFEST.sha256`. All keys are test keys. The folder is under the licence in
LICENSE.

Assisted by little helpers.
