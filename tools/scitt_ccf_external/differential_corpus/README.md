# Differential corpus: one-variable mutations registered on a local scitt-ccf-ledger

Thirty-five statements were registered on one local scitt-ccf-ledger in virtual mode: a control and
one-variable mutations of it in six classes, with every request and receipt artifact kept. The
service accepted 29 and refused 6. Across the mutations, the receipt's data-hash changed only when
the signature bytes changed. The service re-encodes byte-string framing to the shortest form and
drops the submitted unprotected map before it hashes.

## PINS

Every `vectors/<id>/record.json` repeats these; `manifest.json` holds them once more, with the image build inputs.
- service: https://github.com/microsoft/scitt-ccf-ledger
- service commit: `00101f769d872711356e080fbb089ac48589c60a`
- image id: `sha256:1bdd60edc1b8cfc1fb02ed516b5a5ea60d75a3ca4b5d59f128e3c61e23680380`, built locally
- CCF: `ccf-7.0.17` (`/node/version`)
- mode: virtual, one node, attestation format `Insecure_Virtual` (`/node/quotes/self`)
- configuration (`/configuration`): unauthenticated registration allowed; policy `if (!phdr.cwt.iss) {return 'Issuer not found'} else return true;`
- verifier: https://github.com/b7n0de/proofbundle at `9142fa4b7e167b03ebfd231e7de6df388b421672`, tree clean, package 6.1.0
- libraries: CPython 3.11.15, cbor2 6.1.4, cryptography 50.0.1
- measured: 2026-09-26

## THE CONTROL

- An RFC 9995 hash envelope over the RFC 8785 root of `examples/example_bundle.json`
- root: `df6557c0af226ef3e18e2694c7d6b153343495bc9b6f459f6858e7276ea0fac9`
- ES256, P-256 signer with a did:x509 issuer and a two-certificate `x5chain`, made for the run; its private key was discarded
- tagged 18, definite lengths, shortest heads, embedded payload, empty unprotected map
- submitted SHA-256 and receipt data-hash, equal: `78a0fe4b22cbeea3678538aa357bd68b0212d3914f3c302b7760b4b930007ae4`
- Sig_structure SHA-256, the same for all 35 vectors: `932be1457daed06739c23f35c2dcaec2a9af31ff4c8aeac93355d685e4f87972`

## THE CLASSES

| class | what changes against the base | vectors | accepted | refused |
|---|---|---|---|---|
| a | unprotected map: labels 99 (text, other text, bstr, int), "x", -70000, kid 4, receipts 394, x5chain 33, CWT claims 15, and pairs of labels | 13 | 13 | 0 |
| b | protected bstr framing only: 4-byte and 8-byte length arguments, indefinite in one and in two chunks | 4 | 2 | 2 |
| c | payload bstr framing only: 2-, 4- and 8-byte length arguments, indefinite in one and in two chunks | 5 | 3 | 2 |
| d | signature bstr framing only: 2-, 4- and 8-byte length arguments, indefinite in one and in two chunks | 5 | 3 | 2 |
| e | unprotected ordering: the labels of a11, a12, a13 in the other order | 3 | 3 | 0 |
| f | separately generated valid signatures over the same content: two fresh ES256 signatures, and the high-S twin (r, n-s) of the control's, made without the key | 3 | 3 | 0 |
| control | the control, and its identical bytes submitted again | 2 | 2 | 0 |

The protected bstr of this control is 1034 bytes long, so its shortest length argument is two bytes
wide, and class b has no 2-byte variant.

## STORED FORM AND DERIVED VIEWS (owner answer C1 b)

Only raw bytes, and what cannot be derived from them, are stored. Everything else is recomputed by
the tool.
- `vectors/<id>/request.hex`: the submitted bytes, as hex text, 64 characters a line
- `vectors/<id>/receipt.hex`: the receipt the service served (accepted vectors)
- `vectors/<id>/statement.hex`: the statement the service returned (accepted vectors)
- `vectors/<id>/record.json`: class, base, mutation, the pins, the service's answer (HTTP status, txid, error) and the SHA-256 of every file
- `scitt-keys.hex`: the service key set; `manifest.json`: the run, the signer's public key, the target
- `summary.json`, `admissibility.json`: derived, and checked by `python3 ../differential_corpus.py derive --check` and by `tests/test_scitt_ccf_differential_corpus.py`
- `vectors/<id>/candidate_hashes.json` (accepted vectors) and `preimage_summary.json`: derived by `python3 ../preimage_candidates.py --write`, and checked by `--check` and by the same test file
- `python3 ../differential_corpus.py derive --vector <id>` prints the full chain below for one vector
- Converted from the base64 JSON records of commit `56ac85678f83cce7c742fc093b596eb1a420db03`: every
  byte string was held against its recorded SHA-256 before it was written as hex, and the derived
  records equal the old ones in 35 of 35 vectors. No vector was registered again.

## THE CHAIN, PER ACCEPTED VECTOR (`derive --vector <id>`)

- `request.bytes_b64`, `request.sha256`: the submitted bytes
- `request.decoded`: the COSE structure with the framing and byte span of every element
- `sig_structure.bytes_b64`, `sig_structure.sha256`
- `response.returned_statement_b64`: the returned statement (`/entries/{txid}/statement`), with its decoded structure
- `response.receipt_b64`, `response.receipt_leaf_data_hash`: the receipt and its leaf data-hash
- `response.txid`: the transaction id
- `response.receipt_signature_valid_with_service_keyset`: true for all 29
- `response.data_hash_candidates`: the byte strings tried and whether each equals the data-hash
- `v1_reader_on_submitted_bytes` and `response.v1_reader_on_returned_transparent_statement`: the proofbundle scitt-ccf/v1 reader on the same bytes

## ADMISSIBILITY (`admissibility.json`)

The refusals, as this service returned them. A refusal is what this service did with the bytes; it is
not judged SCITT-invalid here.

| id | HTTP | service error |
|---|---|---|
| b03-indefinite1 | 400 | `Failed to decode protected header: QCBOR_ERR_NO_STRING_ALLOCATOR` |
| b04-indefinite2 | 400 | `Failed to decode protected header: QCBOR_ERR_NO_STRING_ALLOCATOR` |
| c04-indefinite1 | 400 | `Detached or empty payloads are not supported` |
| c05-indefinite2 | 400 | `Detached or empty payloads are not supported` |
| d04-indefinite1 | 400 | `Failed to decode COSE_Sign1` |
| d05-indefinite2 | 400 | `Failed to decode COSE_Sign1` |

The error for c04 and c05 names a detached or empty payload. The payload in both is present and
32 bytes long; only its framing is indefinite.

## WHAT THE DATA-HASH COMMITS TO, AS FAR AS THESE MUTATIONS DECIDE IT

- Every accepted vector: the data-hash is SHA-256 over tag 18, a four-element array, the returned
  protected, payload and signature elements as served, and an empty unprotected map (29 of 29).
- (a) The unprotected map's labels and values: not committed. All 13 accepted vectors have the control's
  data-hash. Every returned statement carries label 394 only: the submitted unprotected content,
  including a pre-filled 394, is dropped.
- (e) The order of the unprotected map: not committed. All 3 accepted vectors have their base's data-hash.
- (b), (c), (d) Byte-string framing with a wider length argument: not committed. The 8 accepted vectors
  have the control's data-hash. The returned element is re-encoded in shortest form, and the data-hash
  equals the re-encoded form, not the submitted one.
- (b), (c), (d) Indefinite-length framing: NOT MEASURABLE. The service refused all 6, so no receipt exists.
- (f) The signature bytes, with the signed content unchanged: committed. The three vectors have three
  data-hashes, none equal to the control's, over one and the same Sig_structure. This includes the
  high-S twin, made without the key.
- The same bytes submitted twice: the same data-hash, under two transaction ids (`2.70`, `2.72`).
- NOT MEASURABLE here: anything these mutations do not change. That covers the protected header's
  content, the payload's content, the tag and the array framing. Changing any of these changes the
  signed content or leaves this corpus's six classes. `../local_ledger_result.json` measured some of
  them on the same service commit.

## THE DATA-HASH PREIMAGE, TEN CANDIDATES (owner order of 2026-09-26)

A reviewer of this corpus asked for the exact preimage of the data-hash before the mutations are
broadened. `../preimage_candidates.py` computes ten candidates per accepted vector from the stored
bytes, with no new ledger run. Where the order leaves a choice open, it computes every named variant.
Owner answer 2 of 2026-09-26 added two more: the variant 4-deep-tagged and the candidate 11.
Each candidate is compared with the data-hash in that vector's receipt. The result is in
`vectors/<id>/candidate_hashes.json` and `preimage_summary.json`.

Exactly one byte string matches all 29 accepted vectors:

- the COSE_Sign1 tag 18 (`d2`)
- a definite array of four (`84`)
- the protected, payload and signature byte strings, with their contents as submitted and preferred heads
- an empty map (`a0`) as the unprotected header

Three candidates name that byte string. Candidate 4-tagged rebuilds it from the contents. Candidate
3-tagged cuts label 394 out of the returned statement. The added variant 4-deep-tagged also
re-encodes the map inside the protected bstr. The three are the same bytes in 29 of 29 vectors,
because every protected map of this round is already core deterministic. The second round separates
4-deep-tagged from the other two: it matches 11 of 19 there, and misses exactly the 8 accepted
vectors whose protected map is not core deterministic (`../differential_corpus_round2/README.md`).
No other candidate or variant matches all 29.

| candidate | what | matches the receipt's data-hash | cbor2 encoding of the same candidate |
|---|---|---|---|
| `1` | exact request bytes | 5 of 29 | not encoded by cbor2 |
| `2` | returned statement bytes | 0 of 29 | not encoded by cbor2 |
| `3-tagged` | returned statement, label 394 removed, every other byte as served, tag 18 kept | 29 of 29 | not encoded by cbor2 |
| `3-untagged` | returned statement, label 394 removed, every other byte as served, tag 18 dropped | 0 of 29 | not encoded by cbor2 |
| `4-tagged` | deterministic [protected, {}, payload, signature], tag 18 | 29 of 29 | 29 of 29 equal |
| `4-untagged` | deterministic [protected, {}, payload, signature], no tag | 0 of 29 | 29 of 29 equal |
| `4-deep-tagged` | deterministic [protected, {}, payload, signature], tag 18, the protected map re-encoded per 4.2.1 | 29 of 29 | 29 of 29 equal |
| `5-sorted-tagged` | deterministic [protected, U, payload, signature], U sorted per 4.2.1, tag 18 | 14 of 29 | 29 of 29 equal |
| `5-sorted-untagged` | deterministic [protected, U, payload, signature], U sorted per 4.2.1, no tag | 0 of 29 | 29 of 29 equal |
| `5-submitted-order-tagged` | [protected, U, payload, signature], U in submitted order, preferred heads, tag 18 | 14 of 29 | 29 of 29 equal |
| `5-submitted-order-untagged` | [protected, U, payload, signature], U in submitted order, preferred heads, no tag | 0 of 29 | 29 of 29 equal |
| `6` | Sig_structure, RFC 9052 section 4.4 | 0 of 29 | 29 of 29 equal |
| `7-content` | protected header, content of the bstr | 0 of 29 | not encoded by cbor2 |
| `7-element` | protected header, bstr with a preferred head | 0 of 29 | not encoded by cbor2 |
| `7-element-as-submitted` | protected header, bstr exactly as submitted | 0 of 29 | not encoded by cbor2 |
| `8-content` | payload, content of the bstr | 0 of 29 | not encoded by cbor2 |
| `8-element` | payload, bstr with a preferred head | 0 of 29 | not encoded by cbor2 |
| `9-content` | signature, content of the bstr | 0 of 29 | not encoded by cbor2 |
| `9-element` | signature, bstr with a preferred head | 0 of 29 | not encoded by cbor2 |
| `10-content` | protected, payload and signature contents, concatenated | 0 of 29 | not encoded by cbor2 |
| `10-element` | protected, payload and signature as preferred-head bstrs, concatenated | 0 of 29 | not encoded by cbor2 |
| `11` | request with its unprotected map replaced by `a0`, every other byte as submitted | 21 of 29 | not encoded by cbor2 |

What the partial matches show:

- Candidate 1 matches in 5 vectors: control, control-resubmitted, f01, f02 and f03. There, the
  submitted bytes already are the matching form.
- The tagged variants of candidate 5 match in 14 vectors. These are the vectors whose unprotected
  map is empty once label 394 is removed: control, control-resubmitted, a08, b01, b02, c01 to c03,
  d01 to d03 and f01 to f03.
- Candidate 11 matches in 21 vectors. It misses b01, b02, c01 to c03 and d01 to d03, the eight
  vectors with a non-preferred head in a byte string. The service therefore re-encodes the framing
  of the elements it hashes. It does not only splice out the unprotected map.
- The untagged variants match nowhere.

Rules applied, written into every `candidate_hashes.json` and in full in `preimage_summary.json`:

- Deterministic encoding follows RFC 8949 section 4.2.1, core deterministic encoding:
  - preferred heads
  - definite lengths
  - map keys sorted bytewise by their encodings
- String contents are never changed. The protected header stays the content of its bstr as
  submitted. The one exception is the added variant 4-deep-tagged, which re-encodes the map inside it.
- In this corpus, that content is already core deterministic in 29 of 29 vectors, so re-encoding it
  would change nothing here.
- That the service keeps a protected header as sent, even with a non-preferred integer inside it,
  was measured on 2026-09-25 (ADR 0009, section 3, `../local_ledger_result.json`).
- Receipt material means the unprotected label 394, `receipts`, and nothing else. The sources are
  the COSE Receipts WG source at `df5113e94e6b6788de0bfb112db63726516b88ab` and the SCITT
  architecture WG source at `ba7d23d40557f0206735592036532414139d9a57`, both retrieved 2026-09-25.
- Tag 18 is computed both ways, tagged and untagged, for candidates 3, 4 and 5. Candidates 1 and 2
  are the stored bytes. Candidates 6 to 10 are not COSE_Sign1 messages.
- Candidate 5 uses the key order of the kept map both ways: sorted, and in the submitted order.
  Candidates 7 to 10 use both the content and a preferred-head bstr. Candidate 7 also uses the bstr
  exactly as submitted.

Oracles:

- Every candidate is computed by the tool's own CBOR reader and encoder, and SHA-256 by hashlib.
- The data-hash is read by the tool's own reader, and read again by cbor2 (foreign, pinned by the
  `[scitt]` extra). The two agree in 29 of 29 vectors.
- cbor2 encodes candidates 4, 4-deep-tagged, 5 and 6 a second time, from its own decoding of the
  request. Its encoding equals the tool's in 29 of 29 vectors for each of them.
- A third oracle, a foreign tool built by us (`../vendored_encoder_probe.py`, result in
  `../vendored_encoder_result.json`): CCF `ccf-7.0.17`'s vendored tee-attestation-verification-ffi
  1.0.8 C ABI over EverCBOR, compiled from its pinned sources, with EverCBOR from
  https://github.com/project-everest/everparse at `950bc93838ac2faae51126d8acd0637cf8c8a569` (tag
  v2026.07.02, the commit CCF's vendored Cargo.toml pins). Our `vendored_encoder_probe/src/main.rs`
  makes the calls of `set_unprotected_header` (`src/crypto/cose.cpp` lines 18 to 89) in their order:
  parse, tag 18, elements 0, 2 and 3, shallow copies, an empty map, array, tag 18, serialize. On the
  29 accepted requests, its output equals the served statement minus label 394 byte for byte in 29
  of 29, and its SHA-256 equals the receipt's data-hash in 29 of 29. It equals the request itself
  in 5 of 29. It refuses all 6 requests the service refused, at its parse step (indefinite lengths).
- cbor2's canonical mode orders map keys length-first (RFC 8949 section 4.2.3). This was measured:
  `{"x": 1, 1000: 2}` encodes as `a26178011903e802`. The sorted variant of candidate 5 still agrees
  here, because no kept map in this corpus has keys that the two orders place differently.

The service source that builds the hashed bytes, read at the pinned commits. The run used these;
file digests are in `preimage_summary.json`.

- scitt-ccf-ledger `00101f769d872711356e080fbb089ac48589c60a`, `app/src/main.cpp` lines 417 to 425:
  - `set_unprotected_header(body, ccf::cose::edit::desc::Empty{})`
  - then `set_claims_digest(ccf::ClaimsDigest::Digest(signed_statement))`
- CCF `ccf-7.0.17`, `src/crypto/cose.cpp` lines 18 to 89, the function `ccf::cose::edit::set_unprotected_header`:
  - it requires tag 18
  - it copies the protected header, payload and signature
  - it puts `make_map({})` in position 1
  - it wraps the result in tag 18 and serializes it with `nondet_serialize()`
- scitt-ccf-ledger, the same file, lines 430 to 431: `entry_table->put(signed_statement)`. The ledger
  stores the bytes it hashed.
- scitt-ccf-ledger, the same file, lines 534 to 541: the served statement is that stored entry with
  `{394: [receipt]}` set by `set_unprotected_header(*entry, receipts_desc)`. Removing label 394 from
  it gives back the hashed bytes, which is why candidates 3-tagged and 4-tagged are one construction.
- CCF `ccf-7.0.17`, `3rdparty/internal/tee-attestation-verification/cbor/src/lib.rs` lines 14 to 16:
  both serializer modes "write preferred head widths".
- CCF `ccf-7.0.17`, `include/ccf/claims_digest.h` line 12 and `src/crypto/sha256_hash.cpp` lines 17
  to 20: the digest is SHA-256 over the byte vector.

The source and the measurement name the same bytes. The ledger source was read, not run. CCF's
vendored CBOR code was run on the corpus, as the third oracle above.

NOT MEASURED here:

- a protected header that is not core deterministic, in this corpus (see the 2026-09-25 measurement above)
- a detached payload: the service refused both indefinite payloads before hashing
- any service other than this one commit

## THE ACCEPTANCE DIFFERENCE WITH THE PROOFBUNDLE V1 READER

- The service accepted 10 submitted statements that the v1 reader refuses: a09 and a10 (a label in
  both header buckets), b01, b02, c01 to c03 and d01 to d03 (non-shortest heads).
- The v1 reader confirms all 29 returned statements, because the service re-encoded or dropped what it
  refuses.
- The v1 reader also refuses all 6 statements the service refused.

## KEPT AS FIXTURES: THE TWO VECTORS WITH A LABEL IN BOTH HEADER BUCKETS

The v1 reader refuses two submitted statements for a label that stands in both header buckets. The
service accepted both. Their exact submitted and returned encodings are kept, byte for byte, as
regression fixtures:

| vector | label in both buckets | submitted encoding | returned encoding | v1 reader, submitted / returned |
|---|---|---|---|---|
| a09-x5chain-both-buckets | 33 `x5chain`, the same value in both | `vectors/a09-x5chain-both-buckets/request.hex`, 2011 bytes, sha256 `1cc09f823f7031db19ff403ef77543c13f4d6450498c7e6a575f5fead1dc697b` | `vectors/a09-x5chain-both-buckets/statement.hex`, 1692 bytes, sha256 `2856c9b32cd52ae7ae3823e9374951d6691b07dc5ef694813c2fc504be7c873f` | malformed / confirmed |
| a10-cwt-claims-unprotected | 15 CWT claims, conflicting: the unprotected issuer is `did:example:spoofed` | `vectors/a10-cwt-claims-unprotected/request.hex`, 1163 bytes, sha256 `438162d8f74c898e9833226658c15b09c65e1dfd6d6f8f5df7700ce3b255ef4c` | `vectors/a10-cwt-claims-unprotected/statement.hex`, 1692 bytes, sha256 `e24d0282ef36295053f1915980ed572e5a3d85b4295713c93f66d08c50662453` | malformed / confirmed |

- The returned encoding carries label 394 alone in its unprotected map. The submitted label is gone.
- The data-hash of both vectors is the control's.
- A rerun of `../differential_corpus.py run` would replace `vectors/` with new signatures. These
  bytes are therefore not regenerated. Further classes go into a directory of their own.
- `tests/test_scitt_ccf_differential_corpus.py` holds both files of both vectors to the digests above,
  and holds the labels to the buckets named.

## LIMITS

- One service commit, one node, virtual mode; a production service is NOT MEASURED.
- One signer and one payload; other algorithms and payload sizes are NOT MEASURED.
- Stored: 163 text files, 485691 bytes; the largest is `README.md`, 20372 bytes. Before the preimage candidates: 133 files, 312103 bytes. Before C1 b: 38 files, 627944 bytes.
- No further mutation classes in this directory (owner answer C2 c). The four classes of the owner order of 2026-09-26 are in `../differential_corpus_round2/`.
- Written by `../differential_corpus.py run`; rerunning it replaces `vectors/` with new signatures and new transaction ids.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
