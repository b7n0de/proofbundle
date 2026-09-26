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

## THE ACCEPTANCE DIFFERENCE WITH THE PROOFBUNDLE V1 READER

- The service accepted 10 submitted statements that the v1 reader refuses: a09 and a10 (a label in
  both header buckets), b01, b02, c01 to c03 and d01 to d03 (non-shortest heads).
- The v1 reader confirms all 29 returned statements, because the service re-encoded or dropped what it
  refuses.
- The v1 reader also refuses all 6 statements the service refused.

## LIMITS

- One service commit, one node, virtual mode; a production service is NOT MEASURED.
- One signer and one payload; other algorithms and payload sizes are NOT MEASURED.
- Stored: 133 text files, 312103 bytes; the largest is `summary.json`, 18125 bytes. Before C1 b: 38 files, 627944 bytes.
- No further mutation classes for now (owner answer C2 c).
- Written by `../differential_corpus.py run`; rerunning it replaces `vectors/` with new signatures and new transaction ids.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
