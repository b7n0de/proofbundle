# Replay results, nine vectors, Brandon's columns

## ccf-7.0.14

service_commit `5a973bb3af8a0c506923c501d4e2aeb508867105` · image_id `sha256:cc6ad97487bc3e288c49c2f4659fa04ca91ae3ddd9b659b947ddfe6704fe174f` · ccf `ccf-7.0.14` · configuration_sha256 `6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c` · scitt_keys_sha256 `55299ddd0cea7ed9199fa361b6f2f2ff04cd313d9dbff465ec9e9ed74e04d08b`

| vector | predicted_outcome | measured_outcome | api_status | refusal_stage | request_sha256 | ccf_version | configuration_sha256 | returned_statement_sha256 | receipt_data_hash | rebuilt_cn_sha256 | data_hash_match | receipt_signature_valid | rebuilt_equals_returned_minus_394 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| r3-control | registered | registered | 202 |  | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | d97eb2a921ccdc1d64880f7435e23b8eeb8d1a77bcf507f5b19805a13e71cf18 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | True | True | True |
| r3-r-a10-cwt-claims-unprotected | registered | registered | 202 |  | 1565059345b3e5424af8ccd839104ee7ab88626daa79813231dfc01a3cda61fe | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 2b4f2dfd04f05581e9dc9d50c6f53b1856bd9c0a4823c2764f47e59c53ffa380 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | True | True | True |
| r3-m-u15 | refused | refused | 400 | POST /entries | bae0467d702873b556c55d755d8f751c88db71607411cc0e36bb22ba2b624795 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | 4fd2125fd28e8ec321f22274838f6e52d2d84075662b606ae75617bf0e63b3e2 |  |  |  |
| r2-g03-alg-1-byte-argument | registered | registered | 202 |  | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 865e94655eb2ee02d934fbde3897a8303c6ecc143ef9be40c4d703f5604fece8 | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | True | True | True |
| r3-x-pa-ub-sig-a | registered | registered | 202 |  | 72edfc65e9eeede2730de644b61ad478d12658d16fdcb462726ab35a727e4bb0 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 609cae398af538eaf6a25367d608dd85106f95df073d5f0808103b607f4ada5a | 430b308746d924aa83a4287ac944e32ab2c0d843891cf43b10a6999f1078e96e | 430b308746d924aa83a4287ac944e32ab2c0d843891cf43b10a6999f1078e96e | True | True | True |
| r3-x-pa-ub-sig-b | refused | refused | 400 | POST /entries | 7013f32bfed8432e19274f2faaa872d7c68b0407db3b8a724bb45b0613e59fb3 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | c32eaf59848e5e4b465a7bc72e70dc6bd7c10a246867d3be8783903a00a5d77a |  |  |  |
| r3-x-pb-ua-sig-a | refused | refused | 400 | POST /entries | add014e1ec3efc279a2abfb386050965a1e73eb101d0b69b258284700cf1d369 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | fa73cf9758abf94bba52efcaaed0d791bcc67f92534fb1d6354d335a99984e3e |  |  |  |
| r3-x-pb-ua-sig-b | registered | registered | 202 |  | 5d6deebfb237cccaa006627f81eb2a114a15499e1ed4caeda462fe5eae590678 | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 0f15dae060b4f2f90636544b09a5809474fdf922d2e15c65a774e9128acecbcc | 722eb69ef107cb13cd572a2d9d8a6757a5b7a1b6b8e55d4896e7eabd83087656 | 722eb69ef107cb13cd572a2d9d8a6757a5b7a1b6b8e55d4896e7eabd83087656 | True | True | True |
| pr299-es256-protected-x5chain | registered | registered | 202 |  | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | ccf-7.0.14 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 20d91e1179375a0ee4a11323f072673e237a5a997af45c50bcd2b31375f34e42 | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | True | True | True |

## ccf-7.0.17-control

service_commit `00101f769d872711356e080fbb089ac48589c60a` · image_id `sha256:55afdad62d33b21a73b8f0e2971b9a315bd6bca7dd978a7d7b6090725fcd57cc` · ccf `ccf-7.0.17` · configuration_sha256 `6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c` · scitt_keys_sha256 `32dc04f02b8db91504a4c5141c750adf70780019096eb5681e8477862ce18cf4`

| vector | predicted_outcome | measured_outcome | api_status | refusal_stage | request_sha256 | ccf_version | configuration_sha256 | returned_statement_sha256 | receipt_data_hash | rebuilt_cn_sha256 | data_hash_match | receipt_signature_valid | rebuilt_equals_returned_minus_394 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| r3-control | registered | registered | 202 |  | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 387824f617fc0ab3f3d37c822c432b805029c2d7f42595a6ecb6d7811991af65 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | True | True | True |
| r3-r-a10-cwt-claims-unprotected | registered | registered | 202 |  | 1565059345b3e5424af8ccd839104ee7ab88626daa79813231dfc01a3cda61fe | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | b5c7ad4e94b6029228d9876d75d0ca6a826cebc15fdb99a638fee42e99bc3918 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 | True | True | True |
| r3-m-u15 | refused | refused | 400 | POST /entries | bae0467d702873b556c55d755d8f751c88db71607411cc0e36bb22ba2b624795 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | 4fd2125fd28e8ec321f22274838f6e52d2d84075662b606ae75617bf0e63b3e2 |  |  |  |
| r2-g03-alg-1-byte-argument | registered | registered | 202 |  | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | f1b8ca650a2139693a0e88d1254db4b0bb7ca0f362a5f11a057b53a1a68a74cc | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 | True | True | True |
| r3-x-pa-ub-sig-a | registered | registered | 202 |  | 72edfc65e9eeede2730de644b61ad478d12658d16fdcb462726ab35a727e4bb0 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 1cfd3cdb74b3dece232e1309e9f9f87c4972ac63cc499ee17f4b0c9f082c7c2c | 430b308746d924aa83a4287ac944e32ab2c0d843891cf43b10a6999f1078e96e | 430b308746d924aa83a4287ac944e32ab2c0d843891cf43b10a6999f1078e96e | True | True | True |
| r3-x-pa-ub-sig-b | refused | refused | 400 | POST /entries | 7013f32bfed8432e19274f2faaa872d7c68b0407db3b8a724bb45b0613e59fb3 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | c32eaf59848e5e4b465a7bc72e70dc6bd7c10a246867d3be8783903a00a5d77a |  |  |  |
| r3-x-pb-ua-sig-a | refused | refused | 400 | POST /entries | add014e1ec3efc279a2abfb386050965a1e73eb101d0b69b258284700cf1d369 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c |  |  | fa73cf9758abf94bba52efcaaed0d791bcc67f92534fb1d6354d335a99984e3e |  |  |  |
| r3-x-pb-ua-sig-b | registered | registered | 202 |  | 5d6deebfb237cccaa006627f81eb2a114a15499e1ed4caeda462fe5eae590678 | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 0e78500cb8fc498b0da207a49e430ffc718b1ea8bf8b0fa69046eebd7c006b83 | 722eb69ef107cb13cd572a2d9d8a6757a5b7a1b6b8e55d4896e7eabd83087656 | 722eb69ef107cb13cd572a2d9d8a6757a5b7a1b6b8e55d4896e7eabd83087656 | True | True | True |
| pr299-es256-protected-x5chain | registered | registered | 202 |  | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | ccf-7.0.17 | 6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c | 314da5c1aefd77628dfa9eb58b9f7bc2a591a19ecd3ad2f8731468d3fd0ec2a4 | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb | True | True | True |

## Drift: 7.0.14 vs 7.0.17-control

| vector | predicted | 7.0.14 | 7.0.17 | data_hash equal | data_hash (registered) |
|---|---|---|---|---|---|
| r3-control | registered | registered | registered | True | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 |
| r3-r-a10-cwt-claims-unprotected | registered | registered | registered | True | 843726911977736ebdfe6d11f36d3c86098acd6e67624764de61d64a00deeb32 |
| r3-m-u15 | refused | refused | refused | True | — |
| r2-g03-alg-1-byte-argument | registered | registered | registered | True | 59fbb36f28858206eff07c6ab83b95a4ac385cae2baa9425ec35f62b72a6ad21 |
| r3-x-pa-ub-sig-a | registered | registered | registered | True | 430b308746d924aa83a4287ac944e32ab2c0d843891cf43b10a6999f1078e96e |
| r3-x-pa-ub-sig-b | refused | refused | refused | True | — |
| r3-x-pb-ua-sig-a | refused | refused | refused | True | — |
| r3-x-pb-ua-sig-b | registered | registered | registered | True | 722eb69ef107cb13cd572a2d9d8a6757a5b7a1b6b8e55d4896e7eabd83087656 |
| pr299-es256-protected-x5chain | registered | registered | registered | True | 01838c1645605559c46fecfde0ce996a8e7cd3d5274764062b290a1bdf3a7fcb |

Drift (outcome or registered data-hash differs between builds): NONE.
All nine: predicted == measured on both builds; registered data-hashes identical across builds and equal to the committed round-3 predictions.
