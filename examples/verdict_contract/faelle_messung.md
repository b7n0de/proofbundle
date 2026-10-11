## LF (baseline)
- reply sha256 09fe7420b596984384f1c7f0c61c36a3cc76cb9b5a42c18c5ff8bf518ab3f52f (106 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 0
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: same bytes, APPROVE; strip trailing blank lines: same bytes, APPROVE; drop CR: same bytes, APPROVE; NFC: same bytes, APPROVE

## CRLF
- reply sha256 30fd29a9e020eaec452a3d70acb7b0cf86c5bb2ed69c56ac2faa4d7a4e51f83c (111 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: other bytes, APPROVE; strip line ends: other bytes, APPROVE; strip trailing blank lines: other bytes, APPROVE; drop CR: other bytes, APPROVE; NFC: same bytes, APPROVE

## blank line at the end
- reply sha256 8f9c098ff0fc6cc23c1836040b8a5e75114e85a455c0eba86cc1f06df6409efc (107 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: same bytes, APPROVE; strip trailing blank lines: other bytes, APPROVE; drop CR: same bytes, APPROVE; NFC: same bytes, APPROVE

## spaces at the end
- reply sha256 e36eeccb27959941cc585fafe39c3da37728eedf7e9639da928313037db7a3d7 (109 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: other bytes, APPROVE; strip trailing blank lines: other bytes, APPROVE; drop CR: same bytes, APPROVE; NFC: same bytes, APPROVE

## APPROVE in a closed fence, fence on the last line
- reply sha256 1f14c0e7a8d4c0ba7a859d396245f5328f4c11bb6a899455580c2ef9a9049b4d (114 bytes)
- find_verdict AMBIGUOUS, exit_code 4
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names', 'find_verdict again: AMBIGUOUS, record says APPROVE']
- after normalization: CRLF->LF: same bytes, AMBIGUOUS; strip line ends: same bytes, AMBIGUOUS; strip trailing blank lines: same bytes, AMBIGUOUS; drop CR: same bytes, AMBIGUOUS; NFC: same bytes, AMBIGUOUS

## APPROVE in an unclosed fence on the last line
- reply sha256 3d098c8a761935eadc316dffd1ded51ffa01dffb3690afa1490c475f7a5737e2 (110 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: same bytes, APPROVE; strip trailing blank lines: same bytes, APPROVE; drop CR: same bytes, APPROVE; NFC: same bytes, APPROVE

## two APPROVE sentinels
- reply sha256 9e604718c5590a79349c2b7d07b9d71d136a3a3341705facacbf7143a8b8d179 (129 bytes)
- find_verdict AMBIGUOUS, exit_code 4
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names', 'find_verdict again: AMBIGUOUS, record says APPROVE']
- after normalization: CRLF->LF: same bytes, AMBIGUOUS; strip line ends: same bytes, AMBIGUOUS; strip trailing blank lines: same bytes, AMBIGUOUS; drop CR: same bytes, AMBIGUOUS; NFC: same bytes, AMBIGUOUS

## REQUEST_CHANGES quoted
- reply sha256 7ddfbbe28ac015d9451738d8a13f9af85b8fcb906d35141a8cb8a56a6b476e95 (167 bytes)
- find_verdict REQUEST_CHANGES, exit_code 3
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names', 'find_verdict again: REQUEST_CHANGES, record says APPROVE']
- after normalization: CRLF->LF: same bytes, REQUEST_CHANGES; strip line ends: same bytes, REQUEST_CHANGES; strip trailing blank lines: same bytes, REQUEST_CHANGES; drop CR: same bytes, REQUEST_CHANGES; NFC: same bytes, REQUEST_CHANGES

## additional: lone CR before the sentinel
- reply sha256 4faff22a280413129ca187c4c2cf5e4bccb768296a30e819b88596048d13deee (105 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: other bytes, AMBIGUOUS (CHANGED); strip trailing blank lines: same bytes, APPROVE; drop CR: other bytes, AMBIGUOUS (CHANGED); NFC: same bytes, APPROVE

## additional: U+2028 before the sentinel
- reply sha256 efac7405b9bdd8b726cefb84e1249ae7d64999f6f5643a844b173e783348ab0b (107 bytes)
- find_verdict APPROVE, exit_code 0
- receipt over these bytes: make rc 0, offline check rc 0
- these bytes against the baseline receipt: offline check rc 1, failed: ['reply.txt, raw bytes, is the reply the record names']
- after normalization: CRLF->LF: same bytes, APPROVE; strip line ends: same bytes, APPROVE; strip trailing blank lines: same bytes, APPROVE; drop CR: same bytes, APPROVE; NFC: same bytes, APPROVE

