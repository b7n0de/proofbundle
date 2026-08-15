# Key sources, captured 2026-08-14T08:00:55Z

Every verifier key used in this fixture was fetched from a party **other than the
log being audited**. The files below were captured with their own digests so a
later reader can tell whether a key changed at its source.

| Source file | URL | sha256 |
|---|---|---|
| `torchwood_witness_policy.txt` | `https://raw.githubusercontent.com/FiloSottile/torchwood/main/cmd/age-keyserver/witness_policy.txt` | `00a1b12493056cf85b113a65128364b2b87c729785bd781f885c9e85d41f5d2d` |
| `google_transparency-dev.txt` | `https://raw.githubusercontent.com/google/google-tlog-witness/main/witnesses/transparency-dev.txt` | `604f3f67897418521b5990efa5b690696471238f5d9b8c00d0ea10eb4b9e1cf3` |
| `witness-network_log-list.1` | `https://raw.githubusercontent.com/transparency-dev/witness-network/main/lists/testing/log-list.1` | `9eb8222030c1f192f0f05f540dd588f7bd1d0378d6ae0c5f2b138c9e98414e7b` |
| `stagemole_about.html` | `https://witness.stagemole.eu/about` | `3f7a1a02f0c5709923e3f69f3f0e7e5a83182886d9e31504bc9df94a6183f8c5` |
| `remora_index.html` | `https://remora.n621.de/` | `aabf8fb9834f28fe308077337ae9a15c699915396c0d5b88d353278d1916a0dc` |
| `navigli_index.html` | `https://navigli.sunlight.geomys.org/` | `33c2805b412327ef9c45e7884f852bb23378121d3466ef87c5788c2dee98978d` |

## Which key came from where

| Key | Source file |
|---|---|
| `markovianprotocol.com/log` (log key) | `witness-network_log-list.1` |
| `witness.stagemole.eu` | `stagemole_about.html` **and** `torchwood_witness_policy.txt` |
| `transparency.dev/DEV:witness-little-garden` | `torchwood_witness_policy.txt` |
| `staging.witness.transparency.goog/ring-any-bells` | `google_transparency-dev.txt` |
| `remora.n621.de` | `remora_index.html` |
| `witness.navigli.sunlight.geomys.org` | `torchwood_witness_policy.txt` only |

`navigli_index.html` was fetched but did not serve the key to a plain HTTP fetch,
so that witness rests on a single source. Recorded rather than glossed over.

## Self-check

Each key's 32-bit key ID was recomputed as
`SHA-256(name || 0x0A || algorithm byte || public key)[:4]` and compared with the
hex component of its own vkey string. All six matched. This catches transcription
errors; it does not by itself establish provenance, which is what the table above
is for.
