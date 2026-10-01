# Replay run notes (cloud session kraxo, 2026-10-01)

The nine vectors were registered on the earlier build (CCF 7.0.14) and, as the drift control, on the original
build (CCF 7.0.17). One node, virtual mode, as rounds 1 to 3. The predictions of `predictions.json` (committed at
`32162c35`, before any registration) are reproduced byte for byte: every outcome matched, and every registered
data-hash equalled the committed value and the independent oracle's rebuilt C(n). No outcome and no data-hash moved
between CCF 7.0.14 and CCF 7.0.17.

## Builds

Both built from scitt-ccf-ledger `5a973bb3af8a0c506923c501d4e2aeb508867105` (earlier) and
`00101f769d872711356e080fbb089ac48589c60a` (control), `docker/Dockerfile`, host Docker 29.3.1, BuildKit.

| | earlier (chosen) | control (original) |
|---|---|---|
| ledger commit | `5a973bb3af8a0c506923c501d4e2aeb508867105` | `00101f769d872711356e080fbb089ac48589c60a` |
| CCF | 7.0.14 (`--build-arg CCF_VERSION=7.0.14`) | 7.0.17 (the commit's own pin, no build arg) |
| SOURCE_DATE_EPOCH | 1789426869 | 1790269424 |
| SCITT_VERSION_OVERRIDE | 5a973bb | 00101f7 |
| image id (this build) | `sha256:cc6ad97487bc3e288c49c2f4659fa04ca91ae3ddd9b659b947ddfe6704fe174f` | `sha256:55afdad62d33b21a73b8f0e2971b9a315bd6bca7dd978a7d7b6090725fcd57cc` |
| build-inputs ccf_reproduce_sha256 | `1022713e535bae1fe24f8c0a89acbcb538f57dc1e5dd8e08fccb90cd171057c4` | `6c568e8baa6f5426bbc5fd5ecabc76dd7399658b8b223e7e3581d881b2ab078f` |
| build-inputs ccf_rpm_sha256 | `5939a48f33de90d26e35aa2197cd50539c05b3a7dcd949a9f8aac2395d36bc10` | `789d00bed342b08e468a7397f103881df5b6a75c09f3ccc507e2b78a4735fc2e` |
| build-inputs tdnf_snapshottime | `1788790797` | `1790165199` |

The `ccf_reproduce_sha256`, `ccf_rpm_sha256` and (earlier) `tdnf_snapshottime` match `build_choice.json` exactly.
The earlier build is the primary choice and built cleanly on the first attempt; the fallback (same commit, CCF
7.0.10) was not needed.

## Build-sandbox patch (recorded, as rounds 1 to 3)

The cloud agent proxy (http://127.0.0.1:37457) intercepts HTTPS, and BuildKit `RUN` steps run in an isolated
network namespace. Two changes were needed to reach github and the Azure Linux package server from inside the
build, both recorded here and nowhere in the final image:

1. `docker build --network=host` with the proxy passed as build args (`HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY`), so the
   `RUN` steps can reach the localhost proxy.
2. A base-stage patch to `docker/Dockerfile`: copy the proxy CA bundle to `/etc/ssl/scitt-proxy-ca.crt` and set
   `CURL_CA_BUNDLE`/`GIT_SSL_CAINFO` to it, so `curl`/`git` trust the intercepting proxy. It applies to the build
   stages (all `FROM base`) only; the final image is `FROM scratch`. `.dockerignore` gets one `!scitt-proxy-ca.crt`
   line so the CA is in the build context.

- proxy CA file: `scitt-proxy-ca.crt`, 234366 bytes, sha256 `ee2787e5fcd4384f2fa6f9f7e0a2f2eda06772d28a7405049b472b3f9a835212`
- Dockerfile patch (at 5a973bb3), `git diff docker/Dockerfile` sha256 `a1536ed43fdd62e3db75092ed0e56caf7dc6b47e8b53723b928f5ea0d80ee4dc`
- the same base-stage patch was re-applied verbatim on `00101f76` for the control build.

Because the patch adds a file to the build stages, the final image carries `/etc/ssl/scitt-proxy-ca.crt`, so the
image digests above differ from the unpatched reference image (`build_choice.json` `original.image_id`
`sha256:b6f6aaf0...`). The downloaded content — reproduce.json, the RPM, the tdnf snapshot — is unchanged, which the
build-inputs hashes above confirm.

## Node, configuration

One node, virtual mode, attestation Insecure_Virtual, opened with the repository's own
`scitt governance local_development`; then `scitt governance propose_configuration` applied
`build_choice.json` `configuration.target` (unauthenticated registration allowed, the "any statement with a CWT
issuer" policy). On BOTH builds the configuration read back from `/configuration` had sha256
`6593529c599a0b94b93bc7afe5cf4846068c7fda704b10441ee763f16005529c`, equal to round 3's. Node CCF versions from
`/node/version`: `ccf-7.0.14` and `ccf-7.0.17`.

## Result

All nine vectors on both builds: predicted == measured (6 registered, 3 refused). Every registered data-hash
equals the committed prediction and the oracle's rebuilt C(n); every receipt signature verified; every rebuilt C(n)
equals the returned statement minus label 394. Across the two builds no outcome and no registered data-hash
differs. The returned-statement digest differs between builds only through the receipt's per-run transaction id and
timestamp; the data-hash, the drift-relevant invariant, is identical. See `results_table.md`.

## Limits

One node, virtual mode, no TEE, two builds in one session. A difference between the runs would point to CCF between
7.0.14 and 7.0.17, because the ledger's registration code is the same; there was none. The run measures the
service's answer (accepted or refused); it makes no claim about SCITT conformance. The host runs the registrations;
"whether the build runs and each registration" is this session's measurement, the predictions were predictions.

---

Prepared with AI agent involvement, reviewed and submitted under human oversight.
