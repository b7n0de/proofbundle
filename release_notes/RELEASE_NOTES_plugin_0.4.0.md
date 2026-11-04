# proofbundle plugin 0.4.0

This is the first plugin-specific tag and GitHub release of proofbundle for Claude Code and Codex. It is separate from the Python package and its existing v0.4.0 tag.

The public marketplace of this repository lists one plugin, proofbundle, the verifier. It registers no hook. The Guard is the separate plugin proofbundle-guard, the owner's house profile. No public catalog lists it; the owner's machines add its own marketplace from a checkout of this repository at plugins/proofbundle-guard and install it beside the verifier. Installing proofbundle does not install or enable proofbundle-guard. The source of both plugins is public, and the release archive holds both.

## Earlier 0.4.0 installations

Version 0.4.0 was already available from the public marketplace on main before this release, including an earlier form in which the plugin proofbundle carried the Guard's hooks. If you installed before this release, follow the tested Claude Code reinstall procedure and supported-host notes in the [plugin README](https://github.com/b7n0de/proofbundle/blob/proofbundle--v0.4.0/plugins/proofbundle/README.md#release-040-verification-and-migration).

The version remains 0.4.0. A version display or routine marketplace refresh alone does not establish that the installed files changed. In the measured Claude Code reinstall, source identity, retained data and the absence of the old Guard hooks were checked after a new session. Users of other installations should check their own installed files and hook listing rather than infer a change from the version display. Publishing this release does not revoke earlier installed copies. The number of outside installations is not known.

Codex has not reached M1 for this release. Its unmeasured runtime and lifecycle cases are not covered by the measured Claude Code procedure, and the migration under Codex is NOT MEASURED.

## Acceptance and limits

The release required Claude Code M1 for the verifier and for the Guard's house profile before publication, including real-host and lifecycle evidence at the selected release commit. Known limits and unmeasured cases remain identified in the implementation-gap record.

Verification reports the pinned core verifier's result. A valid signature proves authorship under a trusted key and integrity of the signed bytes; it does not establish that recorded claims are true. An absent, disabled or untrusted Guard provides no protection.

The verifier pin is proofbundle==6.4.0 in the verifier and in the Guard. Initial startup can require the runtime and package download described in the README.

A Guard installed from its house marketplace is read from that checkout in place. It follows the checkout, not a version number, so a house machine compares its checkout with this release's commit when that correspondence matters.

## The Guard's decision receipts

Two corrections of the Guard's decision receipts are in this release, decision D135 of the plugin.

- Trace context. A decision receipt of Level 1 carries `traceContext` with `traceId` equal to the `session_id` and `parentId` equal to the `tool_use_id` of the hook event it decides, so a receipt can be matched to its session and to its tool call. An id the event lacks, or names in another form, is not copied, and the receipt names that in notChecked. A receipt of the pre-push hook carries no trace, since git hands that hook no session and no tool call.
- Merge digest. For a merge of a pull request, `parametersDigest` is the SHA-256 of bytes that bind the repository, the pull request number, the head commit and the merge method, instead of the SHA-256 of empty bytes. A merge call that names no head commit or no merge method is recorded without a digest.

The key signer signs a receipt that carries `traceContext` only from this version on. An operator who updates the Guard updates its key signer with it; until then an owner's release that needs the signed ALLOW stays unused. Receipts written before this release verify as before.

## What the release signature covers

The assets are:

- proofbundle-plugin-0.4.0.tar
- proofbundle-plugin-0.4.0.release.json
- SHA256SUMS
- proofbundle-plugin-0.4.0.release.json.sig

The archive holds LICENSE, the public marketplace file, the verifier's folder plugins/proofbundle and the Guard's folder plugins/proofbundle-guard with its house marketplace file. Every marketplace source in it resolves inside the archive.

The signature authenticates the exact release-statement bytes. The statement binds the archive's filename, size and SHA-256. SHA256SUMS is a deterministic two-line index reconstructed from the authenticated statement and its file hash; it is not independently signed.

The intended release public key, as standard base64 of 32 raw Ed25519 bytes, is:

    iJipntJA8N//h+ln9CgLzeC9n/M5OdCZNeBhbfagom8=

Its raw-key SHA-256 is:

    e53405faeb960e17c653fbc5eb6a862a115550efdf064f64b958a0d9bdca921b

Confirm the owner-key binding through a previously trusted copy or another authenticated channel. The key printed next to these assets is not by itself a new trust anchor. Follow the exact verification procedure in the linked README; checking SHA256SUMS alone does not verify a signature.

The release statement identifies the fixed commit and archive. The default installation commands continue to follow main, which can change. The signature does not establish which source revision or cached files a host loaded, even if they also report 0.4.0. Compare installed source identity and content with the archive when that correspondence matters.

The statement does not authenticate separately downloaded verifier distributions, host software, local configuration or GitHub's automatically generated source archives. The annotated plugin tag itself is unsigned; the detached signature is over the release statement.

If you try the verifier plugin with Claude Code, I'd be glad to hear what works and what doesn't.

[proofbundle.dev](https://proofbundle.dev)

Assisted by little helpers.
