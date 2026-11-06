# proofbundle plugin 0.4.0

This is the first plugin-specific tag and GitHub release of proofbundle for Claude Code and Codex. It is separate from the Python package and its existing v0.4.0 tag.

The public marketplace of this repository lists one plugin, proofbundle, the verifier. It registers no hook. The Guard is the separate plugin proofbundle-guard, the owner's house profile. No public catalog lists it; the owner's machines add its own marketplace from a checkout of this repository at plugins/proofbundle-guard and install it beside the verifier. Installing proofbundle does not install or enable proofbundle-guard. The source of both plugins is public, and the release archive holds both.

## Earlier 0.4.0 installations

Version 0.4.0 was already available from the public marketplace on main before this release, including an earlier form in which the plugin proofbundle carried the Guard's hooks. If you installed before this release, follow the tested Claude Code reinstall procedure and supported-host notes in the [plugin README](https://github.com/b7n0de/proofbundle/blob/proofbundle--v0.4.0/plugins/proofbundle/README.md#release-040-verification-and-migration).

The version remains 0.4.0. A version display or routine marketplace refresh alone does not establish that the installed files changed. In the measured Claude Code reinstall, source identity, retained data and the absence of the old Guard hooks were checked. Users of other installations should check their own installed files and hook listing rather than infer a change from the version display. Publishing this release does not revoke earlier installed copies. The number of outside installations is not known.

Codex has not reached M1 for this release. Its unmeasured runtime and lifecycle cases are not covered by the measured Claude Code procedure, and the migration under Codex is NOT MEASURED.

## Acceptance and limits

Claude Code has not reached M1 for this release, and the release is published without it. M1 is the acceptance defined in the [test plan](https://github.com/b7n0de/proofbundle/blob/proofbundle--v0.4.0/plugins/proofbundle/m0/TEST_PLAN.md); it includes real-host operation and lifecycle checks, not just a passing test harness. The acceptance ran at commit 6d29ead3 on 2026-11-04, and the [implementation-gap record](https://github.com/b7n0de/proofbundle/blob/proofbundle--v0.4.0/plugins/proofbundle/m0/IMPLEMENTATION_GAP.md) carries it row by row. In the record's own words, "At this measurement V-CC-7 (TV-8) is FAILED, G-CC-13 (the pilot of TG-11) is NOT MEASURED, the record of used releases on the operator's machine (G-CC-16) is not measurable with V6 at 6d29ead3, TG-6 was not run in a host (G-CC-7), and the gate directory of TL-3 and TL-4 and a stale hook entry of TL-4 were not checked (L-2, L-3). G-CC-3 (TG-1) has 14 different answers against the comparison head, all additional D129 blocks with none lost. The owner accepted these differences as an intended policy change on 2026-11-05; the unchanged TG-1 requirement of zero different answers is still not met. The delivery-profile TG-9 run showed a push proceeding without Guard protection, but did not emit the literal INACTIVE status required by TEST_PLAN.md. At least acceptance points 1, 2, 4 and 8 remain unmet; Claude Code has not reached M1 at this measurement." M1 is the target of 0.4.1.

At candidate commit 43544e21, the archived-file inventory differs from 6d29ead3 only in `plugins/proofbundle/m0/IMPLEMENTATION_GAP.md`; the plugin code and the marketplace files are unchanged. The final release commit receives its own archive and signature checks. The record's V-CC-2 entry retains the earlier real-host failure and the interactive run at 6d29ead3 in which `/mcp` listed the server with seven tools; the cause of the earlier failure is not known. These release notes are not themselves evidence of a host measurement.

Verification reports the pinned core verifier's result. A valid signature proves authorship under a trusted key and integrity of the signed bytes; it does not establish that recorded claims are true. An absent, disabled or untrusted Guard provides no protection.

The verifier pin is proofbundle==6.4.0 in the verifier and in the Guard. Initial startup can require the runtime and package download described in the README.

A Guard installed from its house marketplace is read from that checkout in place. It follows the checkout, not a version number, so a house machine compares its checkout with this release's commit when that correspondence matters.

## House Guard PR-count behaviour

In Claude Code, the house Guard counts pull requests opened through recognised Bash `gh` commands per session (D110). With a valid count below eight, house rule H3 adds no ask of its own; at eight or more it does. If a session ID and plugin data directory exist but `open-prs.json` is absent, the current gate treats the count as zero and also drops that H3 ask. If the session ID or plugin data directory is unavailable, or the counter file is present but unreadable or invalid, H3 retains its ask. Losing or removing a counter file can therefore reset this advisory count; it is not a guarantee that a session has fewer than eight open pull requests. Other gate rules can still ask or deny. The counter does not cover every GitHub or MCP operation, and it is not a live count across sessions.

## The Guard's decision receipts

Two corrections of the Guard's decision receipts are in this release, decision D135 of the plugin.

- Trace context. A Level 1 receipt records the Guard's decision on a tool call, including a Bash call or a supported MCP write. When the hook event supplies `session_id` or `tool_use_id` in the accepted form, the receipt copies them into `traceContext.traceId` or `traceContext.parentId`, respectively; missing or unusable IDs are identified in `notChecked`. The separate Level 2 git pre-push hook has no Claude session or tool-call IDs and its own receipt carries no trace. A `git push` invoked through Bash can have a Level 1 receipt with trace context even though the pre-push receipt has none.
- Merge digest. For a GitHub merge call with a specified head commit and merge method, `parametersDigest` is the SHA-256 of the RFC 8785 form of the requested `github.merge` operation, including the lowercased repository, pull request number, head commit and merge method, plus the commit title and message where supplied. The digest records what the call requested, not what the host actually merged. A GitHub MCP server that ignores `expectedHeadSha` can merge a different head. Without a specified head commit or merge method the receipt carries no such digest.

The key signer accepts receipts carrying `traceContext` only from this version on. Its program is `plugins/proofbundle/pilot/key_signer.py`, not part of the `proofbundle-guard` plugin. Updating the Guard alone does not update the copy running under the key account. An operator using that pilot must separately replace the key account's copy with the matching version, as described in `plugins/proofbundle/pilot/RUNBOOK.md` (step 2). Until then an owner's release that requires the signed ALLOW stays unused. Receipts written before this release verify as before.

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
