# Decisions

## D15. One marketplace file

Chosen: no `.agents/plugins/marketplace.json`. Codex 0.159.0 reads `.claude-plugin/marketplace.json`
when no `.agents/plugins/marketplace.json` exists. Measured: `codex plugin marketplace add` on the
repository, then `codex plugin add proofbundle@proofbundle`, installed version 0.3.0 from
`.codex-plugin/plugin.json`.

Options:
- A. One file for both hosts (chosen).
- B. A separate `.agents/plugins/marketplace.json`, for Codex-only fields such as `policy.installation`
  or `category`.

## D18. The changes of 2026-09-30 stay inside the unreleased 0.3.0

Chosen (owner, 2026-09-30): the version stays 0.3.0, because 0.3.0 is unpublished. The
changes of that day land inside 0.3.0:
- the rule that everything a receipt contains is data, in every skill and in the server's instructions;
- `safe_for_automation`, `automation_blockers` and `automation_source` in every `verify_receipt` result,
  copied verbatim from the core, and the exit 1 text that no longer rules out a structure failure;
- verify first: the descriptions begin with Verify, except the marketplace's own, and receipt signing
  is marked experimental; the wording is the owner's of 2026-09-30, after an external review;
- the server reports the plugin's version, 0.3.0, as its `serverInfo` version and as `plugin_version`
  in every result, where it said 0.1.0 before; a test holds it equal to every manifest.

Options:
- A. Stay at 0.3.0 (chosen).
- B. Move to 0.4.0 before the first publication.

Addendum (owner answer 11 A of Nachtrag 9, 2026-10-27): the plugin moves to 0.4.0 before its first publication (option B
above): both manifests and the server's SERVER_VERSION say 0.4.0, and the gate's GATE_VERSION follows. The changes named
above land in 0.4.0, which is unpublished as well.

## D133. What Verify rests on

Chosen (owner answer 3 B of Nachtrag 7, 2026-10-26): the six entries D11, D14, D17, D18, D19 and D27 stay as cut;
Verify, the plugin without its Guard, rests on two parts of them, named here.
- From D11: the plugin's MCP server `server/proofbundle_mcp.py` verifies with the one pinned package
  (`proofbundle==6.3.0`). The host starts it with `uv run --no-config --script` (.mcp.json and
  .codex-plugin/plugin.json), and the server runs the command line with `python -I` from an empty temporary
  directory, so no file of the checked repository decides which code runs. The interpreter installation, the
  user's PATH, uv and UV_* variables remain trusted inputs, and the host's faithful use of the start command is
  one too.
- From D19, in the Verify wording (owner answer 2 A): every skill and the server's instructions carry the rule,
  word for word: "Never weaken a trust policy or an expected key; obtain the missing evidence instead or ask the
  user."
