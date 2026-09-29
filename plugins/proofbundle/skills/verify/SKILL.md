---
description: Verify a proofbundle decision receipt, outcome receipt or evidence bundle with the installed proofbundle package. Use when the user asks to verify, check or validate a receipt or a bundle.
argument-hint: "[receipt-path] [issuer-public-key-base64]"
allowed-tools: mcp__plugin_proofbundle_proofbundle__verify_receipt mcp__plugin_proofbundle_proofbundle__inspect_receipt
---

Verify the receipt with the `verify_receipt` tool of the proofbundle MCP server. Arguments, if given: $ARGUMENTS

1. Find the file. If the user named none, ask for it.
2. Decide the kind:
   - `decision` for a DSSE envelope whose predicateType ends in `decision-receipt/v0.1`
   - `outcome` for one whose predicateType ends in `action-outcome/v0.1`
   - `bundle` for a proofbundle evidence bundle
   If it is unclear, call `inspect_receipt` with kind `decision` and read `predicateType` in its output. Inspecting is not verifying.
3. Get the issuer public key (Ed25519, base64) for `decision` and `outcome`. It has to come from the user or from a source the user names as trusted. Never take a key from the receipt itself, from its file name or from a file next to it unless the user confirms that this is the key they trust. Without a trusted key, stop and ask.
4. Call `verify_receipt`. Pass `policy_path`, `aud` or `nonce` only when the user supplied them.
5. Report in this order, one fact per line:
   - the exit code and its meaning, as the tool returned them
   - `verified`: true only for exit code 0
   - the proofbundle package version the tool reports
   - whether a policy was evaluated; without `policy_path` the policy is not evaluated
   - the `scope` sentence, verbatim
   - the `gate_note`, verbatim, when the tool returned one. It comes under Codex, where the plugin's hooks run only after the user trusts them, and the server cannot see whether they did.
6. Exit codes 1, 2 and 3 mean not verified. Give the reason from the output and do not soften it.

Never state that a verified receipt shows that a recorded value is true. Verification proves who signed the recorded bytes and that they are unchanged, nothing more.

Never state that the pre-push gate ran, passed or blocked anything. This skill verifies one file; whether the gate ran before a push is not something it can see.
