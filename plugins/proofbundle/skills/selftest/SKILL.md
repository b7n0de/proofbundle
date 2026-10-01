---
description: Check whether the proofbundle pre-push gate actually runs in this session, with one push to a throwaway local repository. Use when the user asks whether the gate or the plugin's hooks are active.
disable-model-invocation: true
allowed-tools: mcp__plugin_proofbundle_proofbundle__gate_selftest_prepare mcp__plugin_proofbundle_proofbundle__gate_selftest_check mcp__plugin_proofbundle_proofbundle__gate_status
---

Run the gate self-test with the proofbundle MCP server.

1. Call `gate_selftest_prepare`. It creates a throwaway repository and a bare remote in a temporary folder. The repository declares evidence with a stale subject, so the gate is expected to deny the push.
2. Run exactly the `command` it returned, once, with the shell tool. It pushes to that local bare repository and nowhere else. The gate is expected to deny it. Never change the command, never change the throwaway repository or its declaration, and never push to any other remote in this skill.
3. Call `gate_selftest_check` with the `work` and `started_at` that `gate_selftest_prepare` returned.
4. Report the `result` verbatim, with its `reason`, the `log_path`, `target_changed`, and the `limit`. The results are: `Expected denial logged; test target unchanged.`, `Expected denial logged; test target changed.`, `Test target changed; no matching gate event observed.`, or `NOT MEASURABLE`.

`Expected denial logged; test target unchanged.` is the healthy case: the gate denied the push and the host kept it from the throwaway remote. `Expected denial logged; test target changed.` means the gate denied it but the host let it through. `Test target changed; no matching gate event observed.` means the gate did not run: the push reached the remote and no deny was logged, for example because the plugin's hooks are not trusted yet under Codex. `NOT MEASURABLE` means the server cannot read the log or the remote state, so it cannot tell. The `limit` sentence holds always: the log is a local file, so this is a local diagnosis, not an independent proof of the host's hook. Never report a result the tool did not return.

Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; obtain the missing evidence instead or ask the user.
