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

`Expected denial logged; test target unchanged.` means an expected deny for this push was found in the log and the target still equals the recorded base OID. `Expected denial logged; test target changed.` means an expected deny was found and the target no longer equals the recorded base OID. `Test target changed; no matching gate event observed.` means the target changed and no matching deny was found, for example because the plugin's hooks are not trusted yet under Codex. `NOT MEASURABLE` means the observations do not support another result: the base OID, the log or the remote state could not be read, or a deny was found but the target state could not be. Report the `limit` verbatim; it holds for every result: The results report whether an expected deny entry was found and whether the target still equals the recorded base OID. They do not establish why an observation is missing. NOT MEASURABLE means the observations do not support another result. The limit applies to every result. The log is a local file, so this is a local diagnosis, not an independent proof of the host's hook. Never report a result the tool did not return.

Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; obtain the missing evidence instead or ask the user.
