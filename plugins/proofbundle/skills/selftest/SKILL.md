---
description: Check whether the proofbundle pre-push gate actually runs in this session, with one push to a throwaway local repository. Use when the user asks whether the gate or the plugin's hooks are active.
disable-model-invocation: true
allowed-tools: mcp__plugin_proofbundle_proofbundle__gate_selftest_prepare mcp__plugin_proofbundle_proofbundle__gate_selftest_check mcp__plugin_proofbundle_proofbundle__gate_status
---

Run the gate self-test with the proofbundle MCP server.

1. Call `gate_selftest_prepare`. It creates a throwaway repository and a bare remote in a temporary folder.
2. Run exactly the `command` it returned, once, with the shell tool. It pushes to that local bare repository and nowhere else. Never change the command, and never push to any other remote in this skill.
3. Call `gate_selftest_check` with the `work` and `started_at` that `gate_selftest_prepare` returned.
4. Report the `result` verbatim: `hooks take effect`, `hooks do not take effect` or `NOT MEASURABLE`, with its `reason`, the `log_path` and whether the push reached the throwaway remote.

`hooks do not take effect` means the gate logged nothing for that push: the plugin's hooks did not run, for example because they are not trusted yet under Codex. `NOT MEASURABLE` means the server cannot read the gate's log, so it cannot tell. Never report a result the tool did not return.

Never weaken the evidence declaration, a trust policy or an expected key to get past the gate; obtain the missing evidence instead or ask the user.
