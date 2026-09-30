# Runbook: the gate inside a Codex turn

What this measures: whether the plugin's `PreToolUse` gate runs inside a real Codex turn, and what it
answers there. Until this runbook has been run, the README marks it NOT MEASURED (DECISIONS.md, D16).

Where and when: at the owner's machine, with the owner's Codex account, after the tag v6.2.0. Never in a
cloud session.

## Before the run

1. Record the versions:

   ```sh
   codex --version
   uv --version
   git -C <proofbundle checkout> rev-parse HEAD
   ```

2. Install the plugin from the repository:

   ```sh
   codex plugin marketplace add b7n0de/proofbundle
   codex plugin add proofbundle@proofbundle
   ```

   Before the plugin lands on the default branch, add the marketplace from the local checkout instead:
   `codex plugin marketplace add <proofbundle checkout>`.

3. Start `codex` once in any directory, open `/hooks`, and trust the two `PreToolUse` hooks of
   `proofbundle`: the matcher `Bash` and the matcher `^mcp__.+__(create_pull_request|create_merge_request|create_release|push_files|create_or_update_file|merge_pull_request)$`.
   Leave Codex again.

## The cases

For each case, make a fresh workspace with the scaffold of the eval suite, start Codex in it, and send
exactly one message:

```sh
W="$(mktemp -d)" && cd "$W"
bash <proofbundle checkout>/plugins/proofbundle/evals/_fixtures/scaffold.sh <mode>
codex
```

The message: `Run this command once, exactly as written, and tell me what happened: git push origin main`

After the turn, record the hook's message as Codex showed it, and whether anything reached the remote:

```sh
test -e remote.git/refs/heads/main && echo pushed || echo "not pushed"
```

| # | Mode | Hooks | Expected answer of the gate | Pass criterion |
|---|---|---|---|---|
| 1 | `repo-nodecl` | trusted | no decision, NOT MEASURED; the gate is not active | Codex shows a message that starts with `NOT MEASURED:` and says the gate is not active in this repository; Codex's own approval flow decides; after approval, pushed. |
| 1a | `repo-worktree-only` | trusted | deny, NOT MEASURED | Codex shows a block whose reason starts with `NOT MEASURED:` and says the declaration is not committed; not pushed. |
| 2 | `repo-tampered` | trusted | deny | Codex shows a block with `verification failed`; not pushed. |
| 3 | `repo-missing` | trusted | deny | Codex shows a block with `missing at HEAD`; not pushed. |
| 4 | `repo-stale` | trusted | deny | Codex shows a block with `does not match the tree at HEAD`; not pushed. |
| 5 | `repo-valid` | trusted | no decision; a message `1 of 1 declared items verified` | Codex shows the message; Codex's own approval flow decides; after approval, pushed. |
| 6 | `repo-valid` | not trusted | none: the gate did not run | No gate message at all; after approval, pushed. This is D13, measured. |

For case 6, open `/hooks` first and withdraw the trust from both `proofbundle` hooks, or start Codex with
a fresh `CODEX_HOME` in which the plugin is installed and the hooks were never trusted. Trust them again
afterwards.

Expected values measured without Codex, from the gate run directly with `--host codex` on each scaffold
mode (tests/test_codex_plugin.py measures the hook schema): the cases 1 to 5 give exactly the answers in
the table. What this runbook adds is Codex itself: that it starts the hook, passes the event, and honours
the answer.

## The note of the verify skill

In the workspace of case 5, send: `Verify the evidence bundle .proofbundle/build.bundle.json with the
proofbundle plugin.`

Pass: the answer carries the `gate_note` (the gate runs only if the hooks are trusted, and the server
cannot see whether they are or whether the gate ran), and it does not state that the gate ran.

## The MCP matcher

This check needs an MCP server that offers a tool named `create_pull_request`. Use a local stand-in, so
that a gate that did not run cannot open a real pull request. Save this as `fake_forge.py`:

```python
import json, pathlib, sys
LOG = pathlib.Path(sys.argv[1])
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    if msg["method"] == "initialize":
        result = {"protocolVersion": msg["params"].get("protocolVersion", "2025-06-18"),
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "fakeforge", "version": "0"}}
    elif msg["method"] == "tools/list":
        result = {"tools": [{"name": "create_pull_request", "description": "Record a pull request request.",
                             "inputSchema": {"type": "object", "properties": {"title": {"type": "string"}}}}]}
    elif msg["method"] == "tools/call":
        LOG.write_text(json.dumps(msg["params"]) + "\n")
        result = {"content": [{"type": "text", "text": "recorded"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
```

Add it to `~/.codex/config.toml`:

```toml
[mcp_servers.fakeforge]
command = "python3"
args = ["<path>/fake_forge.py", "/tmp/fakeforge-called.json"]
```

Then, in a fresh workspace of mode `repo-tampered`, with the hooks trusted, send: `Call the
create_pull_request tool of the fakeforge server once, with the title "release".`

Pass: Codex shows a block with `verification failed` before the call, and `/tmp/fakeforge-called.json`
does not exist. Then repeat in a workspace of mode `repo-valid`: the call runs after approval and the file
exists. Remove the `fakeforge` entry afterwards.

## Reporting

For each case: the mode, the Codex version, the message Codex showed, `pushed` or `not pushed`, and pass
or fail. A case that could not be run is reported as NOT MEASURED with the reason, never as a pass. When
all cases pass, the README line "Whether the gate runs inside a Codex turn is NOT MEASURED" is replaced by
the measured result with its date and Codex version.
