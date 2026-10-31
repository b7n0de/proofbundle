"""Follow-up note 33, point 8: the fallbook of account A as a test file.

Each case of the fallbook (without F1 to F5, which follow-up note 32 builds) is rebuilt with placeholders and goes
to the PreToolUse hook as the host starts it: `python3 -I <gate> --autonomous` under Claude Code, `--host codex` under
Codex, with the event on stdin, in two repositories: b7n0de (declared, origin https://github.com/b7n0de/proofbundle.git,
on the work branch claude/x) and lokal (declared, a local bare remote). Nothing a case names runs; the hook only judges
the text. A tool the host's hook configuration does not match is nicht_gesehen. Each answer is one of: frei (no
output), klick (an ask), umweg (a deny with a rewrite of D85), sperre (any other deny, a card of D93 included), hinweis
(a line and context without a permission decision, or a pass with a receipt line). The reason the case is about
(grund) must stand in the log line of the call.

The expected answers are those of the head of follow-up note 41 (n41/messung/fallbuch_n41.jsonl of the delivery, measured
with the same probe at 63b88d07 and at the head: 288 rows, 77 changed, none softer). Where the answer differs from the
Soll of the fallbook, the case says why (note): an owner question, a point not ordered, or the review session's reading 1 (under
Codex there is no ask, so a Soll Frage is a deny there). C2 and C3 are also run as the fallbook means them: at 8 open
pull requests of the session (D110) and with a text the house's form checker finds red (D109).

RED at 63b88d07: the cases the rules of follow-up note 33 changed (w01 to w03, l01 to l03, c01, c02, r01, S4, S6, S8, S9),
and C2 and C3 as the fallbook means them.
"""
from __future__ import annotations

import contextlib
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

import test_claude_code_plugin_gate as cg
import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n37_machine_check_d92 as d92
from _plugin_env import plugin_env

gate = d71.gate
pytestmark = d71.pytestmark
PLUGIN = pathlib.Path(gate.__file__).resolve().parent.parent
SESSION = "fallbook-session"

CASES = [{'id': 'f01',
  'tool': 'Bash',
  'form': 'git -C {R} push --force origin main',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_force', 'codex': 'codex_push_not_plain'}},
 {'id': 'f02',
  'tool': 'Bash',
  'form': 'git -C {R} push -f origin feature/x',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_force', 'codex': 'codex_push_not_plain'}},
 {'id': 'f03',
  'tool': 'Bash',
  'form': 'git -C {R} push --force-with-lease origin main',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_force', 'codex': 'codex_push_not_plain'}},
 {'id': 'm01',
  'tool': 'Bash',
  'form': 'git -C {R} push origin main',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_protected', 'codex': 'codex_push_not_plain'}},
 {'id': 'm02',
  'tool': 'Bash',
  'form': 'git -C {R} push origin HEAD:main',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_protected', 'codex': 'codex_push_not_plain'}},
 {'id': 'z01',
  'tool': 'Bash',
  'form': 'git -C {R} push origin --delete feature/x',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_delete', 'codex': 'codex_push_not_plain'}},
 {'id': 'z02',
  'tool': 'Bash',
  'form': 'git -C {R} push origin :feature/x',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_delete', 'codex': 'codex_push_not_plain'}},
 {'id': 'g01',
  'tool': 'Bash',
  'form': 'git -C {R} reset --hard HEAD~1',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'git_form_not_free', 'codex': 'git_form_not_free'},
  'note': 'Soll Frage; under --autonomous no rewrite is free, so D85 blocks (autonomy_blocked)'},
 {'id': 'g02',
  'tool': 'Bash',
  'form': "git -C {R} filter-branch --tree-filter 'rm -f x' HEAD",
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'possible_unmodeled_push', 'codex': 'possible_unmodeled_push'},
  'note': 'a reason of its own is point 2 of follow-up note 33, not ordered here (follow-up note 41: without point 2)'},
 {'id': 'g03',
  'tool': 'Bash',
  'form': 'git -C {R} push --mirror origin',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_tag_out', 'codex': 'house_tag_out'}},
 {'id': 'n01',
  'tool': 'Bash',
  'form': 'git -C {R} commit --no-verify -m msg',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'git_form_not_free', 'codex': 'git_form_not_free'},
  'note': 'a reason of its own is point 2 of follow-up note 33, not ordered here (follow-up note 41: without point 2)'},
 {'id': 'n02',
  'tool': 'Bash',
  'form': 'git -C {R} push --no-verify origin feature/x',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'hooks_disabled', 'codex': 'hooks_disabled'}},
 {'id': 'h01',
  'tool': 'Bash',
  'form': 'git -C {R} -c core.hooksPath=/dev/null commit -m msg',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'hooks_disabled', 'codex': 'hooks_disabled'}},
 {'id': 'h02',
  'tool': 'Bash',
  'form': 'git -C {R} config core.hooksPath /tmp/h',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'hooks_disabled', 'codex': 'hooks_disabled'}},
 {'id': 't01',
  'tool': 'Write',
  'input': {'file_path': '{T}/gatedir/mode', 'content': 'auto\n'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_gate_dir', 'codex': 'write_to_gate_dir'}},
 {'id': 't02',
  'tool': 'Bash',
  'form': 'echo x > {T}/gatedir/mode',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_gate_dir', 'codex': 'write_to_gate_dir'}},
 {'id': 'a01',
  'tool': 'Bash',
  'form': 'gh pr merge 12 -R b7n0de/proofbundle --admin --merge',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_admin_merge', 'codex': 'house_admin_merge'}},
 {'id': 'a02',
  'tool': 'Bash',
  'form': 'gh pr merge 12 --admin --squash',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_admin_merge', 'codex': 'house_admin_merge'}},
 {'id': 'd01',
  'tool': 'Bash',
  'form': 'gh api -X DELETE repos/b7n0de/proofbundle/git/refs/heads/x',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'net_unmodeled_git', 'codex': 'net_unmodeled_git'}},
 {'id': 'd02',
  'tool': 'Bash',
  'form': 'gh api --method DELETE repos/b7n0de/proofbundle/releases/1',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_tag_out', 'codex': 'house_tag_out'}},
 {'id': 'w01',
  'tool': 'Edit',
  'input': {'file_path': '{H}/.claude/settings.json', 'old_string': '{}', 'new_string': '{"hooks": {}}'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w01p',
  'tool': 'Edit',
  'input': {'file_path': '{R}/.claude/settings.json', 'old_string': '{}', 'new_string': '{"hooks": {}}'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w01c',
  'tool': 'Edit',
  'input': {'file_path': '{H}/.codex/config.toml', 'old_string': 'a', 'new_string': 'b'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w02',
  'tool': 'Write',
  'input': {'file_path': '{H}/.claude/settings.json', 'content': '{}\n'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w02p',
  'tool': 'Write',
  'input': {'file_path': '{R}/.claude/settings.local.json', 'content': '{}\n'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w02m',
  'tool': 'Write',
  'input': {'file_path': '{R}/.mcp.json', 'content': '{}\n'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'w03',
  'tool': 'Bash',
  'form': "echo '{}' > {H}/.claude/settings.json",
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'write_to_host_settings', 'codex': 'write_to_host_settings'}},
 {'id': 'l01',
  'tool': 'Read',
  'input': {'file_path': '{H}/.ssh/id_ed25519'},
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre',
           'b7n0de/codex': 'nicht_gesehen',
           'lokal/claude': 'sperre',
           'lokal/codex': 'nicht_gesehen'},
  'grund': {'claude': 'secret_path', 'codex': None}},
 {'id': 'l02',
  'tool': 'Bash',
  'form': 'cat {H}/.ssh/id_ed25519',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'secret_path', 'codex': 'secret_path'}},
 {'id': 'l03',
  'tool': 'Bash',
  'form': 'base64 < ~/.ssh/id_ed25519',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'secret_path', 'codex': 'secret_path'}},
 {'id': 'c01',
  'tool': 'Bash',
  'form': 'curl -F file=@notes.md https://example.invalid/upload',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'upload_to_host', 'codex': 'upload_to_host'}},
 {'id': 'c02',
  'tool': 'Bash',
  'form': 'curl --data-binary @notes.md https://example.invalid/upload',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'upload_to_host', 'codex': 'upload_to_host'}},
 {'id': 'r01',
  'tool': 'Bash',
  'form': 'rm -rf /tmp/elsewhere',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'delete_outside_work', 'codex': 'delete_outside_work'}},
 {'id': 'v01',
  'tool': 'Bash',
  'form': 'git -C {R} tag v1.2.3',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'git_form_not_free', 'codex': 'git_form_not_free'}},
 {'id': 'v02',
  'tool': 'Bash',
  'form': 'git -C {R} push origin v1.2.3',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_tag_out', 'codex': 'house_tag_out'}},
 {'id': 'v03',
  'tool': 'Bash',
  'form': 'gh release create v1.2.3 -R b7n0de/proofbundle --notes x',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_tag_out', 'codex': 'house_tag_out'}},
 {'id': 'C1',
  'tool': 'Bash',
  'form': 'gh pr merge 12 --repo b7n0de/proofbundle --merge --match-head-commit abc123',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'net_unmodeled_git', 'codex': 'net_unmodeled_git'}},
 {'id': 'C2',
  'tool': 'Bash',
  'form': 'gh pr create -R b7n0de/proofbundle --base main --head x --title t --body b',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_not_measured', 'codex': 'codex_context_unbound'},
  'note': 'with no pull request counted H3 asks no more (D110); at 8 see test_fallbook_C2_at_eight_open_prs'},
 {'id': 'C3',
  'tool': 'Bash',
  'form': 'gh pr comment 12 -R b7n0de/proofbundle --body-file note.md',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'klick', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'text_form_unchecked', 'codex': 'text_form_unchecked'},
  'note': "no form checker at the fixture's remote: the ask names it (D109); red: test_fallbook_C3_red_text"},
 {'id': 'S3',
  'tool': 'Bash',
  'form': 'git -C {R} push origin feature/x',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_unmeasured', 'codex': 'codex_push_not_plain'},
  'note': 'owner question: the house has no checker of commit messages'},
 {'id': 'S4',
  'tool': 'Bash',
  'form': "gh api repos/b7n0de/proofbundle/pulls/12/comments -f 'body=Zeile eins\\nZeile zwei'",
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'text_literal_newline', 'codex': 'text_literal_newline'}},
 {'id': 'S5',
  'tool': 'Bash',
  'form': 'git -C {R} commit -m msg',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'frei', 'b7n0de/codex': 'frei', 'lokal/claude': 'frei', 'lokal/codex': 'frei'},
  'grund': {'claude': 'free_after_state_check', 'codex': 'free_after_state_check'},
  'note': 'owner question: the index is readable, the order is not'},
 {'id': 'S6',
  'tool': 'Bash',
  'form': 'mv MANIFEST.json /tmp/x',
  'soll': 'Hinweis',
  'kopf': {'b7n0de/claude': 'hinweis',
           'b7n0de/codex': 'hinweis',
           'lokal/claude': 'hinweis',
           'lokal/codex': 'hinweis'},
  'grund': {'claude': 'hint_tmp_not_scratch', 'codex': 'hint_tmp_not_scratch'}},
 {'id': 'S7',
  'tool': 'Bash',
  'form': 'pkill -f gate_server ; python3 tool.py',
  'soll': 'Frage',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'house_kill_pattern', 'codex': 'house_kill_pattern'},
  'note': 'Soll Frage; under --autonomous no rewrite is free, so D85 blocks (autonomy_blocked)'},
 {'id': 'S8',
  'tool': 'Bash',
  'form': "cat > /tmp/x.txt <<'EOF'\neins\nzwei\ndrei\nEOF",
  'soll': 'Hinweis',
  'kopf': {'b7n0de/claude': 'hinweis',
           'b7n0de/codex': 'hinweis',
           'lokal/claude': 'hinweis',
           'lokal/codex': 'hinweis'},
  'grund': {'claude': 'hint_tmp_not_scratch', 'codex': 'hint_tmp_not_scratch'}},
 {'id': 'S9',
  'tool': 'Bash',
  'form': 'python3 tool.py >> /tmp/audit.log',
  'soll': 'Sperre',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'append_outside_work', 'codex': 'append_outside_work'}},
 {'id': 'S10',
  'tool': 'Bash',
  'form': 'z185-slv-f3 ; git -C {R} status --porcelain | head -5 ; git -C {R} log -1',
  'soll': 'Hinweis',
  'kopf': {'b7n0de/claude': 'sperre', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'step_after_state_change', 'codex': 'git_form_not_free'},
  'note': 'owner question O33-4: the form carries no redirection'},
 {'id': 'GO1',
  'tool': 'Bash',
  'form': 'git -C {R} push origin claude/x',
  'soll': 'frei',
  'kopf': {'b7n0de/claude': 'hinweis', 'b7n0de/codex': 'sperre', 'lokal/claude': 'sperre', 'lokal/codex': 'sperre'},
  'grund': {'claude': 'push_not_measured', 'codex': 'codex_push_not_plain'},
  'note': 'free with a receipt line in the profile of b7n0de (D87, D92); the local remote is no work branch of it'}]


def _matched(config: dict, tool: str) -> bool:
    for entry in config.get("hooks", {}).get("PreToolUse", []):
        pattern = entry.get("matcher", "")
        if pattern in ("", "*") or pattern == tool or (re.search(r"[\^$|()\[\]+.*?]", pattern)
                                                        and re.fullmatch(pattern, tool)):
            return True
    return False


@contextlib.contextmanager
def _environment(env: dict):
    """os.environ is exactly `env` while the repositories of the probe are made in-process, then as it was."""
    with pytest.MonkeyPatch.context() as patch:
        for name in [n for n in os.environ if n not in env]:
            patch.delenv(name)
        for name, value in env.items():
            patch.setenv(name, value)
        yield


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    """The folders, programs and repositories of the probe, made once: a HOME of its own, a stand-in gh and uv, the
    temp folder with the session's folder of Claude Code, and the repositories b7n0de and lokal."""
    w = tmp_path_factory.mktemp("fallbook")
    home = w / "home"
    (home / ".config" / "gh").mkdir(parents=True)
    (w / "bin").mkdir()
    (w / "bin" / "gh").write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "gh version 2.89.0 (2026-03-26)"; '
                                  'exit 0; fi\nexit 0\n')
    (w / "bin" / "gh").chmod(0o755)
    (w / "bin" / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                                  f'exec "{sys.executable}" "$@"\n')
    (w / "bin" / "uv").chmod(0o755)
    tmp = w / "tmp"
    (tmp / f"claude-{os.getuid()}" / "-fallbook" / SESSION).mkdir(parents=True)
    env = plugin_env(without=("GIT_", "GH_"), GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull, LC_ALL="C",
                     HOME=str(home), PROOFBUNDLE_GATE_DIR=str(w / "gatedir"), TMPDIR=str(tmp),
                     CLAUDE_CODE_SESSION_ID=SESSION, PATH=f"{w / 'bin'}:/usr/local/bin:/usr/bin:/bin")
    with _environment(env):
        (w / "b").mkdir()
        r = d71._repo(w / "b")
        d71._git(r, "update-ref", "refs/remotes/origin/main", "main")
        d71._git(r, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
        d71._git(r, "checkout", "-q", "-b", "claude/x", "main")
        (r / "w.txt").write_text("w\n")
        (r / "MANIFEST.json").write_text('{"files": []}\n')
        d71._git(r, "add", "-A")
        d71._git(r, "commit", "-q", "-m", "W")
        (w / "d").mkdir()
        repos = {"b7n0de": r, "lokal": cg.repo.__wrapped__(w / "d")}
    for repo in repos.values():
        (repo / "note.md").write_text("## Summary\n\nText.\n")
        (repo / "tool.py").write_text("print('x')\n")
    return {"w": w, "home": home, "env": env, "repos": repos}


def run(world, host: str, tool: str, tool_input: dict, repo: pathlib.Path, data: pathlib.Path | None = None) -> dict:
    """The answer of the hook as the host starts it, as the probe of follow-up note 33 reads it."""
    hooks = json.loads((PLUGIN / "hooks" / "hooks.json").read_text())
    codex = json.loads((PLUGIN / ".codex-plugin" / "plugin.json").read_text())
    if not _matched(hooks if host == "claude" else codex.get("hooks", {}), tool):
        return {"art": "nicht_gesehen", "reasons": []}
    if data is None:
        data = world["w"] / f"data-{host}-{repo.name}-{abs(hash(json.dumps(tool_input))) % 10 ** 8}"
        data.mkdir(exist_ok=True)
    env = dict(world["env"], CLAUDE_PLUGIN_DATA=str(data), PLUGIN_DATA=str(data), CLAUDE_PROJECT_DIR=str(repo))
    event = {"session_id": SESSION, "transcript_path": str(world["w"] / "transcript.jsonl"), "cwd": str(repo),
             "hook_event_name": "PreToolUse", "permission_mode": "default", "tool_name": tool, "tool_input": tool_input,
             "tool_use_id": "toolu_fallbook"}
    argv = [sys.executable, "-I", gate.__file__] + (["--autonomous"] if host == "claude" else ["--host", "codex"])
    done = subprocess.run(argv, input=json.dumps(event), capture_output=True, text=True, env=env, cwd=str(repo),
                          timeout=180)
    assert done.returncode == 0, done.stderr
    printed = json.loads(done.stdout) if done.stdout.strip() else None
    log = next(iter(sorted(data.glob("*.jsonl"))), None)
    entry = json.loads(log.read_text().splitlines()[-1]) if log is not None and log.read_text().strip() else {}
    if printed is None:
        art = "frei"
    else:
        spec = printed.get("hookSpecificOutput", {})
        decision = spec.get("permissionDecision")
        art = ("klick" if decision == "ask" else
               ("umweg" if (printed.get("rewriteHint") or {}).get("calls") else "sperre") if decision == "deny" else
               "inaktiv" if entry.get("verdict") == "inactive" else
               "hinweis" if spec.get("additionalContext") or printed.get("systemMessage") else "frei")
    return {"art": art, "reasons": entry.get("reason_ids", []), "printed": printed}


def _fill(text: str, world, repo: pathlib.Path) -> str:
    return text.replace("{R}", str(repo)).replace("{T}", str(world["w"])).replace("{H}", str(world["home"]))


def _input(case: dict, world, repo: pathlib.Path) -> dict:
    if case["tool"] == "Bash":
        return {"command": _fill(case["form"], world, repo), "description": "fallbook"}
    return {k: _fill(v, world, repo) if isinstance(v, str) else v for k, v in case["input"].items()}


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("kind", ["b7n0de", "lokal"])
@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_fallbook_case(world, case, kind, host):
    repo = world["repos"][kind]
    got = run(world, host, case["tool"], _input(case, world, repo), repo)
    assert got["art"] == case["kopf"][f"{kind}/{host}"], (case["id"], kind, host, got["art"], got["reasons"])
    grund = case["grund"][host]
    if grund is not None and got["art"] != "nicht_gesehen":
        assert grund in got["reasons"], (case["id"], kind, host, got["reasons"])


def test_fallbook_C2_at_eight_open_prs(world, tmp_path):
    """C2 as the fallbook means it: the session already holds 8 open pull requests (D110), counted by the hook after
    each call; the gate asks and the line says so (a card in the profile of b7n0de, a deny under Codex)."""
    case = next(c for c in CASES if c["id"] == "C2")
    for kind, host, art in (("lokal", "claude", "klick"), ("b7n0de", "claude", "sperre"), ("lokal", "codex", "sperre")):
        data = tmp_path / f"{kind}-{host}"
        data.mkdir()
        (data / "open-prs.json").write_text(json.dumps({"schema": "proofbundle-plugin/open-prs/v0.1", "sitzungen": {
            SESSION: [f"b7n0de/proofbundle#{k}" for k in range(1, 9)]}}))
        repo = world["repos"][kind]
        got = run(world, host, "Bash", _input(case, world, repo), repo, data=data)
        assert got["art"] == art and "house_pr_limit_reached" in got["reasons"], (kind, host, got)
        if host == "claude" and kind == "lokal":
            assert "8 or more open PRs" in got["printed"]["systemMessage"], got["printed"]


def test_fallbook_C3_red_text(world, tmp_path):
    """C3 as the fallbook means it: the text of the file breaks the house form (rule (c): a tool attribution), and the
    house's form checker stands at the default branch the remote records (D109)."""
    with _environment(world["env"]):
        repo = d92._fixture(tmp_path)
    (repo / "note.md").write_text("Generated with a tool.\n")
    case = next(c for c in CASES if c["id"] == "C3")
    for host in ("claude", "codex"):
        got = run(world, host, "Bash", _input(case, world, repo), repo, data=tmp_path / f"data-{host}")
        assert got["art"] == "sperre" and "text_form_red" in got["reasons"], (host, got)
