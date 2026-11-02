"""D38, F1 of follow-up note 17: done-order behind a program that builds its arguments from its input.

Measured by the review session at f6408b97 (Lieferung 9): `echo --replace | xargs python3 <gate> done-order --repo /work/clone` got
no answer under either host, while xargs runs `done-order --repo /work/clone --replace`. Owner choice O2 of follow-up note 13:
where the gate cannot read the switches, the answer is the one for a replacement. Now done-order behind xargs or GNU
parallel is a change in every form: ask under Claude Code, deny under Codex.

Measured at d6e248a8 for the siblings: `xargs -I{} … {}` and `xargs -i … {}` asked already (`{}` is a word the shell
may rewrite), and so did parallel with `:::` and every `find -exec`/`-execdir` form (`{}`, and the closing `;` read as
an unknown switch). Plain xargs, `-a`, `-0`, `-n`, `-I %` and parallel reading its input got no answer.

RED at d6e248a8 for the forms with no answer there; the forms that asked there and the free controls answer the same at
both heads.
"""
from __future__ import annotations

import pytest

import test_plugin_done_order_shell_call as s

pytestmark = s.pytestmark
G = s.G

CHANGING = [
    f"echo --replace | xargs python3 {G} done-order --repo /work/clone",
    f"echo /work/clone | xargs -I % python3 {G} done-order --repo %",
    f"xargs -a list.txt python3 {G} done-order --repo /work/clone",
    f"printf '%s\\0' --remove | xargs -0 python3 {G} done-order --repo /work/clone",
    f"echo --replace | xargs -n 1 python3 {G} done-order --repo /work/clone",
    f"echo --replace | parallel python3 {G} done-order --repo /work/clone",
    f"echo done-order --replace | xargs python3 {G}",
    f"echo --replace | env xargs python3 {G} done-order --repo /work/clone",
    f"echo --replace | xargs {G} done-order --repo /work/clone",
]
ASKED_BEFORE = [
    f"echo /work/clone | xargs -I{{}} python3 {G} done-order --repo {{}}",
    f"echo /work/clone | xargs -i python3 {G} done-order --repo {{}}",
    f"parallel python3 {G} done-order --repo /work/clone ::: --replace",
    f"find /work -maxdepth 0 -exec python3 {G} done-order --repo {{}} \\;",
    f"find /work -maxdepth 0 -execdir python3 {G} done-order --repo {{}} +",
    f"find /work -maxdepth 0 -exec python3 {G} done-order --repo /work/clone ';'",
]
FREE = [
    f"python3 {G} done-order --list | head -5",
    "echo done-order --replace | xargs echo",
    f"echo x | xargs python3 {G} stop",
]


@pytest.mark.parametrize("host, expected", [("claude", "ask"), ("codex", "deny")])
@pytest.mark.parametrize("command", CHANGING + ASKED_BEFORE)
def test_F1_done_order_behind_xargs_or_parallel_asks_or_is_denied(tmp_path, command, host, expected):
    code, decision, reason = s._answer(tmp_path, command, host)
    assert (code, decision) == (0, expected), (code, decision, reason)
    assert "replaces or removes a local done order" in reason, reason


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", FREE)
def test_F1_control_the_list_and_other_programs_stay_free(tmp_path, command, host):
    assert s._answer(tmp_path, command, host)[:2] == (0, None)
