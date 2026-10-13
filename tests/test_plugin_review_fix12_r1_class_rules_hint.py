"""Review round 12 of 2026-10-13, the class of R12-1: the rules hint of owner choice 4 says what today's fetch rules map,
not that no local record exists.

Measured here at 0edc6810 with git 2.43.0, in the class search of R12-1: in the declared fixture repository a local tag
refs/tags/release (as `git fetch` leaves a tag it followed) at a commit without a declaration; no fetch rule maps
refs/tags/release to a present ref. Level 1 for `git push origin HEAD:refs/tags/release` asked as before and added the hint
"No local record of refs/tags/release was found", while that present ref may record the destination. The verdict was
not affected; the sentence concluded absence from today's configuration.

Property: the hint compares with the refs today's fetch rules map the destination to and says so; it claims no absence of
local records. Red against 0edc6810.
"""
from __future__ import annotations

import test_claude_code_plugin_gate as cg
import test_plugin_owner_choice4_rules_hint as h4
from test_claude_code_plugin_gate import _clean_git_config, repo, shim  # noqa: F401  (fixtures)

pytestmark = h4.pytestmark


def test_a_present_tag_no_fetch_rule_maps_is_not_called_no_record(shim, repo):  # noqa: F811
    head = h4._rev(repo, "HEAD")
    cg._git(repo, "tag", "release", "HEAD~1")
    text = h4._ask(shim, repo, "git push origin HEAD:refs/tags/release")
    assert "No local record of refs/tags/release was found" not in text, text
    assert (f"Today's fetch rules map refs/tags/release to no present ref, so the evidence rules at source commit "
            f"{head[:12]} were compared with none; that is no equality.") in text, text


def test_a_new_branch_gets_the_same_wording(shim, repo):  # noqa: F811
    text = h4._ask(shim, repo, "git push origin main:fresh")
    assert (f"Today's fetch rules map fresh to no present ref, so the evidence rules at source commit "
            f"{h4._rev(repo, 'HEAD')[:12]} were compared with none; that is no equality.") in text, text
