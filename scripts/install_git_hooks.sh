#!/bin/sh
# Install the repo's committed git hooks into .git/hooks (currently: pre-commit mutant guard).
# Refuses to overwrite a foreign pre-existing hook unless called with --force.
set -eu
top="$(git rev-parse --show-toplevel)"
src="$top/scripts/git-hooks/pre-commit"
# --git-path resolves correctly for worktrees (where .git is a file) and core.hooksPath setups.
hooks_dir="$(git rev-parse --git-path hooks)"
mkdir -p "$hooks_dir"
dst="$hooks_dir/pre-commit"
if [ -e "$dst" ] && [ "${1:-}" != "--force" ] && ! grep -q "mutant_signature_guard" "$dst"; then
    echo "install_git_hooks: $dst exists and is not ours; re-run with --force to replace" >&2
    exit 1
fi
cp "$src" "$dst"
chmod +x "$dst"
echo "install_git_hooks: pre-commit mutant guard installed at $dst"
