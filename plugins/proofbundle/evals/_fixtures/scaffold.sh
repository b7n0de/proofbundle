#!/usr/bin/env bash
# Seed an eval workspace from the committed fixtures in data/. Runs in the empty workspace, offline.
#
# receipt-valid | receipt-tampered   receipt.json and issuer.pub
# receipt-nokey                      receipt.json only
# repo-nodecl                        a git repository with a bare remote at remote.git, no declaration
# repo-valid | repo-tampered         the same, declaring a bundle whose policy pins its signer and whose
#                                    signed payload names the tree digest of the commit made here
# repo-missing                       the same, with the declared bundle never committed
# repo-worktree-only                 repo-nodecl plus the declaration, bundle and policy of repo-valid in the
#                                    working tree, never committed
# repo-stale                         repo-valid plus one more committed file, so the tree at HEAD is not
#                                    the tree the declaration and the bundle name
set -euo pipefail
mode="$1"
data="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/data"
case "$mode" in
  receipt-valid|receipt-tampered)
    cp "$data/$mode.json" receipt.json
    cp "$data/issuer.pub" issuer.pub ;;
  receipt-nokey)
    cp "$data/receipt-valid.json" receipt.json ;;
  repo-nodecl|repo-valid|repo-tampered|repo-missing|repo-stale|repo-worktree-only)
    git init -q -b main
    git config user.name Eval
    git config user.email eval@example.org
    git config commit.gpgsign false
    git init -q --bare remote.git
    git remote add origin remote.git
    echo "remote.git/" > .git/info/exclude
    echo "A project that publishes a release." > README.md
    if [ "$mode" != repo-nodecl ] && [ "$mode" != repo-worktree-only ]; then
      mkdir -p .proofbundle
      cp "$data/policy.json" .proofbundle/policy.json
      cp "$data/evidence.json" .proofbundle/evidence.json
      case "$mode" in
        repo-valid) cp "$data/bundle-valid.json" .proofbundle/build.bundle.json ;;
        repo-tampered) cp "$data/bundle-tampered.json" .proofbundle/build.bundle.json ;;
        repo-stale)
          cp "$data/bundle-valid.json" .proofbundle/build.bundle.json
          echo "A change made after the evidence was signed." > CHANGES.md ;;
      esac
    fi
    git add -A
    git commit -q -m release
    if [ "$mode" = repo-worktree-only ]; then
      mkdir -p .proofbundle
      cp "$data/policy.json" .proofbundle/policy.json
      cp "$data/evidence.json" .proofbundle/evidence.json
      cp "$data/bundle-valid.json" .proofbundle/build.bundle.json
    fi ;;
  *) echo "unknown mode: $mode" >&2; exit 1 ;;
esac
