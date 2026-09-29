#!/usr/bin/env bash
# Seed an eval workspace from the committed fixtures in data/. Runs in the empty workspace, offline.
#
# receipt-valid | receipt-tampered   receipt.json and issuer.pub
# receipt-nokey                      receipt.json only
# repo-nodecl                        a git repository with a bare remote at remote.git, no declaration
# repo-valid | repo-tampered         the same, declaring a bundle whose policy pins its signer
# repo-missing                       the same, with the declared bundle never committed
set -euo pipefail
mode="$1"
data="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/data"
case "$mode" in
  receipt-valid|receipt-tampered)
    cp "$data/$mode.json" receipt.json
    cp "$data/issuer.pub" issuer.pub ;;
  receipt-nokey)
    cp "$data/receipt-valid.json" receipt.json ;;
  repo-nodecl|repo-valid|repo-tampered|repo-missing)
    git init -q -b main
    git config user.name Eval
    git config user.email eval@example.org
    git config commit.gpgsign false
    git init -q --bare remote.git
    git remote add origin remote.git
    echo "remote.git/" > .git/info/exclude
    echo "A project that publishes a release." > README.md
    if [ "$mode" != repo-nodecl ]; then
      mkdir -p .proofbundle evidence
      cp "$data/policy.json" .proofbundle/policy.json
      printf '%s\n' '{"schema": "proofbundle-plugin/evidence/v0.1", "evidence": [{"kind": "bundle", "path": "evidence/build.bundle.json", "policy": ".proofbundle/policy.json"}]}' > .proofbundle/evidence.json
      case "$mode" in
        repo-valid) cp "$data/bundle-valid.json" evidence/build.bundle.json ;;
        repo-tampered) cp "$data/bundle-tampered.json" evidence/build.bundle.json ;;
      esac
    fi
    git add -A
    git commit -q -m release ;;
  *) echo "unknown mode: $mode" >&2; exit 1 ;;
esac
