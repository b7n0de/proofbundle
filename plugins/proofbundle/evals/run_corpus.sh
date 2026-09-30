#!/usr/bin/env bash
# Run the failure corpus after every update of Claude Code or Codex, and record the host versions.
#
#   bash plugins/proofbundle/evals/run_corpus.sh             (from the repository root; no model call)
#   bash plugins/proofbundle/evals/run_corpus.sh --with-eval (adds the model cases, a cost ceiling of 2 USD)
#
# Writes plugins/proofbundle/evals/results/corpus-<UTC time>/ (ignored by git): versions.txt, tests.txt,
# codex-hooks.json and, with --with-eval, eval-*.json. Each case of the corpus has a valid counterpart that
# must keep passing (evals/CORPUS.md).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
out="plugins/proofbundle/evals/results/corpus-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $(git rev-parse HEAD)"
  echo "claude: $(claude --version 2>/dev/null || echo 'not installed')"
  echo "codex: $(codex --version 2>/dev/null || echo 'not installed')"
  echo "uv: $(uv --version 2>/dev/null || echo 'not installed')"
  echo "python: $(python3 --version 2>&1)"
} > "$out/versions.txt"
python3 -m pytest -q -p no:cacheprovider tests/test_claude_code_plugin.py tests/test_claude_code_plugin_gate.py \
  tests/test_codex_plugin.py tests/test_plugin_gate_log.py tests/test_plugin_evals.py > "$out/tests.txt" 2>&1 \
  && echo "tests: passed" >> "$out/versions.txt" || echo "tests: FAILED, see tests.txt" >> "$out/versions.txt"
python3 plugins/proofbundle/evals/corpus_codex_hooks.py > "$out/codex-hooks.json" 2>&1 \
  && echo "codex hooks: ok" >> "$out/versions.txt" || echo "codex hooks: not ok or NOT MEASURED, see codex-hooks.json" >> "$out/versions.txt"
if [ "${1:-}" = "--with-eval" ]; then
  for tag in corpus counterpart; do
    claude plugin eval plugins/proofbundle --tag "$tag" --trust-plugin --scaffold --mocks off --no-publish \
      --runs 1 --ablation none --max-cost-usd 1 --allow-tools Bash Write "mcp__plugin_proofbundle_proofbundle__*" \
      --json "$out/eval-$tag.json" > "$out/eval-$tag.txt" 2>&1 || true
  done
fi
cat "$out/versions.txt"
