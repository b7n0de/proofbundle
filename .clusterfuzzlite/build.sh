#!/bin/bash -eu
# ClusterFuzzLite build script (WP-D). Compiles the Atheris fuzz target(s) into $OUT.
# Docs: https://google.github.io/clusterfuzzlite/build-integration/python-lang/
# NOTE: the source tree is intentionally NOT deleted — ClusterFuzzLite needs it for coverage builds.

pip install --no-cache-dir .

# Package each fuzz_* entrypoint as a self-contained libFuzzer-compatible binary via Atheris' helper.
for fuzzer in "$SRC"/proofbundle/../../fuzz/fuzz_*.py; do
  name="$(basename "$fuzzer" .py)"
  compile_python_fuzzer "$fuzzer" \
    --add-data "$SRC/conformance:conformance"
done

# Seed corpus (deduped by ClusterFuzzLite): the committed conformance receipts + a few adversarial seeds.
if [ -d "$SRC/fuzz/corpus" ]; then
  for f in fuzz_*; do
    zip -q -j "$OUT/${f}_seed_corpus.zip" "$SRC"/fuzz/corpus/* 2>/dev/null || true
  done
fi
