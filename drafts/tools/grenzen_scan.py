"""Boundary scan over the draft texts: case-insensitive counts per name, the same names as the -00 scan."""
import re
import sys
NAMES = ["proofbundle", "b7n0de", "Claude", "Codex", "Cowork", "nanogpt", "qwen", "gemini", "Anthropic", "OpenAI",
         "Kraxo"]
def counts(path):
    raw = open(path, encoding="utf-8").read()
    # the plain text wraps lines; join a hyphen line break and collapse page breaks for the multi-word patterns
    flat = re.sub(r"\n\f?\n?Gruszka[^\n]*\n\f?\nInternet-Draft[^\n]*\n", "\n", raw)
    flat = re.sub(r"-\n\s+", "-", flat)
    flat = re.sub(r"\s+", " ", flat)
    out = {n: len(re.findall(re.escape(n), raw, re.I)) for n in NAMES}
    out["standard"] = len(re.findall(r"Standards Track", flat, re.I))
    out["working_group"] = len(re.findall(r"working group", flat, re.I))
    out["urn:ietf:params:"] = len(re.findall(re.escape("urn:ietf:params:"), flat, re.I))
    out["vnd-type"] = len(re.findall(re.escape("application/vnd.signed-evidence.eval-receipt+json"), flat))
    out["schema-uri"] = len(re.findall(re.escape("https://signed-evidence.org/eval-receipt/v1"), flat))
    return out
for label, path in zip(sys.argv[1::2], sys.argv[2::2]):
    print(label, " ".join(f"{k}={v}" for k, v in counts(path).items()))
