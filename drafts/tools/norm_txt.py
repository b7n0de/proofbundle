import re
import sys
# drop page headers/footers and form feeds, join to one word per line
t = open(sys.argv[1], encoding="utf-8").read()
out = []
for ln in t.split("\n"):
    if "\f" in ln or re.match(r"^Internet-Draft\s{2,}", ln) or re.match(r"^Gruszka\s{2,}.*\[Page \d+\]$", ln):
        continue
    out.append(ln)
words = " ".join(out).split()
open(sys.argv[2], "w", encoding="utf-8").write("\n".join(words) + "\n")
