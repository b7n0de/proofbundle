import sys
# print each hunk of a one-word-per-line diff as: context [-removed-]{+added+}
lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
hunks, cur = [], None
for ln in lines:
    if ln.startswith("@@"):
        cur = []
        hunks.append(cur)
        continue
    if cur is None or ln.startswith(("diff ", "index ", "--- ", "+++ ")):
        continue
    cur.append(ln)
for i, h in enumerate(hunks, 1):
    s, mode, buf = [], " ", []
    def flush():
        if buf:
            w = " ".join(buf)
            s.append({" ": w, "-": "[-" + w + "-]", "+": "{+" + w + "+}"}[mode])
    for ln in [x for x in h if x and x[:1] in "+- "]:
        m = ln[:1] if ln[:1] in "+- " else " "
        if m != mode:
            flush()
            buf, mode = [], m
        buf.append(ln[1:])
    flush()
    print(f"H{i}: " + " ".join(s)[:int(sys.argv[2]) if len(sys.argv) > 2 else 4000])
