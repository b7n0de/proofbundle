import re
import sys
import glob
import os
draft=open(sys.argv[1],encoding='utf-8').read()
srcdir=sys.argv[2]
def strip_pages(t):
    lines=t.split('\n')
    out=[]
    for ln in lines:
        if '\f' in ln:
            continue
        if re.match(r'^\S.*\[Page \d+\]\s*$',ln):
            continue
        if re.match(r'^(Internet-Draft|RFC \d+)\s{2,}.*\s{2,}\S+ \d{4}\s*$',ln):
            continue
        out.append(ln)
    return '\n'.join(out)
def norm(t):
    t=strip_pages(t)
    t=re.sub(r'-\n\s+','-',t)  # keep hyphen joins
    t=re.sub(r'\s+',' ',t)
    return t
D=norm(draft)
srcs={os.path.basename(f):norm(open(f,encoding='utf-8',errors='replace').read()) for f in glob.glob(os.path.join(srcdir,'*.txt'))}
qs=re.findall(r'"([^"]{12,400})"',D)
seen=set()
for q in qs:
    if q in seen:
        continue
    seen.add(q)
    hits=[n for n,s in srcs.items() if q in s]
    if not hits:
        # try without hyphen artifacts
        q2=q.replace('- ','-')
        hits=[n+'(hyphen-norm)' for n,s in srcs.items() if q2 in s or q2 in s.replace('- ','-')]
    i=D.find(q)
    ctx=D[max(0,i-90):i].strip()
    print(('OK   ' if hits else 'MISS ')+repr(q[:110]), '->', hits, '| ctx:', ctx[-90:])
