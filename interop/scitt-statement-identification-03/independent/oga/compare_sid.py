import json,os,sys,datetime
vp, cases_d = sys.argv[1:3]
v=json.load(open(vp))["verdicts"]; n=agree=0; rows=[]
for cid,o in v.items():
    f=json.load(open(os.path.join(cases_d,cid+".json")))
    pairs=[(cid,o["case"],f["expected"])]+[(cid+" / "+x["name"],x["axes"],e["expected"]) for x,e in zip(o["variants"],f.get("variants",[]))]
    for name,mine,exp in pairs:
        n+=1; same=all(mine[k]==exp.get(k) for k in exp)
        agree+=same
        if not same or set(exp)!=set(mine): rows.append((name,mine,exp))
print("opened expected at",datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
print("agree %d of %d"%(agree,n))
for r in rows: print("DIFF",r)
