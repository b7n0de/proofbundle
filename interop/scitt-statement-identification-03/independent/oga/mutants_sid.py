"""Single-byte mutants of statement 01 (each position: xor 0x01, xor 0x80, set 0x00), C1's reference and key."""
import base64,hashlib,json,os,sys,time,collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sid_axes as X
f=json.load(open(sys.argv[1])); out=sys.argv[2]
b=lambda o: base64.b64decode(o["base64"]); inp=f["inputs"]
c=b(inp["candidate"]); r=b(inp["reference"]); k=b(inp["stated_key"]["public_key"])
seen=set(); rows=[]; t=time.time(); errs=0
for i in range(len(c)):
    for op,nv in (("xor01",c[i]^1),("xor80",c[i]^0x80),("set00",0)):
        m=c[:i]+bytes([nv])+c[i+1:]
        if m==c or m in seen: continue
        seen.add(m)
        try: a=X.axes(m,r,-16,"ToBeSigned",b"",X.NOT_SUPPLIED,k)
        except Exception as e: a={"error":type(e).__name__+": "+str(e)}; errs+=1
        rows.append({"pos":i,"op":op,"sha256":hashlib.sha256(m).hexdigest(),"axes":a})
with open(out,"w") as fh:
    for x in rows: fh.write(json.dumps(x,sort_keys=True)+"\n")
cnt=collections.Counter(json.dumps(x["axes"],sort_keys=True) for x in rows)
print("mutants",len(rows),"errors",errs,"seconds %.0f"%(time.time()-t))
for kx,v in cnt.most_common(): print(v,kx)
