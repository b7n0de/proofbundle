package main

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/sha256"
    "crypto/sha512"
    "crypto/x509"
    "encoding/hex"
    "encoding/pem"
    "errors"
    "flag"
    "fmt"
    "io"
    "math/big"
    "os"
    "strconv"
    "strings"
    "unicode/utf8"
)

// Limits are exclusive: reaching a limit yields resource_limit, not FAIL.
const MaxProofs = 256
const MaxPath = 256
const MaxKeys = 256
const MaxTree = 4096

type failure string
func (e failure) Error() string { return string(e) }

func readInput(path string) ([]byte, error) {
    f, err := os.Open(path)
    if err != nil { return nil, failure("io") }
    defer f.Close()
    b, err := io.ReadAll(io.LimitReader(f, MaxFile))
    if err != nil { return nil, failure("io") }
    if len(b) >= MaxFile { return nil, ErrLimit }
    return b, nil
}

func number(v *V) (int64, bool) {
    if v == nil || v.U > uint64(1<<63-1) { return 0, false }
    if v.Kind == 0 { return int64(v.U), true }
    if v.Kind == 1 { return -1-int64(v.U), true }
    return 0, false
}

func label(v *V) (string, bool) {
    if v == nil { return "", false }
    if v.Kind == 0 || v.Kind == 1 {
        return strconv.Itoa(int(v.Kind))+":"+strconv.FormatUint(v.U,10), true
    }
    if v.Kind == 3 { return "t:"+string(v.B), true }
    return "", false
}

func labels(v *V, reason string) (map[string]*V, error) {
    if v == nil || v.Kind != 5 { return nil, failure(reason) }
    out := make(map[string]*V)
    for _, item := range v.M {
        k, ok := label(item.K)
        if !ok { return nil, failure(reason) }
        if _, exists := out[k]; exists { return nil, failure(reason) }
        out[k] = item.X
    }
    return out, nil
}

func get(v *V, key int64) *V {
    if v == nil || v.Kind != 5 { return nil }
    for _, item := range v.M {
        n, ok := number(item.K)
        if ok && n == key { return item.X }
    }
    return nil
}

func isBytes(v *V, size int) bool { return v != nil && v.Kind == 2 && len(v.B) == size }

func coseArray(v *V, tagRequired bool) (*V, error) {
    if v.Kind == 6 {
        if v.U != 18 { return nil, failure("cbor") }
        v = v.Elem
    } else if tagRequired { return nil, failure("statement") }
    if v == nil || v.Kind != 4 || len(v.A) != 4 { return nil, failure("cbor") }
    if v.A[0].Kind != 2 || v.A[1].Kind != 5 || v.A[3].Kind != 2 {
        return nil, failure("cbor")
    }
    if !(v.A[2].Kind == 2 || (v.A[2].Kind == 7 && v.A[2].U == 22)) {
        return nil, failure("cbor")
    }
    return v, nil
}

func protected(v *V) (*V, error) {
    if len(v.B) == 0 { return &V{Kind:5}, nil }
    p, err := decode(v.B)
    if err != nil { return nil, err }
    if p.Kind != 5 { return nil, failure("header") }
    return p, nil
}

func statementHash(raw []byte) ([]byte, error) {
    v, err := decode(raw)
    if err != nil { return nil, err }
    a, err := coseArray(v, true)
    if err != nil { return nil, err }
    p, err := protected(a.A[0])
    if err != nil { return nil, err }
    if _, err = labels(p, "statement"); err != nil { return nil, err }
    if _, err = labels(a.A[1], "statement"); err != nil { return nil, err }
    // Preserve tag, array and complete encoded protected/payload/signature items.
    // Explicit local reading of 2.2: replace even an already empty map with a0.
    u := a.A[1]
    preimage := make([]byte, 0, len(raw)-(u.End-u.Start)+1)
    preimage = append(preimage, raw[:u.Start]...)
    preimage = append(preimage, 0xa0)
    preimage = append(preimage, raw[u.End:]...)
    h := sha256.Sum256(preimage)
    return h[:], nil
}

type receipt struct {
    body []byte
    signature []byte
    alg int64
    kid []byte
    hasKid bool
    vdp *V
}

func parseReceipt(raw []byte) (*receipt, error) {
    v, err := decode(raw)
    if err != nil { return nil, err }
    a, err := coseArray(v, false)
    if err != nil { return nil, err }
    if a.A[2].Kind != 7 || a.A[2].U != 22 { return nil, failure("header") }
    p, err := protected(a.A[0])
    if err != nil { return nil, err }
    pm, err := labels(p, "header")
    if err != nil { return nil, err }
    um, err := labels(a.A[1], "header")
    if err != nil { return nil, err }
    for k := range pm { if _, exists := um[k]; exists { return nil, failure("header") } }
    alg, ok := number(get(p, 1))
    if !ok { return nil, failure("header") }
    if alg != -7 && alg != -35 && alg != -36 { return nil, failure("algorithm") }
    vds, ok := number(get(p, 395))
    if !ok || vds != 2 { return nil, failure("header") }
    if get(a.A[1], 2) != nil { return nil, failure("header") }
    if crit := get(p, 2); crit != nil {
        if crit.Kind != 4 || len(crit.A) == 0 { return nil, failure("header") }
        seen := make(map[string]bool)
        for _, item := range crit.A {
            k, good := label(item)
            n, integer := number(item)
            if !good || seen[k] || pm[k] == nil || !integer || (n != 1 && n != 4 && n != 395) {
                return nil, failure("header")
            }
            seen[k] = true
        }
    }
    r := &receipt{body:a.A[0].B, signature:a.A[3].B, alg:alg, vdp:get(a.A[1],396)}
    if kid := get(p,4); kid != nil {
        if kid.Kind != 2 { return nil, failure("header") }
        r.kid, r.hasKid = kid.B, true
    }
    if r.vdp == nil || r.vdp.Kind != 5 { return nil, failure("header") }
    if _, err = labels(r.vdp,"proof"); err != nil { return nil, err }
    for _, item := range r.vdp.M {
        k, good := number(item.K)
        if !good || (k != -1 && k != -2) { return nil, failure("proof") }
    }
    if len(r.vdp.M) == 0 { return nil, failure("proof") }
    return r, nil
}

type step struct { left bool; hash []byte }
type inclusion struct { transaction, evidence, data []byte; path []step }
type consistency struct { anchor []byte; path []step }

func proofMap(v *V) (*V,error) {
    if v == nil || v.Kind != 2 { return nil,failure("proof") }
    p,err := decode(v.B)
    if err != nil { return nil,err }
    if p.Kind != 5 || len(p.M) != 2 { return nil,failure("proof") }
    if _,err = labels(p,"proof"); err != nil { return nil,err }
    if get(p,1) == nil || get(p,2) == nil { return nil,failure("proof") }
    return p,nil
}

func parsePath(v *V) ([]step,error) {
    if v == nil || v.Kind != 4 || len(v.A) == 0 { return nil,failure("proof") }
    if len(v.A) >= MaxPath { return nil,ErrLimit }
    path := make([]step,0,len(v.A))
    for _, s := range v.A {
        if s.Kind != 4 || len(s.A) != 2 { return nil,failure("proof") }
        b,h := s.A[0],s.A[1]
        if b.Kind != 7 || (b.U != 20 && b.U != 21) || !isBytes(h,32) {
            return nil,failure("proof")
        }
        path = append(path,step{b.U == 21,h.B})
    }
    return path,nil
}

func parseProofs(r *receipt) ([]inclusion,[]consistency,error) {
    var incs []inclusion
    var cons []consistency
    total := 0
    for _, item := range r.vdp.M {
        k,_ := number(item.K)
        list := item.X
        if list.Kind != 4 || len(list.A) == 0 { return nil,nil,failure("proof") }
        total += len(list.A)
        if total >= MaxProofs { return nil,nil,ErrLimit }
        for _, raw := range list.A {
            p,err := proofMap(raw)
            if err != nil { return nil,nil,err }
            path,err := parsePath(get(p,2))
            if err != nil { return nil,nil,err }
            first := get(p,1)
            if k == -1 {
                if first.Kind != 4 || len(first.A) != 3 { return nil,nil,failure("proof") }
                a,e,d := first.A[0],first.A[1],first.A[2]
                if !isBytes(a,32) || !isBytes(d,32) || e.Kind != 3 || len(e.B)<1 || len(e.B)>1024 || !utf8.Valid(e.B) {
                    return nil,nil,failure("proof")
                }
                incs = append(incs,inclusion{a.B,e.B,d.B,path})
            } else {
                if !isBytes(first,32) { return nil,nil,failure("proof") }
                cons = append(cons,consistency{first.B,path})
            }
        }
    }
    return incs,cons,nil
}

func hashParts(parts ...[]byte) []byte {
    h := sha256.New()
    for _, p := range parts { _,_ = h.Write(p) }
    return h.Sum(nil)
}

func inclusionRoot(p inclusion) []byte {
    h := hashParts(p.transaction,hashParts(p.evidence),p.data)
    for _, s := range p.path {
        if s.left { h = hashParts(s.hash,h) } else { h = hashParts(h,s.hash) }
    }
    return h
}

func consistencyRoots(p consistency) ([]byte,[]byte) {
    older,newer := p.anchor,p.anchor
    for _, s := range p.path {
        if s.left { older=hashParts(s.hash,older); newer=hashParts(s.hash,newer) } else { newer=hashParts(newer,s.hash) }
    }
    return older,newer
}

type publicKey struct {
    key *ecdsa.PublicKey
    kid []byte
    hasKid bool
    alg int64
    hasAlg bool
    canVerify bool
}

func curveFor(n int64) elliptic.Curve {
    switch n { case 1: return elliptic.P256(); case 2: return elliptic.P384(); case 3: return elliptic.P521() }
    return nil
}

func readKeys(raw []byte) ([]publicKey,error) {
    if bytes.HasPrefix(bytes.TrimSpace(raw),[]byte("-----BEGIN")) {
        block,rest := pem.Decode(raw)
        if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 { return nil,failure("key") }
        cert,err := x509.ParseCertificate(block.Bytes)
        if err != nil { return nil,failure("key") }
        key,ok := cert.PublicKey.(*ecdsa.PublicKey)
        if !ok { return nil,failure("key") }
        return []publicKey{{key:key,canVerify:true}},nil
    }
    v,err := decode(raw)
    if err != nil { return nil,err }
    if v.Kind != 4 || len(v.A) == 0 { return nil,failure("key") }
    if len(v.A) >= MaxKeys { return nil,ErrLimit }
    keys := make([]publicKey,0,len(v.A))
    for _, item := range v.A {
        if _,err := labels(item,"key"); err != nil { return nil,err }
        kty,ok := number(get(item,1))
        if !ok || kty != 2 { return nil,failure("key") }
        crv,ok := number(get(item,-1))
        if !ok { return nil,failure("key") }
        curve := curveFor(crv)
        if curve == nil { return nil,failure("key") }
        size := (curve.Params().BitSize+7)/8
        xv,yv := get(item,-2),get(item,-3)
        if !isBytes(xv,size) { return nil,failure("key") }
        x := new(big.Int).SetBytes(xv.B)
        var y *big.Int
        if isBytes(yv,size) {
            y = new(big.Int).SetBytes(yv.B)
        } else if yv != nil && yv.Kind == 7 && (yv.U == 20 || yv.U == 21) {
            // EC2 compressed y: solve y^2 = x^3 - 3x + B and select parity.
            prime := curve.Params().P
            if x.Cmp(prime)>=0 { return nil,failure("key") }
            rhs := new(big.Int).Mul(x,x)
            rhs.Mul(rhs,x)
            rhs.Sub(rhs,new(big.Int).Mul(big.NewInt(3),x))
            rhs.Add(rhs,curve.Params().B)
            rhs.Mod(rhs,prime)
            y = new(big.Int).ModSqrt(rhs,prime)
            if y == nil { return nil,failure("key") }
            if (y.Bit(0)==1) != (yv.U==21) { y.Sub(prime,y) }
        } else { return nil,failure("key") }
        if !curve.IsOnCurve(x,y) { return nil,failure("key") }
        key := publicKey{key:&ecdsa.PublicKey{Curve:curve,X:x,Y:y},canVerify:true}
        if kid := get(item,2); kid != nil {
            if kid.Kind != 2 { return nil,failure("key") }
            key.kid,key.hasKid = kid.B,true
        }
        if a := get(item,3); a != nil {
            key.alg,key.hasAlg = number(a)
            if !key.hasAlg { return nil,failure("key") }
        }
        if ops := get(item,4); ops != nil {
            if ops.Kind != 4 || len(ops.A)==0 { return nil,failure("key") }
            key.canVerify=false
            seen:=make(map[string]bool)
            for _, op:=range ops.A {
                opLabel,good:=label(op)
                if !good || seen[opLabel] { return nil,failure("key") }
                seen[opLabel]=true
                operation,integer:=number(op)
                if integer && operation==2 { key.canVerify=true }
            }
        }
        keys = append(keys,key)
    }
    return keys,nil
}

func sigStructure(body,root []byte) []byte {
    return encArray(encTstr("Signature1"),encBstr(body),encBstr(nil),encBstr(root))
}

func verifySignature(r *receipt, root []byte, keys []publicKey) error {
    structure := sigStructure(r.body,root)
    var digest []byte
    switch r.alg {
    case -7: h:=sha256.Sum256(structure); digest=h[:]
    case -35: h:=sha512.Sum384(structure); digest=h[:]
    case -36: h:=sha512.Sum512(structure); digest=h[:]
    default: return failure("algorithm")
    }
    anyKid := false
    for _, k := range keys { anyKid = anyKid || k.hasKid }
    selected := false
    for _, k := range keys {
        if r.hasKid && anyKid && (!k.hasKid || !bytes.Equal(r.kid,k.kid)) { continue }
        if !k.canVerify || (k.hasAlg && k.alg!=r.alg) { continue }
        selected = true
        size := (k.key.Curve.Params().BitSize+7)/8
        if len(r.signature) != 2*size { continue }
        rr := new(big.Int).SetBytes(r.signature[:size])
        ss := new(big.Int).SetBytes(r.signature[size:])
        if ecdsa.Verify(k.key,digest,rr,ss) { return nil }
    }
    if !selected { return failure("key") }
    return failure("signature")
}

func verify(r *receipt, keys []publicKey, digest, older []byte, mode string) ([]byte,error) {
    incs,cons,err := parseProofs(r)
    if err != nil { return nil,err }
    if mode == "receipt" && len(incs)==0 { return nil,failure("proof") }
    if mode == "consistency" && len(cons)==0 { return nil,failure("proof") }
    var root []byte
    join := func(h []byte) error {
        if root == nil { root=h; return nil }
        if !bytes.Equal(root,h) { return failure("root_mismatch") }
        return nil
    }
    for _, p := range incs {
        if mode == "receipt" && !bytes.Equal(p.data,digest) { return nil,failure("digest_mismatch") }
        if err=join(inclusionRoot(p)); err != nil { return nil,err }
    }
    matched := false
    for _, p := range cons {
        old,newer := consistencyRoots(p)
        if bytes.Equal(old,older) { matched=true }
        if err=join(newer); err != nil { return nil,err }
    }
    if mode == "consistency" && !matched { return nil,failure("older_root_mismatch") }
    if err=verifySignature(r,root,keys); err != nil { return nil,err }
    return root,nil
}

type interval struct { lo,hi int }
func splitSize(n int) int { k:=1; for k*2<n { k*=2 }; return k }

func generatedProof(m,n int) ([]byte,[]byte,[]byte,[]step) {
    cache:=make(map[interval][]byte)
    var mth func(int,int) []byte
    mth=func(a,b int) []byte {
        id:=interval{a,b}
        if h,ok:=cache[id]; ok { return h }
        var h []byte
        if b-a==1 { h=hashParts(bytes.Repeat([]byte{byte(a%256)},96)) } else {
            k:=splitSize(b-a)
            h=hashParts(mth(a,a+k),mth(a+k,b))
        }
        cache[id]=h
        return h
    }
    lowbit:=m & -m
    anchorRange:=interval{m-lowbit,m}
    var path []step
    var walk func(int,int)
    walk=func(a,b int) {
        if a==anchorRange.lo && b==anchorRange.hi { return }
        k:=splitSize(b-a)
        mid:=a+k
        if anchorRange.hi<=mid {
            walk(a,mid)
            path=append(path,step{false,mth(mid,b)})
        } else {
            walk(mid,b)
            path=append(path,step{true,mth(a,mid)})
        }
    }
    walk(0,n)
    return mth(0,m),mth(0,n),mth(anchorRange.lo,anchorRange.hi),path
}

func genLine(m,n int) string {
    rm,rn,anchor,path:=generatedProof(m,n)
    fields:=make([]string,0,len(path))
    for _, s:=range path {
        side:="R"; if s.left { side="L" }
        fields=append(fields,side+":"+hex.EncodeToString(s.hash))
    }
    return fmt.Sprintf("r_m=%x r_n=%x anchor=%x path=%s",rm,rn,anchor,strings.Join(fields,","))
}

func resultError(mode,digest string, err error) string {
    if errors.Is(err,ErrLimit) { return "resource_limit" }
    reason:="internal"
    if errors.Is(err,ErrCBOR) { reason="cbor" } else if f,ok:=err.(failure); ok { reason=string(f) }
    if mode=="receipt" { return "verdict=FAIL reason="+reason+" statement_digest="+digest }
    return "verdict=FAIL reason="+reason
}

func execute(args []string) (line string) {
    mode,digestText:="receipt","-"
    defer func() { if recover()!=nil { line=resultError(mode,digestText,failure("internal")) } }()
    fs:=flag.NewFlagSet("ccfverify",flag.ContinueOnError)
    fs.SetOutput(io.Discard)
    rec:=fs.String("receipt","","")
    con:=fs.String("consistency","","")
    keyPath:=fs.String("keys","","")
    stmt:=fs.String("statement","","")
    dig:=fs.String("digest","","")
    old:=fs.String("older-root","","")
    gen:=fs.Bool("gen",false,"")
    m:=fs.Int("m",0,"")
    n:=fs.Int("n",0,"")
    parseErr:=fs.Parse(args)
    if *con!="" { mode="consistency" }
    if *gen { mode="gen" }
    if parseErr!=nil || fs.NArg()!=0 { return resultError(mode,digestText,failure("arguments")) }
    fail:=func(e error) string { return resultError(mode,digestText,e) }
    count:=0
    if *rec!="" { count++ }; if *con!="" { count++ }; if *gen { count++ }
    if count!=1 { return fail(failure("arguments")) }
    if *gen {
        if *keyPath!="" || *stmt!="" || *dig!="" || *old!="" || *m<1 || *n<=*m { return fail(failure("arguments")) }
        if *n>=MaxTree { return fail(ErrLimit) }
        return genLine(*m,*n)
    }
    if *keyPath=="" || *m!=0 || *n!=0 { return fail(failure("arguments")) }
    var digest,older []byte
    var err error
    path:=*rec
    if mode=="receipt" {
        if (*stmt=="")==(*dig=="") || *old!="" { return fail(failure("arguments")) }
        if *stmt!="" {
            raw,e:=readInput(*stmt); if e!=nil { return fail(e) }
            digest,err=statementHash(raw)
        } else {
            digest,err=hex.DecodeString(*dig)
            if err!=nil || len(digest)!=32 { return fail(failure("arguments")) }
        }
        if err!=nil { return fail(err) }
        digestText=hex.EncodeToString(digest)
    } else {
        if *stmt!="" || *dig!="" || *old=="" { return fail(failure("arguments")) }
        older,err=hex.DecodeString(*old)
        if err!=nil || len(older)!=32 { return fail(failure("arguments")) }
        path=*con
    }
    raw,err:=readInput(path); if err!=nil { return fail(err) }
    receipt,err:=parseReceipt(raw); if err!=nil { return fail(err) }
    keyBytes,err:=readInput(*keyPath); if err!=nil { return fail(err) }
    keys,err:=readKeys(keyBytes); if err!=nil { return fail(err) }
    root,err:=verify(receipt,keys,digest,older,mode); if err!=nil { return fail(err) }
    if mode=="consistency" { return fmt.Sprintf("verdict=PASS newer_root=%x",root) }
    return fmt.Sprintf("verdict=PASS root=%x statement_digest=%x",root,digest)
}

func main() { fmt.Println(execute(os.Args[1:])) }

// Resource ceilings are exclusive: reaching a ceiling is resource_limit.
// The root value has depth 0; at depth 64 decoding stops without a verdict.
const (
	MaxFile      = 4 << 20
	MaxDepth     = 64
	MaxNodes     = 100000
	MaxContainer = 16384
	MaxString    = 4 << 20
)

var ErrCBOR = errors.New("cbor")
var ErrLimit = errors.New("resource_limit")

type V struct {
	Kind       byte
	U          uint64
	B          []byte
	A          []*V
	M          []KV
	Elem       *V
	Start, End int
}

type KV struct{ K, X *V }

type cborReader struct {
	b     []byte
	i     int
	nodes int
}

func decode(b []byte) (*V, error) {
	if len(b) >= MaxFile {
		return nil, ErrLimit
	}
	p := cborReader{b: b}
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	if p.i != len(b) {
		return nil, ErrCBOR
	}
	return v, nil
}

// argument accepts legal non-preferred lengths. Reserved additional-information
// values, and indefinite encodings where the major type forbids them, fail later.
func (p *cborReader) argument(ai byte) (uint64, error) {
	if ai < 24 {
		return uint64(ai), nil
	}
	var width int
	switch ai {
	case 24:
		width = 1
	case 25:
		width = 2
	case 26:
		width = 4
	case 27:
		width = 8
	default:
		return 0, ErrCBOR
	}
	if width > len(p.b)-p.i {
		return 0, ErrCBOR
	}
	var n uint64
	for _, octet := range p.b[p.i : p.i+width] {
		n = n<<8 | uint64(octet)
	}
	p.i += width
	return n, nil
}

func (p *cborReader) value(depth int) (*V, error) {
	if p.i == len(p.b) {
		return nil, ErrCBOR
	}
	if depth >= MaxDepth {
		return nil, ErrLimit
	}
	p.nodes++
	if p.nodes >= MaxNodes {
		return nil, ErrLimit
	}
	start := p.i
	initial := p.b[p.i]
	p.i++
	kind, ai := initial>>5, initial&31
	v := &V{Kind: kind, Start: start}
	if ai == 31 {
		if kind < 2 || kind > 5 {
			return nil, ErrCBOR
		}
		if err := p.indefinite(v, depth); err != nil {
			return nil, err
		}
		v.End = p.i
		return v, nil
	}
	argStart := p.i
	n, err := p.argument(ai)
	if err != nil {
		return nil, err
	}
	v.U = n
	switch kind {
	case 0, 1:
		// Negative integers retain their encoded (-1 - value) magnitude.
	case 2, 3:
		// A lying length is malformed, even when it also exceeds a ceiling.
		if n > uint64(len(p.b)-p.i) {
			return nil, ErrCBOR
		}
		if n >= MaxString {
			return nil, ErrLimit
		}
		v.B = p.b[p.i : p.i+int(n)]
		p.i += int(n)
		if kind == 3 && !utf8.Valid(v.B) {
			return nil, ErrCBOR
		}
	case 4:
		// Every encoded item needs at least one byte.
		if n > uint64(len(p.b)-p.i) {
			return nil, ErrCBOR
		}
		if n >= MaxContainer {
			return nil, ErrLimit
		}
		v.A = make([]*V, 0, int(n))
		for j := uint64(0); j < n; j++ {
			x, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v.A = append(v.A, x)
		}
	case 5:
		// Each map entry needs at least two bytes, avoiding n*2 overflow.
		if n > uint64((len(p.b)-p.i)/2) {
			return nil, ErrCBOR
		}
		if n >= MaxContainer {
			return nil, ErrLimit
		}
		v.M = make([]KV, 0, int(n))
		for j := uint64(0); j < n; j++ {
			k, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			x, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			v.M = append(v.M, KV{k, x})
		}
	case 6:
		v.Elem, err = p.value(depth + 1)
		if err != nil {
			return nil, err
		}
	case 7:
		if ai == 24 && n < 32 {
			return nil, ErrCBOR
		}
		if ai >= 25 && ai <= 27 {
			v.U = uint64(ai)
			v.B = p.b[argStart:p.i]
		}
	}
	v.End = p.i
	return v, nil
}

func (p *cborReader) indefinite(v *V, depth int) error {
	count := 0
	for {
		if p.i == len(p.b) {
			return ErrCBOR
		}
		if p.b[p.i] == 0xff {
			p.i++
			return nil
		}
		count++
		if count >= MaxContainer {
			return ErrLimit
		}
		switch v.Kind {
		case 2, 3:
			// An indefinite string consists only of definite chunks of its
			// own major type. UTF-8 is checked separately for each chunk.
			initial := p.b[p.i]
			if initial>>5 != v.Kind || initial&31 == 31 {
				return ErrCBOR
			}
			x, err := p.value(depth + 1)
			if err != nil {
				return err
			}
			if len(x.B) >= MaxString-len(v.B) {
				return ErrLimit
			}
			v.B = append(v.B, x.B...)
		case 4:
			x, err := p.value(depth + 1)
			if err != nil {
				return err
			}
			v.A = append(v.A, x)
		case 5:
			k, err := p.value(depth + 1)
			if err != nil {
				return err
			}
			// A break after a key is malformed, not an end-of-map marker.
			x, err := p.value(depth + 1)
			if err != nil {
				return err
			}
			v.M = append(v.M, KV{k, x})
		}
	}
}

func encHead(major byte, n uint64) []byte {
	if n < 24 {
		return []byte{major<<5 | byte(n)}
	}
	var ai byte
	var width int
	switch {
	case n <= 0xff:
		ai, width = 24, 1
	case n <= 0xffff:
		ai, width = 25, 2
	case n <= 0xffffffff:
		ai, width = 26, 4
	default:
		ai, width = 27, 8
	}
	b := make([]byte, width+1)
	b[0] = major<<5 | ai
	for i := width; i > 0; i-- {
		b[i] = byte(n)
		n >>= 8
	}
	return b
}

func encBstr(b []byte) []byte { return append(encHead(2, uint64(len(b))), b...) }

func encTstr(s string) []byte { return append(encHead(3, uint64(len(s))), []byte(s)...) }

func encArray(items ...[]byte) []byte {
	b := encHead(4, uint64(len(items)))
	for _, item := range items {
		b = append(b, item...)
	}
	return b
}

func encInt(n int64) []byte {
	if n >= 0 {
		return encHead(0, uint64(n))
	}
	return encHead(1, uint64(-(n + 1)))
}
