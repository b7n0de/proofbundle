// RFC 9162 consistency proofs from github.com/transparency-dev/merkle (testonly.Tree, proof.VerifyConsistency),
// with CCF's hashing: children hashed as SHA-256(l || r) without prefixes, leaves given already hashed.
// Reads {"leaves": [hex], "pairs": [[m, n]], "claims": [{"m","n","root_m","root_n","proof":[hex]}]} on stdin;
// driven and built by consistency_probe.py (build_oracle), never on its own.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/testonly"
)

type ccf struct{}

func (ccf) EmptyRoot() []byte          { h := sha256.Sum256(nil); return h[:] }
func (ccf) HashLeaf(b []byte) []byte   { h := sha256.Sum256(b); return h[:] }
func (ccf) HashChildren(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte{}, l...), r...))
	return h[:]
}
func (ccf) Size() int { return 32 }

func main() {
	var in struct {
		Leaves []string    `json:"leaves"`
		Pairs  [][2]uint64 `json:"pairs"`
		Claims []struct {
			M     uint64   `json:"m"`
			N     uint64   `json:"n"`
			RootM string   `json:"root_m"`
			RootN string   `json:"root_n"`
			Proof []string `json:"proof"`
		} `json:"claims"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		panic(err)
	}
	t := testonly.New(ccf{})
	for _, l := range in.Leaves {
		b, _ := hex.DecodeString(l)
		t.Append(b)
	}
	type row struct {
		M, N   uint64
		Proof  []string `json:"proof"`
		RootM  string   `json:"root_m"`
		RootN  string   `json:"root_n"`
		Verify string   `json:"verify_consistency"`
	}
	out := struct {
		Rows   []row    `json:"rows"`
		Claims []string `json:"claims"`
	}{}
	for _, p := range in.Pairs {
		pr, err := t.ConsistencyProof(p[0], p[1])
		if err != nil {
			panic(err)
		}
		r := row{M: p[0], N: p[1], RootM: hex.EncodeToString(t.HashAt(p[0])), RootN: hex.EncodeToString(t.HashAt(p[1]))}
		for _, h := range pr {
			r.Proof = append(r.Proof, hex.EncodeToString(h))
		}
		r.Verify = "ok"
		if err := proof.VerifyConsistency(ccf{}, p[0], p[1], pr, t.HashAt(p[0]), t.HashAt(p[1])); err != nil {
			r.Verify = err.Error()
		}
		out.Rows = append(out.Rows, r)
	}
	for _, c := range in.Claims {
		var pr [][]byte
		for _, h := range c.Proof {
			b, _ := hex.DecodeString(h)
			pr = append(pr, b)
		}
		rm, _ := hex.DecodeString(c.RootM)
		rn, _ := hex.DecodeString(c.RootN)
		res := "ok"
		if err := proof.VerifyConsistency(ccf{}, c.M, c.N, pr, rm, rn); err != nil {
			res = err.Error()
		}
		out.Claims = append(out.Claims, res)
	}
	json.NewEncoder(os.Stdout).Encode(out)
}
