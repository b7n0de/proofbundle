// Command z225probe reads proofbundle's DSSE-wrapped in-toto attestations with two foreign Go
// libraries and prints one JSON object per envelope. It trusts nothing: the Ed25519 public key it
// verifies against is the test key the inputs were made with.
//
//   - DSSE: github.com/secure-systems-lab/go-securesystemslib/dsse, the reference implementation of
//     the DSSE authors. The Ed25519 arithmetic is Go's crypto/ed25519.
//   - Statement: github.com/in-toto/attestation/go/v1, the protobuf binding of the in-toto
//     attestation framework, parsed with protojson once strictly (its default) and once with
//     DiscardUnknown, then Statement.Validate().
//
// Usage: z225probe <public key, base64 of 32 raw bytes> <envelope.json>...
package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
)

type edVerifier struct{ pub ed25519.PublicKey }

func (v edVerifier) Verify(_ context.Context, data, sig []byte) error {
	if ed25519.Verify(v.pub, data, sig) {
		return nil
	}
	return errors.New("ed25519: signature does not verify")
}

func (v edVerifier) KeyID() (string, error)   { return "", nil }
func (v edVerifier) Public() crypto.PublicKey { return v.pub }

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type result struct {
	File              string    `json:"file"`
	PayloadType       string    `json:"payload_type"`
	DSSEVerified      bool      `json:"dsse_verified"`
	DSSEError         string    `json:"dsse_error,omitempty"`
	StrictParseError  string    `json:"statement_strict_parse_error,omitempty"`
	LenientParseError string    `json:"statement_lenient_parse_error,omitempty"`
	ValidateError     string    `json:"statement_validate_error,omitempty"`
	StatementType     string    `json:"statement_type,omitempty"`
	PredicateType     string    `json:"predicate_type,omitempty"`
	Subjects          []subject `json:"subjects,omitempty"`
	PredicateKeys     []string  `json:"predicate_keys,omitempty"`
}

func probe(pub ed25519.PublicKey, path string) result {
	r := result{File: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		r.DSSEError = err.Error()
		return r
	}
	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		r.DSSEError = "envelope: " + err.Error()
		return r
	}
	r.PayloadType = env.PayloadType
	ev, err := dsse.NewEnvelopeVerifier(edVerifier{pub})
	if err != nil {
		r.DSSEError = err.Error()
		return r
	}
	accepted, body, err := ev.VerifyAndDecode(context.Background(), &env)
	if err != nil {
		r.DSSEError = err.Error()
	}
	r.DSSEVerified = err == nil && len(accepted) > 0
	if body == nil {
		if body, err = env.DecodeB64Payload(); err != nil {
			return r
		}
	}
	var strict v1.Statement
	if err := protojson.Unmarshal(body, &strict); err != nil {
		r.StrictParseError = err.Error()
	}
	var st v1.Statement
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &st); err != nil {
		r.LenientParseError = err.Error()
		return r
	}
	if err := st.Validate(); err != nil {
		r.ValidateError = err.Error()
	}
	r.StatementType = st.GetType()
	r.PredicateType = st.GetPredicateType()
	for _, s := range st.GetSubject() {
		r.Subjects = append(r.Subjects, subject{Name: s.GetName(), Digest: s.GetDigest()})
	}
	for k := range st.GetPredicate().GetFields() {
		r.PredicateKeys = append(r.PredicateKeys, k)
	}
	sort.Strings(r.PredicateKeys)
	return r
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: z225probe <pubkey-b64> <envelope.json>...")
		os.Exit(2)
	}
	key, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil || len(key) != ed25519.PublicKeySize {
		fmt.Fprintln(os.Stderr, "the public key is not base64 of 32 bytes")
		os.Exit(2)
	}
	out := json.NewEncoder(os.Stdout)
	for _, path := range os.Args[2:] {
		if err := out.Encode(probe(ed25519.PublicKey(key), path)); err != nil {
			os.Exit(1)
		}
	}
}
