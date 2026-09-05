// Echtes Differential gegen die REFERENZ: golang.org/x/mod/sumdb/note.Open.
//
// Liest cases.json ({"vkey": "...", "cases":[{"id":"...","b64":"..."}]}), ruft fuer jeden Fall
// note.Open mit genau EINEM bekannten Verifizierer (dem Log-Schluessel, Ed25519/0x01) auf und gibt
// je Fall eine Zeile "id\tACCEPT|REJECT\tgrund" aus. err==nil bei note.Open heisst: die Rahmung ist
// kanonisch UND mindestens eine Signatur eines BEKANNTEN Schluessels verifiziert — dasselbe
// Praedikat wie proofbundle.verify_checkpoint(...)["ok"] is True.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/note"
)

type Fall struct {
	ID  string `json:"id"`
	B64 string `json:"b64"`
}

type Eingabe struct {
	Vkey  string `json:"vkey"`
	Cases []Fall `json:"cases"`
}

func main() {
	roh, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "cases.json:", err)
		os.Exit(2)
	}
	var ein Eingabe
	if err := json.Unmarshal(roh, &ein); err != nil {
		fmt.Fprintln(os.Stderr, "json:", err)
		os.Exit(2)
	}
	v, err := note.NewVerifier(ein.Vkey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "note.NewVerifier:", err)
		os.Exit(2)
	}
	known := note.VerifierList(v)

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()

	for _, f := range ein.Cases {
		msg, derr := base64.StdEncoding.DecodeString(f.B64)
		if derr != nil {
			fmt.Fprintf(w, "%s\tERROR\tbase64: %v\n", f.ID, derr)
			continue
		}
		_, oerr := note.Open(msg, known)
		if oerr == nil {
			fmt.Fprintf(w, "%s\tACCEPT\t-\n", f.ID)
		} else {
			fmt.Fprintf(w, "%s\tREJECT\t%v\n", f.ID, oerr)
		}
	}
}
