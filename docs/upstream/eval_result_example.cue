// CUE constraints for the eval-result predicate (in-toto/attestation#565).
// Mirrors the field rules of spec/predicates/eval-result.md; usable as a policy
// starting point per the new-predicate guidelines.
package eval_result

#Digest: {
	alg:   string & !=""
	value: string & =~"^[0-9a-f]+$"
}

#SaltedCommitment: {
	alg:    string & !=""
	// a commitment (hash over secret salt || identifier), NOT an artifact digest
	value:  string & =~"^[0-9a-f]+$"
	salted: true
}

#Claim: {
	metric:     string & !=""
	comparator: ">=" | ">" | "<=" | "<"
	// decimal STRING, never a JSON float
	threshold: string & =~"^-?[0-9]+(\\.[0-9]+)?$"
	passed:    bool
}

#EvalResult: {
	verifier: id: string & !=""
	evaluatedAt: string // RFC 3339
	suite: {
		name:     string & !=""
		version?: string
	}
	claims: [#Claim, ...#Claim]
	sampleSize: int & >=0
	commitments: {
		model:   #SaltedCommitment
		dataset: #SaltedCommitment
	}
	assuranceLevel: "self_attested" | "third_party" | "reproduced" | "enclave_attested"
	subjectProfile: "receipt" | "public-model" | "release-gate"
	preRegistration?: #Digest
	receipt?: {
		schema:        string & !=""
		merkleRootB64: string & !=""
	}
	harness?: {
		name:     string & !=""
		version?: string
	}
	anchors?: [...]
}

predicate: #EvalResult
