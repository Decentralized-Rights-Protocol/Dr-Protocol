package network

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

const proofRequestJSON = `{"version":"0.1","id":"proof-signature-test","claim":{"version":"0.1","id":"claim-proof-test","subject":"alice","type":"activity","statement":"completed activity"},"evidence":[{"version":"0.1","id":"evidence-proof-test","sourceId":"test","type":"attestation","contentHash":"abc"}],"policy":{"version":"0.1","id":"policy-proof-test","minVerifiers":1,"minEvidence":1}}`

func postProofForTest(t *testing.T, s *Server) protocol.Proof {
	t.Helper()
	req := httptest.NewRequest("POST", "/drp/v1/verify", strings.NewReader(proofRequestJSON))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 202 { t.Fatalf("verify returned %d: %s", rec.Code, rec.Body.String()) }
	var response struct { Proof protocol.Proof `json:"proof"` }
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil { t.Fatal(err) }
	return response.Proof
}

func verifyProofEndpoint(t *testing.T, s *Server, proofID string) map[string]any {
	t.Helper()
	req := httptest.NewRequest("GET", "/drp/v1/proofs/"+proofID+"/verify", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 { t.Fatalf("proof verify returned %d: %s", rec.Code, rec.Body.String()) }
	var result map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil { t.Fatal(err) }
	return result
}

func TestProofVerificationEndpointEd25519(t *testing.T) {
	signer, err := drpcrypto.NewSigner()
	if err != nil { t.Fatal(err) }
	s := NewWithProofSigner(store.New(), signer)
	proof := postProofForTest(t, s)
	if proof.SignatureAlgorithm != drpcrypto.SignatureAlgorithmEd25519 || proof.SignerID != signer.SignerID() {
		t.Fatalf("unexpected proof signature metadata: %#v", proof)
	}
	if result := verifyProofEndpoint(t, s, proof.ID); result["valid"] != true || result["trustedSigner"] != true {
		t.Fatalf("expected valid trusted Ed25519 proof, got %#v", result)
	}
	proof.ClaimDigest = "tampered"
	s.Store.PutProof(proof)
	if result := verifyProofEndpoint(t, s, proof.ID); result["valid"] != false {
		t.Fatalf("tampered proof was accepted: %#v", result)
	}
}

func TestProofVerificationEndpointMLDSA44(t *testing.T) {
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil { t.Fatal(err) }
	signer, err := drpcrypto.NewMLDSAProofSigner("test-node-pqc", publicKey, privateKey)
	if err != nil { t.Fatal(err) }
	s := NewWithProofSigner(store.New(), signer)
	proof := postProofForTest(t, s)
	if proof.SignatureAlgorithm != drpcrypto.SignatureAlgorithmMLDSA44 || proof.SignerID != "test-node-pqc" {
		t.Fatalf("unexpected proof signature metadata: %#v", proof)
	}
	if result := verifyProofEndpoint(t, s, proof.ID); result["valid"] != true || result["trustedSigner"] != true {
		t.Fatalf("expected valid trusted ML-DSA-44 proof, got %#v", result)
	}
	proof.Result.Status = protocol.StatusRevoked
	s.Store.PutProof(proof)
	if result := verifyProofEndpoint(t, s, proof.ID); result["valid"] != false {
		t.Fatalf("tampered ML-DSA-44 proof was accepted: %#v", result)
	}
}

func TestProofVerificationRejectsUnknownSigner(t *testing.T) {
	signer, err := drpcrypto.NewSigner()
	if err != nil { t.Fatal(err) }
	s := NewWithProofSigner(store.New(), signer)
	proof := postProofForTest(t, s)
	proof.SignerID = "untrusted-node"
	s.Store.PutProof(proof)
	result := verifyProofEndpoint(t, s, proof.ID)
	if result["valid"] != false || result["trustedSigner"] != false {
		t.Fatalf("proof with untrusted signer identity was accepted: %#v", result)
	}
}
