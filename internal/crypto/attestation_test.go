package crypto

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func TestVerifyMLDSAAttestation(t *testing.T) {
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	a := protocol.Attestation{
		Version: "0.1",
		ID: "attestation-pqc-1",
		VerifierID: "verifier-pqc-1",
		SignatureAlgorithm: SignatureAlgorithmMLDSA44,
		ClaimID: "claim-1",
		Decision: protocol.StatusVerified,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	payload, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := pqc.Sign(privateKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(signature)
	publicKeyString := base64.RawURLEncoding.EncodeToString(publicKey)
	if !VerifyAttestation(a, publicKeyString) {
		t.Fatal("VerifyAttestation rejected a valid ML-DSA-44 attestation")
	}
	a.Decision = protocol.StatusRevoked
	if VerifyAttestation(a, publicKeyString) {
		t.Fatal("VerifyAttestation accepted a modified ML-DSA-44 attestation")
	}
}

func TestVerifyAttestationRejectsUnknownAlgorithm(t *testing.T) {
	a := protocol.Attestation{SignatureAlgorithm: "UNKNOWN", Signature: "c2ln"}
	if VerifyAttestation(a, "cHVi") {
		t.Fatal("VerifyAttestation accepted an unknown signature algorithm")
	}
}
