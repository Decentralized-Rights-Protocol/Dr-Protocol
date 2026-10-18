package network

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func TestPostQuantumAttestationAcceptedForRegisteredVerifier(t *testing.T) {
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := New(store.New())
	s.Registry.Register(Verifier{
		ID: "verifier-pqc-1",
		Name: "PQC test verifier",
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
		Active: true,
	})

	a := protocol.Attestation{
		Version: "0.1",
		ID: "attestation-pqc-1",
		VerifierID: "verifier-pqc-1",
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
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
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/drp/v1/attestations", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 201 {
		t.Fatalf("expected 201 for valid ML-DSA attestation, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.Store.GetAttestations("claim-1"); len(got) != 1 {
		t.Fatalf("expected one stored attestation, got %d", len(got))
	}
}

func TestPostQuantumAttestationAlgorithmMustMatchRegistry(t *testing.T) {
	pqcPublicKey, _, err := pqc.GenerateKey()
	if err != nil { t.Fatal(err) }
	// Construct a genuinely valid Ed25519 envelope while registering this verifier
	// for ML-DSA-44. This proves the registry mismatch guard itself is exercised.
	edPublicKey, edPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	s := New(store.New())
	s.Registry.Register(Verifier{
		ID: "verifier-pqc-2",
		PublicKey: base64.RawURLEncoding.EncodeToString(pqcPublicKey),
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
		Active: true,
	})
	a := protocol.Attestation{
		Version: "0.1", ID: "attestation-mismatch", VerifierID: "verifier-pqc-2",
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmEd25519, ClaimID: "claim-2",
		Decision: protocol.StatusVerified,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	payload, err := json.Marshal(a)
	if err != nil { t.Fatal(err) }
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(edPrivateKey, payload))
	body, err := json.Marshal(a)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest("POST", "/drp/v1/attestations", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for algorithm mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.Store.GetAttestations("claim-2"); len(got) != 0 {
		t.Fatalf("algorithm-mismatched attestation was stored: %d", len(got))
	}
}

func TestPostQuantumAttestationRejectsMalleableSignatureWithoutStorage(t *testing.T) {
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil { t.Fatal(err) }
	s := New(store.New())
	s.Registry.Register(Verifier{
		ID: "verifier-pqc-malformed",
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
		Active: true,
	})
	a := protocol.Attestation{
		Version: "0.1", ID: "attestation-appended-byte", VerifierID: "verifier-pqc-malformed",
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44, ClaimID: "claim-malformed",
		Decision: protocol.StatusVerified,
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	payload, err := json.Marshal(a)
	if err != nil { t.Fatal(err) }
	signature, err := pqc.Sign(privateKey, payload)
	if err != nil { t.Fatal(err) }
	signature = append(signature, 0x00)
	a.Signature = base64.RawURLEncoding.EncodeToString(signature)
	body, err := json.Marshal(a)
	if err != nil { t.Fatal(err) }
	req := httptest.NewRequest("POST", "/drp/v1/attestations", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("expected 401 for appended signature byte, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := s.Store.GetAttestations("claim-malformed"); len(got) != 0 {
		t.Fatalf("invalid attestation was stored: %d", len(got))
	}
}
