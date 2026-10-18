package network

import (
	"bytes"
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
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := New(store.New())
	s.Registry.Register(Verifier{
		ID: "verifier-pqc-2",
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
		Active: true,
	})
	a := protocol.Attestation{
		Version: "0.1",
		ID: "attestation-mismatch",
		VerifierID: "verifier-pqc-2",
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmEd25519,
		ClaimID: "claim-2",
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
	if rec.Code != 401 {
		t.Fatalf("expected 401 for algorithm mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
}


func TestPostQuantumAttestationRejectsMalformedSignatureLengthsWithoutStorage(t *testing.T) {
	publicKey, privateKey, err := pqc.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s := New(store.New())
	s.Registry.Register(Verifier{
		ID: "verifier-pqc-length",
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
		Active: true,
	})

	for _, tc := range []struct {
		name string
		mutate func([]byte) []byte
	}{
		{name: "appended byte", mutate: func(sig []byte) []byte { return append(append([]byte(nil), sig...), 0x00) }},
		{name: "truncated", mutate: func(sig []byte) []byte { return append([]byte(nil), sig[:len(sig)-1]...) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := protocol.Attestation{
				Version: "0.1",
				ID: "attestation-pqc-length-" + tc.name,
				VerifierID: "verifier-pqc-length",
				SignatureAlgorithm: drpcrypto.SignatureAlgorithmMLDSA44,
				ClaimID: "claim-pqc-length",
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
			a.Signature = base64.RawURLEncoding.EncodeToString(tc.mutate(signature))
			body, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/drp/v1/attestations", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != 401 {
				t.Fatalf("expected 401 for malformed ML-DSA signature, got %d: %s", rec.Code, rec.Body.String())
			}
			if got := s.Store.GetAttestations("claim-pqc-length"); len(got) != 0 {
				t.Fatalf("malformed signature was stored: %d attestations", len(got))
			}
		})
	}
}
