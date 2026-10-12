package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func TestPersistentStoreSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node", "store.json")
	first, err := NewPersistent(path)
	if err != nil { t.Fatalf("create persistent store: %v", err) }

	createdAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	req := protocol.VerificationRequest{
		Version: protocol.Version, ID: "request-1",
		Claim: protocol.Claim{Version: protocol.Version, ID: "claim-1", Subject: "subject-1", Type: "community_activity", Statement: "participated in a tree planting", CreatedAt: createdAt},
		Evidence: []protocol.Evidence{{Version: protocol.Version, ID: "evidence-1", SourceID: "community-ledger", Type: "attestation", ContentHash: "sha256:example", CreatedAt: createdAt}},
		Policy: protocol.VerificationPolicy{Version: protocol.Version, ID: "policy-1", MinVerifiers: 2, MinEvidence: 1}, CreatedAt: createdAt,
	}
	if err := first.PutRequest(req); err != nil { t.Fatalf("persist request: %v", err) }
	proof := protocol.Proof{Version: protocol.Version, ID: "request-1:proof", ClaimDigest: "claim-digest", PolicyDigest: "policy-digest", EvidenceDigests: []string{"evidence-digest"}, CreatedAt: createdAt}
	if err := first.PutProof(proof); err != nil { t.Fatalf("persist proof: %v", err) }
	attestation := protocol.Attestation{Version: protocol.Version, ID: "attestation-1", VerifierID: "verifier-1", ClaimID: "claim-1", Decision: protocol.StatusVerified, Signature: "signature-placeholder", CreatedAt: createdAt}
	if err := first.PutAttestation(attestation); err != nil { t.Fatalf("persist attestation: %v", err) }

	second, err := NewPersistent(path)
	if err != nil { t.Fatalf("reopen persistent store: %v", err) }
	if got, ok := second.GetRequest(req.ID); !ok || got.Claim.ID != req.Claim.ID { t.Fatalf("request not restored: found=%v value=%+v", ok, got) }
	if got, ok := second.GetProof(proof.ID); !ok || got.ClaimDigest != proof.ClaimDigest { t.Fatalf("proof not restored: found=%v value=%+v", ok, got) }
	gotAttestations := second.GetAttestations(attestation.ClaimID)
	if len(gotAttestations) != 1 || gotAttestations[0].ID != attestation.ID { t.Fatalf("attestations not restored: %+v", gotAttestations) }
}

func TestPersistentStoreRejectsCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("not-json"), 0o600); err != nil { t.Fatal(err) }
	if _, err := NewPersistent(path); err == nil { t.Fatal("expected corrupt state to fail closed") }
}
