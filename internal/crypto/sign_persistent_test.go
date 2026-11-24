package crypto

import (
	"os"
	"path/filepath"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"testing"
)

func TestLoadOrCreateSignerKeepsIdentityAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node", "node-ed25519.key")
	first, err := LoadOrCreateSigner(path)
	if err != nil { t.Fatalf("create signer: %v", err) }
	second, err := LoadOrCreateSigner(path)
	if err != nil { t.Fatalf("reload signer: %v", err) }
	if first.PublicKeyString() != second.PublicKeyString() { t.Fatal("public identity changed after reload") }
	payload := []byte("DRP persistent identity test")
	if !Verify(second.Public, payload, first.Sign(payload)) { t.Fatal("reloaded key cannot verify signature from original key") }
	info, err := os.Stat(path)
	if err != nil { t.Fatalf("stat signer key: %v", err) }
	if info.Mode().Perm() != 0o600 { t.Fatalf("signer key permissions = %o, want 600", info.Mode().Perm()) }
}

func TestLoadOrCreateSignerRepairsExistingKeyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	if _, err := LoadOrCreateSigner(path); err != nil {
		t.Fatalf("create signer: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("make fixture permissive: %v", err)
	}
	if _, err := LoadOrCreateSigner(path); err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat signer key: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("signer key permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestDomainSeparatedSignaturesCannotCrossDomains(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	payload := []byte("same payload")
	signature := signer.SignDomain("drp/proof/v1", payload)
	if !VerifyDomain(signer.Public, "drp/proof/v1", payload, signature) {
		t.Fatal("signature did not verify in its intended domain")
	}
	if VerifyDomain(signer.Public, "drp/replication-envelope/v1", payload, signature) {
		t.Fatal("signature unexpectedly verified in a different domain")
	}
	if Verify(signer.Public, payload, signature) {
		t.Fatal("domain-separated signature unexpectedly verified without its domain")
	}
}

func TestProofSignatureCoversAllProofFields(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	proof := protocol.Proof{
		Version: protocol.Version,
		ID: "proof-1",
		ClaimDigest: "claim-digest",
		PolicyDigest: "policy-digest",
		EvidenceDigests: []string{"evidence-1"},
		Result: protocol.VerificationResult{Version: protocol.Version, ID: "result-1", ClaimID: "claim-1", Status: protocol.StatusVerified},
	}
	signed, err := SignProof(signer, proof)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	if !VerifyProof(signed, signer.PublicKeyString()) {
		t.Fatal("valid proof signature rejected")
	}
	signed.Result.Status = protocol.StatusDisputed
	if VerifyProof(signed, signer.PublicKeyString()) {
		t.Fatal("modified proof unexpectedly verified")
	}
	if VerifyProof(proof, base64.RawURLEncoding.EncodeToString(ed25519.PublicKey{})) {
		t.Fatal("invalid public key unexpectedly verified")
	}
}

func TestVerifyProofSupportsLegacyProofsWithoutSchemeField(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	proof := protocol.Proof{
		Version: protocol.Version,
		ID: "legacy-proof",
		ClaimDigest: "claim-digest",
		PolicyDigest: "policy-digest",
		EvidenceDigests: []string{"evidence-1"},
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal legacy proof: %v", err)
	}
	proof.Signature = signer.Sign(payload)
	if !VerifyProof(proof, signer.PublicKeyString()) {
		t.Fatal("legacy proof signature should remain verifiable")
	}
}
