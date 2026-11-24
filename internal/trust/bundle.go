// Package trust verifies DRP proofs against independently provisioned trusted node keys.
package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

type Key struct {
	SignerID string `json:"signerId"`
	KeyID string `json:"keyId"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"`
	Revoked bool `json:"revoked,omitempty"`
	NotBefore string `json:"notBefore,omitempty"`
	NotAfter string `json:"notAfter,omitempty"`
}

type Bundle struct {
	Version string `json:"version"`
	Keys []Key `json:"keys"`
}

func LoadBundle(path string) (Bundle, error) {
	var b Bundle
	raw, err := os.ReadFile(path)
	if err != nil { return b, err }
	if err := json.Unmarshal(raw, &b); err != nil { return b, fmt.Errorf("decode trust bundle: %w", err) }
	if b.Version != "1" { return b, fmt.Errorf("unsupported trust bundle version %q", b.Version) }
	if len(b.Keys) == 0 { return b, errors.New("trust bundle contains no trusted keys") }
	return b, nil
}

func KeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

// VerifyProof checks signature, signer ID, algorithm, key fingerprint, revocation,
// and optional validity window. Trust bundles must be delivered out-of-band and
// protected by an independent administrative process.
func VerifyProof(p protocol.Proof, b Bundle, now time.Time) error {
	if p.ID == "" || p.Signature == "" || p.SignerID == "" || p.SignerKeyID == "" || p.SignatureAlgorithm == "" {
		return errors.New("proof is missing required signature metadata")
	}
	for _, k := range b.Keys {
		if k.SignerID != p.SignerID || k.KeyID != p.SignerKeyID || k.Algorithm != p.SignatureAlgorithm { continue }
		if k.Revoked { return errors.New("signing key is revoked") }
		if k.NotBefore != "" {
			t, err := time.Parse(time.RFC3339, k.NotBefore); if err != nil { return errors.New("invalid trust key notBefore") }
			if now.Before(t) { return errors.New("signing key is not yet valid") }
		}
		if k.NotAfter != "" {
			t, err := time.Parse(time.RFC3339, k.NotAfter); if err != nil { return errors.New("invalid trust key notAfter") }
			if now.After(t) { return errors.New("signing key has expired") }
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
		if err != nil { return errors.New("invalid base64url public key in trust bundle") }
		if KeyID(pub) != k.KeyID { return errors.New("trust bundle key fingerprint does not match public key") }
		payload, err := protocol.ProofSigningBytes(p)
		if err != nil { return err }
		sig, err := base64.RawURLEncoding.DecodeString(p.Signature)
		if err != nil { return errors.New("invalid base64url proof signature") }
		switch k.Algorithm {
		case drpcrypto.SignatureAlgorithmEd25519:
			if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
				return errors.New("invalid Ed25519 proof signature")
			}
		case drpcrypto.SignatureAlgorithmMLDSA44:
			valid, err := pqc.Verify(pub, payload, sig)
			if err != nil { return fmt.Errorf("invalid ML-DSA-44 proof: %w", err) }
			if !valid { return errors.New("invalid ML-DSA-44 proof signature") }
		default:
			return fmt.Errorf("unsupported proof signature algorithm %q", k.Algorithm)
		}
		return nil
	}
	return errors.New("no trusted, non-revoked key matches proof signer, key ID, and algorithm")
}
