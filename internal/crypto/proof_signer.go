package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
)

// ProofSigner signs and verifies versioned proof payloads. The configured public
// key is the trust anchor; a proof must never be trusted solely because it
// supplies its own key.
type ProofSigner interface {
	Algorithm() string
	SignerID() string
	PublicKeyEncoded() string
	KeyID() string
	SignProof(payload []byte) (string, error)
	VerifyProof(payload []byte, signature string) bool
}

type MLDSAProofSigner struct {
	id string
	publicKey []byte
	privateKey []byte
}

// NewMLDSAProofSigner creates a node proof signer from provisioned key bytes.
// Callers should load private keys from a protected, persistent secret store.
func NewMLDSAProofSigner(id string, publicKey, privateKey []byte) (*MLDSAProofSigner, error) {
	if id == "" || len(publicKey) == 0 || len(privateKey) == 0 {
		return nil, errors.New("signer ID, public key, and private key are required")
	}
	// Sign and verify a challenge to validate both encodings and ensure the keys match.
	sig, err := pqc.Sign(privateKey, []byte("DRP proof signer key validation"))
	if err != nil {
		return nil, err
	}
	valid, err := pqc.Verify(publicKey, []byte("DRP proof signer key validation"), sig)
	if err != nil || !valid {
		return nil, errors.New("ML-DSA-44 public and private keys do not match")
	}
	return &MLDSAProofSigner{id: id, publicKey: append([]byte(nil), publicKey...), privateKey: append([]byte(nil), privateKey...)}, nil
}

func (s *MLDSAProofSigner) Algorithm() string { return SignatureAlgorithmMLDSA44 }
func (s *MLDSAProofSigner) SignerID() string { return s.id }
func (s *MLDSAProofSigner) PublicKeyEncoded() string { return base64.RawURLEncoding.EncodeToString(s.publicKey) }
func (s *MLDSAProofSigner) KeyID() string { sum := sha256.Sum256(s.publicKey); return hex.EncodeToString(sum[:]) }
func (s *MLDSAProofSigner) SignProof(payload []byte) (string, error) {
	sig, err := pqc.Sign(s.privateKey, payload)
	if err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(sig), nil
}
func (s *MLDSAProofSigner) VerifyProof(payload []byte, signature string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil { return false }
	valid, err := pqc.Verify(s.publicKey, payload, sig)
	return err == nil && valid
}
