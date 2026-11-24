package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
)

const (
	SignatureAlgorithmEd25519 = "Ed25519"
	SignatureAlgorithmMLDSA44 = pqc.Algorithm
)

// VerifyAttestation verifies the attestation using the algorithm declared in
// the signed envelope. An omitted algorithm retains legacy Ed25519 behavior.
func VerifyAttestation(a protocol.Attestation, publicKey string) bool {
	algorithm := a.SignatureAlgorithm
	if algorithm == "" {
		algorithm = SignatureAlgorithmEd25519
	}
	pub, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(a.Signature)
	if err != nil {
		return false
	}
	a.Signature = ""
	payload, err := json.Marshal(a)
	if err != nil {
		return false
	}

	switch algorithm {
	case SignatureAlgorithmEd25519:
		if len(pub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
	case SignatureAlgorithmMLDSA44:
		valid, verifyErr := pqc.Verify(pub, payload, sig)
		return verifyErr == nil && valid
	default:
		return false
	}
}
