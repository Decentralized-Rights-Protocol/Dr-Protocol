package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

const proofSignatureDomain = "drp/proof/v1"

func (s *Signer) PublicKeyString() string {
	return base64.RawURLEncoding.EncodeToString(s.Public)
}

// SignProof signs the deterministic JSON representation of a proof with its
// Signature field cleared. The purpose-specific domain prevents the same
// signature from being accepted as a different kind of DRP message.
func SignProof(s *Signer, p protocol.Proof) (protocol.Proof, error) {
	p.Signature = ""
	payload, err := json.Marshal(p)
	if err != nil {
		return protocol.Proof{}, err
	}
	p.Signature = s.SignDomain(proofSignatureDomain, payload)
	return p, nil
}

func VerifyProof(p protocol.Proof, publicKey string) bool {
	pub, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	signature := p.Signature
	p.Signature = ""
	payload, err := json.Marshal(p)
	if err != nil {
		return false
	}
	return VerifyDomain(ed25519.PublicKey(pub), proofSignatureDomain, payload, signature)
}
