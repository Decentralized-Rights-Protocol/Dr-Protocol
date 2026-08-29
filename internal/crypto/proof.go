package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func (s *Signer) PublicKeyString() string { return base64.RawURLEncoding.EncodeToString(s.Public) }

func VerifyProof(p protocol.Proof, publicKey string) bool {
	pub, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize { return false }
	sig, err := base64.RawURLEncoding.DecodeString(p.Signature)
	if err != nil { return false }
	p.Signature = ""
	payload, err := json.Marshal(p)
	if err != nil { return false }
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}
