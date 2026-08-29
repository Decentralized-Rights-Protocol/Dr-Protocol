package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
)

type Signer struct {
	Private ed25519.PrivateKey
	Public ed25519.PublicKey
}

func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return nil, err }
	return &Signer{Private: priv, Public: pub}, nil
}

func (s *Signer) Sign(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.Private, data))
}

func Verify(pub ed25519.PublicKey, data []byte, encoded string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && ed25519.Verify(pub, data, sig)
}
