package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Signer struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

func NewSigner() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return nil, err }
	return &Signer{Private: priv, Public: pub}, nil
}

// LoadOrCreateSigner keeps a node's Ed25519 identity stable across restarts.
// The private key is stored in a raw 0600 file and must never be committed.
func LoadOrCreateSigner(path string) (*Signer, error) {
	if path == "" { return nil, errors.New("signer key path is required") }
	absolutePath, err := filepath.Abs(path)
	if err != nil { return nil, fmt.Errorf("resolve signer path: %w", err) }
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil { return nil, fmt.Errorf("create signer directory: %w", err) }
	privateKey, err := os.ReadFile(absolutePath)
	if err == nil {
		if len(privateKey) != ed25519.PrivateKeySize { return nil, fmt.Errorf("invalid signer key length: got %d bytes", len(privateKey)) }
		// Existing keys may predate restrictive permissions; repair them before use.
		if err := os.Chmod(absolutePath, 0o600); err != nil { return nil, fmt.Errorf("secure existing signer key permissions: %w", err) }
		priv := ed25519.PrivateKey(append([]byte(nil), privateKey...))
		pub := append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
		return &Signer{Private: priv, Public: pub}, nil
	}
	if !errors.Is(err, os.ErrNotExist) { return nil, fmt.Errorf("read signer key: %w", err) }
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { return nil, fmt.Errorf("generate signer key: %w", err) }
	file, err := os.OpenFile(absolutePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) { return LoadOrCreateSigner(absolutePath) }
	if err != nil { return nil, fmt.Errorf("create signer key: %w", err) }
	if _, err := file.Write(priv); err != nil { _ = file.Close(); _ = os.Remove(absolutePath); return nil, fmt.Errorf("write signer key: %w", err) }
	if err := file.Sync(); err != nil { _ = file.Close(); _ = os.Remove(absolutePath); return nil, fmt.Errorf("sync signer key: %w", err) }
	if err := file.Close(); err != nil { _ = os.Remove(absolutePath); return nil, fmt.Errorf("close signer key: %w", err) }
	return &Signer{Private: priv, Public: pub}, nil
}

func (s *Signer) Sign(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.Private, data))
}

func Verify(pub ed25519.PublicKey, data []byte, encoded string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && ed25519.Verify(pub, data, sig)
}


// SignDomain signs a payload with an explicit protocol purpose. The prefix is
// versioned and NUL-delimited so signatures cannot be reused across DRP domains.
func (s *Signer) SignDomain(domain string, data []byte) string {
	return s.Sign(domainSeparatedPayload(domain, data))
}

// VerifyDomain verifies a signature over a domain-separated payload.
func VerifyDomain(pub ed25519.PublicKey, domain string, data []byte, encoded string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && ed25519.Verify(pub, domainSeparatedPayload(domain, data), sig)
}

func domainSeparatedPayload(domain string, data []byte) []byte {
	prefix := []byte("DRP-SIGNATURE-V1\x00" + domain + "\x00")
	return append(prefix, data...)
}
