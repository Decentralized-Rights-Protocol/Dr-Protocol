package crypto

import (
	"os"
	"path/filepath"
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
