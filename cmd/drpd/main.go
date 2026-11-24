package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/network"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func configuredSigner() (drpcrypto.ProofSigner, error) {
	publicPath := os.Getenv("DRP_PQC_PUBLIC_KEY_FILE")
	privatePath := os.Getenv("DRP_PQC_PRIVATE_KEY_FILE")
	if publicPath == "" && privatePath == "" {
		log.Printf("WARNING: using ephemeral Ed25519 node key; proofs will not remain verifiable after restart")
		return drpcrypto.NewSigner()
	}
	if publicPath == "" || privatePath == "" {
		return nil, fmt.Errorf("DRP_PQC_PUBLIC_KEY_FILE and DRP_PQC_PRIVATE_KEY_FILE must both be set")
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil { return nil, fmt.Errorf("stat private key: %w", err) }
	if privateInfo.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file permissions are too open; require owner-only permissions (0600)")
	}
	publicKey, err := os.ReadFile(publicPath)
	if err != nil { return nil, fmt.Errorf("read public key: %w", err) }
	privateKey, err := os.ReadFile(privatePath)
	if err != nil { return nil, fmt.Errorf("read private key: %w", err) }
	id := os.Getenv("DRP_NODE_ID")
	if id == "" { return nil, fmt.Errorf("DRP_NODE_ID is required when ML-DSA-44 proof signing is configured") }
	return drpcrypto.NewMLDSAProofSigner(id, publicKey, privateKey)
}

func main() {
	addr := flag.String("addr", ":8080", "HTTP gateway address")
	chainPath := flag.String("chain-db", "./data/drp-chain", "LevelDB directory for committed blocks")
	validatorPath := flag.String("validators", "", "JSON file mapping validator IDs to base64 Ed25519 public keys")
	flag.Parse()

	node := network.New(store.New())
	handler := network.NewReplicationHandler(node)
	log.Printf("DRP Verification Network v0.1 listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, handler))
}

func loadValidators(path string) (map[string]ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var encoded map[string]string
	if err := json.Unmarshal(raw,&encoded); err != nil { return nil, fmt.Errorf("validator file must be a JSON object of ID to base64 public key: %w",err) }
	validators := make(map[string]ed25519.PublicKey,len(encoded))
	for id, value := range encoded {
		key, err := base64.StdEncoding.DecodeString(value)
		if err != nil { return nil, fmt.Errorf("validator %q: decode public key: %w",id,err) }
		if len(key) != ed25519.PublicKeySize { return nil, fmt.Errorf("validator %q: expected %d-byte Ed25519 public key",id,ed25519.PublicKeySize) }
		validators[id] = ed25519.PublicKey(key)
	}
	if len(validators)==0 { return nil, fmt.Errorf("validator set cannot be empty") }
	return validators,nil
}
