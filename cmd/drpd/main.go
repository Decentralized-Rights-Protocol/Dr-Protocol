package main

import (
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
	flag.Parse()
	signer, err := configuredSigner()
	if err != nil { log.Fatalf("configure proof signer: %v", err) }
	srv := network.NewWithProofSigner(store.New(), signer)
	log.Printf("DRP Verification Network v0.1 listening on %s (proof signer: %s / %s)", *addr, signer.SignerID(), signer.Algorithm())
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
