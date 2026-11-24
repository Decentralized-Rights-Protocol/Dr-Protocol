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

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/consensus"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/network"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP gateway address")
	chainPath := flag.String("chain-db", "./data/drp-chain", "LevelDB directory for committed blocks")
	validatorPath := flag.String("validators", "", "JSON file mapping validator IDs to base64 Ed25519 public keys")
	flag.Parse()

	persistentStore, err := store.NewPersistent(filepath.Join(*dataDir, "store.json"))
	if err != nil { log.Fatalf("open DRP persistent store: %v", err) }
	signer, err := drpcrypto.LoadOrCreateSigner(filepath.Join(*dataDir, "node-ed25519.key"))
	if err != nil { log.Fatalf("load DRP node identity: %v", err) }

	node := network.NewWithSigner(persistentStore, signer)
	handler := network.NewReplicationHandler(node)
	log.Printf("DRP Verification Network v0.1 listening on %s (data dir: %s)", *addr, *dataDir)
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
