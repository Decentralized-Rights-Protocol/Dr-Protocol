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

	chain, err := store.OpenChain(*chainPath)
	if err != nil { log.Fatalf("open chain storage: %v", err) }
	defer chain.Close()

	srv := network.New(store.New())
	if *validatorPath != "" {
		validators, err := loadValidators(*validatorPath)
		if err != nil { log.Fatalf("load validators: %v", err) }
		engine, err := consensus.New(validators)
		if err != nil { log.Fatalf("initialize consensus: %v", err) }
		if err := chain.ValidateChain(validators); err != nil { log.Fatalf("validate persisted chain: %v", err) }
		if tip, ok, err := chain.Tip(); err != nil {
			log.Fatalf("read chain tip: %v", err)
		} else if ok {
			if err := engine.RestoreCommitted(tip); err != nil { log.Fatalf("restore consensus tip: %v", err) }
		}
		srv.ConfigureConsensus(engine, validators, chain)
		log.Printf("DRP consensus enabled with %d validators; quorum=%d",len(validators),engine.Quorum())
	} else {
		log.Printf("DRP consensus API disabled: provide --validators with trusted validator public keys")
	}
	log.Printf("DRP Verification Network v0.2 listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
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
