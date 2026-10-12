package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/network"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP gateway address")
	dataDir := flag.String("data-dir", "./data", "directory for persistent DRP node state and identity key")
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
