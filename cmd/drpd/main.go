package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/network"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP gateway address")
	flag.Parse()
	srv := network.New(store.New())
	log.Printf("DRP Verification Network v0.1 listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, srv.Handler()))
}
