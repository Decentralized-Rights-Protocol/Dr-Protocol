package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/trust"
)

func main() {
	if len(os.Args) != 3 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		fmt.Fprintln(os.Stderr, "Usage: drp-proof-verify <proof.json> <trusted-keys.json>")
		fmt.Fprintln(os.Stderr, "Verifies a proof against an independently provisioned DRP trusted-key bundle.")
		if len(os.Args) == 3 { os.Exit(0) }
		os.Exit(2)
	}
	proofBytes, err := os.ReadFile(os.Args[1])
	if err != nil { fatal(err) }
	var proof protocol.Proof
	if err := json.Unmarshal(proofBytes, &proof); err != nil { fatal(fmt.Errorf("decode proof: %w", err)) }
	bundle, err := trust.LoadBundle(os.Args[2])
	if err != nil { fatal(err) }
	if err := trust.VerifyProof(proof, bundle, time.Now().UTC()); err != nil {
		fmt.Printf("INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("VALID: proof %s signed by trusted node %s using %s (key %s)\n", proof.ID, proof.SignerID, proof.SignatureAlgorithm, proof.SignerKeyID)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "drp-proof-verify:", err)
	os.Exit(2)
}
