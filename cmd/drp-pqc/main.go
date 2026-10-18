// drp-pqc is a local testing utility for DRP's experimental ML-DSA-44 proof signatures.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
)

func usage() {
	fmt.Fprintln(os.Stderr, `DRP Post-Quantum Signature Utility

Usage:
  drp-pqc keygen <private-key-file> <public-key-file>
  drp-pqc sign   <private-key-file> <message-file> <signature-file>
  drp-pqc verify <public-key-file> <message-file> <signature-file>

Uses ML-DSA-44 (NIST FIPS 204) for post-quantum digital signatures.
This prototype signs exact file bytes; it does not yet integrate signatures into
network attestations, consensus, wallets, or blockchain transactions.`)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		usage()
		return nil
	}

	switch args[0] {
	case "keygen":
		if len(args) != 3 {
			return fmt.Errorf("usage: drp-pqc keygen <private-key-file> <public-key-file>")
		}
		privatePath, publicPath := args[1], args[2]
		if filepath.Clean(privatePath) == filepath.Clean(publicPath) {
			return fmt.Errorf("private and public key paths must be different")
		}
		publicKey, privateKey, err := pqc.GenerateKey()
		if err != nil {
			return err
		}
		if err := writeNew(privatePath, privateKey, 0o600); err != nil {
			return fmt.Errorf("write private key: %w", err)
		}
		if err := writeNew(publicPath, publicKey, 0o644); err != nil {
			_ = os.Remove(privatePath)
			return fmt.Errorf("write public key: %w", err)
		}
		fmt.Printf("Generated %s key pair\nPrivate key: %s (permissions 0600)\nPublic key:  %s\n", pqc.Algorithm, privatePath, publicPath)
		fmt.Println("Keep the private key secret and backed up. It cannot be recovered from the public key.")
		return nil

	case "sign":
		if len(args) != 4 {
			return fmt.Errorf("usage: drp-pqc sign <private-key-file> <message-file> <signature-file>")
		}
		privateKey, err := os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("read private key: %w", err)
		}
		message, err := os.ReadFile(args[2])
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}
		signature, err := pqc.Sign(privateKey, message)
		if err != nil {
			return fmt.Errorf("sign message: %w", err)
		}
		if err := writeNew(args[3], signature, 0o644); err != nil {
			return fmt.Errorf("write signature: %w", err)
		}
		fmt.Printf("Signed %s with %s; signature saved to %s\n", args[2], pqc.Algorithm, args[3])
		return nil

	case "verify":
		if len(args) != 4 {
			return fmt.Errorf("usage: drp-pqc verify <public-key-file> <message-file> <signature-file>")
		}
		publicKey, err := os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("read public key: %w", err)
		}
		message, err := os.ReadFile(args[2])
		if err != nil {
			return fmt.Errorf("read message: %w", err)
		}
		signature, err := os.ReadFile(args[3])
		if err != nil {
			return fmt.Errorf("read signature: %w", err)
		}
		valid, err := pqc.Verify(publicKey, message, signature)
		if err != nil {
			return fmt.Errorf("verify signature: %w", err)
		}
		if !valid {
			fmt.Println("INVALID: signature does not match this message and public key")
			return fmt.Errorf("invalid signature")
		}
		fmt.Printf("VALID: %s signature verified\n", pqc.Algorithm)
		return nil

	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "drp-pqc:", err)
		os.Exit(1)
	}
}
