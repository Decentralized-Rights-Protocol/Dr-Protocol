// Package pqc provides DRP's experimental post-quantum proof-signing primitives.
package pqc

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

const (
	// Algorithm is the standardized post-quantum signature algorithm used here.
	Algorithm = "ML-DSA-44"
	// Context domain-separates DRP proof signatures from signatures used elsewhere.
	Context = "DRP-POAT-PROOF-v1"
)

// GenerateKey creates an ML-DSA-44 key pair and returns the public and private
// keys in the binary encoding provided by CIRCL. Keep the private key secret.
func GenerateKey() (publicKey, privateKey []byte, err error) {
	public, private, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err = public.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	privateKey, err = private.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// Sign signs the exact message bytes with an ML-DSA-44 private key.
// Callers should serialize proof data canonically before signing it.
func Sign(privateKey, message []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("private key is empty")
	}
	var private mldsa44.PrivateKey
	if err := private.UnmarshalBinary(privateKey); err != nil {
		return nil, errors.New("invalid ML-DSA-44 private key")
	}
	signature := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(&private, message, []byte(Context), true, signature); err != nil {
		return nil, err
	}
	return signature, nil
}

// Verify checks a signature over the exact message bytes. It rejects non-canonical
// signature lengths before calling the crypto library, preventing trailing-byte
// malleability. It returns an error for malformed public keys and valid=false for
// a well-formed key with a bad signature.
func Verify(publicKey, message, signature []byte) (valid bool, err error) {
	if len(publicKey) == 0 {
		return false, errors.New("public key is empty")
	}
	if len(signature) != mldsa44.SignatureSize {
		return false, fmt.Errorf("invalid ML-DSA-44 signature length: got %d, want %d", len(signature), mldsa44.SignatureSize)
	}
	var public mldsa44.PublicKey
	if err := public.UnmarshalBinary(publicKey); err != nil {
		return false, errors.New("invalid ML-DSA-44 public key")
	}
	return mldsa44.Verify(&public, message, []byte(Context), signature), nil
}
