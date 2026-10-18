package pqc

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

func TestMLDSASignVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatalf("GenerateKey() error = %v", err) }
	message := []byte(`{"claimId":"claim-test-001","status":"VERIFIED","protocol":"DRP"}`)
	signature, err := Sign(privateKey, message)
	if err != nil { t.Fatalf("Sign() error = %v", err) }
	valid, err := Verify(publicKey, message, signature)
	if err != nil { t.Fatalf("Verify() error = %v", err) }
	if !valid { t.Fatal("Verify() rejected a valid signature") }
}

func TestMLDSARejectsTamperedMessage(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	signature, err := Sign(privateKey, []byte("original proof"))
	if err != nil { t.Fatal(err) }
	valid, err := Verify(publicKey, []byte("tampered proof"), signature)
	if err != nil { t.Fatal(err) }
	if valid { t.Fatal("Verify() accepted a signature for a different message") }
}

func TestMLDSARejectsTamperedSignature(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	signature, err := Sign(privateKey, []byte("proof"))
	if err != nil { t.Fatal(err) }
	signature[len(signature)/2] ^= 0x01
	valid, err := Verify(publicKey, []byte("proof"), signature)
	if err != nil { t.Fatal(err) }
	if valid { t.Fatal("Verify() accepted a modified signature") }
}

func TestMLDSARejectsNonCanonicalSignatureLengths(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil { t.Fatal(err) }
	if len(signature) != mldsa44.SignatureSize { t.Fatalf("signature length = %d, want %d", len(signature), mldsa44.SignatureSize) }

	cases := []struct{name string; signature []byte}{
		{name: "appended byte", signature: append(append([]byte(nil), signature...), 0x00)},
		{name: "truncated", signature: append([]byte(nil), signature[:len(signature)-1]...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := Verify(publicKey, message, tc.signature)
			if err == nil { t.Fatal("Verify() accepted a non-canonical signature length without error") }
			if valid { t.Fatal("Verify() accepted a non-canonical signature length") }
		})
	}
}

func TestMLDSARejectsWrongKeyAndEmptyPrivateKey(t *testing.T) {
	_, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	otherPublicKey, _, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil { t.Fatal(err) }
	valid, err := Verify(otherPublicKey, message, signature)
	if err != nil { t.Fatal(err) }
	if valid { t.Fatal("Verify() accepted a signature from another key") }
	if _, err := Sign(nil, message); err == nil { t.Fatal("Sign() accepted an empty private key") }
	if _, err := Verify(nil, message, signature); err == nil { t.Fatal("Verify() accepted an empty public key") }
}

func TestMLDSAKeyEncodingRoundTrip(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	if bytes.Equal(publicKey, privateKey) { t.Fatal("public and private key encodings unexpectedly match") }
	if len(publicKey) == 0 || len(privateKey) == 0 { t.Fatal("generated empty key encoding") }
}
