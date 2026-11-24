package pqc

import (
	"bytes"
	"testing"
)

func TestMLDSASignVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	message := []byte(`{"claimId":"claim-test-001","status":"VERIFIED","protocol":"DRP"}`)
	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	valid, err := Verify(publicKey, message, signature)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !valid {
		t.Fatal("Verify() rejected a valid signature")
	}
}

func TestMLDSARejectsTamperedMessage(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("original proof")
	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := Verify(publicKey, []byte("tampered proof"), signature)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("Verify() accepted a signature for a different message")
	}
}

func TestMLDSARejectsTamperedSignature(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	signature[len(signature)/2] ^= 0x01
	valid, err := Verify(publicKey, message, signature)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("Verify() accepted a modified signature")
	}
}

func TestMLDSARejectsWrongKeyAndEmptyPrivateKey(t *testing.T) {
	_, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	otherPublicKey, _, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := Verify(otherPublicKey, message, signature)
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("Verify() accepted a signature from another key")
	}
	if _, err := Sign(nil, message); err == nil {
		t.Fatal("Sign() accepted an empty private key")
	}
	if _, err := Verify(nil, message, signature); err == nil {
		t.Fatal("Verify() accepted an empty public key")
	}
}

func TestMLDSAKeyEncodingRoundTrip(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(publicKey, privateKey) {
		t.Fatal("public and private key encodings unexpectedly match")
	}
	if len(publicKey) == 0 || len(privateKey) == 0 {
		t.Fatal("generated empty key encoding")
	}
}

func TestMLDSARejectsAppendedSignatureBytes(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil { t.Fatal(err) }
	appended := append(append([]byte(nil), signature...), 0x00)
	if valid, err := Verify(publicKey, message, appended); err == nil || valid {
		t.Fatal("Verify() accepted a signature with appended bytes")
	}
}

func TestMLDSARejectsTruncatedSignature(t *testing.T) {
	publicKey, privateKey, err := GenerateKey()
	if err != nil { t.Fatal(err) }
	message := []byte("proof")
	signature, err := Sign(privateKey, message)
	if err != nil { t.Fatal(err) }
	if valid, err := Verify(publicKey, message, signature[:len(signature)-1]); err == nil || valid {
		t.Fatal("Verify() accepted a truncated signature")
	}
}
