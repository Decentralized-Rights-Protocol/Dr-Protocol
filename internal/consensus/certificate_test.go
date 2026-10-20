package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func certificateFixture(t *testing.T, count int) (Block, Certificate, map[string]ed25519.PublicKey) {
	t.Helper()
	validators := make(map[string]ed25519.PublicKey, count)
	privateKeys := make(map[string]ed25519.PrivateKey, count)
	for i := 0; i < count; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := string(rune('a' + i))
		validators[id] = pub
		privateKeys[id] = priv
	}
	block := Block{Height: 1, TimestampUnix: 1, Payload: []byte("certificate-test")}
	hash := block.Hash()
	cert := Certificate{BlockHash: hash}
	for _, id := range []string{"a", "b", "c"} {
		cert.Votes = append(cert.Votes, Vote{
			ValidatorID: id,
			BlockHash: hash,
			Signature: ed25519.Sign(privateKeys[id], []byte(hash)),
		})
	}
	return block, cert, validators
}

func TestVerifyCertificateRejectsDuplicateValidator(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)
	cert.Votes = append(cert.Votes, cert.Votes[0])
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected invalid certificate for duplicate vote, got %v", err)
	}
}

func TestVerifyCertificateRejectsUnknownValidatorAndBadSignature(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)

	unknown := cert
	unknown.Votes = append([]Vote(nil), cert.Votes...)
	unknown.Votes[0] = Vote{ValidatorID: "unknown", BlockHash: block.Hash(), Signature: make([]byte, ed25519.SignatureSize)}
	if err := VerifyCertificate(block, unknown, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected unknown validator rejection, got %v", err)
	}

	badSignature := cert
	badSignature.Votes = append([]Vote(nil), cert.Votes...)
	badSignature.Votes[0].Signature = make([]byte, ed25519.SignatureSize)
	if err := VerifyCertificate(block, badSignature, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected invalid signature rejection, got %v", err)
	}
}

func TestVerifyCertificateRejectsInvalidBlockMetadata(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)
	block.TimestampUnix = 0
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrInvalidHeight) {
		t.Fatalf("expected invalid block metadata rejection, got %v", err)
	}
}

func TestVerifyCertificateRequiresQuorum(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)
	cert.Votes = cert.Votes[:2]
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("expected quorum error, got %v", err)
	}
}
