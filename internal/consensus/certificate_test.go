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

func TestVerifyCertificateRejectsMalformedValidatorSet(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)

	// Invalid entries must not inflate the validator count used for quorum.
	validators["malformed"] = ed25519.PublicKey{1, 2, 3}
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected invalid validator set rejection, got %v", err)
	}

	delete(validators, "malformed")
	validators[""] = validators["a"]
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected empty validator ID rejection, got %v", err)
	}
}

func TestVerifyCertificateRejectsDuplicateValidatorPublicKeys(t *testing.T) {
	block, cert, validators := certificateFixture(t, 4)
	validators["d"] = append(ed25519.PublicKey(nil), validators["a"]...)
	if err := VerifyCertificate(block, cert, validators); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("expected duplicate public key rejection, got %v", err)
	}
	if _, err := New(validators); err == nil {
		t.Fatal("expected engine construction to reject duplicate validator public keys")
	}
}

func TestVerifyCertificateRejectsMalformedParentHash(t *testing.T) {
	_, cert, validators := certificateFixture(t, 4)
	for _, parentHash := range []string{"", "not-a-hash", "abcd"} {
		block := Block{
			Height:        2,
			PreviousHash:  parentHash,
			TimestampUnix: 2,
			Payload:       []byte("child"),
		}
		invalidCert := cert
		invalidCert.BlockHash = block.Hash()
		if err := VerifyCertificate(block, invalidCert, validators); !errors.Is(err, ErrInvalidHeight) {
			t.Errorf("parent hash %q: expected invalid height/parent error, got %v", parentHash, err)
		}
	}
}
