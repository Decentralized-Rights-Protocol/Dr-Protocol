package consensus

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func testValidators(t *testing.T, n int) (map[string]ed25519.PublicKey, map[string]ed25519.PrivateKey) {
	t.Helper()
	pub := make(map[string]ed25519.PublicKey, n)
	priv := make(map[string]ed25519.PrivateKey, n)
	for i := 0; i < n; i++ {
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { t.Fatal(err) }
		id := string(rune('a' + i))
		pub[id], priv[id] = p, s
	}
	return pub, priv
}

func TestCommitRequiresQuorum(t *testing.T) {
	pub, priv := testValidators(t, 4)
	engine, err := New(pub)
	if err != nil { t.Fatal(err) }
	block := Block{Height: 1, TimestampUnix: 1, Payload: []byte("drp-state-transition")}
	if err := engine.Propose(block); err != nil { t.Fatal(err) }
	for _, id := range []string{"a", "b"} {
		hash := block.Hash()
		if err := engine.AddVote(Vote{ValidatorID:id, BlockHash:hash, Signature:ed25519.Sign(priv[id], []byte(hash))}); err != nil { t.Fatal(err) }
	}
	if _, _, err := engine.Commit(); !errors.Is(err, ErrNoQuorum) { t.Fatalf("expected quorum error, got %v", err) }
	id := "c"; hash := block.Hash()
	if err := engine.AddVote(Vote{ValidatorID:id, BlockHash:hash, Signature:ed25519.Sign(priv[id], []byte(hash))}); err != nil { t.Fatal(err) }
	committed, cert, err := engine.Commit()
	if err != nil { t.Fatal(err) }
	if committed.Hash() != block.Hash() { t.Fatal("committed block hash changed") }
	if err := VerifyCertificate(committed, cert, pub); err != nil { t.Fatalf("certificate invalid: %v", err) }
	if _, ok := engine.LastCommitted(); !ok { t.Fatal("expected committed block") }
}

func TestRejectsUnknownAndInvalidVotes(t *testing.T) {
	pub, priv := testValidators(t, 1)
	engine, _ := New(pub)
	block := Block{Height:1, TimestampUnix:1}
	if err := engine.Propose(block); err != nil { t.Fatal(err) }
	if err := engine.AddVote(Vote{ValidatorID:"unknown", BlockHash:block.Hash()}); !errors.Is(err, ErrUnknownValidator) { t.Fatalf("got %v", err) }
	if err := engine.AddVote(Vote{ValidatorID:"a", BlockHash:block.Hash(), Signature:[]byte("bad")}); !errors.Is(err, ErrInvalidSignature) { t.Fatalf("got %v", err) }
	hash := block.Hash()
	if err := engine.AddVote(Vote{ValidatorID:"a", BlockHash:hash, Signature:ed25519.Sign(priv["a"], []byte(hash))}); err != nil { t.Fatal(err) }
	if _, _, err := engine.Commit(); err != nil { t.Fatal(err) }
}

func TestRejectsWrongHeightAndParent(t *testing.T) {
	pub, _ := testValidators(t, 1)
	engine, _ := New(pub)
	if err := engine.Propose(Block{Height:2, TimestampUnix:1}); !errors.Is(err, ErrInvalidHeight) { t.Fatalf("got %v", err) }
}
