package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/consensus"
)

func TestChainStorePersistsVerifiedCommit(t *testing.T) {
	dir := t.TempDir()
	publicKeys := make(map[string]ed25519.PublicKey)
	privateKeys := make(map[string]ed25519.PrivateKey)
	for _, id := range []string{"a","b","c","d"} {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { t.Fatal(err) }
		publicKeys[id], privateKeys[id] = pub, priv
	}
	engine, err := consensus.New(publicKeys)
	if err != nil { t.Fatal(err) }
	block := consensus.Block{Height:1,TimestampUnix:1,Payload:[]byte("state transition")}
	if err := engine.Propose(block); err != nil { t.Fatal(err) }
	hash := block.Hash()
	for _, id := range []string{"a","b","c"} {
		vote := consensus.Vote{ValidatorID:id,BlockHash:hash,Signature:ed25519.Sign(privateKeys[id],[]byte(hash))}
		if err := engine.AddVote(vote); err != nil { t.Fatal(err) }
	}
	db, err := OpenChain(dir)
	if err != nil { t.Fatal(err) }
	committed, _, err := engine.CommitWith(func(b consensus.Block, cert consensus.Certificate) error {
		return db.CommitBlock(b,cert,publicKeys)
	})
	if err != nil { t.Fatal(err) }
	if committed.Hash()!=block.Hash() { t.Fatal("committed block hash mismatch") }
	if err := db.Close(); err != nil { t.Fatal(err) }

	db, err = OpenChain(dir)
	if err != nil { t.Fatal(err) }
	defer db.Close()
	if err := db.ValidateChain(publicKeys); err != nil { t.Fatalf("persisted chain invalid: %v",err) }
	tip, ok, err := db.Tip()
	if err != nil || !ok { t.Fatalf("tip missing: ok=%v err=%v",ok,err) }
	if tip.Hash()!=block.Hash() { t.Fatal("reopened tip hash mismatch") }
	if _, ok, err := db.Certificate(1); err != nil || !ok { t.Fatalf("certificate missing: ok=%v err=%v",ok,err) }
}

func TestChainStoreRejectsUncertifiedCommit(t *testing.T) {
	db, err := OpenChain(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer db.Close()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	block := consensus.Block{Height:1,TimestampUnix:1}
	err = db.CommitBlock(block,consensus.Certificate{BlockHash:block.Hash()},map[string]ed25519.PublicKey{"a":pub})
	if err == nil { t.Fatal("expected invalid certificate to be rejected") }
}
