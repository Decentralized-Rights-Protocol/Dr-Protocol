// Package consensus implements an experimental deterministic DRP consensus primitive.
// It is not a complete production BFT protocol: networking, timeouts, view changes,
// validator-set transitions, and a durable write-ahead log remain out of scope.
package consensus

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

var (
	ErrUnknownValidator = errors.New("consensus: unknown validator")
	ErrInvalidSignature = errors.New("consensus: invalid vote signature")
	ErrNoProposal       = errors.New("consensus: no pending proposal")
	ErrConflictingVote  = errors.New("consensus: validator already voted for another block")
	ErrNoQuorum          = errors.New("consensus: quorum not reached")
	ErrInvalidHeight     = errors.New("consensus: invalid block height or parent")
	ErrInvalidCertificate = errors.New("consensus: invalid commit certificate")
)

type Block struct {
	Height        uint64 `json:"height"`
	PreviousHash  string `json:"previous_hash"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Payload       []byte `json:"payload"`
}

func (b Block) Hash() string {
	encoded, _ := json.Marshal(b)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

type Vote struct {
	ValidatorID string `json:"validator_id"`
	BlockHash   string `json:"block_hash"`
	Signature   []byte `json:"signature"`
}

type Certificate struct {
	BlockHash string `json:"block_hash"`
	Votes     []Vote `json:"votes"`
}

type Engine struct {
	mu         sync.Mutex
	validators map[string]ed25519.PublicKey
	last       *Block
	pending    *Block
	votes      map[string]Vote
}

func New(validators map[string]ed25519.PublicKey) (*Engine, error) {
	if len(validators) == 0 {
		return nil, errors.New("consensus: validator set cannot be empty")
	}
	copySet := make(map[string]ed25519.PublicKey, len(validators))
	seenKeys := make(map[string]string, len(validators))
	for id, key := range validators {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("consensus: invalid validator %q", id)
		}
		keyID := string(key)
		if previousID, exists := seenKeys[keyID]; exists {
			return nil, fmt.Errorf("consensus: validators %q and %q share a public key", previousID, id)
		}
		seenKeys[keyID] = id
		copySet[id] = append(ed25519.PublicKey(nil), key...)
	}
	return &Engine{validators: copySet, votes: make(map[string]Vote)}, nil
}

func (e *Engine) Quorum() int { return (2*len(e.validators))/3 + 1 }

// RestoreCommitted seeds a freshly constructed engine from the durable chain tip.
// Startup code must validate the stored block and certificate before calling this.
func (e *Engine) RestoreCommitted(block Block) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.last != nil || e.pending != nil {
		return errors.New("consensus: restore requires an empty engine")
	}
	if block.Height == 0 || block.TimestampUnix <= 0 {
		return ErrInvalidHeight
	}
	if block.Height == 1 && block.PreviousHash != "" {
		return ErrInvalidHeight
	}
	e.last = ptrBlock(cloneBlock(block))
	return nil
}

func ptrBlock(b Block) *Block { return &b }

func (e *Engine) LastCommitted() (Block, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.last == nil {
		return Block{}, false
	}
	return cloneBlock(*e.last), true
}

func (e *Engine) Propose(block Block) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	expectedHeight := uint64(1)
	expectedParent := ""
	if e.last != nil {
		expectedHeight = e.last.Height + 1
		expectedParent = e.last.Hash()
	}
	if block.Height != expectedHeight || block.PreviousHash != expectedParent {
		return ErrInvalidHeight
	}
	if e.pending != nil {
		if e.pending.Hash() == block.Hash() {
			return nil
		}
		return errors.New("consensus: another proposal is already pending")
	}
	if block.TimestampUnix <= 0 {
		return errors.New("consensus: block timestamp must be positive")
	}
	copy := cloneBlock(block)
	e.pending = &copy
	e.votes = make(map[string]Vote)
	return nil
}

func (e *Engine) AddVote(v Vote) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return ErrNoProposal
	}
	key, ok := e.validators[v.ValidatorID]
	if !ok {
		return ErrUnknownValidator
	}
	if v.BlockHash != e.pending.Hash() || !ed25519.Verify(key, []byte(v.BlockHash), v.Signature) {
		return ErrInvalidSignature
	}
	if previous, exists := e.votes[v.ValidatorID]; exists {
		if previous.BlockHash != v.BlockHash {
			return ErrConflictingVote
		}
		return nil
	}
	v.Signature = append([]byte(nil), v.Signature...)
	e.votes[v.ValidatorID] = v
	return nil
}

func (e *Engine) VoteCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.votes)
}

func (e *Engine) Commit() (Block, Certificate, error) { return e.CommitWith(nil) }

// CommitWith runs persist while the proposal and votes are locked, and only
// advances in-memory consensus state if persistence succeeds. persist may be nil.
func (e *Engine) CommitWith(persist func(Block, Certificate) error) (Block, Certificate, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending == nil {
		return Block{}, Certificate{}, ErrNoProposal
	}
	if len(e.votes) < e.Quorum() {
		return Block{}, Certificate{}, ErrNoQuorum
	}
	hash := e.pending.Hash()
	cert := Certificate{BlockHash: hash, Votes: make([]Vote, 0, len(e.votes))}
	ids := make([]string, 0, len(e.votes))
	for id := range e.votes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		vote := e.votes[id]
		vote.Signature = append([]byte(nil), vote.Signature...)
		cert.Votes = append(cert.Votes, vote)
	}
	committed := cloneBlock(*e.pending)
	if persist != nil {
		if err := persist(cloneBlock(committed), cert); err != nil {
			return Block{}, Certificate{}, fmt.Errorf("consensus: persist commit: %w", err)
		}
	}
	e.last = &committed
	e.pending = nil
	e.votes = make(map[string]Vote)
	return cloneBlock(committed), cert, nil
}

// VerifyCertificate strictly validates a certificate. Every included vote must be
// from a known validator, unique, bound to this block, and cryptographically valid.
// Rejecting invalid extras prevents callers from accidentally accepting a malformed
// certificate merely because enough other votes happen to be valid.
func VerifyCertificate(block Block, cert Certificate, validators map[string]ed25519.PublicKey) error {
	if block.Height == 0 || block.TimestampUnix <= 0 {
		return ErrInvalidHeight
	}
	if block.Height == 1 {
		if block.PreviousHash != "" {
			return ErrInvalidHeight
		}
	} else {
		parentHash, err := hex.DecodeString(block.PreviousHash)
		if err != nil || len(parentHash) != sha256.Size {
			return ErrInvalidHeight
		}
	}
	if len(validators) == 0 {
		return ErrNoQuorum
	}
	seenKeys := make(map[string]string, len(validators))
	for id, key := range validators {
		if id == "" || len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: invalid validator set entry %q", ErrInvalidCertificate, id)
		}
		keyID := string(key)
		if previousID, exists := seenKeys[keyID]; exists {
			return fmt.Errorf("%w: validators %q and %q share a public key", ErrInvalidCertificate, previousID, id)
		}
		seenKeys[keyID] = id
	}
	hash := block.Hash()
	if cert.BlockHash != hash {
		return fmt.Errorf("%w: block hash mismatch", ErrInvalidCertificate)
	}
	quorum := (2*len(validators))/3 + 1
	seen := make(map[string]struct{}, len(cert.Votes))
	for _, vote := range cert.Votes {
		if _, exists := seen[vote.ValidatorID]; exists {
			return fmt.Errorf("%w: duplicate validator %q", ErrInvalidCertificate, vote.ValidatorID)
		}
		key, ok := validators[vote.ValidatorID]
		if !ok {
			return fmt.Errorf("%w: unknown validator %q", ErrInvalidCertificate, vote.ValidatorID)
		}
		if len(key) != ed25519.PublicKeySize || vote.BlockHash != hash ||
			len(vote.Signature) != ed25519.SignatureSize ||
			!ed25519.Verify(key, []byte(hash), vote.Signature) {
			return fmt.Errorf("%w: invalid vote from %q", ErrInvalidCertificate, vote.ValidatorID)
		}
		seen[vote.ValidatorID] = struct{}{}
	}
	if len(seen) < quorum {
		return ErrNoQuorum
	}
	return nil
}

func cloneBlock(b Block) Block {
	b.Payload = append([]byte(nil), b.Payload...)
	return b
}
