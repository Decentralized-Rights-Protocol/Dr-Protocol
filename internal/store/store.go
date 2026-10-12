package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

const storeFormatVersion = 1

type diskState struct {
	FormatVersion int `json:"formatVersion"`
	Requests map[string]protocol.VerificationRequest `json:"requests"`
	Proofs map[string]protocol.Proof `json:"proofs"`
	Attestations map[string]protocol.Attestation `json:"attestations"`
}

type Store struct {
	mu sync.RWMutex
	requests map[string]protocol.VerificationRequest
	proofs map[string]protocol.Proof
	attestations map[string]protocol.Attestation
	persistencePath string
}

// New creates an in-memory store for tests and explicitly ephemeral deployments.
func New() *Store { return newEmptyStore() }

// NewPersistent opens a JSON-backed store and loads its state before returning.
// The state file is written with private permissions and replaced atomically.
func NewPersistent(path string) (*Store, error) {
	if path == "" { return nil, errors.New("persistent store path is required") }
	absolutePath, err := filepath.Abs(path)
	if err != nil { return nil, fmt.Errorf("resolve store path: %w", err) }
	if err := os.MkdirAll(filepath.Dir(absolutePath), 0o700); err != nil { return nil, fmt.Errorf("create store directory: %w", err) }
	s := newEmptyStore()
	s.persistencePath = absolutePath
	data, err := os.ReadFile(absolutePath)
	if errors.Is(err, os.ErrNotExist) { return s, nil }
	if err != nil { return nil, fmt.Errorf("read persistent store: %w", err) }
	var state diskState
	if err := json.Unmarshal(data, &state); err != nil { return nil, fmt.Errorf("decode persistent store: %w", err) }
	if state.FormatVersion != storeFormatVersion { return nil, fmt.Errorf("unsupported store format version %d", state.FormatVersion) }
	if state.Requests != nil { s.requests = state.Requests }
	if state.Proofs != nil { s.proofs = state.Proofs }
	if state.Attestations != nil { s.attestations = state.Attestations }
	return s, nil
}

func newEmptyStore() *Store {
	return &Store{requests: map[string]protocol.VerificationRequest{}, proofs: map[string]protocol.Proof{}, attestations: map[string]protocol.Attestation{}}
}

func (s *Store) PutRequest(r protocol.VerificationRequest) error {
	s.mu.Lock(); defer s.mu.Unlock()
	old, existed := s.requests[r.ID]
	s.requests[r.ID] = r
	if err := s.persistLocked(); err != nil { if existed { s.requests[r.ID] = old } else { delete(s.requests, r.ID) }; return err }
	return nil
}

func (s *Store) GetRequest(id string) (protocol.VerificationRequest, bool) {
	s.mu.RLock(); defer s.mu.RUnlock(); r, ok := s.requests[id]; return r, ok
}

func (s *Store) PutProof(p protocol.Proof) error {
	s.mu.Lock(); defer s.mu.Unlock()
	old, existed := s.proofs[p.ID]
	s.proofs[p.ID] = p
	if err := s.persistLocked(); err != nil { if existed { s.proofs[p.ID] = old } else { delete(s.proofs, p.ID) }; return err }
	return nil
}

func (s *Store) GetProof(id string) (protocol.Proof, bool) {
	s.mu.RLock(); defer s.mu.RUnlock(); p, ok := s.proofs[id]; return p, ok
}

func (s *Store) PutAttestation(a protocol.Attestation) error {
	s.mu.Lock(); defer s.mu.Unlock()
	old, existed := s.attestations[a.ID]
	s.attestations[a.ID] = a
	if err := s.persistLocked(); err != nil { if existed { s.attestations[a.ID] = old } else { delete(s.attestations, a.ID) }; return err }
	return nil
}

func (s *Store) GetAttestations(claimID string) []protocol.Attestation {
	s.mu.RLock(); defer s.mu.RUnlock()
	out := make([]protocol.Attestation, 0, len(s.attestations))
	for _, a := range s.attestations { if a.ClaimID == claimID { out = append(out, a) } }
	sort.Slice(out, func(i, j int) bool { if out[i].CreatedAt.Equal(out[j].CreatedAt) { return out[i].ID < out[j].ID }; return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) persistLocked() error {
	if s.persistencePath == "" { return nil }
	state := diskState{FormatVersion: storeFormatVersion, Requests: s.requests, Proofs: s.proofs, Attestations: s.attestations}
	data, err := json.Marshal(state)
	if err != nil { return fmt.Errorf("encode persistent store: %w", err) }
	dir := filepath.Dir(s.persistencePath)
	tmp, err := os.CreateTemp(dir, ".drp-store-*.tmp")
	if err != nil { return fmt.Errorf("create store temporary file: %w", err) }
	tmpName := tmp.Name(); defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil { _ = tmp.Close(); return fmt.Errorf("secure temporary store file: %w", err) }
	if _, err := tmp.Write(data); err != nil { _ = tmp.Close(); return fmt.Errorf("write persistent store: %w", err) }
	if err := tmp.Sync(); err != nil { _ = tmp.Close(); return fmt.Errorf("sync persistent store: %w", err) }
	if err := tmp.Close(); err != nil { return fmt.Errorf("close persistent store: %w", err) }
	if err := os.Rename(tmpName, s.persistencePath); err != nil { return fmt.Errorf("replace persistent store: %w", err) }
	return nil
}
