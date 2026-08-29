package store

import (
	"sync"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

type Store struct {
	mu sync.RWMutex
	requests map[string]protocol.VerificationRequest
	proofs map[string]protocol.Proof
}

func New() *Store { return &Store{requests: map[string]protocol.VerificationRequest{}, proofs: map[string]protocol.Proof{}} }

func (s *Store) PutRequest(r protocol.VerificationRequest) { s.mu.Lock(); defer s.mu.Unlock(); s.requests[r.ID] = r }
func (s *Store) GetRequest(id string) (protocol.VerificationRequest, bool) { s.mu.RLock(); defer s.mu.RUnlock(); r, ok := s.requests[id]; return r, ok }
func (s *Store) PutProof(p protocol.Proof) { s.mu.Lock(); defer s.mu.Unlock(); s.proofs[p.ID] = p }
func (s *Store) GetProof(id string) (protocol.Proof, bool) { s.mu.RLock(); defer s.mu.RUnlock(); p, ok := s.proofs[id]; return p, ok }
