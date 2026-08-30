package store

import (
	"sync"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

type Store struct {
	mu sync.RWMutex
	requests map[string]protocol.VerificationRequest
	proofs map[string]protocol.Proof
	attestations map[string]protocol.Attestation
}

func New() *Store { return &Store{requests: map[string]protocol.VerificationRequest{}, proofs: map[string]protocol.Proof{}, attestations: map[string]protocol.Attestation{}} }
func (s *Store) PutRequest(r protocol.VerificationRequest) { s.mu.Lock(); defer s.mu.Unlock(); s.requests[r.ID]=r }
func (s *Store) GetRequest(id string) (protocol.VerificationRequest,bool) { s.mu.RLock(); defer s.mu.RUnlock(); r,ok:=s.requests[id]; return r,ok }
func (s *Store) PutProof(p protocol.Proof) { s.mu.Lock(); defer s.mu.Unlock(); s.proofs[p.ID]=p }
func (s *Store) GetProof(id string) (protocol.Proof,bool) { s.mu.RLock(); defer s.mu.RUnlock(); p,ok:=s.proofs[id]; return p,ok }
func (s *Store) PutAttestation(a protocol.Attestation) { s.mu.Lock(); defer s.mu.Unlock(); s.attestations[a.ID]=a }
func (s *Store) GetAttestations(claimID string) []protocol.Attestation { s.mu.RLock(); defer s.mu.RUnlock(); out:=[]protocol.Attestation{}; for _,a:=range s.attestations { if a.ClaimID==claimID {out=append(out,a)} }; return out }
