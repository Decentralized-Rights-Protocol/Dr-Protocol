package network

import (
	"sync"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

type Verifier struct {
	ID string `json:"id"`
	Name string `json:"name"`
	Capabilities []string `json:"capabilities,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
	Active bool `json:"active"`
}

type Registry struct {
	mu sync.RWMutex
	verifiers map[string]Verifier
}

func NewRegistry() *Registry { return &Registry{verifiers: map[string]Verifier{}} }
func (r *Registry) Register(v Verifier) { r.mu.Lock(); defer r.mu.Unlock(); r.verifiers[v.ID]=v }
func (r *Registry) List() []Verifier { r.mu.RLock(); defer r.mu.RUnlock(); out:=make([]Verifier,0,len(r.verifiers)); for _,v:=range r.verifiers { out=append(out,v) }; return out }
func (r *Registry) ActiveCount() int { n:=0; for _,v:=range r.List(){if v.Active{n++}}; return n }
var _ = protocol.Version
