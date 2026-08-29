package network

import (
	"sync"
	"time"
)

type Peer struct {
	ID string `json:"id"`
	Address string `json:"address"`
	LastSeen time.Time `json:"lastSeen"`
}

type PeerBook struct { mu sync.RWMutex; peers map[string]Peer }
func NewPeerBook()*PeerBook{return &PeerBook{peers:map[string]Peer{}}}
func(p *PeerBook) Upsert(peer Peer){p.mu.Lock();defer p.mu.Unlock();p.peers[peer.ID]=peer}
func(p *PeerBook) List()[]Peer{p.mu.RLock();defer p.mu.RUnlock();out:=make([]Peer,0,len(p.peers));for _,v:=range p.peers{out=append(out,v)};return out}
