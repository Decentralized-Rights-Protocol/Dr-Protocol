package network

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/consensus"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

// ConsensusAPI is the HTTP adapter for the consensus engine. It deliberately
// requires explicit engine configuration; the gateway must not invent a
// validator set or private keys at startup.
type ConsensusAPI struct {
	Engine *consensus.Engine
	Validators map[string]ed25519.PublicKey // Ed25519 public keys, keyed by validator ID.
	Chain *store.ChainStore
}

func (s *Server) ConfigureConsensus(engine *consensus.Engine, validators map[string]ed25519.PublicKey, chain *store.ChainStore) {
	s.Consensus = &ConsensusAPI{Engine: engine, Validators: validators, Chain: chain}
}

func (s *Server) consensusHandler(w http.ResponseWriter, r *http.Request) {
	if s.Consensus == nil || s.Consensus.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error":"consensus is not configured"})
		return
	}
	switch {
	case r.URL.Path == "/drp/v1/consensus/status" && r.Method == http.MethodGet:
		block, ok := s.Consensus.Engine.LastCommitted()
		out := map[string]any{"configured":true,"quorum":s.Consensus.Engine.Quorum(),"votes":s.Consensus.Engine.VoteCount()}
		if ok { out["height"] = block.Height; out["blockHash"] = block.Hash() } else { out["height"] = 0 }
		writeJSON(w, http.StatusOK, out)
	case r.URL.Path == "/drp/v1/consensus/proposals" && r.Method == http.MethodPost:
		var block consensus.Block
		if err := json.NewDecoder(http.MaxBytesReader(w,r.Body,1<<20)).Decode(&block); err != nil {
			writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid block JSON"}); return
		}
		if err := s.Consensus.Engine.Propose(block); err != nil {
			writeJSON(w,http.StatusUnprocessableEntity,map[string]string{"error":err.Error()}); return
		}
		writeJSON(w,http.StatusAccepted,map[string]any{"blockHash":block.Hash(),"height":block.Height,"status":"proposal accepted"})
	case r.URL.Path == "/drp/v1/consensus/votes" && r.Method == http.MethodPost:
		var vote consensus.Vote
		if err := json.NewDecoder(http.MaxBytesReader(w,r.Body,1<<20)).Decode(&vote); err != nil {
			writeJSON(w,http.StatusBadRequest,map[string]string{"error":"invalid vote JSON"}); return
		}
		if err := s.Consensus.Engine.AddVote(vote); err != nil {
			status := http.StatusUnprocessableEntity
			if errors.Is(err,consensus.ErrUnknownValidator) { status = http.StatusForbidden }
			writeJSON(w,status,map[string]string{"error":err.Error()}); return
		}
		writeJSON(w,http.StatusAccepted,map[string]any{"accepted":true,"votes":s.Consensus.Engine.VoteCount()})
	case r.URL.Path == "/drp/v1/consensus/commit" && r.Method == http.MethodPost:
		if s.Consensus.Chain == nil { writeJSON(w,http.StatusServiceUnavailable,map[string]string{"error":"durable chain storage is not configured"}); return }
		block, cert, err := s.Consensus.Engine.CommitWith(func(b consensus.Block, c consensus.Certificate) error { return s.Consensus.Chain.CommitBlock(b,c,s.Consensus.Validators) })
		if err != nil { writeJSON(w,http.StatusConflict,map[string]string{"error":err.Error()}); return }
		writeJSON(w,http.StatusOK,map[string]any{"block":block,"certificate":cert})
	case strings.HasPrefix(r.URL.Path,"/drp/v1/consensus/") && r.Method != http.MethodGet && r.Method != http.MethodPost:
		writeJSON(w,http.StatusMethodNotAllowed,map[string]string{"error":"method not allowed"})
	default:
		writeJSON(w,http.StatusNotFound,map[string]string{"error":"consensus route not found"})
	}
}
