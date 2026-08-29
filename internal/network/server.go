package network

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/verification"
)

type Server struct { Store *store.Store; Engine verification.Engine }

func New(s *store.Store) *Server { return &Server{Store: s} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/drp/v1/verify", s.verify)
	mux.HandleFunc("/drp/v1/proofs/", s.proof)
	mux.HandleFunc("/drp/v1/claims/", s.claim)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status":"ok","protocol":"DRP","version":protocol.Version})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { writeJSON(w,405,map[string]string{"error":"method not allowed"}); return }
	var req protocol.VerificationRequest
	if err:=json.NewDecoder(r.Body).Decode(&req); err != nil { writeJSON(w,400,map[string]string{"error":"invalid JSON"}); return }
	if err:=req.Validate(); err != nil { writeJSON(w,422,map[string]string{"error":err.Error()}); return }
	s.Store.PutRequest(req)
	result := s.Engine.Evaluate(req, nil)
	writeJSON(w, http.StatusAccepted, result)
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	id:=strings.TrimPrefix(r.URL.Path,"/drp/v1/claims/")
	req,ok:=s.Store.GetRequest(id)
	if !ok { writeJSON(w,404,map[string]string{"error":"claim/request not found"}); return }
	writeJSON(w,200,req)
}

func (s *Server) proof(w http.ResponseWriter, r *http.Request) {
	id:=strings.TrimPrefix(r.URL.Path,"/drp/v1/proofs/")
	p,ok:=s.Store.GetProof(id)
	if !ok { writeJSON(w,404,map[string]string{"error":"proof not found"}); return }
	writeJSON(w,200,p)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func NewRequest(id, subject, typ, statement string, evidence []protocol.Evidence) protocol.VerificationRequest {
	return protocol.VerificationRequest{
		Version: protocol.Version, ID:id,
		Claim: protocol.Claim{Version:protocol.Version, ID:id+":claim", Subject:subject, Type:typ, Statement:statement, CreatedAt:time.Now().UTC()},
		Evidence:evidence,
		Policy:protocol.VerificationPolicy{Version:protocol.Version, ID:id+":policy", MinVerifiers:2, MinEvidence:1},
		CreatedAt:time.Now().UTC(),
	}
}
