package network

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/verification"
)

type Server struct {
	Store *store.Store
	Engine verification.Engine
	Registry *Registry
	Peers *PeerBook
	Signer *drpcrypto.Signer
}

// New retains the convenient ephemeral setup used by tests and local demos.
func New(s *store.Store) *Server {
	signer, err := drpcrypto.NewSigner()
	if err != nil { panic("generate ephemeral DRP node identity: " + err.Error()) }
	return NewWithSigner(s, signer)
}

// NewWithSigner allows the daemon to load a stable identity from its data directory.
func NewWithSigner(s *store.Store, signer *drpcrypto.Signer) *Server {
	return &Server{Store: s, Registry: NewRegistry(), Peers: NewPeerBook(), Signer: signer}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.health)
	mux.HandleFunc("/drp/v1/verify", s.verify)
	mux.HandleFunc("/drp/v1/proofs/", s.proof)
	mux.HandleFunc("/drp/v1/claims/", s.claim)
	mux.HandleFunc("/drp/v1/verifiers", s.verifiers)
	mux.HandleFunc("/drp/v1/peers", s.peers)
	mux.HandleFunc("/drp/v1/attestations", s.attestations)
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status":"ok", "protocol":"DRP", "version":protocol.Version, "activeVerifiers":s.Registry.ActiveCount(), "peers":len(s.Peers.List())})
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"method not allowed"}); return }
	var req protocol.VerificationRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid JSON"}); return }
	if err := req.Validate(); err != nil { writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error":err.Error()}); return }
	if err := s.Store.PutRequest(req); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not persist verification request"}); return }
	attestations := s.Store.GetAttestations(req.Claim.ID)
	result := s.Engine.Evaluate(req, attestations)
	digest, err := protocol.CanonicalDigest(req.Claim)
	if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not digest claim"}); return }
	policyDigest, err := protocol.CanonicalDigest(req.Policy)
	if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not digest policy"}); return }
	evidenceDigests := make([]string, 0, len(req.Evidence))
	for _, evidence := range req.Evidence {
		d, err := protocol.CanonicalDigest(evidence)
		if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not digest evidence"}); return }
		evidenceDigests = append(evidenceDigests, d)
	}
	proof := protocol.Proof{Version:protocol.Version, ID:req.ID+":proof", ClaimDigest:digest, PolicyDigest:policyDigest, EvidenceDigests:evidenceDigests, Result:result, CreatedAt:time.Now().UTC()}
	proof, err = drpcrypto.SignProof(s.Signer, proof)
	if err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not sign proof"}); return }
	if err := s.Store.PutProof(proof); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not persist proof"}); return }
	writeJSON(w, http.StatusAccepted, map[string]any{"result":result, "proof":proof, "network":"DRP Verification Network"})
}

func (s *Server) attestations(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet { writeJSON(w, http.StatusOK, map[string]any{"attestations":s.Store.GetAttestations(r.URL.Query().Get("claimId"))}); return }
	if r.Method != http.MethodPost { writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"method not allowed"}); return }
	var a protocol.Attestation
	if json.NewDecoder(r.Body).Decode(&a) != nil || a.ID == "" || a.VerifierID == "" || a.ClaimID == "" { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid attestation"}); return }
	var verifier Verifier
	found := false
	for _, v := range s.Registry.List() { if v.ID == a.VerifierID { verifier = v; found = true; break } }
	if !found || !verifier.Active || verifier.PublicKey == "" { writeJSON(w, http.StatusForbidden, map[string]string{"error":"verifier is not registered, active, or missing public key"}); return }
	if !drpcrypto.VerifyAttestation(a, verifier.PublicKey) { writeJSON(w, http.StatusUnauthorized, map[string]string{"error":"invalid attestation signature"}); return }
	if err := s.Store.PutAttestation(a); err != nil { writeJSON(w, http.StatusInternalServerError, map[string]string{"error":"could not persist attestation"}); return }
	writeJSON(w, http.StatusCreated, a)
}

func (s *Server) claim(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/drp/v1/claims/")
	req, ok := s.Store.GetRequest(id)
	if !ok { writeJSON(w, http.StatusNotFound, map[string]string{"error":"claim/request not found"}); return }
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) proof(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/drp/v1/proofs/")
	p, ok := s.Store.GetProof(id)
	if !ok { writeJSON(w, http.StatusNotFound, map[string]string{"error":"proof not found"}); return }
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) verifiers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet { writeJSON(w, http.StatusOK, map[string]any{"verifiers":s.Registry.List()}); return }
	if r.Method == http.MethodPost {
		var v Verifier
		if json.NewDecoder(r.Body).Decode(&v) != nil || v.ID == "" { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid verifier"}); return }
		s.Registry.Register(v); writeJSON(w, http.StatusCreated, v); return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"method not allowed"})
}

func (s *Server) peers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet { writeJSON(w, http.StatusOK, map[string]any{"peers":s.Peers.List()}); return }
	if r.Method == http.MethodPost {
		var p Peer
		if json.NewDecoder(r.Body).Decode(&p) != nil || p.ID == "" || p.Address == "" { writeJSON(w, http.StatusBadRequest, map[string]string{"error":"invalid peer"}); return }
		p.LastSeen = time.Now().UTC(); s.Peers.Upsert(p); writeJSON(w, http.StatusCreated, p); return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error":"method not allowed"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func NewRequest(id, subject, typ, statement string, evidence []protocol.Evidence) protocol.VerificationRequest {
	return protocol.VerificationRequest{Version:protocol.Version, ID:id, Claim:protocol.Claim{Version:protocol.Version, ID:id+":claim", Subject:subject, Type:typ, Statement:statement, CreatedAt:time.Now().UTC()}, Evidence:evidence, Policy:protocol.VerificationPolicy{Version:protocol.Version, ID:id+":policy", MinVerifiers:2, MinEvidence:1}, CreatedAt:time.Now().UTC()}
}
