package network

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

const replicationPath = "/drp/v1/replication/proofs"

type proofEnvelope struct {
	Version  string         `json:"version"`
	SenderID string         `json:"senderId"`
	Proof    protocol.Proof `json:"proof"`
	Signature string        `json:"signature"`
}

func envelopePayload(e proofEnvelope) ([]byte, error) {
	e.Signature = ""
	return json.Marshal(e)
}

func (s *Server) SignProofForReplication(p protocol.Proof) (proofEnvelope, error) {
	e := proofEnvelope{Version: protocol.Version, SenderID: s.Signer.PublicKeyString(), Proof: p}
	payload, err := envelopePayload(e)
	if err != nil {
		return proofEnvelope{}, err
	}
	e.Signature = s.Signer.Sign(payload)
	return e, nil
}

func (s *Server) ReplicateProof(ctx context.Context, peer Peer, p protocol.Proof) error {
	if strings.TrimSpace(peer.Address) == "" || strings.TrimSpace(peer.ID) == "" {
		return &replicationError{status: http.StatusBadRequest, message: "peer requires id and address"}
	}
	e, err := s.SignProofForReplication(p)
	if err != nil {
		return err
	}
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(peer.Address, "/")+replicationPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &replicationError{status: resp.StatusCode, message: "peer rejected proof replication"}
	}
	return nil
}

func (s *Server) replicationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var e proofEnvelope
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if e.Version != protocol.Version || e.SenderID == "" || e.Signature == "" || e.Proof.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid replication envelope"})
		return
	}
	if !s.isKnownPeer(e.SenderID) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unknown peer"})
		return
	}
	payload, err := envelopePayload(e)
	if err != nil || !verifyPublicKeySignature(e.SenderID, payload, e.Signature) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid replication signature"})
		return
	}
	if !drpcrypto.VerifyProof(e.Proof, e.SenderID) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid proof signature"})
		return
	}
	if existing, ok := s.Store.GetProof(e.Proof.ID); ok {
		if sameJSON(existing, e.Proof) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "already_present", "id": e.Proof.ID})
			return
		}
		writeJSON(w, http.StatusConflict, map[string]string{"error": "proof id already exists with different content"})
		return
	}
	s.Store.PutProof(e.Proof)
	writeJSON(w, http.StatusCreated, map[string]string{"status": "replicated", "id": e.Proof.ID})
}

func verifyPublicKeySignature(publicKey string, payload []byte, signature string) bool {
	pub, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return drpcrypto.Verify(ed25519.PublicKey(pub), payload, signature)
}

func (s *Server) isKnownPeer(id string) bool {
	for _, p := range s.Peers.List() {
		if p.ID == id {
			return true
		}
	}
	return false
}

func sameJSON(a, b protocol.Proof) bool {
	aa, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(aa, bb)
}

type replicationError struct {
	status  int
	message string
}

func (e *replicationError) Error() string { return e.message }

func NewReplicationHandler(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(replicationPath, s.replicationHandler)
	mux.Handle("/", s.Handler())
	return mux
}
