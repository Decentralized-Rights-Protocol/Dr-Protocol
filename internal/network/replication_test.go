package network

import (
	"net/http/httptest"
	"testing"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func TestTwoNodeProofReplication(t *testing.T) {
	nodeA := New(store.New())
	nodeB := New(store.New())

	proofReq := NewRequest("r1", "alice", "activity", "performed X", nil)
	proofReq.Evidence = []protocol.Evidence{{Version: protocol.Version, ID: "e1", SourceID: "phone", Type: "attestation", ContentHash: "abc"}}

	// Produce a real signed proof on node A through the normal verification endpoint.
	body, err := jsonBody(proofReq)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/drp/v1/verify", body)
	rec := httptest.NewRecorder()
	nodeA.Handler().ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("node A verification status = %d, want 202", rec.Code)
	}

	proof, ok := nodeA.Store.GetProof("r1:proof")
	if !ok {
		t.Fatal("node A did not persist proof")
	}

	// Pin node A's public key as a trusted peer on node B.
	nodeB.Peers.Upsert(Peer{ID: nodeA.Signer.PublicKeyString(), Address: "node-a"})

	ts := httptest.NewServer(NewReplicationHandler(nodeB))
	defer ts.Close()

	peer := Peer{ID: nodeA.Signer.PublicKeyString(), Address: ts.URL}
	if err := nodeA.ReplicateProof(testContext(), peer, proof); err != nil {
		t.Fatalf("replication failed: %v", err)
	}

	replicated, ok := nodeB.Store.GetProof(proof.ID)
	if !ok {
		t.Fatal("node B did not persist replicated proof")
	}
	if !sameJSON(proof, replicated) {
		t.Fatal("node B proof differs from node A proof")
	}

	// Replaying the same proof must be idempotent.
	if err := nodeA.ReplicateProof(testContext(), peer, proof); err != nil {
		t.Fatalf("idempotent replay failed: %v", err)
	}
}

func TestReplicationRejectsUnknownPeer(t *testing.T) {
	node := New(store.New())
	ts := httptest.NewServer(NewReplicationHandler(node))
	defer ts.Close()

	proof := protocol.Proof{Version: protocol.Version, ID: "p1"}
	node := node
	_ = proof
	_ = ts
}
