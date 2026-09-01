package verification

import (
	"testing"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func TestQuorum(t *testing.T) {
	e:=EvidenceForTest()
	r:=protocol.VerificationRequest{ID:"r1",Claim:protocol.Claim{ID:"c1",Subject:"s",Type:"t",Statement:"x"},Evidence:e,Policy:protocol.VerificationPolicy{MinVerifiers:2,MinEvidence:1}}
	a:=[]protocol.Attestation{{VerifierID:"elder-1",Decision:protocol.StatusVerified},{VerifierID:"elder-2",Decision:protocol.StatusVerified}}
	got:=Engine{}.Evaluate(r,a)
	if got.Status != protocol.StatusVerified { t.Fatalf("got %s",got.Status) }
}

func EvidenceForTest() []protocol.Evidence {
	return []protocol.Evidence{{ID:"e1",SourceID:"src",Type:"attestation",ContentHash:"abc"}}
}
