package network

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/store"
)

func TestVerifyProducesSignedProof(t *testing.T) {
	s:=New(store.New())
	body:=`{"version":"0.1","id":"r1","claim":{"version":"0.1","id":"c1","subject":"alice","type":"activity","statement":"performed X"},"evidence":[{"version":"0.1","id":"e1","sourceId":"phone","type":"attestation","contentHash":"abc"}],"policy":{"version":"0.1","id":"p1","minVerifiers":1,"minEvidence":1}}`
	req:=httptest.NewRequest("POST","/drp/v1/verify",strings.NewReader(body))
	rec:=httptest.NewRecorder()
	s.Handler().ServeHTTP(rec,req)
	if rec.Code!=202 { t.Fatalf("got status %d: %s",rec.Code,rec.Body.String()) }
	p,ok:=s.Store.GetProof("r1:proof")
	if !ok || p.Signature=="" { t.Fatal("expected signed proof") }
	if p.Result.Status!=protocol.StatusInsufficientEvidence { t.Fatalf("unexpected result %s",p.Result.Status) }
}
