package protocol

import "testing"

func TestCanonicalDigestDeterministic(t *testing.T) {
	c:=Claim{Version:Version,ID:"c1",Subject:"alice",Type:"activity",Statement:"did X"}
	a,_:=CanonicalDigest(c); b,_:=CanonicalDigest(c)
	if a != b || len(a) != 64 { t.Fatalf("unexpected digest: %s %s",a,b) }
}

func TestRequestValidation(t *testing.T) {
	r:=VerificationRequest{Claim:Claim{ID:"c",Subject:"s",Type:"t",Statement:"x"},Policy:VerificationPolicy{MinVerifiers:1,MinEvidence:1}}
	if r.Validate()==nil { t.Fatal("expected insufficient evidence") }
}
