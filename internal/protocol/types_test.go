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

func TestCanonicalDigestDomainsAreSeparated(t *testing.T) {
	value := Claim{Version: Version, ID: "same", Subject: "subject", Type: "activity", Statement: "test"}
	claimDigest, err := CanonicalDigestDomain("drp/claim/v1", value)
	if err != nil { t.Fatalf("claim digest: %v", err) }
	evidenceDigest, err := CanonicalDigestDomain("drp/evidence/v1", value)
	if err != nil { t.Fatalf("evidence digest: %v", err) }
	if claimDigest == evidenceDigest { t.Fatal("same JSON unexpectedly produced the same digest across domains") }
	if _, err := CanonicalDigestDomain("", value); err == nil { t.Fatal("empty digest domain should fail") }
}
