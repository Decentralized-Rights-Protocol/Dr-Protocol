package trust

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	drpcrypto "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/crypto"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

func signedProof(t *testing.T, signer drpcrypto.ProofSigner) protocol.Proof {
	t.Helper()
	p := protocol.Proof{Version:protocol.Version, ID:"proof-trust-test", SignerID:signer.SignerID(), SignerKeyID:signer.KeyID(), SignatureAlgorithm:signer.Algorithm(), ClaimDigest:"claim-digest", PolicyDigest:"policy-digest", EvidenceDigests:[]string{"evidence"}, Result:protocol.VerificationResult{Version:protocol.Version, ID:"result-1", Status:protocol.StatusVerified}, CreatedAt:time.Date(2026,1,1,0,0,0,0,time.UTC)}
	payload, err := protocol.ProofSigningBytes(p); if err != nil { t.Fatal(err) }
	p.Signature, err = signer.SignProof(payload); if err != nil { t.Fatal(err) }
	return p
}

func trustedBundle(s drpcrypto.ProofSigner, revoked bool) Bundle {
	return Bundle{Version:"1", Keys:[]Key{{SignerID:s.SignerID(),KeyID:s.KeyID(),Algorithm:s.Algorithm(),PublicKey:s.PublicKeyEncoded(),Revoked:revoked}}}
}

func TestVerifyProofWithTrustedEd25519Key(t *testing.T) {
	s, err := drpcrypto.NewSigner(); if err != nil { t.Fatal(err) }
	p := signedProof(t,s)
	if err := VerifyProof(p,trustedBundle(s,false),time.Now().UTC()); err != nil { t.Fatal(err) }
	p.ClaimDigest="tampered"
	if err := VerifyProof(p,trustedBundle(s,false),time.Now().UTC()); err == nil { t.Fatal("tampered proof accepted") }
}

func TestVerifyProofWithTrustedMLDSAKey(t *testing.T) {
	pub,priv,err:=pqc.GenerateKey(); if err!=nil {t.Fatal(err)}
	s,err:=drpcrypto.NewMLDSAProofSigner("node-pqc",pub,priv); if err!=nil {t.Fatal(err)}
	p:=signedProof(t,s)
	if err:=VerifyProof(p,trustedBundle(s,false),time.Now().UTC()); err!=nil {t.Fatal(err)}
}

func TestRevokedAndUnknownKeysAreRejected(t *testing.T) {
	s,err:=drpcrypto.NewSigner(); if err!=nil {t.Fatal(err)}
	p:=signedProof(t,s)
	if err:=VerifyProof(p,trustedBundle(s,true),time.Now().UTC()); err==nil {t.Fatal("revoked key accepted")}
	other,err:=drpcrypto.NewSigner(); if err!=nil {t.Fatal(err)}
	if err:=VerifyProof(p,trustedBundle(other,false),time.Now().UTC()); err==nil {t.Fatal("unknown key accepted")}
}

func TestTrustBundleLoadAndFingerprintValidation(t *testing.T) {
	s,err:=drpcrypto.NewSigner(); if err!=nil {t.Fatal(err)}
	b:=trustedBundle(s,false)
	raw,err:=json.Marshal(b); if err!=nil {t.Fatal(err)}
	path:=t.TempDir()+"/trusted-keys.json"
	if err:=os.WriteFile(path,raw,0600); err!=nil {t.Fatal(err)}
	loaded,err:=LoadBundle(path); if err!=nil {t.Fatal(err)}
	p:=signedProof(t,s)
	loaded.Keys[0].PublicKey=s.PublicKeyEncoded()
	loaded.Keys[0].KeyID="wrong-fingerprint"
	if err:=VerifyProof(p,loaded,time.Now().UTC()); err==nil {t.Fatal("mismatched fingerprint accepted")}
}
