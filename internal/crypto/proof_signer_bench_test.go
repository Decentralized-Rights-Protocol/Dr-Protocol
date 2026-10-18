package crypto

import (
	"testing"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/pqc"
)

func BenchmarkEd25519ProofSign(b *testing.B) {
	s,err:=NewSigner(); if err!=nil {b.Fatal(err)}
	payload:=[]byte("DRP proof benchmark payload")
	b.ReportAllocs(); b.ResetTimer()
	for i:=0;i<b.N;i++ { if _,err:=s.SignProof(payload); err!=nil {b.Fatal(err)} }
}

func BenchmarkEd25519ProofVerify(b *testing.B) {
	s,err:=NewSigner(); if err!=nil {b.Fatal(err)}
	payload:=[]byte("DRP proof benchmark payload")
	sig,err:=s.SignProof(payload); if err!=nil {b.Fatal(err)}
	b.ReportAllocs(); b.ResetTimer()
	for i:=0;i<b.N;i++ { if !s.VerifyProof(payload,sig) {b.Fatal("verification failed")} }
}

func BenchmarkMLDSA44ProofSign(b *testing.B) {
	pub,priv,err:=pqc.GenerateKey(); if err!=nil {b.Fatal(err)}
	s,err:=NewMLDSAProofSigner("benchmark-node",pub,priv); if err!=nil {b.Fatal(err)}
	payload:=[]byte("DRP proof benchmark payload")
	b.ReportAllocs(); b.ResetTimer()
	for i:=0;i<b.N;i++ { if _,err:=s.SignProof(payload); err!=nil {b.Fatal(err)} }
}

func BenchmarkMLDSA44ProofVerify(b *testing.B) {
	pub,priv,err:=pqc.GenerateKey(); if err!=nil {b.Fatal(err)}
	s,err:=NewMLDSAProofSigner("benchmark-node",pub,priv); if err!=nil {b.Fatal(err)}
	payload:=[]byte("DRP proof benchmark payload")
	sig,err:=s.SignProof(payload); if err!=nil {b.Fatal(err)}
	b.ReportAllocs(); b.ResetTimer()
	for i:=0;i<b.N;i++ { if !s.VerifyProof(payload,sig) {b.Fatal("verification failed")} }
}
