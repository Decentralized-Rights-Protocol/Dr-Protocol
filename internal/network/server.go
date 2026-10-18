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
	Signer drpcrypto.ProofSigner
}

// New retains the legacy Ed25519 default for compatibility. The default key is
// ephemeral and is suitable only for local development; production should use
// NewWithProofSigner with a provisioned persistent key.
func New(s *store.Store) *Server {
	signer, _ := drpcrypto.NewSigner()
	return NewWithProofSigner(s, signer)
}

func NewWithProofSigner(s *store.Store, signer drpcrypto.ProofSigner) *Server {
	return &Server{Store:s, Registry:NewRegistry(), Peers:NewPeerBook(), Signer:signer}
}

func(s *Server) Handler() http.Handler {
	mux:=http.NewServeMux()
	mux.HandleFunc("/health",s.health)
	mux.HandleFunc("/drp/v1/node/identity",s.nodeIdentity)
	mux.HandleFunc("/drp/v1/verify",s.verify)
	mux.HandleFunc("/drp/v1/proofs/",s.proof)
	mux.HandleFunc("/drp/v1/claims/",s.claim)
	mux.HandleFunc("/drp/v1/verifiers",s.verifiers)
	mux.HandleFunc("/drp/v1/peers",s.peers)
	mux.HandleFunc("/drp/v1/attestations",s.attestations)
	return mux
}

// nodeIdentity publishes signing-key metadata. Clients must authenticate
// this information independently before adding it to a trust bundle.
func(s *Server) nodeIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" { writeJSON(w,405,map[string]string{"error":"method not allowed"}); return }
	writeJSON(w,200,map[string]any{
		"protocol":"DRP", "signerId":s.Signer.SignerID(),
		"signatureAlgorithm":s.Signer.Algorithm(), "signerKeyId":s.Signer.KeyID(),
		"publicKey":s.Signer.PublicKeyEncoded(),
		"warning":"public key metadata is not self-authenticating; verify signer identity out-of-band before trusting it",
	})
}

func(s *Server) health(w http.ResponseWriter,_ *http.Request){
	writeJSON(w,200,map[string]any{"status":"ok","protocol":"DRP","version":protocol.Version,"activeVerifiers":s.Registry.ActiveCount(),"peers":len(s.Peers.List())})
}

func(s *Server) verify(w http.ResponseWriter,r *http.Request){
	if r.Method!="POST"{writeJSON(w,405,map[string]string{"error":"method not allowed"});return}
	var req protocol.VerificationRequest
	if json.NewDecoder(r.Body).Decode(&req)!=nil{writeJSON(w,400,map[string]string{"error":"invalid JSON"});return}
	if err:=req.Validate();err!=nil{writeJSON(w,422,map[string]string{"error":err.Error()});return}
	s.Store.PutRequest(req)
	attestations:=s.Store.GetAttestations(req.Claim.ID)
	result:=s.Engine.Evaluate(req,attestations)
	digest,_:=protocol.CanonicalDigest(req.Claim)
	policyDigest,_:=protocol.CanonicalDigest(req.Policy)
	evidenceDigests:=make([]string,0,len(req.Evidence))
	for _,e:=range req.Evidence{d,_:=protocol.CanonicalDigest(e);evidenceDigests=append(evidenceDigests,d)}
	proof:=protocol.Proof{
		Version:protocol.Version, ID:req.ID+":proof", ClaimDigest:digest,
		PolicyDigest:policyDigest, EvidenceDigests:evidenceDigests, Result:result,
		SignatureAlgorithm:s.Signer.Algorithm(), SignerID:s.Signer.SignerID(), SignerKeyID:s.Signer.KeyID(), CreatedAt:time.Now().UTC(),
	}
	payload,err:=protocol.ProofSigningBytes(proof)
	if err!=nil{writeJSON(w,500,map[string]string{"error":"could not serialize proof"});return}
	proof.Signature,err=s.Signer.SignProof(payload)
	if err!=nil{writeJSON(w,500,map[string]string{"error":"could not sign proof"});return}
	s.Store.PutProof(proof)
	writeJSON(w,202,map[string]any{"result":result,"proof":proof,"network":"DRP Verification Network"})
}

func(s *Server) attestations(w http.ResponseWriter,r *http.Request){
	if r.Method=="GET"{writeJSON(w,200,map[string]any{"attestations":s.Store.GetAttestations(r.URL.Query().Get("claimId"))});return}
	if r.Method!="POST"{writeJSON(w,405,map[string]string{"error":"method not allowed"});return}
	var a protocol.Attestation
	if json.NewDecoder(r.Body).Decode(&a)!=nil||a.ID==""||a.VerifierID==""||a.ClaimID==""{writeJSON(w,400,map[string]string{"error":"invalid attestation"});return}
	var verifier Verifier
	found:=false
	for _,v:=range s.Registry.List(){if v.ID==a.VerifierID{verifier=v;found=true;break}}
	if !found||!verifier.Active||verifier.PublicKey==""{writeJSON(w,403,map[string]string{"error":"verifier is not registered, active, or missing public key"});return}
	attestationAlgorithm:=a.SignatureAlgorithm
	if attestationAlgorithm==""{attestationAlgorithm=drpcrypto.SignatureAlgorithmEd25519}
	verifierAlgorithm:=verifier.SignatureAlgorithm
	if verifierAlgorithm==""{verifierAlgorithm=drpcrypto.SignatureAlgorithmEd25519}
	if attestationAlgorithm!=verifierAlgorithm{writeJSON(w,401,map[string]string{"error":"attestation signature algorithm does not match registered verifier"});return}
	if !drpcrypto.VerifyAttestation(a,verifier.PublicKey){writeJSON(w,401,map[string]string{"error":"invalid attestation signature"});return}
	s.Store.PutAttestation(a)
	writeJSON(w,201,a)
}

func(s *Server) claim(w http.ResponseWriter,r *http.Request){
	id:=strings.TrimPrefix(r.URL.Path,"/drp/v1/claims/")
	req,ok:=s.Store.GetRequest(id)
	if !ok{writeJSON(w,404,map[string]string{"error":"claim/request not found"});return}
	writeJSON(w,200,req)
}

func(s *Server) proof(w http.ResponseWriter,r *http.Request){
	if r.Method!="GET"{writeJSON(w,405,map[string]string{"error":"method not allowed"});return}
	id:=strings.TrimPrefix(r.URL.Path,"/drp/v1/proofs/")
	verifyOnly:=strings.HasSuffix(id,"/verify")
	if verifyOnly{id=strings.TrimSuffix(id,"/verify")}
	if id==""||strings.Contains(id,"/"){writeJSON(w,404,map[string]string{"error":"proof not found"});return}
	p,ok:=s.Store.GetProof(id)
	if !ok{writeJSON(w,404,map[string]string{"error":"proof not found"});return}
	if !verifyOnly{writeJSON(w,200,p);return}
	payload,err:=protocol.ProofSigningBytes(p)
	trustedSigner:=p.SignerID==s.Signer.SignerID() && p.SignatureAlgorithm==s.Signer.Algorithm() && p.SignerKeyID==s.Signer.KeyID()
	valid:=err==nil && trustedSigner && s.Signer.VerifyProof(payload,p.Signature)
	writeJSON(w,200,map[string]any{"proofId":p.ID,"valid":valid,"trustedSigner":trustedSigner,"signerId":p.SignerID,"signerKeyId":p.SignerKeyID,"signatureAlgorithm":p.SignatureAlgorithm})
}

func(s *Server) verifiers(w http.ResponseWriter,r *http.Request){
	if r.Method=="GET"{writeJSON(w,200,map[string]any{"verifiers":s.Registry.List()});return}
	if r.Method=="POST"{var v Verifier;if json.NewDecoder(r.Body).Decode(&v)!=nil||v.ID==""{writeJSON(w,400,map[string]string{"error":"invalid verifier"});return};s.Registry.Register(v);writeJSON(w,201,v);return}
	writeJSON(w,405,map[string]string{"error":"method not allowed"})
}
func(s *Server) peers(w http.ResponseWriter,r *http.Request){
	if r.Method=="GET"{writeJSON(w,200,map[string]any{"peers":s.Peers.List()});return}
	if r.Method=="POST"{var p Peer;if json.NewDecoder(r.Body).Decode(&p)!=nil||p.ID==""||p.Address==""{writeJSON(w,400,map[string]string{"error":"invalid peer"});return};p.LastSeen=time.Now().UTC();s.Peers.Upsert(p);writeJSON(w,201,p);return}
	writeJSON(w,405,map[string]string{"error":"method not allowed"})
}
func writeJSON(w http.ResponseWriter,code int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(code);_ = json.NewEncoder(w).Encode(v)}
func NewRequest(id,subject,typ,statement string,evidence []protocol.Evidence)protocol.VerificationRequest{return protocol.VerificationRequest{Version:protocol.Version,ID:id,Claim:protocol.Claim{Version:protocol.Version,ID:id+":claim",Subject:subject,Type:typ,Statement:statement,CreatedAt:time.Now().UTC()},Evidence:evidence,Policy:protocol.VerificationPolicy{Version:protocol.Version,ID:id+":policy",MinVerifiers:2,MinEvidence:1},CreatedAt:time.Now().UTC()}}
