package verification

import "github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"

type Engine struct{}

func (Engine) Evaluate(req protocol.VerificationRequest, attestations []protocol.Attestation) protocol.VerificationResult {
	status:=protocol.StatusInsufficientEvidence
	if len(req.Evidence)>=req.Policy.MinEvidence {
		verified,disputed:=0,0
		seen:=map[string]bool{}
		for _,a:=range attestations {
			if seen[a.VerifierID]{continue}
			seen[a.VerifierID]=true
			if a.Decision==protocol.StatusVerified{verified++}
			if a.Decision==protocol.StatusDisputed||a.Decision==protocol.StatusFailed{disputed++}
		}
		switch {case disputed>0: status=protocol.StatusDisputed; case verified>=req.Policy.MinVerifiers: status=protocol.StatusVerified; case verified>0: status=protocol.StatusPartiallyVerified}
	}
	return protocol.VerificationResult{Version:protocol.Version,ID:req.ID+":result",ClaimID:req.Claim.ID,Status:status,VerifierCount:len(seenVerifierIDs(attestations)),EvidenceCount:len(req.Evidence),Attestations:attestations}
}
func seenVerifierIDs(a []protocol.Attestation) []string { m:=map[string]bool{}; for _,x:=range a {m[x.VerifierID]=true}; out:=make([]string,0,len(m)); for id:=range m {out=append(out,id)}; return out }
