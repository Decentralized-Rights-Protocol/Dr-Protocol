package verification

import (
	"time"

	"github.com/Decentralized-Rights-Protocol/Dr-Protocol/internal/protocol"
)

type Engine struct{}

func (Engine) Evaluate(req protocol.VerificationRequest, attestations []protocol.Attestation) protocol.VerificationResult {
	status := protocol.StatusInsufficientEvidence
	if len(req.Evidence) >= req.Policy.MinEvidence {
		verified := 0
		disputed := 0
		for _, a := range attestations {
			if a.Decision == protocol.StatusVerified { verified++ }
			if a.Decision == protocol.StatusDisputed || a.Decision == protocol.StatusFailed { disputed++ }
		}
		if disputed > 0 { status = protocol.StatusDisputed
		} else if verified >= req.Policy.MinVerifiers { status = protocol.StatusVerified
		} else if verified > 0 { status = protocol.StatusPartiallyVerified }
	}
	return protocol.VerificationResult{
		Version: protocol.Version,
		ID: req.ID + ":result",
		ClaimID: req.Claim.ID,
		Status: status,
		VerifierCount: len(attestations),
		EvidenceCount: len(req.Evidence),
		Attestations: attestations,
		CreatedAt: time.Now().UTC(),
	}
}
