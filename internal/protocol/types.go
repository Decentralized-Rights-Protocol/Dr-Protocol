package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

const Version = "0.1"

type Status string
const (
	StatusVerified Status = "VERIFIED"
	StatusPartiallyVerified Status = "PARTIALLY_VERIFIED"
	StatusInsufficientEvidence Status = "INSUFFICIENT_EVIDENCE"
	StatusDisputed Status = "DISPUTED"
	StatusRevoked Status = "REVOKED"
	StatusExpired Status = "EXPIRED"
	StatusFailed Status = "FAILED"
)

type Identity struct {
	Version string `json:"version"`
	ID string `json:"id"`
	Type string `json:"type"`
	PublicKey string `json:"publicKey"`
	CreatedAt time.Time `json:"createdAt"`
}

type Claim struct {
	Version string `json:"version"`
	ID string `json:"id"`
	Subject string `json:"subject"`
	Type string `json:"type"`
	Statement string `json:"statement"`
	CreatedAt time.Time `json:"createdAt"`
}

type Evidence struct {
	Version string `json:"version"`
	ID string `json:"id"`
	SourceID string `json:"sourceId"`
	Type string `json:"type"`
	ContentHash string `json:"contentHash"`
	Metadata map[string]string `json:"metadata,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type VerificationPolicy struct {
	Version string `json:"version"`
	ID string `json:"id"`
	MinVerifiers int `json:"minVerifiers"`
	MinEvidence int `json:"minEvidence"`
	AllowedEvidenceTypes []string `json:"allowedEvidenceTypes,omitempty"`
}

type VerificationRequest struct {
	Version string `json:"version"`
	ID string `json:"id"`
	Claim Claim `json:"claim"`
	Evidence []Evidence `json:"evidence"`
	Policy VerificationPolicy `json:"policy"`
	CreatedAt time.Time `json:"createdAt"`
}

type Attestation struct {
	Version string `json:"version"`
	ID string `json:"id"`
	VerifierID string `json:"verifierId"`
	ClaimID string `json:"claimId"`
	Decision Status `json:"decision"`
	Reason string `json:"reason,omitempty"`
	Signature string `json:"signature"`
	CreatedAt time.Time `json:"createdAt"`
}

type VerificationResult struct {
	Version string `json:"version"`
	ID string `json:"id"`
	ClaimID string `json:"claimId"`
	Status Status `json:"status"`
	VerifierCount int `json:"verifierCount"`
	EvidenceCount int `json:"evidenceCount"`
	Attestations []Attestation `json:"attestations"`
	CreatedAt time.Time `json:"createdAt"`
}

type Proof struct {
	Version string `json:"version"`
	ID string `json:"id"`
	ClaimDigest string `json:"claimDigest"`
	PolicyDigest string `json:"policyDigest"`
	EvidenceDigests []string `json:"evidenceDigests"`
	Result VerificationResult `json:"result"`
	Signature string `json:"signature"`
	CreatedAt time.Time `json:"createdAt"`
}

type Challenge struct {
	Version string `json:"version"`
	ID string `json:"id"`
	ClaimID string `json:"claimId"`
	ChallengerID string `json:"challengerId"`
	Reason string `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
}

func CanonicalDigest(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil { return "", err }
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func (c Claim) Validate() error {
	if c.ID == "" || c.Subject == "" || c.Type == "" || c.Statement == "" { return errors.New("claim requires id, subject, type and statement") }
	return nil
}

func (p VerificationPolicy) Validate() error {
	if p.MinVerifiers < 1 { return errors.New("minVerifiers must be >= 1") }
	if p.MinEvidence < 1 { return errors.New("minEvidence must be >= 1") }
	return nil
}

func (r VerificationRequest) Validate() error {
	if err := r.Claim.Validate(); err != nil { return err }
	if err := r.Policy.Validate(); err != nil { return err }
	if len(r.Evidence) < r.Policy.MinEvidence { return errors.New("insufficient evidence") }
	return nil
}
