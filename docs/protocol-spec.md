# DRP Protocol Specification v0.1

## 1. Purpose

DRP defines a verification-native protocol for exchanging claims, evidence commitments, verification requests, attestations, challenges, and cryptographically verifiable proofs.

DRP does not define human worth and does not assert omniscience. A VERIFIED result means that a claim satisfied a declared verification policy using the evidence and attestations available to the network at verification time.

## 2. Normative language

MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are interpreted as protocol requirements.

## 3. Core objects

The canonical objects are Identity, Claim, Evidence, VerificationRequest, VerificationPolicy, Attestation, VerificationResult, Proof, Challenge, and Revocation.

Each object MUST have a version, stable identifier, creation timestamp where applicable, and deterministic JSON representation when signed or hashed.

Raw private evidence SHOULD remain off-chain/off-network. The protocol records hashes, commitments, provenance, and proofs unless disclosure is explicitly authorized.

## 4. Verification

A client submits a VerificationRequest containing a claim, evidence references, policy, and optional privacy requirements.

Verifiers independently assess the evidence against the policy. A result may be VERIFIED, PARTIALLY_VERIFIED, INSUFFICIENT_EVIDENCE, DISPUTED, REVOKED, EXPIRED, or FAILED.

Verification consensus is distinct from blockchain consensus.

## 5. Proofs

A proof MUST contain the claim digest, verification result, policy digest, evidence digests, verifier attestations, quorum information, and a cryptographic signature.

A relying application SHOULD be able to validate a proof without trusting the original application database.

## 6. Challenges

Consequential claims SHOULD remain challengeable. A challenge creates a dispute record and can cause reassessment or revocation.

## 7. Privacy

DRP follows data minimization: prove the claim, not the person's entire life. Implementations SHOULD support selective disclosure, commitments, local processing, pseudonymous identifiers, and zero-knowledge proofs as mature implementations become available.

## 8. Human participation

Humans, institutions, software, phones, sensors, and AI systems can be evidence sources. No single sensor or AI model is inherently an oracle of truth.

## 9. Cryptographic agility

Implementations MUST isolate cryptographic algorithms behind an abstraction layer so algorithms can be upgraded. DRP MUST NOT invent cryptographic primitives.

## 10. Status

v0.1 is an experimental interoperable foundation, not a final production standard.
