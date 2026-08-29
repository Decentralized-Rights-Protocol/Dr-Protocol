# DRP Verification Network Architecture

## North star

DRP is a verification-oriented protocol. HTTP is an initial transport/gateway, not the definition of the protocol.

Application → DRP client/SDK → DRP gateway → claim/evidence layer → verification engine → cryptographic proof → relying application.

## Network roles

- **Client** — creates claims and requests verification.
- **Gateway** — accepts protocol requests over HTTP initially.
- **Verifier** — independently evaluates evidence against a policy.
- **Peer** — propagates network metadata and future verification messages.
- **Archive/Indexer** — future role for durable public proof discovery.
- **Validator** — future blockchain role for state consensus.

## Two kinds of consensus

Blockchain consensus establishes agreement about network state.

Verification consensus establishes whether a claim satisfies a verification policy.

They MUST remain conceptually separate.

## Evidence

Evidence is represented by integrity/provenance metadata and content hashes. Sensitive raw evidence belongs off-chain by default.

## Proof

A DRP proof binds a claim digest, policy digest, evidence digests, verification result, and attestations. The proof is independently checkable with the issuer's public key.

## Current MVP boundary

v0.1 contains a working HTTP gateway, canonical protocol objects, policy evaluation, proof generation/signing, verifier registry, peer book, CLI, and tests. Remote peer-to-peer attestation exchange, durable storage, blockchain anchoring, ZK proofs, and production-grade Byzantine consensus are deliberately next phases.
